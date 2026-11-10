"""FastAPI application for LNC Care (`/admin`, `/api/*`, `/webhooks/meta`, `/mcp`)."""
from collections import defaultdict
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.datastructures import Headers

from . import audit, connections as conn_mod, evaluator, settings, store, worker
from .connections import Connections
from .mcp_server import AUDIENCE, SCOPES, TOOL_SCOPES, build_mcp_asgi
from .providers import ProviderError
from .vault import Vault, VaultError

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = Path(__file__).resolve().parent / "public"
VERSION = (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").exists() else "0.1.0.0"


def _session_cookie_value(key: str, sid: str, exp: int) -> str:
    msg = f"{sid}.{exp}".encode()
    sig = hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()
    return f"{sid}.{exp}.{sig}"


def _verify_session_cookie(key: str, cookie: str | None) -> str | None:
    if not key or not cookie:
        return None
    try:
        sid, exp_s, sig = cookie.split(".", 2)
        exp = int(exp_s)
    except ValueError:
        return None
    expected = hmac.new(key.encode(), f"{sid}.{exp}".encode(), hashlib.sha256).hexdigest()
    if exp <= time.time() or not hmac.compare_digest(sig, expected):
        return None
    return hashlib.sha256(cookie.encode()).hexdigest()


def create_app(
    *,
    db_path: Path | None = None,
    master_key: str | None = None,
    previous_master_key: str | None = None,
    management_key: str | None = None,
    mcp_bearer_token: str | None = None,
    delegation_secret: str | None = None,
    transport=None,
) -> FastAPI:
    env = os.environ
    default_db = (
        Path(env["DATA_DIR"]) / "care.db"
        if env.get("DATA_DIR")
        else ROOT / "data" / "lnc-care.db"
    )
    path = Path(db_path or env.get("DATABASE_PATH", str(default_db)))
    org = env.get("ORGANIZATION_ID") or env.get("DEFAULT_ORG_SLUG") or "lnc-default"
    org_name = env.get("ORGANIZATION_NAME") or env.get("DEFAULT_ORG_NAME") or "Le Ngoc Care"
    mgmt_key = (
        management_key
        if management_key is not None
        else (env.get("MANAGEMENT_KEY") or env.get("LNC_MANAGEMENT_KEY") or "")
    )
    bearer = (
        mcp_bearer_token
        if mcp_bearer_token is not None
        else (
            env.get("CONNECTOR_BEARER")
            or env.get("LNC_CONNECTOR_TOKEN")
            or env.get("MCP_BEARER_TOKEN")
            or ""
        )
    )
    del_secret = (
        delegation_secret
        if delegation_secret is not None
        else (
            env.get("DELEGATION_SECRET")
            or env.get("LNC_DELEGATION_SECRET")
            or env.get("MCP_DELEGATION_SECRET")
            or ""
        )
    )
    require_delegation = env.get("MCP_REQUIRE_DELEGATION", "true").lower() != "false"
    writes_enabled = env.get("PROVIDER_WRITES_ENABLED", "false").lower() == "true"

    store.initialize(path, org, org_name)
    vault = Vault(
        master_key if master_key is not None else env.get("LNC_MASTER_KEY"),
        previous_master_key
        if previous_master_key is not None
        else env.get("LNC_PREVIOUS_MASTER_KEY"),
    )
    with store.connect(path) as db:
        vault.verify_master(db, org)
    conns = Connections(path, org, vault, transport=transport)
    mcp_asgi, mcp_lifespan = build_mcp_asgi(
        path, org, bearer, del_secret, require_delegation, writes_enabled=writes_enabled
    )

    app = FastAPI(title="LNC Care", version=VERSION, lifespan=mcp_lifespan)
    attempts: dict[str, list[float]] = defaultdict(list)

    def current_settings() -> dict:
        with store.connect_readonly(path) as db:
            return settings.load(db, org, env)

    def check_rate(bucket: str, limit: int, window: int = 60) -> None:
        now = time.time()
        items = [t for t in attempts[bucket] if now - t < window]
        if len(items) >= limit:
            raise HTTPException(429, "Rate limit exceeded")
        items.append(now)
        attempts[bucket] = items

    def require_admin(request: Request) -> str:
        session_hash = _verify_session_cookie(mgmt_key, request.cookies.get("lnc_care_session"))
        if not session_hash:
            raise HTTPException(401, "Authentication required")
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            csrf_cookie = request.cookies.get("lnc_care_csrf", "")
            csrf_header = request.headers.get("x-csrf-token", "")
            if not csrf_cookie or not secrets.compare_digest(csrf_cookie, csrf_header):
                raise HTTPException(403, "CSRF token required")
        return session_hash

    @app.middleware("http")
    async def host_gate(request: Request, call_next):
        if request.url.path not in ("/health", "/webhooks/meta"):
            cfg = current_settings()
            host = (request.headers.get("host") or "").split(":")[0].lower()
            allowed = {h.lower() for h in cfg["allowed_hosts"]} | {"testserver"}
            if host and host not in allowed:
                return Response(
                    content=json.dumps({"detail": "Disallowed host"}),
                    status_code=421,
                    media_type="application/json",
                )
        return await call_next(request)

    @app.exception_handler(ProviderError)
    async def handle_provider_error(_: Request, exc: ProviderError):
        return Response(
            content=json.dumps({"detail": exc.code}),
            status_code=exc.status,
            media_type="application/json",
        )

    @app.exception_handler(VaultError)
    async def handle_vault_error(_: Request, exc: VaultError):
        return Response(
            content=json.dumps({"detail": str(exc)}),
            status_code=500,
            media_type="application/json",
        )

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "service": AUDIENCE,
            "version": VERSION,
            "writes_enabled": writes_enabled,
        }

    @app.get("/webhooks/meta")
    def meta_webhook_verify(request: Request):
        mode = request.query_params.get("hub.mode", "")
        token = request.query_params.get("hub.verify_token", "")
        challenge = request.query_params.get("hub.challenge", "")
        with store.connect_readonly(path) as db:
            row = db.execute(
                "SELECT webhook_verify_token FROM provider_apps WHERE organization_id=? AND provider='meta'",
                (org,),
            ).fetchone()
        expected = (
            row["webhook_verify_token"]
            if row and row["webhook_verify_token"]
            else env.get("META_WEBHOOK_VERIFY_TOKEN", "")
        )
        if mode == "subscribe" and expected and secrets.compare_digest(token, expected):
            return PlainTextResponse(challenge)
        raise HTTPException(403, "webhook_verify_token_mismatch")

    @app.post("/webhooks/meta")
    async def meta_webhook_receive(request: Request):
        raw_body = await request.body()
        sig_header = request.headers.get("x-hub-signature-256", "")
        with store.connect_readonly(path) as db:
            secret_env = vault.get(db, org, "app", "meta")
        app_secret = (
            secret_env.get("client_secret", "")
            if secret_env
            else env.get("META_APP_SECRET", "")
        )
        if not app_secret or not sig_header.startswith("sha256="):
            raise HTTPException(403, "webhook_signature_missing")
        expected_sig = (
            "sha256=" + hmac.new(app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
        )
        if not hmac.compare_digest(sig_header, expected_sig):
            raise HTTPException(403, "webhook_signature_invalid")

        payload = json.loads(raw_body.decode("utf-8") or "{}")
        dedupe_key = hashlib.sha256(raw_body).hexdigest()
        now = int(time.time())
        enqueued = 0
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT id FROM webhook_events WHERE organization_id=? AND dedupe_key=?",
                (org, dedupe_key),
            ).fetchone()
            if existing:
                return {"ok": True, "deduplicated": True, "enqueued": 0}
            db.execute(
                """INSERT INTO webhook_events
                   (organization_id, provider, dedupe_key, payload_json, received_at, processed_at)
                   VALUES (?, 'meta', ?, ?, ?, ?)""",
                (org, dedupe_key, raw_body.decode("utf-8"), now, now),
            )
            for entry in payload.get("entry") or []:
                for change in entry.get("changes") or []:
                    val = change.get("value") or {}
                    if change.get("field") in ("feed", "comments", "mentions"):
                        worker.enqueue_job(
                            db,
                            org,
                            "fetch_comments",
                            {"entry_id": entry.get("id"), "value": val},
                        )
                        enqueued += 1
        return {"ok": True, "deduplicated": False, "enqueued": enqueued}

    @app.get("/api/auth/status")
    def auth_status(request: Request):
        authenticated = bool(
            _verify_session_cookie(mgmt_key, request.cookies.get("lnc_care_session"))
        )
        return {
            "authenticated": authenticated,
            "csrf": request.cookies.get("lnc_care_csrf", "") if authenticated else "",
        }

    @app.post("/api/auth/login")
    async def login(request: Request, response: Response):
        check_rate(f"login:{request.client.host if request.client else 'local'}", 8)
        body = await request.json()
        key = str(body.get("key") or body.get("password") or "")
        if not mgmt_key or not secrets.compare_digest(key, mgmt_key):
            raise HTTPException(401, "Invalid management key")
        sid, csrf = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        secure = request.url.scheme == "https"
        response.set_cookie(
            "lnc_care_session",
            _session_cookie_value(mgmt_key, sid, int(time.time()) + 43200),
            httponly=True,
            samesite="lax",
            secure=secure,
            path="/",
        )
        response.set_cookie(
            "lnc_care_csrf", csrf, httponly=False, samesite="lax", secure=secure, path="/"
        )
        with store.connect(path) as db:
            audit.append(db, org, "owner", "auth.login", "admin_session", {})
        return {"authenticated": True, "csrf": csrf}

    @app.post("/api/auth/logout")
    def logout(response: Response, _: str = Depends(require_admin)):
        response.delete_cookie("lnc_care_session", path="/")
        response.delete_cookie("lnc_care_csrf", path="/")
        return {"ok": True}

    @app.get("/api/admin/overview")
    def overview(shop_id: int | None = None, _: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            ev_count = db.execute(
                "SELECT COUNT(*) AS c FROM evidence_cases WHERE organization_id=?", (org,)
            ).fetchone()["c"]
            fleet_rows = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM account_runtimes WHERE organization_id=? ORDER BY id", (org,)
                ).fetchall()
            ]
            return {
                "organization": {"id": org, "name": org_name},
                "version": VERSION,
                "writes_enabled": writes_enabled,
                "shops": store.shops(db, org),
                "integrations": conns.inventory(db),
                "channels": store.channels(db, org, shop_id),
                "inbox_summary": store.inbox_summary(db, org, shop_id),
                "evidence_cases_count": ev_count,
                "fleet_summary": {
                    "total": len(fleet_rows),
                    "healthy": sum(1 for r in fleet_rows if r["health_status"] == "healthy"),
                    "runtimes": fleet_rows,
                },
                "rubric_labels": [
                    {"key": k, "label_vi": vi, "label_en": en, "polarity": pol}
                    for k, vi, en, pol in evaluator.RUBRIC_LABELS
                ],
            }

    @app.post("/api/admin/seed-demo")
    def seed_demo(_: str = Depends(require_admin)):
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            return conn_mod.seed_demo_workspace(db, org, actor="owner")

    @app.post("/api/admin/shops")
    async def create_shop(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        name = str(body.get("name", "")).strip()
        if not name or len(name) > 80:
            raise HTTPException(422, "Shop name is required")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                "INSERT INTO shops (organization_id, name) VALUES (?, ?)", (org, name)
            )
            audit.append(db, org, "owner", "shop.created", str(cur.lastrowid), {"name": name})
            return {"id": cur.lastrowid, "name": name}

    @app.get("/api/admin/integrations")
    def get_integrations(_: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            return conns.inventory(db)

    @app.post("/api/admin/integrations/{provider}")
    async def save_integration(provider: str, request: Request, _: str = Depends(require_admin)):
        if provider not in store.PROVIDERS:
            raise HTTPException(404, "Unknown provider")
        return conns.save_app(provider, await request.json())

    @app.post("/api/admin/connections")
    async def create_connection(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        provider = str(body.get("provider", "")).strip()
        label = str(body.get("label", "")).strip()
        if provider not in store.PROVIDERS or not label:
            raise HTTPException(422, "Provider and label are required")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                """INSERT INTO provider_connections (organization_id, provider, label, state)
                   VALUES (?, ?, ?, 'not_connected')""",
                (org, provider, label),
            )
            db.execute(
                "INSERT INTO connection_runtime (organization_id, connection_id, revision, app_revision) VALUES (?, ?, 1, 0)",
                (org, cur.lastrowid),
            )
            audit.append(
                db,
                org,
                "owner",
                "connection.created",
                str(cur.lastrowid),
                {"provider": provider, "label": label},
            )
            return {"id": cur.lastrowid, "provider": provider, "label": label}

    @app.post("/api/admin/connections/{connection_id}/authorize")
    def authorize_connection(
        connection_id: int, request: Request, session_hash: str = Depends(require_admin)
    ):
        check_rate(f"oauth:{session_hash}", 10)
        cfg = current_settings()
        base = cfg["public_base_url"] or f"{request.url.scheme}://{request.headers.get('host', 'localhost')}"
        return conns.start(connection_id, session_hash, base)

    @app.get("/api/auth/providers/{provider}/callback")
    def oauth_callback(provider: str, state: str, code: str, request: Request):
        session_hash = _verify_session_cookie(mgmt_key, request.cookies.get("lnc_care_session"))
        if not session_hash:
            raise HTTPException(401, "Authentication required")
        conns.callback(provider, state, code, session_hash)
        return RedirectResponse("/admin/#channels", status_code=303)

    @app.post("/api/admin/connections/{connection_id}/disconnect")
    def disconnect_connection(connection_id: int, _: str = Depends(require_admin)):
        return conns.disconnect(connection_id)

    @app.post("/api/admin/connections/{connection_id}/discover")
    def discover_channels(
        connection_id: int, session_hash: str = Depends(require_admin)
    ):
        check_rate(f"discover:{session_hash}", 10)
        return conns.discover(connection_id)

    @app.get("/api/admin/connections/{connection_id}/channels")
    def list_discovered_channels(connection_id: int, _: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            return {"channels": conns.discovered(db, connection_id)}

    @app.post("/api/admin/connections/{connection_id}/channels/approve")
    async def approve_channel(
        connection_id: int, request: Request, _: str = Depends(require_admin)
    ):
        body = await request.json()
        return conns.approve_channel(
            connection_id,
            str(body.get("external_id", "")),
            int(body.get("shop_id", 0)),
            str(body.get("reply_policy", "draft_only")),
        )

    @app.post("/api/admin/channels/{channel_id}/sync")
    def sync_channel(channel_id: int, session_hash: str = Depends(require_admin)):
        check_rate(f"sync:{session_hash}", 15)
        return conns.sync_channel(channel_id)

    @app.post("/api/admin/channels/{channel_id}/policy")
    async def update_channel_policy(
        channel_id: int, request: Request, _: str = Depends(require_admin)
    ):
        body = await request.json()
        policy = str(body.get("reply_policy", "draft_only"))
        threshold = int(body.get("auto_suggest_threshold", 80))
        if policy not in store.REPLY_POLICIES or not 10 <= threshold <= 99:
            raise HTTPException(422, "Invalid reply_policy or auto_suggest_threshold")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """UPDATE channels SET reply_policy=?, auto_suggest_threshold=?
                   WHERE organization_id=? AND id=?""",
                (policy, threshold, org, channel_id),
            )
            audit.append(
                db,
                org,
                "owner",
                "channel.policy_updated",
                str(channel_id),
                {"reply_policy": policy, "auto_suggest_threshold": threshold},
            )
        return {"ok": True, "channel_id": channel_id, "reply_policy": policy, "auto_suggest_threshold": threshold}

    @app.get("/api/admin/posts")
    def list_posts(
        channel_id: int | None = None,
        shop_id: int | None = None,
        kind: str | None = None,
        limit: int = 50,
        _: str = Depends(require_admin),
    ):
        with store.connect_readonly(path) as db:
            return {
                "posts": store.posts_list(
                    db, org, channel_id=channel_id, shop_id=shop_id, kind=kind, limit=limit
                )
            }

    @app.get("/api/admin/posts/{post_id}")
    def get_post(post_id: int, _: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            post = store.post_detail(db, org, post_id)
            if not post:
                raise HTTPException(404, "Post not found")
            return {"post": post}

    @app.post("/api/admin/posts/{post_id}/archive")
    def request_post_archive(post_id: int, _: str = Depends(require_admin)):
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM posts WHERE organization_id=? AND id=?", (org, post_id)
            ).fetchone():
                raise HTTPException(404, "Post not found")
            j1 = worker.enqueue_job(db, org, "archive_media", {"post_id": post_id})
            j2 = worker.enqueue_job(db, org, "screenshot", {"post_id": post_id})
            audit.append(db, org, "owner", "post.archive_requested", str(post_id), {"jobs": [j1, j2]})
        res = worker.run_pending_jobs(path, org, limit=5)
        return {"ok": True, "post_id": post_id, "jobs": [j1, j2], "worker": res}

    @app.get("/api/admin/comments")
    def list_comments(
        shop_id: int | None = None,
        channel_id: int | None = None,
        post_id: int | None = None,
        status: str | None = None,
        bucket: str | None = None,
        assignment: str | None = None,
        search: str | None = None,
        limit: int = 100,
        _: str = Depends(require_admin),
    ):
        with store.connect_readonly(path) as db:
            return {
                "comments": store.comments_list(
                    db,
                    org,
                    shop_id=shop_id,
                    channel_id=channel_id,
                    post_id=post_id,
                    status=status,
                    bucket=bucket,
                    assignment=assignment,
                    search=search,
                    limit=limit,
                ),
                "summary": store.inbox_summary(db, org, shop_id=shop_id),
            }

    @app.get("/api/admin/comments/{comment_id}")
    def get_comment(comment_id: int, _: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            thread = store.comment_thread(db, org, comment_id)
            if not thread:
                raise HTTPException(404, "Comment not found")
            return {"thread": thread}

    @app.post("/api/admin/comments/{comment_id}/evaluate")
    async def evaluate_comment_endpoint(
        comment_id: int, request: Request, _: str = Depends(require_admin)
    ):
        body = await request.json() if request.headers.get("content-length") else {}
        threshold = body.get("threshold")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            res = evaluator.evaluate_and_persist(
                db, org, comment_id, threshold=int(threshold) if threshold is not None else None, actor="owner"
            )
            audit.append(
                db,
                org,
                "owner",
                "comment.evaluated",
                str(comment_id),
                {"overall_score": res["overall_score"], "recommended_action": res["recommended_action"]},
            )
            thread = store.comment_thread(db, org, comment_id)
        return {"ok": True, "evaluation": res, "thread": thread}

    @app.post("/api/admin/comments/{comment_id}/feedback")
    async def feedback_comment_endpoint(
        comment_id: int, request: Request, _: str = Depends(require_admin)
    ):
        body = await request.json()
        label = str(body.get("label", "_decision"))
        agreed = bool(body.get("agreed", True))
        human_decision = body.get("human_decision")
        if human_decision is not None:
            human_decision = int(human_decision)
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            res = evaluator.record_feedback(
                db,
                org,
                comment_id,
                label=label,
                agreed=agreed,
                human_decision=human_decision,
                actor="owner",
            )
            audit.append(
                db,
                org,
                "owner",
                "comment.feedback_recorded",
                str(comment_id),
                {"label": label, "agreed": agreed, "human_decision": human_decision},
            )
            thread = store.comment_thread(db, org, comment_id)
        return {"ok": True, "feedback": res, "thread": thread}

    @app.post("/api/admin/comments/{comment_id}/state")
    async def update_comment_state(
        comment_id: int, request: Request, _: str = Depends(require_admin)
    ):
        body = await request.json()
        status = str(body.get("status", "needs_reply"))
        bucket = body.get("bucket")
        assigned_to = body.get("assigned_to")
        note = body.get("note")
        if status not in store.COMMENT_STATUSES:
            raise HTTPException(422, "Invalid status")
        if bucket is not None and bucket not in store.COMMENT_BUCKETS:
            raise HTTPException(422, "Invalid bucket")
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                "SELECT * FROM comment_states WHERE organization_id=? AND comment_id=?",
                (org, comment_id),
            ).fetchone()
            eff_bucket = bucket or (cur["bucket"] if cur else "needs_review")
            eff_assigned = assigned_to if assigned_to is not None else (cur["assigned_to"] if cur else "")
            eff_note = note if note is not None else (cur["note"] if cur else "")
            db.execute(
                """INSERT INTO comment_states
                   (organization_id, comment_id, status, bucket, assigned_to, note, updated_by, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'owner', ?)
                   ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                    status=excluded.status,
                    bucket=excluded.bucket,
                    assigned_to=excluded.assigned_to,
                    note=excluded.note,
                    updated_by='owner',
                    updated_at=excluded.updated_at""",
                (org, comment_id, status, eff_bucket, eff_assigned, eff_note, now),
            )
            audit.append(
                db,
                org,
                "owner",
                "comment.state_updated",
                str(comment_id),
                {"status": status, "bucket": eff_bucket, "assigned_to": eff_assigned},
            )
            thread = store.comment_thread(db, org, comment_id)
        return {"ok": True, "thread": thread}

    @app.post("/api/admin/comments/{comment_id}/drafts")
    async def save_comment_draft(
        comment_id: int, request: Request, _: str = Depends(require_admin)
    ):
        body = await request.json()
        text = str(body.get("text", "")).strip()
        kind = str(body.get("kind", "public"))
        status = str(body.get("status", "approved"))
        strategy_summary = str(body.get("strategy_summary", "")).strip()
        if not text or kind not in ("public", "private_dm") or status not in ("draft", "approved", "sent", "rejected"):
            raise HTTPException(422, "Valid text, kind, and status are required")
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                """INSERT INTO reply_drafts
                   (organization_id, comment_id, kind, strategy_summary, text, created_by, status, approved_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, 'owner', ?, ?, ?, ?)""",
                (
                    org,
                    comment_id,
                    kind,
                    strategy_summary,
                    text,
                    status,
                    "owner" if status == "approved" else None,
                    now,
                    now,
                ),
            )
            if status in ("approved", "sent"):
                db.execute(
                    """INSERT INTO comment_states (organization_id, comment_id, status, updated_by, updated_at)
                       VALUES (?, ?, 'replied', 'owner', ?)
                       ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                        status='replied', updated_by='owner', updated_at=excluded.updated_at""",
                    (org, comment_id, now),
                )
            audit.append(
                db,
                org,
                "owner",
                f"reply_draft.{status}",
                str(cur.lastrowid),
                {"comment_id": comment_id, "kind": kind},
            )
            thread = store.comment_thread(db, org, comment_id)
        return {"ok": True, "draft_id": cur.lastrowid, "thread": thread}

    @app.get("/api/admin/evidence")
    def list_evidence_cases(_: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            cases = []
            for row in db.execute(
                "SELECT * FROM evidence_cases WHERE organization_id=? ORDER BY id DESC", (org,)
            ).fetchall():
                c = dict(row)
                c["items"] = [
                    {**dict(it), "artifacts": json.loads(it["artifacts_json"] or "{}")}
                    for it in db.execute(
                        "SELECT * FROM evidence_items WHERE organization_id=? AND case_id=? ORDER BY id DESC",
                        (org, c["id"]),
                    ).fetchall()
                ]
                cases.append(c)
            return {"cases": cases}

    @app.post("/api/admin/evidence/capture")
    async def capture_evidence_endpoint(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        target_url = str(body.get("target_url", "")).strip()
        title = str(body.get("title", "")).strip()
        comment_id = body.get("comment_id")
        case_id = body.get("case_id")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            res = conn_mod.capture_forensic_evidence(
                db,
                org,
                target_url=target_url,
                title=title,
                comment_id=int(comment_id) if comment_id is not None else None,
                case_id=int(case_id) if case_id is not None else None,
                actor="owner",
            )
        return res

    @app.get("/api/admin/fleet")
    def list_fleet(_: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            runtimes = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM account_runtimes WHERE organization_id=? ORDER BY id ASC",
                    (org,),
                ).fetchall()
            ]
            leases = [
                dict(l)
                for l in db.execute(
                    "SELECT * FROM runtime_leases WHERE organization_id=? ORDER BY id DESC LIMIT 30",
                    (org,),
                ).fetchall()
            ]
            return {"runtimes": runtimes, "leases": leases}

    @app.post("/api/admin/fleet")
    async def save_fleet_runtime(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        label = str(body.get("label", "")).strip()
        platform = str(body.get("platform", "facebook")).strip()
        account_role = str(body.get("account_role", "care_consultant")).strip()
        adapter = str(body.get("adapter", "veilbrowser")).strip()
        runtime_profile_id = str(body.get("runtime_profile_id", "")).strip()
        expected_exit_ip = str(body.get("expected_exit_ip", "")).strip()
        expected_country = str(body.get("expected_country", "FR")).strip()
        health_status = str(body.get("health_status", "healthy")).strip()
        daily_read_budget = int(body.get("daily_read_budget", 120))
        daily_write_budget = 0 if account_role == "personal_main" else int(body.get("daily_write_budget", 20))
        if not label or not runtime_profile_id or adapter not in store.CHANNEL_ADAPTERS:
            raise HTTPException(422, "Valid label, adapter, and runtime_profile_id are required")
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                """INSERT INTO account_runtimes
                   (organization_id, label, platform, account_role, adapter, runtime_profile_id,
                    expected_exit_ip, expected_country, health_status, daily_read_budget, daily_write_budget, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(organization_id, adapter, runtime_profile_id) DO UPDATE SET
                    label=excluded.label,
                    account_role=excluded.account_role,
                    expected_exit_ip=excluded.expected_exit_ip,
                    expected_country=excluded.expected_country,
                    health_status=excluded.health_status,
                    daily_read_budget=excluded.daily_read_budget,
                    daily_write_budget=excluded.daily_write_budget,
                    updated_at=excluded.updated_at""",
                (
                    org,
                    label,
                    platform,
                    account_role,
                    adapter,
                    runtime_profile_id,
                    expected_exit_ip,
                    expected_country,
                    health_status,
                    daily_read_budget,
                    daily_write_budget,
                    now,
                ),
            )
            audit.append(
                db,
                org,
                "owner",
                "fleet.runtime_saved",
                runtime_profile_id,
                {"adapter": adapter, "account_role": account_role, "health_status": health_status},
            )
        return {"ok": True, "id": cur.lastrowid, "runtime_profile_id": runtime_profile_id}

    @app.get("/api/admin/rules")
    def list_rules(_: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            return {
                "rules": [
                    dict(r)
                    for r in db.execute(
                        "SELECT * FROM rules WHERE organization_id=? ORDER BY id DESC", (org,)
                    ).fetchall()
                ]
            }

    @app.post("/api/admin/rules")
    async def save_rule(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        name = str(body.get("name", "")).strip()
        pattern = str(body.get("pattern", "")).strip()
        match_kind = str(body.get("match_kind", "keyword")).strip()
        flag = str(body.get("flag", "flagged")).strip()
        auto_status = str(body.get("auto_status", "needs_reply")).strip()
        auto_bucket = str(body.get("auto_bucket", "needs_review")).strip()
        if not name or not pattern or auto_status not in store.COMMENT_STATUSES or auto_bucket not in store.COMMENT_BUCKETS:
            raise HTTPException(422, "Valid rule name, pattern, status, and bucket required")
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO rules
                   (organization_id, name, pattern, match_kind, flag, auto_status, auto_bucket, enabled, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                   ON CONFLICT(organization_id, name) DO UPDATE SET
                    pattern=excluded.pattern,
                    match_kind=excluded.match_kind,
                    flag=excluded.flag,
                    auto_status=excluded.auto_status,
                    auto_bucket=excluded.auto_bucket""",
                (org, name, pattern, match_kind, flag, auto_status, auto_bucket, now),
            )
            audit.append(db, org, "owner", "rule.saved", name, {"pattern": pattern, "auto_bucket": auto_bucket})
        return {"ok": True, "name": name}

    @app.post("/api/admin/jobs/run")
    def trigger_worker_jobs(_: str = Depends(require_admin)):
        return worker.run_pending_jobs(path, org, limit=15)

    @app.get("/api/admin/connector")
    def connector_info(_: str = Depends(require_admin)):
        cfg = current_settings()
        return {
            "audience": AUDIENCE,
            "namespace": "care__*",
            "endpoint": (cfg["public_base_url"] or "") + "/mcp",
            "transport": "streamable-http",
            "bearer_configured": bool(bearer),
            "delegation_secret_configured": bool(del_secret),
            "require_delegation": require_delegation,
            "writes_enabled": writes_enabled,
            "max_scopes": cfg["mcp_max_scopes"],
            "available_scopes": sorted(SCOPES),
            "tools": {k: sorted(v) for k, v in TOOL_SCOPES.items()},
        }

    @app.get("/api/admin/audit")
    def get_audit(_: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            return {"events": audit.list_recent(db, org), **audit.verify(db, org)}

    @app.get("/api/admin/audit/verify")
    def verify_audit(_: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            return audit.verify(db, org)

    @app.get("/api/settings")
    def get_settings(_: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            return settings.load_with_sources(db, org, env)

    @app.post("/api/settings")
    async def post_settings(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        try:
            with store.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                saved = settings.save(db, org, body, env)
                audit.append(
                    db, org, "owner", "settings.updated", "runtime", {"keys": sorted(body.keys())}
                )
                return saved
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/")
    def root(request: Request):
        if _verify_session_cookie(mgmt_key, request.cookies.get("lnc_care_session")):
            return RedirectResponse("/admin/", status_code=303)
        return RedirectResponse("/login.html", status_code=303)

    @app.get("/login.html")
    def login_page():
        return FileResponse(PUBLIC / "login.html")

    @app.get("/admin")
    @app.get("/admin/")
    def admin_page(request: Request):
        if not _verify_session_cookie(mgmt_key, request.cookies.get("lnc_care_session")):
            return RedirectResponse("/login.html", status_code=303)
        return FileResponse(PUBLIC / "index.html")

    @app.get("/icon.svg")
    def icon_svg():
        return FileResponse(PUBLIC / "icon.svg", media_type="image/svg+xml")

    @app.get("/icon.png")
    def icon_png():
        return FileResponse(PUBLIC / "icon.png", media_type="image/png")

    @app.get("/favicon.ico")
    def favicon():
        return FileResponse(PUBLIC / "favicon.ico", media_type="image/x-icon")

    @app.get("/style.css")
    @app.get("/admin/style.css")
    def style_css():
        return FileResponse(PUBLIC / "style.css", media_type="text/css")

    @app.get("/app.js")
    @app.get("/admin/app.js")
    def app_js():
        return FileResponse(PUBLIC / "app.js", media_type="application/javascript")

    async def mcp_root_redirect(scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/mcp":
            headers = Headers(scope=scope)
            if not headers.get("authorization"):
                await JSONResponse({"error": "Invalid MCP bearer token"}, status_code=401)(
                    scope, receive, send
                )
                return
            scope = {**scope, "path": "/mcp/", "raw_path": b"/mcp/"}
        await app(scope, receive, send)

    app.mount("/mcp", mcp_asgi)
    app.mcp_entry = mcp_root_redirect  # type: ignore[attr-defined]
    return app


app = create_app()
