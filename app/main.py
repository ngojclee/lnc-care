"""FastAPI application for LNC Care (`/admin`, `/api/*`, `/webhooks/meta`, `/mcp`)."""
from collections import defaultdict
import hashlib
import hmac
import json
import os
import secrets
import socket
import time
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
import httpx

from . import (
    agent_hub,
    audit,
    connections as conn_mod,
    evaluator,
    internal_bridge,
    mcp_gateway,
    settings,
    store,
    worker,
)
from .connections import Connections
from .mcp_server import AUDIENCE, SCOPES, TOOL_SCOPES, build_mcp_asgi
from .providers import ProviderError
from .vault import Vault, VaultError

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = Path(__file__).resolve().parent / "public"
VERSION = (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").exists() else "0.2.0.0"


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
    bridge_config: internal_bridge.BridgeConfig | None = None,
    hub_config: agent_hub.AgentHubConfig | None = None,
    mcp_gateway_config: mcp_gateway.McpGatewayConfig | None = None,
    agent_hub_transport=None,
    ads_bridge_transport=None,
    mcp_gateway_transport=None,
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
    env_mgmt_key = (
        management_key
        if management_key is not None
        else (
            env.get("MANAGEMENT_KEY")
            or env.get("MANAGEMENT_TOKEN")
            or env.get("LNC_MANAGEMENT_KEY")
            or env.get("LNC_ADMIN_TOKEN")
            or env.get("EDGE_KEY")
            or ""
        )
    ).strip()
    bootstrap_mgmt_key = (
        ""
        if management_key is not None
        else (
            env.get("CARE_ADMIN_BOOTSTRAP_KEY")
            or env.get("LNC_ADMIN_BOOTSTRAP_KEY")
            or ""
        ).strip()
    )
    env_api_keys = [
        k.strip()
        for k in (env.get("LNC_API_KEYS") or "").split(",")
        if k.strip()
    ]
    boot_ts = int(time.time())
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
    audience = (
        env.get("CONNECTOR_AUDIENCE")
        or env.get("LNC_MCP_AUDIENCE")
        or AUDIENCE
    ).strip() or AUDIENCE
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
        if not env_mgmt_key and bootstrap_mgmt_key:
            existing_mgmt = db.execute(
                "SELECT value FROM runtime_settings WHERE organization_id=? AND key='__mgmt_state'",
                (org,),
            ).fetchone()
            if existing_mgmt is None:
                salt = secrets.token_hex(16)
                digest = hashlib.pbkdf2_hmac(
                    "sha256", bootstrap_mgmt_key.encode(), salt.encode(), 200_000
                ).hex()
                state_obj = {
                    "salt": salt,
                    "hash": digest,
                    "prefix": bootstrap_mgmt_key[:12],
                    "session_secret": secrets.token_urlsafe(32),
                    "created_at": int(time.time()),
                }
                db.execute(
                    "INSERT INTO runtime_settings(organization_id, key, value) VALUES (?, '__mgmt_state', ?)",
                    (org, json.dumps(state_obj)),
                )

    bridge = bridge_config if bridge_config is not None else internal_bridge.bridge_config(env)
    ads_bridge = (
        internal_bridge.AdsBridgeClient(bridge, transport=ads_bridge_transport)
        if bridge is not None
        else None
    )
    eff_hub_cfg = hub_config if hub_config is not None else agent_hub.agent_hub_config(env)
    if eff_hub_cfg is None and ads_bridge is not None:
        eff_hub_cfg = agent_hub.AgentHubConfig(
            url="",
            public_url="",
            api_key="",
            self_id=bridge.self_id if bridge else "lnc-care",
        )
    hub_client = (
        agent_hub.AgentHubClient(
            eff_hub_cfg, ads_bridge=ads_bridge, transport=agent_hub_transport
        )
        if eff_hub_cfg is not None
        else None
    )
    eff_gw_cfg = (
        mcp_gateway_config
        if mcp_gateway_config is not None
        else mcp_gateway.mcp_gateway_config(env)
    )
    gw_client = (
        mcp_gateway.McpGatewayClient(eff_gw_cfg, transport=mcp_gateway_transport)
        if eff_gw_cfg is not None
        else None
    )

    conns = Connections(path, org, vault, transport=transport, hub_client=hub_client)
    mcp_asgi, mcp_lifespan = build_mcp_asgi(
        path,
        org,
        bearer,
        del_secret,
        require_delegation,
        writes_enabled=writes_enabled,
        mcp_gateway=gw_client,
        audience=audience,
        vault=vault,
    )

    app = FastAPI(title="LNC Care", version=VERSION, lifespan=mcp_lifespan)
    attempts: dict[str, list[float]] = defaultdict(list)

    def _load_runtime_mgmt() -> dict | None:
        with store.connect_readonly(path) as db:
            row = db.execute(
                "SELECT value FROM runtime_settings WHERE organization_id=? AND key='__mgmt_state'",
                (org,),
            ).fetchone()
        if row is None:
            return None
        try:
            parsed = json.loads(row["value"])
            if not all(k in parsed for k in ("salt", "hash", "session_secret")):
                raise ValueError("incomplete")
            return parsed
        except Exception as exc:
            raise HTTPException(500, "management_state_corrupt") from exc

    def _session_signing_key() -> str:
        if env_mgmt_key:
            return env_mgmt_key
        rt = _load_runtime_mgmt()
        return str(rt["session_secret"]) if rt else ""

    def _verify_mgmt_secret(candidate: str) -> bool:
        if not candidate:
            return False
        if env_mgmt_key:
            return secrets.compare_digest(candidate, env_mgmt_key)
        rt = _load_runtime_mgmt()
        if not rt:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", candidate.encode(), str(rt["salt"]).encode(), 200_000
        ).hex()
        return secrets.compare_digest(digest, str(rt["hash"]))

    def _mgmt_inventory() -> dict:
        if env_mgmt_key:
            return {
                "configured": True,
                "prefix": (env_mgmt_key[:8] + "…") if len(env_mgmt_key) > 8 else "env_****",
                "source": "environment",
                "rotatable": False,
                "bootstrap_ignored": False,
            }
        rt = _load_runtime_mgmt()
        if rt:
            return {
                "configured": True,
                "prefix": (str(rt.get("prefix") or "")[:10] + "…") if rt.get("prefix") else "care_mgmt…",
                "created_at": rt.get("created_at"),
                "source": "runtime",
                "rotatable": True,
                "bootstrap_ignored": bool(bootstrap_mgmt_key),
            }
        return {
            "configured": False,
            "prefix": "",
            "source": "none",
            "rotatable": True,
            "bootstrap_ignored": False,
        }

    def current_settings() -> dict:
        with store.connect_readonly(path) as db:
            return settings.load(db, org, env)

    def public_base(request: Request | None = None) -> str:
        cfg = current_settings()
        if cfg.get("public_base_url"):
            return str(cfg["public_base_url"]).rstrip("/")
        if request is not None:
            proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "http"
            host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc or "localhost"
            return f"{proto.split(',')[0].strip()}://{host.split(',')[0].strip()}".rstrip("/")
        return ""

    def check_rate(bucket: str, limit: int, window: int = 60) -> None:
        now = time.time()
        items = [t for t in attempts[bucket] if now - t < window]
        if len(items) >= limit:
            raise HTTPException(429, "Rate limit exceeded")
        items.append(now)
        attempts[bucket] = items

    def _verify_api_key(token: str) -> str | None:
        tok = token.strip()
        if not tok:
            return None
        if _verify_mgmt_secret(tok):
            return "mgmt"
        for idx, ek in enumerate(env_api_keys):
            if secrets.compare_digest(tok, ek):
                return f"env:{idx}"
        key_hash = hashlib.sha256(tok.encode()).hexdigest()
        with store.connect_readonly(path) as db:
            row = db.execute(
                "SELECT id, status FROM api_keys WHERE organization_id=? AND key_hash=?",
                (org, key_hash),
            ).fetchone()
        if row and row["status"] == "enabled":
            return f"key:{row['id']}"
        return None

    def require_admin(request: Request) -> str:
        sig_key = _session_signing_key()
        session_hash = _verify_session_cookie(sig_key, request.cookies.get("lnc_care_session"))
        if not session_hash:
            raise HTTPException(401, "Authentication required")
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            csrf_cookie = request.cookies.get("lnc_care_csrf", "")
            csrf_header = request.headers.get("x-csrf-token", "")
            if not csrf_cookie or not secrets.compare_digest(csrf_cookie, csrf_header):
                raise HTTPException(403, "CSRF token required")
        return session_hash

    def require_api_or_admin(request: Request) -> str:
        auth = request.headers.get("authorization", "")
        raw_tok = ""
        if auth.lower().startswith("bearer "):
            raw_tok = auth[7:].strip()
        elif request.headers.get("x-api-key"):
            raw_tok = request.headers.get("x-api-key", "").strip()
        elif request.headers.get("x-token"):
            raw_tok = request.headers.get("x-token", "").strip()
        elif request.query_params.get("token"):
            raw_tok = request.query_params.get("token", "").strip()
        if raw_tok:
            principal = _verify_api_key(raw_tok)
            if principal:
                return principal
            raise HTTPException(401, "Invalid or revoked API key")
        sig_key = _session_signing_key()
        session_hash = _verify_session_cookie(sig_key, request.cookies.get("lnc_care_session"))
        if session_hash:
            return session_hash
        raise HTTPException(401, "Authentication required")

    def _issue_admin_cookies(request: Request, response: Response) -> str:
        sig_key = _session_signing_key()
        sid, csrf = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        secure = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").lower() == "https"
        )
        response.set_cookie(
            "lnc_care_session",
            _session_cookie_value(sig_key, sid, int(time.time()) + 43200),
            httponly=True,
            samesite="lax",
            secure=secure,
            path="/",
        )
        response.set_cookie(
            "lnc_care_csrf", csrf, httponly=False, samesite="lax", secure=secure, path="/"
        )
        return csrf

    def _bridge_summary() -> dict:
        if bridge is None:
            return {
                "enabled": False,
                "self_id": "lnc-care",
                "peers": {},
                "ads_internal_url": None,
            }
        return {
            "enabled": True,
            "self_id": bridge.self_id,
            "peers": dict(bridge.peers),
            "ads_internal_url": bridge.ads_internal_url,
        }

    def _hub_summary(*, force: bool = False) -> dict:
        if hub_client is None:
            return {
                "configured": False,
                "has_api_key": False,
                "url": "",
                "public_url": "",
                "reachable": False,
                "platform_api_ready": False,
                "bridge_fallback_ready": False,
                "mode": "standalone_local_vault",
                "sso_path": None,
                "last_sync_at": None,
                "last_sync_source": None,
                "last_warning": None,
            }
        return hub_client.status_summary(force=force)

    def _gateway_summary() -> dict:
        if gw_client is None:
            return {
                "configured": False,
                "has_api_key": False,
                "gateway_url": "",
                "route": "lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)",
                "allowed_prefixes": list(mcp_gateway.ALLOWED_CROSS_APP_PREFIXES),
            }
        return gw_client.status_summary()

    local_hosts = {
        "localhost",
        "127.0.0.1",
        "::1",
        "testserver",
        socket.gethostname().lower(),
    }

    @app.middleware("http")
    async def host_gate(request: Request, call_next):
        req_path = request.url.path
        if req_path not in ("/health", "/webhooks/meta"):
            cfg = current_settings()
            host = (request.headers.get("host") or "").split(":")[0].strip("[]").lower()
            allowed = {h.lower() for h in cfg["allowed_hosts"]} | local_hosts
            if req_path.startswith("/api/internal/bridge/"):
                allowed = allowed | (
                    bridge.internal_hosts if bridge else internal_bridge.DEFAULT_INTERNAL_HOSTS
                )
            if "*" not in allowed and host and host not in allowed:
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

    @app.exception_handler(agent_hub.AgentHubError)
    async def handle_hub_error(_: Request, exc: agent_hub.AgentHubError):
        return Response(
            content=json.dumps({"detail": exc.code}),
            status_code=exc.status,
            media_type="application/json",
        )

    @app.exception_handler(mcp_gateway.McpGatewayError)
    async def handle_mcp_gateway_error(_: Request, exc: mcp_gateway.McpGatewayError):
        return Response(
            content=json.dumps({"detail": exc.code}),
            status_code=exc.status,
            media_type="application/json",
        )

    @app.exception_handler(internal_bridge.BridgeClientError)
    async def handle_bridge_client_error(_: Request, exc: internal_bridge.BridgeClientError):
        return Response(
            content=json.dumps({"detail": exc.code}),
            status_code=exc.status,
            media_type="application/json",
        )

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "service": audience,
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
        if not sig_header.startswith("sha256="):
            raise HTTPException(403, "webhook_signature_missing")

        with store.connect_readonly(path) as db:
            secret_env = vault.get(db, org, "app", "meta")
        env_secret = env.get("META_APP_SECRET", "")
        local_secret = (
            secret_env.get("client_secret", "")
            if secret_env and secret_env.get("client_secret")
            else env_secret
        )

        if hub_client is not None:
            has_verifier = bool(
                local_secret or hub_client.cfg.api_key or hub_client.ads_bridge is not None
            )
            if not has_verifier:
                raise HTTPException(403, "webhook_signature_missing")
            valid = hub_client.verify_meta_webhook(
                path, org, vault, raw_body, sig_header, env_secret=env_secret
            )
            if not valid:
                raise HTTPException(403, "webhook_signature_invalid")
        else:
            if not local_secret:
                raise HTTPException(403, "webhook_signature_missing")
            expected_sig = (
                "sha256=" + hmac.new(local_secret.encode(), raw_body, hashlib.sha256).hexdigest()
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
                    if change.get("field") in ("feed", "comments", "mentions", "messages"):
                        worker.enqueue_job(
                            db,
                            org,
                            "fetch_comments",
                            {"entry_id": entry.get("id"), "field": change.get("field"), "value": val},
                        )
                        enqueued += 1
        return {"ok": True, "deduplicated": False, "enqueued": enqueued}

    @app.get("/api/app-info")
    def app_info():
        return {"service": audience, "name": "LNC Care", "version": VERSION}

    @app.get("/api/auth/status")
    def auth_status(request: Request):
        sig_key = _session_signing_key()
        authenticated = bool(
            _verify_session_cookie(sig_key, request.cookies.get("lnc_care_session"))
        )
        csrf_val = request.cookies.get("lnc_care_csrf", "") if authenticated else ""
        return {
            "ok": authenticated,
            "authenticated": authenticated,
            "service": audience,
            "version": VERSION,
            "csrf": csrf_val,
            "csrf_token": csrf_val,
        }

    @app.post("/api/auth/login")
    async def login(request: Request, response: Response):
        check_rate(f"login:{request.client.host if request.client else 'local'}", 8, window=300)
        body = await request.json()
        key = str(body.get("key") or body.get("token") or body.get("password") or "")
        if not _verify_mgmt_secret(key):
            raise HTTPException(401, "Invalid management key")
        csrf = _issue_admin_cookies(request, response)
        with store.connect(path) as db:
            audit.append(db, org, "owner", "auth.login", "admin_session", {})
        return {"ok": True, "authenticated": True, "csrf": csrf, "csrf_token": csrf}

    @app.get("/api/auth/logout")
    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        if request.method == "POST":
            _ = require_admin(request)
        response.delete_cookie("lnc_care_session", path="/")
        response.delete_cookie("lnc_care_csrf", path="/")
        if request.method == "GET":
            return RedirectResponse("/login.html", status_code=303)
        return {"ok": True}

    # --- 3-Way Universal Operator SSO (`LNC Agent Hub` <-> `LNC Care` <-> `LNC Ads`) ---

    @app.get("/api/auth/sso/redirect")
    def sso_redirect(
        request: Request,
        peer: str,
        next: str = "/admin/#overview",
        session_hash: str = Depends(require_admin),
    ):
        check_rate(f"sso_mint:{session_hash}", 20)
        target_peer = peer.strip().lower()

        if target_peer == "lnc-agent-hub":
            if hub_client is None:
                raise HTTPException(503, "agent_hub_not_configured")
            safe_hub_next = internal_bridge.safe_relative_next(next, default="/")
            target_url = hub_client.mint_sso_redirect_url(
                audience="lnc-agent-hub", next_path=safe_hub_next, subject="owner"
            )
            with store.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                audit.append(
                    db,
                    org,
                    "owner",
                    "sso.ticket_minted",
                    target_peer,
                    {"via": "lnc-agent-hub"},
                )
            return RedirectResponse(target_url, status_code=303)

        safe_next = internal_bridge.safe_relative_next(next, default="/admin/#overview")
        if hub_client is not None and hub_client.cfg.api_key:
            st = hub_client.status_summary()
            if st.get("platform_api_ready"):
                target_url = hub_client.mint_sso_redirect_url(
                    audience=target_peer, next_path=safe_next, subject="owner"
                )
                with store.connect(path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    audit.append(
                        db,
                        org,
                        "owner",
                        "sso.ticket_minted",
                        target_peer,
                        {"via": "lnc-agent-hub"},
                    )
                return RedirectResponse(target_url, status_code=303)

        ticket = internal_bridge.mint_sso_ticket(bridge, audience=target_peer, subject="owner")
        assert bridge is not None
        peer_origin = bridge.peers[target_peer]
        consume_url = f"{peer_origin}/api/auth/sso/consume?{urlencode({'ticket': ticket, 'next': safe_next})}"
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            audit.append(
                db,
                org,
                "owner",
                "sso.ticket_minted",
                target_peer,
                {"via": "internal_bridge"},
            )
        return RedirectResponse(consume_url, status_code=303)

    @app.get("/api/auth/sso/consume")
    def sso_consume(
        request: Request,
        ticket: str,
        next: str = "/admin/#inbox",
    ):
        check_rate(f"sso_consume:{request.client.host if request.client else 'local'}", 20)
        if not _session_signing_key():
            raise HTTPException(503, "management_key_not_configured")

        clean_ticket = ticket.strip()
        if clean_ticket.startswith("lnc_sso_"):
            if hub_client is None:
                raise HTTPException(503, "agent_hub_not_configured")
            claims = hub_client.redeem_sso_ticket(clean_ticket)
            via = "lnc-agent-hub"
        else:
            claims = internal_bridge.consume_sso_ticket(bridge, clean_ticket, path, org)
            via = "internal_bridge"

        safe_dest = internal_bridge.safe_relative_next(next, default="/admin/#inbox")
        redirect = RedirectResponse(safe_dest, status_code=303)
        _issue_admin_cookies(request, redirect)
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            audit.append(
                db,
                org,
                str(claims.get("sub") or "owner"),
                "sso.ticket_consumed",
                str(claims.get("iss") or via),
                {"via": via, "next": safe_dest},
            )
        return redirect

    # --- Inbound Server-to-Server LAN Bridge (`/api/internal/bridge/*`) ---

    @app.get("/api/internal/bridge/status")
    async def inbound_bridge_status(request: Request):
        raw = await request.body()
        peer = internal_bridge.authenticate(bridge, request, raw, path, org)
        assert bridge is not None
        return {
            "ok": True,
            "service": "LNC Care",
            "self_id": bridge.self_id,
            "caller_peer": peer,
            "organization": org,
            "version": VERSION,
            "vault_ready": True,
        }

    @app.get("/api/internal/bridge/shops")
    async def inbound_bridge_shops(request: Request):
        raw = await request.body()
        internal_bridge.authenticate(bridge, request, raw, path, org)
        with store.connect_readonly(path) as db:
            return {"shops": store.shops(db, org)}

    @app.get("/api/internal/bridge/channels")
    async def inbound_bridge_channels(request: Request, shop: str | None = None):
        raw = await request.body()
        internal_bridge.authenticate(bridge, request, raw, path, org)
        with store.connect_readonly(path) as db:
            shop_id = None
            if shop:
                srow = db.execute(
                    "SELECT id FROM shops WHERE organization_id=? AND LOWER(name)=LOWER(?)",
                    (org, shop.strip()),
                ).fetchone()
                if srow:
                    shop_id = int(srow["id"])
                else:
                    return {"shop": shop, "channels": []}
            return {
                "shop": shop,
                "shop_id": shop_id,
                "channels": store.channels(db, org, shop_id=shop_id, approved_only=True),
            }

    # --- Admin Hub, Shared Vault Sync, Shared OAuth & MCP Gateway ---

    @app.get("/api/admin/hub/status")
    def get_hub_status(refresh: bool = False, _: str = Depends(require_admin)):
        return {
            "agent_hub": _hub_summary(force=refresh),
            "bridge": _bridge_summary(),
            "mcp_gateway": _gateway_summary(),
        }

    @app.post("/api/admin/hub/sync")
    def trigger_hub_sync(session_hash: str = Depends(require_admin)):
        check_rate(f"hub_sync:{session_hash}", 12)
        if hub_client is None:
            raise HTTPException(409, "agent_hub_or_bridge_not_configured")
        return hub_client.sync(path, org, vault)

    @app.post("/api/admin/oauth/shared/start")
    async def start_shared_oauth_endpoint(
        request: Request, session_hash: str = Depends(require_admin)
    ):
        check_rate(f"shared_oauth:{session_hash}", 10)
        if hub_client is None:
            raise HTTPException(409, "agent_hub_or_bridge_not_configured")
        body = await request.json()
        provider = str(body.get("provider", "meta")).strip()
        shop = str(body.get("shop", "")).strip()
        label = str(body.get("label", "")).strip()
        extra_scopes = str(body.get("extra_scopes", "")).strip()
        if provider not in store.PROVIDERS or not shop:
            raise HTTPException(422, "Valid provider and shop name are required")
        cfg = current_settings()
        base = cfg["public_base_url"] or f"{request.url.scheme}://{request.headers.get('host', 'localhost')}"
        return_to = str(body.get("return_to") or f"{base}/admin/#channels").strip()
        started = hub_client.start_shared_oauth(
            provider=provider,
            shop=shop,
            label=label,
            return_to=return_to,
            extra_scopes=extra_scopes,
        )
        if not started:
            raise HTTPException(503, "shared_oauth_broker_unavailable")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            audit.append(
                db,
                org,
                "owner",
                "oauth.shared_started",
                provider,
                {"shop": shop, "via": started.get("via")},
            )
        return started

    @app.get("/api/admin/mcp-gateway/status")
    def get_mcp_gateway_status(_: str = Depends(require_admin)):
        return _gateway_summary()

    @app.post("/api/admin/mcp-gateway/call")
    async def call_mcp_gateway_endpoint(
        request: Request, session_hash: str = Depends(require_admin)
    ):
        check_rate(f"mcp_gw:{session_hash}", 20)
        if gw_client is None:
            raise HTTPException(409, "mcp_gateway_not_configured")
        body = await request.json()
        tool_name = str(body.get("tool") or body.get("name") or "").strip()
        arguments = body.get("arguments") or {}
        if not tool_name:
            raise HTTPException(422, "tool name is required")
        return gw_client.call_tool(tool_name, arguments)

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
                "agent_hub": _hub_summary(),
                "bridge": _bridge_summary(),
                "mcp_gateway": _gateway_summary(),
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

    @app.post("/api/admin/purge-demo")
    def purge_demo(_: str = Depends(require_admin)):
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            return conn_mod.purge_demo_workspace(db, org, actor="owner")

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
            shop_id = cur.lastrowid
        if hub_client is not None:
            hub_client.try_push_shop(name)
        return {"id": shop_id, "name": name}

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
        session_hash = _verify_session_cookie(
            _session_signing_key(), request.cookies.get("lnc_care_session")
        )
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

    @app.get("/api/admin/conversations")
    def list_conversations(
        shop_id: int | None = None,
        channel_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
        _: str = Depends(require_admin),
    ):
        with store.connect_readonly(path) as db:
            return {
                "conversations": store.conversations_list(
                    db, org, shop_id=shop_id, channel_id=channel_id, status=status, limit=limit
                )
            }

    @app.get("/api/admin/conversations/{conversation_id}/messages")
    def list_conversation_messages(
        conversation_id: int, limit: int = 100, _: str = Depends(require_admin)
    ):
        with store.connect_readonly(path) as db:
            conv = db.execute(
                "SELECT * FROM conversations WHERE organization_id=? AND id=?",
                (org, conversation_id),
            ).fetchone()
            if not conv:
                raise HTTPException(404, "Conversation not found")
            return {
                "conversation": dict(conv),
                "messages": store.messages_list(db, org, conversation_id, limit=limit),
            }

    @app.post("/api/admin/conversations/{conversation_id}/messages")
    async def send_conversation_message(
        conversation_id: int, request: Request, _: str = Depends(require_admin)
    ):
        body = await request.json()
        text = str(body.get("text") or "").strip()
        if not text:
            raise HTTPException(422, "Message text is required")
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            conv = db.execute(
                """SELECT cv.*, c.reply_policy FROM conversations cv
                   JOIN channels c ON c.id=cv.channel_id AND c.organization_id=cv.organization_id
                   WHERE cv.organization_id=? AND cv.id=?""",
                (org, conversation_id),
            ).fetchone()
            if not conv:
                raise HTTPException(404, "Conversation not found")
            msg_status = "sent" if (writes_enabled and conv["reply_policy"] != "draft_only") else "draft"
            ext_id = f"out_{conversation_id}_{secrets.token_hex(6)}"
            cur = db.execute(
                """INSERT INTO messages
                   (organization_id, conversation_id, channel_id, external_id, direction, sender_id, sender_name, text, status, created_at)
                   VALUES (?, ?, ?, ?, 'outbound', 'owner', 'Care Operator', ?, ?, ?)""",
                (org, conversation_id, conv["channel_id"], ext_id, text, msg_status, now),
            )
            db.execute(
                """UPDATE conversations
                   SET last_message_preview=?, status=?, unread_count=0, updated_at=?
                   WHERE organization_id=? AND id=?""",
                (
                    text[:160],
                    "replied" if msg_status == "sent" else "pending_reply",
                    now,
                    org,
                    conversation_id,
                ),
            )
            audit.append(
                db,
                org,
                "owner",
                f"conversation.message_{msg_status}",
                str(conversation_id),
                {"message_id": cur.lastrowid},
            )
        return {"ok": True, "status": msg_status, "message_id": cur.lastrowid}

    @app.get("/api/admin/leads")
    def list_leads_endpoint(
        shop_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
        _: str = Depends(require_admin),
    ):
        with store.connect_readonly(path) as db:
            return {"leads": store.leads_list(db, org, shop_id=shop_id, status=status, limit=limit)}

    @app.post("/api/admin/leads")
    async def create_lead_endpoint(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        customer_name = str(body.get("customer_name") or "").strip()[:120]
        if not customer_name:
            raise HTTPException(422, "Customer name is required")
        contact_handle = str(body.get("contact_handle") or "").strip()[:120]
        phone = str(body.get("phone") or "").strip()[:40]
        email = str(body.get("email") or "").strip()[:120]
        notes = str(body.get("notes") or "").strip()[:500]
        source = str(body.get("source") or "manual").strip()
        if source not in ("comment", "dm", "meta_lead_ad", "manual"):
            source = "manual"
        shop_id = int(body["shop_id"]) if body.get("shop_id") else None
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                """INSERT INTO leads
                   (organization_id, shop_id, source, customer_name, contact_handle, phone, email, intent_score, status, notes, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 85.0, 'new', ?, ?, ?)""",
                (org, shop_id, source, customer_name, contact_handle, phone, email, notes, now, now),
            )
            audit.append(db, org, "owner", "lead.created", str(cur.lastrowid), {"customer_name": customer_name})
        return {"ok": True, "id": cur.lastrowid}

    @app.get("/api/admin/handoffs")
    def list_handoffs_endpoint(
        shop_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
        _: str = Depends(require_admin),
    ):
        with store.connect_readonly(path) as db:
            return {
                "handoffs": store.handoffs_list(db, org, shop_id=shop_id, status=status, limit=limit)
            }

    @app.post("/api/admin/handoffs")
    async def create_handoff_endpoint(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        summary = str(body.get("summary") or "").strip()[:300]
        if not summary:
            raise HTTPException(422, "Summary is required")
        priority = str(body.get("priority") or "normal").strip()
        if priority not in ("low", "normal", "high", "urgent"):
            priority = "normal"
        assignee = str(body.get("assignee") or "care-team").strip()[:80]
        shop_id = int(body["shop_id"]) if body.get("shop_id") else None
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                """INSERT INTO ticket_handoffs
                   (organization_id, shop_id, priority, assignee, summary, status, created_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, 'open', 'owner', ?, ?)""",
                (org, shop_id, priority, assignee, summary, now, now),
            )
            audit.append(db, org, "owner", "handoff.created", str(cur.lastrowid), {"priority": priority, "assignee": assignee})
        return {"ok": True, "id": cur.lastrowid}

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

    def _pairing_secrets_summary(db) -> dict:
        ui_pair = (vault.get(db, org, "pairing", "connector") if vault.ready else None) or {}
        has_ui_bearer = bool(ui_pair.get("connector_bearer"))
        has_ui_secret = bool(ui_pair.get("delegation_secret"))
        return {
            "connector_bearer": {
                "configured": bool(bearer or has_ui_bearer),
                "source": "environment" if bearer else ("database" if has_ui_bearer else "unset"),
            },
            "delegation_secret": {
                "configured": bool(del_secret or has_ui_secret),
                "source": "environment" if del_secret else ("database" if has_ui_secret else "unset"),
            },
        }

    @app.get("/api/status")
    def api_status(request: Request, _: str = Depends(require_api_or_admin)):
        base = public_base(request)
        with store.connect_readonly(path) as db:
            shops_cnt = db.execute(
                "SELECT COUNT(*) FROM shops WHERE organization_id=?", (org,)
            ).fetchone()[0]
            channels_cnt = db.execute(
                "SELECT COUNT(*) FROM channels WHERE organization_id=? AND approved=1", (org,)
            ).fetchone()[0]
            comments_cnt = db.execute(
                "SELECT COUNT(*) FROM comments WHERE organization_id=?", (org,)
            ).fetchone()[0]
        return {
            "ok": True,
            "service": audience,
            "version": VERSION,
            "uptime_seconds": max(0, int(time.time()) - boot_ts),
            "base_url": base,
            "mcp_endpoint": f"{base}/mcp" if base else "/mcp",
            "writes_enabled": writes_enabled,
            "inventory": {
                "shops": shops_cnt,
                "approved_channels": channels_cnt,
                "comments": comments_cnt,
            },
        }

    # --- The API Page (`/api/keys*` + `/api/mgmt/rotate` + `/api/admin/credentials/*`) ---

    def _keys_inventory_payload(db) -> dict:
        rows = db.execute(
            """SELECT id, label, prefix, status, created_at
               FROM api_keys WHERE organization_id=? ORDER BY id DESC""",
            (org,),
        ).fetchall()
        items: list[dict] = []
        for idx, ek in enumerate(env_api_keys):
            items.append(
                {
                    "id": f"env-{idx + 1}",
                    "label": f"LNC_API_KEYS #{idx + 1}",
                    "prefix": ek[:12],
                    "status": "enabled",
                    "enabled": True,
                    "created_at": boot_ts,
                    "copy_available": False,
                    "source": "environment",
                }
            )
        for r in rows:
            has_copy = False
            if r["status"] != "revoked" and vault.ready:
                stored_sec = vault.get(db, org, "api_key", str(r["id"]))
                has_copy = bool(stored_sec and stored_sec.get("secret"))
            items.append(
                {
                    "id": r["id"],
                    "label": r["label"],
                    "prefix": r["prefix"],
                    "status": r["status"],
                    "enabled": r["status"] == "enabled",
                    "created_at": r["created_at"],
                    "copy_available": has_copy,
                    "source": "runtime",
                }
            )
        mgmt = _mgmt_inventory()
        return {
            "keys": items,
            "mgmt": mgmt,
            "inference": {
                "configured": any(k["enabled"] for k in items),
                "keys": items,
            },
            "management": mgmt,
        }

    @app.get("/api/keys")
    @app.get("/api/admin/credentials/inventory")
    def list_api_keys(_: str = Depends(require_admin)):
        with store.connect_readonly(path) as db:
            return _keys_inventory_payload(db)

    @app.post("/api/keys")
    @app.post("/api/admin/credentials/inference")
    async def create_api_key(request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        label = str(body.get("label") or "").strip()[:80]
        if not label:
            raise HTTPException(422, "Key label is required")
        custom = str(body.get("secret") or body.get("custom") or "").strip()
        if custom:
            if len(custom) < 24:
                raise HTTPException(422, "Custom secret must be at least 24 characters")
            raw_key = custom
        else:
            raw_key = f"care_{secrets.token_urlsafe(24)}"
        prefix = raw_key[:12]
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            dup = db.execute(
                "SELECT id FROM api_keys WHERE organization_id=? AND key_hash=?",
                (org, key_hash),
            ).fetchone()
            if dup:
                raise HTTPException(409, "Key secret already exists")
            cur = db.execute(
                """INSERT INTO api_keys (organization_id, label, prefix, key_hash, status, created_at)
                   VALUES (?, ?, ?, ?, 'enabled', ?)""",
                (org, label, prefix, key_hash, now),
            )
            key_id = int(cur.lastrowid)
            if vault.ready:
                vault.put(db, org, "api_key", str(key_id), {"secret": raw_key})
            audit.append(db, org, "owner", "api_key.created", str(key_id), {"label": label, "prefix": prefix})
        return {
            "key": raw_key,
            "secret": raw_key,
            "item": {
                "id": key_id,
                "label": label,
                "prefix": prefix,
                "status": "enabled",
                "enabled": True,
                "created_at": now,
                "copy_available": vault.ready,
                "source": "runtime",
            },
        }

    @app.post("/api/keys/{key_id}/copy")
    @app.post("/api/admin/credentials/inference/{key_id}/copy")
    def copy_api_key(key_id: int, _: str = Depends(require_admin)):
        with store.connect(path) as db:
            row = db.execute(
                "SELECT id, label, status FROM api_keys WHERE organization_id=? AND id=?",
                (org, key_id),
            ).fetchone()
            if not row or row["status"] == "revoked":
                raise HTTPException(404, "Copyable API key not found")
            env_sec = vault.get(db, org, "api_key", str(key_id)) if vault.ready else None
            if not env_sec or not env_sec.get("secret"):
                raise HTTPException(409, "Secret is not stored for copy")
            audit.append(db, org, "owner", "api_key.copied", str(key_id), {"label": row["label"]})
            return {"key": env_sec["secret"], "secret": env_sec["secret"]}

    @app.patch("/api/keys/{key_id}")
    @app.patch("/api/admin/credentials/inference/{key_id}")
    async def rename_api_key(key_id: int, request: Request, _: str = Depends(require_admin)):
        body = await request.json()
        label = str(body.get("label") or "").strip()[:80]
        if not label:
            raise HTTPException(422, "Key label is required")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id FROM api_keys WHERE organization_id=? AND id=?",
                (org, key_id),
            ).fetchone()
            if not row:
                raise HTTPException(404, "API key not found")
            db.execute(
                "UPDATE api_keys SET label=? WHERE organization_id=? AND id=?",
                (label, org, key_id),
            )
            audit.append(db, org, "owner", "api_key.renamed", str(key_id), {"label": label})
        return {"ok": True, "id": key_id, "label": label}

    @app.post("/api/keys/{key_id}/toggle")
    @app.post("/api/admin/credentials/inference/{key_id}/enable")
    @app.post("/api/admin/credentials/inference/{key_id}/disable")
    def toggle_api_key(key_id: int, request: Request, _: str = Depends(require_admin)):
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id, status FROM api_keys WHERE organization_id=? AND id=?",
                (org, key_id),
            ).fetchone()
            if not row:
                raise HTTPException(404, "API key not found")
            if row["status"] == "revoked":
                raise HTTPException(409, "Revoked API key cannot be re-enabled")
            if request.url.path.endswith("/enable"):
                next_status = "enabled"
            elif request.url.path.endswith("/disable"):
                next_status = "disabled"
            else:
                next_status = "disabled" if row["status"] == "enabled" else "enabled"
            db.execute(
                "UPDATE api_keys SET status=? WHERE organization_id=? AND id=?",
                (next_status, org, key_id),
            )
            audit.append(db, org, "owner", f"api_key.{next_status}", str(key_id), {})
        return {"ok": True, "id": key_id, "status": next_status, "enabled": next_status == "enabled"}

    @app.post("/api/keys/{key_id}/revoke")
    @app.post("/api/admin/credentials/inference/{key_id}/revoke")
    def revoke_api_key(key_id: int, _: str = Depends(require_admin)):
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id, status FROM api_keys WHERE organization_id=? AND id=?",
                (org, key_id),
            ).fetchone()
            if not row:
                raise HTTPException(404, "API key not found")
            db.execute(
                "UPDATE api_keys SET status='revoked' WHERE organization_id=? AND id=?",
                (org, key_id),
            )
            vault.delete(db, org, "api_key", str(key_id))
            audit.append(db, org, "owner", "api_key.revoked", str(key_id), {})
        return {"ok": True, "id": key_id, "status": "revoked", "enabled": False}

    @app.delete("/api/keys/{key_id}")
    @app.delete("/api/admin/credentials/inference/{key_id}")
    def delete_api_key(key_id: int, _: str = Depends(require_admin)):
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id, status FROM api_keys WHERE organization_id=? AND id=?",
                (org, key_id),
            ).fetchone()
            if not row:
                raise HTTPException(404, "API key not found")
            if row["status"] != "revoked":
                raise HTTPException(409, "Revoke the API key before deleting its record")
            vault.delete(db, org, "api_key", str(key_id))
            db.execute("DELETE FROM api_keys WHERE organization_id=? AND id=?", (org, key_id))
            audit.append(db, org, "owner", "api_key.deleted", str(key_id), {})
        return {"ok": True, "id": key_id}

    @app.post("/api/mgmt/rotate")
    @app.post("/api/admin/credentials/management/rotate")
    async def rotate_management_key(
        request: Request, response: Response, _: str = Depends(require_admin)
    ):
        if env_mgmt_key:
            raise HTTPException(409, "management_key_env_managed")
        body = await request.json()
        current_key = str(body.get("current_key") or "").strip()
        rt_existing = _load_runtime_mgmt()
        if rt_existing is not None and (not current_key or not _verify_mgmt_secret(current_key)):
            raise HTTPException(401, "Current management key is required to confirm rotation")
        custom = str(body.get("secret") or "").strip()
        if custom and len(custom) < 16:
            raise HTTPException(422, "Replacement management key must be at least 16 characters")
        new_secret = custom or f"care_mgmt_{secrets.token_urlsafe(24)}"
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", new_secret.encode(), salt.encode(), 200_000).hex()
        state_obj = {
            "salt": salt,
            "hash": digest,
            "prefix": new_secret[:12],
            "session_secret": secrets.token_urlsafe(32),
            "created_at": int(time.time()),
        }
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO runtime_settings(organization_id, key, value) VALUES (?, '__mgmt_state', ?)
                   ON CONFLICT(organization_id, key) DO UPDATE SET value=excluded.value""",
                (org, json.dumps(state_obj)),
            )
            audit.append(db, org, "owner", "mgmt_key.rotated", "runtime", {"prefix": new_secret[:8]})
        response.delete_cookie("lnc_care_session", path="/")
        response.delete_cookie("lnc_care_csrf", path="/")
        return {"ok": True, "key": new_secret, "prefix": new_secret[:12], "source": "runtime"}

    @app.get("/api/admin/connector")
    def connector_info(request: Request, _: str = Depends(require_admin)):
        cfg = current_settings()
        base = public_base(request)
        with store.connect_readonly(path) as db:
            p_sec = _pairing_secrets_summary(db)
        return {
            "audience": audience,
            "namespace": "care__*",
            "endpoint": f"{base}/mcp" if base else "/mcp",
            "transport": "streamable-http",
            "ready": p_sec["connector_bearer"]["configured"] and p_sec["delegation_secret"]["configured"],
            "bearer_configured": p_sec["connector_bearer"]["configured"],
            "bearer_source": p_sec["connector_bearer"]["source"],
            "delegation_secret_configured": p_sec["delegation_secret"]["configured"],
            "delegation_secret_source": p_sec["delegation_secret"]["source"],
            "require_delegation": require_delegation,
            "writes_enabled": writes_enabled,
            "max_scopes": cfg["mcp_max_scopes"],
            "available_scopes": sorted(SCOPES),
            "tools": {k: sorted(v) for k, v in TOOL_SCOPES.items()},
            "mcp_gateway": _gateway_summary(),
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
            res = settings.load_with_sources(db, org, env)
            res["secrets"] = _pairing_secrets_summary(db)
            return res

    @app.post("/api/settings")
    async def post_settings(request: Request, _: str = Depends(require_admin)):
        body = dict(await request.json())
        raw_bearer = body.pop("connector_bearer", None)
        raw_secret = body.pop("delegation_secret", None)
        try:
            with store.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                if body:
                    settings.save(db, org, body, env)
                if raw_bearer is not None or raw_secret is not None:
                    if (raw_bearer and bearer) or (raw_secret and del_secret):
                        raise ValueError("Environment-managed pairing secret cannot be overridden in UI")
                    existing_pair = (vault.get(db, org, "pairing", "connector") if vault.ready else None) or {}
                    updated_pair = dict(existing_pair)
                    if raw_bearer and raw_bearer != "********":
                        updated_pair["connector_bearer"] = str(raw_bearer).strip()
                    if raw_secret and raw_secret != "********":
                        updated_pair["delegation_secret"] = str(raw_secret).strip()
                    if updated_pair != existing_pair:
                        vault.put(db, org, "pairing", "connector", updated_pair)
                saved = settings.load_with_sources(db, org, env)
                saved["secrets"] = _pairing_secrets_summary(db)
                audit.append(
                    db,
                    org,
                    "owner",
                    "settings.updated",
                    "runtime",
                    {
                        "keys": sorted(body.keys()),
                        "pairing_updated": bool(raw_bearer or raw_secret),
                    },
                )
                return saved
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/")
    def root(request: Request):
        if _verify_session_cookie(_session_signing_key(), request.cookies.get("lnc_care_session")):
            return RedirectResponse("/admin/", status_code=303)
        return RedirectResponse("/login.html", status_code=303)

    @app.get("/login.html")
    def login_page():
        return FileResponse(PUBLIC / "login.html")

    @app.get("/admin")
    @app.get("/admin/")
    def admin_page(request: Request):
        if not _verify_session_cookie(
            _session_signing_key(), request.cookies.get("lnc_care_session")
        ):
            return RedirectResponse("/login.html", status_code=303)
        return FileResponse(PUBLIC / "index.html")

    @app.get("/icon.svg")
    @app.get("/favicon.svg")
    def icon_svg():
        return FileResponse(PUBLIC / "icon.svg", media_type="image/svg+xml")

    @app.get("/icon.png")
    @app.get("/favicon.png")
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

    # Zero-redirect MCP routes: both `/mcp` (Business MCP Hub & LNC-Agent-Hub) and `/mcp/` respond 200 directly.
    @app.api_route("/mcp", methods=["GET", "POST", "DELETE"])
    @app.api_route("/mcp/", methods=["GET", "POST", "DELETE"], include_in_schema=False)
    async def connector_mcp(request: Request):
        fwd_headers = {
            name: value
            for name, value in request.headers.items()
            if name.lower() not in ("host", "content-length", "connection", "transfer-encoding")
        }
        raw_body = await request.body()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mcp_asgi),
            base_url="http://lnc-care.internal",
        ) as mcp_http:
            upstream = await mcp_http.request(
                request.method,
                "/",
                headers=fwd_headers,
                params=request.query_params,
                content=raw_body,
            )
        passthrough = {
            name: value
            for name, value in upstream.headers.items()
            if name.lower()
            in ("content-type", "mcp-session-id", "mcp-protocol-version", "cache-control")
        }
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=passthrough,
        )

    return app


app = create_app()
