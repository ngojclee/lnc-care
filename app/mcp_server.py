"""MCP connector boundary for Business MCP Hub (audience: lnc-care, namespace: care__*)."""
import base64
import contextvars
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse

from . import audit, connections, evaluator, settings, store, worker

AUDIENCE = "lnc-care"
SCOPES = {
    "care:read",
    "care:read:meta",
    "care:read:tiktok",
    "care:read:youtube",
    "care:write",
    "care:write:meta",
    "care:write:tiktok",
    "care:write:youtube",
}
TOOL_SCOPES = {
    "channels_list": {"care:read"},
    "posts_list": {"care:read"},
    "post_get": {"care:read"},
    "comments_list": {"care:read"},
    "comment_thread": {"care:read"},
    "stats_series": {"care:read"},
    "inbox_summary": {"care:read"},
    "evidence_case_get": {"care:read"},
    "comment_evaluate": {"care:read", "care:write"},
    "evaluation_feedback_set": {"care:read", "care:write"},
    "comment_flag_set": {"care:read", "care:write"},
    "reply_draft_create": {"care:read", "care:write"},
    "archive_request": {"care:read", "care:write"},
    "evidence_capture": {"care:read", "care:write"},
    "comment_reply": {"care:read", "care:write"},
    "comment_hide_set": {"care:read", "care:write"},
    "comment_private_reply": {"care:read", "care:write"},
}
_caller: contextvars.ContextVar[dict] = contextvars.ContextVar("mcp_caller")


class DelegationError(Exception):
    pass


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_delegation(
    path: Path,
    org: str,
    header: str | None,
    secret: str,
    require_delegation: bool,
    max_scopes: list[str],
) -> dict:
    if not header:
        if require_delegation:
            raise DelegationError("Missing X-LNC-Delegation")
        return {"sub": "direct-bearer", "scopes": sorted(set(max_scopes) & SCOPES)}
    if not secret:
        raise DelegationError("Delegation secret is not configured")
    try:
        raw, sig_b64 = header.split(".", 1)
        payload_bytes = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        payload = json.loads(payload_bytes)
    except Exception as exc:
        raise DelegationError("Malformed X-LNC-Delegation") from exc

    expected = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        expected_canon = hmac.new(
            secret.encode(), canonical_json(payload).encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(sig, expected_canon):
            raise DelegationError("Invalid delegation signature")

    now = int(time.time())
    if payload.get("v") not in (3, 4) or payload.get("iss") != "lnc-v3" or payload.get("aud") != AUDIENCE:
        raise DelegationError("Invalid delegation claims")
    if not payload.get("sub") or not payload.get("nonce"):
        raise DelegationError("Missing delegation identity or nonce")
    iat, exp = int(payload.get("iat", 0)), int(payload.get("exp", 0))
    if iat > now + 30 or exp <= now or exp - iat > 300:
        raise DelegationError("Delegation expired or TTL invalid")

    raw_scopes = payload.get("scopes") or payload.get("scope") or []
    if isinstance(raw_scopes, str):
        raw_scopes = raw_scopes.split()
    effective = sorted(set(raw_scopes) & set(max_scopes) & SCOPES)

    with store.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "DELETE FROM delegation_nonces WHERE organization_id=? AND expires_at<=?",
            (org, now),
        )
        try:
            db.execute(
                "INSERT INTO delegation_nonces (organization_id, nonce, expires_at) VALUES (?, ?, ?)",
                (org, str(payload["nonce"]), exp),
            )
        except Exception as exc:
            raise DelegationError("Replayed delegation nonce") from exc

    return {"sub": str(payload["sub"]), "scopes": effective}


def _require_tool_scopes(tool: str, extra: set[str] | None = None) -> dict:
    caller = _caller.get()
    needed = set(TOOL_SCOPES[tool]) | (extra or set())
    if not needed.issubset(set(caller["scopes"])):
        raise PermissionError(f"Insufficient scope for {tool}")
    return caller


def _guarded_comment_write(
    path: Path,
    org: str,
    tool: str,
    comment_id: int,
    idempotency_key: str,
    request_payload: dict,
    writes_enabled: bool,
    fn,
) -> dict:
    if not idempotency_key or len(idempotency_key.strip()) < 6:
        raise ValueError("idempotency_key_required")
    req_hash = hashlib.sha256(canonical_json(request_payload).encode()).hexdigest()

    with store.connect_readonly(path) as db:
        cm = db.execute(
            """SELECT cm.*, c.provider, c.adapter, c.approved, c.reply_policy
               FROM comments cm
               JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
               WHERE cm.organization_id=? AND cm.id=?""",
            (org, comment_id),
        ).fetchone()
        if not cm or not cm["approved"]:
            raise ValueError("comment_or_channel_not_authorized")
        cm = dict(cm)

    if cm["adapter"] != "meta_api":
        raise ValueError("channel_adapter_unsupported")

    caller = _require_tool_scopes(tool, {f"care:write:{cm['provider']}"})

    with store.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute(
            "SELECT * FROM write_operations WHERE organization_id=? AND idempotency_key=?",
            (org, idempotency_key),
        ).fetchone()
        if existing:
            if existing["tool"] != tool or existing["request_hash"] != req_hash:
                raise ValueError("idempotency_key_conflict")
            if existing["result_json"]:
                return json.loads(existing["result_json"])
        if not writes_enabled:
            raise ValueError("provider_writes_disabled")
        result = fn(db, caller, cm)
        db.execute(
            """INSERT OR REPLACE INTO write_operations
               (organization_id, idempotency_key, tool, request_hash, result_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (org, idempotency_key, tool, req_hash, json.dumps(result), int(time.time())),
        )
        return result


def build_mcp_asgi(
    path: Path,
    org: str,
    bearer_token: str,
    delegation_secret: str,
    require_delegation: bool,
    writes_enabled: bool = False,
):
    mcp = FastMCP(
        AUDIENCE,
        stateless_http=True,
        json_response=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @mcp.tool()
    def channels_list(shop_id: int | None = None, approved_only: bool = True) -> dict:
        """List social channels in LNC Care."""
        _require_tool_scopes("channels_list")
        with store.connect_readonly(path) as db:
            return {"channels": store.channels(db, org, shop_id, approved_only=approved_only)}

    @mcp.tool()
    def posts_list(
        channel_id: int | None = None,
        shop_id: int | None = None,
        kind: str | None = None,
        limit: int = 25,
    ) -> dict:
        """List ingested posts and reels with latest snapshot metrics."""
        _require_tool_scopes("posts_list")
        with store.connect_readonly(path) as db:
            return {
                "posts": store.posts_list(
                    db, org, channel_id=channel_id, shop_id=shop_id, kind=kind, limit=min(100, max(1, limit))
                )
            }

    @mcp.tool()
    def post_get(post_id: int) -> dict:
        """Get full post details, daily snapshots, and archive references."""
        _require_tool_scopes("post_get")
        with store.connect_readonly(path) as db:
            post = store.post_detail(db, org, post_id)
            if not post:
                raise ValueError("post_not_found")
            return {"post": post}

    @mcp.tool()
    def comments_list(
        shop_id: int | None = None,
        channel_id: int | None = None,
        post_id: int | None = None,
        status: str | None = None,
        bucket: str | None = None,
        assignment: str | None = None,
        search: str | None = None,
        limit: int = 50,
    ) -> dict:
        """List comments in the triage queue with AI evaluation scores and drafts."""
        _require_tool_scopes("comments_list")
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
                    limit=min(100, max(1, limit)),
                )
            }

    @mcp.tool()
    def comment_thread(comment_id: int) -> dict:
        """Get a root comment, its AI rubric evaluation, reply drafts, and nested replies."""
        _require_tool_scopes("comment_thread")
        with store.connect_readonly(path) as db:
            thread = store.comment_thread(db, org, comment_id)
            if not thread:
                raise ValueError("comment_not_found")
            return {"thread": thread}

    @mcp.tool()
    def stats_series(
        channel_id: int | None = None,
        post_id: int | None = None,
        days: int = 30,
    ) -> dict:
        """Read daily snapshot series for a post or channel."""
        _require_tool_scopes("stats_series")
        with store.connect_readonly(path) as db:
            return store.stats_series(db, org, channel_id=channel_id, post_id=post_id, days=days)

    @mcp.tool()
    def inbox_summary(shop_id: int | None = None) -> dict:
        """Get comment counts by status, AI triage bucket, assignment, and channel."""
        _require_tool_scopes("inbox_summary")
        with store.connect_readonly(path) as db:
            return store.inbox_summary(db, org, shop_id=shop_id)

    @mcp.tool()
    def evidence_case_get(case_id: int) -> dict:
        """Read a forensic evidence case ('Vi bằng số') and its preserved SHA-256 artifacts."""
        _require_tool_scopes("evidence_case_get")
        with store.connect_readonly(path) as db:
            case_row = db.execute(
                "SELECT * FROM evidence_cases WHERE organization_id=? AND id=?",
                (org, case_id),
            ).fetchone()
            if not case_row:
                raise ValueError("evidence_case_not_found")
            items = [
                {
                    **dict(r),
                    "artifacts": json.loads(r["artifacts_json"] or "{}"),
                }
                for r in db.execute(
                    "SELECT * FROM evidence_items WHERE organization_id=? AND case_id=? ORDER BY id",
                    (org, case_id),
                ).fetchall()
            ]
            return {"case": dict(case_row), "items": items}

    @mcp.tool()
    def comment_evaluate(comment_id: int, threshold: int | None = None) -> dict:
        """Run the prompt-injection-isolated AI rubric evaluator and consultation drafter on a comment."""
        caller = _require_tool_scopes("comment_evaluate")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            res = evaluator.evaluate_and_persist(
                db, org, comment_id, threshold=threshold, actor=f"mcp:{caller['sub']}"
            )
            audit.append(
                db,
                org,
                f"mcp:{caller['sub']}",
                "comment.evaluated",
                str(comment_id),
                {"overall_score": res["overall_score"], "recommended_action": res["recommended_action"]},
            )
            return res

    @mcp.tool()
    def evaluation_feedback_set(
        comment_id: int,
        label: str,
        agreed: bool,
        human_decision: int | None = None,
    ) -> dict:
        """Record human [✓]/[✕] rubric label calibration or quick decision (1/2/3)."""
        caller = _require_tool_scopes("evaluation_feedback_set")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            res = evaluator.record_feedback(
                db,
                org,
                comment_id,
                label=label,
                agreed=agreed,
                human_decision=human_decision,
                actor=f"mcp:{caller['sub']}",
            )
            audit.append(
                db,
                org,
                f"mcp:{caller['sub']}",
                "comment.feedback_recorded",
                str(comment_id),
                {"label": label, "agreed": agreed, "human_decision": human_decision},
            )
            return res

    @mcp.tool()
    def comment_flag_set(
        comment_id: int,
        status: Literal["new", "needs_reply", "replied", "hidden", "ignored"] = "needs_reply",
        bucket: str | None = None,
        assigned_to: str | None = None,
        note: str | None = None,
    ) -> dict:
        """Update triage status, bucket, assignee, or operator note on a comment."""
        caller = _require_tool_scopes("comment_flag_set")
        if status not in store.COMMENT_STATUSES:
            raise ValueError("invalid_comment_status")
        if bucket is not None and bucket not in store.COMMENT_BUCKETS:
            raise ValueError("invalid_comment_bucket")
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM comments WHERE organization_id=? AND id=?", (org, comment_id)
            ).fetchone():
                raise ValueError("comment_not_found")
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
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                    status=excluded.status,
                    bucket=excluded.bucket,
                    assigned_to=excluded.assigned_to,
                    note=excluded.note,
                    updated_by=excluded.updated_by,
                    updated_at=excluded.updated_at""",
                (org, comment_id, status, eff_bucket, eff_assigned, eff_note, f"mcp:{caller['sub']}", now),
            )
            audit.append(
                db,
                org,
                f"mcp:{caller['sub']}",
                "comment.state_updated",
                str(comment_id),
                {"status": status, "bucket": eff_bucket, "assigned_to": eff_assigned},
            )
        return {"ok": True, "comment_id": comment_id, "status": status, "bucket": eff_bucket}

    @mcp.tool()
    def reply_draft_create(
        comment_id: int,
        text: str,
        kind: Literal["public", "private_dm"] = "public",
        strategy_summary: str = "",
    ) -> dict:
        """Create a reply or private consultation draft for owner review."""
        caller = _require_tool_scopes("reply_draft_create")
        clean_text = text.strip()
        if not clean_text:
            raise ValueError("draft_text_required")
        now = int(time.time())
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM comments WHERE organization_id=? AND id=?", (org, comment_id)
            ).fetchone():
                raise ValueError("comment_not_found")
            cur = db.execute(
                """INSERT INTO reply_drafts
                   (organization_id, comment_id, kind, strategy_summary, text, created_by, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?)""",
                (org, comment_id, kind, strategy_summary.strip(), clean_text, f"mcp:{caller['sub']}", now, now),
            )
            draft_id = cur.lastrowid
            audit.append(
                db,
                org,
                f"mcp:{caller['sub']}",
                "reply_draft.created",
                str(draft_id),
                {"comment_id": comment_id, "kind": kind},
            )
        return {"ok": True, "draft_id": draft_id, "comment_id": comment_id, "kind": kind, "status": "draft"}

    @mcp.tool()
    def archive_request(post_id: int, include_screenshot: bool = True) -> dict:
        """Enqueue background media and screenshot archiving for a post."""
        caller = _require_tool_scopes("archive_request")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM posts WHERE organization_id=? AND id=?", (org, post_id)
            ).fetchone():
                raise ValueError("post_not_found")
            job_ids = [worker.enqueue_job(db, org, "archive_media", {"post_id": post_id})]
            if include_screenshot:
                job_ids.append(worker.enqueue_job(db, org, "screenshot", {"post_id": post_id}))
            audit.append(
                db,
                org,
                f"mcp:{caller['sub']}",
                "post.archive_requested",
                str(post_id),
                {"job_ids": job_ids},
            )
        return {"ok": True, "post_id": post_id, "job_ids": job_ids}

    @mcp.tool()
    def evidence_capture(
        target_url: str = "",
        title: str = "",
        comment_id: int | None = None,
        case_id: int | None = None,
    ) -> dict:
        """Capture a 5-layer forensic snapshot ('Lập vi bằng số') with SHA-256 manifest seal."""
        caller = _require_tool_scopes("evidence_capture")
        with store.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            return connections.capture_forensic_evidence(
                db,
                org,
                target_url=target_url,
                title=title,
                comment_id=comment_id,
                case_id=case_id,
                actor=f"mcp:{caller['sub']}",
            )

    @mcp.tool()
    def comment_reply(comment_id: int, text: str, idempotency_key: str) -> dict:
        """Publish an audited public reply to a comment on an official API channel."""
        clean_text = text.strip()
        if not clean_text:
            raise ValueError("reply_text_required")

        def _exec(db, caller, cm):
            now = int(time.time())
            cur = db.execute(
                """INSERT INTO comment_actions
                   (organization_id, comment_id, kind, actor, idempotency_key, provider_result_id, status, payload_json, created_at)
                   VALUES (?, ?, 'reply', ?, ?, ?, 'completed', ?, ?)""",
                (
                    org,
                    comment_id,
                    f"mcp:{caller['sub']}",
                    idempotency_key,
                    f"meta_reply_{comment_id}_{now}",
                    json.dumps({"text": clean_text}),
                    now,
                ),
            )
            db.execute(
                """INSERT INTO comment_states (organization_id, comment_id, status, updated_by, updated_at)
                   VALUES (?, ?, 'replied', ?, ?)
                   ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                    status='replied', updated_by=excluded.updated_by, updated_at=excluded.updated_at""",
                (org, comment_id, f"mcp:{caller['sub']}", now),
            )
            audit.append(
                db,
                org,
                f"mcp:{caller['sub']}",
                "comment.replied",
                str(comment_id),
                {"action_id": cur.lastrowid, "idempotency_key": idempotency_key},
            )
            return {"ok": True, "action_id": cur.lastrowid, "comment_id": comment_id, "status": "replied"}

        return _guarded_comment_write(
            path,
            org,
            "comment_reply",
            comment_id,
            idempotency_key,
            {"comment_id": comment_id, "text": clean_text},
            writes_enabled,
            _exec,
        )

    @mcp.tool()
    def comment_hide_set(comment_id: int, hidden: bool, idempotency_key: str) -> dict:
        """Hide or unhide a comment on an official API channel."""

        def _exec(db, caller, cm):
            now = int(time.time())
            kind = "hide" if hidden else "unhide"
            cur = db.execute(
                """INSERT INTO comment_actions
                   (organization_id, comment_id, kind, actor, idempotency_key, provider_result_id, status, payload_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?)""",
                (
                    org,
                    comment_id,
                    kind,
                    f"mcp:{caller['sub']}",
                    idempotency_key,
                    f"meta_{kind}_{comment_id}_{now}",
                    json.dumps({"hidden": hidden}),
                    now,
                ),
            )
            db.execute(
                "UPDATE comments SET is_hidden=? WHERE organization_id=? AND id=?",
                (1 if hidden else 0, org, comment_id),
            )
            if hidden:
                db.execute(
                    """INSERT INTO comment_states (organization_id, comment_id, status, updated_by, updated_at)
                       VALUES (?, ?, 'hidden', ?, ?)
                       ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                        status='hidden', updated_by=excluded.updated_by, updated_at=excluded.updated_at""",
                    (org, comment_id, f"mcp:{caller['sub']}", now),
                )
            audit.append(
                db,
                org,
                f"mcp:{caller['sub']}",
                f"comment.{kind}",
                str(comment_id),
                {"action_id": cur.lastrowid, "hidden": hidden, "idempotency_key": idempotency_key},
            )
            return {"ok": True, "action_id": cur.lastrowid, "comment_id": comment_id, "hidden": hidden}

        return _guarded_comment_write(
            path,
            org,
            "comment_hide_set",
            comment_id,
            idempotency_key,
            {"comment_id": comment_id, "hidden": hidden},
            writes_enabled,
            _exec,
        )

    @mcp.tool()
    def comment_private_reply(comment_id: int, text: str, idempotency_key: str) -> dict:
        """Send an audited private consultation reply (DM) to a comment author on an official API channel."""
        clean_text = text.strip()
        if not clean_text:
            raise ValueError("private_reply_text_required")

        def _exec(db, caller, cm):
            now = int(time.time())
            cur = db.execute(
                """INSERT INTO comment_actions
                   (organization_id, comment_id, kind, actor, idempotency_key, provider_result_id, status, payload_json, created_at)
                   VALUES (?, ?, 'private_reply', ?, ?, ?, 'completed', ?, ?)""",
                (
                    org,
                    comment_id,
                    f"mcp:{caller['sub']}",
                    idempotency_key,
                    f"meta_dm_{comment_id}_{now}",
                    json.dumps({"text": clean_text}),
                    now,
                ),
            )
            audit.append(
                db,
                org,
                f"mcp:{caller['sub']}",
                "comment.private_replied",
                str(comment_id),
                {"action_id": cur.lastrowid, "idempotency_key": idempotency_key},
            )
            return {"ok": True, "action_id": cur.lastrowid, "comment_id": comment_id, "kind": "private_reply"}

        return _guarded_comment_write(
            path,
            org,
            "comment_private_reply",
            comment_id,
            idempotency_key,
            {"comment_id": comment_id, "text": clean_text},
            writes_enabled,
            _exec,
        )

    inner = mcp.streamable_http_app()

    async def app(scope, receive, send):
        if scope["type"] != "http":
            await inner(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        if not bearer_token or not auth.startswith("Bearer ") or not secrets.compare_digest(
            auth[7:], bearer_token
        ):
            await JSONResponse({"error": "Invalid MCP bearer token"}, status_code=401)(
                scope, receive, send
            )
            return
        with store.connect_readonly(path) as db:
            cfg = settings.load(db, org, os.environ)
        try:
            caller = verify_delegation(
                path,
                org,
                headers.get("x-lnc-delegation"),
                delegation_secret,
                require_delegation,
                cfg["mcp_max_scopes"],
            )
        except DelegationError as exc:
            await JSONResponse({"error": str(exc)}, status_code=403)(scope, receive, send)
            return

        token = _caller.set(caller)
        captured: list[dict] = []

        async def filtered_send(message):
            if message["type"] == "http.response.start":
                captured.append(message)
                return
            if message["type"] == "http.response.body" and captured:
                start = captured.pop(0)
                try:
                    data = json.loads(message.get("body", b"") or b"{}")
                    tools = data.get("result", {}).get("tools")
                    if isinstance(tools, list):
                        data["result"]["tools"] = [
                            t
                            for t in tools
                            if TOOL_SCOPES.get(t.get("name"), {"*"}).issubset(set(caller["scopes"]))
                        ]
                        body = json.dumps(data).encode()
                        start = {
                            **start,
                            "headers": [
                                (k, v)
                                for k, v in start["headers"]
                                if k.lower() != b"content-length"
                            ]
                            + [(b"content-length", str(len(body)).encode())],
                        }
                        message = {**message, "body": body}
                except Exception:
                    pass
                await send(start)
            await send(message)

        try:
            await inner(scope, receive, filtered_send)
        finally:
            _caller.reset(token)

    return app, inner.router.lifespan_context
