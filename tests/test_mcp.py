import base64
import hashlib
import hmac
import json
import secrets
import time

from fastapi.testclient import TestClient

from app.main import create_app

KEY = "44" * 32
MGMT = "mgmt-secret"
BEARER = "mcp-bearer-token-secret"
DEL_SECRET = "mcp-delegation-hmac-secret"


def make_delegation(
    scopes: list[str],
    *,
    sub: str = "agent:lnm-care",
    aud: str = "lnc-care",
    version: int = 4,
    nonce: str | None = None,
    ttl: int = 60,
    secret: str = DEL_SECRET,
) -> str:
    now = int(time.time())
    payload = {
        "v": version,
        "iss": "lnc-v3",
        "aud": aud,
        "sub": sub,
        "scopes": scopes,
        "iat": now,
        "exp": now + ttl,
        "nonce": nonce or secrets.token_hex(12),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(secret.encode(), raw, hashlib.sha256).digest()
    p_b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    s_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{p_b64}.{s_b64}"


def mcp_call(client: TestClient, method: str, params: dict, scopes: list[str], *, nonce=None, aud="lnc-care"):
    header = make_delegation(scopes, nonce=nonce, aud=aud)
    return client.post(
        "/mcp/",
        headers={
            "Authorization": f"Bearer {BEARER}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "X-LNC-Delegation": header,
        },
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )


def test_mcp_bearer_delegation_replay_and_scope_filtering(tmp_path):
    app = create_app(
        db_path=tmp_path / "mcp.db",
        master_key=KEY,
        management_key=MGMT,
        mcp_bearer_token=BEARER,
        delegation_secret=DEL_SECRET,
    )
    with TestClient(app) as client:
        # 1. Missing bearer -> 401
        assert client.post("/mcp/", json={}).status_code == 401

        # 2. Wrong audience -> 403
        bad_aud = mcp_call(client, "tools/list", {}, ["care:read"], aud="lnc-ads")
        assert bad_aud.status_code == 403

        # 3. Nonce replay guard -> second request with same nonce returns 403
        fixed_nonce = "nonce-replay-check-001"
        r1 = mcp_call(client, "tools/list", {}, ["care:read"], nonce=fixed_nonce)
        assert r1.status_code == 200
        r2 = mcp_call(client, "tools/list", {}, ["care:read"], nonce=fixed_nonce)
        assert r2.status_code == 403
        assert "Replayed delegation nonce" in r2.json()["error"]

        # 4. Read-only caller only sees read tools in tools/list
        read_list = mcp_call(client, "tools/list", {}, ["care:read"]).json()["result"]["tools"]
        read_names = {t["name"] for t in read_list}
        assert "channels_list" in read_names
        assert "comments_list" in read_names
        assert "comment_reply" not in read_names
        assert "evidence_capture" not in read_names

        # 5. Write-scoped caller sees all tools when max_scopes allows care:write
        h = client.post("/api/auth/login", json={"key": MGMT}).json()["csrf"]
        client.post(
            "/api/settings",
            headers={"X-CSRF-Token": h},
            json={
                "mcp_max_scopes": [
                    "care:read",
                    "care:read:meta",
                    "care:write",
                    "care:write:meta",
                ]
            },
        )
        write_list = mcp_call(
            client, "tools/list", {}, ["care:read", "care:write", "care:write:meta"]
        ).json()["result"]["tools"]
        write_names = {t["name"] for t in write_list}
        assert "comment_reply" in write_names
        assert "evidence_capture" in write_names
        assert "comment_evaluate" in write_names


def test_mcp_tools_execution_and_browser_write_guard(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVIDER_WRITES_ENABLED", "true")
    app = create_app(
        db_path=tmp_path / "mcp_tools.db",
        master_key=KEY,
        management_key=MGMT,
        mcp_bearer_token=BEARER,
        delegation_secret=DEL_SECRET,
    )
    with TestClient(app) as client:
        csrf = client.post("/api/auth/login", json={"key": MGMT}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}

        # Enable write scopes in runtime settings & seed demo data
        client.post(
            "/api/settings",
            headers=headers,
            json={
                "mcp_max_scopes": [
                    "care:read",
                    "care:read:meta",
                    "care:write",
                    "care:write:meta",
                ]
            },
        )
        client.post("/api/admin/seed-demo", headers=headers)

        scopes = ["care:read", "care:read:meta", "care:write", "care:write:meta"]

        # Call inbox_summary via MCP
        res_sum = mcp_call(
            client, "tools/call", {"name": "inbox_summary", "arguments": {}}, scopes
        ).json()
        summary_data = json.loads(res_sum["result"]["content"][0]["text"])
        assert summary_data["total"] == 6

        # Call comments_list via MCP
        res_cms = mcp_call(
            client, "tools/call", {"name": "comments_list", "arguments": {}}, scopes
        ).json()
        comments = json.loads(res_cms["result"]["content"][0]["text"])["comments"]
        api_comment = next(c for c in comments if c["adapter"] == "meta_api")
        browser_comment = next(c for c in comments if c["adapter"] == "veilbrowser")

        # 1. Guarded write on official meta_api channel succeeds & is idempotent
        rep1 = mcp_call(
            client,
            "tools/call",
            {
                "name": "comment_reply",
                "arguments": {
                    "comment_id": api_comment["id"],
                    "text": "Dạ shop đã gửi bảng size và báo giá chi tiết qua inbox cho mình rồi ạ!",
                    "idempotency_key": "idem-reply-001",
                },
            },
            scopes,
        ).json()
        rep1_payload = json.loads(rep1["result"]["content"][0]["text"])
        assert rep1_payload["ok"] is True

        # Replay with same idempotency_key returns identical action_id
        rep2 = mcp_call(
            client,
            "tools/call",
            {
                "name": "comment_reply",
                "arguments": {
                    "comment_id": api_comment["id"],
                    "text": "Dạ shop đã gửi bảng size và báo giá chi tiết qua inbox cho mình rồi ạ!",
                    "idempotency_key": "idem-reply-001",
                },
            },
            scopes,
        ).json()
        rep2_payload = json.loads(rep2["result"]["content"][0]["text"])
        assert rep2_payload["action_id"] == rep1_payload["action_id"]

        # 2. Guarded write on VeilBrowser / Personal Profile MUST fail with channel_adapter_unsupported
        bad_rep = mcp_call(
            client,
            "tools/call",
            {
                "name": "comment_reply",
                "arguments": {
                    "comment_id": browser_comment["id"],
                    "text": "Automated reply on personal profile",
                    "idempotency_key": "idem-personal-001",
                },
            },
            scopes,
        ).json()
        assert bad_rep["result"]["isError"] is True
        assert "channel_adapter_unsupported" in bad_rep["result"]["content"][0]["text"]

        # 3. Capture 5-Layer Forensic Evidence via MCP
        ev_res = mcp_call(
            client,
            "tools/call",
            {
                "name": "evidence_capture",
                "arguments": {
                    "comment_id": browser_comment["id"],
                    "title": "MCP Forensic Capture Test",
                },
            },
            scopes,
        ).json()
        ev_payload = json.loads(ev_res["result"]["content"][0]["text"])
        assert ev_payload["ok"] is True
        assert len(ev_payload["manifest_sha256"]) == 64
