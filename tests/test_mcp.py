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


def make_hub_headers(
    scopes: list[str],
    *,
    client_id: str = "agent-care",
    app_id: str = "",
    aud: str = "lnc-care",
    nonce: str | None = None,
    secret: str = DEL_SECRET,
) -> dict[str, str]:
    ts = str(int(time.time()))
    sorted_scopes = sorted(set(scopes))
    n = nonce or f"hub_nonce_{secrets.token_urlsafe(18)}"
    envelope = (
        f"v4\n{aud}\n{client_id}\n{app_id}\n{ts}\n{n}\n{','.join(sorted_scopes)}"
        if app_id
        else f"v3\n{aud}\n{client_id}\n{ts}\n{n}\n{','.join(sorted_scopes)}"
    )
    sig = hmac.new(secret.encode(), envelope.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Authorization": f"Bearer {BEARER}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "x-mcp-hub-client-id": client_id,
        "x-mcp-hub-client-scopes": ",".join(sorted_scopes),
        "x-mcp-hub-client-timestamp": ts,
        "x-mcp-hub-client-nonce": n,
        "x-mcp-hub-client-signature": sig,
    }
    if app_id:
        headers["x-mcp-hub-app-id"] = app_id
    return headers


def test_mcp_hub_wire_headers_v3_v4_no_trailing_slash_and_omnichannel_tools(tmp_path, monkeypatch):
    import httpx
    from app.mcp_gateway import McpGatewayConfig

    monkeypatch.setenv("PROVIDER_WRITES_ENABLED", "true")

    gw_state = {"session_id": None, "initialized": False}

    def fake_gw_handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://10.21.4.101:8380/mcp"
        assert request.headers.get("authorization") == "Bearer lnc_k_care_svc_key"
        rpc = json.loads(request.content.decode())
        method = rpc.get("method")
        if method == "initialize":
            gw_state["session_id"] = "sess_hub_fastmcp_01"
            gw_state["initialized"] = False
            return httpx.Response(
                200,
                headers={"mcp-session-id": gw_state["session_id"]},
                json={
                    "jsonrpc": "2.0",
                    "id": rpc["id"],
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {"listChanged": True}},
                        "serverInfo": {"name": "Business MCP Hub", "version": "1.28.1"},
                    },
                },
            )
        if method == "notifications/initialized":
            if request.headers.get("mcp-session-id") != gw_state["session_id"]:
                return httpx.Response(400, text="Bad Request: Missing session ID")
            gw_state["initialized"] = True
            return httpx.Response(202)

        if not gw_state["session_id"] or not request.headers.get("mcp-session-id"):
            return httpx.Response(400, text="Bad Request: Missing session ID")
        if request.headers.get("mcp-session-id") != gw_state["session_id"] or not gw_state["initialized"]:
            return httpx.Response(
                404,
                json={"jsonrpc": "2.0", "id": "server-error", "error": {"code": -32600, "message": "Session not found"}},
            )
        assert method == "tools/call"
        assert rpc["params"]["name"] == "ads__page_posts_list"
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": rpc["id"],
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {"shop": "LuxeClaw", "posts": [{"id": "235513372986478_901", "ad_id": "ad_77"}]}
                            ),
                        }
                    ]
                },
            },
        )

    app = create_app(
        db_path=tmp_path / "mcp_hub.db",
        master_key=KEY,
        management_key=MGMT,
        mcp_bearer_token=BEARER,
        delegation_secret=DEL_SECRET,
        mcp_gateway_config=McpGatewayConfig(
            gateway_url="http://10.21.4.101:8380/mcp",
            api_key="lnc_k_care_svc_key",
        ),
        mcp_gateway_transport=httpx.MockTransport(fake_gw_handler),
    )

    with TestClient(app) as client:
        csrf = client.post("/api/auth/login", json={"key": MGMT}).json()["csrf"]
        all_scopes = [
            "care:read",
            "care:read:meta",
            "care:write",
            "care:write:meta",
        ]
        client.post(
            "/api/settings",
            headers={"X-CSRF-Token": csrf},
            json={"mcp_max_scopes": all_scopes},
        )
        client.post("/api/admin/seed-demo", headers={"X-CSRF-Token": csrf})

        # 1. POST /mcp (NO trailing slash!) responds 200 directly with Business MCP Hub v3 headers
        fixed_nonce = "hub_v3_replay_nonce_1234567890"
        r_v3 = client.post(
            "/mcp",
            headers=make_hub_headers(["care:read"], nonce=fixed_nonce),
            json={"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
            follow_redirects=False,
        )
        assert r_v3.status_code == 200
        read_tools = {t["name"] for t in r_v3.json()["result"]["tools"]}
        assert {
            "shops_list",
            "channels_list",
            "conversations_list",
            "messages_list",
            "leads_list",
            "handoffs_list",
            "ads_context_lookup",
        }.issubset(read_tools)

        # Replay of same Hub nonce is rejected with 403
        r_replay = client.post(
            "/mcp",
            headers=make_hub_headers(["care:read"], nonce=fixed_nonce),
            json={"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}},
        )
        assert r_replay.status_code == 403

        # 2. Business MCP Hub v4 headers (`x-mcp-hub-app-id`) + omnichannel & cross-app tools
        convs_resp = client.post(
            "/mcp",
            headers=make_hub_headers(all_scopes, app_id="lnc-agent-hub"),
            json={"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "conversations_list", "arguments": {}}},
        ).json()
        convs = json.loads(convs_resp["result"]["content"][0]["text"])["conversations"]
        assert len(convs) >= 1
        conv_id = convs[0]["id"]

        msg_rep = client.post(
            "/mcp",
            headers=make_hub_headers(all_scopes, app_id="lnc-agent-hub"),
            json={
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "message_reply",
                    "arguments": {
                        "conversation_id": conv_id,
                        "text": "Bonjour ! Voici le guide des tailles Almond S.",
                        "idempotency_key": "idem-msg-001",
                    },
                },
            },
        ).json()
        assert json.loads(msg_rep["result"]["content"][0]["text"])["ok"] is True

        lead_res = client.post(
            "/mcp",
            headers=make_hub_headers(all_scopes, app_id="lnc-agent-hub"),
            json={
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/call",
                "params": {
                    "name": "lead_upsert",
                    "arguments": {
                        "customer_name": "Claire Dubois",
                        "source": "dm",
                        "contact_handle": "@claire.paris",
                        "status": "qualified",
                    },
                },
            },
        ).json()
        assert json.loads(lead_res["result"]["content"][0]["text"])["ok"] is True

        handoff_res = client.post(
            "/mcp",
            headers=make_hub_headers(all_scopes, app_id="lnc-agent-hub"),
            json={
                "jsonrpc": "2.0",
                "id": 15,
                "method": "tools/call",
                "params": {
                    "name": "ticket_handoff",
                    "arguments": {
                        "summary": "VIP custom bridal press-on sizing consultation",
                        "priority": "high",
                        "conversation_id": conv_id,
                    },
                },
            },
        ).json()
        assert json.loads(handoff_res["result"]["content"][0]["text"])["ok"] is True

        # 3. Cross-app `ads__*` lookup routed strictly via `LNC_MCP_GATEWAY_URL`
        ads_res = client.post(
            "/mcp",
            headers=make_hub_headers(["care:read"], app_id="lnc-agent-hub"),
            json={
                "jsonrpc": "2.0",
                "id": 16,
                "method": "tools/call",
                "params": {
                    "name": "ads_context_lookup",
                    "arguments": {
                        "tool_name": "ads__page_posts_list",
                        "arguments": {"shop": "LuxeClaw"},
                    },
                },
            },
        ).json()
        ads_payload = json.loads(ads_res["result"]["content"][0]["text"])
        assert ads_payload["ok"] is True
        assert ads_payload["data"]["shop"] == "LuxeClaw"
        assert ads_payload["data"]["posts"][0]["ad_id"] == "ad_77"


def test_mcp_gateway_session_cache_and_reinit_on_400_and_404():
    import httpx
    import pytest
    from app.mcp_gateway import McpGatewayClient, McpGatewayConfig, McpGatewayError

    state = {
        "init_calls": 0,
        "notify_calls": 0,
        "active_session": None,
        "force_next_400": False,
        "always_404": False,
    }

    def stateful_fastmcp_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == "Bearer lnc_k_care_svc_key"
        rpc = json.loads(request.content.decode())
        method = rpc.get("method")

        if method == "initialize":
            state["init_calls"] += 1
            sid = f"mcp_sess_{state['init_calls']}"
            state["active_session"] = sid
            return httpx.Response(
                200,
                headers={"Mcp-Session-Id": sid},
                json={
                    "jsonrpc": "2.0",
                    "id": rpc["id"],
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {"listChanged": True}},
                        "serverInfo": {"name": "Business MCP Hub", "version": "1.28.1"},
                    },
                },
            )

        if method == "notifications/initialized":
            assert "id" not in rpc
            if request.headers.get("mcp-session-id") != state["active_session"]:
                return httpx.Response(400, text="Bad Request: Missing session ID")
            state["notify_calls"] += 1
            return httpx.Response(202)

        if state["always_404"]:
            return httpx.Response(
                404,
                json={"jsonrpc": "2.0", "id": "server-error", "error": {"code": -32600, "message": "Session not found"}},
            )

        if state["force_next_400"]:
            state["force_next_400"] = False
            return httpx.Response(400, text="Bad Request: Missing session ID")

        req_sid = request.headers.get("mcp-session-id")
        if not req_sid:
            return httpx.Response(400, text="Bad Request: Missing session ID")
        if req_sid != state["active_session"]:
            return httpx.Response(
                404,
                json={"jsonrpc": "2.0", "id": "server-error", "error": {"code": -32600, "message": "Session not found"}},
            )

        if method == "tools/list":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": rpc["id"],
                    "result": {
                        "tools": [
                            {"name": "ads__shops_list"},
                            {"name": "ads__page_posts_list"},
                            {"name": "care__channels_list"},
                        ]
                    },
                },
            )

        assert method == "tools/call"
        sse_body = (
            "event: message\n"
            + "data: "
            + json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": rpc["id"],
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps({"shops": [{"name": "LuxeClaw"}], "session_seen": req_sid}),
                            }
                        ]
                    },
                }
            )
            + "\n\n"
        )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text=sse_body,
        )

    gw = McpGatewayClient(
        McpGatewayConfig(gateway_url="http://10.21.4.101:8380/mcp", api_key="lnc_k_care_svc_key"),
        transport=httpx.MockTransport(stateful_fastmcp_handler),
    )

    assert gw.status_summary()["has_session"] is False

    # 1. First call initializes + sends notifications/initialized + caches Mcp-Session-Id
    r1 = gw.call_tool("ads__shops_list", {})
    assert r1["ok"] is True
    assert r1["data"]["session_seen"] == "mcp_sess_1"
    assert state["init_calls"] == 1
    assert state["notify_calls"] == 1
    assert gw.status_summary()["has_session"] is True
    assert "mcp_sess_1" not in json.dumps(gw.status_summary())

    # 2. Subsequent call reuses cached Mcp-Session-Id without re-initializing
    ads_tools = gw.list_tools(prefix="ads__")
    assert [t["name"] for t in ads_tools] == ["ads__shops_list", "ads__page_posts_list"]
    assert state["init_calls"] == 1
    assert state["notify_calls"] == 1

    # 3. Upstream Hub restarts / evicts session -> HTTP 404 triggers 1x re-init & transparent retry
    state["active_session"] = "evicted_on_server"
    r2 = gw.call_tool("ads__shops_list", {})
    assert r2["ok"] is True
    assert r2["data"]["session_seen"] == "mcp_sess_2"
    assert state["init_calls"] == 2
    assert state["notify_calls"] == 2

    # 4. Upstream returns HTTP 400 Missing session ID -> triggers 1x re-init & transparent retry
    state["force_next_400"] = True
    r3 = gw.call_tool("ads__shops_list", {})
    assert r3["ok"] is True
    assert r3["data"]["session_seen"] == "mcp_sess_3"
    assert state["init_calls"] == 3
    assert state["notify_calls"] == 3

    # 5. Persistent 404 stops after 1 re-init attempt (no infinite retry loop)
    state["always_404"] = True
    with pytest.raises(McpGatewayError) as exc_info:
        gw.call_tool("ads__shops_list", {})
    assert exc_info.value.code == "mcp_gateway_http_404"
    assert exc_info.value.status == 502
    assert state["init_calls"] == 4


