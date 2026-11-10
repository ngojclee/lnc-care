import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time

import httpx
from fastapi.testclient import TestClient

from app import agent_hub, internal_bridge
from app.main import create_app

KEY = "55" * 32
MGMT = "mgmt-care-secret"
BRIDGE_SECRET = "99" * 32  # 64-char hex secret matching LNC_INTERNAL_BRIDGE_SECRET
HUB_API_KEY = "lnc_k_svc_lnc_care_secret"


def _make_bridge_cfg() -> internal_bridge.BridgeConfig:
    return internal_bridge.BridgeConfig(
        secret=BRIDGE_SECRET,
        self_id="lnc-care",
        peers={"lnc-ads": "https://ads-mcp.lengoc.me"},
        ads_internal_url="http://10.21.4.101:8480",
        internal_hosts=internal_bridge.DEFAULT_INTERNAL_HOSTS,
    )


def _make_hub_cfg(*, api_key: str = HUB_API_KEY) -> agent_hub.AgentHubConfig:
    return agent_hub.AgentHubConfig(
        url="http://10.21.4.101:8380",
        public_url="https://hub.lengoc.me",
        api_key=api_key,
        self_id="lnc-care",
        lease_ttl_seconds=900,
    )


def test_agent_hub_vault_sync_encrypted_local_cache_and_standalone_survival(tmp_path):
    hub_online = {"up": True}
    leased_calls = {"count": 0}
    raw_secret_token = "EAAB_SUPER_SECRET_HUB_LEASED_TOKEN_999"
    raw_page_token = "EAAB_SUPER_SECRET_PAGE_TOKEN_777"
    raw_meta_app_secret = "meta_shared_app_secret_xyz"

    def hub_handler(request: httpx.Request) -> httpx.Response:
        if not hub_online["up"]:
            raise httpx.ConnectError("LNC-Agent-Hub restarting")
        path = request.url.path
        if path != "/health":
            assert request.headers.get("authorization") == f"Bearer {HUB_API_KEY}"
        if path == "/v1/platform/status":
            return httpx.Response(
                200,
                json={"ok": True, "principal_key": "svc:lnc-care", "version": "2.0.0"},
            )
        if path == "/v1/platform/shops" and request.method == "GET":
            return httpx.Response(200, json={"shops": [{"id": 1, "name": "LuxeClaw"}]})
        if path == "/v1/platform/shops" and request.method == "POST":
            return httpx.Response(200, json={"ok": True})
        if path == "/v1/platform/apps" and request.method == "GET":
            return httpx.Response(
                200,
                json={"apps": {"meta": {"configured": True, "revision": 2}, "google": {"configured": True}}},
            )
        if path == "/v1/platform/apps/meta/credentials":
            return httpx.Response(
                200,
                json={
                    "client_id": "1821062268930458",
                    "client_secret": raw_meta_app_secret,
                    "project_id": "",
                    "webhook_verify_token": "verify_luxe",
                    "revision": 2,
                },
            )
        if path == "/v1/platform/connections" and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "connections": [
                        {
                            "hub_connection_id": "hub_conn_meta_1",
                            "provider": "meta",
                            "label": "LuxeClaw Meta Business",
                            "state": "verified",
                            "revision": 3,
                            "shops": ["LuxeClaw"],
                        }
                    ]
                },
            )
        if path == "/v1/platform/connections/hub_conn_meta_1/lease":
            leased_calls["count"] += 1
            return httpx.Response(
                200,
                json={
                    "token": {"access_token": raw_secret_token},
                    "page_tokens": {"235513372986478": raw_page_token},
                    "expires_at": int(time.time()) + 7200,
                    "revision": 3,
                },
            )
        return httpx.Response(404)

    def meta_graph_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/me/accounts" in url:
            assert request.headers.get("authorization") == f"Bearer {raw_secret_token}"
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "235513372986478",
                            "name": "LuxeClaw Official",
                            "username": "luxeclaw",
                            "followers_count": 15200,
                            "access_token": raw_page_token,
                        }
                    ]
                },
            )
        if "/235513372986478/published_posts" in url:
            assert request.headers.get("authorization") == f"Bearer {raw_page_token}"
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "235513372986478_101",
                            "message": "Handcrafted press-on nails",
                            "permalink_url": "https://facebook.com/luxeclaw/posts/101",
                        }
                    ]
                },
            )
        if "/235513372986478_101/comments" in url:
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "cm_live_1",
                            "from": {"id": "u_1", "name": "Sophie Laurent"},
                            "message": "Shop tư vấn giúp mình bộ Almond size S giá bao nhiêu ạ?",
                            "is_hidden": False,
                            "like_count": 1,
                            "comment_count": 0,
                        }
                    ]
                },
            )
        return httpx.Response(404)

    db_file = tmp_path / "care_hub.db"
    app = create_app(
        db_path=db_file,
        master_key=KEY,
        management_key=MGMT,
        hub_config=_make_hub_cfg(),
        agent_hub_transport=httpx.MockTransport(hub_handler),
        transport=httpx.MockTransport(meta_graph_handler),
    )

    with TestClient(app) as client:
        csrf = client.post("/api/auth/login", json={"key": MGMT}).json()["csrf"]
        h = {"X-CSRF-Token": csrf}

        st = client.get("/api/admin/hub/status").json()
        assert st["agent_hub"]["mode"] == "vault_synced"
        assert st["agent_hub"]["platform_api_ready"] is True

        sync_res = client.post("/api/admin/hub/sync", headers=h).json()
        assert sync_res["ok"] is True
        assert sync_res["source"] == "lnc-agent-hub"
        assert sync_res["pulled_shops"] == 1
        assert sync_res["pulled_apps"] == 1
        assert sync_res["pulled_connections"] == 1
        assert leased_calls["count"] == 1

        # Confirm raw tokens are NEVER stored in plaintext in SQLite
        raw_sqlite_bytes = db_file.read_bytes()
        assert raw_secret_token.encode() not in raw_sqlite_bytes
        assert raw_page_token.encode() not in raw_sqlite_bytes
        assert raw_meta_app_secret.encode() not in raw_sqlite_bytes

        # NOW SHUT DOWN LNC-AGENT-HUB COMPLETELY (100% Standalone Survival Test!)
        hub_online["up"] = False

        ov = client.get("/api/admin/overview").json()
        conn_id = ov["integrations"]["connections"][0]["id"]
        shop_id = ov["shops"][0]["id"]

        # Discover & approve channel while Hub is OFFLINE using local encrypted Vault cache (TTL=900s)
        disc = client.post(f"/api/admin/connections/{conn_id}/discover", headers=h)
        assert disc.status_code == 200
        assert disc.json()["channels"][0]["external_id"] == "235513372986478"

        app_ch = client.post(
            f"/api/admin/connections/{conn_id}/channels/approve",
            headers=h,
            json={"external_id": "235513372986478", "shop_id": shop_id, "reply_policy": "draft_only"},
        ).json()
        sync_ch = client.post(f"/api/admin/channels/{app_ch['channel_id']}/sync", headers=h)
        assert sync_ch.status_code == 200
        assert sync_ch.json()["comments"] == 1
        assert leased_calls["count"] == 1  # No extra lease call needed within 900s TTL!

        # Webhook verification also works 100% standalone from locally cached Meta app secret
        wh_body = json.dumps(
            {"entry": [{"id": "235513372986478", "changes": [{"field": "feed", "value": {"comment_id": "c_2"}}]}]}
        ).encode()
        wh_sig = "sha256=" + hmac.new(raw_meta_app_secret.encode(), wh_body, hashlib.sha256).hexdigest()
        wh_res = client.post(
            "/webhooks/meta", content=wh_body, headers={"X-Hub-Signature-256": wh_sig}
        )
        assert wh_res.status_code == 200
        assert wh_res.json()["enqueued"] == 1


def test_ads_lan_bridge_fallback_when_hub_returns_404(tmp_path):
    def hub_404_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404, json={"detail": "Not Found"})

    def verify_ads_bridge_hmac(request: httpx.Request) -> None:
        peer = request.headers["x-lnc-bridge-peer"]
        ts = request.headers["x-lnc-bridge-timestamp"]
        nonce = request.headers["x-lnc-bridge-nonce"]
        sig = request.headers["x-lnc-bridge-signature"]
        assert peer == "lnc-care"
        path_q = request.url.path + (f"?{request.url.query.decode()}" if request.url.query else "")
        expected = internal_bridge.sign_request(
            BRIDGE_SECRET, peer, ts, nonce, request.method, path_q, request.content
        )
        assert hmac.compare_digest(expected, sig)

    def ads_bridge_handler(request: httpx.Request) -> httpx.Response:
        verify_ads_bridge_hmac(request)
        path = request.url.path
        if path == "/api/internal/bridge/status":
            return httpx.Response(
                200,
                json={"ok": True, "service": "LNC Ads", "self_id": "lnc-ads", "version": "1.2.0"},
            )
        if path == "/api/internal/bridge/shops" and request.method == "GET":
            return httpx.Response(200, json={"shops": [{"id": 1, "name": "LuxeClaw"}]})
        if path == "/api/internal/bridge/connections":
            return httpx.Response(
                200,
                json={
                    "connections": [
                        {
                            "id": 3,
                            "provider": "meta",
                            "label": "luxeclaw-meta",
                            "state": "verified",
                            "expires_at": int(time.time()) + 86400,
                            "shops": ["LuxeClaw"],
                        }
                    ]
                },
            )
        if path == "/api/internal/bridge/channels":
            return httpx.Response(
                200,
                json={
                    "shop": "LuxeClaw",
                    "channels": [
                        {
                            "provider": "meta",
                            "channel_type": "facebook_page",
                            "channel_id": "100200300",
                            "name": "LuxeClaw Official Page",
                            "username": "luxeclaw.official",
                            "followers_count": 12500,
                            "connection_id": 3,
                        },
                        {
                            "provider": "meta",
                            "channel_type": "instagram_business",
                            "channel_id": "17841400001",
                            "name": "LuxeClaw IG",
                            "username": "luxeclaw.ig",
                            "followers_count": 8400,
                            "connection_id": 3,
                        },
                    ],
                },
            )
        if path == "/api/internal/bridge/platform-call":
            body = json.loads(request.content.decode())
            assert body["shop"] == "LuxeClaw"
            assert body["connection_id"] == 3
            if body["path"] == "100200300/published_posts":
                assert body["use_page_token"] is True
                return httpx.Response(
                    200,
                    json={
                        "ok": True,
                        "data": {
                            "data": [
                                {
                                    "id": "100200300_555",
                                    "message": "Velvet Cat-Eye Collection",
                                    "permalink_url": "https://facebook.com/luxeclaw/posts/555",
                                }
                            ]
                        },
                    },
                )
            if body["path"] == "100200300_555/comments":
                return httpx.Response(
                    200,
                    json={
                        "ok": True,
                        "data": {
                            "data": [
                                {
                                    "id": "cm_bridge_1",
                                    "from": {"id": "u_99", "name": "Camille Moreau"},
                                    "message": "Shop ơi mẫu này ship Lyon bao lâu nhận được ạ?",
                                    "is_hidden": False,
                                    "like_count": 3,
                                    "comment_count": 0,
                                }
                            ]
                        },
                    },
                )
        if path == "/api/internal/bridge/oauth/start":
            body = json.loads(request.content.decode())
            assert body["include_care_scopes"] is True
            return httpx.Response(
                200,
                json={
                    "authorization_url": "https://www.facebook.com/v25.0/dialog/oauth?client_id=1821062268930458",
                    "connection_id": 3,
                    "shop": body["shop"],
                },
            )
        if path == "/api/internal/bridge/meta/verify-signature":
            body = json.loads(request.content.decode())
            raw = base64.b64decode(body["raw_body_b64"])
            expected = "sha256=" + hmac.new(b"ads_meta_secret", raw, hashlib.sha256).hexdigest()
            return httpx.Response(
                200,
                json={"valid": hmac.compare_digest(expected, body["signature_header"])},
            )
        return httpx.Response(404)

    app = create_app(
        db_path=tmp_path / "care_bridge.db",
        master_key=KEY,
        management_key=MGMT,
        bridge_config=_make_bridge_cfg(),
        hub_config=_make_hub_cfg(),
        agent_hub_transport=httpx.MockTransport(hub_404_handler),
        ads_bridge_transport=httpx.MockTransport(ads_bridge_handler),
    )

    with TestClient(app) as client:
        csrf = client.post("/api/auth/login", json={"key": MGMT}).json()["csrf"]
        h = {"X-CSRF-Token": csrf}

        # 1. Status automatically detects Hub 404 + live LNC Ads LAN Bridge
        st = client.get("/api/admin/hub/status").json()
        assert st["agent_hub"]["mode"] == "ads_bridge_fallback"
        assert st["agent_hub"]["bridge_fallback_ready"] is True

        # 2. Sync pulls LuxeClaw + 2 Meta channels via LNC Ads LAN Bridge
        sync = client.post("/api/admin/hub/sync", headers=h).json()
        assert sync["ok"] is True
        assert sync["source"] == "lnc-ads-bridge"
        assert sync["pulled_shops"] == 1
        assert sync["pulled_connections"] == 1
        assert sync["pulled_channels"] == 2

        ov = client.get("/api/admin/overview").json()
        fb_channel = next(c for c in ov["channels"] if c["external_id"] == "100200300")

        # 3. Syncing a bridge-imported channel fetches posts/comments via /api/internal/bridge/platform-call
        ch_sync = client.post(f"/api/admin/channels/{fb_channel['id']}/sync", headers=h).json()
        assert ch_sync["ok"] is True
        assert ch_sync["posts"] == 1
        assert ch_sync["comments"] == 1

        # 4. Shared OAuth start falls back to LNC Ads bridge
        oauth_res = client.post(
            "/api/admin/oauth/shared/start",
            headers=h,
            json={"provider": "meta", "shop": "LuxeClaw"},
        ).json()
        assert oauth_res["via"] == "ads_bridge_fallback"
        assert "facebook.com" in oauth_res["authorization_url"]

        # 5. Meta webhook verification falls back to LNC Ads bridge when Hub returns 404
        wh_raw = json.dumps({"entry": []}).encode()
        good_sig = "sha256=" + hmac.new(b"ads_meta_secret", wh_raw, hashlib.sha256).hexdigest()
        assert (
            client.post(
                "/webhooks/meta", content=wh_raw, headers={"X-Hub-Signature-256": good_sig}
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/webhooks/meta",
                content=wh_raw,
                headers={"X-Hub-Signature-256": "sha256=" + "0" * 64},
            ).status_code
            == 403
        )


def test_universal_3way_sso_and_inbound_bridge_auth(tmp_path):
    def hub_sso_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/platform/status":
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/v1/platform/sso/mint":
            body = json.loads(request.content.decode())
            return httpx.Response(
                200,
                json={
                    "ticket": "lnc_sso_minted_xyz",
                    "consume_url": f"https://hub.lengoc.me/v1/platform/sso/consume?ticket=lnc_sso_minted_xyz&aud={body['audience']}",
                },
            )
        if request.url.path == "/v1/platform/sso/redeem":
            body = json.loads(request.content.decode())
            if body["ticket"] == "lnc_sso_valid_ticket_123" and body["audience"] == "lnc-care":
                return httpx.Response(
                    200,
                    json={"ok": True, "audience": "lnc-care", "issuer": "lnc-agent-hub", "subject": "owner"},
                )
            return httpx.Response(401, json={"ok": False})
        return httpx.Response(404)

    app = create_app(
        db_path=tmp_path / "care_sso.db",
        master_key=KEY,
        management_key=MGMT,
        bridge_config=_make_bridge_cfg(),
        hub_config=_make_hub_cfg(),
        agent_hub_transport=httpx.MockTransport(hub_sso_handler),
    )

    with TestClient(app) as client:
        # 1. Redeem `lnc_sso_*` ticket from LNC-Agent-Hub
        r_hub_consume = client.get(
            "/api/auth/sso/consume?ticket=lnc_sso_valid_ticket_123&next=/admin/%23channels",
            follow_redirects=False,
        )
        assert r_hub_consume.status_code == 303
        assert r_hub_consume.headers["location"] == "/admin/#channels"
        assert client.get("/api/auth/status").json()["authenticated"] is True

        # 2. Redirect to LNC-Agent-Hub via `/api/auth/sso/redirect?peer=lnc-agent-hub`
        r_hub_redir = client.get(
            "/api/auth/sso/redirect?peer=lnc-agent-hub&next=/",
            follow_redirects=False,
        )
        assert r_hub_redir.status_code == 303
        assert "hub.lengoc.me/v1/platform/sso/consume" in r_hub_redir.headers["location"]

        # 3. Consume HMAC peer SSO ticket minted by `lnc-ads` + verify single-use replay rejection
        ads_peer_cfg = internal_bridge.BridgeConfig(
            secret=BRIDGE_SECRET,
            self_id="lnc-ads",
            peers={"lnc-care": "https://care-mcp.lengoc.me"},
            ads_internal_url="http://10.21.4.101:8480",
            internal_hosts=internal_bridge.DEFAULT_INTERNAL_HOSTS,
        )
        peer_ticket = internal_bridge.mint_sso_ticket(ads_peer_cfg, audience="lnc-care")

        client.cookies.clear()
        assert client.get("/api/auth/status").json()["authenticated"] is False

        c1 = client.get(
            f"/api/auth/sso/consume?ticket={peer_ticket}&next=https://evil.example/phish",
            follow_redirects=False,
        )
        assert c1.status_code == 303
        # Open-redirect protection forces fallback to safe relative path
        assert c1.headers["location"] == "/admin/#inbox"
        assert client.get("/api/auth/status").json()["authenticated"] is True

        # Replaying the exact same ticket MUST fail with 401
        c2 = client.get(
            f"/api/auth/sso/consume?ticket={peer_ticket}",
            follow_redirects=False,
        )
        assert c2.status_code == 401
        assert "replayed" in c2.json()["detail"]

        # 4. Inbound LAN Bridge endpoint `/api/internal/bridge/status` + replay protection
        ts = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        sig = internal_bridge.sign_request(
            BRIDGE_SECRET, "lnc-ads", ts, nonce, "GET", "/api/internal/bridge/status", b""
        )
        b_headers = {
            "Host": "10.21.4.101:8482",
            "X-LNC-Bridge-Peer": "lnc-ads",
            "X-LNC-Bridge-Timestamp": ts,
            "X-LNC-Bridge-Nonce": nonce,
            "X-LNC-Bridge-Signature": sig,
        }
        ib1 = client.get("/api/internal/bridge/status", headers=b_headers)
        assert ib1.status_code == 200
        assert ib1.json()["self_id"] == "lnc-care"

        ib_replay = client.get("/api/internal/bridge/status", headers=b_headers)
        assert ib_replay.status_code == 401
