import hashlib
import hmac
import json
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient
import httpx
import pytest

from app import rotate_vault, store
from app.main import create_app
from app.vault import VaultError

KEY_1 = "11" * 32
KEY_2 = "22" * 32
MGMT = "mgmt-secret-key"
BEARER = "mcp-bearer-token"
DELEGATION = "mcp-delegation-secret"


def mock_meta_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "graph.facebook.com" in url and "oauth/access_token" in url:
            return httpx.Response(
                200,
                json={"access_token": "meta-user-token-secret", "expires_in": 5184000},
            )
        if "graph.facebook.com" in url and "/me/accounts" in url:
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "235513372986478",
                            "name": "LuxeClaw Official Page",
                            "username": "luxeclaw.official",
                            "fan_count": 24800,
                            "access_token": "page-secret-token-999",
                            "instagram_business_account": {
                                "id": "17841464987749627",
                                "username": "luxe.claw",
                                "name": "LuxeClaw Instagram",
                                "followers_count": 18400,
                            },
                        }
                    ]
                },
            )
        if "graph.facebook.com" in url and ("/235513372986478/published_posts" in url or "/235513372986478/posts" in url):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "235513372986478_101",
                            "message": "Royal Fantasy Press-On Nails — Custom Almond & Coffin sizing.",
                            "permalink_url": "https://www.facebook.com/luxeclaw/posts/101",
                            "created_time": "2026-11-10T10:00:00+0000",
                            "full_picture": "https://cdn.example.com/post101.jpg",
                        }
                    ]
                },
            )
        if "graph.facebook.com" in url and "/235513372986478_101/comments" in url:
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "cm_ext_501",
                            "message": "Shop ơi bộ này size S giá bao nhiêu ạ? Ship Paris mất mấy ngày?",
                            "created_time": "2026-11-10T11:00:00+0000",
                            "like_count": 3,
                            "comment_count": 0,
                            "is_hidden": False,
                            "from": {"id": "1000881122", "name": "Nguyen Hoang Oanh"},
                        }
                    ]
                },
            )
        return httpx.Response(404, json={"error": "unhandled_mock_url", "url": url})

    return httpx.MockTransport(handler)


def make_client(tmp_path, *, master_key=KEY_1, previous_key=None) -> tuple[TestClient, object]:
    db_path = tmp_path / "care.db"
    app = create_app(
        db_path=db_path,
        master_key=master_key,
        previous_master_key=previous_key,
        management_key=MGMT,
        mcp_bearer_token=BEARER,
        delegation_secret=DELEGATION,
        transport=mock_meta_transport(),
    )
    return TestClient(app), db_path


def login(client: TestClient) -> dict[str, str]:
    res = client.post("/api/auth/login", json={"key": MGMT})
    assert res.status_code == 200
    csrf = res.json()["csrf"]
    return {"X-CSRF-Token": csrf}


def test_health_auth_csrf_and_host_gate(tmp_path):
    client, _ = make_client(tmp_path)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["service"] == "lnc-care"
    assert r.json()["writes_enabled"] is False

    assert client.get("/api/admin/overview").status_code == 401
    assert client.post("/api/auth/login", json={"key": "wrong"}).status_code == 401

    headers = login(client)
    assert client.get("/api/admin/overview").status_code == 200
    assert client.post("/api/admin/shops", json={"name": "No CSRF"}).status_code == 403
    assert client.post("/api/admin/shops", json={"name": "Valid Shop"}, headers=headers).status_code == 200

    bad_host = client.get("/api/admin/overview", headers={"Host": "evil.example.com"})
    assert bad_host.status_code == 421


def test_vault_encryption_and_rotation(tmp_path, monkeypatch):
    client, db_path = make_client(tmp_path, master_key=KEY_1)
    headers = login(client)

    res = client.post(
        "/api/admin/integrations/meta",
        headers=headers,
        json={
            "client_id": "meta-app-123",
            "client_secret": "super-secret-meta-app-key",
            "webhook_verify_token": "verify-tok-123",
            "revision": 0,
        },
    )
    assert res.status_code == 200

    raw_bytes = db_path.read_bytes()
    assert b"super-secret-meta-app-key" not in raw_bytes

    with pytest.raises(VaultError):
        make_client(tmp_path, master_key=KEY_2)

    monkeypatch.setenv("DATABASE_PATH", str(db_path))
    monkeypatch.setenv("LNC_MASTER_KEY", KEY_2)
    monkeypatch.setenv("LNC_PREVIOUS_MASTER_KEY", KEY_1)
    assert rotate_vault.main() == 0

    client2, _ = make_client(tmp_path, master_key=KEY_2)
    h2 = login(client2)
    inv = client2.get("/api/admin/integrations", headers=h2).json()
    assert inv["apps"]["meta"]["configured"] is True


def test_oauth_discovery_approval_and_bounded_poller(tmp_path):
    client, db_path = make_client(tmp_path)
    headers = login(client)

    shop_id = client.post("/api/admin/shops", headers=headers, json={"name": "LuxeClaw FR"}).json()["id"]
    client.post(
        "/api/admin/integrations/meta",
        headers=headers,
        json={
            "client_id": "meta-client-id",
            "client_secret": "meta-client-secret",
            "webhook_verify_token": "meta-verify-token",
            "revision": 0,
        },
    )
    conn_id = client.post(
        "/api/admin/connections",
        headers=headers,
        json={"provider": "meta", "label": "Main Meta Business"},
    ).json()["id"]

    start = client.post(f"/api/admin/connections/{conn_id}/authorize", headers=headers)
    assert start.status_code == 200
    state_param = parse_qs(urlsplit(start.json()["authorization_url"]).query)["state"][0]

    cb = client.get(
        f"/api/auth/providers/meta/callback?state={state_param}&code=oauth-code-1",
        follow_redirects=False,
    )
    assert cb.status_code == 303

    disc = client.post(f"/api/admin/connections/{conn_id}/discover", headers=headers)
    assert disc.status_code == 200
    channels = disc.json()["channels"]
    assert len(channels) == 2
    fb_page = next(c for c in channels if c["kind"] == "fb_page")
    assert "page_access_token" not in fb_page

    app_res = client.post(
        f"/api/admin/connections/{conn_id}/channels/approve",
        headers=headers,
        json={"external_id": fb_page["external_id"], "shop_id": shop_id, "reply_policy": "draft_only"},
    )
    assert app_res.status_code == 200
    channel_id = app_res.json()["channel_id"]

    sync_res = client.post(f"/api/admin/channels/{channel_id}/sync", headers=headers)
    assert sync_res.status_code == 200
    assert sync_res.json()["posts"] == 1
    assert sync_res.json()["comments"] == 1

    # Verify the comment was evaluated by AI and consultation drafts were created
    cm_list = client.get("/api/admin/comments", headers=headers).json()["comments"]
    assert len(cm_list) == 1
    cm = cm_list[0]
    assert cm["author_name"] == "Nguyen Hoang Oanh"
    assert cm["evaluation"] is not None
    assert cm["evaluation"]["overall_score"] >= 80
    assert cm["evaluation"]["recommended_action"] == "should_consult"
    assert len(cm["drafts"]) == 2

    # Ensure tokens never leaked to plaintext DB or audit events
    raw_db = db_path.read_bytes()
    assert b"meta-user-token-secret" not in raw_db
    assert b"page-secret-token-999" not in raw_db


def test_meta_webhook_verification_and_hmac_signature(tmp_path):
    client, _ = make_client(tmp_path)
    headers = login(client)
    app_secret = "webhook-hmac-secret-999"
    client.post(
        "/api/admin/integrations/meta",
        headers=headers,
        json={
            "client_id": "meta-id",
            "client_secret": app_secret,
            "webhook_verify_token": "my-verify-token",
            "revision": 0,
        },
    )

    ok_challenge = client.get(
        "/webhooks/meta?hub.mode=subscribe&hub.verify_token=my-verify-token&hub.challenge=123456"
    )
    assert ok_challenge.status_code == 200
    assert ok_challenge.text == "123456"

    bad_challenge = client.get(
        "/webhooks/meta?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=123456"
    )
    assert bad_challenge.status_code == 403

    payload = {
        "object": "page",
        "entry": [
            {
                "id": "235513372986478",
                "time": 1731250000,
                "changes": [{"field": "feed", "value": {"item": "comment", "comment_id": "cm_1"}}],
            }
        ],
    }
    raw = json.dumps(payload).encode("utf-8")
    sig = "sha256=" + hmac.new(app_secret.encode(), raw, hashlib.sha256).hexdigest()

    assert client.post("/webhooks/meta", content=raw, headers={"X-Hub-Signature-256": "sha256=bad"}).status_code == 403

    w1 = client.post("/webhooks/meta", content=raw, headers={"X-Hub-Signature-256": sig})
    assert w1.status_code == 200
    assert w1.json() == {"ok": True, "deduplicated": False, "enqueued": 1}

    w2 = client.post("/webhooks/meta", content=raw, headers={"X-Hub-Signature-256": sig})
    assert w2.status_code == 200
    assert w2.json() == {"ok": True, "deduplicated": True, "enqueued": 0}
