"""Tests for LNC Internal App Blueprint full UI contract, API keys, mgmt key rotation, and env_or_cfg."""
import hashlib
import hmac
import json
import re
import time
import uuid

from fastapi.testclient import TestClient

from app import store
from app.main import ROOT, VERSION, create_app

MASTER_KEY = "22" * 32
MGMT_KEY = "env-mgmt-secret-for-tests-1234"


def _hub_headers(secret: str, scopes: list[str]) -> dict[str, str]:
    ts = str(int(time.time()))
    nonce = f"nonce-{uuid.uuid4().hex}"
    client_id = "hub-test"
    app_id = "agent-care"
    scopes_csv = ",".join(sorted(scopes))
    msg = f"v4\nlnc-care\n{client_id}\n{app_id}\n{ts}\n{nonce}\n{scopes_csv}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return {
        "x-mcp-hub-client-id": client_id,
        "x-mcp-hub-app-id": app_id,
        "x-mcp-hub-client-scopes": scopes_csv,
        "x-mcp-hub-client-timestamp": ts,
        "x-mcp-hub-client-nonce": nonce,
        "x-mcp-hub-client-signature": sig,
    }


def test_static_blueprint_assets_icons_and_english_only_ui(tmp_path):
    app = create_app(
        db_path=tmp_path / "ui.db",
        master_key=MASTER_KEY,
        management_key=MGMT_KEY,
    )
    client = TestClient(app)

    # Unauthenticated root & /admin redirect to /login.html
    r_root = client.get("/", follow_redirects=False)
    assert r_root.status_code == 303
    assert r_root.headers["location"] == "/login.html"

    r_admin = client.get("/admin", follow_redirects=False)
    assert r_admin.status_code == 303
    assert r_admin.headers["location"] == "/login.html"

    # Public login & brand icon assets
    assert client.get("/login.html").status_code == 200
    assert client.get("/icon.svg").status_code == 200
    assert client.get("/favicon.svg").status_code == 200
    icon_png = client.get("/icon.png")
    assert icon_png.status_code == 200
    assert len(icon_png.content) > 50_000  # genuine 1024x1024 raster, not a 1x1 stub
    fav_ico = client.get("/favicon.ico")
    assert fav_ico.status_code == 200
    assert len(fav_ico.content) > 10_000  # genuine multi-size ICO

    for doc_asset in ("icon.svg", "icon.png", "icon.ico"):
        assert (ROOT / "docs" / doc_asset).exists()

    info = client.get("/api/app-info").json()
    assert info["version"] == VERSION == "0.3.0.1"

    # Static blueprint & English-only checks on HTML / CSS / JS
    index_html = (ROOT / "app" / "public" / "index.html").read_text(encoding="utf-8")
    login_html = (ROOT / "app" / "public" / "login.html").read_text(encoding="utf-8")
    style_css = (ROOT / "app" / "public" / "style.css").read_text(encoding="utf-8")
    app_js = (ROOT / "app" / "public" / "app.js").read_text(encoding="utf-8")

    for slug in (
        "overview",
        "inbox",
        "conversations",
        "posts",
        "evidence",
        "fleet",
        "channels",
        "rules",
        "connector",
        "audit",
        "keys",
        "settings",
    ):
        assert f'id="page-{slug}"' in index_html

    # Exact 3-row .side-foot order: #app-build -> #theme-toggle -> #signout
    assert index_html.index('id="app-build"') < index_html.index('id="theme-toggle"') < index_html.index('id="signout"')

    # Dual theme tokens, autohide scrollbar, custom select & table-err in CSS
    assert '[data-theme="light"]' in style_css
    assert '[data-theme="dark"]' in style_css
    assert ".is-scrolling" in style_css
    assert ".select-menu" in style_css
    assert ".table-err" in style_css

    # Custom dropdown enhancer & no browser blocking dialogs
    assert "function enhanceSelect" in app_js
    assert "enhanceAllSelects" in app_js
    assert not re.search(r"\b(?:alert|confirm|prompt)\s*\(", app_js)

    # Zero leaked Vietnamese strings in UI files
    combined_ui = index_html + "\n" + login_html + "\n" + app_js
    for forbidden in ("label_vi", "Nên tư vấn", "Cần xem tay", "Lập vi bằng", "Suy luận tư vấn", "Nhãn"):
        assert forbidden not in combined_ui


def test_api_keys_lifecycle_and_cookie_free_bearer_status(tmp_path):
    db_file = tmp_path / "keys.db"
    app = create_app(
        db_path=db_file,
        master_key=MASTER_KEY,
        management_key=MGMT_KEY,
    )
    admin = TestClient(app)
    csrf = admin.post("/api/auth/login", json={"key": MGMT_KEY}).json()["csrf_token"]
    h = {"X-CSRF-Token": csrf}

    # Initially empty
    inv0 = admin.get("/api/keys").json()
    assert inv0["keys"] == []
    assert inv0["mgmt"]["source"] == "environment"
    assert inv0["mgmt"]["rotatable"] is False

    # Env-managed mgmt key refuses UI rotation
    rot_blocked = admin.post("/api/mgmt/rotate", headers=h, json={"current_key": MGMT_KEY})
    assert rot_blocked.status_code == 409

    # Create API key
    created = admin.post("/api/keys", headers=h, json={"label": "Hub Monitor"}).json()
    raw_secret = created["secret"]
    key_id = created["item"]["id"]
    assert raw_secret.startswith("care_")

    # GET /api/keys never leaks plaintext secret or hash
    inv1 = admin.get("/api/keys").json()
    assert len(inv1["keys"]) == 1
    assert raw_secret not in json.dumps(inv1)
    assert inv1["keys"][0]["label"] == "Hub Monitor"
    assert inv1["keys"][0]["copy_available"] is True

    # SQLite table stores hash only, never plaintext secret
    with store.connect_readonly(db_file) as db:
        row = dict(db.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone())
    assert raw_secret not in json.dumps(row)
    assert row["key_hash"] == hashlib.sha256(raw_secret.encode()).hexdigest()

    # Fresh unauthenticated client (no session cookie!) calls /api/status with Bearer API key
    probe = TestClient(app)
    assert probe.get("/api/status").status_code == 401
    ok_status = probe.get("/api/status", headers={"Authorization": f"Bearer {raw_secret}"})
    assert ok_status.status_code == 200
    assert ok_status.json()["ok"] is True
    assert ok_status.json()["mcp_endpoint"].endswith("/mcp")

    # Copy endpoint returns decrypted secret and logs audit event
    copied = admin.post(f"/api/keys/{key_id}/copy", headers=h).json()
    assert copied["secret"] == raw_secret

    # Rename key
    assert admin.patch(f"/api/keys/{key_id}", headers=h, json={"label": "Renamed Probe"}).status_code == 200
    assert admin.get("/api/keys").json()["keys"][0]["label"] == "Renamed Probe"

    # Disable key -> Bearer probe rejected immediately; toggle again -> accepted
    admin.post(f"/api/keys/{key_id}/toggle", headers=h)
    assert probe.get("/api/status", headers={"Authorization": f"Bearer {raw_secret}"}).status_code == 401
    admin.post(f"/api/keys/{key_id}/toggle", headers=h)
    assert probe.get("/api/status", headers={"Authorization": f"Bearer {raw_secret}"}).status_code == 200

    # Delete before revoke is blocked (409)
    assert admin.delete(f"/api/keys/{key_id}", headers=h).status_code == 409

    # Revoke permanently wipes Vault copy envelope and rejects Bearer auth + re-enable
    assert admin.post(f"/api/keys/{key_id}/revoke", headers=h).status_code == 200
    assert probe.get("/api/status", headers={"Authorization": f"Bearer {raw_secret}"}).status_code == 401
    assert admin.post(f"/api/keys/{key_id}/copy", headers=h).status_code == 404
    assert admin.post(f"/api/keys/{key_id}/toggle", headers=h).status_code == 409

    # Delete revoked tombstoned record
    assert admin.delete(f"/api/keys/{key_id}", headers=h).status_code == 200
    assert admin.get("/api/keys").json()["keys"] == []


def test_bootstrap_to_runtime_mgmt_key_rotation_and_fail_closed(tmp_path, monkeypatch):
    db_file = tmp_path / "mgmt.db"
    monkeypatch.delenv("MANAGEMENT_KEY", raising=False)
    monkeypatch.setenv("CARE_ADMIN_BOOTSTRAP_KEY", "bootstrap-initial-key-alpha")

    app1 = create_app(db_path=db_file, master_key=MASTER_KEY)
    c1 = TestClient(app1)

    login_a = c1.post("/api/auth/login", json={"key": "bootstrap-initial-key-alpha"})
    assert login_a.status_code == 200
    csrf_a = login_a.json()["csrf_token"]

    inv = c1.get("/api/keys").json()["mgmt"]
    assert inv["source"] == "runtime"
    assert inv["rotatable"] is True

    # Rotate A -> B
    rot = c1.post(
        "/api/mgmt/rotate",
        headers={"X-CSRF-Token": csrf_a},
        json={"current_key": "bootstrap-initial-key-alpha", "secret": "rotated-runtime-key-bravo-9999"},
    )
    assert rot.status_code == 200
    assert rot.json()["key"] == "rotated-runtime-key-bravo-9999"

    # Existing session invalidated immediately
    assert c1.get("/api/keys").status_code == 401

    # Restart with a brand-new CARE_ADMIN_BOOTSTRAP_KEY=charlie: runtime key bravo MUST win
    monkeypatch.setenv("CARE_ADMIN_BOOTSTRAP_KEY", "bootstrap-restart-key-charlie")
    app2 = create_app(db_path=db_file, master_key=MASTER_KEY)
    c2 = TestClient(app2)

    assert c2.post("/api/auth/login", json={"key": "bootstrap-initial-key-alpha"}).status_code == 401
    assert c2.post("/api/auth/login", json={"key": "bootstrap-restart-key-charlie"}).status_code == 401
    login_b = c2.post("/api/auth/login", json={"key": "rotated-runtime-key-bravo-9999"})
    assert login_b.status_code == 200
    assert c2.get("/api/keys").json()["mgmt"]["bootstrap_ignored"] is True

    # Corrupting __mgmt_state in SQLite fails closed (500), never falling back to bootstrap env
    with store.connect(db_file) as db:
        db.execute("UPDATE runtime_settings SET value='{corrupt' WHERE key='__mgmt_state'")
    c3 = TestClient(app2)
    res_corrupt = c3.post("/api/auth/login", json={"key": "bootstrap-restart-key-charlie"})
    assert res_corrupt.status_code == 500
    assert res_corrupt.json()["detail"] == "management_state_corrupt"


def test_ui_saved_hub_pairing_secrets_env_or_cfg_on_mcp(tmp_path):
    app = create_app(
        db_path=tmp_path / "pairing.db",
        master_key=MASTER_KEY,
        management_key=MGMT_KEY,
        mcp_bearer_token="",
        delegation_secret="",
    )
    with TestClient(app) as client:
        csrf = client.post("/api/auth/login", json={"key": MGMT_KEY}).json()["csrf_token"]
        saved = client.post(
            "/api/settings",
            headers={"X-CSRF-Token": csrf},
            json={
                "connector_bearer": "ui-saved-connector-bearer-xyz",
                "delegation_secret": "ui-saved-delegation-secret-xyz",
            },
        )
        assert saved.status_code == 200
        sec_meta = saved.json()["secrets"]
        assert sec_meta["connector_bearer"] == {"configured": True, "source": "database"}
        assert sec_meta["delegation_secret"] == {"configured": True, "source": "database"}
        assert "ui-saved-connector-bearer-xyz" not in json.dumps(saved.json())

        # /mcp immediately authenticates using the UI-saved Vault pairing secrets
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        raw = json.dumps(payload).encode()
        headers = {
            "Authorization": "Bearer ui-saved-connector-bearer-xyz",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **_hub_headers("ui-saved-delegation-secret-xyz", ["care:read"]),
        }
        mcp_res = client.post("/mcp", content=raw, headers=headers)
        assert mcp_res.status_code == 200
        tools = mcp_res.json()["result"]["tools"]
        assert any(t["name"] == "channels_list" for t in tools)

    # Env-managed pairing secret cannot be overridden via UI POST /api/settings
    app_env = create_app(
        db_path=tmp_path / "pairing_env.db",
        master_key=MASTER_KEY,
        management_key=MGMT_KEY,
        mcp_bearer_token="env-locked-bearer",
        delegation_secret="env-locked-secret",
    )
    c_env = TestClient(app_env)
    csrf_env = c_env.post("/api/auth/login", json={"key": MGMT_KEY}).json()["csrf_token"]
    blocked = c_env.post(
        "/api/settings",
        headers={"X-CSRF-Token": csrf_env},
        json={"connector_bearer": "attempt-override"},
    )
    assert blocked.status_code == 422
