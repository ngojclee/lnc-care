from fastapi.testclient import TestClient

from app.main import create_app

KEY = "33" * 32
MGMT = "mgmt-secret"


def make_client(tmp_path) -> TestClient:
    app = create_app(
        db_path=tmp_path / "care.db",
        master_key=KEY,
        management_key=MGMT,
        mcp_bearer_token="bearer",
        delegation_secret="del-secret",
    )
    return TestClient(app)


def login(client: TestClient) -> dict[str, str]:
    res = client.post("/api/auth/login", json={"key": MGMT})
    assert res.status_code == 200
    return {"X-CSRF-Token": res.json()["csrf"]}


def test_seed_demo_evidence_vault_and_fleet_guardrails(tmp_path):
    client = make_client(tmp_path)
    headers = login(client)

    seed = client.post("/api/admin/seed-demo", headers=headers)
    assert seed.status_code == 200
    assert seed.json()["channels"] == 3
    assert seed.json()["comments"] == 6

    # Check Overview KPIs
    ov = client.get("/api/admin/overview", headers=headers).json()
    assert ov["inbox_summary"]["total"] == 6
    assert ov["evidence_cases_count"] >= 1
    assert ov["fleet_summary"]["total"] == 6

    # Capture a new 5-Layer Forensic Evidence case
    cap = client.post(
        "/api/admin/evidence/capture",
        headers=headers,
        json={
            "title": "Defamation Thread Preservation",
            "target_url": "https://www.facebook.com/example/posts/999",
        },
    )
    assert cap.status_code == 200
    body = cap.json()
    assert body["ok"] is True
    assert len(body["manifest_sha256"]) == 64
    assert "layer_1_immutable_ids" in body["layers"]
    assert "layer_3_visual_and_network_replay" in body["layers"]
    assert "layer_5_watchdog" in body["layers"]

    ev_list = client.get("/api/admin/evidence", headers=headers).json()["cases"]
    assert len(ev_list) >= 2

    # Register a personal_main runtime and verify daily_write_budget is forced to 0
    fl = client.post(
        "/api/admin/fleet",
        headers=headers,
        json={
            "label": "Owner Personal FB Backup",
            "platform": "facebook",
            "account_role": "personal_main",
            "adapter": "veilbrowser",
            "runtime_profile_id": "vb_personal_backup_01",
            "expected_exit_ip": "82.64.1.99",
            "daily_write_budget": 99,
        },
    )
    assert fl.status_code == 200

    fleet_data = client.get("/api/admin/fleet", headers=headers).json()["runtimes"]
    personal_row = next(r for r in fleet_data if r["runtime_profile_id"] == "vb_personal_backup_01")
    assert personal_row["daily_write_budget"] == 0

    # Test Post Archive & Worker execution
    posts = client.get("/api/admin/posts", headers=headers).json()["posts"]
    assert len(posts) >= 3
    arch = client.post(f"/api/admin/posts/{posts[0]['id']}/archive", headers=headers)
    assert arch.status_code == 200
    assert arch.json()["worker"]["processed"] >= 2

    post_detail = client.get(f"/api/admin/posts/{posts[0]['id']}", headers=headers).json()["post"]
    assert len(post_detail["archives"]) >= 2

    # Verify hash-chained audit log integrity
    audit_res = client.get("/api/admin/audit/verify", headers=headers).json()
    assert audit_res["valid"] is True
    assert audit_res["checked"] >= 5
