//! Blueprint v2.0 contract tests for LNC Care: security headers, CSRF/Origin, server-side sessions,
//! Keycloak-style OIDC (PKCE S256, loopback-free mock transport), copy rate limit, MCP connector lifecycle.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Method, Request};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

use lnc_care::routes::{build_router, AppConfig};
use lnc_care::transport::{mock_transport, TransportRequest, TransportResponse};

const KEY_1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const MGMT_KEY: &str = "blueprint-mgmt-key-123456";

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

struct Client {
    router: Router,
    cookies: HashMap<String, String>,
}

impl Client {
    fn new(router: Router) -> Self {
        Self {
            router,
            cookies: HashMap::new(),
        }
    }

    async fn send(
        &mut self,
        method: Method,
        uri: &str,
        extra: &[(&str, &str)],
        body: Option<Value>,
    ) -> Resp {
        let mut b = Request::builder().method(method).uri(uri).header("host", "localhost");
        if !self.cookies.is_empty() {
            let c = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            b = b.header(header::COOKIE, c);
        }
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let body = match body {
            Some(v) => {
                b = b.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            None => Body::empty(),
        };
        let resp = self
            .router
            .clone()
            .oneshot(b.body(body).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let mut headers = Vec::new();
        for (n, v) in resp.headers().iter() {
            if let Ok(s) = v.to_str() {
                if n == header::SET_COOKIE {
                    if let Some((k, val)) = s.split(';').next().and_then(|p| p.split_once('=')) {
                        if val.trim().is_empty() || s.contains("Max-Age=0") {
                            self.cookies.remove(k.trim());
                        } else {
                            self.cookies.insert(k.trim().to_string(), val.trim().to_string());
                        }
                    }
                }
                headers.push((n.as_str().to_string(), s.to_string()));
            }
        }
        let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        Resp {
            status,
            headers,
            body,
        }
    }

    async fn login(&mut self) -> String {
        let r = self
            .send(Method::POST, "/api/auth/login", &[], Some(json!({ "key": MGMT_KEY })))
            .await;
        assert_eq!(r.status, 200, "login: {}", String::from_utf8_lossy(&r.body));
        r.json()["csrf_token"].as_str().unwrap().to_string()
    }
}

fn base_cfg(dir: &TempDir, env: HashMap<String, String>) -> AppConfig {
    AppConfig {
        db_path: Some(dir.path().join("care.db")),
        master_key: Some(KEY_1.to_string()),
        management_key: Some(MGMT_KEY.to_string()),
        env_overrides: Some(env),
        ..Default::default()
    }
}

#[tokio::test]
async fn headers_query_secret_csrf_origin_and_local_only_logout() {
    let dir = TempDir::new().unwrap();
    let mut c = Client::new(build_router(base_cfg(&dir, HashMap::new())).unwrap());

    let st = c.send(Method::GET, "/api/auth/status", &[], None).await;
    assert_eq!(st.status, 200);
    assert!(st.header("cache-control").unwrap().contains("no-store"));
    assert_eq!(st.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(st.header("x-frame-options"), Some("DENY"));
    assert_eq!(st.header("referrer-policy"), Some("same-origin"));
    let csp = st.header("content-security-policy").unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    let j = st.json();
    assert_eq!(j["authenticated"], false);
    assert_eq!(j["oidc_enabled"], false);
    assert!(j.get("csrf_token").is_none(), "no csrf before auth");

    // Secrets in the query string are refused on every path
    for q in ["token=x", "key=x", "api_key=x", "access_token=x"] {
        let r = c.send(Method::GET, &format!("/api/status?{q}"), &[], None).await;
        assert_eq!(r.status, 400, "{q}");
        assert_eq!(r.json()["detail"], "query_secret_forbidden");
    }

    // MANAGEMENT_KEY is a login secret only: it is not an API bearer
    let bearer = format!("Bearer {MGMT_KEY}");
    assert_eq!(
        c.send(Method::GET, "/api/status", &[("authorization", &bearer)], None)
            .await
            .status,
        401
    );

    let csrf = c.login().await;
    let login_set = c.send(Method::GET, "/api/auth/status", &[], None).await;
    assert_eq!(login_set.json()["authenticated"], true);
    assert_eq!(login_set.json()["auth_method"], "management_key");
    assert!(c.cookies.keys().all(|k| k != "lnc_care_csrf"), "no JS-readable csrf cookie");
    assert!(c.cookies.contains_key("lnc_care_sess"));

    // Cookie flags: HttpOnly + SameSite=Lax (Secure auto: absent over plain http)
    let mut raw = Client::new(build_router(base_cfg(&dir, HashMap::new())).unwrap());
    let r = raw
        .send(Method::POST, "/api/auth/login", &[], Some(json!({ "key": MGMT_KEY })))
        .await;
    let sc = r.all("set-cookie").join("|");
    assert!(sc.contains("HttpOnly") && sc.contains("SameSite=Lax") && !sc.contains("Secure"));
    let r = raw
        .send(
            Method::POST,
            "/api/auth/login",
            &[("x-forwarded-proto", "https")],
            Some(json!({ "key": MGMT_KEY })),
        )
        .await;
    assert!(r.all("set-cookie").join("|").contains("Secure"));

    // Spoofed Origin + X-Forwarded-Host never passes; same Origin does
    let evil = [
        ("x-csrf-token", csrf.as_str()),
        ("origin", "https://evil.attacker"),
        ("x-forwarded-host", "evil.attacker"),
    ];
    let r = c
        .send(Method::POST, "/api/admin/shops", &evil, Some(json!({ "name": "S1" })))
        .await;
    assert_eq!(r.status, 403);
    let ok = [("x-csrf-token", csrf.as_str()), ("origin", "http://localhost")];
    let r = c
        .send(Method::POST, "/api/admin/shops", &ok, Some(json!({ "name": "S1" })))
        .await;
    assert_eq!(r.status, 200);
    // Cross-site fetch metadata is refused even with the right token
    let xsite = [("x-csrf-token", csrf.as_str()), ("sec-fetch-site", "cross-site")];
    assert_eq!(
        c.send(Method::POST, "/api/admin/shops", &xsite, Some(json!({ "name": "S2" })))
            .await
            .status,
        403
    );

    // Logout: POST only, same-origin required, local-only
    assert_eq!(c.send(Method::GET, "/api/auth/logout", &[], None).await.status, 405);
    assert_eq!(c.send(Method::POST, "/api/auth/logout", &[], None).await.status, 403);
    assert_eq!(
        c.send(
            Method::POST,
            "/api/auth/logout",
            &[("origin", "https://evil.attacker"), ("x-forwarded-host", "evil.attacker")],
            None
        )
        .await
        .status,
        403
    );
    let out = c
        .send(Method::POST, "/api/auth/logout", &[("origin", "http://localhost")], None)
        .await;
    assert_eq!(out.status, 200);
    assert_eq!(out.json()["local_only"], true);
    assert_eq!(c.send(Method::GET, "/api/keys", &[], None).await.status, 401);
}

#[tokio::test]
async fn revoke_all_sessions_epoch_and_idle_max_lifetime() {
    let dir = TempDir::new().unwrap();
    let cfg_path = dir.path().join("care.db");
    let mut c = Client::new(build_router(base_cfg(&dir, HashMap::new())).unwrap());
    let csrf = c.login().await;
    assert_eq!(c.send(Method::GET, "/api/keys", &[], None).await.status, 200);

    // Idle expiry (12h sliding) enforced server-side
    {
        let db = rusqlite::Connection::open(&cfg_path).unwrap();
        db.execute("UPDATE management_sessions SET idle_expires_at = 1", []).unwrap();
    }
    assert_eq!(c.send(Method::GET, "/api/keys", &[], None).await.status, 401);

    // Max lifetime (7d) enforced even when idle window is fresh
    let mut c2 = Client::new(build_router(base_cfg(&dir, HashMap::new())).unwrap());
    let csrf2 = c2.login().await;
    {
        let db = rusqlite::Connection::open(&cfg_path).unwrap();
        db.execute("UPDATE management_sessions SET max_expires_at = 1", []).unwrap();
    }
    assert_eq!(c2.send(Method::GET, "/api/keys", &[], None).await.status, 401);
    let _ = (csrf, csrf2);

    // session_epoch: revoke-all kills every cookie immediately
    let mut a = Client::new(build_router(base_cfg(&dir, HashMap::new())).unwrap());
    let mut b = Client::new(build_router(base_cfg(&dir, HashMap::new())).unwrap());
    let csrf_a = a.login().await;
    b.login().await;
    let r = a
        .send(
            Method::POST,
            "/api/mgmt/revoke-sessions",
            &[("x-csrf-token", &csrf_a)],
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(r.json()["session_epoch"].as_i64().unwrap() >= 2);
    assert_eq!(a.send(Method::GET, "/api/keys", &[], None).await.status, 401);
    assert_eq!(b.send(Method::GET, "/api/keys", &[], None).await.status, 401);
}

fn ed25519_encoding_key() -> EncodingKey {
    // Deterministic RFC 8032 Ed25519 PKCS#8 fixture (seed [7u8;32]); no PEM / secret literal.
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    pkcs8.extend_from_slice(&[7u8; 32]);
    EncodingKey::from_ed_der(&pkcs8)
}

#[tokio::test]
async fn oidc_pkce_s256_roundtrip_allowlist_and_local_only_logout() {
    let dir = TempDir::new().unwrap();
    let issuer = "https://auth.example.test/realms/lengoc";
    let challenge = Arc::new(Mutex::new(String::new()));
    let nonce = Arc::new(Mutex::new(String::new()));
    let user = Arc::new(Mutex::new("louis".to_string()));
    let verified = Arc::new(Mutex::new(0u32));
    let end_session_hits = Arc::new(Mutex::new(0u32));
    let (ch, no, us, vf, es) = (
        challenge.clone(),
        nonce.clone(),
        user.clone(),
        verified.clone(),
        end_session_hits.clone(),
    );
    let enc = ed25519_encoding_key();
    let transport = mock_transport(move |req: TransportRequest| {
        let json_resp = |v: Value| -> Result<TransportResponse, String> {
            Ok(TransportResponse {
                status: 200,
                headers: HashMap::new(),
                body: serde_json::to_vec(&v).unwrap(),
            })
        };
        if req.url.ends_with("/.well-known/openid-configuration") {
            return json_resp(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/protocol/openid-connect/auth"),
                "token_endpoint": format!("{issuer}/protocol/openid-connect/token"),
                "jwks_uri": format!("{issuer}/protocol/openid-connect/certs"),
                "end_session_endpoint": format!("{issuer}/protocol/openid-connect/logout"),
            }));
        }
        if req.url.ends_with("/certs") {
            return json_resp(json!({ "keys": [{
                "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
                "x": "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
            }]}));
        }
        if req.url.ends_with("/token") {
            let form = String::from_utf8_lossy(req.body.as_deref().unwrap_or_default()).to_string();
            let params: HashMap<String, String> =
                url::form_urlencoded::parse(form.as_bytes()).into_owned().collect();
            let verifier = params.get("code_verifier").cloned().unwrap_or_default();
            let computed = B64_URL.encode(Sha256::digest(verifier.as_bytes()));
            if computed != *ch.lock().unwrap() || params.get("client_secret").map(|s| s.as_str()) != Some("kc-secret-test") {
                return Ok(TransportResponse { status: 400, headers: HashMap::new(), body: b"{}".to_vec() });
            }
            *vf.lock().unwrap() += 1;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let uname = us.lock().unwrap().clone();
            let claims = json!({
                "iss": issuer, "aud": "lnc-care", "sub": format!("sub-{uname}"),
                "preferred_username": uname, "nonce": no.lock().unwrap().clone(),
                "iat": now, "exp": now + 300
            });
            let mut hdr = Header::new(Algorithm::EdDSA);
            hdr.kid = Some("k1".to_string());
            let id_token = encode(&hdr, &claims, &enc).unwrap();
            return json_resp(json!({ "access_token": "a", "id_token": id_token, "token_type": "Bearer" }));
        }
        if req.url.contains("/logout") {
            *es.lock().unwrap() += 1;
        }
        Err("unexpected url".to_string())
    });
    let mut env = HashMap::new();
    for (k, v) in [
        ("OIDC_ENABLED", "true"),
        ("OIDC_ISSUER_URL", issuer),
        ("OIDC_CLIENT_ID", "lnc-care"),
        ("OIDC_CLIENT_SECRET", "kc-secret-test"),
        ("OIDC_REDIRECT_URI", "https://care-mcp.lengoc.me/api/auth/oidc/callback"),
        ("OIDC_ALLOWED_USERS", "louis"),
    ] {
        env.insert(k.to_string(), v.to_string());
    }
    let mut cfg = base_cfg(&dir, env);
    cfg.transport = Some(transport);
    let mut c = Client::new(build_router(cfg).unwrap());

    let status = c.send(Method::GET, "/api/auth/status", &[], None).await.json();
    assert_eq!(status["oidc_enabled"], true);

    for (uname, expect_ok) in [("louis", true), ("mallory", false)] {
        *user.lock().unwrap() = uname.to_string();
        let mut browser = Client::new(c.router.clone());
        let login = browser.send(Method::GET, "/api/auth/oidc/login", &[], None).await;
        assert_eq!(login.status, 303);
        let loc = url::Url::parse(login.header("location").unwrap()).unwrap();
        let q: HashMap<String, String> = loc.query_pairs().into_owned().collect();
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["client_id"], "lnc-care");
        assert!(q["scope"].contains("openid"));
        let tx_cookie = login.all("set-cookie").join("|");
        assert!(tx_cookie.contains("lnc_care_oidc_tx=") && tx_cookie.contains("HttpOnly"));
        *challenge.lock().unwrap() = q["code_challenge"].clone();
        *nonce.lock().unwrap() = q["nonce"].clone();
        let cb = browser
            .send(
                Method::GET,
                &format!(
                    "/api/auth/oidc/callback?code=abc&state={}",
                    url::form_urlencoded::byte_serialize(q["state"].as_bytes()).collect::<String>()
                ),
                &[],
                None,
            )
            .await;
        assert_eq!(cb.status, 303);
        if expect_ok {
            assert_eq!(cb.header("location"), Some("/admin/"));
            let s = browser.send(Method::GET, "/api/auth/status", &[], None).await.json();
            assert_eq!(s["authenticated"], true);
            assert_eq!(s["auth_method"], "oidc");
            assert_eq!(s["username"], "louis");
            let csrf = s["csrf_token"].as_str().unwrap().to_string();
            // Local-only logout: the IdP end_session_endpoint is never contacted
            let out = browser
                .send(
                    Method::POST,
                    "/api/auth/logout",
                    &[("origin", "http://localhost"), ("x-csrf-token", &csrf)],
                    None,
                )
                .await;
            assert_eq!(out.status, 200);
            assert_eq!(
                browser.send(Method::GET, "/api/auth/status", &[], None).await.json()["authenticated"],
                false
            );
        } else {
            assert!(cb.header("location").unwrap().contains("error=oidc_user_not_allowed"));
            let s = browser.send(Method::GET, "/api/auth/status", &[], None).await.json();
            assert_eq!(s["authenticated"], false);
        }
    }
    assert_eq!(*verified.lock().unwrap(), 2, "PKCE S256 verified on both token exchanges");
    assert_eq!(*end_session_hits.lock().unwrap(), 0);

    // Tampered state / replayed callback without tx cookie is refused
    let mut browser = Client::new(c.router.clone());
    let cb = browser
        .send(Method::GET, "/api/auth/oidc/callback?code=abc&state=forged", &[], None)
        .await;
    assert!(cb.header("location").unwrap().contains("error=oidc_state"));
}

#[tokio::test]
async fn copy_rate_limit_and_inbound_mcp_connector_lifecycle() {
    let dir = TempDir::new().unwrap();
    let mut c = Client::new(build_router(base_cfg(&dir, HashMap::new())).unwrap());
    let csrf = c.login().await;
    let h = [("x-csrf-token", csrf.as_str())];

    // Unpaired inbound connector: nothing to copy yet
    let info = c.send(Method::GET, "/api/admin/connector", &[], None).await.json();
    assert_eq!(info["status"], "unpaired");
    assert_eq!(info["bearer_copy_available"], false);
    assert_eq!(
        c.send(Method::POST, "/api/mcp-connectors/inbound-mcp/copy", &h, None).await.status,
        409
    );

    // Rotate bearer + delegation (secrets shown once), then copy returns the sealed value
    let rb = c
        .send(Method::POST, "/api/mcp-connectors/inbound-mcp/rotate?field=bearer", &h, Some(json!({})))
        .await;
    assert_eq!(rb.status, 200);
    let bearer = rb.json()["secret"].as_str().unwrap().to_string();
    let rd = c
        .send(Method::POST, "/api/mcp-connectors/inbound-mcp/rotate?field=delegation", &h, Some(json!({})))
        .await;
    assert_eq!(rd.status, 200);
    let info = c.send(Method::GET, "/api/admin/connector", &[], None).await.json();
    assert_eq!(info["status"], "active");
    assert_eq!(info["bearer_copy_available"], true);
    assert!(!info.to_string().contains(&bearer), "GET never leaks the secret");
    let cp = c
        .send(Method::POST, "/api/mcp-connectors/inbound-mcp/copy?field=bearer", &h, None)
        .await;
    assert_eq!(cp.status, 200);
    assert_eq!(cp.json()["secret"], bearer.as_str());
    assert!(cp.header("cache-control").unwrap().contains("no-store"));

    // Test probe lists the care__ tools
    let probe = c
        .send(Method::POST, "/api/mcp-connectors/inbound-mcp/test", &h, None)
        .await
        .json();
    assert_eq!(probe["paired"], true);
    assert!(probe["tool_count"].as_u64().unwrap() > 0);

    // Revoke blocks /mcp immediately (valid bearer, connector revoked), reactivate restores auth path
    let mcp_hdr = format!("Bearer {bearer}");
    let before = c
        .send(Method::POST, "/mcp", &[("authorization", &mcp_hdr)], Some(json!({"jsonrpc":"2.0","id":1,"method":"ping"})))
        .await;
    assert_ne!(before.json()["error"], "mcp_connector_revoked");
    let rv = c
        .send(Method::POST, "/api/mcp-connectors/inbound-mcp/revoke", &h, Some(json!({ "revoked": true })))
        .await;
    assert_eq!(rv.json()["status"], "revoked");
    let blocked = c
        .send(Method::POST, "/mcp", &[("authorization", &mcp_hdr)], Some(json!({"jsonrpc":"2.0","id":1,"method":"ping"})))
        .await;
    assert_eq!(blocked.status, 403);
    assert_eq!(blocked.json()["error"], "mcp_connector_revoked");
    let rv = c
        .send(Method::POST, "/api/mcp-connectors/inbound-mcp/revoke", &h, Some(json!({ "revoked": false })))
        .await;
    assert_eq!(rv.json()["status"], "active");

    // Remove clears the runtime pairing secret
    let del = c
        .send(Method::DELETE, "/api/mcp-connectors/inbound-mcp?field=bearer", &h, None)
        .await;
    assert_eq!(del.status, 200);
    assert_eq!(
        c.send(Method::POST, "/api/mcp-connectors/inbound-mcp/copy?field=bearer", &h, None).await.status,
        409
    );

    // API key Copy: 15 / 5 min / IP -> 429 on the 16th (the connector copy above already counted 1+... reset by new app)
    let mut k = Client::new(build_router(base_cfg(&dir, HashMap::new())).unwrap());
    let kcsrf = k.login().await;
    let kh = [("x-csrf-token", kcsrf.as_str())];
    let created = k
        .send(Method::POST, "/api/keys", &kh, Some(json!({ "label": "Rate" })))
        .await
        .json();
    let id = created["item"]["id"].as_i64().unwrap();
    let mut last = 0;
    for _ in 0..15 {
        last = k
            .send(Method::POST, &format!("/api/keys/{id}/copy"), &kh, None)
            .await
            .status;
        assert_eq!(last, 200);
    }
    let over = k
        .send(Method::POST, &format!("/api/keys/{id}/copy"), &kh, None)
        .await;
    assert_eq!((last, over.status), (200, 429));
    assert_eq!(over.json()["detail"], "copy_rate_limited");
}

#[tokio::test]
async fn legacy_pbkdf2_runtime_key_and_legacy_sha256_api_key_keep_working() {
    use pbkdf2::pbkdf2_hmac;
    let dir = TempDir::new().unwrap();
    // First boot with a bootstrap key creates an Argon2id runtime state (no env MANAGEMENT_KEY).
    let mut env = HashMap::new();
    env.insert("CARE_ADMIN_BOOTSTRAP_KEY".to_string(), "bootstrap-boot-key-abcdef".to_string());
    let cfg = |env: HashMap<String, String>| AppConfig {
        db_path: Some(dir.path().join("care.db")),
        master_key: Some(KEY_1.to_string()),
        env_overrides: Some(env),
        ..Default::default()
    };
    drop(build_router(cfg(env.clone())).unwrap());
    // Rewrite the runtime state as a legacy PBKDF2 row and add a legacy SHA-256 API key.
    {
        let db = rusqlite::Connection::open(dir.path().join("care.db")).unwrap();
        let salt = "00112233445566778899aabbccddeeff";
        let mut out = [0u8; 32];
        pbkdf2_hmac::<Sha256>(b"legacy-runtime-key-xyz-1", salt.as_bytes(), 200_000, &mut out);
        let state = json!({
            "salt": salt, "hash": hex::encode(out), "prefix": "legacy-runti", "session_secret": "s", "created_at": 1
        });
        db.execute(
            "UPDATE runtime_settings SET value=?1 WHERE key='__mgmt_state'",
            [state.to_string()],
        )
        .unwrap();
        db.execute(
            "INSERT INTO api_keys (organization_id, label, prefix, key_hash, status, created_at)
             VALUES ('lnc-default', 'legacy', 'care_legacy', ?1, 'enabled', 1)",
            [hex::encode(Sha256::digest(b"care_legacy_secret_value_0001"))],
        )
        .unwrap();
    }
    let mut c = Client::new(build_router(cfg(env)).unwrap());
    let bad = c
        .send(Method::POST, "/api/auth/login", &[], Some(json!({ "key": "nope-nope-nope-nope" })))
        .await;
    assert_eq!(bad.status, 401);
    let ok = c
        .send(Method::POST, "/api/auth/login", &[], Some(json!({ "key": "legacy-runtime-key-xyz-1" })))
        .await;
    assert_eq!(ok.status, 200);
    // Upgraded to Argon2id after a successful sign-in; the same key still works
    {
        let db = rusqlite::Connection::open(dir.path().join("care.db")).unwrap();
        let v: String = db
            .query_row("SELECT value FROM runtime_settings WHERE key='__mgmt_state'", [], |r| r.get(0))
            .unwrap();
        assert!(v.contains("$argon2id$v=19$m=65536,t=3,p=4$"), "{v}");
        assert!(!v.contains("legacy-runtime-key-xyz-1"));
    }
    let mut c2 = Client::new(c.router.clone());
    assert_eq!(
        c2.send(Method::POST, "/api/auth/login", &[], Some(json!({ "key": "legacy-runtime-key-xyz-1" })))
            .await
            .status,
        200
    );
    // Legacy SHA-256 digest API key (pre-upgrade) still authenticates Bearer calls
    let hdr = "Bearer care_legacy_secret_value_0001".to_string();
    assert_eq!(
        c.send(Method::GET, "/api/status", &[("authorization", &hdr)], None).await.status,
        200
    );
}

#[tokio::test]
async fn cfg_or_env_oidc_management_hot_reload_validation_and_logout_405() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("care.db");
    let enc = ed25519_encoding_key();

    // Seed env OIDC values on boot, then test DB override + hot-reload + reset.
    let mut env = HashMap::new();
    env.insert("OIDC_ISSUER_URL".to_string(), "https://env-sso.example/realms/care".to_string());
    env.insert("OIDC_CLIENT_ID".to_string(), "env-client".to_string());
    env.insert("OIDC_CLIENT_SECRET".to_string(), "env-client-secret-123".to_string());
    env.insert("OIDC_ALLOWED_USERS".to_string(), "env-user@lengoc.me".to_string());

    let transport = mock_transport(move |req: TransportRequest| {
        if req.url == "https://hot-sso.example/realms/lnc/.well-known/openid-configuration" {
            return Ok(TransportResponse {
                status: 200,
                headers: HashMap::new(),
                body: json!({
                    "issuer": "https://hot-sso.example/realms/lnc",
                    "authorization_endpoint": "https://hot-sso.example/realms/lnc/protocol/openid-connect/auth",
                    "token_endpoint": "https://hot-sso.example/realms/lnc/protocol/openid-connect/token",
                    "jwks_uri": "https://hot-sso.example/realms/lnc/protocol/openid-connect/certs"
                })
                .to_string()
                .into_bytes(),
            });
        }
        if req.url == "https://hot-sso.example/realms/lnc/protocol/openid-connect/certs" {
            return Ok(TransportResponse {
                status: 200,
                headers: HashMap::new(),
                body: json!({
                    "keys": [{
                        "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
                        "x": "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
                    }]
                })
                .to_string()
                .into_bytes(),
            });
        }
        if req.url == "https://hot-sso.example/realms/lnc/protocol/openid-connect/token" {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let mut h = Header::new(Algorithm::EdDSA);
            h.kid = Some("k1".to_string());
            let claims = json!({
                "iss": "https://hot-sso.example/realms/lnc",
                "sub": "u-hot",
                "aud": "lnc-care-hot",
                "exp": now + 600,
                "iat": now,
                "email": "admin@lengoc.me",
                "preferred_username": "admin@lengoc.me"
            });
            let id_token = encode(&h, &claims, &enc).unwrap();
            return Ok(TransportResponse {
                status: 200,
                headers: HashMap::new(),
                body: json!({ "access_token": "at", "id_token": id_token })
                    .to_string()
                    .into_bytes(),
            });
        }
        Err(format!("unexpected url: {}", req.url))
    });

    let router = build_router(AppConfig {
        db_path: Some(db_path.clone()),
        management_key: Some(MGMT_KEY.to_string()),
        master_key: Some(KEY_1.to_string()),
        env_overrides: Some(env.clone()),
        transport: Some(transport),
        ..Default::default()
    })
    .unwrap();

    let mut c = Client::new(router);
    // Unauthenticated admin OIDC read must fail closed; GET logout must return 405
    assert_eq!(c.send(Method::GET, "/api/admin/oidc", &[], None).await.status, 401);
    assert_eq!(c.send(Method::GET, "/api/auth/logout", &[], None).await.status, 405);

    let csrf = c.login().await;
    let h = [("origin", "http://localhost"), ("x-csrf-token", csrf.as_str())];

    // Initial summary reflects env config with masked secret + no-store header
    let initial = c.send(Method::GET, "/api/admin/oidc", &[], None).await;
    assert_eq!(initial.status, 200);
    assert_eq!(initial.header("cache-control"), Some("no-store, private"));
    let init_j = initial.json();
    assert_eq!(init_j["source"], "environment");
    assert_eq!(init_j["client_secret_masked"], "********");
    assert_eq!(init_j["client_secret_configured"], true);

    // Wildcard '*' and empty allowed_users rejected with 422
    let wild = c
        .send(
            Method::PUT,
            "/api/admin/oidc",
            &h,
            Some(json!({
                "enabled": true,
                "issuer_url": "https://hot-sso.example/realms/lnc",
                "client_id": "lnc-care-hot",
                "client_secret": "hot-secret-value-123",
                "allowed_users": "*"
            })),
        )
        .await;
    assert_eq!(wild.status, 422);

    let empty_users = c
        .send(
            Method::PUT,
            "/api/admin/oidc",
            &h,
            Some(json!({
                "enabled": true,
                "issuer_url": "https://hot-sso.example/realms/lnc",
                "client_id": "lnc-care-hot",
                "client_secret": "hot-secret-value-123",
                "allowed_users": ""
            })),
        )
        .await;
    assert_eq!(empty_users.status, 422);

    // SSRF metadata endpoint blocked on /test
    let ssrf = c
        .send(
            Method::POST,
            "/api/admin/oidc/test",
            &h,
            Some(json!({ "issuer_url": "http://169.254.169.254/latest/meta-data" })),
        )
        .await;
    assert_eq!(ssrf.status, 422);

    // Probe valid OIDC discovery + JWKS before saving
    let probe = c
        .send(
            Method::POST,
            "/api/admin/oidc/test",
            &h,
            Some(json!({ "issuer_url": "https://hot-sso.example/realms/lnc" })),
        )
        .await;
    assert_eq!(probe.status, 200);
    assert_eq!(probe.json()["ok"], true);
    assert_eq!(probe.json()["jwk_count"], 1);

    // Save DB override (even though env OIDC_* vars exist -> cfg_or_env allows DB override + hot-reload!)
    let saved = c
        .send(
            Method::PUT,
            "/api/admin/oidc",
            &h,
            Some(json!({
                "enabled": true,
                "issuer_url": "https://hot-sso.example/realms/lnc",
                "client_id": "lnc-care-hot",
                "client_secret": "hot-secret-xyz-999",
                "redirect_uri": "https://care.example/api/auth/oidc/callback",
                "allowed_users": ["Admin@lengoc.me"],
                "scopes": "openid profile email"
            })),
        )
        .await;
    assert_eq!(saved.status, 200);
    let saved_j = saved.json();
    assert_eq!(saved_j["source"], "database");
    assert_eq!(saved_j["active"], true);
    assert_eq!(saved_j["client_secret_masked"], "********");
    assert!(!String::from_utf8_lossy(&saved.body).contains("hot-secret-xyz-999"));

    // Blank/masked secret update preserves the encrypted vault client_secret (omitBlankSecrets)
    let updated_blank = c
        .send(
            Method::PATCH,
            "/api/oidc",
            &h,
            Some(json!({
                "enabled": true,
                "issuer_url": "https://hot-sso.example/realms/lnc",
                "client_id": "lnc-care-hot",
                "client_secret": "",
                "allowed_users": ["admin@lengoc.me", "ops@lengoc.me"]
            })),
        )
        .await;
    assert_eq!(updated_blank.status, 200);

    // Secret in vault must be encrypted (never plaintext in sqlite)
    {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        let raw_blobs: String = db
            .query_row("SELECT envelope FROM secret_envelopes WHERE kind='auth' AND subject='oidc_client_secret'", [], |r| r.get(0))
            .unwrap();
        assert!(!raw_blobs.contains("hot-secret-xyz-999"));
    }

    // Immediate hot-reload verified: fresh browser can initiate PKCE S256 against the newly saved issuer WITHOUT restart
    let mut oidc_client = Client::new(c.router.clone());
    let start = oidc_client.send(Method::GET, "/api/auth/oidc/login", &[], None).await;
    assert_eq!(start.status, 303);
    let loc = start.header("location").unwrap();
    assert!(loc.starts_with("https://hot-sso.example/realms/lnc/protocol/openid-connect/auth?"));
    assert!(loc.contains("client_id=lnc-care-hot"));

    // Verify local-only POST /api/auth/logout returns JSON ok without Keycloak end_session redirect
    let logout = c
        .send(Method::POST, "/api/auth/logout", &h, None)
        .await;
    assert_eq!(logout.status, 200);
    assert_eq!(logout.json()["ok"], true);
    assert!(logout.header("location").is_none());

    // Sign back in and reset OIDC overrides back to env defaults
    let csrf2 = c.login().await;
    let h2 = [("origin", "http://localhost"), ("x-csrf-token", csrf2.as_str())];
    let reset = c
        .send(Method::POST, "/api/admin/oidc/reset", &h2, None)
        .await;
    assert_eq!(reset.status, 200);
    assert_eq!(reset.json()["source"], "environment");
    assert_eq!(reset.json()["client_id"], "env-client");
}

#[tokio::test]
async fn automatic_master_key_boot_rotation_preserves_vault_and_api_keys() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("care.db");
    let key_v1 = KEY_1;
    let key_v2 = "2222222222222222222222222222222222222222222222222222222222222222";

    // Boot 1 (V1): store encrypted OIDC secret, inbound pairing secrets, and create an API key.
    let mut c1 = Client::new(
        build_router(AppConfig {
            db_path: Some(db_path.clone()),
            management_key: Some(MGMT_KEY.to_string()),
            master_key: Some(key_v1.to_string()),
            ..Default::default()
        })
        .unwrap(),
    );
    let csrf1 = c1.login().await;
    let h1 = [("origin", "http://localhost"), ("x-csrf-token", csrf1.as_str())];

    assert_eq!(
        c1.send(
            Method::PUT,
            "/api/admin/oidc",
            &h1,
            Some(json!({
                "enabled": true,
                "issuer_url": "https://sso.lengoc.me/realms/lnc",
                "client_id": "lnc-care",
                "client_secret": "v1-oidc-secret-preserve-me",
                "allowed_users": ["boss@lengoc.me"]
            })),
        )
        .await
        .status,
        200
    );

    let created_key = c1
        .send(
            Method::POST,
            "/api/keys",
            &h1,
            Some(json!({ "label": "ci-runner" })),
        )
        .await;
    assert_eq!(created_key.status, 200);
    let key_id = created_key.json()["item"]["id"].as_i64().unwrap();
    let key_secret = created_key.json()["secret"].as_str().unwrap().to_string();

    let rot_mcp = c1
        .send(
            Method::POST,
            "/api/mcp-connectors/inbound-mcp/rotate?field=bearer",
            &h1,
            Some(json!({})),
        )
        .await;
    assert_eq!(rot_mcp.status, 200);
    let mcp_bearer = rot_mcp.json()["secret"].as_str().unwrap().to_string();
    drop(c1);

    // Boot 2 (V2 + LNC_MASTER_KEY_OLD=V1): automatic boot rotation rewraps envelopes + re-peppers hmac1: API keys.
    let mut env_v2_old = HashMap::new();
    env_v2_old.insert("LNC_MASTER_KEY_OLD".to_string(), key_v1.to_string());
    let mut c2 = Client::new(
        build_router(AppConfig {
            db_path: Some(db_path.clone()),
            management_key: Some(MGMT_KEY.to_string()),
            master_key: Some(key_v2.to_string()),
            env_overrides: Some(env_v2_old),
            ..Default::default()
        })
        .unwrap(),
    );
    c2.login().await;
    let audit = c2.send(Method::GET, "/api/admin/audit", &[], None).await.json();
    let actions: Vec<&str> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x["action"].as_str())
        .collect();
    assert!(actions.contains(&"vault.master_key_rotated"), "expected vault.master_key_rotated audit entry, got {actions:?}");
    drop(c2);

    // Boot 3 (V2 only, NO old key): everything must decrypt, verify, copy, and authenticate with V2 alone!
    let mut c3 = Client::new(
        build_router(AppConfig {
            db_path: Some(db_path.clone()),
            management_key: Some(MGMT_KEY.to_string()),
            master_key: Some(key_v2.to_string()),
            ..Default::default()
        })
        .unwrap(),
    );

    // API key Bearer auth must pass with new V2 HMAC pepper
    let auth_hdr = format!("Bearer {key_secret}");
    assert_eq!(
        c3.send(Method::GET, "/api/status", &[("authorization", &auth_hdr)], None)
            .await
            .status,
        200
    );

    let csrf3 = c3.login().await;
    let h3 = [("origin", "http://localhost"), ("x-csrf-token", csrf3.as_str())];
    // Copy API key still returns exact original secret
    let copy_key = c3
        .send(
            Method::POST,
            &format!("/api/keys/{key_id}/copy"),
            &h3,
            None,
        )
        .await;
    assert_eq!(copy_key.status, 200);
    assert_eq!(copy_key.json()["secret"], key_secret);

    // Copy inbound MCP bearer still returns exact original secret
    let copy_mcp = c3
        .send(
            Method::POST,
            "/api/mcp-connectors/inbound-mcp/copy?field=bearer",
            &h3,
            None,
        )
        .await;
    assert_eq!(copy_mcp.status, 200);
    assert_eq!(copy_mcp.json()["secret"], mcp_bearer);

    // OIDC config survived V1 -> V2 rotation active and secret-intact
    let oidc_sum = c3.send(Method::GET, "/api/admin/oidc", &[], None).await.json();
    assert_eq!(oidc_sum["active"], true);
    assert_eq!(oidc_sum["client_secret_configured"], true);
    assert_eq!(oidc_sum["client_id"], "lnc-care");
}

#[tokio::test]
async fn rule_t2_agent_hub_env_aliases_and_v4s_contract_a_connector() {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let dir = TempDir::new().unwrap();
    let hub_token = "hub-shared-v4s-token-9876543210";
    let mut env = HashMap::new();
    env.insert("LNC_AGENTS_HUB_URL".to_string(), "http://127.0.0.1:49999".to_string());
    env.insert("LNC_AGENTS_HUB_PUBLIC_URL".to_string(), "https://agents.lengoc.me".to_string());
    env.insert("LNC_AGENTS_HUB_TOKEN".to_string(), hub_token.to_string());
    env.insert("MCP_CONNECTOR_AUDIENCE".to_string(), "lnc-care".to_string());

    let mut c = Client::new(
        build_router(AppConfig {
            db_path: Some(dir.path().join("care.db")),
            management_key: Some(MGMT_KEY.to_string()),
            master_key: Some(KEY_1.to_string()),
            env_overrides: Some(env),
            ..Default::default()
        })
        .unwrap(),
    );

    // Health routes bypass Host header gate cleanly and advertise protocol=v4s
    for path in [
        "/v1/app-connectors/lnc-care/health",
        "/v1/app-connectors/lnc-care/healthz",
        "/v1/app-connectors/lnc-care/mcp/health",
    ] {
        let r = c
            .send(Method::GET, path, &[("host", "internal-docker-service:8000")], None)
            .await;
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.json()["protocol"], "v4s");
    }

    // Also verify LNC_AGENTS_HUB_* aliases surfaced on /api/admin/hub/status once signed in
    c.login().await;
    let hub_sum = c.send(Method::GET, "/api/admin/hub/status", &[], None).await;
    assert_eq!(hub_sum.status, 200);
    assert_eq!(hub_sum.json()["agent_hub"]["configured"], true);
    assert_eq!(hub_sum.json()["agent_hub"]["has_api_key"], true);
    assert_eq!(hub_sum.json()["agent_hub"]["public_url"], "https://agents.lengoc.me");

    let sign_v4s = |nonce: &str, scopes: &[&str], secret: &str| -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut sorted: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        sorted.sort();
        sorted.dedup();
        let ctx_sha = hex::encode(Sha256::digest(b"{}"));
        let canonical = format!(
            "v4s\nlnc-care\nagent-iris\nboss@lengoc.me\nlnc-care\n{now}\n{nonce}\n{}\n{ctx_sha}",
            sorted.join(",")
        );
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        B64_URL.encode(
            serde_json::to_vec(&json!({
                "version": "v4s",
                "audience": "lnc-care",
                "caller_agent": "agent-iris",
                "delegated_user": "boss@lengoc.me",
                "app_id": "lnc-care",
                "timestamp": now,
                "expires_at": now + 120,
                "nonce": nonce,
                "scopes": scopes,
                "resource_ctx": {},
                "resource_ctx_sha256": ctx_sha,
                "signature": sig
            }))
            .unwrap(),
        )
    };

    let rpc_list = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
    let auth_hdr = format!("Bearer {hub_token}");

    // Missing X-Lnc-V4s-Grant -> 401
    let missing = c
        .send(
            Method::POST,
            "/v1/app-connectors/lnc-care/mcp",
            &[("authorization", &auth_hdr), ("host", "care-mcp-internal:8000")],
            Some(rpc_list.clone()),
        )
        .await;
    assert_eq!(missing.status, 401);

    // Bad HMAC signature -> 403
    let bad_grant = sign_v4s("nonce_bad_sig_000001", &["lnc:read"], "wrong-secret");
    let bad_sig = c
        .send(
            Method::POST,
            "/v1/app-connectors/lnc-care/mcp",
            &[
                ("authorization", &auth_hdr),
                ("x-lnc-v4s-grant", &bad_grant),
                ("host", "care-mcp-internal:8000"),
            ],
            Some(rpc_list.clone()),
        )
        .await;
    assert_eq!(bad_sig.status, 403);

    // Valid Contract A call succeeds (even over non-allowed Docker host header)
    let good_grant = sign_v4s("nonce_valid_v4s_00001", &["lnc:read"], hub_token);
    let ok = c
        .send(
            Method::POST,
            "/v1/app-connectors/lnc-care/mcp",
            &[
                ("authorization", &auth_hdr),
                ("x-lnc-v4s-grant", &good_grant),
                ("host", "care-mcp-internal:8000"),
            ],
            Some(rpc_list.clone()),
        )
        .await;
    assert_eq!(ok.status, 200);
    assert!(ok.json()["result"]["tools"].is_array());

    // Single-use nonce replay rejected -> 403
    let replay = c
        .send(
            Method::POST,
            "/v1/app-connectors/lnc-care/mcp",
            &[
                ("authorization", &auth_hdr),
                ("x-lnc-v4s-grant", &good_grant),
            ],
            Some(rpc_list),
        )
        .await;
    assert_eq!(replay.status, 403);
}
