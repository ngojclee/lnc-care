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
