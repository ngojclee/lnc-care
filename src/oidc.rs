//! Keycloak (OIDC) Authorization Code + PKCE S256 sign-in for the LNC Care admin console.
//!
//! Confidential client, `OIDC_ALLOWED_USERS` allowlist (fail-closed when empty), sealed
//! `HttpOnly` transaction cookie (AES-256-GCM, HKDF `oidc-tx` subkey), RS/ES/EdDSA ID-token
//! verification (HS* refused), nonce + state checks. Logout is local-only (see `routes.rs`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Extension;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::auth_core::{self, OIDC_TX_COOKIE, OIDC_TX_TTL_SECS};
use crate::routes::{now_unix, AppState};
use crate::transport::{SharedTransport, TransportRequest};
use crate::{audit, store};

const DISCOVERY_TTL_SECS: i64 = 300;
const TX_AAD: &[u8] = b"oidc_tx:v1";

#[derive(Clone, Debug, Default)]
pub struct OidcConfig {
    pub enabled: bool,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub allowed_users: Vec<String>,
    pub scopes: String,
    pub source: String,
}

pub fn validate_http_url(raw: &str, label: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let parsed = Url::parse(trimmed)
        .map_err(|_| format!("{label} must be a valid HTTP(S) URL"))?;
    let scheme = parsed.scheme();
    if !matches!(scheme, "http" | "https") {
        return Err(format!("{label} must use http:// or https://"));
    }
    let Some(host) = parsed.host_str() else {
        return Err(format!("{label} must include a host"));
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{label} must not embed credentials"));
    }
    if parsed.fragment().is_some() {
        return Err(format!("{label} must not include a URL fragment"));
    }
    let h_low = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if h_low == "metadata.google.internal"
        || h_low == "0.0.0.0"
        || h_low == "::"
        || h_low.starts_with("169.254.")
        || h_low.starts_with("fe80:")
    {
        return Err(format!("{label} host is blocked by SSRF policy"));
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

pub fn normalize_scopes(raw: &str) -> String {
    let mut parts: Vec<String> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !parts.iter().any(|s| s == "openid") {
        parts.insert(0, "openid".to_string());
    }
    if parts.len() == 1 && parts[0] == "openid" && raw.trim().is_empty() {
        return "openid profile email".to_string();
    }
    let mut deduped = Vec::new();
    for p in parts {
        if !deduped.contains(&p) {
            deduped.push(p);
        }
    }
    deduped.join(" ")
}

pub fn parse_allowed_users_value(val: &serde_json::Value) -> Result<Vec<String>, String> {
    let raw_items: Vec<String> = match val {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect(),
        serde_json::Value::String(s) => s
            .split([',', '\n', '\r'])
            .map(|x| x.trim().to_ascii_lowercase())
            .filter(|x| !x.is_empty())
            .collect(),
        serde_json::Value::Null => Vec::new(),
        _ => return Err("allowed_users must be a string or list of strings".to_string()),
    };
    let mut out = Vec::new();
    for item in raw_items {
        if item.contains('*') {
            return Err("Wildcard '*' is not allowed in allowed_users".to_string());
        }
        if !out.contains(&item) {
            out.push(item);
        }
    }
    Ok(out)
}

impl OidcConfig {
    pub fn from_env(env: &HashMap<String, String>) -> Self {
        let get = |k: &str| {
            env.get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let issuer_url = get("OIDC_ISSUER_URL")
            .map(|v| v.trim_end_matches('/').to_string())
            .unwrap_or_default();
        let client_id = get("OIDC_CLIENT_ID").unwrap_or_default();
        let client_secret = get("OIDC_CLIENT_SECRET").unwrap_or_default();
        let redirect_uri = get("OIDC_REDIRECT_URI").unwrap_or_default();
        let allowed_users: Vec<String> = get("OIDC_ALLOWED_USERS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty() && !s.contains('*'))
            .collect();
        let has_fields = !issuer_url.is_empty() && !client_id.is_empty() && !client_secret.is_empty();
        let enabled = match get("OIDC_ENABLED").map(|v| v.to_ascii_lowercase()).as_deref() {
            Some("false" | "0" | "no") => false,
            _ => has_fields,
        };
        let scopes = get("OIDC_SCOPES")
            .map(|s| s.replace(',', " "))
            .filter(|s| s.split_whitespace().any(|x| x == "openid"))
            .unwrap_or_else(|| "openid profile email".to_string());
        let env_any = !issuer_url.is_empty()
            || !client_id.is_empty()
            || !client_secret.is_empty()
            || !redirect_uri.is_empty()
            || !allowed_users.is_empty();
        Self {
            enabled,
            scopes,
            issuer_url,
            client_id,
            client_secret,
            redirect_uri,
            allowed_users,
            source: if env_any {
                "environment".to_string()
            } else {
                "unset".to_string()
            },
        }
    }

    pub fn is_active(&self) -> bool {
        self.enabled
            && !self.issuer_url.is_empty()
            && !self.client_id.is_empty()
            && !self.client_secret.is_empty()
    }

    pub fn issuer_host(&self) -> String {
        auth_core::url_host(&self.issuer_url).unwrap_or_default()
    }

    /// Fail closed when `OIDC_ALLOWED_USERS` is empty or contains a wildcard.
    pub fn user_allowed(&self, candidates: &[Option<&str>]) -> Option<String> {
        if self.allowed_users.is_empty() || self.allowed_users.iter().any(|u| u.contains('*')) {
            return None;
        }
        for cand in candidates.iter().flatten() {
            let clean = cand.trim();
            if !clean.is_empty() && self.allowed_users.iter().any(|u| u == &clean.to_ascii_lowercase()) {
                return Some(clean.to_string());
            }
        }
        None
    }
}

pub fn load_effective_config(
    db: &rusqlite::Connection,
    org: &str,
    env_cfg: &OidcConfig,
    vault: &crate::vault::Vault,
) -> Result<OidcConfig, String> {
    let db_raw: Option<String> = db
        .query_row(
            "SELECT value FROM runtime_settings WHERE organization_id=?1 AND key='__oidc_config'",
            rusqlite::params![org],
            |r| r.get(0),
        )
        .ok();
    let vault_secret = if vault.ready {
        vault
            .get(db, org, "auth", "oidc_client_secret")
            .ok()
            .flatten()
            .and_then(|v| {
                v.get("client_secret")
                    .and_then(|s| s.as_str())
                    .map(|s| s.trim().to_string())
            })
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    let Some(raw) = db_raw.filter(|s| !s.trim().is_empty()) else {
        let mut eff = env_cfg.clone();
        if let Some(sec) = vault_secret {
            eff.client_secret = sec;
            eff.source = "database".to_string();
        }
        return Ok(eff);
    };

    let obj: serde_json::Value =
        serde_json::from_str(&raw).map_err(|_| "Corrupt runtime OIDC configuration".to_string())?;
    let issuer_url = obj
        .get("issuer_url")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|| env_cfg.issuer_url.clone());
    let client_id = obj
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| env_cfg.client_id.clone());
    let redirect_uri = obj
        .get("redirect_uri")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| env_cfg.redirect_uri.clone());
    let allowed_users = match obj.get("allowed_users") {
        Some(v) => parse_allowed_users_value(v).unwrap_or_default(),
        None => env_cfg.allowed_users.clone(),
    };
    let scopes = obj
        .get("scopes")
        .and_then(|v| v.as_str())
        .map(normalize_scopes)
        .unwrap_or_else(|| env_cfg.scopes.clone());
    let enabled = obj
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let client_secret = vault_secret.unwrap_or_else(|| env_cfg.client_secret.clone());

    Ok(OidcConfig {
        enabled,
        issuer_url,
        client_id,
        client_secret,
        redirect_uri,
        allowed_users,
        scopes,
        source: "database".to_string(),
    })
}

pub fn effective_summary(cfg: &OidcConfig, env_cfg: &OidcConfig) -> serde_json::Value {
    let has_secret = !cfg.client_secret.is_empty();
    let env_present = !env_cfg.issuer_url.is_empty()
        || !env_cfg.client_id.is_empty()
        || !env_cfg.client_secret.is_empty()
        || !env_cfg.allowed_users.is_empty();
    json!({
        "enabled": cfg.enabled,
        "active": cfg.is_active(),
        "source": if cfg.source.is_empty() { "unset" } else { cfg.source.as_str() },
        "issuer_url": cfg.issuer_url,
        "issuer_host": cfg.issuer_host(),
        "client_id": cfg.client_id,
        "client_secret_configured": has_secret,
        "client_secret_masked": if has_secret { "********" } else { "" },
        "has_client_secret": has_secret,
        "redirect_uri": cfg.redirect_uri,
        "allowed_users": cfg.allowed_users,
        "scopes": cfg.scopes,
        "env_present": env_present,
    })
}

pub async fn probe_discovery_and_jwks(
    transport: SharedTransport,
    issuer_url: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let clean_iss = validate_http_url(issuer_url, "issuer_url")
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
    if clean_iss.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "issuer_url is required to test OIDC discovery".to_string(),
        ));
    }
    let disc_url = format!("{clean_iss}/.well-known/openid-configuration");
    let body = http_get_json(transport.clone(), disc_url)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "oidc_discovery_unreachable".to_string()))?;
    let doc: DiscoveryDoc = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_GATEWAY, "oidc_discovery_invalid".to_string()))?;
    let jwks_url = validate_http_url(&doc.jwks_uri, "jwks_uri")
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let jwks_body = http_get_json(transport, jwks_url)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "oidc_jwks_unreachable".to_string()))?;
    let set: JwkSet = serde_json::from_slice(&jwks_body)
        .map_err(|_| (StatusCode::BAD_GATEWAY, "oidc_jwks_invalid".to_string()))?;
    Ok(json!({
        "ok": true,
        "issuer": doc.issuer,
        "authorization_endpoint": doc.authorization_endpoint,
        "token_endpoint": doc.token_endpoint,
        "jwks_uri": doc.jwks_uri,
        "jwk_count": set.keys.len(),
    }))
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDoc {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Default)]
pub struct OidcCache {
    pub discovery: Option<(i64, DiscoveryDoc)>,
    pub jwks: Option<(i64, JwkSet)>,
}

#[derive(Serialize, Deserialize)]
struct OidcTx {
    state: String,
    nonce: String,
    code_verifier: String,
    redirect_uri: String,
    created_at: i64,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdClaims {
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

fn pkce_challenge_s256(verifier: &str) -> String {
    B64_URL.encode(Sha256::digest(verifier.as_bytes()))
}

fn effective_redirect_uri(oidc: &OidcConfig, st: &AppState, headers: &HeaderMap, uri: &Uri) -> Result<String, &'static str> {
    if !oidc.redirect_uri.is_empty() {
        return Ok(oidc.redirect_uri.clone());
    }
    if let Ok(base) = st.public_base(headers, uri) {
        if !base.is_empty() {
            return Ok(format!("{base}/api/auth/oidc/callback"));
        }
    }
    Err("oidc_unavailable")
}

async fn http_get_json(transport: SharedTransport, url: String) -> Result<Vec<u8>, &'static str> {
    tokio::task::spawn_blocking(move || {
        transport.execute(TransportRequest {
            method: "GET".to_string(),
            url,
            headers: vec![("accept".to_string(), "application/json".to_string())],
            body: None,
            timeout_ms: 10_000,
        })
    })
    .await
    .map_err(|_| "oidc_unavailable")?
    .map_err(|_| "oidc_unavailable")
    .and_then(|r| {
        if r.status == 200 {
            Ok(r.body)
        } else {
            Err("oidc_unavailable")
        }
    })
}

async fn http_post_form(
    transport: SharedTransport,
    url: String,
    form: String,
) -> Result<Vec<u8>, &'static str> {
    tokio::task::spawn_blocking(move || {
        transport.execute(TransportRequest {
            method: "POST".to_string(),
            url,
            headers: vec![
                (
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ),
                ("accept".to_string(), "application/json".to_string()),
            ],
            body: Some(form.into_bytes()),
            timeout_ms: 10_000,
        })
    })
    .await
    .map_err(|_| "oidc_exchange_failed")?
    .map_err(|_| "oidc_exchange_failed")
    .and_then(|r| {
        if r.status == 200 {
            Ok(r.body)
        } else {
            Err("oidc_exchange_failed")
        }
    })
}

async fn load_discovery(st: &AppState, oidc: &OidcConfig) -> Result<DiscoveryDoc, &'static str> {
    let now = now_unix();
    if let Some((at, doc)) = st.oidc_cache.lock().expect("oidc cache poisoned").discovery.clone() {
        if now - at < DISCOVERY_TTL_SECS {
            return Ok(doc);
        }
    }
    let url = format!(
        "{}/.well-known/openid-configuration",
        oidc.issuer_url.trim_end_matches('/')
    );
    let body = http_get_json(st.transport.clone(), url).await?;
    let doc: DiscoveryDoc = serde_json::from_slice(&body).map_err(|_| "oidc_unavailable")?;
    st.oidc_cache.lock().expect("oidc cache poisoned").discovery = Some((now, doc.clone()));
    Ok(doc)
}

async fn load_jwks(st: &AppState, jwks_uri: &str, force: bool) -> Result<JwkSet, &'static str> {
    let now = now_unix();
    if !force {
        if let Some((at, set)) = st.oidc_cache.lock().expect("oidc cache poisoned").jwks.clone() {
            if now - at < DISCOVERY_TTL_SECS {
                return Ok(set);
            }
        }
    }
    let body = http_get_json(st.transport.clone(), jwks_uri.to_string()).await?;
    let set: JwkSet = serde_json::from_slice(&body).map_err(|_| "oidc_unavailable")?;
    st.oidc_cache.lock().expect("oidc cache poisoned").jwks = Some((now, set.clone()));
    Ok(set)
}

pub fn verify_id_token_claims(
    id_token: &str,
    jwks: &JwkSet,
    issuers: &[&str],
    client_id: &str,
    expected_nonce: &str,
) -> Result<IdClaims, &'static str> {
    let header = decode_header(id_token).map_err(|_| "oidc_exchange_failed")?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    ) {
        return Err("oidc_exchange_failed");
    }
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid).ok_or("oidc_unknown_kid")?,
        None if jwks.keys.len() == 1 => &jwks.keys[0],
        None => return Err("oidc_exchange_failed"),
    };
    let key = DecodingKey::from_jwk(jwk).map_err(|_| "oidc_exchange_failed")?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(issuers);
    validation.set_audience(&[client_id]);
    validation.validate_exp = true;
    validation.leeway = 60;
    let claims = decode::<IdClaims>(id_token, &key, &validation)
        .map_err(|_| "oidc_exchange_failed")?
        .claims;
    let nonce = claims.nonce.as_deref().unwrap_or("");
    if nonce.is_empty() || !auth_core::ct_eq(nonce, expected_nonce) {
        return Err("oidc_state");
    }
    Ok(claims)
}

fn redirect_login_error(st: &AppState, headers: &HeaderMap, uri: &Uri, code: &str) -> Response {
    let secure = st.cookie_secure(headers, uri);
    let mut resp = Redirect::to(&format!("/login.html?error={code}")).into_response();
    if let Ok(hv) = HeaderValue::from_str(&auth_core::clear_cookie_header(
        OIDC_TX_COOKIE,
        "/api/auth/oidc",
        secure,
    )) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn oidc_login(
    State(st): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let oidc = st.current_oidc();
    if !oidc.is_active() {
        return redirect_login_error(&st, &headers, &uri, "oidc_unavailable");
    }
    let ip = st.client_ip(peer.as_ref().map(|p| p.0 .0.ip()), &headers);
    if st.check_rate(&format!("oidc:{ip}"), 20, 60).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "oidc_rate_limited").into_response();
    }
    let doc = match load_discovery(&st, &oidc).await {
        Ok(d) => d,
        Err(code) => return redirect_login_error(&st, &headers, &uri, code),
    };
    let redirect_uri = match effective_redirect_uri(&oidc, &st, &headers, &uri) {
        Ok(u) => u,
        Err(code) => return redirect_login_error(&st, &headers, &uri, code),
    };
    let state_val = auth_core::random_urlsafe(24);
    let nonce_val = auth_core::random_urlsafe(24);
    let code_verifier = auth_core::random_urlsafe(48);
    let challenge = pkce_challenge_s256(&code_verifier);
    let tx = OidcTx {
        state: state_val.clone(),
        nonce: nonce_val.clone(),
        code_verifier,
        redirect_uri: redirect_uri.clone(),
        created_at: now_unix(),
    };
    let tx_json = serde_json::to_vec(&tx).unwrap_or_default();
    let tx_key = st.vault.derive_key("oidc-tx");
    let Ok(sealed) = auth_core::seal_blob(&tx_key, TX_AAD, &tx_json) else {
        return redirect_login_error(&st, &headers, &uri, "generic");
    };
    let Ok(mut auth_url) = Url::parse(&doc.authorization_endpoint) else {
        return redirect_login_error(&st, &headers, &uri, "oidc_unavailable");
    };
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &oidc.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &oidc.scopes)
        .append_pair("state", &state_val)
        .append_pair("nonce", &nonce_val)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let secure = st.cookie_secure(&headers, &uri);
    let mut resp = Redirect::to(auth_url.as_str()).into_response();
    if let Ok(hv) = HeaderValue::from_str(&auth_core::cookie_header(
        OIDC_TX_COOKIE,
        &sealed,
        "/api/auth/oidc",
        OIDC_TX_TTL_SECS,
        secure,
    )) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn oidc_callback(
    State(st): State<Arc<AppState>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let oidc = st.current_oidc();
    if !oidc.is_active() {
        return redirect_login_error(&st, &headers, &uri, "oidc_unavailable");
    }
    let ip = st.client_ip(peer.as_ref().map(|p| p.0 .0.ip()), &headers);
    if st.check_rate(&format!("oidc:{ip}"), 20, 60).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "oidc_rate_limited").into_response();
    }
    if query.error.is_some() {
        return redirect_login_error(&st, &headers, &uri, "oidc_denied");
    }
    let (Some(code), Some(incoming_state), Some(tx_cookie)) = (
        query.code.as_deref().filter(|s| !s.is_empty()),
        query.state.as_deref().filter(|s| !s.is_empty()),
        auth_core::cookie_value(&headers, OIDC_TX_COOKIE),
    ) else {
        return redirect_login_error(&st, &headers, &uri, "oidc_state");
    };
    let tx_key = st.vault.derive_key("oidc-tx");
    let Ok(tx_bytes) = auth_core::open_blob(&tx_key, TX_AAD, &tx_cookie) else {
        return redirect_login_error(&st, &headers, &uri, "oidc_state");
    };
    let Ok(tx) = serde_json::from_slice::<OidcTx>(&tx_bytes) else {
        return redirect_login_error(&st, &headers, &uri, "oidc_state");
    };
    if now_unix() - tx.created_at > OIDC_TX_TTL_SECS || !auth_core::ct_eq(&tx.state, incoming_state) {
        return redirect_login_error(&st, &headers, &uri, "oidc_state");
    }
    let doc = match load_discovery(&st, &oidc).await {
        Ok(d) => d,
        Err(code) => return redirect_login_error(&st, &headers, &uri, code),
    };
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &tx.redirect_uri)
        .append_pair("client_id", &oidc.client_id)
        .append_pair("client_secret", &oidc.client_secret)
        .append_pair("code_verifier", &tx.code_verifier)
        .finish();
    let body = match http_post_form(st.transport.clone(), doc.token_endpoint.clone(), form).await {
        Ok(b) => b,
        Err(code) => return redirect_login_error(&st, &headers, &uri, code),
    };
    let Ok(tok) = serde_json::from_slice::<TokenResponse>(&body) else {
        return redirect_login_error(&st, &headers, &uri, "oidc_exchange_failed");
    };
    let Some(id_token) = tok.id_token.as_deref().filter(|s| !s.is_empty()) else {
        return redirect_login_error(&st, &headers, &uri, "oidc_exchange_failed");
    };
    let configured_iss = oidc.issuer_url.trim_end_matches('/').to_string();
    let doc_iss = doc.issuer.trim_end_matches('/').to_string();
    let issuers = [configured_iss.as_str(), doc_iss.as_str()];
    let jwks = match load_jwks(&st, &doc.jwks_uri, false).await {
        Ok(j) => j,
        Err(code) => return redirect_login_error(&st, &headers, &uri, code),
    };
    let claims = match verify_id_token_claims(id_token, &jwks, &issuers, &oidc.client_id, &tx.nonce) {
        Ok(c) => c,
        Err("oidc_unknown_kid") => {
            let fresh = match load_jwks(&st, &doc.jwks_uri, true).await {
                Ok(j) => j,
                Err(code) => return redirect_login_error(&st, &headers, &uri, code),
            };
            match verify_id_token_claims(id_token, &fresh, &issuers, &oidc.client_id, &tx.nonce) {
                Ok(c) => c,
                Err(code) => return redirect_login_error(&st, &headers, &uri, code),
            }
        }
        Err(code) => return redirect_login_error(&st, &headers, &uri, code),
    };
    let allowed = oidc.user_allowed(&[
        claims.preferred_username.as_deref(),
        claims.email.as_deref(),
        claims.sub.as_deref(),
    ]);
    let Some(username) = allowed else {
        let actor = claims
            .preferred_username
            .clone()
            .or(claims.email.clone())
            .or(claims.sub.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let _ = store::with_write_tx(&st.path, |db| {
            audit::append(
                db,
                &st.org,
                &actor,
                "auth.oidc_denied",
                "oidc",
                &json!({ "reason": "user_not_allowed" }),
            )
        });
        return redirect_login_error(&st, &headers, &uri, "oidc_user_not_allowed");
    };
    let cookie = match st.start_session(&headers, &uri, "oidc", &username) {
        Ok((c, _csrf)) => c,
        Err(_) => return redirect_login_error(&st, &headers, &uri, "generic"),
    };
    let _ = store::with_write_tx(&st.path, |db| {
        audit::append(
            db,
            &st.org,
            &username,
            "auth.login",
            "admin_session",
            &json!({ "method": "oidc", "ip": ip }),
        )
    });
    let secure = st.cookie_secure(&headers, &uri);
    let mut resp = Redirect::to("/admin/").into_response();
    if let Ok(hv) = HeaderValue::from_str(&auth_core::clear_cookie_header(
        OIDC_TX_COOKIE,
        "/api/auth/oidc",
        secure,
    )) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
}
