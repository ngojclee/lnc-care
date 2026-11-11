//! Axum HTTP router for LNC Care (`/admin`, `/api/*`, `/webhooks/meta`, `/mcp`).

use std::collections::{HashMap, HashSet};
use std::path::{Path as StdPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, patch, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::agent_hub::{self, AgentHubClient, AgentHubConfig, AgentHubError};
use crate::connections::{self as conn_mod, Connections};
use crate::internal_bridge::{self, AdsBridgeClient, BridgeClientError, BridgeConfig};
use crate::mcp_gateway::{self, McpGatewayClient, McpGatewayConfig, McpGatewayError};
use crate::mcp_server::{self, McpServerConfig, AUDIENCE, SCOPES};
use crate::providers::ProviderError;
use crate::store::{self, query_maps, query_one_map};
use crate::transport::{build_url_with_params, SharedTransport};
use crate::vault::{Vault, VaultError};
use crate::{audit, evaluator, evidence, fleet, settings, worker};

type HmacSha256 = Hmac<Sha256>;

#[derive(Default, Clone)]
pub struct AppConfig {
    pub db_path: Option<PathBuf>,
    pub public_dir: Option<PathBuf>,
    pub master_key: Option<String>,
    pub previous_master_key: Option<String>,
    pub management_key: Option<String>,
    pub mcp_bearer_token: Option<String>,
    pub delegation_secret: Option<String>,
    pub transport: Option<SharedTransport>,
    pub bridge_config: Option<BridgeConfig>,
    pub hub_config: Option<AgentHubConfig>,
    pub mcp_gateway_config: Option<McpGatewayConfig>,
    pub agent_hub_transport: Option<SharedTransport>,
    pub ads_bridge_transport: Option<SharedTransport>,
    pub mcp_gateway_transport: Option<SharedTransport>,
    pub env_overrides: Option<HashMap<String, String>>,
}

#[derive(Clone)]
pub struct AppState {
    pub path: PathBuf,
    pub public_dir: PathBuf,
    pub org: String,
    pub org_name: String,
    pub env_mgmt_key: String,
    pub bootstrap_mgmt_key: String,
    pub env_api_keys: Vec<String>,
    pub boot_ts: i64,
    pub bearer: String,
    pub del_secret: String,
    pub audience: String,
    pub require_delegation: bool,
    pub writes_enabled: bool,
    pub vault: Vault,
    pub bridge: Option<BridgeConfig>,
    pub hub_client: Option<AgentHubClient>,
    pub gw_client: Option<McpGatewayClient>,
    pub conns: Connections,
    pub mcp_cfg: McpServerConfig,
    pub env_map: HashMap<String, String>,
    pub local_hosts: HashSet<String>,
    pub attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub detail: String,
}

impl AppError {
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }
    pub fn u16(code: u16, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            detail: detail.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "detail": self.detail }))).into_response()
    }
}

impl From<ProviderError> for AppError {
    fn from(e: ProviderError) -> Self {
        Self::u16(e.status, e.code)
    }
}

impl From<VaultError> for AppError {
    fn from(e: VaultError) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, e.0)
    }
}

impl From<AgentHubError> for AppError {
    fn from(e: AgentHubError) -> Self {
        Self::u16(e.status, e.code)
    }
}

impl From<McpGatewayError> for AppError {
    fn from(e: McpGatewayError) -> Self {
        Self::u16(e.status, e.code)
    }
}

impl From<BridgeClientError> for AppError {
    fn from(e: BridgeClientError) -> Self {
        Self::u16(e.status, e.code)
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_hex(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn random_urlsafe(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    rand::thread_rng().fill_bytes(&mut buf);
    B64_URL.encode(&buf)
}

fn pbkdf2_hex(secret: &str, salt: &str) -> String {
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(secret.as_bytes(), salt.as_bytes(), 200_000, &mut out);
    hex::encode(out)
}

fn hmac_hex(key: &str, msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC key");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

fn session_cookie_value(key: &str, sid: &str, exp: i64) -> String {
    let msg = format!("{sid}.{exp}");
    let sig = hmac_hex(key, msg.as_bytes());
    format!("{sid}.{exp}.{sig}")
}

fn verify_session_cookie(key: &str, cookie: Option<&str>) -> Option<String> {
    let raw = cookie.filter(|s| !s.is_empty() && !key.is_empty())?;
    let mut parts = raw.splitn(3, '.');
    let sid = parts.next()?;
    let exp_s = parts.next()?;
    let sig = parts.next()?;
    let exp: i64 = exp_s.parse().ok()?;
    if exp <= now_unix() {
        return None;
    }
    let expected = hmac_hex(key, format!("{sid}.{exp}").as_bytes());
    if !ct_eq_str(sig, &expected) {
        return None;
    }
    Some(hex::encode(Sha256::digest(raw.as_bytes())))
}

fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for val in headers.get_all(header::COOKIE).iter() {
        if let Ok(s) = val.to_str() {
            for part in s.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    out.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
    }
    out
}

fn query_map(uri: &Uri) -> HashMap<String, String> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .into_owned()
        .collect()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

fn is_https(headers: &HeaderMap, uri: &Uri) -> bool {
    uri.scheme_str() == Some("https")
        || header_str(headers, "x-forwarded-proto")
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("https")
}

fn append_admin_cookies(resp_headers: &mut HeaderMap, sig_key: &str, secure: bool) -> String {
    let sid = random_urlsafe(24);
    let csrf = random_urlsafe(24);
    let sess_val = session_cookie_value(sig_key, &sid, now_unix() + 43200);
    let sec_flag = if secure { "; Secure" } else { "" };
    let c1 = format!("lnc_care_session={sess_val}; HttpOnly; SameSite=Lax; Path=/{sec_flag}");
    let c2 = format!("lnc_care_csrf={csrf}; SameSite=Lax; Path=/{sec_flag}");
    if let Ok(hv) = HeaderValue::from_str(&c1) {
        resp_headers.append(header::SET_COOKIE, hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&c2) {
        resp_headers.append(header::SET_COOKIE, hv);
    }
    csrf
}

fn append_delete_cookies(resp_headers: &mut HeaderMap) {
    if let Ok(hv) = HeaderValue::from_str("lnc_care_session=; Path=/; Max-Age=0") {
        resp_headers.append(header::SET_COOKIE, hv);
    }
    if let Ok(hv) = HeaderValue::from_str("lnc_care_csrf=; Path=/; Max-Age=0") {
        resp_headers.append(header::SET_COOKIE, hv);
    }
}

fn redirect_303(location: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    if let Ok(hv) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, hv);
    }
    resp
}

fn env_first(env: &HashMap<String, String>, keys: &[&str]) -> String {
    for k in keys {
        if let Some(v) = env.get(*k) {
            let t = v.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

fn parse_json_body(bytes: &[u8]) -> Result<Value, AppError> {
    if bytes.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::new(StatusCode::UNPROCESSABLE_ENTITY, "Invalid JSON body"))
}

impl AppState {
    fn load_runtime_mgmt(&self) -> Result<Option<Value>, AppError> {
        let db = store::connect_readonly(&self.path)?;
        let row: Option<String> = db
            .query_row(
                "SELECT value FROM runtime_settings WHERE organization_id=?1 AND key='__mgmt_state'",
                params![self.org],
                |r| r.get(0),
            )
            .ok();
        let Some(raw) = row else {
            return Ok(None);
        };
        let parsed: Value = serde_json::from_str(&raw)
            .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "management_state_corrupt"))?;
        let valid = parsed.get("salt").and_then(|v| v.as_str()).is_some()
            && parsed.get("hash").and_then(|v| v.as_str()).is_some()
            && parsed
                .get("session_secret")
                .and_then(|v| v.as_str())
                .is_some();
        if !valid {
            return Err(AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "management_state_corrupt",
            ));
        }
        Ok(Some(parsed))
    }

    fn session_signing_key(&self) -> Result<String, AppError> {
        if !self.env_mgmt_key.is_empty() {
            return Ok(self.env_mgmt_key.clone());
        }
        Ok(self
            .load_runtime_mgmt()?
            .and_then(|rt| rt.get("session_secret").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_default())
    }

    fn verify_mgmt_secret(&self, candidate: &str) -> Result<bool, AppError> {
        if candidate.is_empty() {
            return Ok(false);
        }
        if !self.env_mgmt_key.is_empty() {
            return Ok(ct_eq_str(candidate, &self.env_mgmt_key));
        }
        let Some(rt) = self.load_runtime_mgmt()? else {
            return Ok(false);
        };
        let salt = rt.get("salt").and_then(|v| v.as_str()).unwrap_or("");
        let hash = rt.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let digest = pbkdf2_hex(candidate, salt);
        Ok(ct_eq_str(&digest, hash))
    }

    fn mgmt_inventory(&self) -> Result<Value, AppError> {
        if !self.env_mgmt_key.is_empty() {
            let pfx = if self.env_mgmt_key.len() > 8 {
                format!("{}…", &self.env_mgmt_key[..8])
            } else {
                "env_****".to_string()
            };
            return Ok(json!({
                "configured": true,
                "prefix": pfx,
                "source": "environment",
                "rotatable": false,
                "bootstrap_ignored": false,
            }));
        }
        if let Some(rt) = self.load_runtime_mgmt()? {
            let p_raw = rt.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
            let pfx = if !p_raw.is_empty() {
                let slice: String = p_raw.chars().take(10).collect();
                format!("{slice}…")
            } else {
                "care_mgmt…".to_string()
            };
            return Ok(json!({
                "configured": true,
                "prefix": pfx,
                "created_at": rt.get("created_at").cloned().unwrap_or(Value::Null),
                "source": "runtime",
                "rotatable": true,
                "bootstrap_ignored": !self.bootstrap_mgmt_key.is_empty(),
            }));
        }
        Ok(json!({
            "configured": false,
            "prefix": "",
            "source": "none",
            "rotatable": true,
            "bootstrap_ignored": false,
        }))
    }

    fn current_settings(&self) -> Result<settings::LoadedSettings, AppError> {
        let db = store::connect_readonly(&self.path)?;
        Ok(settings::load(&db, &self.org, &self.env_map))
    }

    fn public_base(&self, headers: &HeaderMap, uri: &Uri) -> Result<String, AppError> {
        let cfg = self.current_settings()?;
        if !cfg.public_base_url.is_empty() {
            return Ok(cfg.public_base_url.trim_end_matches('/').to_string());
        }
        let proto = header_str(headers, "x-forwarded-proto")
            .split(',')
            .next()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| uri.scheme_str())
            .unwrap_or("http")
            .trim();
        let host = header_str(headers, "x-forwarded-host")
            .split(',')
            .next()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                let h = header_str(headers, "host");
                if h.is_empty() { None } else { Some(h) }
            })
            .or_else(|| uri.authority().map(|a| a.as_str()))
            .unwrap_or("localhost")
            .trim();
        Ok(format!("{proto}://{host}").trim_end_matches('/').to_string())
    }

    fn check_rate(&self, bucket: &str, limit: usize, window_secs: u64) -> Result<(), AppError> {
        let now = Instant::now();
        let mut map = self.attempts.lock().unwrap();
        let items = map.entry(bucket.to_string()).or_default();
        items.retain(|t| now.duration_since(*t).as_secs() < window_secs);
        if items.len() >= limit {
            return Err(AppError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded",
            ));
        }
        items.push(now);
        Ok(())
    }

    fn verify_api_key(&self, token: &str) -> Result<Option<String>, AppError> {
        let tok = token.trim();
        if tok.is_empty() {
            return Ok(None);
        }
        if self.verify_mgmt_secret(tok)? {
            return Ok(Some("mgmt".to_string()));
        }
        for (idx, ek) in self.env_api_keys.iter().enumerate() {
            if ct_eq_str(tok, ek) {
                return Ok(Some(format!("env:{idx}")));
            }
        }
        let key_hash = hex::encode(Sha256::digest(tok.as_bytes()));
        let db = store::connect_readonly(&self.path)?;
        let row: Option<(i64, String)> = db
            .query_row(
                "SELECT id, status FROM api_keys WHERE organization_id=?1 AND key_hash=?2",
                params![self.org, key_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        if let Some((id, status)) = row {
            if status == "enabled" {
                return Ok(Some(format!("key:{id}")));
            }
        }
        Ok(None)
    }

    fn require_admin(&self, method: &Method, headers: &HeaderMap) -> Result<String, AppError> {
        let sig_key = self.session_signing_key()?;
        let cookies = parse_cookies(headers);
        let session_hash = verify_session_cookie(&sig_key, cookies.get("lnc_care_session").map(|s| s.as_str()))
            .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "Authentication required"))?;
        if matches!(
            *method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            let csrf_cookie = cookies.get("lnc_care_csrf").map(|s| s.as_str()).unwrap_or("");
            let csrf_header = header_str(headers, "x-csrf-token");
            if csrf_cookie.is_empty() || !ct_eq_str(csrf_cookie, csrf_header) {
                return Err(AppError::new(StatusCode::FORBIDDEN, "CSRF token required"));
            }
        }
        Ok(session_hash)
    }

    fn require_api_or_admin(&self, headers: &HeaderMap, uri: &Uri) -> Result<String, AppError> {
        let auth = header_str(headers, "authorization");
        let q = query_map(uri);
        let raw_tok = if auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
            auth[7..].trim().to_string()
        } else if !header_str(headers, "x-api-key").trim().is_empty() {
            header_str(headers, "x-api-key").trim().to_string()
        } else if !header_str(headers, "x-token").trim().is_empty() {
            header_str(headers, "x-token").trim().to_string()
        } else if let Some(t) = q.get("token").filter(|s| !s.trim().is_empty()) {
            t.trim().to_string()
        } else {
            String::new()
        };

        if !raw_tok.is_empty() {
            if let Some(principal) = self.verify_api_key(&raw_tok)? {
                return Ok(principal);
            }
            return Err(AppError::new(
                StatusCode::UNAUTHORIZED,
                "Invalid or revoked API key",
            ));
        }

        let sig_key = self.session_signing_key()?;
        let cookies = parse_cookies(headers);
        verify_session_cookie(&sig_key, cookies.get("lnc_care_session").map(|s| s.as_str()))
            .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "Authentication required"))
    }

    fn bridge_summary(&self) -> Value {
        match &self.bridge {
            None => json!({
                "enabled": false,
                "self_id": "lnc-care",
                "peers": {},
                "ads_internal_url": Value::Null,
            }),
            Some(b) => json!({
                "enabled": true,
                "self_id": b.self_id,
                "peers": b.peers,
                "ads_internal_url": b.ads_internal_url,
            }),
        }
    }

    fn hub_summary(&self, force: bool) -> Value {
        match &self.hub_client {
            None => json!({
                "configured": false,
                "has_api_key": false,
                "url": "",
                "public_url": "",
                "reachable": false,
                "platform_api_ready": false,
                "bridge_fallback_ready": false,
                "mode": "standalone_local_vault",
                "sso_path": Value::Null,
                "last_sync_at": Value::Null,
                "last_sync_source": Value::Null,
                "last_warning": Value::Null,
            }),
            Some(h) => h.status_summary(force),
        }
    }

    fn gateway_summary(&self) -> Value {
        match &self.gw_client {
            None => json!({
                "configured": false,
                "has_api_key": false,
                "gateway_url": "",
                "route": "lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)",
                "allowed_prefixes": mcp_gateway::ALLOWED_CROSS_APP_PREFIXES,
            }),
            Some(gw) => gw.status_summary(),
        }
    }

    fn pairing_secrets_summary(&self, db: &rusqlite::Connection) -> Value {
        let ui_pair = if self.vault.ready {
            self.vault
                .get(db, &self.org, "pairing", "connector")
                .ok()
                .flatten()
                .unwrap_or_else(|| json!({}))
        } else {
            json!({})
        };
        let has_ui_bearer = ui_pair
            .get("connector_bearer")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let has_ui_secret = ui_pair
            .get("delegation_secret")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        json!({
            "connector_bearer": {
                "configured": !self.bearer.is_empty() || has_ui_bearer,
                "source": if !self.bearer.is_empty() {
                    "environment"
                } else if has_ui_bearer {
                    "database"
                } else {
                    "unset"
                },
            },
            "delegation_secret": {
                "configured": !self.del_secret.is_empty() || has_ui_secret,
                "source": if !self.del_secret.is_empty() {
                    "environment"
                } else if has_ui_secret {
                    "database"
                } else {
                    "unset"
                },
            },
        })
    }

    fn keys_inventory_payload(&self, db: &rusqlite::Connection) -> Result<Value, AppError> {
        let rows = query_maps(
            db,
            "SELECT id, label, prefix, status, created_at FROM api_keys WHERE organization_id=? ORDER BY id DESC",
            &[self.org.clone().into()],
        );
        let mut items = Vec::new();
        for (idx, ek) in self.env_api_keys.iter().enumerate() {
            let pfx: String = ek.chars().take(12).collect();
            items.push(json!({
                "id": format!("env-{}", idx + 1),
                "label": format!("LNC_API_KEYS #{}", idx + 1),
                "prefix": pfx,
                "status": "enabled",
                "enabled": true,
                "created_at": self.boot_ts,
                "copy_available": false,
                "source": "environment",
            }));
        }
        for r in rows {
            let id_val = r.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
            let status_str = r.get("status").and_then(|v| v.as_str()).unwrap_or("");
            let has_copy = if status_str != "revoked" && self.vault.ready {
                self.vault
                    .get(db, &self.org, "api_key", &id_val.to_string())?
                    .and_then(|s| s.get("secret").and_then(|v| v.as_str()).map(|x| !x.is_empty()))
                    .unwrap_or(false)
            } else {
                false
            };
            items.push(json!({
                "id": id_val,
                "label": r.get("label").cloned().unwrap_or(Value::String(String::new())),
                "prefix": r.get("prefix").cloned().unwrap_or(Value::String(String::new())),
                "status": status_str,
                "enabled": status_str == "enabled",
                "created_at": r.get("created_at").cloned().unwrap_or(Value::Number(0.into())),
                "copy_available": has_copy,
                "source": "runtime",
            }));
        }
        let any_enabled = items
            .iter()
            .any(|k| k.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false));
        let mgmt = self.mgmt_inventory()?;
        Ok(json!({
            "keys": items,
            "mgmt": mgmt,
            "inference": {
                "configured": any_enabled,
                "keys": items,
            },
            "management": mgmt,
        }))
    }
}

async fn host_gate_mw(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let req_path = req.uri().path();
    if req_path != "/health" && req_path != "/webhooks/meta" {
        if let Ok(cfg) = state.current_settings() {
            let raw_host = header_str(req.headers(), "host");
            let host = if raw_host.starts_with('[') {
                raw_host
                    .split(']')
                    .next()
                    .unwrap_or("")
                    .trim_start_matches('[')
                    .to_ascii_lowercase()
            } else {
                raw_host
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            };
            let mut allowed: HashSet<String> = cfg
                .allowed_hosts
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect();
            allowed.extend(state.local_hosts.iter().cloned());
            if req_path.starts_with("/api/internal/bridge/") {
                if let Some(ref b) = state.bridge {
                    allowed.extend(b.internal_hosts.iter().cloned());
                } else {
                    allowed.extend(
                        internal_bridge::DEFAULT_INTERNAL_HOSTS
                            .iter()
                            .map(|s| (*s).to_string()),
                    );
                }
            }
            if !allowed.contains("*") && !host.is_empty() && !allowed.contains(&host) {
                return (
                    StatusCode::MISDIRECTED_REQUEST,
                    Json(json!({ "detail": "Disallowed host" })),
                )
                    .into_response();
            }
        }
    }
    next.run(req).await
}

fn serve_static_file(dir: &StdPath, filename: &str, content_type: &'static str) -> Response {
    let full = dir.join(filename);
    match std::fs::read(&full) {
        Ok(bytes) => {
            let mut resp = (StatusCode::OK, bytes).into_response();
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            resp
        }
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

pub fn build_router(cfg: AppConfig) -> Result<Router, String> {
    let env_map: HashMap<String, String> = match cfg.env_overrides {
        Some(ov) => ov,
        None => std::env::vars().collect(),
    };

    let default_db = if let Some(dd) = env_map.get("DATA_DIR").filter(|s| !s.trim().is_empty()) {
        PathBuf::from(dd.trim()).join("care.db")
    } else {
        PathBuf::from("data").join("lnc-care.db")
    };
    let path = cfg
        .db_path
        .or_else(|| {
            env_map
                .get("DATABASE_PATH")
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or(default_db);

    let public_dir = cfg
        .public_dir
        .or_else(|| {
            env_map
                .get("PUBLIC_DIR")
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            let cwd_pub = PathBuf::from("public");
            if cwd_pub.exists() {
                cwd_pub
            } else {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("public")
            }
        });

    let org = {
        let v = env_first(&env_map, &["ORGANIZATION_ID", "DEFAULT_ORG_SLUG"]);
        if v.is_empty() {
            "lnc-default".to_string()
        } else {
            v
        }
    };
    let org_name = {
        let v = env_first(&env_map, &["ORGANIZATION_NAME", "DEFAULT_ORG_NAME"]);
        if v.is_empty() {
            "Le Ngoc Care".to_string()
        } else {
            v
        }
    };

    let has_explicit_mgmt = cfg.management_key.is_some();
    let env_mgmt_key = match cfg.management_key {
        Some(mk) => mk.trim().to_string(),
        None => env_first(
            &env_map,
            &[
                "MANAGEMENT_KEY",
                "MANAGEMENT_TOKEN",
                "LNC_MANAGEMENT_KEY",
                "LNC_ADMIN_TOKEN",
                "EDGE_KEY",
            ],
        ),
    };
    let bootstrap_mgmt_key = if has_explicit_mgmt {
        String::new()
    } else {
        env_first(
            &env_map,
            &["CARE_ADMIN_BOOTSTRAP_KEY", "LNC_ADMIN_BOOTSTRAP_KEY"],
        )
    };
    let env_api_keys: Vec<String> = env_map
        .get("LNC_API_KEYS")
        .map(|s| {
            s.split(',')
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let bearer = match cfg.mcp_bearer_token {
        Some(b) => b,
        None => env_first(
            &env_map,
            &["CONNECTOR_BEARER", "LNC_CONNECTOR_TOKEN", "MCP_BEARER_TOKEN"],
        ),
    };
    let del_secret = match cfg.delegation_secret {
        Some(s) => s,
        None => env_first(
            &env_map,
            &[
                "DELEGATION_SECRET",
                "LNC_DELEGATION_SECRET",
                "MCP_DELEGATION_SECRET",
            ],
        ),
    };
    let audience = {
        let a = env_first(&env_map, &["CONNECTOR_AUDIENCE", "LNC_MCP_AUDIENCE"]);
        if a.is_empty() {
            AUDIENCE.to_string()
        } else {
            a
        }
    };
    let require_delegation = env_map
        .get("MCP_REQUIRE_DELEGATION")
        .map(|v| !v.trim().eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    let writes_enabled = env_map
        .get("PROVIDER_WRITES_ENABLED")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    store::initialize(&path, &org, &org_name).map_err(|e| e.to_string())?;
    let mk_ref = cfg
        .master_key
        .as_deref()
        .or_else(|| env_map.get("LNC_MASTER_KEY").map(|s| s.as_str()));
    let pk_ref = cfg
        .previous_master_key
        .as_deref()
        .or_else(|| env_map.get("LNC_PREVIOUS_MASTER_KEY").map(|s| s.as_str()));
    let vault = Vault::new(mk_ref, pk_ref).map_err(|e| e.0)?;

    {
        let db = store::connect(&path).map_err(|e| e.to_string())?;
        vault.verify_master(&db, &org).map_err(|e| e.0)?;
        if env_mgmt_key.is_empty() && !bootstrap_mgmt_key.is_empty() {
            let exists: Option<String> = db
                .query_row(
                    "SELECT value FROM runtime_settings WHERE organization_id=?1 AND key='__mgmt_state'",
                    params![org],
                    |r| r.get(0),
                )
                .ok();
            if exists.is_none() {
                let salt = random_hex(16);
                let digest = pbkdf2_hex(&bootstrap_mgmt_key, &salt);
                let pfx: String = bootstrap_mgmt_key.chars().take(12).collect();
                let state_obj = json!({
                    "salt": salt,
                    "hash": digest,
                    "prefix": pfx,
                    "session_secret": random_urlsafe(32),
                    "created_at": now_unix(),
                });
                db.execute(
                    "INSERT INTO runtime_settings(organization_id, key, value) VALUES (?1, '__mgmt_state', ?2)",
                    params![org, state_obj.to_string()],
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }

    let bridge = match cfg.bridge_config {
        Some(b) => Some(b),
        None => internal_bridge::bridge_config(&env_map)?,
    };
    let ads_bridge = bridge
        .as_ref()
        .map(|b| AdsBridgeClient::new(b.clone(), cfg.ads_bridge_transport.clone()));

    let mut eff_hub_cfg = match cfg.hub_config {
        Some(h) => Some(h),
        None => agent_hub::agent_hub_config(&env_map)?,
    };
    if eff_hub_cfg.is_none() && ads_bridge.is_some() {
        let self_id = bridge
            .as_ref()
            .map(|b| b.self_id.as_str())
            .unwrap_or("lnc-care");
        eff_hub_cfg = Some(AgentHubConfig::new("", "", "", self_id));
    }
    let hub_client = eff_hub_cfg.map(|hc| {
        AgentHubClient::new(hc, ads_bridge.clone(), cfg.agent_hub_transport.clone())
    });

    let eff_gw_cfg = match cfg.mcp_gateway_config {
        Some(g) => Some(g),
        None => mcp_gateway::mcp_gateway_config(&env_map)?,
    };
    let gw_client =
        eff_gw_cfg.map(|gc| McpGatewayClient::new(gc, cfg.mcp_gateway_transport.clone()));

    let conns = Connections::new(
        path.clone(),
        org.clone(),
        vault.clone(),
        cfg.transport.clone(),
        hub_client.clone(),
    );

    let mcp_cfg = McpServerConfig {
        path: path.clone(),
        org: org.clone(),
        bearer_token: bearer.clone(),
        delegation_secret: del_secret.clone(),
        require_delegation,
        writes_enabled,
        mcp_gateway: gw_client.clone(),
        audience: audience.clone(),
        vault: vault.clone(),
        env_map: env_map.clone(),
        transport: cfg.transport.clone(),
    };

    let mut local_hosts: HashSet<String> = ["localhost", "127.0.0.1", "::1", "testserver"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if let Some(hn) = env_map
        .get("HOSTNAME")
        .or_else(|| env_map.get("COMPUTERNAME"))
    {
        if !hn.trim().is_empty() {
            local_hosts.insert(hn.trim().to_ascii_lowercase());
        }
    }

    let state = Arc::new(AppState {
        path,
        public_dir,
        org,
        org_name,
        env_mgmt_key,
        bootstrap_mgmt_key,
        env_api_keys,
        boot_ts: now_unix(),
        bearer,
        del_secret,
        audience,
        require_delegation,
        writes_enabled,
        vault,
        bridge,
        hub_client,
        gw_client,
        conns,
        mcp_cfg,
        env_map,
        local_hosts,
        attempts: Arc::new(Mutex::new(HashMap::new())),
    });

    let router = Router::new()
        .route("/health", get(health_handler))
        .route(
            "/webhooks/meta",
            get(meta_webhook_verify_handler).post(meta_webhook_receive_handler),
        )
        .route("/api/app-info", get(app_info_handler))
        .route("/api/auth/status", get(auth_status_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/auth/logout", get(logout_handler).post(logout_handler))
        .route("/api/auth/sso/redirect", get(sso_redirect_handler))
        .route("/api/auth/sso/consume", get(sso_consume_handler))
        .route(
            "/api/internal/bridge/status",
            get(inbound_bridge_status_handler),
        )
        .route(
            "/api/internal/bridge/shops",
            get(inbound_bridge_shops_handler),
        )
        .route(
            "/api/internal/bridge/channels",
            get(inbound_bridge_channels_handler),
        )
        .route("/api/admin/hub/status", get(hub_status_handler))
        .route("/api/admin/hub/sync", post(hub_sync_handler))
        .route(
            "/api/admin/oauth/shared/start",
            post(shared_oauth_start_handler),
        )
        .route(
            "/api/admin/mcp-gateway/status",
            get(mcp_gateway_status_handler),
        )
        .route(
            "/api/admin/mcp-gateway/call",
            post(mcp_gateway_call_handler),
        )
        .route("/api/admin/overview", get(overview_handler))
        .route("/api/admin/seed-demo", post(seed_demo_handler))
        .route("/api/admin/purge-demo", post(purge_demo_handler))
        .route("/api/admin/shops", post(create_shop_handler))
        .route("/api/admin/integrations", get(get_integrations_handler))
        .route(
            "/api/admin/integrations/:provider",
            post(save_integration_handler),
        )
        .route("/api/admin/connections", post(create_connection_handler))
        .route(
            "/api/admin/connections/:connection_id/authorize",
            post(authorize_connection_handler),
        )
        .route(
            "/api/auth/providers/:provider/callback",
            get(oauth_callback_handler),
        )
        .route(
            "/api/admin/connections/:connection_id/disconnect",
            post(disconnect_connection_handler),
        )
        .route(
            "/api/admin/connections/:connection_id/discover",
            post(discover_channels_handler),
        )
        .route(
            "/api/admin/connections/:connection_id/channels",
            get(list_discovered_channels_handler),
        )
        .route(
            "/api/admin/connections/:connection_id/channels/approve",
            post(approve_channel_handler),
        )
        .route(
            "/api/admin/channels/:channel_id/sync",
            post(sync_channel_handler),
        )
        .route(
            "/api/admin/channels/:channel_id/subscribe",
            post(subscribe_channel_webhook_handler),
        )
        .route(
            "/api/admin/channels/:channel_id/browser-sync",
            post(browser_sync_channel_handler),
        )
        .route(
            "/api/admin/channels/:channel_id/policy",
            post(update_channel_policy_handler),
        )
        .route("/api/admin/conversations", get(list_conversations_handler))
        .route(
            "/api/admin/conversations/:conversation_id/messages",
            get(list_conversation_messages_handler).post(send_conversation_message_handler),
        )
        .route(
            "/api/admin/leads",
            get(list_leads_handler).post(create_lead_handler),
        )
        .route(
            "/api/admin/handoffs",
            get(list_handoffs_handler).post(create_handoff_handler),
        )
        .route("/api/admin/posts", get(list_posts_handler))
        .route("/api/admin/posts/:post_id", get(get_post_handler))
        .route(
            "/api/admin/posts/:post_id/archive",
            post(request_post_archive_handler),
        )
        .route("/api/admin/comments", get(list_comments_handler))
        .route("/api/admin/comments/:comment_id", get(get_comment_handler))
        .route(
            "/api/admin/comments/:comment_id/evaluate",
            post(evaluate_comment_handler),
        )
        .route(
            "/api/admin/comments/:comment_id/feedback",
            post(feedback_comment_handler),
        )
        .route(
            "/api/admin/comments/:comment_id/state",
            post(update_comment_state_handler),
        )
        .route(
            "/api/admin/comments/:comment_id/drafts",
            post(save_comment_draft_handler),
        )
        .route("/api/admin/evidence", get(list_evidence_cases_handler))
        .route(
            "/api/admin/evidence/capture",
            post(capture_evidence_handler),
        )
        .route(
            "/api/admin/evidence/:case_id/export",
            get(export_evidence_case_handler),
        )
        .route(
            "/api/admin/evidence/:case_id/verify",
            get(verify_evidence_case_handler),
        )
        .route(
            "/api/admin/evidence/:case_id/check",
            post(check_evidence_case_handler),
        )
        .route(
            "/api/admin/fleet",
            get(list_fleet_handler).post(save_fleet_runtime_handler),
        )
        .route(
            "/api/admin/fleet/:runtime_id/probe",
            post(probe_fleet_runtime_handler),
        )
        .route(
            "/api/admin/fleet/:runtime_id/resume",
            post(resume_fleet_runtime_handler),
        )
        .route(
            "/api/admin/playbooks",
            get(list_playbooks_handler).post(save_playbook_handler),
        )
        .route(
            "/api/admin/rules",
            get(list_rules_handler).post(save_rule_handler),
        )
        .route("/api/admin/jobs/run", post(trigger_worker_jobs_handler))
        .route("/api/status", get(api_status_handler))
        .route(
            "/api/keys",
            get(list_api_keys_handler).post(create_api_key_handler),
        )
        .route(
            "/api/admin/credentials/inventory",
            get(list_api_keys_handler),
        )
        .route(
            "/api/admin/credentials/inference",
            post(create_api_key_handler),
        )
        .route("/api/keys/:key_id/copy", post(copy_api_key_handler))
        .route(
            "/api/admin/credentials/inference/:key_id/copy",
            post(copy_api_key_handler),
        )
        .route(
            "/api/keys/:key_id",
            patch(rename_api_key_handler).delete(delete_api_key_handler),
        )
        .route(
            "/api/admin/credentials/inference/:key_id",
            patch(rename_api_key_handler).delete(delete_api_key_handler),
        )
        .route("/api/keys/:key_id/toggle", post(toggle_api_key_handler))
        .route(
            "/api/admin/credentials/inference/:key_id/enable",
            post(toggle_api_key_handler),
        )
        .route(
            "/api/admin/credentials/inference/:key_id/disable",
            post(toggle_api_key_handler),
        )
        .route("/api/keys/:key_id/revoke", post(revoke_api_key_handler))
        .route(
            "/api/admin/credentials/inference/:key_id/revoke",
            post(revoke_api_key_handler),
        )
        .route("/api/mgmt/rotate", post(rotate_mgmt_key_handler))
        .route(
            "/api/admin/credentials/management/rotate",
            post(rotate_mgmt_key_handler),
        )
        .route("/api/admin/connector", get(connector_info_handler))
        .route("/api/admin/audit", get(get_audit_handler))
        .route("/api/admin/audit/verify", get(verify_audit_handler))
        .route(
            "/api/settings",
            get(get_settings_handler).post(post_settings_handler),
        )
        .route("/", get(root_handler))
        .route("/login.html", get(login_page_handler))
        .route("/admin", get(admin_page_handler))
        .route("/admin/", get(admin_page_handler))
        .route("/icon.svg", get(icon_svg_handler))
        .route("/favicon.svg", get(icon_svg_handler))
        .route("/icon.png", get(icon_png_handler))
        .route("/favicon.png", get(icon_png_handler))
        .route("/favicon.ico", get(favicon_ico_handler))
        .route("/style.css", get(style_css_handler))
        .route("/admin/style.css", get(style_css_handler))
        .route("/app.js", get(app_js_handler))
        .route("/admin/app.js", get(app_js_handler))
        .route("/mcp", any(connector_mcp_handler))
        .route("/mcp/", any(connector_mcp_handler))
        .layer(middleware::from_fn_with_state(state.clone(), host_gate_mw))
        .with_state(state);

    Ok(router)
}

// --- Handlers ---

async fn health_handler(State(st): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": st.audience,
        "version": crate::VERSION,
        "writes_enabled": st.writes_enabled,
    }))
}

async fn meta_webhook_verify_handler(
    State(st): State<Arc<AppState>>,
    uri: Uri,
) -> Result<Response, AppError> {
    let q = query_map(&uri);
    let mode = q.get("hub.mode").map(|s| s.as_str()).unwrap_or("");
    let token = q.get("hub.verify_token").map(|s| s.as_str()).unwrap_or("");
    let challenge = q.get("hub.challenge").cloned().unwrap_or_default();

    let db = store::connect_readonly(&st.path)?;
    let db_tok: Option<String> = db
        .query_row(
            "SELECT webhook_verify_token FROM provider_apps WHERE organization_id=?1 AND provider='meta'",
            params![st.org],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .filter(|s| !s.is_empty());
    let expected = db_tok.unwrap_or_else(|| {
        st.env_map
            .get("META_WEBHOOK_VERIFY_TOKEN")
            .cloned()
            .unwrap_or_default()
    });

    if mode == "subscribe" && !expected.is_empty() && ct_eq_str(token, &expected) {
        let mut resp = (StatusCode::OK, challenge).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        return Ok(resp);
    }
    Err(AppError::new(
        StatusCode::FORBIDDEN,
        "webhook_verify_token_mismatch",
    ))
}

async fn meta_webhook_receive_handler(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    let sig_header = header_str(&headers, "x-hub-signature-256");
    if !sig_header.starts_with("sha256=") {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "webhook_signature_missing",
        ));
    }

    let env_secret = st
        .env_map
        .get("META_APP_SECRET")
        .map(|s| s.as_str())
        .unwrap_or("");
    let local_secret = {
        let db = store::connect_readonly(&st.path)?;
        st.vault
            .get(&db, &st.org, "app", "meta")?
            .and_then(|v| v.get("client_secret").and_then(|s| s.as_str()).map(String::from))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| env_secret.to_string())
    };

    if let Some(ref hub) = st.hub_client {
        let has_verifier =
            !local_secret.is_empty() || !hub.cfg.api_key.is_empty() || hub.ads_bridge.is_some();
        if !has_verifier {
            return Err(AppError::new(
                StatusCode::FORBIDDEN,
                "webhook_signature_missing",
            ));
        }
        if !hub.verify_meta_webhook(
            &st.path,
            &st.org,
            &st.vault,
            &raw_body,
            sig_header,
            env_secret,
        ) {
            return Err(AppError::new(
                StatusCode::FORBIDDEN,
                "webhook_signature_invalid",
            ));
        }
    } else {
        if local_secret.is_empty() {
            return Err(AppError::new(
                StatusCode::FORBIDDEN,
                "webhook_signature_missing",
            ));
        }
        let expected_sig = format!("sha256={}", hmac_hex(&local_secret, &raw_body));
        if !ct_eq_str(sig_header, &expected_sig) {
            return Err(AppError::new(
                StatusCode::FORBIDDEN,
                "webhook_signature_invalid",
            ));
        }
    }

    let body_str = String::from_utf8_lossy(&raw_body).into_owned();
    let payload: Value = serde_json::from_str(if body_str.is_empty() { "{}" } else { &body_str })
        .unwrap_or_else(|_| json!({}));
    let dedupe_key = hex::encode(Sha256::digest(&raw_body));
    let now = now_unix();

    let res = store::with_write_tx(&st.path, |db| -> Result<Value, rusqlite::Error> {
        let exists = db
            .query_row(
                "SELECT id FROM webhook_events WHERE organization_id=?1 AND dedupe_key=?2",
                params![st.org, dedupe_key],
                |r| r.get::<_, i64>(0),
            )
            .is_ok();
        if exists {
            return Ok(json!({ "ok": true, "deduplicated": true, "enqueued": 0 }));
        }
        db.execute(
            "INSERT INTO webhook_events
             (organization_id, provider, dedupe_key, payload_json, received_at, processed_at)
             VALUES (?1, 'meta', ?2, ?3, ?4, ?5)",
            params![st.org, dedupe_key, body_str, now, now],
        )?;
        let mut enqueued = 0i64;
        if let Some(entries) = payload.get("entry").and_then(|v| v.as_array()) {
            for entry in entries {
                if let Some(changes) = entry.get("changes").and_then(|v| v.as_array()) {
                    for change in changes {
                        let field = change.get("field").and_then(|v| v.as_str()).unwrap_or("");
                        if matches!(field, "feed" | "comments" | "mentions" | "messages") {
                            let val = change.get("value").cloned().unwrap_or_else(|| json!({}));
                            worker::enqueue_job(
                                db,
                                &st.org,
                                "fetch_comments",
                                &json!({
                                    "entry_id": entry.get("id").cloned().unwrap_or(Value::Null),
                                    "field": field,
                                    "value": val,
                                }),
                                0,
                            )?;
                            enqueued += 1;
                        }
                    }
                }
            }
        }
        Ok(json!({ "ok": true, "deduplicated": false, "enqueued": enqueued }))
    })?;
    Ok(Json(res))
}

async fn app_info_handler(State(st): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "service": st.audience,
        "name": "LNC Care",
        "version": crate::VERSION,
    }))
}

async fn auth_status_handler(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let sig_key = st.session_signing_key()?;
    let cookies = parse_cookies(&headers);
    let authenticated =
        verify_session_cookie(&sig_key, cookies.get("lnc_care_session").map(|s| s.as_str()))
            .is_some();
    let csrf_val = if authenticated {
        cookies.get("lnc_care_csrf").cloned().unwrap_or_default()
    } else {
        String::new()
    };
    Ok(Json(json!({
        "ok": authenticated,
        "authenticated": authenticated,
        "service": st.audience,
        "version": crate::VERSION,
        "csrf": csrf_val,
        "csrf_token": csrf_val,
    })))
}

async fn login_handler(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    raw_body: Bytes,
) -> Result<Response, AppError> {
    let client_ip = header_str(&headers, "x-forwarded-for")
        .split(',')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("local");
    st.check_rate(&format!("login:{client_ip}"), 8, 300)?;
    let body = parse_json_body(&raw_body)?;
    let key = body
        .get("key")
        .or_else(|| body.get("token"))
        .or_else(|| body.get("password"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !st.verify_mgmt_secret(key)? {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid management key",
        ));
    }
    let sig_key = st.session_signing_key()?;
    let mut resp_headers = HeaderMap::new();
    let csrf = append_admin_cookies(&mut resp_headers, &sig_key, is_https(&headers, &uri));
    store::with_write_tx(&st.path, |db| {
        audit::append(db, &st.org, "owner", "auth.login", "admin_session", &json!({}))
    })?;
    let mut resp = Json(json!({
        "ok": true,
        "authenticated": true,
        "csrf": csrf,
        "csrf_token": csrf,
    }))
    .into_response();
    for (k, v) in resp_headers.iter() {
        resp.headers_mut().append(k.clone(), v.clone());
    }
    Ok(resp)
}

async fn logout_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if method == Method::POST {
        st.require_admin(&method, &headers)?;
    }
    let mut resp = if method == Method::GET {
        redirect_303("/login.html")
    } else {
        Json(json!({ "ok": true })).into_response()
    };
    append_delete_cookies(resp.headers_mut());
    Ok(resp)
}

async fn sso_redirect_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("sso_mint:{session_hash}"), 20, 60)?;
    let q = query_map(&uri);
    let target_peer = q
        .get("peer")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::new(StatusCode::UNPROCESSABLE_ENTITY, "peer is required"))?;
    let next_raw = q.get("next").map(|s| s.as_str());

    if target_peer == "lnc-agent-hub" {
        let hub = st
            .hub_client
            .as_ref()
            .ok_or_else(|| AppError::new(StatusCode::SERVICE_UNAVAILABLE, "agent_hub_not_configured"))?;
        let safe_hub_next = internal_bridge::safe_relative_next(next_raw, "/");
        let target_url = hub.mint_sso_redirect_url("lnc-agent-hub", &safe_hub_next, "owner")?;
        store::with_write_tx(&st.path, |db| {
            audit::append(
                db,
                &st.org,
                "owner",
                "sso.ticket_minted",
                &target_peer,
                &json!({ "via": "lnc-agent-hub" }),
            )
        })?;
        return Ok(redirect_303(&target_url));
    }

    let safe_next = internal_bridge::safe_relative_next(next_raw, "/admin/#overview");
    if let Some(ref hub) = st.hub_client {
        if !hub.cfg.api_key.is_empty() {
            let st_sum = hub.status_summary(false);
            if st_sum
                .get("platform_api_ready")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                let target_url = hub.mint_sso_redirect_url(&target_peer, &safe_next, "owner")?;
                store::with_write_tx(&st.path, |db| {
                    audit::append(
                        db,
                        &st.org,
                        "owner",
                        "sso.ticket_minted",
                        &target_peer,
                        &json!({ "via": "lnc-agent-hub" }),
                    )
                })?;
                return Ok(redirect_303(&target_url));
            }
        }
    }

    let ticket = internal_bridge::mint_sso_ticket(
        st.bridge.as_ref(),
        &target_peer,
        "owner",
        internal_bridge::SSO_TTL_SECONDS,
    )?;
    let bridge = st.bridge.as_ref().unwrap();
    let peer_origin = &bridge.peers[&target_peer];
    let consume_url = build_url_with_params(
        &format!("{peer_origin}/api/auth/sso/consume"),
        &[("ticket", ticket), ("next", safe_next)],
    );
    store::with_write_tx(&st.path, |db| {
        audit::append(
            db,
            &st.org,
            "owner",
            "sso.ticket_minted",
            &target_peer,
            &json!({ "via": "internal_bridge" }),
        )
    })?;
    Ok(redirect_303(&consume_url))
}

async fn sso_consume_handler(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, AppError> {
    st.check_rate("sso_consume:local", 20, 60)?;
    let sig_key = st.session_signing_key()?;
    if sig_key.is_empty() {
        return Err(AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "management_key_not_configured",
        ));
    }
    let q = query_map(&uri);
    let clean_ticket = q
        .get("ticket")
        .map(|s| s.trim())
        .unwrap_or("");
    if clean_ticket.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ticket is required",
        ));
    }

    let (claims, via) = if clean_ticket.starts_with("lnc_sso_") {
        let hub = st
            .hub_client
            .as_ref()
            .ok_or_else(|| AppError::new(StatusCode::SERVICE_UNAVAILABLE, "agent_hub_not_configured"))?;
        (hub.redeem_sso_ticket(clean_ticket)?, "lnc-agent-hub")
    } else {
        (
            internal_bridge::consume_sso_ticket(
                st.bridge.as_ref(),
                clean_ticket,
                &st.path,
                &st.org,
            )?,
            "internal_bridge",
        )
    };

    let safe_dest =
        internal_bridge::safe_relative_next(q.get("next").map(|s| s.as_str()), "/admin/#inbox");
    let mut resp = redirect_303(&safe_dest);
    append_admin_cookies(resp.headers_mut(), &sig_key, is_https(&headers, &uri));
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("owner");
    let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or(via);
    store::with_write_tx(&st.path, |db| {
        audit::append(
            db,
            &st.org,
            sub,
            "sso.ticket_consumed",
            iss,
            &json!({ "via": via, "next": safe_dest }),
        )
    })?;
    Ok(resp)
}

fn headers_to_lower_map(headers: &HeaderMap) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            m.insert(k.as_str().to_ascii_lowercase(), s.to_string());
        }
    }
    m
}

fn uri_path_and_query(uri: &Uri) -> String {
    match uri.query() {
        Some(q) if !q.is_empty() => format!("{}?{q}", uri.path()),
        _ => uri.path().to_string(),
    }
}

async fn inbound_bridge_status_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    let peer = internal_bridge::authenticate_headers(
        st.bridge.as_ref(),
        method.as_str(),
        &uri_path_and_query(&uri),
        &headers_to_lower_map(&headers),
        &raw_body,
        &st.path,
        &st.org,
    )?;
    let bridge = st.bridge.as_ref().unwrap();
    Ok(Json(json!({
        "ok": true,
        "service": "LNC Care",
        "self_id": bridge.self_id,
        "caller_peer": peer,
        "organization": st.org,
        "version": crate::VERSION,
        "vault_ready": true,
    })))
}

async fn inbound_bridge_shops_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    internal_bridge::authenticate_headers(
        st.bridge.as_ref(),
        method.as_str(),
        &uri_path_and_query(&uri),
        &headers_to_lower_map(&headers),
        &raw_body,
        &st.path,
        &st.org,
    )?;
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(json!({ "shops": store::shops(&db, &st.org) })))
}

async fn inbound_bridge_channels_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    internal_bridge::authenticate_headers(
        st.bridge.as_ref(),
        method.as_str(),
        &uri_path_and_query(&uri),
        &headers_to_lower_map(&headers),
        &raw_body,
        &st.path,
        &st.org,
    )?;
    let q = query_map(&uri);
    let shop = q.get("shop").filter(|s| !s.trim().is_empty()).cloned();
    let db = store::connect_readonly(&st.path)?;
    let mut shop_id: Option<i64> = None;
    if let Some(ref sname) = shop {
        let found: Option<i64> = db
            .query_row(
                "SELECT id FROM shops WHERE organization_id=?1 AND LOWER(name)=LOWER(?2)",
                params![st.org, sname.trim()],
                |r| r.get(0),
            )
            .ok();
        match found {
            Some(id) => shop_id = Some(id),
            None => {
                return Ok(Json(json!({
                    "shop": shop,
                    "channels": [],
                })));
            }
        }
    }
    Ok(Json(json!({
        "shop": shop,
        "shop_id": shop_id,
        "channels": store::channels(&db, &st.org, shop_id, true),
    })))
}

async fn hub_status_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let refresh = q
        .get("refresh")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false);
    Ok(Json(json!({
        "agent_hub": st.hub_summary(refresh),
        "bridge": st.bridge_summary(),
        "mcp_gateway": st.gateway_summary(),
    })))
}

async fn hub_sync_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("hub_sync:{session_hash}"), 12, 60)?;
    let hub = st.hub_client.as_ref().ok_or_else(|| {
        AppError::new(StatusCode::CONFLICT, "agent_hub_or_bridge_not_configured")
    })?;
    Ok(Json(hub.sync(&st.path, &st.org, &st.vault)?))
}

async fn shared_oauth_start_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("shared_oauth:{session_hash}"), 10, 60)?;
    let hub = st.hub_client.as_ref().ok_or_else(|| {
        AppError::new(StatusCode::CONFLICT, "agent_hub_or_bridge_not_configured")
    })?;
    let body = parse_json_body(&raw_body)?;
    let provider = body
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("meta")
        .trim();
    let shop = body
        .get("shop")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let extra_scopes = body
        .get("extra_scopes")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !store::PROVIDERS.contains(&provider) || shop.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Valid provider and shop name are required",
        ));
    }
    let base = st.public_base(&headers, &uri)?;
    let default_ret = format!("{base}/admin/#channels");
    let return_to = body
        .get("return_to")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_ret);

    let started = hub
        .start_shared_oauth(provider, shop, label, return_to, extra_scopes)
        .ok_or_else(|| {
            AppError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "shared_oauth_broker_unavailable",
            )
        })?;
    store::with_write_tx(&st.path, |db| {
        audit::append(
            db,
            &st.org,
            "owner",
            "oauth.shared_started",
            provider,
            &json!({ "shop": shop, "via": started.get("via") }),
        )
    })?;
    Ok(Json(started))
}

async fn mcp_gateway_status_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    Ok(Json(st.gateway_summary()))
}

async fn mcp_gateway_call_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("mcp_gw:{session_hash}"), 20, 60)?;
    let gw = st
        .gw_client
        .as_ref()
        .ok_or_else(|| AppError::new(StatusCode::CONFLICT, "mcp_gateway_not_configured"))?;
    let body = parse_json_body(&raw_body)?;
    let tool_name = body
        .get("tool")
        .or_else(|| body.get("name"))
        .or_else(|| body.get("tool_name"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if tool_name.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "tool name is required",
        ));
    }
    let arguments = body.get("arguments");
    Ok(Json(gw.call_tool(tool_name, arguments)?))
}

async fn overview_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let shop_id = q.get("shop_id").and_then(|s| s.trim().parse::<i64>().ok());
    let db = store::connect_readonly(&st.path)?;
    let ev_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM evidence_cases WHERE organization_id=?1",
        params![st.org],
        |r| r.get(0),
    )?;
    let fleet_rows: Vec<Value> = query_maps(
        &db,
        "SELECT * FROM account_runtimes WHERE organization_id=? ORDER BY id",
        &[st.org.clone().into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();
    let healthy = fleet_rows
        .iter()
        .filter(|r| r.get("health_status").and_then(|v| v.as_str()) == Some("healthy"))
        .count();
    let rubric_labels: Vec<Value> = evaluator::RUBRIC_LABELS
        .iter()
        .map(|(k, vi, en, pol)| json!({ "key": k, "label_vi": vi, "label_en": en, "polarity": pol }))
        .collect();
    Ok(Json(json!({
        "organization": { "id": st.org, "name": st.org_name },
        "version": crate::VERSION,
        "writes_enabled": st.writes_enabled,
        "shops": store::shops(&db, &st.org),
        "integrations": st.conns.inventory(&db),
        "channels": store::channels(&db, &st.org, shop_id, false),
        "inbox_summary": store::inbox_summary(&db, &st.org, shop_id),
        "evidence_cases_count": ev_count,
        "fleet_summary": {
            "total": fleet_rows.len(),
            "healthy": healthy,
            "runtimes": fleet_rows,
        },
        "worker_summary": store::jobs_summary(&db, &st.org),
        "playbooks": fleet::playbooks_list(&db, &st.org, shop_id, None),
        "agent_hub": st.hub_summary(false),
        "bridge": st.bridge_summary(),
        "mcp_gateway": st.gateway_summary(),
        "rubric_labels": rubric_labels,
    })))
}

async fn seed_demo_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let res = store::with_write_tx_str(&st.path, |db| {
        conn_mod::seed_demo_workspace(db, &st.org, "owner")
    })
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(res))
}

async fn purge_demo_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let res = store::with_write_tx_str(&st.path, |db| {
        conn_mod::purge_demo_workspace(db, &st.org, "owner")
    })
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(res))
}

async fn create_shop_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() || name.len() > 80 {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Shop name is required",
        ));
    }
    let shop_id = store::with_write_tx(&st.path, |db| -> Result<i64, rusqlite::Error> {
        db.execute(
            "INSERT INTO shops (organization_id, name) VALUES (?1, ?2)",
            params![st.org, name],
        )?;
        let sid = db.last_insert_rowid();
        audit::append(
            db,
            &st.org,
            "owner",
            "shop.created",
            &sid.to_string(),
            &json!({ "name": name }),
        )?;
        Ok(sid)
    })
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::new(StatusCode::CONFLICT, "Shop already exists")
        } else {
            AppError::from(e)
        }
    })?;
    if let Some(ref hub) = st.hub_client {
        hub.try_push_shop(&name);
    }
    Ok(Json(json!({ "id": shop_id, "name": name })))
}

async fn get_integrations_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(st.conns.inventory(&db)))
}

async fn save_integration_handler(
    State(st): State<Arc<AppState>>,
    Path(provider): Path<String>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    if !store::PROVIDERS.contains(&provider.as_str()) {
        return Err(AppError::new(StatusCode::NOT_FOUND, "Unknown provider"));
    }
    let body = parse_json_body(&raw_body)?;
    Ok(Json(st.conns.save_app(&provider, &body)?))
}

async fn create_connection_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let provider = body
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !store::PROVIDERS.contains(&provider.as_str()) || label.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Provider and label are required",
        ));
    }
    let cid = store::with_write_tx(&st.path, |db| -> Result<i64, rusqlite::Error> {
        db.execute(
            "INSERT INTO provider_connections (organization_id, provider, label, state)
             VALUES (?1, ?2, ?3, 'not_connected')",
            params![st.org, provider, label],
        )?;
        let id = db.last_insert_rowid();
        db.execute(
            "INSERT INTO connection_runtime (organization_id, connection_id, revision, app_revision) VALUES (?1, ?2, 1, 0)",
            params![st.org, id],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            "connection.created",
            &id.to_string(),
            &json!({ "provider": provider, "label": label }),
        )?;
        Ok(id)
    })?;
    Ok(Json(json!({ "id": cid, "provider": provider, "label": label })))
}

async fn authorize_connection_handler(
    State(st): State<Arc<AppState>>,
    Path(connection_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("oauth:{session_hash}"), 10, 60)?;
    let base = st.public_base(&headers, &uri)?;
    Ok(Json(st.conns.start(connection_id, &session_hash, &base)?))
}

async fn oauth_callback_handler(
    State(st): State<Arc<AppState>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, AppError> {
    let sig_key = st.session_signing_key()?;
    let cookies = parse_cookies(&headers);
    let session_hash = verify_session_cookie(&sig_key, cookies.get("lnc_care_session").map(|s| s.as_str()))
        .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "Authentication required"))?;
    let q = query_map(&uri);
    let state_param = q.get("state").map(|s| s.as_str()).unwrap_or("");
    let code_param = q.get("code").map(|s| s.as_str()).unwrap_or("");
    st.conns
        .callback(&provider, state_param, code_param, &session_hash)?;
    Ok(redirect_303("/admin/#channels"))
}

async fn disconnect_connection_handler(
    State(st): State<Arc<AppState>>,
    Path(connection_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    Ok(Json(st.conns.disconnect(connection_id)?))
}

async fn discover_channels_handler(
    State(st): State<Arc<AppState>>,
    Path(connection_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("discover:{session_hash}"), 10, 60)?;
    Ok(Json(st.conns.discover(connection_id)?))
}

async fn list_discovered_channels_handler(
    State(st): State<Arc<AppState>>,
    Path(connection_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(json!({ "channels": st.conns.discovered(&db, connection_id)? })))
}

async fn approve_channel_handler(
    State(st): State<Arc<AppState>>,
    Path(connection_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let external_id = body
        .get("external_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let shop_id = body
        .get("shop_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0);
    let reply_policy = body
        .get("reply_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("draft_only");
    Ok(Json(st.conns.approve_channel(
        connection_id,
        external_id,
        shop_id,
        reply_policy,
    )?))
}

async fn sync_channel_handler(
    State(st): State<Arc<AppState>>,
    Path(channel_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("sync:{session_hash}"), 15, 60)?;
    Ok(Json(st.conns.sync_channel(channel_id, 25, 50)?))
}

async fn subscribe_channel_webhook_handler(
    State(st): State<Arc<AppState>>,
    Path(channel_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("subscribe:{session_hash}"), 15, 60)?;
    let body = parse_json_body(&raw_body)?;
    let fields = body
        .get("fields")
        .and_then(|v| v.as_str())
        .unwrap_or("feed,messages,mention");
    Ok(Json(st.conns.subscribe_channel_webhooks(channel_id, fields)?))
}

async fn browser_sync_channel_handler(
    State(st): State<Arc<AppState>>,
    Path(channel_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    let session_hash = st.require_admin(&method, &headers)?;
    st.check_rate(&format!("browser_sync:{session_hash}"), 15, 60)?;
    let body = parse_json_body(&raw_body)?;
    let runtime_id = body
        .get("runtime_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let inline_posts = body.get("posts").and_then(|v| v.as_array()).map(|a| a.as_slice());
    let reschedule = body
        .get("reschedule")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let res = fleet::run_browser_channel_fetch(
        &st.path,
        &st.org,
        channel_id,
        runtime_id,
        inline_posts,
        reschedule,
        Some(st.conns.providers.transport()),
        &st.env_map,
        "owner",
    )
    .map_err(|e| AppError::new(StatusCode::CONFLICT, e))?;
    Ok(Json(res))
}

async fn update_channel_policy_handler(
    State(st): State<Arc<AppState>>,
    Path(channel_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let policy = body
        .get("reply_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("draft_only");
    let threshold = body
        .get("auto_suggest_threshold")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(80);
    if !store::REPLY_POLICIES.contains(&policy) || !(10..=99).contains(&threshold) {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid reply_policy or auto_suggest_threshold",
        ));
    }
    store::with_write_tx(&st.path, |db| -> Result<(), rusqlite::Error> {
        db.execute(
            "UPDATE channels SET reply_policy=?1, auto_suggest_threshold=?2 WHERE organization_id=?3 AND id=?4",
            params![policy, threshold, st.org, channel_id],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            "channel.policy_updated",
            &channel_id.to_string(),
            &json!({ "reply_policy": policy, "auto_suggest_threshold": threshold }),
        )?;
        Ok(())
    })?;
    Ok(Json(json!({
        "ok": true,
        "channel_id": channel_id,
        "reply_policy": policy,
        "auto_suggest_threshold": threshold,
    })))
}

async fn list_conversations_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let shop_id = q.get("shop_id").and_then(|s| s.trim().parse::<i64>().ok());
    let channel_id = q
        .get("channel_id")
        .and_then(|s| s.trim().parse::<i64>().ok());
    let status = q.get("status").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let limit = q
        .get("limit")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(50);
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(json!({
        "conversations": store::conversations_list(&db, &st.org, shop_id, channel_id, status, limit)
    })))
}

async fn list_conversation_messages_handler(
    State(st): State<Arc<AppState>>,
    Path(conversation_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let limit = q
        .get("limit")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(100);
    let db = store::connect_readonly(&st.path)?;
    let conv = query_one_map(
        &db,
        "SELECT * FROM conversations WHERE organization_id=? AND id=?",
        &[st.org.clone().into(), conversation_id.into()],
    )
    .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "Conversation not found"))?;
    Ok(Json(json!({
        "conversation": conv,
        "messages": store::messages_list(&db, &st.org, conversation_id, limit),
    })))
}

async fn send_conversation_message_handler(
    State(st): State<Arc<AppState>>,
    Path(conversation_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let text = body
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if text.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Message text is required",
        ));
    }
    let now = now_unix();
    let res = store::with_write_tx(&st.path, |db| -> Result<Value, AppError> {
        let conv = query_one_map(
            db,
            "SELECT cv.*, c.reply_policy FROM conversations cv
             JOIN channels c ON c.id=cv.channel_id AND c.organization_id=cv.organization_id
             WHERE cv.organization_id=? AND cv.id=?",
            &[st.org.clone().into(), conversation_id.into()],
        )
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "Conversation not found"))?;
        let policy = conv
            .get("reply_policy")
            .and_then(|v| v.as_str())
            .unwrap_or("draft_only");
        let msg_status = if st.writes_enabled && policy != "draft_only" {
            "sent"
        } else {
            "draft"
        };
        let ext_id = format!("out_{conversation_id}_{}", random_hex(6));
        let channel_id = conv.get("channel_id").and_then(|v| v.as_i64()).unwrap_or(0);
        db.execute(
            "INSERT INTO messages
             (organization_id, conversation_id, channel_id, external_id, direction, sender_id, sender_name, text, status, created_at)
             VALUES (?1, ?2, ?3, ?4, 'outbound', 'owner', 'Care Operator', ?5, ?6, ?7)",
            params![st.org, conversation_id, channel_id, ext_id, text, msg_status, now],
        )?;
        let msg_id = db.last_insert_rowid();
        let preview: String = text.chars().take(160).collect();
        let conv_status = if msg_status == "sent" {
            "replied"
        } else {
            "pending_reply"
        };
        db.execute(
            "UPDATE conversations
             SET last_message_preview=?1, status=?2, unread_count=0, updated_at=?3
             WHERE organization_id=?4 AND id=?5",
            params![preview, conv_status, now, st.org, conversation_id],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            &format!("conversation.message_{msg_status}"),
            &conversation_id.to_string(),
            &json!({ "message_id": msg_id }),
        )?;
        Ok(json!({ "ok": true, "status": msg_status, "message_id": msg_id }))
    })?;
    Ok(Json(res))
}

async fn list_leads_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let shop_id = q.get("shop_id").and_then(|s| s.trim().parse::<i64>().ok());
    let status = q.get("status").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let limit = q
        .get("limit")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(50);
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(json!({
        "leads": store::leads_list(&db, &st.org, shop_id, None, status, limit)
    })))
}

async fn create_lead_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let customer_name: String = body
        .get("customer_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(120)
        .collect();
    if customer_name.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Customer name is required",
        ));
    }
    let contact_handle: String = body
        .get("contact_handle")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(120)
        .collect();
    let phone: String = body
        .get("phone")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(40)
        .collect();
    let email: String = body
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(120)
        .collect();
    let notes: String = body
        .get("notes")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(500)
        .collect();
    let raw_src = body
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("manual")
        .trim();
    let source = if matches!(raw_src, "comment" | "dm" | "meta_lead_ad" | "manual") {
        raw_src
    } else {
        "manual"
    };
    let shop_id = body
        .get("shop_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .filter(|&x| x > 0);
    let now = now_unix();
    let id = store::with_write_tx(&st.path, |db| -> Result<i64, rusqlite::Error> {
        db.execute(
            "INSERT INTO leads
             (organization_id, shop_id, source, customer_name, contact_handle, phone, email, intent_score, status, notes, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 85.0, 'new', ?8, ?9, ?10)",
            params![
                st.org,
                shop_id,
                source,
                customer_name,
                contact_handle,
                phone,
                email,
                notes,
                now,
                now
            ],
        )?;
        let lid = db.last_insert_rowid();
        audit::append(
            db,
            &st.org,
            "owner",
            "lead.created",
            &lid.to_string(),
            &json!({ "customer_name": customer_name }),
        )?;
        Ok(lid)
    })?;
    Ok(Json(json!({ "ok": true, "id": id })))
}

async fn list_handoffs_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let shop_id = q.get("shop_id").and_then(|s| s.trim().parse::<i64>().ok());
    let status = q.get("status").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let limit = q
        .get("limit")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(50);
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(json!({
        "handoffs": store::handoffs_list(&db, &st.org, shop_id, status, limit)
    })))
}

async fn create_handoff_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let summary: String = body
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(300)
        .collect();
    if summary.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Summary is required",
        ));
    }
    let raw_prio = body
        .get("priority")
        .and_then(|v| v.as_str())
        .unwrap_or("normal")
        .trim();
    let priority = if matches!(raw_prio, "low" | "normal" | "high" | "urgent") {
        raw_prio
    } else {
        "normal"
    };
    let assignee: String = body
        .get("assignee")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("care-team")
        .chars()
        .take(80)
        .collect();
    let shop_id = body
        .get("shop_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .filter(|&x| x > 0);
    let now = now_unix();
    let id = store::with_write_tx(&st.path, |db| -> Result<i64, rusqlite::Error> {
        db.execute(
            "INSERT INTO ticket_handoffs
             (organization_id, shop_id, priority, assignee, summary, status, created_by, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'open', 'owner', ?6, ?7)",
            params![st.org, shop_id, priority, assignee, summary, now, now],
        )?;
        let hid = db.last_insert_rowid();
        audit::append(
            db,
            &st.org,
            "owner",
            "handoff.created",
            &hid.to_string(),
            &json!({ "priority": priority, "assignee": assignee }),
        )?;
        Ok(hid)
    })?;
    Ok(Json(json!({ "ok": true, "id": id })))
}

async fn list_posts_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let channel_id = q
        .get("channel_id")
        .and_then(|s| s.trim().parse::<i64>().ok());
    let shop_id = q.get("shop_id").and_then(|s| s.trim().parse::<i64>().ok());
    let kind = q.get("kind").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let limit = q
        .get("limit")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(50);
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(json!({
        "posts": store::posts_list(&db, &st.org, channel_id, shop_id, kind, limit)
    })))
}

async fn get_post_handler(
    State(st): State<Arc<AppState>>,
    Path(post_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let post = store::post_detail(&db, &st.org, post_id)
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "Post not found"))?;
    Ok(Json(json!({ "post": post })))
}

async fn request_post_archive_handler(
    State(st): State<Arc<AppState>>,
    Path(post_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let jobs = store::with_write_tx(&st.path, |db| -> Result<Vec<i64>, AppError> {
        let exists = db
            .query_row(
                "SELECT 1 FROM posts WHERE organization_id=?1 AND id=?2",
                params![st.org, post_id],
                |r| r.get::<_, i64>(0),
            )
            .is_ok();
        if !exists {
            return Err(AppError::new(StatusCode::NOT_FOUND, "Post not found"));
        }
        let j1 = worker::enqueue_job(db, &st.org, "archive_media", &json!({ "post_id": post_id }), 0)?;
        let j2 = worker::enqueue_job(db, &st.org, "screenshot", &json!({ "post_id": post_id }), 0)?;
        audit::append(
            db,
            &st.org,
            "owner",
            "post.archive_requested",
            &post_id.to_string(),
            &json!({ "jobs": [j1, j2] }),
        )?;
        Ok(vec![j1, j2])
    })?;
    let worker_res = worker::run_pending_jobs_with_runtime(
        &st.path,
        &st.org,
        5,
        "care-worker",
        Some(&st.conns),
        Some(st.conns.providers.transport()),
        &st.env_map,
    );
    Ok(Json(json!({
        "ok": true,
        "post_id": post_id,
        "jobs": jobs,
        "worker": worker_res,
    })))
}

async fn list_comments_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let shop_id = q.get("shop_id").and_then(|s| s.trim().parse::<i64>().ok());
    let channel_id = q
        .get("channel_id")
        .and_then(|s| s.trim().parse::<i64>().ok());
    let post_id = q.get("post_id").and_then(|s| s.trim().parse::<i64>().ok());
    let status = q.get("status").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let bucket = q.get("bucket").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let assignment = q
        .get("assignment")
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty());
    let search = q.get("search").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let limit = q
        .get("limit")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(100);
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(json!({
        "comments": store::comments_list(
            &db, &st.org, shop_id, channel_id, post_id, status, bucket, assignment, search, limit
        ),
        "summary": store::inbox_summary(&db, &st.org, shop_id),
    })))
}

async fn get_comment_handler(
    State(st): State<Arc<AppState>>,
    Path(comment_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let thread = store::comment_thread(&db, &st.org, comment_id)
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, "Comment not found"))?;
    Ok(Json(json!({ "thread": thread })))
}

async fn evaluate_comment_handler(
    State(st): State<Arc<AppState>>,
    Path(comment_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let threshold = body
        .get("threshold")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let res = store::with_write_tx(&st.path, |db| -> Result<Value, AppError> {
        let ev = evaluator::evaluate_and_persist(db, &st.org, comment_id, threshold, "owner")
            .map_err(|e| AppError::new(StatusCode::NOT_FOUND, e))?;
        audit::append(
            db,
            &st.org,
            "owner",
            "comment.evaluated",
            &comment_id.to_string(),
            &json!({
                "overall_score": ev.get("overall_score"),
                "recommended_action": ev.get("recommended_action"),
            }),
        )?;
        let thread = store::comment_thread(db, &st.org, comment_id);
        Ok(json!({ "ok": true, "evaluation": ev, "thread": thread }))
    })?;
    Ok(Json(res))
}

async fn feedback_comment_handler(
    State(st): State<Arc<AppState>>,
    Path(comment_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("_decision");
    let agreed = body
        .get("agreed")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let human_decision = body
        .get("human_decision")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let res = store::with_write_tx(&st.path, |db| -> Result<Value, AppError> {
        let fb = evaluator::record_feedback(
            db,
            &st.org,
            comment_id,
            Some(label),
            Some(agreed),
            human_decision,
            "owner",
        )
        .map_err(|e| AppError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
        audit::append(
            db,
            &st.org,
            "owner",
            "comment.feedback_recorded",
            &comment_id.to_string(),
            &json!({
                "label": label,
                "agreed": agreed,
                "human_decision": human_decision,
            }),
        )?;
        let thread = store::comment_thread(db, &st.org, comment_id);
        Ok(json!({ "ok": true, "feedback": fb, "thread": thread }))
    })?;
    Ok(Json(res))
}

async fn update_comment_state_handler(
    State(st): State<Arc<AppState>>,
    Path(comment_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("needs_reply");
    let bucket = body.get("bucket").and_then(|v| v.as_str());
    let assigned_to = body.get("assigned_to").and_then(|v| v.as_str());
    let note = body.get("note").and_then(|v| v.as_str());
    if !store::COMMENT_STATUSES.contains(&status) {
        return Err(AppError::new(StatusCode::UNPROCESSABLE_ENTITY, "Invalid status"));
    }
    if let Some(b) = bucket {
        if !store::COMMENT_BUCKETS.contains(&b) {
            return Err(AppError::new(StatusCode::UNPROCESSABLE_ENTITY, "Invalid bucket"));
        }
    }
    let now = now_unix();
    let res = store::with_write_tx(&st.path, |db| -> Result<Value, rusqlite::Error> {
        let cur = query_one_map(
            db,
            "SELECT * FROM comment_states WHERE organization_id=? AND comment_id=?",
            &[st.org.clone().into(), comment_id.into()],
        );
        let eff_bucket = bucket
            .map(String::from)
            .or_else(|| {
                cur.as_ref()
                    .and_then(|c| c.get("bucket"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "needs_review".to_string());
        let eff_assigned = assigned_to
            .map(String::from)
            .or_else(|| {
                cur.as_ref()
                    .and_then(|c| c.get("assigned_to"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        let eff_note = note
            .map(String::from)
            .or_else(|| {
                cur.as_ref()
                    .and_then(|c| c.get("note"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        db.execute(
            "INSERT INTO comment_states
             (organization_id, comment_id, status, bucket, assigned_to, note, updated_by, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'owner', ?7)
             ON CONFLICT(organization_id, comment_id) DO UPDATE SET
              status=excluded.status,
              bucket=excluded.bucket,
              assigned_to=excluded.assigned_to,
              note=excluded.note,
              updated_by='owner',
              updated_at=excluded.updated_at",
            params![st.org, comment_id, status, eff_bucket, eff_assigned, eff_note, now],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            "comment.state_updated",
            &comment_id.to_string(),
            &json!({ "status": status, "bucket": eff_bucket, "assigned_to": eff_assigned }),
        )?;
        let thread = store::comment_thread(db, &st.org, comment_id);
        Ok(json!({ "ok": true, "thread": thread }))
    })?;
    Ok(Json(res))
}

async fn save_comment_draft_handler(
    State(st): State<Arc<AppState>>,
    Path(comment_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let text = body
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let kind = body
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("public");
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("approved");
    let strategy_summary = body
        .get("strategy_summary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if text.is_empty()
        || !matches!(kind, "public" | "private_dm")
        || !matches!(status, "draft" | "approved" | "sent" | "rejected")
    {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Valid text, kind, and status are required",
        ));
    }
    let now = now_unix();
    let res = store::with_write_tx(&st.path, |db| -> Result<Value, rusqlite::Error> {
        let approved_by: Option<&str> = if status == "approved" {
            Some("owner")
        } else {
            None
        };
        db.execute(
            "INSERT INTO reply_drafts
             (organization_id, comment_id, kind, strategy_summary, text, created_by, status, approved_by, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'owner', ?6, ?7, ?8, ?9)",
            params![
                st.org,
                comment_id,
                kind,
                strategy_summary,
                text,
                status,
                approved_by,
                now,
                now
            ],
        )?;
        let draft_id = db.last_insert_rowid();
        if matches!(status, "approved" | "sent") {
            db.execute(
                "INSERT INTO comment_states (organization_id, comment_id, status, updated_by, updated_at)
                 VALUES (?1, ?2, 'replied', 'owner', ?3)
                 ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                  status='replied', updated_by='owner', updated_at=excluded.updated_at",
                params![st.org, comment_id, now],
            )?;
        }
        audit::append(
            db,
            &st.org,
            "owner",
            &format!("reply_draft.{status}"),
            &draft_id.to_string(),
            &json!({ "comment_id": comment_id, "kind": kind }),
        )?;
        let thread = store::comment_thread(db, &st.org, comment_id);
        Ok(json!({ "ok": true, "draft_id": draft_id, "thread": thread }))
    })?;
    Ok(Json(res))
}

async fn list_evidence_cases_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let mut cases = Vec::new();
    for mut c in query_maps(
        &db,
        "SELECT * FROM evidence_cases WHERE organization_id=? ORDER BY id DESC",
        &[st.org.clone().into()],
    ) {
        let cid = c.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let items: Vec<Value> = query_maps(
            &db,
            "SELECT * FROM evidence_items WHERE organization_id=? AND case_id=? ORDER BY id DESC",
            &[st.org.clone().into(), cid.into()],
        )
        .into_iter()
        .map(|mut it| {
            let art = it
                .get("artifacts_json")
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .unwrap_or_else(|| json!({}));
            it.insert("artifacts".to_string(), art);
            Value::Object(it)
        })
        .collect();
        c.insert("items".to_string(), Value::Array(items));
        cases.push(Value::Object(c));
    }
    Ok(Json(json!({ "cases": cases })))
}

async fn capture_evidence_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let target_url = body
        .get("target_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let title = body
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let comment_id = body
        .get("comment_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let case_id = body
        .get("case_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let res = store::with_write_tx_str(&st.path, |db| {
        conn_mod::capture_forensic_evidence_on_disk(
            db,
            &st.path,
            &st.org,
            target_url,
            title,
            comment_id,
            case_id,
            "owner",
            Some(st.conns.providers.transport()),
        )
    })
    .map_err(|e| AppError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    Ok(Json(res))
}

async fn export_evidence_case_handler(
    State(st): State<Arc<AppState>>,
    Path(case_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let data_dir = evidence::resolve_data_dir(&st.path);
    let (filename, zip_bytes) = evidence::export_case_zip(&db, &data_dir, &st.org, case_id)
        .map_err(|e| AppError::new(StatusCode::NOT_FOUND, e))?;
    let mut resp = (StatusCode::OK, zip_bytes).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    if let Ok(cd) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, cd);
    }
    Ok(resp)
}

async fn verify_evidence_case_handler(
    State(st): State<Arc<AppState>>,
    Path(case_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let data_dir = evidence::resolve_data_dir(&st.path);
    let res = evidence::verify_case_custody(&db, &data_dir, &st.org, case_id)
        .map_err(|e| AppError::new(StatusCode::NOT_FOUND, e))?;
    Ok(Json(res))
}

async fn check_evidence_case_handler(
    State(st): State<Arc<AppState>>,
    Path(case_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let item_id = body
        .get("item_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let res = store::with_write_tx_str(&st.path, |db| {
        evidence::run_watchdog_check(
            db,
            &st.org,
            Some(case_id),
            item_id,
            Some(st.conns.providers.transport()),
            "owner",
        )
    })
    .map_err(|e| AppError::new(StatusCode::NOT_FOUND, e))?;
    Ok(Json(res))
}

async fn list_fleet_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let runtimes: Vec<Value> = query_maps(
        &db,
        "SELECT * FROM account_runtimes WHERE organization_id=? ORDER BY id ASC",
        &[st.org.clone().into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();
    let leases: Vec<Value> = query_maps(
        &db,
        "SELECT * FROM runtime_leases WHERE organization_id=? ORDER BY id DESC LIMIT 30",
        &[st.org.clone().into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();
    Ok(Json(json!({ "runtimes": runtimes, "leases": leases })))
}

async fn save_fleet_runtime_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let platform = body
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("facebook")
        .trim();
    let account_role = body
        .get("account_role")
        .and_then(|v| v.as_str())
        .unwrap_or("care_consultant")
        .trim();
    let adapter = body
        .get("adapter")
        .and_then(|v| v.as_str())
        .unwrap_or("veilbrowser")
        .trim();
    let runtime_profile_id = body
        .get("runtime_profile_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let expected_exit_ip = body
        .get("expected_exit_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let expected_country = body
        .get("expected_country")
        .and_then(|v| v.as_str())
        .unwrap_or("FR")
        .trim();
    let health_status = body
        .get("health_status")
        .and_then(|v| v.as_str())
        .unwrap_or("healthy")
        .trim();
    let daily_read_budget = body
        .get("daily_read_budget")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(120);
    let daily_write_budget = if account_role == "personal_main" {
        0
    } else {
        body.get("daily_write_budget")
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(20)
    };

    if label.is_empty()
        || runtime_profile_id.is_empty()
        || !store::CHANNEL_ADAPTERS.contains(&adapter)
    {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Valid label, adapter, and runtime_profile_id are required",
        ));
    }
    let now = now_unix();
    let id = store::with_write_tx(&st.path, |db| -> Result<i64, rusqlite::Error> {
        db.execute(
            "INSERT INTO account_runtimes
             (organization_id, label, platform, account_role, adapter, runtime_profile_id,
              expected_exit_ip, expected_country, health_status, daily_read_budget, daily_write_budget, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(organization_id, adapter, runtime_profile_id) DO UPDATE SET
              label=excluded.label,
              account_role=excluded.account_role,
              expected_exit_ip=excluded.expected_exit_ip,
              expected_country=excluded.expected_country,
              health_status=excluded.health_status,
              daily_read_budget=excluded.daily_read_budget,
              daily_write_budget=excluded.daily_write_budget,
              updated_at=excluded.updated_at",
            params![
                st.org,
                label,
                platform,
                account_role,
                adapter,
                runtime_profile_id,
                expected_exit_ip,
                expected_country,
                health_status,
                daily_read_budget,
                daily_write_budget,
                now
            ],
        )?;
        let rid: i64 = db
            .query_row(
                "SELECT id FROM account_runtimes WHERE organization_id=?1 AND adapter=?2 AND runtime_profile_id=?3",
                params![st.org, adapter, runtime_profile_id],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| db.last_insert_rowid());
        audit::append(
            db,
            &st.org,
            "owner",
            "fleet.runtime_saved",
            runtime_profile_id,
            &json!({
                "adapter": adapter,
                "account_role": account_role,
                "health_status": health_status,
            }),
        )?;
        Ok(rid)
    })?;
    Ok(Json(json!({
        "ok": true,
        "id": id,
        "runtime_profile_id": runtime_profile_id,
    })))
}

async fn probe_fleet_runtime_handler(
    State(st): State<Arc<AppState>>,
    Path(runtime_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let res = fleet::probe_runtime(
        &st.path,
        &st.org,
        runtime_id,
        Some(st.conns.providers.transport()),
        &st.env_map,
        "owner",
    )
    .map_err(|e| AppError::new(StatusCode::CONFLICT, e))?;
    Ok(Json(res))
}

async fn resume_fleet_runtime_handler(
    State(st): State<Arc<AppState>>,
    Path(runtime_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let res = fleet::resume_runtime(&st.path, &st.org, runtime_id, "owner")
        .map_err(|e| AppError::new(StatusCode::NOT_FOUND, e))?;
    Ok(Json(res))
}

async fn list_playbooks_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let q = query_map(&uri);
    let shop_id = q.get("shop_id").and_then(|s| s.trim().parse::<i64>().ok());
    let channel_id = q
        .get("channel_id")
        .and_then(|s| s.trim().parse::<i64>().ok());
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(json!({
        "playbooks": fleet::playbooks_list(&db, &st.org, shop_id, channel_id)
    })))
}

async fn save_playbook_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let playbook_id = body
        .get("id")
        .or_else(|| body.get("playbook_id"))
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let shop_id = body
        .get("shop_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .filter(|&x| x > 0);
    let channel_id = body
        .get("channel_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .filter(|&x| x > 0);
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let threshold = body
        .get("auto_suggest_threshold")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(80);
    let auto_consult = match body.get("auto_consult_enabled") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "on"),
        Some(Value::Number(n)) => n.as_i64().map(|x| x != 0).unwrap_or(false),
        _ => false,
    };
    let knowledge_md = body
        .get("consultation_knowledge_md")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let forbidden: Vec<String> = match body.get("forbidden_topics") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    let res = store::with_write_tx_str(&st.path, |db| {
        fleet::upsert_playbook(
            db,
            &st.org,
            playbook_id,
            shop_id,
            channel_id,
            name,
            threshold,
            auto_consult,
            knowledge_md,
            &forbidden,
            "owner",
        )
    })
    .map_err(|e| AppError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    Ok(Json(res))
}

async fn list_rules_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let rules: Vec<Value> = query_maps(
        &db,
        "SELECT * FROM rules WHERE organization_id=? ORDER BY id DESC",
        &[st.org.clone().into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();
    Ok(Json(json!({ "rules": rules })))
}

async fn save_rule_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let pattern = body
        .get("pattern")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let match_kind = body
        .get("match_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("keyword")
        .trim();
    let flag = body
        .get("flag")
        .and_then(|v| v.as_str())
        .unwrap_or("flagged")
        .trim();
    let auto_status = body
        .get("auto_status")
        .and_then(|v| v.as_str())
        .unwrap_or("needs_reply")
        .trim();
    let auto_bucket = body
        .get("auto_bucket")
        .and_then(|v| v.as_str())
        .unwrap_or("needs_review")
        .trim();
    if name.is_empty()
        || pattern.is_empty()
        || !store::COMMENT_STATUSES.contains(&auto_status)
        || !store::COMMENT_BUCKETS.contains(&auto_bucket)
    {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Valid rule name, pattern, status, and bucket required",
        ));
    }
    let now = now_unix();
    store::with_write_tx(&st.path, |db| -> Result<(), rusqlite::Error> {
        db.execute(
            "INSERT INTO rules
             (organization_id, name, pattern, match_kind, flag, auto_status, auto_bucket, enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)
             ON CONFLICT(organization_id, name) DO UPDATE SET
              pattern=excluded.pattern,
              match_kind=excluded.match_kind,
              flag=excluded.flag,
              auto_status=excluded.auto_status,
              auto_bucket=excluded.auto_bucket",
            params![st.org, name, pattern, match_kind, flag, auto_status, auto_bucket, now],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            "rule.saved",
            name,
            &json!({ "pattern": pattern, "auto_bucket": auto_bucket }),
        )?;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true, "name": name })))
}

async fn trigger_worker_jobs_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    Ok(Json(worker::run_pending_jobs_with_runtime(
        &st.path,
        &st.org,
        15,
        "care-worker",
        Some(&st.conns),
        Some(st.conns.providers.transport()),
        &st.env_map,
    )))
}

async fn api_status_handler(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_api_or_admin(&headers, &uri)?;
    let base = st.public_base(&headers, &uri)?;
    let db = store::connect_readonly(&st.path)?;
    let shops_cnt: i64 = db.query_row(
        "SELECT COUNT(*) FROM shops WHERE organization_id=?1",
        params![st.org],
        |r| r.get(0),
    )?;
    let channels_cnt: i64 = db.query_row(
        "SELECT COUNT(*) FROM channels WHERE organization_id=?1 AND approved=1",
        params![st.org],
        |r| r.get(0),
    )?;
    let comments_cnt: i64 = db.query_row(
        "SELECT COUNT(*) FROM comments WHERE organization_id=?1",
        params![st.org],
        |r| r.get(0),
    )?;
    Ok(Json(json!({
        "ok": true,
        "service": st.audience,
        "version": crate::VERSION,
        "uptime_seconds": (now_unix() - st.boot_ts).max(0),
        "base_url": base,
        "mcp_endpoint": if !base.is_empty() { format!("{base}/mcp") } else { "/mcp".to_string() },
        "writes_enabled": st.writes_enabled,
        "inventory": {
            "shops": shops_cnt,
            "approved_channels": channels_cnt,
            "comments": comments_cnt,
        },
    })))
}

async fn list_api_keys_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(st.keys_inventory_payload(&db)?))
}

async fn create_api_key_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let label: String = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(80)
        .collect();
    if label.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Key label is required",
        ));
    }
    let custom = body
        .get("secret")
        .or_else(|| body.get("custom"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let raw_key = if !custom.is_empty() {
        if custom.len() < 24 {
            return Err(AppError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Custom secret must be at least 24 characters",
            ));
        }
        custom.to_string()
    } else {
        format!("care_{}", random_urlsafe(24))
    };
    let prefix: String = raw_key.chars().take(12).collect();
    let key_hash = hex::encode(Sha256::digest(raw_key.as_bytes()));
    let now = now_unix();

    let key_id = store::with_write_tx(&st.path, |db| -> Result<i64, AppError> {
        let dup = db
            .query_row(
                "SELECT id FROM api_keys WHERE organization_id=?1 AND key_hash=?2",
                params![st.org, key_hash],
                |r| r.get::<_, i64>(0),
            )
            .is_ok();
        if dup {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "Key secret already exists",
            ));
        }
        db.execute(
            "INSERT INTO api_keys (organization_id, label, prefix, key_hash, status, created_at)
             VALUES (?1, ?2, ?3, ?4, 'enabled', ?5)",
            params![st.org, label, prefix, key_hash, now],
        )?;
        let kid = db.last_insert_rowid();
        if st.vault.ready {
            st.vault
                .put(db, &st.org, "api_key", &kid.to_string(), &json!({ "secret": raw_key }))?;
        }
        audit::append(
            db,
            &st.org,
            "owner",
            "api_key.created",
            &kid.to_string(),
            &json!({ "label": label, "prefix": prefix }),
        )?;
        Ok(kid)
    })?;

    Ok(Json(json!({
        "key": raw_key,
        "secret": raw_key,
        "item": {
            "id": key_id,
            "label": label,
            "prefix": prefix,
            "status": "enabled",
            "enabled": true,
            "created_at": now,
            "copy_available": st.vault.ready,
            "source": "runtime",
        }
    })))
}

async fn copy_api_key_handler(
    State(st): State<Arc<AppState>>,
    Path(key_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let res = store::with_write_tx(&st.path, |db| -> Result<Value, AppError> {
        let row: Option<(String, String)> = db
            .query_row(
                "SELECT label, status FROM api_keys WHERE organization_id=?1 AND id=?2",
                params![st.org, key_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let Some((label, status)) = row else {
            return Err(AppError::new(
                StatusCode::NOT_FOUND,
                "Copyable API key not found",
            ));
        };
        if status == "revoked" {
            return Err(AppError::new(
                StatusCode::NOT_FOUND,
                "Copyable API key not found",
            ));
        }
        let env_sec = if st.vault.ready {
            st.vault.get(db, &st.org, "api_key", &key_id.to_string())?
        } else {
            None
        };
        let sec_str = env_sec
            .as_ref()
            .and_then(|s| s.get("secret").and_then(|v| v.as_str()))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::new(StatusCode::CONFLICT, "Secret is not stored for copy"))?
            .to_string();
        audit::append(
            db,
            &st.org,
            "owner",
            "api_key.copied",
            &key_id.to_string(),
            &json!({ "label": label }),
        )?;
        Ok(json!({ "key": sec_str, "secret": sec_str }))
    })?;
    Ok(Json(res))
}

async fn rename_api_key_handler(
    State(st): State<Arc<AppState>>,
    Path(key_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let body = parse_json_body(&raw_body)?;
    let label: String = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(80)
        .collect();
    if label.is_empty() {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Key label is required",
        ));
    }
    store::with_write_tx(&st.path, |db| -> Result<(), AppError> {
        let exists = db
            .query_row(
                "SELECT id FROM api_keys WHERE organization_id=?1 AND id=?2",
                params![st.org, key_id],
                |r| r.get::<_, i64>(0),
            )
            .is_ok();
        if !exists {
            return Err(AppError::new(StatusCode::NOT_FOUND, "API key not found"));
        }
        db.execute(
            "UPDATE api_keys SET label=?1 WHERE organization_id=?2 AND id=?3",
            params![label, st.org, key_id],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            "api_key.renamed",
            &key_id.to_string(),
            &json!({ "label": label }),
        )?;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true, "id": key_id, "label": label })))
}

async fn toggle_api_key_handler(
    State(st): State<Arc<AppState>>,
    Path(key_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let req_path = uri.path().to_string();
    let next_status = store::with_write_tx(&st.path, |db| -> Result<String, AppError> {
        let cur_status: String = db
            .query_row(
                "SELECT status FROM api_keys WHERE organization_id=?1 AND id=?2",
                params![st.org, key_id],
                |r| r.get(0),
            )
            .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "API key not found"))?;
        if cur_status == "revoked" {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "Revoked API key cannot be re-enabled",
            ));
        }
        let next = if req_path.ends_with("/enable") {
            "enabled"
        } else if req_path.ends_with("/disable") {
            "disabled"
        } else if cur_status == "enabled" {
            "disabled"
        } else {
            "enabled"
        };
        db.execute(
            "UPDATE api_keys SET status=?1 WHERE organization_id=?2 AND id=?3",
            params![next, st.org, key_id],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            &format!("api_key.{next}"),
            &key_id.to_string(),
            &json!({}),
        )?;
        Ok(next.to_string())
    })?;
    Ok(Json(json!({
        "ok": true,
        "id": key_id,
        "status": next_status,
        "enabled": next_status == "enabled",
    })))
}

async fn revoke_api_key_handler(
    State(st): State<Arc<AppState>>,
    Path(key_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    store::with_write_tx(&st.path, |db| -> Result<(), AppError> {
        let exists = db
            .query_row(
                "SELECT id FROM api_keys WHERE organization_id=?1 AND id=?2",
                params![st.org, key_id],
                |r| r.get::<_, i64>(0),
            )
            .is_ok();
        if !exists {
            return Err(AppError::new(StatusCode::NOT_FOUND, "API key not found"));
        }
        db.execute(
            "UPDATE api_keys SET status='revoked' WHERE organization_id=?1 AND id=?2",
            params![st.org, key_id],
        )?;
        let _ = st.vault.delete(db, &st.org, "api_key", &key_id.to_string());
        audit::append(
            db,
            &st.org,
            "owner",
            "api_key.revoked",
            &key_id.to_string(),
            &json!({}),
        )?;
        Ok(())
    })?;
    Ok(Json(json!({
        "ok": true,
        "id": key_id,
        "status": "revoked",
        "enabled": false,
    })))
}

async fn delete_api_key_handler(
    State(st): State<Arc<AppState>>,
    Path(key_id): Path<i64>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    store::with_write_tx(&st.path, |db| -> Result<(), AppError> {
        let status: String = db
            .query_row(
                "SELECT status FROM api_keys WHERE organization_id=?1 AND id=?2",
                params![st.org, key_id],
                |r| r.get(0),
            )
            .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "API key not found"))?;
        if status != "revoked" {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "Revoke the API key before deleting its record",
            ));
        }
        let _ = st.vault.delete(db, &st.org, "api_key", &key_id.to_string());
        db.execute(
            "DELETE FROM api_keys WHERE organization_id=?1 AND id=?2",
            params![st.org, key_id],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            "api_key.deleted",
            &key_id.to_string(),
            &json!({}),
        )?;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true, "id": key_id })))
}

async fn rotate_mgmt_key_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Response, AppError> {
    st.require_admin(&method, &headers)?;
    if !st.env_mgmt_key.is_empty() {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "management_key_env_managed",
        ));
    }
    let body = parse_json_body(&raw_body)?;
    let current_key = body
        .get("current_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let rt_existing = st.load_runtime_mgmt()?;
    if rt_existing.is_some() && (current_key.is_empty() || !st.verify_mgmt_secret(current_key)?) {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "Current management key is required to confirm rotation",
        ));
    }
    let custom = body
        .get("secret")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !custom.is_empty() && custom.len() < 16 {
        return Err(AppError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Replacement management key must be at least 16 characters",
        ));
    }
    let new_secret = if !custom.is_empty() {
        custom.to_string()
    } else {
        format!("care_mgmt_{}", random_urlsafe(24))
    };
    let salt = random_hex(16);
    let digest = pbkdf2_hex(&new_secret, &salt);
    let pfx12: String = new_secret.chars().take(12).collect();
    let pfx8: String = new_secret.chars().take(8).collect();
    let state_obj = json!({
        "salt": salt,
        "hash": digest,
        "prefix": pfx12,
        "session_secret": random_urlsafe(32),
        "created_at": now_unix(),
    });
    store::with_write_tx(&st.path, |db| -> Result<(), rusqlite::Error> {
        db.execute(
            "INSERT INTO runtime_settings(organization_id, key, value) VALUES (?1, '__mgmt_state', ?2)
             ON CONFLICT(organization_id, key) DO UPDATE SET value=excluded.value",
            params![st.org, state_obj.to_string()],
        )?;
        audit::append(
            db,
            &st.org,
            "owner",
            "mgmt_key.rotated",
            "runtime",
            &json!({ "prefix": pfx8 }),
        )?;
        Ok(())
    })?;

    let mut resp = Json(json!({
        "ok": true,
        "key": new_secret,
        "prefix": pfx12,
        "source": "runtime",
    }))
    .into_response();
    append_delete_cookies(resp.headers_mut());
    Ok(resp)
}

async fn connector_info_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let cfg = st.current_settings()?;
    let base = st.public_base(&headers, &uri)?;
    let p_sec = {
        let db = store::connect_readonly(&st.path)?;
        st.pairing_secrets_summary(&db)
    };
    let b_conf = p_sec["connector_bearer"]["configured"]
        .as_bool()
        .unwrap_or(false);
    let d_conf = p_sec["delegation_secret"]["configured"]
        .as_bool()
        .unwrap_or(false);
    let mut avail: Vec<&str> = SCOPES.to_vec();
    avail.sort();
    let tools_map = mcp_server::tool_scopes_map();
    Ok(Json(json!({
        "audience": st.audience,
        "namespace": "care__*",
        "endpoint": if !base.is_empty() { format!("{base}/mcp") } else { "/mcp".to_string() },
        "transport": "streamable-http",
        "ready": b_conf && d_conf,
        "bearer_configured": b_conf,
        "bearer_source": p_sec["connector_bearer"]["source"],
        "delegation_secret_configured": d_conf,
        "delegation_secret_source": p_sec["delegation_secret"]["source"],
        "require_delegation": st.require_delegation,
        "writes_enabled": st.writes_enabled,
        "max_scopes": cfg.mcp_max_scopes,
        "available_scopes": avail,
        "tools": tools_map,
        "mcp_gateway": st.gateway_summary(),
    })))
}

async fn get_audit_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let mut ver = audit::verify(&db, &st.org);
    if let Some(obj) = ver.as_object_mut() {
        obj.insert("events".to_string(), json!(audit::list_recent(&db, &st.org, 100)));
    }
    Ok(Json(ver))
}

async fn verify_audit_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    Ok(Json(audit::verify(&db, &st.org)))
}

async fn get_settings_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let db = store::connect_readonly(&st.path)?;
    let mut res = settings::load_with_sources(&db, &st.org, &st.env_map);
    if let Some(obj) = res.as_object_mut() {
        obj.insert("secrets".to_string(), st.pairing_secrets_summary(&db));
    }
    Ok(Json(res))
}

async fn post_settings_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Result<Json<Value>, AppError> {
    st.require_admin(&method, &headers)?;
    let parsed = parse_json_body(&raw_body)?;
    let mut body_map = parsed
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::new(StatusCode::UNPROCESSABLE_ENTITY, "JSON object expected"))?;
    let raw_bearer = body_map.remove("connector_bearer");
    let raw_secret = body_map.remove("delegation_secret");
    let mut keys_vec: Vec<String> = body_map.keys().cloned().collect();
    keys_vec.sort();

    let res = store::with_write_tx(&st.path, |db| -> Result<Value, AppError> {
        if !body_map.is_empty() {
            settings::save(db, &st.org, &body_map, &st.env_map)
                .map_err(|e| AppError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
        }
        let b_str = raw_bearer
            .as_ref()
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");
        let s_str = raw_secret
            .as_ref()
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");
        if raw_bearer.is_some() || raw_secret.is_some() {
            if (!b_str.is_empty() && !st.bearer.is_empty())
                || (!s_str.is_empty() && !st.del_secret.is_empty())
            {
                return Err(AppError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Environment-managed pairing secret cannot be overridden in UI",
                ));
            }
            let existing_pair = if st.vault.ready {
                st.vault
                    .get(db, &st.org, "pairing", "connector")?
                    .unwrap_or_else(|| json!({}))
            } else {
                json!({})
            };
            let mut updated_pair = existing_pair.clone();
            if !b_str.is_empty() && b_str != "********" {
                updated_pair["connector_bearer"] = json!(b_str);
            }
            if !s_str.is_empty() && s_str != "********" {
                updated_pair["delegation_secret"] = json!(s_str);
            }
            if updated_pair != existing_pair && st.vault.ready {
                st.vault
                    .put(db, &st.org, "pairing", "connector", &updated_pair)?;
            }
        }
        let mut saved = settings::load_with_sources(db, &st.org, &st.env_map);
        if let Some(obj) = saved.as_object_mut() {
            obj.insert("secrets".to_string(), st.pairing_secrets_summary(db));
        }
        audit::append(
            db,
            &st.org,
            "owner",
            "settings.updated",
            "runtime",
            &json!({
                "keys": keys_vec,
                "pairing_updated": !b_str.is_empty() || !s_str.is_empty(),
            }),
        )?;
        Ok(saved)
    })?;
    Ok(Json(res))
}

async fn root_handler(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let sig_key = st.session_signing_key()?;
    let cookies = parse_cookies(&headers);
    if verify_session_cookie(&sig_key, cookies.get("lnc_care_session").map(|s| s.as_str())).is_some()
    {
        Ok(redirect_303("/admin/"))
    } else {
        Ok(redirect_303("/login.html"))
    }
}

async fn login_page_handler(State(st): State<Arc<AppState>>) -> Response {
    serve_static_file(&st.public_dir, "login.html", "text/html; charset=utf-8")
}

async fn admin_page_handler(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let sig_key = st.session_signing_key()?;
    let cookies = parse_cookies(&headers);
    if verify_session_cookie(&sig_key, cookies.get("lnc_care_session").map(|s| s.as_str())).is_none()
    {
        return Ok(redirect_303("/login.html"));
    }
    Ok(serve_static_file(
        &st.public_dir,
        "index.html",
        "text/html; charset=utf-8",
    ))
}

async fn icon_svg_handler(State(st): State<Arc<AppState>>) -> Response {
    serve_static_file(&st.public_dir, "icon.svg", "image/svg+xml")
}

async fn icon_png_handler(State(st): State<Arc<AppState>>) -> Response {
    serve_static_file(&st.public_dir, "icon.png", "image/png")
}

async fn favicon_ico_handler(State(st): State<Arc<AppState>>) -> Response {
    serve_static_file(&st.public_dir, "favicon.ico", "image/x-icon")
}

async fn style_css_handler(State(st): State<Arc<AppState>>) -> Response {
    serve_static_file(&st.public_dir, "style.css", "text/css; charset=utf-8")
}

async fn app_js_handler(State(st): State<Arc<AppState>>) -> Response {
    serve_static_file(
        &st.public_dir,
        "app.js",
        "application/javascript; charset=utf-8",
    )
}

async fn connector_mcp_handler(
    State(st): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    mcp_server::handle_mcp_http(&st.mcp_cfg, &method, &headers, &raw_body)
}
