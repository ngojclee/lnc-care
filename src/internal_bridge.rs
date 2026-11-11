//! Authenticated server-to-server LAN bridge, peer SSO tickets, and LNC Ads fallback client.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use regex::Regex;
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use crate::audit::canonical_ascii_json;
use crate::store;
use crate::transport::{build_url_with_params, SharedTransport, TransportRequest, UreqTransport};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_SKEW_SECONDS: i64 = 60;
pub const SSO_TTL_SECONDS: i64 = 60;

pub const DEFAULT_INTERNAL_HOSTS: &[&str] = &[
    "10.21.4.101",
    "lnc-care",
    "lnc-care-lnc-care-1",
    "lnm-ads",
    "lnc-ads",
    "lnm-ads-lnm-ads-1",
    "localhost",
    "127.0.0.1",
    "::1",
    "testserver",
];

#[derive(Debug, Clone)]
pub struct BridgeClientError {
    pub code: String,
    pub status: u16,
}

impl BridgeClientError {
    pub fn new(code: impl Into<String>, status: u16) -> Self {
        Self {
            code: code.into(),
            status,
        }
    }
}

impl std::fmt::Display for BridgeClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}

impl std::error::Error for BridgeClientError {}

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub secret: String,
    pub self_id: String,
    pub peers: HashMap<String, String>,
    pub ads_internal_url: String,
    pub internal_hosts: HashSet<String>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_urlsafe_token(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    rand::thread_rng().fill_bytes(&mut buf);
    B64_URL.encode(&buf)
}

fn bare_origin(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    let parsed = Url::parse(trimmed).map_err(|_| format!("Invalid peer origin URL: {value:?}"))?;
    let scheme = parsed.scheme();
    if (scheme != "http" && scheme != "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(format!("Invalid peer origin URL: {value:?}"));
    }
    let host = parsed.host_str().unwrap();
    let host_fmt = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let netloc = match parsed.port() {
        Some(p) => format!("{host_fmt}:{p}"),
        None => host_fmt,
    };
    Ok(format!("{scheme}://{netloc}"))
}

pub fn bridge_config(env: &HashMap<String, String>) -> Result<Option<BridgeConfig>, String> {
    let secret = env
        .get("LNC_INTERNAL_BRIDGE_SECRET")
        .map(|s| s.trim())
        .unwrap_or_default()
        .to_string();
    if secret.is_empty() {
        return Ok(None);
    }
    if secret.len() < 32 {
        return Err("LNC_INTERNAL_BRIDGE_SECRET must be at least 32 characters".to_string());
    }

    let raw_peers = env
        .get("LNC_INTERNAL_BRIDGE_PEERS")
        .map(|s| s.trim())
        .unwrap_or_default();
    let ads_public_default = env
        .get("LNC_ADS_PUBLIC_URL")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("https://ads-mcp.lengoc.me");
    let ads_internal_raw = env
        .get("LNC_ADS_INTERNAL_URL")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("http://10.21.4.101:8480");
    let ads_internal = bare_origin(ads_internal_raw)?;

    let peer_re = Regex::new(r"^[a-z][a-z0-9-]{1,31}$").unwrap();
    let mut peers = HashMap::new();
    if !raw_peers.is_empty() {
        for entry in raw_peers.split(',') {
            let item = entry.trim();
            if item.is_empty() {
                continue;
            }
            if let Some((pid_raw, purl_raw)) = item.split_once('=') {
                let pid = pid_raw.trim().to_ascii_lowercase();
                if !peer_re.is_match(&pid) {
                    return Err(format!("Invalid bridge peer id: {pid:?}"));
                }
                peers.insert(pid, bare_origin(purl_raw)?);
            } else {
                let pid = item.to_ascii_lowercase();
                if !peer_re.is_match(&pid) {
                    return Err(format!("Invalid bridge peer id: {pid:?}"));
                }
                let default_url = if pid == "lnc-ads" {
                    ads_public_default.to_string()
                } else {
                    format!("https://{pid}.lengoc.me")
                };
                peers.insert(pid, bare_origin(&default_url)?);
            }
        }
    } else {
        peers.insert("lnc-ads".to_string(), bare_origin(ads_public_default)?);
    }

    let mut internal_hosts: HashSet<String> = DEFAULT_INTERNAL_HOSTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if let Some(extra) = env.get("LNC_INTERNAL_BRIDGE_HOSTS") {
        for h in extra.split(',') {
            let clean = h.trim().to_ascii_lowercase();
            if !clean.is_empty() {
                internal_hosts.insert(clean);
            }
        }
    }

    let self_id = env
        .get("LNC_INTERNAL_BRIDGE_SELF_ID")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("lnc-care")
        .to_string();

    Ok(Some(BridgeConfig {
        secret,
        self_id,
        peers,
        ads_internal_url: ads_internal,
        internal_hosts,
    }))
}

pub fn canonical_payload(
    peer: &str,
    timestamp: &str,
    nonce: &str,
    method: &str,
    path_with_query: &str,
    body: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hex::encode(hasher.finalize());
    format!(
        "{peer}\n{timestamp}\n{nonce}\n{}\n{path_with_query}\n{body_hash}",
        method.to_ascii_uppercase()
    )
}

pub fn sign_request(
    secret: &str,
    peer: &str,
    timestamp: &str,
    nonce: &str,
    method: &str,
    path_with_query: &str,
    body: &[u8],
) -> String {
    let msg = canonical_payload(peer, timestamp, nonce, method, path_with_query, body);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn consume_nonce(db_path: &Path, org: &str, key: &str, expires_at: i64) -> bool {
    let now = now_unix();
    let Ok(db) = store::connect(db_path) else {
        return false;
    };
    if db.execute_batch("BEGIN IMMEDIATE;").is_err() {
        return false;
    }
    let _ = db.execute(
        "DELETE FROM bridge_nonces WHERE organization_id=?1 AND expires_at<=?2",
        params![org, now],
    );
    let inserted = db
        .execute(
            "INSERT INTO bridge_nonces(organization_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
            params![org, key, expires_at],
        )
        .is_ok();
    if inserted {
        let _ = db.execute_batch("COMMIT;");
        true
    } else {
        let _ = db.execute_batch("ROLLBACK;");
        false
    }
}

pub fn authenticate_headers(
    cfg: Option<&BridgeConfig>,
    method: &str,
    path_with_query: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    db_path: &Path,
    org: &str,
) -> Result<String, BridgeClientError> {
    let Some(cfg) = cfg else {
        return Err(BridgeClientError::new("internal_bridge_not_configured", 503));
    };
    let peer = headers
        .get("x-lnc-bridge-peer")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let ts_str = headers
        .get("x-lnc-bridge-timestamp")
        .map(|s| s.trim())
        .unwrap_or_default();
    let nonce = headers
        .get("x-lnc-bridge-nonce")
        .map(|s| s.trim())
        .unwrap_or_default();
    let sig = headers
        .get("x-lnc-bridge-signature")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    let nonce_re = Regex::new(r"^[A-Za-z0-9_-]{16,80}$").unwrap();
    if !cfg.peers.contains_key(&peer) || !nonce_re.is_match(nonce) || sig.len() != 64 {
        return Err(BridgeClientError::new("bridge_unauthorized", 401));
    }
    let ts: i64 = ts_str
        .parse()
        .map_err(|_| BridgeClientError::new("bridge_timestamp_invalid", 401))?;
    let now = now_unix();
    if (now - ts).abs() > MAX_SKEW_SECONDS {
        return Err(BridgeClientError::new("bridge_timestamp_expired", 401));
    }

    let expected = sign_request(
        &cfg.secret,
        &peer,
        ts_str,
        nonce,
        method,
        path_with_query,
        body,
    );
    if expected.as_bytes().ct_eq(sig.as_bytes()).unwrap_u8() != 1 {
        return Err(BridgeClientError::new("bridge_signature_invalid", 401));
    }

    if !consume_nonce(
        db_path,
        org,
        &format!("req:{peer}:{nonce}"),
        now + MAX_SKEW_SECONDS * 2,
    ) {
        return Err(BridgeClientError::new("bridge_nonce_replayed", 401));
    }
    Ok(peer)
}

pub fn mint_sso_ticket(
    cfg: Option<&BridgeConfig>,
    audience: &str,
    subject: &str,
    ttl: i64,
) -> Result<String, BridgeClientError> {
    let Some(cfg) = cfg else {
        return Err(BridgeClientError::new("internal_bridge_not_configured", 503));
    };
    if !cfg.peers.contains_key(audience) {
        return Err(BridgeClientError::new("bridge_peer_unknown", 404));
    }
    let now = now_unix();
    let payload = json!({
        "v": 1,
        "iss": cfg.self_id,
        "aud": audience,
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "jti": random_urlsafe_token(24),
    });
    let raw = canonical_ascii_json(&payload).into_bytes();
    let b64 = B64_URL.encode(&raw);
    let mut mac = HmacSha256::new_from_slice(cfg.secret.as_bytes()).expect("HMAC key");
    mac.update(b64.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    Ok(format!("{b64}.{sig}"))
}

pub fn consume_sso_ticket(
    cfg: Option<&BridgeConfig>,
    ticket: &str,
    db_path: &Path,
    org: &str,
) -> Result<Value, BridgeClientError> {
    let Some(cfg) = cfg else {
        return Err(BridgeClientError::new("internal_bridge_not_configured", 503));
    };
    if ticket.len() > 2048 {
        return Err(BridgeClientError::new("sso_ticket_invalid", 401));
    }
    let Some((b64, sig_raw)) = ticket.split_once('.') else {
        return Err(BridgeClientError::new("sso_ticket_invalid", 401));
    };
    let sig = sig_raw.to_ascii_lowercase();
    let mut mac = HmacSha256::new_from_slice(cfg.secret.as_bytes()).expect("HMAC key");
    mac.update(b64.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if expected.as_bytes().ct_eq(sig.as_bytes()).unwrap_u8() != 1 {
        return Err(BridgeClientError::new("sso_ticket_invalid", 401));
    }

    let raw_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim_end_matches('='))
        .map_err(|_| BridgeClientError::new("sso_ticket_invalid", 401))?;
    let payload: Value = serde_json::from_slice(&raw_bytes)
        .map_err(|_| BridgeClientError::new("sso_ticket_invalid", 401))?;

    let now = now_unix();
    let nonce_re = Regex::new(r"^[A-Za-z0-9_-]{16,80}$").unwrap();
    let v = payload.get("v").and_then(|x| x.as_i64());
    let aud = payload.get("aud").and_then(|x| x.as_str()).unwrap_or_default();
    let iss = payload.get("iss").and_then(|x| x.as_str()).unwrap_or_default();
    let jti = payload.get("jti").and_then(|x| x.as_str()).unwrap_or_default();
    let iat = payload.get("iat").and_then(|x| x.as_i64());
    let exp = payload.get("exp").and_then(|x| x.as_i64());

    let (Some(iat_val), Some(exp_val)) = (iat, exp) else {
        return Err(BridgeClientError::new("sso_ticket_expired_or_invalid", 401));
    };
    if v != Some(1)
        || aud != cfg.self_id
        || !cfg.peers.contains_key(iss)
        || !nonce_re.is_match(jti)
        || iat_val > now + 15
        || exp_val <= now
    {
        return Err(BridgeClientError::new("sso_ticket_expired_or_invalid", 401));
    }

    if !consume_nonce(db_path, org, &format!("sso:{jti}"), exp_val + 60) {
        return Err(BridgeClientError::new("sso_ticket_replayed", 401));
    }
    Ok(payload)
}

pub fn safe_relative_next(next_path: Option<&str>, default: &str) -> String {
    let val = next_path.unwrap_or_default().trim();
    if val.is_empty()
        || !val.starts_with('/')
        || val.starts_with("//")
        || val.contains('\\')
        || val.contains('\r')
        || val.contains('\n')
        || val.contains("://")
    {
        return default.to_string();
    }
    val.to_string()
}

#[derive(Clone)]
pub struct AdsBridgeClient {
    pub cfg: BridgeConfig,
    transport: SharedTransport,
}

impl AdsBridgeClient {
    pub fn new(cfg: BridgeConfig, transport: Option<SharedTransport>) -> Self {
        Self {
            cfg,
            transport: transport.unwrap_or_else(UreqTransport::shared),
        }
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        params: &[(&str, String)],
        json_body: Option<&Value>,
        timeout_ms: u64,
    ) -> Result<Value, BridgeClientError> {
        let path_with_query = build_url_with_params(path, params);
        let body_bytes = match json_body {
            Some(v) => Some(serde_json::to_vec(v).unwrap_or_default()),
            None => None,
        };
        let raw_slice = body_bytes.as_deref().unwrap_or(b"");
        let ts = now_unix().to_string();
        let nonce = random_urlsafe_token(24);
        let sig = sign_request(
            &self.cfg.secret,
            &self.cfg.self_id,
            &ts,
            &nonce,
            method,
            &path_with_query,
            raw_slice,
        );
        let mut headers = vec![
            ("Accept".to_string(), "application/json".to_string()),
            ("X-LNC-Bridge-Peer".to_string(), self.cfg.self_id.clone()),
            ("X-LNC-Bridge-Timestamp".to_string(), ts),
            ("X-LNC-Bridge-Nonce".to_string(), nonce),
            ("X-LNC-Bridge-Signature".to_string(), sig),
        ];
        if json_body.is_some() {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }

        let url = format!("{}{path_with_query}", self.cfg.ads_internal_url);
        let res = self
            .transport
            .execute(TransportRequest {
                method: method.to_ascii_uppercase(),
                url,
                headers,
                body: body_bytes,
                timeout_ms,
            })
            .map_err(|_| BridgeClientError::new("ads_bridge_unreachable", 503))?;

        let data = res.json().unwrap_or_else(|_| json!({}));
        if res.status >= 400 {
            let detail = data
                .get("detail")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| format!("ads_bridge_http_{}", res.status));
            return Err(BridgeClientError::new(detail, res.status));
        }
        if data.is_object() {
            Ok(data)
        } else {
            Ok(json!({"data": data}))
        }
    }

    pub fn status(&self) -> Result<Value, BridgeClientError> {
        self.call("GET", "/api/internal/bridge/status", &[], None, 3_000)
    }

    pub fn list_shops(&self) -> Result<Vec<Value>, BridgeClientError> {
        let data = self.call("GET", "/api/internal/bridge/shops", &[], None, 6_000)?;
        Ok(data
            .get("shops")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    pub fn ensure_shop(&self, name: &str) -> Result<Value, BridgeClientError> {
        self.call(
            "POST",
            "/api/internal/bridge/shops",
            &[],
            Some(&json!({"name": name})),
            6_000,
        )
    }

    pub fn list_connections(
        &self,
        shop: Option<&str>,
        provider: Option<&str>,
    ) -> Result<Vec<Value>, BridgeClientError> {
        let mut p = Vec::new();
        if let Some(s) = shop {
            p.push(("shop", s.to_string()));
        }
        if let Some(pr) = provider {
            p.push(("provider", pr.to_string()));
        }
        let data = self.call("GET", "/api/internal/bridge/connections", &p, None, 6_000)?;
        Ok(data
            .get("connections")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    pub fn list_channels(
        &self,
        shop: &str,
        provider: Option<&str>,
    ) -> Result<Value, BridgeClientError> {
        let mut p = vec![("shop", shop.to_string())];
        if let Some(pr) = provider {
            p.push(("provider", pr.to_string()));
        }
        self.call("GET", "/api/internal/bridge/channels", &p, None, 10_000)
    }

    pub fn start_oauth(
        &self,
        provider: &str,
        shop: &str,
        label: &str,
        connection_id: Option<i64>,
        include_care_scopes: bool,
        extra_scopes: &str,
        return_to: &str,
    ) -> Result<Value, BridgeClientError> {
        let mut body = json!({
            "provider": provider,
            "shop": shop,
            "label": label,
            "include_care_scopes": include_care_scopes,
            "extra_scopes": extra_scopes,
            "return_to": return_to,
        });
        if let Some(cid) = connection_id {
            body["connection_id"] = json!(cid);
        }
        self.call(
            "POST",
            "/api/internal/bridge/oauth/start",
            &[],
            Some(&body),
            6_000,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn platform_call(
        &self,
        shop: &str,
        connection_id: i64,
        method: &str,
        path: &str,
        params: Option<Value>,
        body: Option<Value>,
        use_page_token: bool,
        page_id: &str,
    ) -> Result<Value, BridgeClientError> {
        let req_body = json!({
            "shop": shop,
            "connection_id": connection_id,
            "method": method.to_ascii_uppercase(),
            "path": path,
            "params": params,
            "body": body,
            "use_page_token": use_page_token,
            "page_id": page_id,
        });
        self.call(
            "POST",
            "/api/internal/bridge/platform-call",
            &[],
            Some(&req_body),
            10_000,
        )
    }

    pub fn verify_meta_signature(
        &self,
        raw_body: &[u8],
        signature_header: &str,
    ) -> Result<Value, BridgeClientError> {
        let req_body = json!({
            "raw_body_b64": B64_STD.encode(raw_body),
            "signature_header": signature_header,
        });
        self.call(
            "POST",
            "/api/internal/bridge/meta/verify-signature",
            &[],
            Some(&req_body),
            3_500,
        )
    }
}
