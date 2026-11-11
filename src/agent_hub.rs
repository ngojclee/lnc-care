//! LNC Agent Hub shared Platform Vault, encrypted local lease cache (TTL=900s), Universal SSO, and LAN bridge fallback.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::params;
use serde_json::{json, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use url::Url;

use crate::internal_bridge::AdsBridgeClient;
use crate::store::{self, query_maps, query_one_map};
use crate::transport::{build_url_with_params, SharedTransport, TransportRequest, TransportResponse, UreqTransport};
use crate::vault::Vault;
use crate::audit;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_LEASE_TTL_SECONDS: i64 = 900;
pub const STATUS_CACHE_TTL_SECONDS: u64 = 30;
pub const CARE_PROVIDERS: &[&str] = &["meta", "tiktok", "youtube"];

#[derive(Debug, Clone)]
pub struct AgentHubError {
    pub code: String,
    pub status: u16,
}

impl AgentHubError {
    pub fn new(code: impl Into<String>, status: u16) -> Self {
        Self {
            code: code.into(),
            status,
        }
    }
}

impl std::fmt::Display for AgentHubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}

impl std::error::Error for AgentHubError {}

#[derive(Debug, Clone)]
pub struct AgentHubConfig {
    pub url: String,
    pub public_url: String,
    pub api_key: String,
    pub self_id: String,
    pub lease_ttl_seconds: i64,
}

impl AgentHubConfig {
    pub fn new(url: &str, public_url: &str, api_key: &str, self_id: &str) -> Self {
        let pub_eff = if public_url.is_empty() {
            url.to_string()
        } else {
            public_url.to_string()
        };
        Self {
            url: url.to_string(),
            public_url: pub_eff,
            api_key: api_key.to_string(),
            self_id: if self_id.is_empty() {
                "lnc-care".to_string()
            } else {
                self_id.to_string()
            },
            lease_ttl_seconds: DEFAULT_LEASE_TTL_SECONDS,
        }
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

fn bare_origin(value: &str, env_name: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let parsed = Url::parse(trimmed).map_err(|_| format!("{env_name} must be a bare HTTP(S) origin"))?;
    let scheme = parsed.scheme();
    if (scheme != "http" && scheme != "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (parsed.path() != "" && parsed.path() != "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(format!("{env_name} must be a bare HTTP(S) origin"));
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

pub fn agent_hub_config(env: &HashMap<String, String>) -> Result<Option<AgentHubConfig>, String> {
    let url = bare_origin(
        env.get("LNC_AGENT_HUB_URL").map(|s| s.as_str()).unwrap_or(""),
        "LNC_AGENT_HUB_URL",
    )?;
    let public_url = bare_origin(
        env.get("LNC_AGENT_HUB_PUBLIC_URL")
            .map(|s| s.as_str())
            .unwrap_or(""),
        "LNC_AGENT_HUB_PUBLIC_URL",
    )?;
    let api_key = env
        .get("LNC_AGENT_HUB_API_KEY")
        .map(|s| s.trim())
        .unwrap_or_default()
        .to_string();
    if url.is_empty() && api_key.is_empty() {
        return Ok(None);
    }
    if !api_key.is_empty() && url.is_empty() {
        return Err("LNC_AGENT_HUB_URL is required when LNC_AGENT_HUB_API_KEY is set".to_string());
    }
    let self_id = env
        .get("LNC_INTERNAL_BRIDGE_SELF_ID")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("lnc-care");
    Ok(Some(AgentHubConfig::new(&url, &public_url, &api_key, self_id)))
}

struct HubMutableState {
    cached_status: Option<(Value, Instant)>,
    last_sync_at: Option<i64>,
    last_sync_source: Option<String>,
    last_warning: Option<String>,
}

#[derive(Clone)]
pub struct AgentHubClient {
    pub cfg: AgentHubConfig,
    pub ads_bridge: Option<AdsBridgeClient>,
    transport: SharedTransport,
    state: Arc<Mutex<HubMutableState>>,
}

impl AgentHubClient {
    pub fn new(
        cfg: AgentHubConfig,
        ads_bridge: Option<AdsBridgeClient>,
        transport: Option<SharedTransport>,
    ) -> Self {
        Self {
            cfg,
            ads_bridge,
            transport: transport.unwrap_or_else(UreqTransport::shared),
            state: Arc::new(Mutex::new(HubMutableState {
                cached_status: None,
                last_sync_at: None,
                last_sync_source: None,
                last_warning: None,
            })),
        }
    }

    fn set_warning(&self, warning: Option<String>) {
        if let Ok(mut st) = self.state.lock() {
            st.last_warning = warning;
        }
    }

    fn invalidate_status_cache(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.cached_status = None;
        }
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        params: &[(&str, String)],
        json_body: Option<&Value>,
        auth: bool,
        timeout_ms: u64,
    ) -> Result<TransportResponse, String> {
        if self.cfg.url.is_empty() {
            return Err("hub_url_empty".to_string());
        }
        let base = format!("{}{path}", self.cfg.url);
        let url = build_url_with_params(&base, params);
        let mut headers = vec![
            ("Accept".to_string(), "application/json".to_string()),
            ("X-Request-Id".to_string(), format!("req_{}", random_hex(13))),
        ];
        if auth && !self.cfg.api_key.is_empty() {
            headers.push((
                "Authorization".to_string(),
                format!("Bearer {}", self.cfg.api_key),
            ));
        }
        let body = json_body.map(|v| {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
            serde_json::to_vec(v).unwrap_or_default()
        });
        self.transport.execute(TransportRequest {
            method: method.to_ascii_uppercase(),
            url,
            headers,
            body,
            timeout_ms,
        })
    }

    pub fn status_summary(&self, force: bool) -> Value {
        if !force {
            if let Ok(st) = self.state.lock() {
                if let Some((ref cached, at)) = st.cached_status {
                    if at.elapsed() < Duration::from_secs(STATUS_CACHE_TTL_SECONDS) {
                        return cached.clone();
                    }
                }
            }
        }

        let mut reachable = false;
        let mut platform_ready = false;
        let mut principal_key = Value::Null;
        let mut hub_version = Value::Null;
        let mut mode: String;

        if !self.cfg.url.is_empty() {
            if !self.cfg.api_key.is_empty() {
                match self.request("GET", "/v1/platform/status", &[], None, true, 2_500) {
                    Ok(res) if res.status == 200 => {
                        let data = res.json().unwrap_or_else(|_| json!({}));
                        reachable = true;
                        platform_ready = data.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
                        principal_key = data.get("principal_key").cloned().unwrap_or(Value::Null);
                        hub_version = data.get("version").cloned().unwrap_or(Value::Null);
                        mode = "vault_synced".to_string();
                    }
                    Ok(res) if res.status == 404 => {
                        reachable = self
                            .request("GET", "/health", &[], None, false, 2_000)
                            .map(|h| h.status == 200)
                            .unwrap_or(false);
                        mode = if reachable {
                            "awaiting_hub_upgrade".to_string()
                        } else {
                            "local_cache_fallback".to_string()
                        };
                    }
                    Ok(res) if res.status == 401 || res.status == 403 => {
                        reachable = true;
                        mode = "auth_error".to_string();
                    }
                    Ok(_) => {
                        mode = "local_cache_fallback".to_string();
                    }
                    Err(_) => {
                        reachable = false;
                        mode = "local_cache_fallback".to_string();
                    }
                }
            } else {
                reachable = self
                    .request("GET", "/health", &[], None, false, 2_000)
                    .map(|h| h.status == 200)
                    .unwrap_or(false);
                mode = if reachable {
                    "awaiting_api_key".to_string()
                } else {
                    "local_cache_fallback".to_string()
                };
            }
        } else {
            mode = "local_cache_fallback".to_string();
        }

        let mut bridge_ready = false;
        if !platform_ready {
            if let Some(ref bridge) = self.ads_bridge {
                if let Ok(bst) = bridge.status() {
                    bridge_ready = bst.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if bridge_ready
                        && matches!(
                            mode.as_str(),
                            "awaiting_hub_upgrade" | "awaiting_api_key" | "local_cache_fallback"
                        )
                    {
                        mode = "ads_bridge_fallback".to_string();
                    }
                }
            }
        }

        let public_origin = if !self.cfg.public_url.is_empty() {
            &self.cfg.public_url
        } else {
            &self.cfg.url
        };
        let sso_path = if !self.cfg.api_key.is_empty() && platform_ready && !public_origin.is_empty()
        {
            Value::String("/api/auth/sso/redirect?peer=lnc-agent-hub".to_string())
        } else {
            Value::Null
        };

        let (last_sync_at, last_sync_source, last_warning) = match self.state.lock() {
            Ok(st) => (
                st.last_sync_at.map(Value::from).unwrap_or(Value::Null),
                st.last_sync_source
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                st.last_warning
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            Err(_) => (Value::Null, Value::Null, Value::Null),
        };

        let summary = json!({
            "configured": true,
            "has_api_key": !self.cfg.api_key.is_empty(),
            "url": self.cfg.url,
            "public_url": public_origin,
            "reachable": reachable,
            "platform_api_ready": platform_ready,
            "bridge_fallback_ready": bridge_ready,
            "mode": mode,
            "principal_key": principal_key,
            "hub_version": hub_version,
            "sso_path": sso_path,
            "last_sync_at": last_sync_at,
            "last_sync_source": last_sync_source,
            "last_warning": last_warning,
        });

        if let Ok(mut st) = self.state.lock() {
            st.cached_status = Some((summary.clone(), Instant::now()));
        }
        summary
    }

    pub fn try_push_shop(&self, name: &str) -> bool {
        if !self.cfg.api_key.is_empty() {
            match self.request(
                "POST",
                "/v1/platform/shops",
                &[],
                Some(&json!({"name": name, "metadata": {}})),
                true,
                4_000,
            ) {
                Ok(res) if res.status == 200 || res.status == 201 => return true,
                Ok(res) if res.status != 404 => {
                    self.set_warning(Some(format!("shop_push_http_{}", res.status)));
                }
                Ok(_) => {}
                Err(_) => {
                    self.set_warning(Some("hub_unreachable_cached_locally".to_string()));
                }
            }
        }
        if let Some(ref bridge) = self.ads_bridge {
            if bridge.ensure_shop(name).is_ok() {
                return true;
            }
        }
        false
    }

    pub fn try_push_app(&self, db_path: &Path, org: &str, provider: &str, vault: &Vault) -> bool {
        if self.cfg.api_key.is_empty() || !CARE_PROVIDERS.contains(&provider) {
            return false;
        }
        let Ok(db) = store::connect_readonly(db_path) else {
            return false;
        };
        let row = query_one_map(
            &db,
            "SELECT * FROM provider_apps WHERE organization_id=? AND provider=?",
            &[org.to_string().into(), provider.to_string().into()],
        );
        let Some(row) = row else {
            return false;
        };
        let Ok(Some(secret)) = vault.get(&db, org, "app", provider) else {
            return false;
        };
        let client_secret = secret
            .get("client_secret")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if client_secret.is_empty() {
            return false;
        }
        let body = json!({
            "client_id": row.get("client_id").and_then(|v| v.as_str()).unwrap_or_default(),
            "client_secret": client_secret,
            "project_id": row.get("project_id").and_then(|v| v.as_str()).unwrap_or_default(),
            "webhook_verify_token": row.get("webhook_verify_token").and_then(|v| v.as_str()).unwrap_or_default(),
            "source_app": self.cfg.self_id,
        });
        match self.request(
            "PUT",
            &format!("/v1/platform/apps/{provider}"),
            &[],
            Some(&body),
            true,
            4_000,
        ) {
            Ok(res) if res.status == 200 || res.status == 201 => true,
            Ok(res) => {
                self.set_warning(Some(format!("app_push_http_{}", res.status)));
                false
            }
            Err(_) => {
                self.set_warning(Some("hub_unreachable_cached_locally".to_string()));
                false
            }
        }
    }

    pub fn try_push_connection(
        &self,
        db_path: &Path,
        org: &str,
        connection_id: i64,
        vault: &Vault,
    ) -> Option<String> {
        if self.cfg.api_key.is_empty() {
            return None;
        }
        let (conn, runtime, link_id, shop_names, token) = {
            let db = store::connect_readonly(db_path).ok()?;
            let conn = query_one_map(
                &db,
                "SELECT * FROM provider_connections WHERE organization_id=? AND id=?",
                &[org.to_string().into(), connection_id.into()],
            )?;
            let runtime = query_one_map(
                &db,
                "SELECT * FROM connection_runtime WHERE organization_id=? AND connection_id=?",
                &[org.to_string().into(), connection_id.into()],
            );
            let link = query_one_map(
                &db,
                "SELECT hub_connection_id FROM hub_connection_links WHERE organization_id=? AND connection_id=?",
                &[org.to_string().into(), connection_id.into()],
            );
            let link_id = link
                .and_then(|l| l.get("hub_connection_id").and_then(|v| v.as_str().map(String::from)));
            if link_id
                .as_deref()
                .map(|s| s.starts_with("ads_bridge:"))
                .unwrap_or(false)
            {
                return None;
            }
            let shop_rows = query_maps(
                &db,
                "SELECT DISTINCT s.name FROM shops s
                 WHERE s.organization_id=? AND (
                     EXISTS (SELECT 1 FROM shop_connection_bindings scb
                             WHERE scb.organization_id=s.organization_id AND scb.shop_id=s.id AND scb.connection_id=?)
                     OR EXISTS (SELECT 1 FROM channel_shop_bindings csb
                                JOIN channels ch ON ch.organization_id=csb.organization_id AND ch.id=csb.channel_id
                                WHERE csb.organization_id=s.organization_id AND csb.shop_id=s.id
                                AND ch.connection_id=? AND ch.approved=1)
                 ) ORDER BY s.name",
                &[
                    org.to_string().into(),
                    connection_id.into(),
                    connection_id.into(),
                ],
            );
            let shop_names: Vec<String> = shop_rows
                .into_iter()
                .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(String::from))
                .collect();
            let state_str = conn
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let token = if state_str == "verified" {
                vault
                    .get(&db, org, "connection", &connection_id.to_string())
                    .ok()
                    .flatten()
            } else {
                None
            };
            (conn, runtime, link_id, shop_names, token)
        };

        let expires_at = runtime
            .and_then(|r| r.get("expires_at").and_then(|v| v.as_i64()))
            .map(Value::from)
            .unwrap_or(Value::Null);
        let mut payload = json!({
            "provider": conn.get("provider").and_then(|v| v.as_str()).unwrap_or_default(),
            "label": conn.get("label").and_then(|v| v.as_str()).unwrap_or_default(),
            "state": conn.get("state").and_then(|v| v.as_str()).unwrap_or_default(),
            "expires_at": expires_at,
            "shops": shop_names,
            "source_app": self.cfg.self_id,
        });
        if let Some(hid) = link_id.filter(|s| !s.is_empty()) {
            payload["hub_connection_id"] = json!(hid);
        }
        if let Some(tok) = token {
            if tok.get("access_token").and_then(|v| v.as_str()).is_some() {
                payload["token"] = tok;
            }
        }

        match self.request(
            "POST",
            "/v1/platform/connections/upsert",
            &[],
            Some(&payload),
            true,
            4_000,
        ) {
            Ok(res) if res.status == 200 || res.status == 201 => {
                let data = res.json().unwrap_or_else(|_| json!({}));
                let hub_id = data
                    .get("hub_connection_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let hub_rev = data.get("revision").and_then(|v| v.as_i64()).unwrap_or(1);
                if !hub_id.is_empty() {
                    let now = now_unix();
                    if let Ok(db) = store::connect(db_path) {
                        let _ = db.execute_batch("BEGIN IMMEDIATE;");
                        let _ = db.execute(
                            "INSERT INTO hub_connection_links
                               (organization_id, connection_id, hub_connection_id, hub_revision, leased_at)
                             VALUES (?1, ?2, ?3, ?4, ?5)
                             ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                                hub_connection_id=excluded.hub_connection_id,
                                hub_revision=excluded.hub_revision,
                                leased_at=excluded.leased_at",
                            params![org, connection_id, hub_id, hub_rev, now],
                        );
                        let _ = db.execute_batch("COMMIT;");
                    }
                    return Some(hub_id);
                }
                None
            }
            Ok(res) => {
                self.set_warning(Some(format!("connection_push_http_{}", res.status)));
                None
            }
            Err(_) => {
                self.set_warning(Some("hub_unreachable_cached_locally".to_string()));
                None
            }
        }
    }

    pub fn ensure_fresh_token(
        &self,
        db_path: &Path,
        org: &str,
        vault: &Vault,
        connection_id: i64,
        force: bool,
    ) -> bool {
        if self.cfg.api_key.is_empty() {
            return false;
        }
        let now = now_unix();
        let (hub_id, prev_hub_rev, leased_at, provider, expires_at, has_local_token) = {
            let Ok(db) = store::connect_readonly(db_path) else {
                return false;
            };
            let Some(link) = query_one_map(
                &db,
                "SELECT hub_connection_id, hub_revision, leased_at
                 FROM hub_connection_links WHERE organization_id=? AND connection_id=?",
                &[org.to_string().into(), connection_id.into()],
            ) else {
                return false;
            };
            let hub_id = link
                .get("hub_connection_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if hub_id.is_empty() || hub_id.starts_with("ads_bridge:") {
                return false;
            }
            let prev_rev = link
                .get("hub_revision")
                .and_then(|v| v.as_i64())
                .unwrap_or(1);
            let leased_at = link.get("leased_at").and_then(|v| v.as_i64()).unwrap_or(0);
            let Some(conn) = query_one_map(
                &db,
                "SELECT provider, state FROM provider_connections WHERE organization_id=? AND id=?",
                &[org.to_string().into(), connection_id.into()],
            ) else {
                return false;
            };
            let provider = conn
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("meta")
                .to_string();
            let runtime = query_one_map(
                &db,
                "SELECT expires_at FROM connection_runtime WHERE organization_id=? AND connection_id=?",
                &[org.to_string().into(), connection_id.into()],
            );
            let expires_at = runtime.and_then(|r| r.get("expires_at").and_then(|v| v.as_i64()));
            let local_token = vault
                .get(&db, org, "connection", &connection_id.to_string())
                .ok()
                .flatten();
            (
                hub_id,
                prev_rev,
                leased_at,
                provider,
                expires_at,
                local_token.is_some(),
            )
        };

        let needs_lease = force
            || !has_local_token
            || expires_at.is_none()
            || expires_at.unwrap_or(0) <= now + 120
            || leased_at <= now - self.cfg.lease_ttl_seconds;
        if !needs_lease {
            return true;
        }

        let res = match self.request(
            "POST",
            &format!("/v1/platform/connections/{hub_id}/lease"),
            &[],
            Some(&json!({"purpose": "provider_api", "force_refresh": force})),
            true,
            4_000,
        ) {
            Ok(r) => r,
            Err(_) => {
                self.set_warning(Some("hub_unreachable_serving_local_cache".to_string()));
                return false;
            }
        };

        if res.status != 200 {
            self.set_warning(Some(format!("lease_http_{}", res.status)));
            return false;
        }
        let Ok(data) = res.json() else {
            return false;
        };
        let Some(token) = data.get("token").filter(|t| {
            t.is_object()
                && t.get("access_token")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
        }) else {
            return false;
        };
        let new_expires = data
            .get("expires_at")
            .and_then(|v| v.as_i64())
            .unwrap_or(now + 3600);
        let hub_rev = data
            .get("revision")
            .and_then(|v| v.as_i64())
            .unwrap_or(prev_hub_rev);

        let Ok(db) = store::connect(db_path) else {
            return false;
        };
        if db.execute_batch("BEGIN IMMEDIATE;").is_err() {
            return false;
        }
        let app_rev: i64 = db
            .query_row(
                "SELECT revision FROM provider_apps WHERE organization_id=?1 AND provider=?2",
                params![org, provider],
                |r| r.get(0),
            )
            .unwrap_or(1);

        if vault
            .put(&db, org, "connection", &connection_id.to_string(), token)
            .is_err()
        {
            let _ = db.execute_batch("ROLLBACK;");
            return false;
        }
        if let Some(ptoks) = data.get("page_tokens").and_then(|v| v.as_object()) {
            for (page_id, ptok_val) in ptoks {
                if let Some(ptok) = ptok_val.as_str().filter(|s| !s.is_empty()) {
                    let _ = vault.put(
                        &db,
                        org,
                        "channel_token",
                        &format!("{provider}:{page_id}"),
                        &json!({"access_token": ptok}),
                    );
                }
            }
        }
        let _ = db.execute(
            "INSERT INTO connection_runtime
               (organization_id, connection_id, revision, app_revision, expires_at, last_error)
             VALUES (?1, ?2, 1, ?3, ?4, NULL)
             ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                revision=revision+1,
                app_revision=excluded.app_revision,
                expires_at=excluded.expires_at,
                last_error=NULL",
            params![org, connection_id, app_rev, new_expires],
        );
        let _ = db.execute(
            "UPDATE provider_connections SET state='verified' WHERE organization_id=?1 AND id=?2",
            params![org, connection_id],
        );
        let _ = db.execute(
            "UPDATE hub_connection_links SET hub_revision=?1, leased_at=?2 WHERE organization_id=?3 AND connection_id=?4",
            params![hub_rev, now, org, connection_id],
        );
        let _ = db.execute_batch("COMMIT;");
        self.set_warning(None);
        true
    }

    pub fn start_shared_oauth(
        &self,
        provider: &str,
        shop: &str,
        label: &str,
        return_to: &str,
        extra_scopes: &str,
    ) -> Option<Value> {
        if !self.cfg.api_key.is_empty() {
            if let Ok(res) = self.request(
                "POST",
                "/v1/platform/oauth/start",
                &[],
                Some(&json!({
                    "provider": provider,
                    "shop": shop,
                    "label": label,
                    "include_care_scopes": true,
                    "extra_scopes": extra_scopes,
                    "return_to": return_to,
                    "caller_app": self.cfg.self_id,
                })),
                true,
                4_000,
            ) {
                if res.status == 200 {
                    if let Ok(mut data) = res.json() {
                        if let Some(obj) = data.as_object_mut() {
                            obj.insert("via".to_string(), json!("agent_hub"));
                            return Some(data);
                        }
                    }
                }
            }
        }
        if let Some(ref bridge) = self.ads_bridge {
            if matches!(provider, "meta" | "tiktok") {
                if let Ok(mut started) = bridge.start_oauth(
                    provider,
                    shop,
                    label,
                    None,
                    true,
                    extra_scopes,
                    return_to,
                ) {
                    if let Some(obj) = started.as_object_mut() {
                        obj.insert("via".to_string(), json!("ads_bridge_fallback"));
                        return Some(started);
                    }
                }
            }
        }
        None
    }

    pub fn verify_meta_webhook(
        &self,
        db_path: &Path,
        org: &str,
        vault: &Vault,
        raw_body: &[u8],
        signature_header: &str,
        env_secret: &str,
    ) -> bool {
        if !signature_header.starts_with("sha256=") {
            return false;
        }
        let local_secret = store::connect_readonly(db_path)
            .ok()
            .and_then(|db| vault.get(&db, org, "app", "meta").ok().flatten())
            .and_then(|v| v.get("client_secret").and_then(|s| s.as_str()).map(String::from))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| env_secret.to_string());

        if !local_secret.is_empty() {
            let mut mac = HmacSha256::new_from_slice(local_secret.as_bytes()).expect("HMAC key");
            mac.update(raw_body);
            let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
            return signature_header
                .as_bytes()
                .ct_eq(expected.as_bytes())
                .unwrap_u8()
                == 1;
        }

        if !self.cfg.api_key.is_empty() {
            if let Ok(res) = self.request(
                "POST",
                "/v1/platform/meta/verify-signature",
                &[],
                Some(&json!({
                    "raw_body_b64": B64_STD.encode(raw_body),
                    "signature_header": signature_header,
                })),
                true,
                3_000,
            ) {
                if res.status == 200 {
                    if let Ok(data) = res.json() {
                        return data.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
                    }
                }
            }
        }

        if let Some(ref bridge) = self.ads_bridge {
            if let Ok(res) = bridge.verify_meta_signature(raw_body, signature_header) {
                return res.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
            }
        }
        false
    }

    pub fn sync(&self, db_path: &Path, org: &str, vault: &Vault) -> Result<Value, AgentHubError> {
        let mut hub_status_code: Option<u16> = None;
        if !self.cfg.api_key.is_empty() {
            match self.request("GET", "/v1/platform/status", &[], None, true, 4_000) {
                Ok(st) => hub_status_code = Some(st.status),
                Err(_) => {
                    self.invalidate_status_cache();
                    if self.ads_bridge.is_some() {
                        return self.sync_via_ads_bridge(db_path, org, "hub_unreachable");
                    }
                    return Err(AgentHubError::new("agent_hub_unreachable", 503));
                }
            }
        }

        if hub_status_code == Some(200) {
            return self.sync_via_agent_hub(db_path, org, vault);
        }
        if matches!(hub_status_code, Some(401 | 403)) {
            self.invalidate_status_cache();
            return Err(AgentHubError::new("agent_hub_unauthorized", 403));
        }

        if self.ads_bridge.is_some() && matches!(hub_status_code, None | Some(404)) {
            let reason = if hub_status_code == Some(404) {
                "hub_platform_404"
            } else {
                "awaiting_hub_api_key"
            };
            return self.sync_via_ads_bridge(db_path, org, reason);
        }

        if self.cfg.api_key.is_empty() {
            return Err(AgentHubError::new("agent_hub_api_key_not_configured", 409));
        }
        if hub_status_code == Some(404) {
            self.invalidate_status_cache();
            return Err(AgentHubError::new(
                "agent_hub_platform_routes_not_deployed",
                503,
            ));
        }
        self.invalidate_status_cache();
        Err(AgentHubError::new("agent_hub_unavailable", 502))
    }

    fn sync_via_agent_hub(
        &self,
        db_path: &Path,
        org: &str,
        vault: &Vault,
    ) -> Result<Value, AgentHubError> {
        let mut pushed_shops = 0i64;
        let mut pushed_apps = 0i64;
        let mut pushed_connections = 0i64;
        let mut pulled_shops = 0i64;
        let mut pulled_apps = 0i64;
        let mut pulled_connections = 0i64;

        let (local_shops, local_apps, local_conns) = {
            let db = store::connect_readonly(db_path)
                .map_err(|e| AgentHubError::new(e.to_string(), 500))?;
            let ls: Vec<String> = store::shops(&db, org)
                .into_iter()
                .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(String::from))
                .collect();
            let la: Vec<String> = query_maps(
                &db,
                "SELECT provider FROM provider_apps WHERE organization_id=?",
                &[org.to_string().into()],
            )
            .into_iter()
            .filter_map(|r| r.get("provider").and_then(|v| v.as_str()).map(String::from))
            .collect();
            let lc: Vec<i64> = query_maps(
                &db,
                "SELECT id FROM provider_connections WHERE organization_id=? ORDER BY id",
                &[org.to_string().into()],
            )
            .into_iter()
            .filter_map(|r| r.get("id").and_then(|v| v.as_i64()))
            .collect();
            (ls, la, lc)
        };

        for sname in &local_shops {
            if self.try_push_shop(sname) {
                pushed_shops += 1;
            }
        }
        for prov in &local_apps {
            if self.try_push_app(db_path, org, prov, vault) {
                pushed_apps += 1;
            }
        }
        for cid in &local_conns {
            if self.try_push_connection(db_path, org, *cid, vault).is_some() {
                pushed_connections += 1;
            }
        }

        // Pull shops
        let r_shops = self
            .request("GET", "/v1/platform/shops", &[], None, true, 4_000)
            .map_err(|_| AgentHubError::new("agent_hub_sync_interrupted", 502))?;
        if r_shops.status == 200 {
            if let Ok(data) = r_shops.json() {
                if let Some(items) = data.get("shops").and_then(|v| v.as_array()) {
                    for item in items {
                        let rname = item
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .trim();
                        if rname.is_empty() {
                            continue;
                        }
                        if let Ok(db) = store::connect(db_path) {
                            let _ = db.execute_batch("BEGIN IMMEDIATE;");
                            let exists: bool = db
                                .query_row(
                                    "SELECT 1 FROM shops WHERE organization_id=?1 AND LOWER(name)=LOWER(?2)",
                                    params![org, rname],
                                    |_| Ok(true),
                                )
                                .unwrap_or(false);
                            if !exists
                                && db
                                    .execute(
                                        "INSERT INTO shops(organization_id, name) VALUES (?1, ?2)",
                                        params![org, rname],
                                    )
                                    .is_ok()
                            {
                                pulled_shops += 1;
                            }
                            let _ = db.execute_batch("COMMIT;");
                        }
                    }
                }
            }
        }

        // Pull OAuth apps
        let r_apps = self
            .request("GET", "/v1/platform/apps", &[], None, true, 4_000)
            .map_err(|_| AgentHubError::new("agent_hub_sync_interrupted", 502))?;
        if r_apps.status == 200 {
            if let Ok(data) = r_apps.json() {
                if let Some(apps_map) = data.get("apps").and_then(|v| v.as_object()) {
                    for (prov, meta) in apps_map {
                        if !CARE_PROVIDERS.contains(&prov.as_str())
                            || !meta
                                .get("configured")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                        {
                            continue;
                        }
                        let already_has = store::connect_readonly(db_path)
                            .ok()
                            .map(|db| {
                                let has_row = query_one_map(
                                    &db,
                                    "SELECT revision FROM provider_apps WHERE organization_id=? AND provider=?",
                                    &[org.to_string().into(), prov.clone().into()],
                                )
                                .is_some();
                                let has_sec = vault
                                    .get(&db, org, "app", prov)
                                    .ok()
                                    .flatten()
                                    .and_then(|s| s.get("client_secret").and_then(|v| v.as_str()).map(|x| !x.is_empty()))
                                    .unwrap_or(false);
                                has_row && has_sec
                            })
                            .unwrap_or(false);
                        if already_has {
                            continue;
                        }
                        let cred_res = self
                            .request(
                                "GET",
                                &format!("/v1/platform/apps/{prov}/credentials"),
                                &[],
                                None,
                                true,
                                4_000,
                            )
                            .map_err(|_| AgentHubError::new("agent_hub_sync_interrupted", 502))?;
                        if cred_res.status != 200 {
                            continue;
                        }
                        let Ok(cred) = cred_res.json() else {
                            continue;
                        };
                        let cid_str = cred
                            .get("client_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let csec_str = cred
                            .get("client_secret")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        if cid_str.is_empty() || csec_str.is_empty() {
                            continue;
                        }
                        let rev = cred.get("revision").and_then(|v| v.as_i64()).unwrap_or(1);
                        let proj = cred
                            .get("project_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let wvt = cred
                            .get("webhook_verify_token")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        if let Ok(db) = store::connect(db_path) {
                            let _ = db.execute_batch("BEGIN IMMEDIATE;");
                            let _ = db.execute(
                                "INSERT INTO provider_apps
                                   (organization_id, provider, client_id, project_id, webhook_verify_token, revision)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                                 ON CONFLICT(organization_id, provider) DO UPDATE SET
                                    client_id=excluded.client_id,
                                    project_id=excluded.project_id,
                                    webhook_verify_token=CASE
                                      WHEN excluded.webhook_verify_token!='' THEN excluded.webhook_verify_token
                                      ELSE provider_apps.webhook_verify_token
                                    END,
                                    revision=excluded.revision",
                                params![org, prov, cid_str, proj, wvt, rev],
                            );
                            let _ = vault.put(
                                &db,
                                org,
                                "app",
                                prov,
                                &json!({"client_secret": csec_str}),
                            );
                            let _ = db.execute_batch("COMMIT;");
                            pulled_apps += 1;
                        }
                    }
                }
            }
        }

        // Pull connections & lease verified tokens
        let r_conns = self
            .request("GET", "/v1/platform/connections", &[], None, true, 5_000)
            .map_err(|_| AgentHubError::new("agent_hub_sync_interrupted", 502))?;
        if r_conns.status == 200 {
            if let Ok(data) = r_conns.json() {
                if let Some(conns) = data.get("connections").and_then(|v| v.as_array()) {
                    for rc in conns {
                        let hub_id = rc
                            .get("hub_connection_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .trim();
                        let prov = rc
                            .get("provider")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .trim();
                        let label = rc
                            .get("label")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .trim();
                        let mut state = rc
                            .get("state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("pending_review")
                            .trim();
                        if hub_id.is_empty() || !CARE_PROVIDERS.contains(&prov) || label.is_empty()
                        {
                            continue;
                        }
                        if !matches!(
                            state,
                            "not_connected" | "pending_review" | "verified" | "expired"
                        ) {
                            state = "pending_review";
                        }
                        let hub_rev = rc.get("revision").and_then(|v| v.as_i64()).unwrap_or(1);

                        let mut local_id = 0i64;
                        let mut is_new = false;
                        if let Ok(db) = store::connect(db_path) {
                            let _ = db.execute_batch("BEGIN IMMEDIATE;");
                            let link_cid: Option<i64> = db
                                .query_row(
                                    "SELECT connection_id FROM hub_connection_links WHERE organization_id=?1 AND hub_connection_id=?2",
                                    params![org, hub_id],
                                    |r| r.get(0),
                                )
                                .ok();
                            if let Some(cid) = link_cid {
                                local_id = cid;
                            } else {
                                let by_label: Option<i64> = db
                                    .query_row(
                                        "SELECT id FROM provider_connections
                                         WHERE organization_id=?1 AND provider=?2 AND LOWER(label)=LOWER(?3)
                                         ORDER BY id LIMIT 1",
                                        params![org, prov, label],
                                        |r| r.get(0),
                                    )
                                    .ok();
                                if let Some(cid) = by_label {
                                    local_id = cid;
                                } else {
                                    let init_state = if state == "verified" {
                                        "pending_review"
                                    } else {
                                        state
                                    };
                                    let _ = db.execute(
                                        "INSERT INTO provider_connections(organization_id, provider, label, state)
                                         VALUES (?1, ?2, ?3, ?4)",
                                        params![org, prov, label, init_state],
                                    );
                                    local_id = db.last_insert_rowid();
                                    let _ = db.execute(
                                        "INSERT OR IGNORE INTO connection_runtime
                                           (organization_id, connection_id, revision, app_revision)
                                         VALUES (?1, ?2, 1, 1)",
                                        params![org, local_id],
                                    );
                                    is_new = true;
                                }
                                let _ = db.execute(
                                    "INSERT INTO hub_connection_links
                                       (organization_id, connection_id, hub_connection_id, hub_revision, leased_at)
                                     VALUES (?1, ?2, ?3, ?4, 0)
                                     ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                                        hub_connection_id=excluded.hub_connection_id",
                                    params![org, local_id, hub_id, hub_rev],
                                );
                            }

                            if let Some(shops_arr) = rc.get("shops").and_then(|v| v.as_array()) {
                                for s_val in shops_arr {
                                    let sname = s_val.as_str().unwrap_or_default().trim();
                                    if let Ok(sid) = db.query_row::<i64, _, _>(
                                        "SELECT id FROM shops WHERE organization_id=?1 AND LOWER(name)=LOWER(?2)",
                                        params![org, sname],
                                        |r| r.get(0),
                                    ) {
                                        let _ = db.execute(
                                            "INSERT OR IGNORE INTO shop_connection_bindings VALUES (?1, ?2, ?3)",
                                            params![org, sid, local_id],
                                        );
                                    }
                                }
                            }
                            let _ = db.execute_batch("COMMIT;");
                        }

                        if local_id > 0 {
                            if state == "verified" {
                                let leased =
                                    self.ensure_fresh_token(db_path, org, vault, local_id, is_new);
                                if leased && is_new {
                                    pulled_connections += 1;
                                }
                            } else if is_new {
                                pulled_connections += 1;
                            }
                        }
                    }
                }
            }
        }

        let synced_at = now_unix();
        if let Ok(mut st) = self.state.lock() {
            st.last_sync_at = Some(synced_at);
            st.last_sync_source = Some("lnc-agent-hub".to_string());
            st.last_warning = None;
            st.cached_status = None;
        }

        let summary = json!({
            "ok": true,
            "source": "lnc-agent-hub",
            "pushed_shops": pushed_shops,
            "pushed_apps": pushed_apps,
            "pushed_connections": pushed_connections,
            "pulled_shops": pulled_shops,
            "pulled_apps": pulled_apps,
            "pulled_connections": pulled_connections,
            "pulled_channels": 0,
            "synced_at": synced_at,
        });
        if let Ok(db) = store::connect(db_path) {
            let _ = db.execute_batch("BEGIN IMMEDIATE;");
            let _ = audit::append(&db, org, "owner", "hub.vault_synced", "lnc-agent-hub", &summary);
            let _ = db.execute_batch("COMMIT;");
        }
        Ok(summary)
    }

    fn sync_via_ads_bridge(
        &self,
        db_path: &Path,
        org: &str,
        reason: &str,
    ) -> Result<Value, AgentHubError> {
        let Some(ref bridge) = self.ads_bridge else {
            return Err(AgentHubError::new("internal_bridge_not_configured", 503));
        };
        let remote_shops = bridge
            .list_shops()
            .map_err(|e| AgentHubError::new(e.code, e.status))?;
        let remote_conns = bridge
            .list_connections(None, None)
            .map_err(|e| AgentHubError::new(e.code, e.status))?;

        let mut pushed_shops = 0i64;
        let mut pulled_shops = 0i64;
        let mut pulled_connections = 0i64;
        let mut pulled_channels = 0i64;
        let now = now_unix();
        let today = Utc::now().format("%Y-%m-%d").to_string();

        let remote_shop_names: std::collections::HashSet<String> = remote_shops
            .iter()
            .filter_map(|s| s.get("name").and_then(|v| v.as_str()))
            .map(|s| s.trim().to_lowercase())
            .collect();

        let local_shops: Vec<String> = store::connect_readonly(db_path)
            .map(|db| {
                store::shops(&db, org)
                    .into_iter()
                    .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        for sname in &local_shops {
            if !remote_shop_names.contains(&sname.to_lowercase()) && bridge.ensure_shop(sname).is_ok()
            {
                pushed_shops += 1;
            }
        }

        let mut shop_map: HashMap<String, i64> = HashMap::new();
        if let Ok(db) = store::connect(db_path) {
            let _ = db.execute_batch("BEGIN IMMEDIATE;");
            for item in &remote_shops {
                let rname = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .trim();
                if rname.is_empty() {
                    continue;
                }
                if let Ok(id) = db.query_row::<i64, _, _>(
                    "SELECT id FROM shops WHERE organization_id=?1 AND LOWER(name)=LOWER(?2)",
                    params![org, rname],
                    |r| r.get(0),
                ) {
                    shop_map.insert(rname.to_string(), id);
                } else if db
                    .execute(
                        "INSERT INTO shops(organization_id, name) VALUES (?1, ?2)",
                        params![org, rname],
                    )
                    .is_ok()
                {
                    shop_map.insert(rname.to_string(), db.last_insert_rowid());
                    pulled_shops += 1;
                }
            }
            for r in store::shops(&db, org) {
                if let (Some(n), Some(id)) = (
                    r.get("name").and_then(|v| v.as_str()),
                    r.get("id").and_then(|v| v.as_i64()),
                ) {
                    shop_map.insert(n.to_string(), id);
                }
            }
            let _ = db.execute_batch("COMMIT;");
        }

        let mut conn_id_map: HashMap<i64, i64> = HashMap::new();
        if let Ok(db) = store::connect(db_path) {
            let _ = db.execute_batch("BEGIN IMMEDIATE;");
            for rc in &remote_conns {
                let prov = rc
                    .get("provider")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .trim();
                if !CARE_PROVIDERS.contains(&prov) {
                    continue;
                }
                let Some(remote_cid) = rc.get("id").and_then(|v| v.as_i64()) else {
                    continue;
                };
                let bridge_key = format!("ads_bridge:{remote_cid}");
                let fallback_lbl = format!("{prov}-{remote_cid}");
                let label = rc
                    .get("label")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(&fallback_lbl)
                    .trim();
                let mut state = rc
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("verified")
                    .trim();
                if !matches!(
                    state,
                    "not_connected" | "pending_review" | "verified" | "expired"
                ) {
                    state = "pending_review";
                }

                let local_cid: i64 = if let Ok(cid) = db.query_row::<i64, _, _>(
                    "SELECT connection_id FROM hub_connection_links WHERE organization_id=?1 AND hub_connection_id=?2",
                    params![org, bridge_key],
                    |r| r.get(0),
                ) {
                    let _ = db.execute(
                        "UPDATE provider_connections SET state=?1, label=?2 WHERE organization_id=?3 AND id=?4",
                        params![state, label, org, cid],
                    );
                    cid
                } else {
                    let cid = if let Ok(existing_cid) = db.query_row::<i64, _, _>(
                        "SELECT id FROM provider_connections
                         WHERE organization_id=?1 AND provider=?2 AND LOWER(label)=LOWER(?3)
                         ORDER BY id LIMIT 1",
                        params![org, prov, label],
                        |r| r.get(0),
                    ) {
                        let _ = db.execute(
                            "UPDATE provider_connections SET state=?1 WHERE organization_id=?2 AND id=?3",
                            params![state, org, existing_cid],
                        );
                        existing_cid
                    } else {
                        let _ = db.execute(
                            "INSERT INTO provider_connections(organization_id, provider, label, state)
                             VALUES (?1, ?2, ?3, ?4)",
                            params![org, prov, label, state],
                        );
                        pulled_connections += 1;
                        db.last_insert_rowid()
                    };
                    let _ = db.execute(
                        "INSERT INTO hub_connection_links
                           (organization_id, connection_id, hub_connection_id, hub_revision, leased_at)
                         VALUES (?1, ?2, ?3, 1, ?4)
                         ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                            hub_connection_id=excluded.hub_connection_id,
                            leased_at=excluded.leased_at",
                        params![org, cid, bridge_key, now],
                    );
                    cid
                };

                let exp_at = rc.get("expires_at").and_then(|v| v.as_i64());
                let _ = db.execute(
                    "INSERT INTO connection_runtime
                       (organization_id, connection_id, revision, app_revision, expires_at, last_success)
                     VALUES (?1, ?2, 1, 1, ?3, ?4)
                     ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                        expires_at=COALESCE(excluded.expires_at, connection_runtime.expires_at),
                        last_success=excluded.last_success",
                    params![org, local_cid, exp_at, now],
                );
                conn_id_map.insert(remote_cid, local_cid);

                if let Some(shops_arr) = rc.get("shops").and_then(|v| v.as_array()) {
                    for s_item in shops_arr {
                        let sname = s_item
                            .get("name")
                            .and_then(|v| v.as_str())
                            .or_else(|| s_item.as_str())
                            .unwrap_or_default()
                            .trim();
                        for (k_name, sid) in &shop_map {
                            if k_name.eq_ignore_ascii_case(sname) {
                                let _ = db.execute(
                                    "INSERT OR IGNORE INTO shop_connection_bindings VALUES (?1, ?2, ?3)",
                                    params![org, sid, local_cid],
                                );
                            }
                        }
                    }
                }
            }
            let _ = db.execute_batch("COMMIT;");
        }

        // Discover & bind shared channels per shop
        let shop_entries: Vec<(String, i64)> =
            shop_map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        for (shop_name, local_shop_id) in shop_entries {
            let Ok(ch_resp) = bridge.list_channels(&shop_name, None) else {
                continue;
            };
            let Some(remote_channels) = ch_resp.get("channels").and_then(|v| v.as_array()) else {
                continue;
            };
            if remote_channels.is_empty() {
                continue;
            }
            if let Ok(db) = store::connect(db_path) {
                let _ = db.execute_batch("BEGIN IMMEDIATE;");
                for ch in remote_channels {
                    let prov = ch
                        .get("provider")
                        .and_then(|v| v.as_str())
                        .unwrap_or("meta")
                        .trim();
                    if !CARE_PROVIDERS.contains(&prov) {
                        continue;
                    }
                    let raw_kind = ch
                        .get("kind")
                        .or_else(|| ch.get("channel_type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("fb_page")
                        .trim();
                    let kind = match raw_kind {
                        "facebook_page" | "page" | "fb_page" => "fb_page",
                        "instagram_business" | "instagram" | "ig_account" => "ig_account",
                        "tiktok_identity" | "tiktok" | "tt_account" => "tt_account",
                        _ => {
                            if prov == "meta" {
                                "fb_page"
                            } else {
                                "tt_account"
                            }
                        }
                    };
                    let ext_id = ch
                        .get("external_id")
                        .or_else(|| ch.get("channel_id"))
                        .or_else(|| ch.get("page_id"))
                        .or_else(|| ch.get("ig_id"))
                        .or_else(|| ch.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .trim();
                    let name = ch
                        .get("name")
                        .or_else(|| ch.get("username"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(ext_id)
                        .trim();
                    if ext_id.is_empty() || name.is_empty() {
                        continue;
                    }
                    let username = ch
                        .get("username")
                        .or_else(|| ch.get("handle"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .trim();
                    let handle = if username.is_empty() {
                        String::new()
                    } else {
                        format!("@{}", username.trim_start_matches('@'))
                    };
                    let local_cid = ch
                        .get("connection_id")
                        .and_then(|v| v.as_i64())
                        .and_then(|rcid| conn_id_map.get(&rcid).copied());
                    let adapter = if prov == "meta" {
                        "meta_api"
                    } else {
                        "browser_ingest"
                    };
                    let followers = ch
                        .get("followers_count")
                        .or_else(|| ch.get("fan_count"))
                        .or_else(|| ch.get("followers"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);

                    let channel_id: i64 = if let Ok(existing_id) = db.query_row::<i64, _, _>(
                        "SELECT id FROM channels WHERE organization_id=?1 AND provider=?2 AND external_id=?3",
                        params![org, prov, ext_id],
                        |r| r.get(0),
                    ) {
                        let _ = db.execute(
                            "UPDATE channels
                             SET connection_id=COALESCE(?1, connection_id),
                                 name=?2,
                                 handle=CASE WHEN ?3!='' THEN ?3 ELSE handle END,
                                 approved=1,
                                 last_synced_at=?4
                             WHERE organization_id=?5 AND id=?6",
                            params![local_cid, name, handle, now, org, existing_id],
                        );
                        existing_id
                    } else {
                        let _ = db.execute(
                            "INSERT INTO channels
                               (organization_id, connection_id, provider, adapter, kind, external_id,
                                name, handle, approved, reply_policy, last_synced_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 'draft_only', ?9)",
                            params![org, local_cid, prov, adapter, kind, ext_id, name, handle, now],
                        );
                        pulled_channels += 1;
                        db.last_insert_rowid()
                    };

                    let _ = db.execute(
                        "INSERT OR IGNORE INTO channel_shop_bindings VALUES (?1, ?2, ?3)",
                        params![org, local_shop_id, channel_id],
                    );
                    if let Some(lcid) = local_cid {
                        let disc_item = json!({
                            "external_id": ext_id,
                            "name": name,
                            "handle": handle,
                            "kind": kind,
                            "adapter": adapter,
                            "followers_count": followers,
                        });
                        let _ = db.execute(
                            "INSERT OR REPLACE INTO discovered_channels
                               (organization_id, connection_id, external_id, channel_json, connection_revision, discovered_at)
                             VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                            params![
                                org,
                                lcid,
                                ext_id,
                                serde_json::to_string(&disc_item).unwrap_or_default(),
                                now
                            ],
                        );
                    }
                    let _ = db.execute(
                        "INSERT INTO channel_snapshots
                           (organization_id, channel_id, snapshot_date, followers_count, posts_count, captured_at)
                         VALUES (?1, ?2, ?3, ?4, 0, ?5)
                         ON CONFLICT(organization_id, channel_id, snapshot_date) DO UPDATE SET
                            followers_count=CASE
                              WHEN excluded.followers_count > 0 THEN excluded.followers_count
                              ELSE channel_snapshots.followers_count
                            END",
                        params![org, channel_id, today, followers, now],
                    );
                }
                let _ = db.execute_batch("COMMIT;");
            }
        }

        if let Ok(mut st) = self.state.lock() {
            st.last_sync_at = Some(now);
            st.last_sync_source = Some("lnc-ads-bridge".to_string());
            st.last_warning = Some(reason.to_string());
            st.cached_status = None;
        }

        let summary = json!({
            "ok": true,
            "source": "lnc-ads-bridge",
            "fallback_reason": reason,
            "pushed_shops": pushed_shops,
            "pushed_apps": 0,
            "pushed_connections": 0,
            "pulled_shops": pulled_shops,
            "pulled_apps": 0,
            "pulled_connections": pulled_connections,
            "pulled_channels": pulled_channels,
            "synced_at": now,
        });
        if let Ok(db) = store::connect(db_path) {
            let _ = db.execute_batch("BEGIN IMMEDIATE;");
            let _ = audit::append(
                &db,
                org,
                "owner",
                "hub.bridge_fallback_synced",
                "lnc-ads",
                &summary,
            );
            let _ = db.execute_batch("COMMIT;");
        }
        Ok(summary)
    }

    pub fn mint_sso_redirect_url(
        &self,
        audience: &str,
        next_path: &str,
        subject: &str,
    ) -> Result<String, AgentHubError> {
        if self.cfg.api_key.is_empty() {
            return Err(AgentHubError::new("agent_hub_api_key_not_configured", 503));
        }
        let res = self
            .request(
                "POST",
                "/v1/platform/sso/mint",
                &[],
                Some(&json!({
                    "audience": audience,
                    "subject": subject,
                    "next_path": next_path,
                })),
                true,
                3_500,
            )
            .map_err(|_| AgentHubError::new("agent_hub_sso_unavailable", 503))?;
        if res.status != 200 {
            return Err(AgentHubError::new("agent_hub_sso_unavailable", 503));
        }
        let data = res
            .json()
            .map_err(|_| AgentHubError::new("agent_hub_sso_unavailable", 503))?;
        if let Some(cu) = data
            .get("consume_url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok(cu.to_string());
        }
        let ticket = data
            .get("ticket")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AgentHubError::new("agent_hub_sso_unavailable", 503))?;
        let base = if !self.cfg.public_url.is_empty() {
            &self.cfg.public_url
        } else {
            &self.cfg.url
        };
        Ok(build_url_with_params(
            &format!("{base}/v1/platform/sso/consume"),
            &[
                ("ticket", ticket.to_string()),
                ("next", next_path.to_string()),
            ],
        ))
    }

    pub fn redeem_sso_ticket(&self, ticket: &str) -> Result<Value, AgentHubError> {
        if self.cfg.api_key.is_empty() {
            return Err(AgentHubError::new("agent_hub_api_key_not_configured", 503));
        }
        let res = self
            .request(
                "POST",
                "/v1/platform/sso/redeem",
                &[],
                Some(&json!({
                    "ticket": ticket,
                    "audience": self.cfg.self_id,
                })),
                true,
                3_500,
            )
            .map_err(|_| AgentHubError::new("agent_hub_sso_unavailable", 503))?;
        if res.status != 200 {
            return Err(AgentHubError::new("sso_ticket_expired_or_invalid", 401));
        }
        let data = res
            .json()
            .map_err(|_| AgentHubError::new("sso_ticket_invalid", 401))?;
        if !data.get("ok").and_then(|v| v.as_bool()).unwrap_or(false)
            || data.get("audience").and_then(|v| v.as_str()) != Some(self.cfg.self_id.as_str())
        {
            return Err(AgentHubError::new("sso_ticket_invalid", 401));
        }
        Ok(json!({
            "iss": data.get("issuer").and_then(|v| v.as_str()).unwrap_or("lnc-agent-hub"),
            "aud": self.cfg.self_id,
            "sub": data.get("subject").and_then(|v| v.as_str()).unwrap_or("owner"),
        }))
    }
}
