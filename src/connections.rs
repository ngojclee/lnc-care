//! OAuth connections, channel discovery, bounded pollers, 5-layer Evidence Vault, and demo workspace seeder/purger.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use chrono::{TimeZone, Utc};
use rand::RngCore;
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use crate::agent_hub::AgentHubClient;
use crate::audit;
use crate::evaluator;
use crate::evidence;
use crate::providers::{
    ProviderError, Providers, META_VERSION, TIKTOK_VERSION, YOUTUBE_VERSION,
};
use crate::store::{self, query_maps, query_one_map};
use crate::transport::SharedTransport;
use crate::vault::Vault;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_urlsafe(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    rand::thread_rng().fill_bytes(&mut buf);
    B64_URL.encode(&buf)
}

#[derive(Clone)]
pub struct Connections {
    pub path: PathBuf,
    pub org: String,
    pub vault: Vault,
    pub providers: Providers,
    pub hub_client: Option<AgentHubClient>,
    locks: Arc<Mutex<HashMap<i64, Arc<Mutex<()>>>>>,
}

impl Connections {
    pub fn new(
        path: PathBuf,
        org: String,
        vault: Vault,
        transport: Option<SharedTransport>,
        hub_client: Option<AgentHubClient>,
    ) -> Self {
        Self {
            path,
            org,
            vault,
            providers: Providers::new(transport),
            hub_client,
            locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn conn_lock(&self, connection_id: i64) -> Arc<Mutex<()>> {
        let mut map = self.locks.lock().unwrap();
        map.entry(connection_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub fn app(&self, db: &Connection, provider: &str) -> Result<(Map<String, Value>, Value), ProviderError> {
        let row = query_one_map(
            db,
            "SELECT * FROM provider_apps WHERE organization_id=? AND provider=?",
            &[self.org.clone().into(), provider.to_string().into()],
        )
        .ok_or_else(|| ProviderError::new("oauth_app_not_configured", 409))?;
        let secret = self
            .vault
            .get(db, &self.org, "app", provider)?
            .ok_or_else(|| ProviderError::new("oauth_app_not_configured", 409))?;
        if secret
            .get("client_secret")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .is_empty()
        {
            return Err(ProviderError::new("oauth_app_not_configured", 409));
        }
        Ok((row, secret))
    }

    pub fn connection(&self, db: &Connection, connection_id: i64) -> Result<Map<String, Value>, ProviderError> {
        query_one_map(
            db,
            "SELECT * FROM provider_connections WHERE organization_id=? AND id=?",
            &[self.org.clone().into(), connection_id.into()],
        )
        .ok_or_else(|| ProviderError::new("connection_not_found", 404))
    }

    pub fn inventory(&self, db: &Connection) -> Value {
        let mut apps = Map::new();
        for provider in ["meta", "tiktok", "youtube"] {
            let row = query_one_map(
                db,
                "SELECT * FROM provider_apps WHERE organization_id=? AND provider=?",
                &[self.org.clone().into(), provider.to_string().into()],
            );
            let secret = self.vault.get(db, &self.org, "app", provider).ok().flatten();
            let configured = row.is_some()
                && secret
                    .as_ref()
                    .and_then(|s| s.get("client_secret"))
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
            let contract = match provider {
                "meta" => META_VERSION,
                "tiktok" => TIKTOK_VERSION,
                _ => YOUTUBE_VERSION,
            };
            apps.insert(
                provider.to_string(),
                json!({
                    "client_id": row.as_ref().and_then(|r| r.get("client_id")).and_then(|v| v.as_str()).unwrap_or(""),
                    "project_id": row.as_ref().and_then(|r| r.get("project_id")).and_then(|v| v.as_str()).unwrap_or(""),
                    "webhook_verify_token": row.as_ref().and_then(|r| r.get("webhook_verify_token")).and_then(|v| v.as_str()).unwrap_or(""),
                    "revision": row.as_ref().and_then(|r| r.get("revision")).and_then(|v| v.as_i64()).unwrap_or(0),
                    "configured": configured,
                    "secret_source": if secret.is_some() { "encrypted_store" } else { "unset" },
                    "contract": contract,
                }),
            );
        }

        let connections: Vec<Value> = query_maps(
            db,
            "SELECT c.id, c.provider, c.label, c.state,
                    r.expires_at, r.last_success, r.last_error, r.revision
             FROM provider_connections c
             LEFT JOIN connection_runtime r
               ON r.organization_id=c.organization_id AND r.connection_id=c.id
             WHERE c.organization_id=? ORDER BY c.id",
            &[self.org.clone().into()],
        )
        .into_iter()
        .map(Value::Object)
        .collect();

        json!({
            "vault_ready": true,
            "apps": apps,
            "connections": connections,
            "writes_enabled": false,
        })
    }

    pub fn save_app(&self, provider: &str, values: &Value) -> Result<Value, ProviderError> {
        let revision_in = values.get("revision").and_then(|v| v.as_i64()).unwrap_or(0);
        let client_id = values
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        if client_id.is_empty() {
            return Err(ProviderError::new("client_id_required", 422));
        }
        let project_id = values
            .get("project_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        let webhook_verify_token = values
            .get("webhook_verify_token")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        let client_secret_in = values
            .get("client_secret")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        let confirm_replace = values
            .get("confirm_replace")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let revision = store::with_write_tx(&self.path, |db| -> Result<i64, ProviderError> {
            let old = query_one_map(
                db,
                "SELECT * FROM provider_apps WHERE organization_id=? AND provider=?",
                &[self.org.clone().into(), provider.to_string().into()],
            );
            let old_rev = old
                .as_ref()
                .and_then(|r| r.get("revision"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if old_rev != revision_in {
                return Err(ProviderError::new("configuration_version_conflict", 409));
            }
            let old_sec = self
                .vault
                .get(db, &self.org, "app", provider)?
                .unwrap_or_else(|| json!({}));
            let eff_secret = if !client_secret_in.is_empty() && client_secret_in != "********" {
                client_secret_in.to_string()
            } else {
                old_sec
                    .get("client_secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string()
            };
            if eff_secret.is_empty() {
                return Err(ProviderError::new("client_secret_required", 422));
            }

            let connected: Vec<i64> = query_maps(
                db,
                "SELECT id FROM provider_connections
                 WHERE organization_id=? AND provider=? AND state IN ('verified', 'expired')",
                &[self.org.clone().into(), provider.to_string().into()],
            )
            .into_iter()
            .filter_map(|r| r.get("id").and_then(|v| v.as_i64()))
            .collect();

            if !connected.is_empty() && !confirm_replace {
                return Err(ProviderError::new(
                    "confirm_replace_and_reconnect_channels",
                    409,
                ));
            }
            let new_rev = old_rev + 1;
            db.execute(
                "INSERT INTO provider_apps
                   (organization_id, provider, client_id, project_id, webhook_verify_token, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(organization_id, provider) DO UPDATE SET
                    client_id=excluded.client_id,
                    project_id=excluded.project_id,
                    webhook_verify_token=excluded.webhook_verify_token,
                    revision=excluded.revision",
                params![
                    self.org,
                    provider,
                    client_id,
                    project_id,
                    webhook_verify_token,
                    new_rev
                ],
            )?;
            self.vault.put(
                db,
                &self.org,
                "app",
                provider,
                &json!({"client_secret": eff_secret}),
            )?;
            for cid in &connected {
                self.disconnect_in_tx(db, *cid)?;
            }
            audit::append(
                db,
                &self.org,
                "owner",
                "provider.app_saved",
                provider,
                &json!({"revision": new_rev, "connections_invalidated": connected.len()}),
            )?;
            Ok(new_rev)
        })?;

        if let Some(ref hub) = self.hub_client {
            let _ = hub.try_push_app(&self.path, &self.org, provider, &self.vault);
        }
        Ok(json!({"ok": true, "revision": revision}))
    }

    pub fn start(
        &self,
        connection_id: i64,
        session_hash: &str,
        base: &str,
    ) -> Result<Value, ProviderError> {
        let parsed = Url::parse(base)
            .map_err(|_| ProviderError::new("oauth_requires_https_or_loopback", 422))?;
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or_default();
        if scheme != "https"
            && !(scheme == "http" && matches!(host, "127.0.0.1" | "localhost" | "testserver"))
        {
            return Err(ProviderError::new("oauth_requires_https_or_loopback", 422));
        }

        let mtx = self.conn_lock(connection_id);
        let _guard = mtx.lock().unwrap();

        store::with_write_tx(&self.path, |db| -> Result<Value, ProviderError> {
            let conn = self.connection(db, connection_id)?;
            let provider = conn
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("meta");
            let (app, _secret) = self.app(db, provider)?;
            let app_rev = app.get("revision").and_then(|v| v.as_i64()).unwrap_or(1);
            let client_id = app
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();

            db.execute(
                "INSERT OR IGNORE INTO connection_runtime
                   (organization_id, connection_id, revision, app_revision)
                 VALUES (?1, ?2, 1, ?3)",
                params![self.org, connection_id, app_rev],
            )?;
            let runtime_rev: i64 = db.query_row(
                "SELECT revision FROM connection_runtime WHERE organization_id=?1 AND connection_id=?2",
                params![self.org, connection_id],
                |r| r.get(0),
            )?;

            let state = random_urlsafe(32);
            let verifier = random_urlsafe(64);
            let mut hasher = Sha256::new();
            hasher.update(state.as_bytes());
            let state_hash = hex::encode(hasher.finalize());
            let redirect = format!("{}/api/auth/providers/{provider}/callback", base.trim_end_matches('/'));

            for old_row in query_maps(
                db,
                "SELECT state_hash FROM oauth_sessions WHERE organization_id=? AND connection_id=?",
                &[self.org.clone().into(), connection_id.into()],
            ) {
                if let Some(sh) = old_row.get("state_hash").and_then(|v| v.as_str()) {
                    self.vault.delete(db, &self.org, "state", sh);
                }
            }
            db.execute(
                "DELETE FROM oauth_sessions WHERE organization_id=?1 AND connection_id=?2",
                params![self.org, connection_id],
            )?;
            db.execute(
                "INSERT INTO oauth_sessions
                   (state_hash, organization_id, connection_id, session_hash, app_revision, redirect_uri, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    state_hash,
                    self.org,
                    connection_id,
                    session_hash,
                    app_rev,
                    redirect,
                    now_unix() + 600
                ],
            )?;
            self.vault.put(
                db,
                &self.org,
                "state",
                &state_hash,
                &json!({"verifier": verifier, "connection_revision": runtime_rev}),
            )?;
            let url = self
                .providers
                .authorize(provider, client_id, &redirect, &state)?;
            audit::append(
                db,
                &self.org,
                "owner",
                "connection.oauth_started",
                &connection_id.to_string(),
                &json!({}),
            )?;
            Ok(json!({"authorization_url": url, "redirect_uri": redirect}))
        })
    }

    pub fn callback(
        &self,
        provider: &str,
        state: &str,
        code: &str,
        session_hash: &str,
    ) -> Result<(), ProviderError> {
        let mut hasher = Sha256::new();
        hasher.update(state.as_bytes());
        let state_hash = hex::encode(hasher.finalize());

        let (connection_id, client_id, client_secret, app_rev, redirect_uri) =
            store::with_write_tx(&self.path, |db| -> Result<_, ProviderError> {
                let row = query_one_map(
                    db,
                    "SELECT * FROM oauth_sessions WHERE organization_id=? AND state_hash=?",
                    &[self.org.clone().into(), state_hash.clone().into()],
                )
                .ok_or_else(|| ProviderError::new("oauth_state_invalid_or_expired", 400))?;

                let stored_sh = row
                    .get("session_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let expires_at = row.get("expires_at").and_then(|v| v.as_i64()).unwrap_or(0);
                if stored_sh
                    .as_bytes()
                    .ct_eq(session_hash.as_bytes())
                    .unwrap_u8()
                    != 1
                    || expires_at <= now_unix()
                {
                    return Err(ProviderError::new("oauth_state_invalid_or_expired", 400));
                }

                let cid = row
                    .get("connection_id")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let conn = self.connection(db, cid)?;
                let (app, secret) = self.app(db, provider)?;
                let app_rev = app.get("revision").and_then(|v| v.as_i64()).unwrap_or(0);
                if conn.get("provider").and_then(|v| v.as_str()) != Some(provider)
                    || row.get("app_revision").and_then(|v| v.as_i64()) != Some(app_rev)
                {
                    return Err(ProviderError::new("oauth_configuration_changed", 409));
                }
                if self.vault.get(db, &self.org, "state", &state_hash)?.is_none() {
                    return Err(ProviderError::new("oauth_state_invalid_or_expired", 400));
                }
                db.execute(
                    "DELETE FROM oauth_sessions WHERE organization_id=?1 AND state_hash=?2",
                    params![self.org, state_hash],
                )?;
                self.vault.delete(db, &self.org, "state", &state_hash);
                Ok((
                    cid,
                    app.get("client_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    secret
                        .get("client_secret")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    app_rev,
                    row.get("redirect_uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                ))
            })?;

        let mtx = self.conn_lock(connection_id);
        let _guard = mtx.lock().unwrap();

        let token = self.providers.exchange(
            provider,
            &client_id,
            &client_secret,
            &redirect_uri,
            code,
        )?;
        let expiry = now_unix()
            + token
                .get("expires_in")
                .and_then(|v| v.as_i64())
                .unwrap_or(5_184_000);

        store::with_write_tx(&self.path, |db| -> Result<(), ProviderError> {
            self.vault
                .put(db, &self.org, "connection", &connection_id.to_string(), &token)?;
            db.execute(
                "INSERT INTO connection_runtime
                   (organization_id, connection_id, revision, app_revision, expires_at, last_error)
                 VALUES (?1, ?2, 1, ?3, ?4, NULL)
                 ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                    revision=revision+1,
                    app_revision=excluded.app_revision,
                    expires_at=excluded.expires_at,
                    last_error=NULL",
                params![self.org, connection_id, app_rev, expiry],
            )?;
            db.execute(
                "UPDATE provider_connections SET state='verified' WHERE organization_id=?1 AND id=?2",
                params![self.org, connection_id],
            )?;
            db.execute(
                "UPDATE channels SET approved=0 WHERE organization_id=?1 AND connection_id=?2",
                params![self.org, connection_id],
            )?;
            audit::append(
                db,
                &self.org,
                "owner",
                "connection.authorized",
                &connection_id.to_string(),
                &json!({"provider": provider}),
            )?;
            Ok(())
        })?;

        if let Some(ref hub) = self.hub_client {
            let _ = hub.try_push_connection(&self.path, &self.org, connection_id, &self.vault);
        }
        Ok(())
    }

    fn disconnect_in_tx(&self, db: &Connection, connection_id: i64) -> Result<(), rusqlite::Error> {
        db.execute(
            "UPDATE provider_connections SET state='not_connected' WHERE organization_id=?1 AND id=?2",
            params![self.org, connection_id],
        )?;
        db.execute(
            "UPDATE channels SET approved=0 WHERE organization_id=?1 AND connection_id=?2",
            params![self.org, connection_id],
        )?;
        self.vault
            .delete(db, &self.org, "connection", &connection_id.to_string());
        db.execute(
            "UPDATE connection_runtime SET revision=revision+1, last_error=NULL WHERE organization_id=?1 AND connection_id=?2",
            params![self.org, connection_id],
        )?;
        Ok(())
    }

    pub fn disconnect(&self, connection_id: i64) -> Result<Value, ProviderError> {
        let mtx = self.conn_lock(connection_id);
        let _guard = mtx.lock().unwrap();
        store::with_write_tx(&self.path, |db| -> Result<Value, ProviderError> {
            self.connection(db, connection_id)?;
            self.disconnect_in_tx(db, connection_id)?;
            audit::append(
                db,
                &self.org,
                "owner",
                "connection.disconnected",
                &connection_id.to_string(),
                &json!({}),
            )?;
            Ok(json!({"ok": true}))
        })
    }

    pub fn discover(&self, connection_id: i64) -> Result<Value, ProviderError> {
        let mtx = self.conn_lock(connection_id);
        let _guard = mtx.lock().unwrap();

        if let Some(ref hub) = self.hub_client {
            hub.ensure_fresh_token(&self.path, &self.org, &self.vault, connection_id, false);
        }

        let (provider, access_token, revision) = {
            let db = store::connect_readonly(&self.path)?;
            let conn = self.connection(&db, connection_id)?;
            let provider = conn
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("meta")
                .to_string();
            let link_hid: Option<String> = db
                .query_row(
                    "SELECT hub_connection_id FROM hub_connection_links WHERE organization_id=?1 AND connection_id=?2",
                    params![self.org, connection_id],
                    |r| r.get(0),
                )
                .ok();
            let token = self
                .vault
                .get(&db, &self.org, "connection", &connection_id.to_string())?;

            if token.is_none()
                && link_hid
                    .as_deref()
                    .map(|s| s.starts_with("ads_bridge:"))
                    .unwrap_or(false)
                && self
                    .hub_client
                    .as_ref()
                    .and_then(|h| h.ads_bridge.as_ref())
                    .is_some()
            {
                let cached: Vec<Value> = query_maps(
                    &db,
                    "SELECT channel_json FROM discovered_channels WHERE organization_id=? AND connection_id=? ORDER BY external_id",
                    &[self.org.clone().into(), connection_id.into()],
                )
                .into_iter()
                .filter_map(|r| {
                    r.get("channel_json")
                        .and_then(|v| v.as_str())
                        .and_then(|s| serde_json::from_str::<Value>(s).ok())
                })
                .collect();
                return Ok(json!({"channels": cached, "truncated": false}));
            }

            let _ = self.app(&db, &provider)?;
            let runtime = query_one_map(
                &db,
                "SELECT * FROM connection_runtime WHERE organization_id=? AND connection_id=?",
                &[self.org.clone().into(), connection_id.into()],
            );
            let access_tok = token
                .as_ref()
                .and_then(|t| t.get("access_token"))
                .and_then(|v| v.as_str())
                .map(String::from);
            if conn.get("state").and_then(|v| v.as_str()) != Some("verified")
                || access_tok.is_none()
                || runtime.is_none()
            {
                return Err(ProviderError::new("reauthorization_required", 409));
            }
            let rev = runtime
                .and_then(|r| r.get("revision").and_then(|v| v.as_i64()))
                .unwrap_or(1);
            (provider, access_tok.unwrap(), rev)
        };

        let (channels, truncated) = self.providers.discover(&provider, &access_token)?;
        let now = now_unix();
        store::with_write_tx(&self.path, |db| -> Result<Value, ProviderError> {
            db.execute(
                "DELETE FROM discovered_channels WHERE organization_id=?1 AND connection_id=?2",
                params![self.org, connection_id],
            )?;
            let mut sanitized = Vec::new();
            for mut item in channels {
                let page_tok = item
                    .as_object_mut()
                    .and_then(|o| o.remove("page_access_token"))
                    .and_then(|v| v.as_str().map(String::from));
                let ext_id = item
                    .get("external_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if let Some(pt) = page_tok.filter(|s| !s.is_empty()) {
                    self.vault.put(
                        db,
                        &self.org,
                        "channel_token",
                        &format!("{provider}:{ext_id}"),
                        &json!({"access_token": pt}),
                    )?;
                }
                db.execute(
                    "INSERT INTO discovered_channels VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        self.org,
                        connection_id,
                        ext_id,
                        serde_json::to_string(&item).unwrap_or_default(),
                        revision,
                        now
                    ],
                )?;
                sanitized.push(item);
            }
            db.execute(
                "UPDATE connection_runtime SET last_success=?1, last_error=NULL WHERE organization_id=?2 AND connection_id=?3",
                params![now, self.org, connection_id],
            )?;
            audit::append(
                db,
                &self.org,
                "owner",
                "connection.discovered",
                &connection_id.to_string(),
                &json!({"count": sanitized.len(), "truncated": truncated}),
            )?;
            Ok(json!({"channels": sanitized, "truncated": truncated}))
        })
    }

    pub fn discovered(&self, db: &Connection, connection_id: i64) -> Result<Vec<Value>, ProviderError> {
        self.connection(db, connection_id)?;
        let cutoff = now_unix() - 3600;
        Ok(query_maps(
            db,
            "SELECT channel_json FROM discovered_channels
             WHERE organization_id=? AND connection_id=? AND discovered_at>?
             ORDER BY external_id",
            &[
                self.org.clone().into(),
                connection_id.into(),
                cutoff.into(),
            ],
        )
        .into_iter()
        .filter_map(|r| {
            r.get("channel_json")
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
        })
        .collect())
    }

    pub fn approve_channel(
        &self,
        connection_id: i64,
        external_id: &str,
        shop_id: i64,
        reply_policy: &str,
    ) -> Result<Value, ProviderError> {
        if !store::REPLY_POLICIES.contains(&reply_policy) {
            return Err(ProviderError::new("invalid_reply_policy", 422));
        }
        let mtx = self.conn_lock(connection_id);
        let _guard = mtx.lock().unwrap();

        store::with_write_tx(&self.path, |db| -> Result<Value, ProviderError> {
            let conn = self.connection(db, connection_id)?;
            let provider = conn
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("meta");
            let disc_raw: Option<String> = db
                .query_row(
                    "SELECT channel_json FROM discovered_channels
                     WHERE organization_id=?1 AND connection_id=?2 AND external_id=?3",
                    params![self.org, connection_id, external_id],
                    |r| r.get(0),
                )
                .ok();
            if conn.get("state").and_then(|v| v.as_str()) != Some("verified") || disc_raw.is_none()
            {
                return Err(ProviderError::new("discover_channels_before_approval", 409));
            }
            let item: Value = serde_json::from_str(&disc_raw.unwrap())
                .map_err(|_| ProviderError::new("discover_channels_before_approval", 409))?;

            let shop_exists: bool = db
                .query_row(
                    "SELECT 1 FROM shops WHERE organization_id=?1 AND id=?2",
                    params![self.org, shop_id],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            if !shop_exists {
                return Err(ProviderError::new("shop_not_found", 404));
            }

            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(external_id);
            let handle = item
                .get("handle")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let kind = item
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("fb_page");
            let adapter = item
                .get("adapter")
                .and_then(|v| v.as_str())
                .unwrap_or("meta_api");
            let followers = item
                .get("followers_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            let channel_id: i64 = if let Ok(cid) = db.query_row::<i64, _, _>(
                "SELECT id FROM channels WHERE organization_id=?1 AND provider=?2 AND external_id=?3",
                params![self.org, provider, external_id],
                |r| r.get(0),
            ) {
                db.execute(
                    "UPDATE channels SET approved=1, connection_id=?1, name=?2, handle=?3,
                            kind=?4, adapter=?5, reply_policy=?6
                     WHERE organization_id=?7 AND id=?8",
                    params![
                        connection_id,
                        name,
                        handle,
                        kind,
                        adapter,
                        reply_policy,
                        self.org,
                        cid
                    ],
                )?;
                cid
            } else {
                db.execute(
                    "INSERT INTO channels
                       (organization_id, connection_id, provider, adapter, kind, external_id,
                        name, handle, approved, reply_policy)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                    params![
                        self.org,
                        connection_id,
                        provider,
                        adapter,
                        kind,
                        external_id,
                        name,
                        handle,
                        reply_policy
                    ],
                )?;
                db.last_insert_rowid()
            };

            db.execute(
                "INSERT OR IGNORE INTO channel_shop_bindings VALUES (?1, ?2, ?3)",
                params![self.org, shop_id, channel_id],
            )?;
            let today = Utc::now().format("%Y-%m-%d").to_string();
            db.execute(
                "INSERT INTO channel_snapshots
                   (organization_id, channel_id, snapshot_date, followers_count, posts_count, captured_at)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5)
                 ON CONFLICT(organization_id, channel_id, snapshot_date) DO UPDATE SET
                    followers_count=excluded.followers_count",
                params![self.org, channel_id, today, followers, now_unix()],
            )?;
            audit::append(
                db,
                &self.org,
                "owner",
                "channel.approved",
                &channel_id.to_string(),
                &json!({
                    "shop_id": shop_id,
                    "connection_id": connection_id,
                    "reply_policy": reply_policy
                }),
            )?;
            Ok(json!({"ok": true, "channel_id": channel_id}))
        })
    }

    fn fetch_posts_via_bridge(
        &self,
        shop_name: &str,
        remote_cid: i64,
        kind: &str,
        external_id: &str,
        limit: i64,
    ) -> Result<Vec<Value>, ProviderError> {
        let bridge = self
            .hub_client
            .as_ref()
            .and_then(|h| h.ads_bridge.as_ref())
            .ok_or_else(|| ProviderError::new("internal_bridge_not_configured", 503))?;
        let now = now_unix();
        match kind {
            "fb_page" => {
                let resp = bridge
                    .platform_call(
                        shop_name,
                        remote_cid,
                        "GET",
                        &format!("{external_id}/published_posts"),
                        Some(json!({
                            "fields": "id,message,permalink_url,created_time,attachments{media_type,url,media}",
                            "limit": limit.clamp(1, 50),
                        })),
                        None,
                        true,
                        external_id,
                    )
                    .map_err(|e| ProviderError::new(e.code, e.status))?;
                let rows = resp
                    .get("data")
                    .and_then(|d| d.get("data"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut out = Vec::new();
                for r in rows {
                    let mut media = Vec::new();
                    if let Some(atts) = r
                        .get("attachments")
                        .and_then(|a| a.get("data"))
                        .and_then(|d| d.as_array())
                    {
                        for att in atts {
                            let img = att
                                .get("media")
                                .and_then(|m| m.get("image"))
                                .and_then(|i| i.get("src"))
                                .and_then(|s| s.as_str())
                                .or_else(|| att.get("url").and_then(|u| u.as_str()));
                            if let Some(u) = img {
                                media.push(json!({
                                    "type": att.get("media_type").and_then(|t| t.as_str()).unwrap_or("photo"),
                                    "url": u,
                                }));
                            }
                        }
                    }
                    if let Some(id) = r.get("id").and_then(|v| v.as_str()) {
                        out.push(json!({
                            "external_id": id,
                            "caption": r.get("message").and_then(|v| v.as_str()).unwrap_or(""),
                            "permalink": r.get("permalink_url").and_then(|v| v.as_str()).unwrap_or(""),
                            "kind": "post",
                            "published_at": now,
                            "media": media,
                            "likes": 0,
                        }));
                    }
                }
                Ok(out)
            }
            "ig_account" => {
                let resp = bridge
                    .platform_call(
                        shop_name,
                        remote_cid,
                        "GET",
                        &format!("{external_id}/media"),
                        Some(json!({
                            "fields": "id,caption,media_type,media_url,thumbnail_url,permalink,timestamp,like_count,comments_count",
                            "limit": limit.clamp(1, 50),
                        })),
                        None,
                        false,
                        "",
                    )
                    .map_err(|e| ProviderError::new(e.code, e.status))?;
                let rows = resp
                    .get("data")
                    .and_then(|d| d.get("data"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut out = Vec::new();
                for r in rows {
                    let m_url = r
                        .get("media_url")
                        .and_then(|v| v.as_str())
                        .or_else(|| r.get("thumbnail_url").and_then(|v| v.as_str()));
                    let mtype = r
                        .get("media_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("IMAGE");
                    let media = match m_url {
                        Some(u) => vec![json!({"type": mtype.to_lowercase(), "url": u})],
                        None => Vec::new(),
                    };
                    if let Some(id) = r.get("id").and_then(|v| v.as_str()) {
                        out.push(json!({
                            "external_id": id,
                            "caption": r.get("caption").and_then(|v| v.as_str()).unwrap_or(""),
                            "permalink": r.get("permalink").and_then(|v| v.as_str()).unwrap_or(""),
                            "kind": if mtype == "VIDEO" { "reel" } else { "post" },
                            "published_at": now,
                            "media": media,
                            "likes": r.get("like_count").and_then(|v| v.as_i64()).unwrap_or(0),
                            "comments_count": r.get("comments_count").and_then(|v| v.as_i64()).unwrap_or(0),
                        }));
                    }
                }
                Ok(out)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn fetch_comments_via_bridge(
        &self,
        shop_name: &str,
        remote_cid: i64,
        kind: &str,
        channel_external_id: &str,
        post_external_id: &str,
        limit: i64,
    ) -> Result<Vec<Value>, ProviderError> {
        let bridge = self
            .hub_client
            .as_ref()
            .and_then(|h| h.ads_bridge.as_ref())
            .ok_or_else(|| ProviderError::new("internal_bridge_not_configured", 503))?;
        let now = now_unix();
        match kind {
            "fb_page" => {
                let resp = bridge
                    .platform_call(
                        shop_name,
                        remote_cid,
                        "GET",
                        &format!("{post_external_id}/comments"),
                        Some(json!({
                            "fields": "id,from,message,created_time,parent,is_hidden,comment_count,like_count",
                            "filter": "stream",
                            "limit": limit.clamp(1, 100),
                        })),
                        None,
                        true,
                        channel_external_id,
                    )
                    .map_err(|e| ProviderError::new(e.code, e.status))?;
                let rows = resp
                    .get("data")
                    .and_then(|d| d.get("data"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut out = Vec::new();
                for r in rows {
                    if let Some(id) = r.get("id").and_then(|v| v.as_str()) {
                        let frm = r.get("from").cloned().unwrap_or_else(|| json!({}));
                        let parent = r
                            .get("parent")
                            .and_then(|p| p.get("id"))
                            .and_then(|v| v.as_str())
                            .map(Value::from)
                            .unwrap_or(Value::Null);
                        out.push(json!({
                            "external_id": id,
                            "parent_external_id": parent,
                            "author_external_id": frm.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                            "author_name": frm.get("name").and_then(|v| v.as_str()).unwrap_or("Facebook User"),
                            "text": r.get("message").and_then(|v| v.as_str()).unwrap_or(""),
                            "is_hidden": r.get("is_hidden").and_then(|v| v.as_bool()).unwrap_or(false),
                            "like_count": r.get("like_count").and_then(|v| v.as_i64()).unwrap_or(0),
                            "reply_count": r.get("comment_count").and_then(|v| v.as_i64()).unwrap_or(0),
                            "created_at": now,
                        }));
                    }
                }
                Ok(out)
            }
            "ig_account" => {
                let resp = bridge
                    .platform_call(
                        shop_name,
                        remote_cid,
                        "GET",
                        &format!("{post_external_id}/comments"),
                        Some(json!({
                            "fields": "id,text,username,timestamp,hidden,like_count",
                            "limit": limit.clamp(1, 100),
                        })),
                        None,
                        false,
                        "",
                    )
                    .map_err(|e| ProviderError::new(e.code, e.status))?;
                let rows = resp
                    .get("data")
                    .and_then(|d| d.get("data"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut out = Vec::new();
                for r in rows {
                    if let Some(id) = r.get("id").and_then(|v| v.as_str()) {
                        let uname = r
                            .get("username")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let author_name = if uname.is_empty() {
                            "Instagram User".to_string()
                        } else {
                            format!("@{uname}")
                        };
                        out.push(json!({
                            "external_id": id,
                            "parent_external_id": Value::Null,
                            "author_external_id": uname,
                            "author_name": author_name,
                            "text": r.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                            "is_hidden": r.get("hidden").and_then(|v| v.as_bool()).unwrap_or(false),
                            "like_count": r.get("like_count").and_then(|v| v.as_i64()).unwrap_or(0),
                            "reply_count": 0,
                            "created_at": now,
                        }));
                    }
                }
                Ok(out)
            }
            _ => Ok(Vec::new()),
        }
    }

    pub fn sync_channel(
        &self,
        channel_id: i64,
        post_limit: i64,
        comment_limit: i64,
    ) -> Result<Value, ProviderError> {
        let ch = {
            let db = store::connect_readonly(&self.path)?;
            let ch = query_one_map(
                &db,
                "SELECT * FROM channels WHERE organization_id=? AND id=? AND approved=1",
                &[self.org.clone().into(), channel_id.into()],
            )
            .ok_or_else(|| ProviderError::new("channel_not_authorized", 403))?;
            if ch.get("adapter").and_then(|v| v.as_str()) != Some("meta_api") {
                return Err(ProviderError::new(
                    "channel_adapter_requires_worker_lane",
                    409,
                ));
            }
            ch
        };

        let conn_id = ch.get("connection_id").and_then(|v| v.as_i64());
        if let (Some(cid), Some(ref hub)) = (conn_id, &self.hub_client) {
            hub.ensure_fresh_token(&self.path, &self.org, &self.vault, cid, false);
        }

        let provider = ch
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("meta");
        let ch_kind = ch
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("fb_page");
        let ch_ext = ch
            .get("external_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let (token, bridge_ctx): (Option<String>, Option<(String, i64)>) = {
            let db = store::connect_readonly(&self.path)?;
            let mut tok_env =
                self.vault
                    .get(&db, &self.org, "channel_token", &format!("{provider}:{ch_ext}"))?;
            if tok_env.is_none() {
                if let Some(cid) = conn_id {
                    tok_env = self
                        .vault
                        .get(&db, &self.org, "connection", &cid.to_string())?;
                }
            }
            let tok = tok_env
                .and_then(|t| t.get("access_token").and_then(|v| v.as_str()).map(String::from))
                .filter(|s| !s.is_empty());

            if tok.is_some() {
                (tok, None)
            } else if let Some(cid) = conn_id {
                let has_bridge = self
                    .hub_client
                    .as_ref()
                    .and_then(|h| h.ads_bridge.as_ref())
                    .is_some();
                if has_bridge {
                    let link_hid: Option<String> = db
                        .query_row(
                            "SELECT hub_connection_id FROM hub_connection_links WHERE organization_id=?1 AND connection_id=?2",
                            params![self.org, cid],
                            |r| r.get(0),
                        )
                        .ok();
                    let shop_name: Option<String> = db
                        .query_row(
                            "SELECT s.name FROM shops s
                             JOIN channel_shop_bindings csb
                               ON csb.organization_id=s.organization_id AND csb.shop_id=s.id
                             WHERE csb.organization_id=?1 AND csb.channel_id=?2
                             ORDER BY s.id LIMIT 1",
                            params![self.org, channel_id],
                            |r| r.get(0),
                        )
                        .ok();
                    if let (Some(hid), Some(sname)) = (link_hid, shop_name) {
                        if let Some(rest) = hid.strip_prefix("ads_bridge:") {
                            if let Ok(remote_cid) = rest.parse::<i64>() {
                                (None, Some((sname, remote_cid)))
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        };

        if token.is_none() && bridge_ctx.is_none() {
            return Err(ProviderError::new("channel_token_missing", 409));
        }

        let fetched_posts = if let Some(ref tok) = token {
            self.providers
                .fetch_channel_posts(ch_kind, ch_ext, tok, post_limit)?
        } else {
            let (ref sname, rcid) = bridge_ctx.as_ref().unwrap();
            self.fetch_posts_via_bridge(sname, *rcid, ch_kind, ch_ext, post_limit)?
        };

        let mut posts_with_comments = Vec::new();
        for p in fetched_posts {
            let p_ext = p
                .get("external_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let fetched_comments = if let Some(ref tok) = token {
                self.providers
                    .fetch_post_comments(ch_kind, &p_ext, tok, comment_limit)?
            } else {
                let (ref sname, rcid) = bridge_ctx.as_ref().unwrap();
                self.fetch_comments_via_bridge(sname, *rcid, ch_kind, ch_ext, &p_ext, comment_limit)?
            };
            posts_with_comments.push((p, fetched_comments));
        }

        let now = now_unix();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let mut posts_saved = 0i64;
        let mut comments_saved = 0i64;

        store::with_write_tx(&self.path, |db| -> Result<(), ProviderError> {
            for (p, fetched_comments) in &posts_with_comments {
                let p_ext = p
                    .get("external_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let permalink = p
                    .get("permalink")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let p_kind = p.get("kind").and_then(|v| v.as_str()).unwrap_or("post");
                let caption = p
                    .get("caption")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let pub_at = p.get("published_at").and_then(|v| v.as_i64()).unwrap_or(now);
                let media_json = p
                    .get("media")
                    .map(|m| serde_json::to_string(m).unwrap_or_else(|_| "[]".to_string()))
                    .unwrap_or_else(|| "[]".to_string());
                let likes = p.get("likes").and_then(|v| v.as_i64()).unwrap_or(0);

                db.execute(
                    "INSERT INTO posts
                       (organization_id, channel_id, external_id, permalink, kind, caption,
                        published_at, author_is_channel, media_json, first_seen, last_synced)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10)
                     ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                        caption=excluded.caption,
                        permalink=excluded.permalink,
                        media_json=excluded.media_json,
                        last_synced=excluded.last_synced",
                    params![
                        self.org,
                        channel_id,
                        p_ext,
                        permalink,
                        p_kind,
                        caption,
                        pub_at,
                        media_json,
                        now,
                        now
                    ],
                )?;
                let post_id: i64 = db.query_row(
                    "SELECT id FROM posts WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                    params![self.org, channel_id, p_ext],
                    |r| r.get(0),
                )?;
                posts_saved += 1;

                db.execute(
                    "INSERT INTO post_snapshots
                       (organization_id, post_id, snapshot_date, reactions, comments_count, captured_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(organization_id, post_id, snapshot_date) DO UPDATE SET
                        reactions=excluded.reactions,
                        comments_count=excluded.comments_count,
                        captured_at=excluded.captured_at",
                    params![
                        self.org,
                        post_id,
                        today,
                        likes,
                        fetched_comments.len() as i64,
                        now
                    ],
                )?;

                for c in fetched_comments {
                    let c_ext = c
                        .get("external_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let parent_ext = c.get("parent_external_id").and_then(|v| v.as_str());
                    let auth_ext = c
                        .get("author_external_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let auth_name = c
                        .get("author_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Social User");
                    let text = c.get("text").and_then(|v| v.as_str()).unwrap_or_default();
                    let created_at = c.get("created_at").and_then(|v| v.as_i64()).unwrap_or(now);
                    let is_hidden = if c
                        .get("is_hidden")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        1
                    } else {
                        0
                    };
                    let like_cnt = c.get("like_count").and_then(|v| v.as_i64()).unwrap_or(0);
                    let reply_cnt = c.get("reply_count").and_then(|v| v.as_i64()).unwrap_or(0);

                    db.execute(
                        "INSERT INTO comments
                           (organization_id, post_id, channel_id, external_id, source, verified,
                            parent_external_id, author_external_id, author_name, text,
                            created_at, is_hidden, like_count, reply_count)
                         VALUES (?1, ?2, ?3, ?4, 'api', 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                         ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                            text=excluded.text,
                            is_hidden=excluded.is_hidden,
                            like_count=excluded.like_count,
                            reply_count=excluded.reply_count",
                        params![
                            self.org,
                            post_id,
                            channel_id,
                            c_ext,
                            parent_ext,
                            auth_ext,
                            auth_name,
                            text,
                            created_at,
                            is_hidden,
                            like_cnt,
                            reply_cnt
                        ],
                    )?;
                    let cm_id: i64 = db.query_row(
                        "SELECT id FROM comments WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                        params![self.org, channel_id, c_ext],
                        |r| r.get(0),
                    )?;
                    let _ = evaluator::evaluate_and_persist(
                        db,
                        &self.org,
                        cm_id,
                        None,
                        "poller:ai",
                    );
                    comments_saved += 1;
                }
            }

            db.execute(
                "UPDATE channels SET last_synced_at=?1 WHERE organization_id=?2 AND id=?3",
                params![now, self.org, channel_id],
            )?;
            audit::append(
                db,
                &self.org,
                "owner",
                "channel.synced",
                &channel_id.to_string(),
                &json!({"posts": posts_saved, "comments": comments_saved}),
            )?;
            Ok(())
        })?;

        Ok(json!({
            "ok": true,
            "channel_id": channel_id,
            "posts": posts_saved,
            "comments": comments_saved,
        }))
    }

    pub fn subscribe_channel_webhooks(
        &self,
        channel_id: i64,
        fields: &str,
    ) -> Result<Value, ProviderError> {
        let eff_fields = if fields.trim().is_empty() {
            "feed,messages"
        } else {
            fields.trim()
        };

        let ch = {
            let db = store::connect_readonly(&self.path)?;
            let ch = query_one_map(
                &db,
                "SELECT * FROM channels WHERE organization_id=? AND id=? AND approved=1",
                &[self.org.clone().into(), channel_id.into()],
            )
            .ok_or_else(|| ProviderError::new("channel_not_authorized", 403))?;
            if ch.get("adapter").and_then(|v| v.as_str()) != Some("meta_api") {
                return Err(ProviderError::new("channel_adapter_unsupported", 409));
            }
            ch
        };

        let conn_id = ch.get("connection_id").and_then(|v| v.as_i64());
        if let (Some(cid), Some(ref hub)) = (conn_id, &self.hub_client) {
            hub.ensure_fresh_token(&self.path, &self.org, &self.vault, cid, false);
        }

        let provider = ch
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("meta");
        let ch_kind = ch
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("fb_page");
        let ch_ext = ch
            .get("external_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // For IG business accounts, subscribe the linked FB page if linked_channel_id is set
        let subscribe_target_ext = if ch_kind == "ig_account" {
            let db = store::connect_readonly(&self.path)?;
            if let Some(linked_cid) = ch.get("linked_channel_id").and_then(|v| v.as_i64()) {
                db.query_row(
                    "SELECT external_id FROM channels WHERE organization_id=?1 AND id=?2",
                    params![self.org, linked_cid],
                    |r| r.get::<_, String>(0),
                )
                .unwrap_or_else(|_| ch_ext.clone())
            } else {
                ch_ext.clone()
            }
        } else {
            ch_ext.clone()
        };

        let (token, bridge_ctx): (Option<String>, Option<(String, i64)>) = {
            let db = store::connect_readonly(&self.path)?;
            let mut tok_env = self.vault.get(
                &db,
                &self.org,
                "channel_token",
                &format!("{provider}:{subscribe_target_ext}"),
            )?;
            if tok_env.is_none() {
                tok_env = self.vault.get(
                    &db,
                    &self.org,
                    "channel_token",
                    &format!("{provider}:{ch_ext}"),
                )?;
            }
            if tok_env.is_none() {
                if let Some(cid) = conn_id {
                    tok_env = self
                        .vault
                        .get(&db, &self.org, "connection", &cid.to_string())?;
                }
            }
            let tok = tok_env
                .and_then(|t| t.get("access_token").and_then(|v| v.as_str()).map(String::from))
                .filter(|s| !s.is_empty());

            if tok.is_some() {
                (tok, None)
            } else if let Some(cid) = conn_id {
                let has_bridge = self
                    .hub_client
                    .as_ref()
                    .and_then(|h| h.ads_bridge.as_ref())
                    .is_some();
                if has_bridge {
                    let link_hid: Option<String> = db
                        .query_row(
                            "SELECT hub_connection_id FROM hub_connection_links WHERE organization_id=?1 AND connection_id=?2",
                            params![self.org, cid],
                            |r| r.get(0),
                        )
                        .ok();
                    let shop_name: Option<String> = db
                        .query_row(
                            "SELECT s.name FROM shops s
                             JOIN channel_shop_bindings csb
                               ON csb.organization_id=s.organization_id AND csb.shop_id=s.id
                             WHERE csb.organization_id=?1 AND csb.channel_id=?2
                             ORDER BY s.id LIMIT 1",
                            params![self.org, channel_id],
                            |r| r.get(0),
                        )
                        .ok();
                    if let (Some(hid), Some(sname)) = (link_hid, shop_name) {
                        if let Some(rest) = hid.strip_prefix("ads_bridge:") {
                            if let Ok(remote_cid) = rest.parse::<i64>() {
                                (None, Some((sname, remote_cid)))
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        };

        if token.is_none() && bridge_ctx.is_none() {
            return Err(ProviderError::new("channel_token_missing", 409));
        }

        let sub_res: Result<Value, ProviderError> = if let Some(ref tok) = token {
            self.providers
                .subscribe_page_webhooks(&subscribe_target_ext, tok, eff_fields)
        } else {
            let (ref sname, rcid) = bridge_ctx.as_ref().unwrap();
            let bridge = self
                .hub_client
                .as_ref()
                .and_then(|h| h.ads_bridge.as_ref())
                .ok_or_else(|| ProviderError::new("internal_bridge_not_configured", 503))?;
            bridge
                .platform_call(
                    sname,
                    *rcid,
                    "POST",
                    &format!("{subscribe_target_ext}/subscribed_apps"),
                    Some(json!({ "subscribed_fields": eff_fields })),
                    None,
                    true,
                    &subscribe_target_ext,
                )
                .map_err(|e| ProviderError::new(e.code, e.status))
        };

        let now = now_unix();
        match sub_res {
            Ok(_) => {
                store::with_write_tx(&self.path, |db| -> Result<(), ProviderError> {
                    db.execute(
                        "UPDATE channels
                         SET webhook_subscribed_at=?1, webhook_fields=?2, webhook_error=''
                         WHERE organization_id=?3 AND id=?4",
                        params![now, eff_fields, self.org, channel_id],
                    )?;
                    audit::append(
                        db,
                        &self.org,
                        "owner",
                        "channel.webhook_subscribed",
                        &channel_id.to_string(),
                        &json!({
                            "external_id": subscribe_target_ext,
                            "fields": eff_fields,
                        }),
                    )?;
                    Ok(())
                })?;
                Ok(json!({
                    "ok": true,
                    "channel_id": channel_id,
                    "webhook_subscribed": true,
                    "webhook_subscribed_at": now,
                    "webhook_fields": eff_fields,
                }))
            }
            Err(err) => {
                let _ = store::with_write_tx(&self.path, |db| -> Result<(), ProviderError> {
                    db.execute(
                        "UPDATE channels SET webhook_error=?1 WHERE organization_id=?2 AND id=?3",
                        params![err.code, self.org, channel_id],
                    )?;
                    Ok(())
                });
                Err(err)
            }
        }
    }

    /// Materializes a Meta webhook change (`feed` / `comments` / `mentions` / `messages`) into SQLite
    /// and triggers AI rubric evaluation (`evaluator::evaluate_and_persist`).
    pub fn process_meta_webhook_change(
        &self,
        entry_id: &str,
        field: &str,
        value: &Value,
        actor: &str,
    ) -> Result<Value, String> {
        let entry_clean = entry_id.trim();
        if entry_clean.is_empty() {
            return Ok(json!({"ok": true, "ignored": "empty_entry_id"}));
        }

        let ch_opt = {
            let db = store::connect_readonly(&self.path).map_err(|e| e.to_string())?;
            query_one_map(
                &db,
                "SELECT * FROM channels WHERE organization_id=? AND external_id=? AND approved=1",
                &[self.org.clone().into(), entry_clean.to_string().into()],
            )
        };
        let Some(ch) = ch_opt else {
            return Ok(json!({"ok": true, "ignored": "unapproved_or_unknown_channel"}));
        };

        let channel_id = ch.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let now = now_unix();

        if field == "messages" {
            let sender_id = value
                .get("sender")
                .and_then(|s| s.get("id"))
                .and_then(|v| v.as_str())
                .or_else(|| value.get("from").and_then(|f| f.get("id")).and_then(|v| v.as_str()))
                .unwrap_or("customer_dm");
            let sender_name = value
                .get("sender")
                .and_then(|s| s.get("name"))
                .and_then(|v| v.as_str())
                .or_else(|| value.get("from").and_then(|f| f.get("name")).and_then(|v| v.as_str()))
                .unwrap_or("Messenger User");
            let msg_text = value
                .get("message")
                .and_then(|m| {
                    m.as_str()
                        .or_else(|| m.get("text").and_then(|t| t.as_str()))
                })
                .or_else(|| value.get("text").and_then(|v| v.as_str()))
                .unwrap_or("");
            if msg_text.trim().is_empty() {
                return Ok(json!({"ok": true, "ignored": "empty_message"}));
            }
            let msg_ext = value
                .get("mid")
                .or_else(|| value.get("id"))
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| format!("wh_msg_{channel_id}_{now}"));
            let conv_ext = format!("dm_{entry_clean}_{sender_id}");

            return store::with_write_tx_str(&self.path, |db| {
                let preview: String = msg_text.chars().take(180).collect();
                db.execute(
                    "INSERT INTO conversations
                       (organization_id, channel_id, external_id, participant_id, participant_name,
                        status, last_message_preview, unread_count, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, 1, ?7)
                     ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                        status='open',
                        last_message_preview=excluded.last_message_preview,
                        unread_count=conversations.unread_count+1,
                        updated_at=excluded.updated_at",
                    params![
                        self.org,
                        channel_id,
                        conv_ext,
                        sender_id,
                        sender_name,
                        preview,
                        now
                    ],
                )
                .map_err(|e| e.to_string())?;
                let conv_id: i64 = db
                    .query_row(
                        "SELECT id FROM conversations WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                        params![self.org, channel_id, conv_ext],
                        |r| r.get(0),
                    )
                    .map_err(|e| e.to_string())?;
                db.execute(
                    "INSERT INTO messages
                       (organization_id, conversation_id, channel_id, external_id, direction,
                        sender_id, sender_name, text, status, created_at)
                     VALUES (?1, ?2, ?3, ?4, 'inbound', ?5, ?6, ?7, 'delivered', ?8)
                     ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                        text=excluded.text",
                    params![
                        self.org,
                        conv_id,
                        channel_id,
                        msg_ext,
                        sender_id,
                        sender_name,
                        msg_text,
                        now
                    ],
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({
                    "ok": true,
                    "kind": "message",
                    "conversation_id": conv_id,
                }))
            });
        }

        // Feed / comment / mention delta
        let verb = value
            .get("verb")
            .and_then(|v| v.as_str())
            .unwrap_or("add");
        let item_type = value
            .get("item")
            .and_then(|v| v.as_str())
            .unwrap_or("comment");
        let post_ext = value
            .get("post_id")
            .or_else(|| value.get("media").and_then(|m| m.get("id")))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| format!("{entry_clean}_webhook_post"));
        let comment_ext_opt = value
            .get("comment_id")
            .or_else(|| value.get("id"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && *s != post_ext)
            .map(String::from);

        if verb == "remove" || verb == "delete" {
            if let Some(ref c_ext) = comment_ext_opt {
                return store::with_write_tx_str(&self.path, |db| {
                    db.execute(
                        "UPDATE comments SET deleted_at=?1 WHERE organization_id=?2 AND channel_id=?3 AND external_id=?4",
                        params![now, self.org, channel_id, c_ext],
                    )
                    .map_err(|e| e.to_string())?;
                    Ok(json!({"ok": true, "deleted_comment_external_id": c_ext}))
                });
            }
        }

        let inline_msg = value
            .get("message")
            .or_else(|| value.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // If webhook contains inline comment text, persist directly and evaluate immediately
        if let Some(c_ext) = comment_ext_opt {
            if !inline_msg.trim().is_empty() || item_type == "comment" || field == "comments" {
                let parent_ext = value
                    .get("parent_id")
                    .and_then(|v| v.as_str())
                    .filter(|p| !p.is_empty() && *p != post_ext);
                let from_obj = value.get("from").cloned().unwrap_or_else(|| json!({}));
                let author_id = from_obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let author_name = from_obj
                    .get("name")
                    .or_else(|| from_obj.get("username"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Social User");
                let permalink = value
                    .get("permalink_url")
                    .or_else(|| value.get("post").and_then(|p| p.get("permalink_url")))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| format!("https://www.facebook.com/{post_ext}"));
                let created_ts = value
                    .get("created_time")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(now);
                let is_by_channel = if author_id == entry_clean { 1 } else { 0 };

                return store::with_write_tx_str(&self.path, |db| {
                    db.execute(
                        "INSERT INTO posts
                           (organization_id, channel_id, external_id, permalink, kind, caption,
                            published_at, author_is_channel, media_json, first_seen, last_synced)
                         VALUES (?1, ?2, ?3, ?4, 'post', '', ?5, 1, '[]', ?6, ?6)
                         ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                            last_synced=excluded.last_synced",
                        params![self.org, channel_id, post_ext, permalink, created_ts, now],
                    )
                    .map_err(|e| e.to_string())?;
                    let post_id: i64 = db
                        .query_row(
                            "SELECT id FROM posts WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                            params![self.org, channel_id, post_ext],
                            |r| r.get(0),
                        )
                        .map_err(|e| e.to_string())?;

                    db.execute(
                        "INSERT INTO comments
                           (organization_id, post_id, channel_id, external_id, source, verified,
                            parent_external_id, author_external_id, author_name, text,
                            created_at, is_by_channel, raw_json)
                         VALUES (?1, ?2, ?3, ?4, 'api', 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                         ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                            text=excluded.text,
                            raw_json=excluded.raw_json",
                        params![
                            self.org,
                            post_id,
                            channel_id,
                            c_ext,
                            parent_ext,
                            author_id,
                            author_name,
                            inline_msg,
                            created_ts,
                            is_by_channel,
                            serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    let cm_id: i64 = db
                        .query_row(
                            "SELECT id FROM comments WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                            params![self.org, channel_id, c_ext],
                            |r| r.get(0),
                        )
                        .map_err(|e| e.to_string())?;

                    let ev = evaluator::evaluate_and_persist(db, &self.org, cm_id, None, actor)?;
                    db.execute(
                        "UPDATE channels SET last_synced_at=?1 WHERE organization_id=?2 AND id=?3",
                        params![now, self.org, channel_id],
                    )
                    .map_err(|e| e.to_string())?;

                    Ok(json!({
                        "ok": true,
                        "kind": "comment",
                        "channel_id": channel_id,
                        "post_id": post_id,
                        "comment_id": cm_id,
                        "bucket": ev.get("bucket"),
                    }))
                });
            }
        }

        // Fallback: if webhook only carried post delta or lacked inline body, try Graph sync if token available
        match self.sync_channel(channel_id, 5, 25) {
            Ok(v) => Ok(v),
            Err(_) => Ok(json!({"ok": true, "channel_id": channel_id, "deferred_poll": true})),
        }
    }
}

pub fn capture_forensic_evidence(
    db: &Connection,
    organization_id: &str,
    target_url: &str,
    title: &str,
    comment_id: Option<i64>,
    case_id_in: Option<i64>,
    actor: &str,
) -> Result<Value, String> {
    evidence::capture_forensic_bundle(
        db,
        None,
        organization_id,
        target_url,
        title,
        comment_id,
        case_id_in,
        actor,
        None,
    )
}

pub fn capture_forensic_evidence_on_disk(
    db: &Connection,
    db_path: &std::path::Path,
    organization_id: &str,
    target_url: &str,
    title: &str,
    comment_id: Option<i64>,
    case_id_in: Option<i64>,
    actor: &str,
    transport: Option<&SharedTransport>,
) -> Result<Value, String> {
    let data_dir = evidence::resolve_data_dir(db_path);
    evidence::capture_forensic_bundle(
        db,
        Some(&data_dir),
        organization_id,
        target_url,
        title,
        comment_id,
        case_id_in,
        actor,
        transport,
    )
}

pub fn seed_demo_workspace(
    db: &Connection,
    organization_id: &str,
    actor: &str,
) -> Result<Value, String> {
    let now = now_unix();
    let today = Utc::now().format("%Y-%m-%d").to_string();

    db.execute(
        "INSERT OR IGNORE INTO shops (organization_id, name) VALUES (?1, ?2)",
        params![organization_id, "LuxeClaw Atelier"],
    )
    .map_err(|e| e.to_string())?;
    let shop_id: i64 = db
        .query_row(
            "SELECT id FROM shops WHERE organization_id=?1 ORDER BY id LIMIT 1",
            params![organization_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;

    let sample_channels = [
        (
            "meta",
            "meta_api",
            "fb_page",
            "235513372986478",
            "LuxeClaw Official Page",
            "@luxeclaw.official",
            "draft_only",
            24850i64,
        ),
        (
            "meta",
            "meta_api",
            "ig_account",
            "17841464987749627",
            "LuxeClaw Instagram",
            "@luxe.claw",
            "draft_only",
            18420i64,
        ),
        (
            "meta",
            "veilbrowser",
            "fb_profile",
            "fb_personal_founder",
            "Founder Personal Profile (Read-Only)",
            "@ngocle.personal",
            "draft_only",
            4950i64,
        ),
    ];

    let mut channel_ids = Vec::new();
    for (prov, adapter, kind, ext_id, name, handle, policy, followers) in sample_channels {
        db.execute(
            "INSERT INTO channels
               (organization_id, provider, adapter, kind, external_id, name, handle, approved,
                reply_policy, auto_suggest_threshold, last_synced_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, 80, ?9)
             ON CONFLICT(organization_id, provider, external_id) DO UPDATE SET
                approved=1, last_synced_at=excluded.last_synced_at",
            params![organization_id, prov, adapter, kind, ext_id, name, handle, policy, now],
        )
        .map_err(|e| e.to_string())?;
        let cid: i64 = db
            .query_row(
                "SELECT id FROM channels WHERE organization_id=?1 AND provider=?2 AND external_id=?3",
                params![organization_id, prov, ext_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        channel_ids.push(cid);
        db.execute(
            "INSERT OR IGNORE INTO channel_shop_bindings VALUES (?1, ?2, ?3)",
            params![organization_id, shop_id, cid],
        )
        .map_err(|e| e.to_string())?;
        db.execute(
            "INSERT INTO channel_snapshots
               (organization_id, channel_id, snapshot_date, followers_count, posts_count, captured_at)
             VALUES (?1, ?2, ?3, ?4, 3, ?5)
             ON CONFLICT(organization_id, channel_id, snapshot_date) DO UPDATE SET
                followers_count=excluded.followers_count",
            params![organization_id, cid, today, followers, now],
        )
        .map_err(|e| e.to_string())?;
    }

    let (fb_cid, ig_cid, personal_cid) = (channel_ids[0], channel_ids[1], channel_ids[2]);
    let sample_posts = [
        (
            fb_cid,
            "235513372986478_901",
            "https://www.facebook.com/luxeclaw/posts/901",
            "post",
            "Royal Fantasy 3D Cat-Eye Press-On Nails — Handcrafted salon luxury in 10 minutes. Custom Almond & Coffin sizing available with 48h tracked EU shipping.",
        ),
        (
            ig_cid,
            "17841464987749627_902",
            "https://www.instagram.com/p/LuxeClaw902/",
            "reel",
            "MoonCake Lantern & Velvet Chrome Collection — Reusable up to 5 times with our gentle jelly tab + pro glue kit.",
        ),
        (
            personal_cid,
            "fb_personal_post_903",
            "https://www.facebook.com/ngocle/posts/903",
            "post",
            "Weekend reflection: Building an AI system to curate friend requests by mindset and constructive values rather than mutual friend count.",
        ),
    ];

    let mut post_ids = Vec::new();
    for (cid, ext_id, link, kind, caption) in sample_posts {
        db.execute(
            "INSERT INTO posts
               (organization_id, channel_id, external_id, permalink, kind, caption,
                published_at, author_is_channel, media_json, first_seen, last_synced)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10)
             ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                caption=excluded.caption, last_synced=excluded.last_synced",
            params![
                organization_id,
                cid,
                ext_id,
                link,
                kind,
                caption,
                now - 7200,
                r#"[{"type":"photo","url":"/icon.svg"}]"#,
                now - 7200,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        let pid: i64 = db
            .query_row(
                "SELECT id FROM posts WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                params![organization_id, cid, ext_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        post_ids.push(pid);

        for day_offset in (0..=4).rev() {
            let snap_day = Utc
                .timestamp_opt(now - day_offset * 86400, 0)
                .single()
                .map(|dt| dt.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| today.clone());
            let factor = 5 - day_offset;
            db.execute(
                "INSERT INTO post_snapshots
                   (organization_id, post_id, snapshot_date, impressions, reach, reactions,
                    comments_count, shares, saves, plays, clicks, captured_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(organization_id, post_id, snapshot_date) DO UPDATE SET
                    impressions=excluded.impressions, reach=excluded.reach, reactions=excluded.reactions",
                params![
                    organization_id,
                    pid,
                    snap_day,
                    1200 * factor,
                    950 * factor,
                    85 * factor,
                    6 * factor,
                    12 * factor,
                    28 * factor,
                    1800 * factor,
                    44 * factor,
                    now
                ],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    let sample_comments = [
        (
            post_ids[0],
            fb_cid,
            "cm_9001",
            "api",
            1,
            "10008911201",
            "Nguyen Hoang Oanh",
            "Paris, France · Repeat buyer",
            "Shop ơi bộ Royal Fantasy form Almond size S giá bao nhiêu ạ? Mình ở Paris thì ship bao lâu nhận được nhỉ? Tư vấn giúp mình nhé!",
            now - 1800,
        ),
        (
            post_ids[1],
            ig_cid,
            "cm_9002",
            "api",
            1,
            "ig_minhvan_92",
            "Minh Vân",
            "@minhvan.atelier · 3 mutuals",
            "Cho em hỏi mẫu Velvet Chrome này dán bằng keo jelly tab có bền khi gõ máy tính nhiều không chị ơi? Em muốn đặt 2 bộ size M ạ.",
            now - 2400,
        ),
        (
            post_ids[0],
            fb_cid,
            "cm_9003",
            "api",
            1,
            "10007741902",
            "Hải Yến",
            "Lyon, France · VIP Customer",
            "Bộ trước mình mua bên shop đẹp xuất sắc luôn, ai nhìn cũng tưởng làm ngoài tiệm 80 euro! Cảm ơn shop nhiều lắm ạ ❤️",
            now - 3600,
        ),
        (
            post_ids[0],
            fb_cid,
            "cm_9004",
            "api",
            1,
            "10005531888",
            "Dương Tuấn",
            "Marseille, France",
            "Shop kiểm tra giúp mình đơn #LC4829 với ạ, mình đặt từ thứ 4 mà chưa nhận được mã vận đơn, ngón cái hơi rộng mình muốn đổi size.",
            now - 4200,
        ),
        (
            post_ids[1],
            ig_cid,
            "cm_9005",
            "api",
            1,
            "clone_spam_771",
            "Thịnh Lynx",
            "Suspected bot · 0 followers",
            "Tuyển cộng tác viên kiếm tiền tại nhà 500k/ngày không cần vốn, vào ngay https://t.me/spam_link_demo nhận quà miễn phí!",
            now - 5100,
        ),
        (
            post_ids[2],
            personal_cid,
            "cm_9006",
            "browser",
            0,
            "100099887766",
            "Tài Khoản Công Kích",
            "UID 100099887766 · Personal Post Thread",
            "Shop này lừa đảo treo đầu dê bán thịt chó, mình sẽ đăng bài bôi nhọ và phốt khắp các hội nhóm cho sập tiệm luôn!",
            now - 900,
        ),
    ];

    let mut comment_ids = Vec::new();
    for (pid, cid, ext_id, src, ver, auth_id, auth_name, auth_meta, text, ts) in sample_comments {
        db.execute(
            "INSERT INTO comments
               (organization_id, post_id, channel_id, external_id, source, verified,
                author_external_id, author_name, author_meta, text, created_at, like_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 2)
             ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                text=excluded.text, author_meta=excluded.author_meta",
            params![
                organization_id,
                pid,
                cid,
                ext_id,
                src,
                ver,
                auth_id,
                auth_name,
                auth_meta,
                text,
                ts
            ],
        )
        .map_err(|e| e.to_string())?;
        let cm_id: i64 = db
            .query_row(
                "SELECT id FROM comments WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                params![organization_id, cid, ext_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        comment_ids.push(cm_id);
        evaluator::evaluate_and_persist(db, organization_id, cm_id, None, "seed:ai")?;
    }

    let fleet_rows = [
        (
            "LuxeClaw Official Graph API",
            "facebook",
            "owned_page",
            "meta_api",
            "meta_page_235513372986478",
            "Direct Meta Graph",
            "FR",
            "healthy",
            500i64,
            100i64,
        ),
        (
            "Founder Main FB (Strict Read-Only)",
            "facebook",
            "personal_main",
            "veilbrowser",
            "vb_prof_founder_01",
            "82.64.110.14",
            "FR",
            "healthy",
            80,
            0,
        ),
        (
            "Care Consultant #01 (Camoufox 152 + Xray TUN)",
            "facebook",
            "care_consultant",
            "veilbrowser",
            "vb_prof_consult_01",
            "91.168.42.88",
            "FR",
            "healthy",
            160,
            35,
        ),
        (
            "Care Consultant #02 (Camoufox 152 + Passkey)",
            "instagram",
            "care_consultant",
            "veilbrowser",
            "vb_prof_consult_02",
            "91.168.42.89",
            "FR",
            "healthy",
            160,
            35,
        ),
        (
            "Forensic Evidence Scout #01 (VeilBrowser)",
            "facebook",
            "evidence_scout",
            "veilbrowser",
            "vb_prof_scout_01",
            "176.158.19.44",
            "FR",
            "healthy",
            100,
            0,
        ),
        (
            "Orbine Mobile ARM64 #01 (Pixel 7 + Xray TPROXY)",
            "tiktok",
            "care_consultant",
            "orbine_mobile",
            "orbine_arm64_pixel7_01",
            "37.164.91.12",
            "FR",
            "healthy",
            200,
            40,
        ),
    ];

    for (label, platform, role, adapter, prof_id, ip, country, health, r_budget, w_budget) in
        fleet_rows
    {
        db.execute(
            "INSERT INTO account_runtimes
               (organization_id, shop_id, label, platform, account_role, adapter, runtime_profile_id,
                expected_exit_ip, expected_country, health_status, daily_read_budget, daily_write_budget, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(organization_id, adapter, runtime_profile_id) DO UPDATE SET
                label=excluded.label, updated_at=excluded.updated_at",
            params![
                organization_id,
                shop_id,
                label,
                platform,
                role,
                adapter,
                prof_id,
                ip,
                country,
                health,
                r_budget,
                w_budget,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
    }

    db.execute(
        "INSERT INTO conversations
           (organization_id, channel_id, external_id, participant_id, participant_name,
            status, assigned_to, last_message_preview, unread_count, updated_at)
         VALUES (?1, ?2, 'conv_9001', '10008911201', 'Nguyen Hoang Oanh', 'open', '',
                 'Shop ơi tư vấn thêm cho mình mẫu Almond size S nhé!', 1, ?3)
         ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
            updated_at=excluded.updated_at",
        params![organization_id, fb_cid, now - 600],
    )
    .map_err(|e| e.to_string())?;
    let conv_id: i64 = db
        .query_row(
            "SELECT id FROM conversations WHERE organization_id=?1 AND channel_id=?2 AND external_id='conv_9001'",
            params![organization_id, fb_cid],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO messages
           (organization_id, conversation_id, channel_id, external_id, direction,
            sender_id, sender_name, text, created_at)
         VALUES (?1, ?2, ?3, 'msg_9001_1', 'inbound', '10008911201', 'Nguyen Hoang Oanh',
                 'Shop ơi tư vấn thêm cho mình mẫu Almond size S nhé!', ?4)
         ON CONFLICT(organization_id, channel_id, external_id) DO NOTHING",
        params![organization_id, conv_id, fb_cid, now - 600],
    )
    .map_err(|e| e.to_string())?;

    let has_lead: bool = db
        .query_row(
            "SELECT 1 FROM leads WHERE organization_id=?1 AND external_id='lead_demo_01'",
            params![organization_id],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !has_lead {
        db.execute(
            "INSERT INTO leads
               (organization_id, shop_id, channel_id, source, external_id, customer_name,
                contact_handle, intent_score, status, notes, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'comment', 'lead_demo_01', 'Nguyen Hoang Oanh',
                     'fb:10008911201', 92.5, 'qualified',
                     'Interested in Royal Fantasy Almond size S + Paris 48h shipping', ?4, ?5)",
            params![organization_id, shop_id, fb_cid, now, now],
        )
        .map_err(|e| e.to_string())?;
    }

    let has_handoff: bool = db
        .query_row(
            "SELECT 1 FROM ticket_handoffs WHERE organization_id=?1 AND comment_id=?2",
            params![organization_id, comment_ids[3]],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !has_handoff {
        db.execute(
            "INSERT INTO ticket_handoffs
               (organization_id, shop_id, channel_id, comment_id, conversation_id, priority,
                assignee, summary, status, created_by, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, NULL, 'high', 'fulfillment-eu',
                     'Order #LC4829 tracking & thumb size exchange request', 'open', ?5, ?6, ?7)",
            params![organization_id, shop_id, fb_cid, comment_ids[3], actor, now, now],
        )
        .map_err(|e| e.to_string())?;
    }

    capture_forensic_evidence(
        db,
        organization_id,
        "https://www.facebook.com/ngocle/posts/903?comment_id=9006",
        "Defamation Case #01 · UID 100099887766",
        Some(*comment_ids.last().unwrap()),
        None,
        actor,
    )?;

    audit::append(
        db,
        organization_id,
        actor,
        "workspace.demo_seeded",
        &shop_id.to_string(),
        &json!({
            "channels": channel_ids.len(),
            "posts": post_ids.len(),
            "comments": comment_ids.len(),
        }),
    )
    .map_err(|e| e.to_string())?;

    Ok(json!({
        "ok": true,
        "shop_id": shop_id,
        "channels": channel_ids.len(),
        "comments": comment_ids.len(),
    }))
}

pub fn purge_demo_workspace(
    db: &Connection,
    organization_id: &str,
    actor: &str,
) -> Result<Value, String> {
    let demo_cm_exts = [
        "cm_9001", "cm_9002", "cm_9003", "cm_9004", "cm_9005", "cm_9006",
    ];
    let mut cm_ids = Vec::new();
    for ext in demo_cm_exts {
        for r in query_maps(
            db,
            "SELECT id FROM comments WHERE organization_id=? AND external_id=?",
            &[organization_id.to_string().into(), ext.to_string().into()],
        ) {
            if let Some(id) = r.get("id").and_then(|v| v.as_i64()) {
                cm_ids.push(id);
            }
        }
    }

    for cid in &cm_ids {
        for tbl_col in [
            ("evidence_items", "comment_id"),
            ("ticket_handoffs", "comment_id"),
            ("reply_drafts", "comment_id"),
            ("comment_actions", "comment_id"),
            ("evaluation_feedback", "comment_id"),
            ("comment_evaluations", "comment_id"),
            ("comment_states", "comment_id"),
            ("comments", "id"),
        ] {
            let sql = format!(
                "DELETE FROM {} WHERE organization_id=?1 AND {}=?2",
                tbl_col.0, tbl_col.1
            );
            db.execute(&sql, params![organization_id, cid])
                .map_err(|e| e.to_string())?;
        }
    }

    db.execute(
        "DELETE FROM evidence_items WHERE organization_id=?1 AND target_url LIKE '%ngocle/posts/903%'",
        params![organization_id],
    )
    .map_err(|e| e.to_string())?;
    db.execute(
        "DELETE FROM evidence_cases
         WHERE organization_id=?1
           AND title LIKE 'Defamation Case #01%'
           AND NOT EXISTS (
               SELECT 1 FROM evidence_items ei
               WHERE ei.organization_id=evidence_cases.organization_id AND ei.case_id=evidence_cases.id
           )",
        params![organization_id],
    )
    .map_err(|e| e.to_string())?;

    let demo_post_exts = [
        "235513372986478_901",
        "17841464987749627_902",
        "fb_personal_post_903",
    ];
    let mut post_ids = Vec::new();
    for pext in demo_post_exts {
        for r in query_maps(
            db,
            "SELECT id FROM posts
             WHERE organization_id=? AND external_id=?
               AND NOT EXISTS (
                   SELECT 1 FROM comments cm
                   WHERE cm.organization_id=posts.organization_id AND cm.post_id=posts.id
               )",
            &[organization_id.to_string().into(), pext.to_string().into()],
        ) {
            if let Some(pid) = r.get("id").and_then(|v| v.as_i64()) {
                post_ids.push(pid);
            }
        }
    }
    for pid in &post_ids {
        db.execute(
            "DELETE FROM post_snapshots WHERE organization_id=?1 AND post_id=?2",
            params![organization_id, pid],
        )
        .map_err(|e| e.to_string())?;
        db.execute(
            "DELETE FROM post_archives WHERE organization_id=?1 AND post_id=?2",
            params![organization_id, pid],
        )
        .map_err(|e| e.to_string())?;
        db.execute(
            "DELETE FROM posts WHERE organization_id=?1 AND id=?2",
            params![organization_id, pid],
        )
        .map_err(|e| e.to_string())?;
    }

    for cv in query_maps(
        db,
        "SELECT id FROM conversations WHERE organization_id=? AND external_id='conv_9001'",
        &[organization_id.to_string().into()],
    ) {
        if let Some(cvid) = cv.get("id").and_then(|v| v.as_i64()) {
            db.execute(
                "DELETE FROM messages WHERE organization_id=?1 AND conversation_id=?2",
                params![organization_id, cvid],
            )
            .map_err(|e| e.to_string())?;
            db.execute(
                "DELETE FROM ticket_handoffs WHERE organization_id=?1 AND conversation_id=?2",
                params![organization_id, cvid],
            )
            .map_err(|e| e.to_string())?;
            db.execute(
                "DELETE FROM conversations WHERE organization_id=?1 AND id=?2",
                params![organization_id, cvid],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    db.execute(
        "DELETE FROM leads WHERE organization_id=?1 AND external_id='lead_demo_01'",
        params![organization_id],
    )
    .map_err(|e| e.to_string())?;

    let mut removed_channels = 0i64;
    if let Ok(dcid) = db.query_row::<i64, _, _>(
        "SELECT id FROM channels WHERE organization_id=?1 AND external_id='fb_personal_founder'",
        params![organization_id],
        |r| r.get(0),
    ) {
        let has_posts: bool = db
            .query_row(
                "SELECT 1 FROM posts WHERE organization_id=?1 AND channel_id=?2",
                params![organization_id, dcid],
                |_| Ok(true),
            )
            .unwrap_or(false);
        let has_convs: bool = db
            .query_row(
                "SELECT 1 FROM conversations WHERE organization_id=?1 AND channel_id=?2",
                params![organization_id, dcid],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !has_posts && !has_convs {
            db.execute(
                "DELETE FROM operator_channel_preferences WHERE organization_id=?1 AND channel_id=?2",
                params![organization_id, dcid],
            )
            .map_err(|e| e.to_string())?;
            db.execute(
                "DELETE FROM channel_shop_bindings WHERE organization_id=?1 AND channel_id=?2",
                params![organization_id, dcid],
            )
            .map_err(|e| e.to_string())?;
            db.execute(
                "DELETE FROM channel_snapshots WHERE organization_id=?1 AND channel_id=?2",
                params![organization_id, dcid],
            )
            .map_err(|e| e.to_string())?;
            db.execute(
                "DELETE FROM channels WHERE organization_id=?1 AND id=?2",
                params![organization_id, dcid],
            )
            .map_err(|e| e.to_string())?;
            removed_channels = 1;
        }
    }

    let demo_prof_ids = [
        "meta_page_235513372986478",
        "vb_prof_founder_01",
        "vb_prof_consult_01",
        "vb_prof_consult_02",
        "vb_prof_scout_01",
        "orbine_arm64_pixel7_01",
    ];
    let mut rt_ids = Vec::new();
    for prof in demo_prof_ids {
        for r in query_maps(
            db,
            "SELECT id FROM account_runtimes WHERE organization_id=? AND runtime_profile_id=?",
            &[organization_id.to_string().into(), prof.to_string().into()],
        ) {
            if let Some(id) = r.get("id").and_then(|v| v.as_i64()) {
                rt_ids.push(id);
            }
        }
    }
    for rtid in &rt_ids {
        db.execute(
            "DELETE FROM runtime_leases WHERE organization_id=?1 AND runtime_id=?2",
            params![organization_id, rtid],
        )
        .map_err(|e| e.to_string())?;
        db.execute(
            "DELETE FROM account_runtimes WHERE organization_id=?1 AND id=?2",
            params![organization_id, rtid],
        )
        .map_err(|e| e.to_string())?;
    }

    let demo_shop_id: Option<i64> = db
        .query_row(
            "SELECT id FROM shops WHERE organization_id=?1 AND name='LuxeClaw Atelier'",
            params![organization_id],
            |r| r.get(0),
        )
        .ok();
    let other_shop: bool = db
        .query_row(
            "SELECT 1 FROM shops WHERE organization_id=?1 AND name!='LuxeClaw Atelier' LIMIT 1",
            params![organization_id],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if let (Some(dsid), true) = (demo_shop_id, other_shop) {
        db.execute(
            "DELETE FROM consultation_playbooks WHERE organization_id=?1 AND shop_id=?2 AND name='LuxeClaw Default Playbook'",
            params![organization_id, dsid],
        )
        .map_err(|e| e.to_string())?;
        db.execute(
            "DELETE FROM operator_channel_preferences WHERE organization_id=?1 AND shop_id=?2",
            params![organization_id, dsid],
        )
        .map_err(|e| e.to_string())?;
        db.execute(
            "DELETE FROM channel_shop_bindings WHERE organization_id=?1 AND shop_id=?2",
            params![organization_id, dsid],
        )
        .map_err(|e| e.to_string())?;
        db.execute(
            "DELETE FROM shop_connection_bindings WHERE organization_id=?1 AND shop_id=?2",
            params![organization_id, dsid],
        )
        .map_err(|e| e.to_string())?;
        let has_leads: bool = db
            .query_row(
                "SELECT 1 FROM leads WHERE organization_id=?1 AND shop_id=?2",
                params![organization_id, dsid],
                |_| Ok(true),
            )
            .unwrap_or(false);
        let has_handoffs: bool = db
            .query_row(
                "SELECT 1 FROM ticket_handoffs WHERE organization_id=?1 AND shop_id=?2",
                params![organization_id, dsid],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !has_leads && !has_handoffs {
            db.execute(
                "DELETE FROM shops WHERE organization_id=?1 AND id=?2",
                params![organization_id, dsid],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    audit::append(
        db,
        organization_id,
        actor,
        "workspace.demo_purged",
        organization_id,
        &json!({
            "removed_comments": cm_ids.len(),
            "removed_posts": post_ids.len(),
            "removed_channels": removed_channels,
        }),
    )
    .map_err(|e| e.to_string())?;

    Ok(json!({
        "ok": true,
        "removed_comments": cm_ids.len(),
        "removed_posts": post_ids.len(),
        "removed_channels": removed_channels,
        "removed_runtimes": rt_ids.len(),
    }))
}
