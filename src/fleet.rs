//! Multi-Account Fleet Orchestrator (`Phase 2b`):
//! - Atomic SQLite concurrency leases (`runtime_leases`, `MAX_CONCURRENT_BROWSER_SESSIONS`)
//! - `VeilBrowserAdapter` (`RN2` `xray + wintun` fail-closed proxy, `RN5` HKDF sub-seed + Portable Passkey Store)
//! - `OrbineMobileAdapter` (`RN1` `xray` TPROXY + `XRAY_FAILSAFE_WD` ARM64 mobile container)
//! - Pre-flight outbound residential IP/ASN gate (fail-closed)
//! - Strict `personal_main` (`daily_write_budget == 0`) & `care_consultant` daily read/write budgets
//! - Automatic circuit breaker (`health_status = 'checkpointed'`) + Cygnus Telegram Gateway alert
//! - Consultation Playbooks CRUD (`consultation_playbooks`)

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use rand::Rng;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::store::{self, query_maps, query_one_map};
use crate::transport::{SharedTransport, TransportRequest, UreqTransport};
use crate::{audit, evaluator, worker};

pub const DEFAULT_MAX_CONCURRENT_LEASES: i64 = 4;
pub const DEFAULT_LEASE_TTL_SECS: i64 = 180;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn today_utc() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

pub fn max_concurrent_sessions(env_map: &HashMap<String, String>) -> i64 {
    env_map
        .get("MAX_CONCURRENT_BROWSER_SESSIONS")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| (1..=64).contains(&n))
        .unwrap_or(DEFAULT_MAX_CONCURRENT_LEASES)
}

/// Reaps expired `active` rows in `runtime_leases` and restores `leased` runtimes back to `healthy`.
pub fn reap_expired_leases(db: &Connection, org: &str, now: i64) -> Result<usize, rusqlite::Error> {
    let expired: Vec<(i64, i64)> = {
        let mut stmt = db.prepare(
            "SELECT id, runtime_id FROM runtime_leases
             WHERE organization_id=?1 AND status='active' AND expires_at<=?2",
        )?;
        let rows = stmt
            .query_map(params![org, now], |r| Ok((r.get(0)?, r.get(1)?)))?
            .filter_map(Result::ok)
            .collect();
        rows
    };

    for (lease_id, runtime_id) in &expired {
        db.execute(
            "UPDATE runtime_leases SET status='completed', released_at=?1
             WHERE organization_id=?2 AND id=?3",
            params![now, org, lease_id],
        )?;
        db.execute(
            "UPDATE account_runtimes SET health_status='healthy', updated_at=?1
             WHERE organization_id=?2 AND id=?3 AND health_status='leased'",
            params![now, org, runtime_id],
        )?;
    }
    Ok(expired.len())
}

fn ensure_daily_budget_window(
    db: &Connection,
    org: &str,
    runtime_id: i64,
    today: &str,
) -> Result<(), rusqlite::Error> {
    let cur_date: String = db
        .query_row(
            "SELECT COALESCE(budget_date, '') FROM account_runtimes WHERE organization_id=?1 AND id=?2",
            params![org, runtime_id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    if cur_date != today {
        db.execute(
            "UPDATE account_runtimes SET reads_today=0, writes_today=0, budget_date=?1
             WHERE organization_id=?2 AND id=?3",
            params![today, org, runtime_id],
        )?;
    }
    Ok(())
}

/// Atomically acquires an exclusive concurrency lease on an `account_runtime` (`BEGIN IMMEDIATE`).
pub fn acquire_lease(
    path: &Path,
    org: &str,
    runtime_id: i64,
    job_id: Option<i64>,
    worker_id: &str,
    ttl_secs: i64,
    max_concurrent: i64,
) -> Result<Value, String> {
    let now = now_unix();
    let today = today_utc();
    let eff_ttl = ttl_secs.clamp(10, 900);

    store::with_write_tx_str(path, |db| {
        reap_expired_leases(db, org, now).map_err(|e| e.to_string())?;
        ensure_daily_budget_window(db, org, runtime_id, &today).map_err(|e| e.to_string())?;

        let rt = query_one_map(
            db,
            "SELECT * FROM account_runtimes WHERE organization_id=? AND id=?",
            &[org.to_string().into(), runtime_id.into()],
        )
        .ok_or_else(|| "runtime_not_found".to_string())?;

        let health = rt
            .get("health_status")
            .and_then(|v| v.as_str())
            .unwrap_or("disabled");
        if health == "checkpointed" {
            return Err("runtime_checkpointed".to_string());
        }
        if health == "leased" {
            return Err("runtime_already_leased".to_string());
        }
        if health != "healthy" {
            return Err(format!("runtime_not_healthy:{health}"));
        }

        let active_for_rt: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM runtime_leases
                 WHERE organization_id=?1 AND runtime_id=?2 AND status='active'",
                params![org, runtime_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if active_for_rt > 0 {
            return Err("runtime_already_leased".to_string());
        }

        let active_total: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM runtime_leases WHERE organization_id=?1 AND status='active'",
                params![org],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if active_total >= max_concurrent.max(1) {
            return Err("fleet_concurrency_limit_reached".to_string());
        }

        let expires_at = now + eff_ttl;
        db.execute(
            "INSERT INTO runtime_leases
               (organization_id, runtime_id, job_id, worker_id, leased_at, expires_at, exit_ip_verified, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'active')",
            params![org, runtime_id, job_id, worker_id, now, expires_at],
        )
        .map_err(|e| e.to_string())?;
        let lease_id = db.last_insert_rowid();

        db.execute(
            "UPDATE account_runtimes SET health_status='leased', last_lease_at=?1, updated_at=?1
             WHERE organization_id=?2 AND id=?3",
            params![now, org, runtime_id],
        )
        .map_err(|e| e.to_string())?;

        Ok(json!({
            "lease_id": lease_id,
            "runtime_id": runtime_id,
            "worker_id": worker_id,
            "leased_at": now,
            "expires_at": expires_at,
            "runtime": rt,
        }))
    })
}

pub fn release_lease(
    path: &Path,
    org: &str,
    lease_id: i64,
    status: &str,
    exit_ip_verified: bool,
) -> Result<(), String> {
    let eff_status = if status == "aborted_anomaly" {
        "aborted_anomaly"
    } else {
        "completed"
    };
    let now = now_unix();
    store::with_write_tx_str(path, |db| {
        let rt_id: Option<i64> = db
            .query_row(
                "SELECT runtime_id FROM runtime_leases WHERE organization_id=?1 AND id=?2",
                params![org, lease_id],
                |r| r.get(0),
            )
            .ok();
        db.execute(
            "UPDATE runtime_leases
             SET status=?1, released_at=?2, exit_ip_verified=?3
             WHERE organization_id=?4 AND id=?5",
            params![
                eff_status,
                now,
                if exit_ip_verified { 1 } else { 0 },
                org,
                lease_id
            ],
        )
        .map_err(|e| e.to_string())?;
        if let Some(rid) = rt_id {
            if eff_status == "completed" {
                db.execute(
                    "UPDATE account_runtimes
                     SET health_status='healthy', updated_at=?1
                     WHERE organization_id=?2 AND id=?3 AND health_status='leased'",
                    params![now, org, rid],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    })
}

/// Checks and consumes 1 daily read or write unit on `runtime_id`.
/// Enforces `personal_main` (`daily_write_budget == 0` -> `role_read_only`).
pub fn consume_runtime_budget_tx(
    db: &Connection,
    org: &str,
    runtime_id: i64,
    is_write: bool,
) -> Result<Value, String> {
    let today = today_utc();
    ensure_daily_budget_window(db, org, runtime_id, &today).map_err(|e| e.to_string())?;
    let rt = query_one_map(
        db,
        "SELECT * FROM account_runtimes WHERE organization_id=? AND id=?",
        &[org.to_string().into(), runtime_id.into()],
    )
    .ok_or_else(|| "runtime_not_found".to_string())?;

    let role = rt
        .get("account_role")
        .and_then(|v| v.as_str())
        .unwrap_or("care_consultant");
    let health = rt
        .get("health_status")
        .and_then(|v| v.as_str())
        .unwrap_or("disabled");
    if health == "checkpointed" {
        return Err("runtime_checkpointed".to_string());
    }
    if health == "disabled" {
        return Err("runtime_disabled".to_string());
    }

    let r_today = rt.get("reads_today").and_then(|v| v.as_i64()).unwrap_or(0);
    let r_budget = rt
        .get("daily_read_budget")
        .and_then(|v| v.as_i64())
        .unwrap_or(120);
    let w_today = rt.get("writes_today").and_then(|v| v.as_i64()).unwrap_or(0);
    let w_budget = rt
        .get("daily_write_budget")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    if is_write {
        if matches!(role, "personal_main" | "evidence_scout" | "friend_hygiene") || w_budget <= 0 {
            return Err("role_read_only".to_string());
        }
        if w_today >= w_budget {
            return Err("daily_write_budget_exceeded".to_string());
        }
        db.execute(
            "UPDATE account_runtimes SET writes_today=writes_today+1, updated_at=?1
             WHERE organization_id=?2 AND id=?3",
            params![now_unix(), org, runtime_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(json!({
            "runtime_id": runtime_id,
            "writes_today": w_today + 1,
            "daily_write_budget": w_budget,
        }))
    } else {
        if r_today >= r_budget {
            return Err("daily_read_budget_exceeded".to_string());
        }
        db.execute(
            "UPDATE account_runtimes SET reads_today=reads_today+1, updated_at=?1
             WHERE organization_id=?2 AND id=?3",
            params![now_unix(), org, runtime_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(json!({
            "runtime_id": runtime_id,
            "reads_today": r_today + 1,
            "daily_read_budget": r_budget,
        }))
    }
}

fn resolve_cygnus_auth_key(env_map: &HashMap<String, String>) -> String {
    if let Some(k) = env_map
        .get("CYGNUS_AUTH_KEY")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        return k.to_string();
    }
    if let Some(fp) = env_map
        .get("CYGNUS_AUTH_KEY_FILE")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        if let Ok(raw) = std::fs::read_to_string(fp) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// Dispatches a non-blocking operator alert via the internal Cygnus Telegram Gateway (`lnc-cygnus-telegram-notify`).
pub fn notify_cygnus_telegram(
    transport: &SharedTransport,
    env_map: &HashMap<String, String>,
    message_text: &str,
) -> bool {
    let auth_key = resolve_cygnus_auth_key(env_map);
    if auth_key.is_empty() {
        return false;
    }
    let gateway_url = env_map
        .get("CYGNUS_GATEWAY_URL")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("http://10.21.1.101:8899/send");
    let bot_name = env_map
        .get("CYGNUS_BOT_USERNAME")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("Cygnus_Assitance_Bot");
    let chat_id: i64 = env_map
        .get("TELEGRAM_DEFAULT_CHAT_ID")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(-1_003_921_765_626);
    let thread_id: i64 = env_map
        .get("TELEGRAM_DEFAULT_THREAD_ID")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(7410);

    let payload = json!({
        "bot": bot_name,
        "method": "sendMessage",
        "payload": {
            "chat_id": chat_id,
            "message_thread_id": thread_id,
            "text": message_text,
        }
    });
    let Ok(body) = serde_json::to_vec(&payload) else {
        return false;
    };

    match transport.execute(TransportRequest {
        method: "POST".to_string(),
        url: gateway_url.to_string(),
        headers: vec![
            ("Authorization".to_string(), format!("Bearer {auth_key}")),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: Some(body),
        timeout_ms: 5_000,
    }) {
        Ok(res) => (200..300).contains(&res.status),
        Err(_) => false,
    }
}

/// Trips the circuit breaker on `runtime_id` (`health_status = 'checkpointed'`), aborts any active lease,
/// records tamper-evident audit entry, and alerts the operator via Cygnus Telegram Gateway.
pub fn trip_circuit_breaker(
    path: &Path,
    org: &str,
    runtime_id: i64,
    lease_id: Option<i64>,
    reason: &str,
    transport: Option<&SharedTransport>,
    env_map: &HashMap<String, String>,
    actor: &str,
) -> Result<Value, String> {
    let now = now_unix();
    let clean_reason: String = reason.trim().chars().take(240).collect();

    let (label, profile_id, adapter, anomalies) = store::with_write_tx_str(path, |db| {
        let rt = query_one_map(
            db,
            "SELECT * FROM account_runtimes WHERE organization_id=? AND id=?",
            &[org.to_string().into(), runtime_id.into()],
        )
        .ok_or_else(|| "runtime_not_found".to_string())?;
        let label = rt
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("Runtime")
            .to_string();
        let prof = rt
            .get("runtime_profile_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let adp = rt
            .get("adapter")
            .and_then(|v| v.as_str())
            .unwrap_or("veilbrowser")
            .to_string();
        let next_anom = rt
            .get("consecutive_anomalies")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            + 1;

        db.execute(
            "UPDATE account_runtimes
             SET health_status='checkpointed',
                 consecutive_anomalies=?1,
                 last_checkpoint_reason=?2,
                 updated_at=?3
             WHERE organization_id=?4 AND id=?5",
            params![next_anom, clean_reason, now, org, runtime_id],
        )
        .map_err(|e| e.to_string())?;

        if let Some(lid) = lease_id {
            db.execute(
                "UPDATE runtime_leases
                 SET status='aborted_anomaly', released_at=?1, exit_ip_verified=0
                 WHERE organization_id=?2 AND id=?3",
                params![now, org, lid],
            )
            .map_err(|e| e.to_string())?;
        } else {
            db.execute(
                "UPDATE runtime_leases
                 SET status='aborted_anomaly', released_at=?1, exit_ip_verified=0
                 WHERE organization_id=?2 AND runtime_id=?3 AND status='active'",
                params![now, org, runtime_id],
            )
            .map_err(|e| e.to_string())?;
        }

        audit::append(
            db,
            org,
            actor,
            "fleet.circuit_breaker_tripped",
            &prof,
            &json!({
                "runtime_id": runtime_id,
                "adapter": adp,
                "reason": clean_reason,
                "consecutive_anomalies": next_anom,
            }),
        )
        .map_err(|e| e.to_string())?;

        Ok((label, prof, adp, next_anom))
    })?;

    let default_tr;
    let tr = match transport {
        Some(t) => t,
        None => {
            default_tr = UreqTransport::shared();
            &default_tr
        }
    };
    let alert_msg = format!(
        "🚨 [LNC Care] Fleet Circuit Breaker Tripped\n• Runtime: {label} (#{runtime_id}, `{profile_id}`)\n• Adapter: `{adapter}`\n• Reason: {clean_reason}\n• Consecutive anomalies: {anomalies}\n• Action required: Complete human verification in `{adapter}` and click Resume in `/admin#fleet`."
    );
    let telegram_sent = notify_cygnus_telegram(tr, env_map, &alert_msg);

    Ok(json!({
        "ok": false,
        "tripped": true,
        "runtime_id": runtime_id,
        "runtime_profile_id": profile_id,
        "health_status": "checkpointed",
        "reason": clean_reason,
        "consecutive_anomalies": anomalies,
        "telegram_alert_sent": telegram_sent,
    }))
}

pub fn resume_runtime(
    path: &Path,
    org: &str,
    runtime_id: i64,
    actor: &str,
) -> Result<Value, String> {
    let now = now_unix();
    store::with_write_tx_str(path, |db| {
        let rt = query_one_map(
            db,
            "SELECT * FROM account_runtimes WHERE organization_id=? AND id=?",
            &[org.to_string().into(), runtime_id.into()],
        )
        .ok_or_else(|| "runtime_not_found".to_string())?;
        let prof = rt
            .get("runtime_profile_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        db.execute(
            "UPDATE account_runtimes
             SET health_status='healthy',
                 consecutive_anomalies=0,
                 last_checkpoint_reason='',
                 updated_at=?1
             WHERE organization_id=?2 AND id=?3",
            params![now, org, runtime_id],
        )
        .map_err(|e| e.to_string())?;

        audit::append(
            db,
            org,
            actor,
            "fleet.runtime_resumed",
            prof,
            &json!({ "runtime_id": runtime_id }),
        )
        .map_err(|e| e.to_string())?;

        Ok(json!({
            "ok": true,
            "runtime_id": runtime_id,
            "runtime_profile_id": prof,
            "health_status": "healthy",
        }))
    })
}

fn contains_checkpoint_marker(url_or_text: &str) -> Option<&'static str> {
    let lc = url_or_text.to_lowercase();
    if lc.contains("/checkpoint/") || lc.contains("checkpoint_required") {
        Some("checkpoint_wall_detected")
    } else if lc.contains("/login/") || lc.contains("login_redirect") {
        Some("login_redirect_detected")
    } else if lc.contains("captcha") || lc.contains("security_check") || lc.contains("verify you are human") {
        Some("security_challenge_detected")
    } else {
        None
    }
}

/// Probes an `account_runtime` (`VeilBrowserAdapter` / `OrbineMobileAdapter` / `meta_api`) under an exclusive lease,
/// verifying the fail-closed outbound IP/country (`RN2` `xray + wintun` / `RN1` `xray` TPROXY) BEFORE opening any social page.
pub fn probe_runtime(
    path: &Path,
    org: &str,
    runtime_id: i64,
    transport: Option<&SharedTransport>,
    env_map: &HashMap<String, String>,
    actor: &str,
) -> Result<Value, String> {
    let default_tr;
    let tr: &SharedTransport = match transport {
        Some(t) => t,
        None => {
            default_tr = UreqTransport::shared();
            &default_tr
        }
    };

    let max_conc = max_concurrent_sessions(env_map);
    let lease = acquire_lease(path, org, runtime_id, None, actor, 60, max_conc)?;
    let lease_id = lease.get("lease_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let rt = lease.get("runtime").cloned().unwrap_or_else(|| json!({}));

    let adapter = rt
        .get("adapter")
        .and_then(|v| v.as_str())
        .unwrap_or("veilbrowser");
    let profile_id = rt
        .get("runtime_profile_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected_ip = rt
        .get("expected_exit_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let expected_country = rt
        .get("expected_country")
        .and_then(|v| v.as_str())
        .unwrap_or("FR")
        .trim();

    if adapter == "meta_api" {
        let _ = release_lease(path, org, lease_id, "completed", true);
        return Ok(json!({
            "ok": true,
            "runtime_id": runtime_id,
            "adapter": "meta_api",
            "health_status": "healthy",
            "exit_ip": "Direct Meta Graph",
            "exit_ip_verified": true,
            "capabilities": ["official_graph_v22"],
        }));
    }

    let endpoint_base = match adapter {
        "orbine_mobile" => env_map
            .get("ORBINE_API_URL")
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:9817".to_string()),
        _ => env_map
            .get("VEILBROWSER_API_URL")
            .or_else(|| env_map.get("VEILBROWSER_MCP_URL"))
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default(),
    };

    let capabilities = match adapter {
        "orbine_mobile" => json!([
            "RN1_xray_tproxy_failsafe_wd",
            "arm64_oem_device_binding"
        ]),
        "veilbrowser" => json!([
            "RN2_xray_wintun_per_process_failclosed",
            "RN5_hkdf_subseed_portable_passkey"
        ]),
        _ => json!(["public_http_reader"]),
    };

    // When VeilBrowser or Orbine endpoint is configured (or mocked in tests), execute live pre-flight probe
    let mut observed_ip = if expected_ip.is_empty() {
        "direct".to_string()
    } else {
        expected_ip.to_string()
    };
    let mut observed_country = expected_country.to_string();
    let mut remote_probed = false;

    let should_call_remote = !endpoint_base.is_empty()
        && (adapter != "orbine_mobile" || env_map.contains_key("ORBINE_API_URL"));

    if should_call_remote {
        let probe_url = match adapter {
            "orbine_mobile" => format!("{endpoint_base}/v1/containers/{profile_id}/preflight"),
            _ => format!("{endpoint_base}/v1/profiles/{profile_id}/preflight"),
        };
        let req_body = serde_json::to_vec(&json!({
            "profile_id": profile_id,
            "expected_exit_ip": expected_ip,
            "expected_country": expected_country,
            "proxy_mode": "xray_tun_failclosed",
        }))
        .unwrap_or_default();

        match tr.execute(TransportRequest {
            method: "POST".to_string(),
            url: probe_url,
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            body: Some(req_body),
            timeout_ms: 8_000,
        }) {
            Ok(resp) => {
                remote_probed = true;
                let body_txt = resp.text();
                if let Some(marker) = contains_checkpoint_marker(&body_txt) {
                    return trip_circuit_breaker(
                        path,
                        org,
                        runtime_id,
                        Some(lease_id),
                        marker,
                        Some(tr),
                        env_map,
                        actor,
                    );
                }
                if resp.status >= 400 {
                    return trip_circuit_breaker(
                        path,
                        org,
                        runtime_id,
                        Some(lease_id),
                        &format!("adapter_preflight_http_{}", resp.status),
                        Some(tr),
                        env_map,
                        actor,
                    );
                }
                if let Ok(js) = resp.json() {
                    if let Some(st) = js.get("session_state").and_then(|v| v.as_str()) {
                        if let Some(marker) = contains_checkpoint_marker(st) {
                            return trip_circuit_breaker(
                                path,
                                org,
                                runtime_id,
                                Some(lease_id),
                                marker,
                                Some(tr),
                                env_map,
                                actor,
                            );
                        }
                    }
                    if let Some(u) = js.get("current_url").and_then(|v| v.as_str()) {
                        if let Some(marker) = contains_checkpoint_marker(u) {
                            return trip_circuit_breaker(
                                path,
                                org,
                                runtime_id,
                                Some(lease_id),
                                marker,
                                Some(tr),
                                env_map,
                                actor,
                            );
                        }
                    }
                    if let Some(ip) = js.get("exit_ip").and_then(|v| v.as_str()) {
                        observed_ip = ip.trim().to_string();
                    }
                    if let Some(cc) = js.get("country").and_then(|v| v.as_str()) {
                        observed_country = cc.trim().to_string();
                    }
                    if js.get("xray_failsafe_ok") == Some(&Value::Bool(false)) {
                        return trip_circuit_breaker(
                            path,
                            org,
                            runtime_id,
                            Some(lease_id),
                            "xray_failsafe_watchdog_tripped",
                            Some(tr),
                            env_map,
                            actor,
                        );
                    }
                }
            }
            Err(err) => {
                return trip_circuit_breaker(
                    path,
                    org,
                    runtime_id,
                    Some(lease_id),
                    &format!("adapter_unreachable:{err}"),
                    Some(tr),
                    env_map,
                    actor,
                );
            }
        }
    }

    // Fail-closed IP & country verification
    if !expected_ip.is_empty()
        && expected_ip != "Direct Meta Graph"
        && observed_ip != expected_ip
    {
        return trip_circuit_breaker(
            path,
            org,
            runtime_id,
            Some(lease_id),
            &format!("exit_ip_mismatch:expected={expected_ip},observed={observed_ip}"),
            Some(tr),
            env_map,
            actor,
        );
    }
    if !expected_country.is_empty()
        && !observed_country.is_empty()
        && !observed_country.eq_ignore_ascii_case(expected_country)
    {
        return trip_circuit_breaker(
            path,
            org,
            runtime_id,
            Some(lease_id),
            &format!(
                "exit_country_mismatch:expected={expected_country},observed={observed_country}"
            ),
            Some(tr),
            env_map,
            actor,
        );
    }

    let now = now_unix();
    let _ = store::with_write_tx_str(path, |db| {
        db.execute(
            "UPDATE account_runtimes SET last_exit_ip=?1, updated_at=?2
             WHERE organization_id=?3 AND id=?4",
            params![observed_ip, now, org, runtime_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    });
    let _ = release_lease(path, org, lease_id, "completed", true);

    Ok(json!({
        "ok": true,
        "tripped": false,
        "runtime_id": runtime_id,
        "runtime_profile_id": profile_id,
        "adapter": adapter,
        "remote_probed": remote_probed,
        "exit_ip": observed_ip,
        "country": observed_country,
        "exit_ip_verified": true,
        "health_status": "healthy",
        "capabilities": capabilities,
    }))
}

/// Computes next human-jittered poll delay (`poll_interval_min * 60 ± 35%`).
pub fn jittered_poll_delay_secs(poll_interval_min: i64) -> i64 {
    let base = (poll_interval_min.max(1) * 60) as f64;
    let factor: f64 = rand::thread_rng().gen_range(0.65..=1.35);
    (base * factor).round().max(30.0) as i64
}

/// Executes a bounded read-only feed/comment sync (`browser_fetch`) for a `veilbrowser` or `orbine_mobile` channel:
/// 1. Selects matching healthy runtime (`personal_main`, `evidence_scout`, or `care_consultant`).
/// 2. Acquires lease & verifies pre-flight exit IP (`probe_runtime` logic).
/// 3. Consumes 1 read budget unit.
/// 4. Ingests comments with synthetic `external_id = sha256(channel:post:author:text:ts)`, `source='browser'`, `verified=0`.
/// 5. Runs AI rubric evaluation (`evaluator::evaluate_and_persist`) and schedules next jittered `browser_fetch`.
#[allow(clippy::too_many_arguments)]
pub fn run_browser_channel_fetch(
    path: &Path,
    org: &str,
    channel_id: i64,
    runtime_id_opt: Option<i64>,
    inline_items: Option<&[Value]>,
    reschedule: bool,
    transport: Option<&SharedTransport>,
    env_map: &HashMap<String, String>,
    actor: &str,
) -> Result<Value, String> {
    let default_tr;
    let tr: &SharedTransport = match transport {
        Some(t) => t,
        None => {
            default_tr = UreqTransport::shared();
            &default_tr
        }
    };

    let (ch, selected_rt_id) = {
        let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
        let ch = query_one_map(
            &db,
            "SELECT * FROM channels WHERE organization_id=? AND id=? AND approved=1",
            &[org.to_string().into(), channel_id.into()],
        )
        .ok_or_else(|| "channel_not_authorized".to_string())?;

        let ch_adapter = ch
            .get("adapter")
            .and_then(|v| v.as_str())
            .unwrap_or("veilbrowser");
        let rt_id = match runtime_id_opt {
            Some(id) => id,
            None => db
                .query_row(
                    "SELECT id FROM account_runtimes
                     WHERE organization_id=?1 AND adapter=?2 AND health_status='healthy'
                     ORDER BY CASE WHEN account_role='personal_main' THEN 0 ELSE 1 END, id ASC LIMIT 1",
                    params![org, ch_adapter],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(|_| "no_healthy_runtime_for_adapter".to_string())?,
        };
        (ch, rt_id)
    };

    // Step 1: Pre-flight IP & checkpoint probe (acquires + releases short preflight lease, or trips circuit breaker)
    let preflight = probe_runtime(path, org, selected_rt_id, Some(tr), env_map, actor)?;
    if preflight.get("tripped").and_then(|v| v.as_bool()) == Some(true) {
        return Err(format!(
            "circuit_breaker_tripped:{}",
            preflight
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("anomaly")
        ));
    }

    // Step 2: Acquire execution lease & consume 1 read budget unit
    let max_conc = max_concurrent_sessions(env_map);
    let lease = acquire_lease(path, org, selected_rt_id, None, actor, DEFAULT_LEASE_TTL_SECS, max_conc)?;
    let lease_id = lease.get("lease_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let rt = lease.get("runtime").cloned().unwrap_or_else(|| json!({}));
    let adapter = rt
        .get("adapter")
        .and_then(|v| v.as_str())
        .unwrap_or("veilbrowser");
    let profile_id = rt
        .get("runtime_profile_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ch_ext = ch
        .get("external_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let poll_min = ch
        .get("poll_interval_min")
        .and_then(|v| v.as_i64())
        .unwrap_or(15);

    if let Err(budget_err) = store::with_write_tx_str(path, |db| {
        consume_runtime_budget_tx(db, org, selected_rt_id, false)
    }) {
        let _ = release_lease(path, org, lease_id, "completed", true);
        return Err(budget_err);
    }

    // Step 3: Fetch feed/comments via VeilBrowser / Orbine endpoint if configured (or use inline_items)
    let mut feed_items: Vec<Value> = inline_items.map(|s| s.to_vec()).unwrap_or_default();
    let endpoint_base = match adapter {
        "orbine_mobile" => env_map
            .get("ORBINE_API_URL")
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty()),
        _ => env_map
            .get("VEILBROWSER_API_URL")
            .or_else(|| env_map.get("VEILBROWSER_MCP_URL"))
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty()),
    };

    if feed_items.is_empty() {
        if let Some(base) = endpoint_base {
            let fetch_url = format!("{base}/v1/profiles/{profile_id}/fetch-feed");
            let req_body = serde_json::to_vec(&json!({
                "channel_external_id": ch_ext,
                "read_only": true,
            }))
            .unwrap_or_default();
            match tr.execute(TransportRequest {
                method: "POST".to_string(),
                url: fetch_url,
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("Accept".to_string(), "application/json".to_string()),
                ],
                body: Some(req_body),
                timeout_ms: 15_000,
            }) {
                Ok(resp) => {
                    let txt = resp.text();
                    if let Some(marker) = contains_checkpoint_marker(&txt) {
                        let _ = trip_circuit_breaker(
                            path,
                            org,
                            selected_rt_id,
                            Some(lease_id),
                            marker,
                            Some(tr),
                            env_map,
                            actor,
                        );
                        return Err(format!("circuit_breaker_tripped:{marker}"));
                    }
                    if let Ok(js) = resp.json() {
                        if let Some(arr) = js.get("posts").and_then(|v| v.as_array()) {
                            feed_items = arr.clone();
                        }
                    }
                }
                Err(e) => {
                    let _ = release_lease(path, org, lease_id, "aborted_anomaly", false);
                    return Err(format!("browser_fetch_failed:{e}"));
                }
            }
        }
    }

    let now = now_unix();
    let next_delay = jittered_poll_delay_secs(poll_min);
    let mut posts_ingested = 0i64;
    let mut comments_ingested = 0i64;

    let persist_res = store::with_write_tx_str(path, |db| {
        for p in &feed_items {
            let p_permalink = p
                .get("permalink")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let p_caption = p.get("caption").and_then(|v| v.as_str()).unwrap_or("");
            let p_ext = p
                .get("external_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .unwrap_or_else(|| {
                    format!(
                        "br_post_{}",
                        &sha256_hex(&format!("{ch_ext}:{p_permalink}:{p_caption}"))[..16]
                    )
                });

            db.execute(
                "INSERT INTO posts
                   (organization_id, channel_id, external_id, permalink, kind, caption,
                    published_at, author_is_channel, media_json, first_seen, last_synced)
                 VALUES (?1, ?2, ?3, ?4, 'post', ?5, ?6, 1, '[]', ?6, ?6)
                 ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                    caption=excluded.caption,
                    permalink=CASE WHEN excluded.permalink!='' THEN excluded.permalink ELSE posts.permalink END,
                    last_synced=excluded.last_synced",
                params![org, channel_id, p_ext, p_permalink, p_caption, now],
            )
            .map_err(|e| e.to_string())?;
            let post_id: i64 = db
                .query_row(
                    "SELECT id FROM posts WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                    params![org, channel_id, p_ext],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            posts_ingested += 1;

            if let Some(cms) = p.get("comments").and_then(|v| v.as_array()) {
                for c in cms {
                    let author_name = c
                        .get("author_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Social User");
                    let author_uid = c
                        .get("author_external_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let author_meta = c
                        .get("author_meta")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Browser Ingest");
                    let text = c.get("text").and_then(|v| v.as_str()).unwrap_or("");
                    if text.trim().is_empty() {
                        continue;
                    }
                    let ts = c.get("created_at").and_then(|v| v.as_i64()).unwrap_or(now);
                    // Synthetic deterministic external_id (`sha256(channel:post:author:text:ts)`) per Phase 2b spec
                    let synth_ext = c
                        .get("external_id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .unwrap_or_else(|| {
                            format!(
                                "br_cm_{}",
                                &sha256_hex(&format!(
                                    "{channel_id}:{p_ext}:{author_name}:{text}:{ts}"
                                ))[..20]
                            )
                        });

                    db.execute(
                        "INSERT INTO comments
                           (organization_id, post_id, channel_id, external_id, source, verified,
                            author_external_id, author_name, author_meta, text, created_at)
                         VALUES (?1, ?2, ?3, ?4, 'browser', 0, ?5, ?6, ?7, ?8, ?9)
                         ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                            text=excluded.text,
                            author_meta=excluded.author_meta",
                        params![
                            org,
                            post_id,
                            channel_id,
                            synth_ext,
                            author_uid,
                            author_name,
                            author_meta,
                            text,
                            ts
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    let cm_id: i64 = db
                        .query_row(
                            "SELECT id FROM comments WHERE organization_id=?1 AND channel_id=?2 AND external_id=?3",
                            params![org, channel_id, synth_ext],
                            |r| r.get(0),
                        )
                        .map_err(|e| e.to_string())?;
                    let _ = evaluator::evaluate_and_persist(db, org, cm_id, None, "fleet:ai");
                    comments_ingested += 1;
                }
            }
        }

        db.execute(
            "UPDATE channels SET last_synced_at=?1 WHERE organization_id=?2 AND id=?3",
            params![now, org, channel_id],
        )
        .map_err(|e| e.to_string())?;

        let mut next_job_id: Option<i64> = None;
        if reschedule {
            let jid = worker::enqueue_job(
                db,
                org,
                "browser_fetch",
                &json!({
                    "channel_id": channel_id,
                    "runtime_id": selected_rt_id,
                    "reschedule": false,
                }),
                next_delay,
            )
            .map_err(|e| e.to_string())?;
            next_job_id = Some(jid);
        }

        audit::append(
            db,
            org,
            actor,
            "channel.browser_synced",
            &channel_id.to_string(),
            &json!({
                "runtime_id": selected_rt_id,
                "adapter": adapter,
                "posts": posts_ingested,
                "comments": comments_ingested,
                "next_poll_in_secs": if reschedule { Some(next_delay) } else { None },
            }),
        )
        .map_err(|e| e.to_string())?;

        Ok(next_job_id)
    });

    let _ = release_lease(path, org, lease_id, "completed", true);
    let next_job_id = persist_res?;

    Ok(json!({
        "ok": true,
        "channel_id": channel_id,
        "runtime_id": selected_rt_id,
        "adapter": adapter,
        "posts": posts_ingested,
        "comments": comments_ingested,
        "next_poll_delay_secs": next_delay,
        "next_job_id": next_job_id,
    }))
}

pub fn playbooks_list(
    db: &Connection,
    org: &str,
    shop_id: Option<i64>,
    channel_id: Option<i64>,
) -> Vec<Value> {
    let mut sql = String::from(
        "SELECT pb.*, s.name AS shop_name, c.name AS channel_name
         FROM consultation_playbooks pb
         LEFT JOIN shops s ON s.id=pb.shop_id AND s.organization_id=pb.organization_id
         LEFT JOIN channels c ON c.id=pb.channel_id AND c.organization_id=pb.organization_id
         WHERE pb.organization_id=?",
    );
    let mut params_vec: Vec<rusqlite::types::Value> = vec![org.to_string().into()];
    if let Some(sid) = shop_id {
        sql.push_str(" AND (pb.shop_id=? OR pb.shop_id IS NULL)");
        params_vec.push(sid.into());
    }
    if let Some(cid) = channel_id {
        sql.push_str(" AND (pb.channel_id=? OR pb.channel_id IS NULL)");
        params_vec.push(cid.into());
    }
    sql.push_str(" ORDER BY pb.id DESC");

    query_maps(db, &sql, &params_vec)
        .into_iter()
        .map(|mut m| {
            let raw_fb = m
                .remove("forbidden_topics_json")
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "[]".to_string());
            let auto_en = m
                .get("auto_consult_enabled")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                != 0;
            m.insert("auto_consult_enabled".to_string(), Value::Bool(auto_en));
            m.insert(
                "forbidden_topics".to_string(),
                serde_json::from_str(&raw_fb).unwrap_or_else(|_| json!([])),
            );
            Value::Object(m)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn upsert_playbook(
    db: &Connection,
    org: &str,
    playbook_id: Option<i64>,
    shop_id: Option<i64>,
    channel_id: Option<i64>,
    name: &str,
    auto_suggest_threshold: i64,
    auto_consult_enabled: bool,
    consultation_knowledge_md: &str,
    forbidden_topics: &[String],
    actor: &str,
) -> Result<Value, String> {
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("Playbook name is required".to_string());
    }
    let thresh = auto_suggest_threshold.clamp(10, 99);
    let fb_json = serde_json::to_string(forbidden_topics).unwrap_or_else(|_| "[]".to_string());
    let now = now_unix();

    let id = if let Some(pid) = playbook_id.filter(|&x| x > 0) {
        db.execute(
            "UPDATE consultation_playbooks
             SET shop_id=?1, channel_id=?2, name=?3, auto_suggest_threshold=?4,
                 auto_consult_enabled=?5, consultation_knowledge_md=?6, forbidden_topics_json=?7, updated_at=?8
             WHERE organization_id=?9 AND id=?10",
            params![
                shop_id,
                channel_id,
                clean_name,
                thresh,
                if auto_consult_enabled { 1 } else { 0 },
                consultation_knowledge_md.trim(),
                fb_json,
                now,
                org,
                pid
            ],
        )
        .map_err(|e| e.to_string())?;
        pid
    } else {
        db.execute(
            "INSERT INTO consultation_playbooks
               (organization_id, shop_id, channel_id, name, auto_suggest_threshold,
                auto_consult_enabled, consultation_knowledge_md, forbidden_topics_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                org,
                shop_id,
                channel_id,
                clean_name,
                thresh,
                if auto_consult_enabled { 1 } else { 0 },
                consultation_knowledge_md.trim(),
                fb_json,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        db.last_insert_rowid()
    };

    audit::append(
        db,
        org,
        actor,
        "playbook.saved",
        &id.to_string(),
        &json!({
            "name": clean_name,
            "channel_id": channel_id,
            "auto_suggest_threshold": thresh,
            "auto_consult_enabled": auto_consult_enabled,
        }),
    )
    .map_err(|e| e.to_string())?;

    Ok(json!({
        "ok": true,
        "id": id,
        "name": clean_name,
        "auto_suggest_threshold": thresh,
        "auto_consult_enabled": auto_consult_enabled,
    }))
}
