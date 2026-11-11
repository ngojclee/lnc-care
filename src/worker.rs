//! Worker queue runner (`lnc-care worker`) for background webhooks, media/screenshot archiving,
//! retention pruning, 5-layer forensic Evidence Vault + watchdog, and multi-account browser polling.

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::agent_hub::{self, AgentHubClient, AgentHubConfig};
use crate::connections::{self, Connections};
use crate::internal_bridge::{self, AdsBridgeClient};
use crate::store::{self, query_maps, query_one_map};
use crate::transport::{SharedTransport, TransportRequest, UreqTransport};
use crate::vault::Vault;
use crate::{evaluator, evidence, fleet, settings};

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn enqueue_job(
    db: &Connection,
    organization_id: &str,
    kind: &str,
    payload: &Value,
    delay_seconds: i64,
) -> Result<i64, rusqlite::Error> {
    let now = now_unix();
    let payload_json = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    db.execute(
        "INSERT INTO jobs (organization_id, kind, payload_json, run_after, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            organization_id,
            kind,
            payload_json,
            now + delay_seconds.max(0),
            now
        ],
    )?;
    Ok(db.last_insert_rowid())
}

fn archive_post_artifact(
    db_path: &Path,
    organization_id: &str,
    post_id: i64,
    arch_kind: &str,
    explicit_source_url: &str,
    transport: &SharedTransport,
    env_map: &HashMap<String, String>,
) -> Result<(), String> {
    let post = {
        let db = store::connect_readonly(db_path).map_err(|e| e.to_string())?;
        query_one_map(
            &db,
            "SELECT * FROM posts WHERE organization_id=? AND id=?",
            &[organization_id.to_string().into(), post_id.into()],
        )
        .ok_or_else(|| "post_not_found".to_string())?
    };

    let permalink = post
        .get("permalink")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let caption = post.get("caption").and_then(|v| v.as_str()).unwrap_or("");
    let media_raw = post
        .get("media_json")
        .and_then(|v| v.as_str())
        .unwrap_or("[]");
    let first_media_url: String = serde_json::from_str::<Value>(media_raw)
        .ok()
        .and_then(|v| {
            v.as_array()
                .and_then(|arr| arr.first())
                .and_then(|m| m.get("url").and_then(|u| u.as_str()).map(String::from))
        })
        .unwrap_or_default();

    let source_url = if !explicit_source_url.trim().is_empty() {
        explicit_source_url.trim().to_string()
    } else if arch_kind == "screenshot" {
        permalink.to_string()
    } else if !first_media_url.is_empty() {
        first_media_url
    } else {
        permalink.to_string()
    };

    let mut content_bytes: Vec<u8> = Vec::new();
    let mut ext = if arch_kind == "screenshot" {
        "html"
    } else {
        "bin"
    };

    if arch_kind == "screenshot" {
        if let Some(cap_api) = env_map
            .get("BROWSER_CAPTURE_URL")
            .or_else(|| env_map.get("VEILBROWSER_API_URL"))
            .map(|s| s.trim().trim_end_matches('/'))
            .filter(|s| !s.is_empty())
        {
            if !source_url.is_empty() {
                if let Ok(resp) = transport.execute(TransportRequest {
                    method: "POST".to_string(),
                    url: format!("{cap_api}/v1/screenshot"),
                    headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                    body: Some(
                        serde_json::to_vec(&json!({ "url": source_url })).unwrap_or_default(),
                    ),
                    timeout_ms: 12_000,
                }) {
                    if resp.status == 200 && !resp.body.is_empty() {
                        content_bytes = resp.body;
                        ext = "png";
                    }
                }
            }
        }
    }

    if content_bytes.is_empty()
        && (source_url.starts_with("http://") || source_url.starts_with("https://"))
    {
        if let Ok(resp) = transport.execute(TransportRequest {
            method: "GET".to_string(),
            url: source_url.clone(),
            headers: vec![("User-Agent".to_string(), "LNC-Care-Archiver/0.5".to_string())],
            body: None,
            timeout_ms: 10_000,
        }) {
            if resp.status == 200 && !resp.body.is_empty() {
                let ctype = resp.header("content-type").unwrap_or("");
                if ctype.contains("png") {
                    ext = "png";
                } else if ctype.contains("jpeg") || ctype.contains("jpg") {
                    ext = "jpg";
                } else if ctype.contains("svg") {
                    ext = "svg";
                } else if ctype.contains("html") {
                    ext = "html";
                }
                content_bytes = resp.body;
            }
        }
    }

    let now = now_unix();
    if content_bytes.is_empty() {
        ext = "html";
        content_bytes = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Post #{post_id} Archive</title></head><body><h1>Archived Post #{post_id}</h1><p>Kind: {arch_kind}</p><p>Source: {source_url}</p><pre>{caption}</pre></body></html>"
        )
        .into_bytes();
    }

    let digest = sha256_hex(&content_bytes);
    let byte_len = content_bytes.len() as i64;
    let rel_path = format!(
        "archive/post_{post_id}/{arch_kind}_{now}_{}.{ext}",
        &digest[..8]
    );
    let data_dir = evidence::resolve_data_dir(db_path);
    let abs_path = data_dir.join(&rel_path);
    if let Some(parent) = abs_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&abs_path, &content_bytes).map_err(|e| e.to_string())?;

    store::with_write_tx_str(db_path, |db| {
        db.execute(
            "INSERT INTO post_archives
               (organization_id, post_id, kind, path, sha256, bytes, captured_at, source_url)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                organization_id,
                post_id,
                arch_kind,
                rel_path,
                digest,
                byte_len,
                now,
                source_url
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })
}

/// Prunes `post_archives` rows and files older than `retention_days`.
pub fn prune_expired_archives(
    path: &Path,
    organization_id: &str,
    retention_days: i64,
) -> Result<usize, String> {
    if retention_days <= 0 {
        return Ok(0);
    }
    let cutoff = now_unix() - retention_days * 86_400;
    let data_dir = evidence::resolve_data_dir(path);

    let expired: Vec<(i64, String)> = {
        let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
        query_maps(
            &db,
            "SELECT id, path FROM post_archives WHERE organization_id=? AND captured_at<?",
            &[organization_id.to_string().into(), cutoff.into()],
        )
        .into_iter()
        .filter_map(|m| {
            let id = m.get("id").and_then(|v| v.as_i64())?;
            let p = m.get("path").and_then(|v| v.as_str())?.to_string();
            Some((id, p))
        })
        .collect()
    };

    if expired.is_empty() {
        return Ok(0);
    }

    for (_, rel_path) in &expired {
        if !rel_path.is_empty() && !rel_path.contains("..") {
            let _ = std::fs::remove_file(data_dir.join(rel_path));
        }
    }

    store::with_write_tx_str(path, |db| {
        for (id, _) in &expired {
            db.execute(
                "DELETE FROM post_archives WHERE organization_id=?1 AND id=?2",
                params![organization_id, id],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(expired.len())
    })
}

pub fn build_connections_from_env(
    path: &Path,
    organization_id: &str,
    transport: Option<SharedTransport>,
    env_map: &HashMap<String, String>,
) -> Option<Connections> {
    let mk = env_map.get("LNC_MASTER_KEY").map(|s| s.as_str());
    let pk = env_map.get("LNC_PREVIOUS_MASTER_KEY").map(|s| s.as_str());
    let vault = Vault::new(mk, pk).ok()?;
    let bridge = internal_bridge::bridge_config(env_map).ok().flatten();
    let ads_bridge = bridge
        .as_ref()
        .map(|b| AdsBridgeClient::new(b.clone(), transport.clone()));
    let mut hub_cfg = agent_hub::agent_hub_config(env_map).ok().flatten();
    if hub_cfg.is_none() && ads_bridge.is_some() {
        let sid = bridge
            .as_ref()
            .map(|b| b.self_id.as_str())
            .unwrap_or("lnc-care");
        hub_cfg = Some(AgentHubConfig::new("", "", "", sid));
    }
    let hub_client = hub_cfg.map(|hc| AgentHubClient::new(hc, ads_bridge, transport.clone()));
    Some(Connections::new(
        path.to_path_buf(),
        organization_id.to_string(),
        vault,
        transport,
        hub_client,
    ))
}

pub fn run_pending_jobs(
    path: &Path,
    organization_id: &str,
    limit: i64,
    worker_id: &str,
) -> Value {
    let env_map: HashMap<String, String> = std::env::vars().collect();
    let conns = build_connections_from_env(path, organization_id, None, &env_map);
    run_pending_jobs_with_runtime(
        path,
        organization_id,
        limit,
        worker_id,
        conns.as_ref(),
        None,
        &env_map,
    )
}

pub fn run_pending_jobs_with_runtime(
    path: &Path,
    organization_id: &str,
    limit: i64,
    worker_id: &str,
    conns_opt: Option<&Connections>,
    transport_opt: Option<&SharedTransport>,
    env_map: &HashMap<String, String>,
) -> Value {
    let now = now_unix();
    let mut processed: i64 = 0;
    let mut failed: i64 = 0;
    let mut retried: i64 = 0;

    let default_tr;
    let tr: &SharedTransport = match transport_opt {
        Some(t) => t,
        None => match conns_opt {
            Some(c) => c.providers.transport(),
            None => {
                default_tr = UreqTransport::shared();
                &default_tr
            }
        },
    };

    let (jobs, retention_days): (Vec<(i64, String, String, i64, i64)>, i64) = {
        let Ok(db) = store::connect(path) else {
            return json!({"processed": 0, "failed": 0, "retried": 0, "pruned_archives": 0});
        };
        let _ = fleet::reap_expired_leases(&db, organization_id, now);
        let cfg = settings::load(&db, organization_id, env_map);
        let fetched = match db.prepare(
            "SELECT id, kind, payload_json, attempts, COALESCE(max_attempts, 3)
             FROM jobs
             WHERE organization_id=?1 AND done_at IS NULL AND run_after<=?2
             ORDER BY run_after ASC, id ASC LIMIT ?3",
        ) {
            Ok(mut stmt) => stmt
                .query_map(params![organization_id, now, limit], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .map(|it| it.filter_map(Result::ok).collect())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        (fetched, cfg.archive_retention_days)
    };

    let pruned = prune_expired_archives(path, organization_id, retention_days).unwrap_or(0);

    for (job_id, kind, payload_raw, prev_attempts, max_attempts) in jobs {
        let payload: Value =
            serde_json::from_str(&payload_raw).unwrap_or_else(|_| json!({}));
        let actor = format!("job:{worker_id}");

        let exec_res: Result<(), String> = match kind.as_str() {
            "evaluate_comment" => {
                if let Some(cid) = payload.get("comment_id").and_then(|v| v.as_i64()) {
                    store::with_write_tx_str(path, |db| {
                        evaluator::evaluate_and_persist(db, organization_id, cid, None, &actor)
                            .map(|_| ())
                    })
                } else {
                    Ok(())
                }
            }
            "fetch_comments" | "fetch_post" | "snapshot" | "backfill" => {
                if let Some(entry_id) = payload.get("entry_id").and_then(|v| v.as_str()) {
                    let field = payload
                        .get("field")
                        .and_then(|v| v.as_str())
                        .unwrap_or("feed");
                    let val = payload.get("value").cloned().unwrap_or_else(|| json!({}));
                    if let Some(c) = conns_opt {
                        c.process_meta_webhook_change(entry_id, field, &val, &actor)
                            .map(|_| ())
                    } else if let Some(temp_c) =
                        build_connections_from_env(path, organization_id, Some(tr.clone()), env_map)
                    {
                        temp_c
                            .process_meta_webhook_change(entry_id, field, &val, &actor)
                            .map(|_| ())
                    } else {
                        Ok(())
                    }
                } else if let Some(cid) = payload.get("channel_id").and_then(|v| v.as_i64()) {
                    if let Some(c) = conns_opt {
                        c.sync_channel(cid, 15, 50).map(|_| ()).map_err(|e| e.code)
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            }
            "archive_media" | "screenshot" => {
                if let Some(post_id) = payload.get("post_id").and_then(|v| v.as_i64()) {
                    let arch_kind = if kind == "screenshot" {
                        "screenshot"
                    } else {
                        "media"
                    };
                    let source_url = payload
                        .get("source_url")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    archive_post_artifact(
                        path,
                        organization_id,
                        post_id,
                        arch_kind,
                        source_url,
                        tr,
                        env_map,
                    )
                } else {
                    Ok(())
                }
            }
            "evidence_capture" => {
                let target_url = payload
                    .get("target_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let title = payload
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let comment_id = payload.get("comment_id").and_then(|v| v.as_i64());
                let case_id = payload.get("case_id").and_then(|v| v.as_i64());
                store::with_write_tx_str(path, |db| {
                    connections::capture_forensic_evidence_on_disk(
                        db,
                        path,
                        organization_id,
                        target_url,
                        title,
                        comment_id,
                        case_id,
                        &actor,
                        Some(tr),
                    )
                    .map(|_| ())
                })
            }
            "evidence_watchdog" => {
                let case_id = payload.get("case_id").and_then(|v| v.as_i64());
                let item_id = payload.get("item_id").and_then(|v| v.as_i64());
                store::with_write_tx_str(path, |db| {
                    evidence::run_watchdog_check(
                        db,
                        organization_id,
                        case_id,
                        item_id,
                        Some(tr),
                        &actor,
                    )
                    .map(|_| ())
                })
            }
            "browser_fetch" => {
                if let Some(cid) = payload.get("channel_id").and_then(|v| v.as_i64()) {
                    let rt_id = payload.get("runtime_id").and_then(|v| v.as_i64());
                    let reschedule = payload
                        .get("reschedule")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let inline_items = payload
                        .get("posts")
                        .and_then(|v| v.as_array())
                        .map(|v| v.as_slice());
                    fleet::run_browser_channel_fetch(
                        path,
                        organization_id,
                        cid,
                        rt_id,
                        inline_items,
                        reschedule,
                        Some(tr),
                        env_map,
                        &actor,
                    )
                    .map(|_| ())
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        };

        let finish_now = now_unix();
        if let Ok(db) = store::connect(path) {
            match exec_res {
                Ok(()) => {
                    let _ = db.execute(
                        "UPDATE jobs SET done_at=?1, locked_by=?2, error=NULL, attempts=attempts+1 WHERE id=?3",
                        params![finish_now, worker_id, job_id],
                    );
                    processed += 1;
                }
                Err(err) => {
                    let next_attempts = prev_attempts + 1;
                    let truncated: String = err.chars().take(300).collect();
                    if next_attempts < max_attempts.max(1) {
                        let backoff = 30 * (1i64 << next_attempts.min(6));
                        let _ = db.execute(
                            "UPDATE jobs
                             SET attempts=?1, locked_by=?2, error=?3, run_after=?4
                             WHERE id=?5",
                            params![
                                next_attempts,
                                worker_id,
                                truncated,
                                finish_now + backoff,
                                job_id
                            ],
                        );
                        retried += 1;
                    } else {
                        let _ = db.execute(
                            "UPDATE jobs
                             SET attempts=?1, done_at=?2, locked_by=?3, error=?4
                             WHERE id=?5",
                            params![next_attempts, finish_now, worker_id, truncated, job_id],
                        );
                    }
                    failed += 1;
                }
            }
        }
    }

    json!({
        "processed": processed,
        "failed": failed,
        "retried": retried,
        "pruned_archives": pruned,
    })
}
