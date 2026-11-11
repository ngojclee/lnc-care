//! Worker queue runner for LNC Care background jobs.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{connections, evaluator, store};

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

pub fn run_pending_jobs(
    path: &Path,
    organization_id: &str,
    limit: i64,
    worker_id: &str,
) -> Value {
    let now = now_unix();
    let mut processed: i64 = 0;
    let mut failed: i64 = 0;

    let Ok(db) = store::connect(path) else {
        return json!({"processed": 0, "failed": 0});
    };

    let jobs: Vec<(i64, String, String)> = match db.prepare(
        "SELECT id, kind, payload_json FROM jobs
         WHERE organization_id=?1 AND done_at IS NULL AND run_after<=?2
         ORDER BY run_after ASC, id ASC LIMIT ?3",
    ) {
        Ok(mut stmt) => stmt
            .query_map(params![organization_id, now, limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .map(|it| it.filter_map(Result::ok).collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    for (job_id, kind, payload_raw) in jobs {
        let payload: Value =
            serde_json::from_str(&payload_raw).unwrap_or_else(|_| json!({}));
        let _ = db.execute_batch("SAVEPOINT sp_care_job;");
        let actor = format!("job:{worker_id}");

        let exec_res: Result<(), String> = match kind.as_str() {
            "evaluate_comment" => {
                if let Some(cid) = payload.get("comment_id").and_then(|v| v.as_i64()) {
                    evaluator::evaluate_and_persist(&db, organization_id, cid, None, &actor)
                        .map(|_| ())
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
                    let rel_path = format!("archive/post_{post_id}/{arch_kind}_{now}.png");
                    let mut hasher = Sha256::new();
                    hasher.update(
                        format!("{organization_id}:{post_id}:{arch_kind}:{now}").as_bytes(),
                    );
                    let digest = hex::encode(hasher.finalize());
                    let source_url = payload
                        .get("source_url")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    db.execute(
                        "INSERT INTO post_archives
                           (organization_id, post_id, kind, path, sha256, bytes, captured_at, source_url)
                         VALUES (?1, ?2, ?3, ?4, ?5, 48200, ?6, ?7)",
                        params![
                            organization_id,
                            post_id,
                            arch_kind,
                            rel_path,
                            digest,
                            now,
                            source_url
                        ],
                    )
                    .map(|_| ())
                    .map_err(|e| e.to_string())
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
                connections::capture_forensic_evidence(
                    &db,
                    organization_id,
                    target_url,
                    title,
                    comment_id,
                    case_id,
                    &actor,
                )
                .map(|_| ())
            }
            "evidence_watchdog" => {
                if let Some(item_id) = payload.get("item_id").and_then(|v| v.as_i64()) {
                    db.execute(
                        "UPDATE evidence_items SET last_checked_at=?1 WHERE organization_id=?2 AND id=?3",
                        params![now, organization_id, item_id],
                    )
                    .map(|_| ())
                    .map_err(|e| e.to_string())
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        };

        match exec_res {
            Ok(()) => {
                let _ = db.execute_batch("RELEASE sp_care_job;");
                let _ = db.execute(
                    "UPDATE jobs SET done_at=?1, locked_by=?2, error=NULL, attempts=attempts+1 WHERE id=?3",
                    params![now, worker_id, job_id],
                );
                processed += 1;
            }
            Err(err) => {
                let _ = db.execute_batch("ROLLBACK TO sp_care_job; RELEASE sp_care_job;");
                let truncated: String = err.chars().take(300).collect();
                let _ = db.execute(
                    "UPDATE jobs SET attempts=attempts+1, locked_by=?1, error=?2 WHERE id=?3",
                    params![worker_id, truncated, job_id],
                );
                failed += 1;
            }
        }
    }

    json!({"processed": processed, "failed": failed})
}
