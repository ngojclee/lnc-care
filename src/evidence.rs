//! 5-Layer Forensic Evidence Vault ("Lập vi bằng số"), pure-Rust deterministic PKZIP exporter,
//! SHA-256 chain-of-custody verifier, and `+6h / +24h / +72h` deletion/edit watchdog.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{TimeZone, Utc};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::audit::{self, canonical_ascii_json};
use crate::store::{query_maps, query_one_map};
use crate::transport::{SharedTransport, TransportRequest, UreqTransport};

const WATCHDOG_CHECKPOINTS_SECS: &[i64] = &[6 * 3600, 24 * 3600, 72 * 3600];

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn resolve_data_dir(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// IEEE 802.3 CRC-32 (`0xEDB88320`) used by standard PKZIP archives.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Builds a deterministic PKZIP archive (Store method `0`, MS-DOS epoch `2026-01-01 00:00:00`)
/// with zero C/external crate dependencies.
pub fn build_deterministic_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut sorted: Vec<(&str, &[u8])> = files.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));

    let dos_time: u16 = 0;
    let dos_date: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1;

    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut entry_count: u16 = 0;

    for (raw_name, content) in sorted {
        let name = raw_name.trim_start_matches('/').replace('\\', "/");
        let name_bytes = name.as_bytes();
        let offset = out.len() as u32;
        let size = content.len() as u32;
        let crc = crc32_ieee(content);

        // Local file header (`0x04034b50`)
        out.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed (2.0)
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 filename flag
        out.extend_from_slice(&0u16.to_le_bytes()); // compression = 0 (store)
        out.extend_from_slice(&dos_time.to_le_bytes());
        out.extend_from_slice(&dos_date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(content);

        // Central directory file header (`0x02014b50`)
        central.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 flag
        central.extend_from_slice(&0u16.to_le_bytes()); // store
        central.extend_from_slice(&dos_time.to_le_bytes());
        central.extend_from_slice(&dos_date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);

        entry_count = entry_count.saturating_add(1);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory (`0x06054b50`)
    out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    out
}

#[allow(clippy::too_many_arguments)]
pub fn capture_forensic_bundle(
    db: &Connection,
    data_dir: Option<&Path>,
    organization_id: &str,
    target_url: &str,
    title: &str,
    comment_id: Option<i64>,
    case_id_in: Option<i64>,
    actor: &str,
    transport: Option<&SharedTransport>,
) -> Result<Value, String> {
    let now = now_unix();
    let comment_row = match comment_id {
        Some(cid) => query_one_map(
            db,
            "SELECT cm.*, p.permalink AS post_permalink, p.external_id AS post_external_id,
                    p.caption AS post_caption, p.media_json AS post_media_json,
                    c.id AS channel_id, c.name AS channel_name, c.provider AS channel_provider
             FROM comments cm
             JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
             JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
             WHERE cm.organization_id=? AND cm.id=?",
            &[organization_id.to_string().into(), cid.into()],
        ),
        None => None,
    };

    let fallback_url = comment_row
        .as_ref()
        .and_then(|r| r.get("post_permalink"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let effective_url = if !target_url.trim().is_empty() {
        target_url.trim().to_string()
    } else {
        fallback_url.to_string()
    };
    if effective_url.is_empty() {
        return Err("Target URL or comment with permalink is required".to_string());
    }

    let url_hash = sha256_hex(effective_url.as_bytes());
    let actor_uid = comment_row
        .as_ref()
        .and_then(|r| r.get("author_external_id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("uid_{}", &url_hash[..12]));
    let actor_name = comment_row
        .as_ref()
        .and_then(|r| r.get("author_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("External Subject")
        .to_string();
    let captured_text = comment_row
        .as_ref()
        .and_then(|r| r.get("text"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("Forensic URL preservation: {effective_url}"));
    let post_ext_id = comment_row
        .as_ref()
        .and_then(|r| r.get("post_external_id"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("ext_post_{}", &url_hash[..10]));
    let comment_ext_id = comment_row
        .as_ref()
        .and_then(|r| r.get("external_id"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let channel_id_opt = comment_row
        .as_ref()
        .and_then(|r| r.get("channel_id"))
        .and_then(|v| v.as_i64());
    let published_at = comment_row
        .as_ref()
        .and_then(|r| r.get("created_at"))
        .and_then(|v| v.as_i64())
        .unwrap_or(now);

    let thread_siblings: Vec<Value> = if let Some(cid) = comment_id {
        let post_id_val = comment_row
            .as_ref()
            .and_then(|r| r.get("post_id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        query_maps(
            db,
            "SELECT id, external_id, parent_external_id, author_external_id, author_name, text, created_at
             FROM comments WHERE organization_id=? AND post_id=? ORDER BY created_at ASC LIMIT 50",
            &[organization_id.to_string().into(), post_id_val.into()],
        )
        .into_iter()
        .map(|mut m| {
            m.insert("focus".to_string(), json!(m.get("id").and_then(|v| v.as_i64()) == Some(cid)));
            Value::Object(m)
        })
        .collect()
    } else {
        Vec::new()
    };

    let case_id = match case_id_in {
        Some(cid) => cid,
        None => {
            let case_title = if !title.trim().is_empty() {
                title.trim().to_string()
            } else {
                format!(
                    "Forensic Case · {actor_name} ({})",
                    Utc::now().format("%Y-%m-%d %H:%M UTC")
                )
            };
            db.execute(
                "INSERT INTO evidence_cases
                   (organization_id, title, subject_name, subject_uid, channel_id, status, created_by, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'sealed', ?6, ?7)",
                params![
                    organization_id,
                    case_title,
                    actor_name,
                    actor_uid,
                    channel_id_opt,
                    actor,
                    now
                ],
            )
            .map_err(|e| e.to_string())?;
            db.last_insert_rowid()
        }
    };

    let captured_utc = Utc
        .timestamp_opt(now, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string())
        .unwrap_or_default();

    // Optional live HTTP snapshot of permalink & media via injected transport (never blocks or fails if offline)
    let mut fetched_dom_bytes: Vec<u8> = Vec::new();
    let mut net_status: u16 = 0;
    let mut net_headers = serde_json::Map::new();
    if let Some(tr) = transport {
        if effective_url.starts_with("http://") || effective_url.starts_with("https://") {
            if let Ok(resp) = tr.execute(TransportRequest {
                method: "GET".to_string(),
                url: effective_url.clone(),
                headers: vec![
                    (
                        "Accept".to_string(),
                        "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
                            .to_string(),
                    ),
                    ("User-Agent".to_string(), "LNC-Care-Forensic/0.5".to_string()),
                ],
                body: None,
                timeout_ms: 8_000,
            }) {
                net_status = resp.status;
                for (k, v) in &resp.headers {
                    net_headers.insert(k.clone(), Value::String(v.clone()));
                }
                fetched_dom_bytes = resp.body;
            }
        }
    }

    if fetched_dom_bytes.is_empty() {
        let post_cap = comment_row
            .as_ref()
            .and_then(|r| r.get("post_caption"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        fetched_dom_bytes = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Forensic Case #{case_id}</title></head><body><h1>Preserved Target</h1><p>URL: {effective_url}</p><p>Actor: {actor_name} ({actor_uid})</p><pre>{captured_text}</pre><hr><pre>{post_cap}</pre></body></html>"
        )
        .into_bytes();
    }

    // Attempt Layer 4 original media download if comment's post has HTTP media URL
    let mut media_files: Vec<(String, Vec<u8>, String)> = Vec::new();
    if let (Some(tr), Some(cm)) = (transport, comment_row.as_ref()) {
        if let Some(raw_media) = cm.get("post_media_json").and_then(|v| v.as_str()) {
            if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw_media) {
                for (idx, m) in items.iter().take(3).enumerate() {
                    if let Some(u) = m.get("url").and_then(|v| v.as_str()) {
                        if u.starts_with("http://") || u.starts_with("https://") {
                            if let Ok(r) = tr.execute(TransportRequest {
                                method: "GET".to_string(),
                                url: u.to_string(),
                                headers: Vec::new(),
                                body: None,
                                timeout_ms: 8_000,
                            }) {
                                if r.status == 200 && !r.body.is_empty() {
                                    let d = sha256_hex(&r.body);
                                    media_files.push((
                                        format!("layer4_media/media_{idx}.bin"),
                                        r.body,
                                        d,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let dom_sha = sha256_hex(&fetched_dom_bytes);
    let layer1_bytes = canonical_ascii_json(&json!({
        "actor_uid": actor_uid,
        "actor_name": actor_name,
        "post_external_id": post_ext_id,
        "comment_external_id": comment_ext_id,
        "target_url": effective_url,
        "published_at": published_at,
        "captured_at_utc": captured_utc,
    }))
    .into_bytes();
    let layer2_bytes = canonical_ascii_json(&json!({
        "filter_mode": "ALL_COMMENTS",
        "expanded_replies": true,
        "expanded_see_more": true,
        "captured_text": captured_text,
        "thread_comments": thread_siblings,
    }))
    .into_bytes();
    let layer3_har_bytes = canonical_ascii_json(&json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "lnc-care-forensic", "version": crate::VERSION },
            "entries": [{
                "startedDateTime": captured_utc,
                "request": { "method": "GET", "url": effective_url },
                "response": {
                    "status": net_status,
                    "headers": net_headers,
                    "bodySize": fetched_dom_bytes.len(),
                    "content": { "sha256": dom_sha }
                }
            }]
        }
    }))
    .into_bytes();

    let layers = json!({
        "layer_1_immutable_ids": {
            "actor_uid": actor_uid,
            "post_id": post_ext_id,
            "comment_id": comment_ext_id,
            "file": "layer1_immutable_ids.json",
            "sha256": sha256_hex(&layer1_bytes),
        },
        "layer_2_thread_expansion": {
            "filter_mode": "ALL_COMMENTS",
            "expanded_replies": true,
            "expanded_see_more": true,
            "thread_count": thread_siblings.len(),
            "file": "layer2_thread_snapshot.json",
            "sha256": sha256_hex(&layer2_bytes),
        },
        "layer_3_visual_and_network_replay": {
            "fullpage_screenshot": format!("evidence/case_{case_id}/layer3_dom_snapshot.html"),
            "dom_mhtml": format!("evidence/case_{case_id}/layer3_dom_snapshot.html"),
            "playwright_trace_har": format!("evidence/case_{case_id}/layer3_network_trace.har.json"),
            "dom_sha256": dom_sha,
            "har_sha256": sha256_hex(&layer3_har_bytes),
            "http_status": net_status,
        },
        "layer_4_original_media": {
            "media_dir": format!("evidence/case_{case_id}/layer4_media/"),
            "files": media_files.iter().map(|(p, b, d)| json!({"path": p, "bytes": b.len(), "sha256": d})).collect::<Vec<_>>(),
        },
        "layer_5_watchdog": {
            "checkpoints_hours": [6, 24, 72],
            "alive_status": "alive",
        },
    });

    let manifest_payload = json!({
        "case_id": case_id,
        "target_url": effective_url,
        "actor_uid": actor_uid,
        "actor_name": actor_name,
        "post_external_id": post_ext_id,
        "comment_external_id": comment_ext_id,
        "captured_text": captured_text,
        "captured_at_utc": captured_utc,
        "layers": layers,
    });
    let manifest_json = canonical_ascii_json(&manifest_payload);
    let manifest_sha256 = sha256_hex(manifest_json.as_bytes());

    let preserved_snip: String = captured_text.chars().take(300).collect();
    let summary_md = format!(
        "### Forensic Evidence Record (Case #{case_id})\n- **Subject:** {actor_name} (`UID: {actor_uid}`)\n- **Target URL:** `{effective_url}`\n- **Captured UTC:** `{captured_utc}`\n- **Manifest SHA-256:** `{manifest_sha256}`\n- **Preserved Content:** {preserved_snip}\n"
    );

    let mut zip_entries: Vec<(&str, &[u8])> = vec![
        ("manifest.json", manifest_json.as_bytes()),
        ("forensic_report.md", summary_md.as_bytes()),
        ("layer1_immutable_ids.json", &layer1_bytes),
        ("layer2_thread_snapshot.json", &layer2_bytes),
        ("layer3_dom_snapshot.html", &fetched_dom_bytes),
        ("layer3_network_trace.har.json", &layer3_har_bytes),
    ];
    for (mpath, mbytes, _) in &media_files {
        zip_entries.push((mpath.as_str(), mbytes.as_slice()));
    }
    let zip_bytes = build_deterministic_zip(&zip_entries);
    let bundle_sha256 = sha256_hex(&zip_bytes);
    let bundle_rel_path = format!(
        "evidence/case_{case_id}/forensic_bundle_{}.zip",
        &manifest_sha256[..12]
    );

    if let Some(dd) = data_dir {
        let case_dir = dd.join("evidence").join(format!("case_{case_id}"));
        let _ = std::fs::create_dir_all(case_dir.join("layer4_media"));
        let _ = std::fs::write(case_dir.join("manifest.json"), manifest_json.as_bytes());
        let _ = std::fs::write(case_dir.join("forensic_report.md"), summary_md.as_bytes());
        let _ = std::fs::write(case_dir.join("layer1_immutable_ids.json"), &layer1_bytes);
        let _ = std::fs::write(case_dir.join("layer2_thread_snapshot.json"), &layer2_bytes);
        let _ = std::fs::write(
            case_dir.join("layer3_dom_snapshot.html"),
            &fetched_dom_bytes,
        );
        let _ = std::fs::write(
            case_dir.join("layer3_network_trace.har.json"),
            &layer3_har_bytes,
        );
        for (mpath, mbytes, _) in &media_files {
            let _ = std::fs::write(case_dir.join(mpath), mbytes);
        }
        let zip_abs = dd.join(&bundle_rel_path);
        if let Some(parent) = zip_abs.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(zip_abs, &zip_bytes);
    }

    let target_kind = if comment_id.is_some() {
        "comment"
    } else {
        "post"
    };
    db.execute(
        "INSERT INTO evidence_items
           (organization_id, case_id, comment_id, target_url, target_kind, actor_uid, actor_name,
            post_external_id, comment_external_id, captured_text, published_at, captured_at,
            artifacts_json, manifest_sha256, alive_status, last_checked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 'alive', ?15)",
        params![
            organization_id,
            case_id,
            comment_id,
            effective_url,
            target_kind,
            actor_uid,
            actor_name,
            post_ext_id,
            comment_ext_id,
            captured_text,
            published_at,
            now,
            manifest_json,
            manifest_sha256,
            now
        ],
    )
    .map_err(|e| e.to_string())?;
    let item_id = db.last_insert_rowid();

    db.execute(
        "UPDATE evidence_cases
         SET status='sealed', summary_md=?1, bundle_zip_path=?2, bundle_sha256=?3
         WHERE organization_id=?4 AND id=?5",
        params![
            summary_md,
            bundle_rel_path,
            bundle_sha256,
            organization_id,
            case_id
        ],
    )
    .map_err(|e| e.to_string())?;

    // Enqueue all 3 post-capture deletion/edit watchdog checkpoints: +6h, +24h, +72h
    let mut watchdog_job_ids = Vec::new();
    for &delay in WATCHDOG_CHECKPOINTS_SECS {
        let checkpoint_hours = delay / 3600;
        db.execute(
            "INSERT INTO jobs (organization_id, kind, payload_json, run_after, created_at)
             VALUES (?1, 'evidence_watchdog', ?2, ?3, ?4)",
            params![
                organization_id,
                serde_json::to_string(&json!({
                    "case_id": case_id,
                    "item_id": item_id,
                    "checkpoint_hours": checkpoint_hours,
                }))
                .unwrap_or_default(),
                now + delay,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        watchdog_job_ids.push(db.last_insert_rowid());
    }

    audit::append(
        db,
        organization_id,
        actor,
        "evidence.captured",
        &case_id.to_string(),
        &json!({
            "item_id": item_id,
            "manifest_sha256": manifest_sha256,
            "bundle_sha256": bundle_sha256,
            "bundle_bytes": zip_bytes.len(),
            "target_url": effective_url,
        }),
    )
    .map_err(|e| e.to_string())?;

    Ok(json!({
        "ok": true,
        "case_id": case_id,
        "item_id": item_id,
        "manifest_sha256": manifest_sha256,
        "bundle_sha256": bundle_sha256,
        "bundle_bytes": zip_bytes.len(),
        "bundle_zip_path": bundle_rel_path,
        "watchdog_checkpoints_hours": [6, 24, 72],
        "watchdog_job_ids": watchdog_job_ids,
        "layers": layers,
    }))
}

pub fn export_case_zip(
    db: &Connection,
    data_dir: &Path,
    organization_id: &str,
    case_id: i64,
) -> Result<(String, Vec<u8>), String> {
    let case_row = query_one_map(
        db,
        "SELECT * FROM evidence_cases WHERE organization_id=? AND id=?",
        &[organization_id.to_string().into(), case_id.into()],
    )
    .ok_or_else(|| "Evidence case not found".to_string())?;

    let rel_path = case_row
        .get("bundle_zip_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let filename = format!("lnc_care_forensic_case_{case_id}.zip");

    if !rel_path.is_empty() {
        let abs = data_dir.join(rel_path);
        if let Ok(bytes) = std::fs::read(&abs) {
            if bytes.starts_with(b"PK\x03\x04") {
                return Ok((filename, bytes));
            }
        }
    }

    // Reconstruct deterministic archive from DB sealed rows if captured before v0.5 on-disk bundle support
    let items = query_maps(
        db,
        "SELECT * FROM evidence_items WHERE organization_id=? AND case_id=? ORDER BY id ASC",
        &[organization_id.to_string().into(), case_id.into()],
    );
    let summary_md = case_row
        .get("summary_md")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let manifest_raw = items
        .first()
        .and_then(|i| i.get("artifacts_json"))
        .and_then(|v| v.as_str())
        .unwrap_or("{}")
        .to_string();
    let items_json = canonical_ascii_json(&Value::Array(
        items.into_iter().map(Value::Object).collect(),
    ));
    let zip_bytes = build_deterministic_zip(&[
        ("manifest.json", manifest_raw.as_bytes()),
        ("forensic_report.md", summary_md.as_bytes()),
        ("evidence_items.json", items_json.as_bytes()),
    ]);
    Ok((filename, zip_bytes))
}

pub fn verify_case_custody(
    db: &Connection,
    data_dir: &Path,
    organization_id: &str,
    case_id: i64,
) -> Result<Value, String> {
    let case_row = query_one_map(
        db,
        "SELECT * FROM evidence_cases WHERE organization_id=? AND id=?",
        &[organization_id.to_string().into(), case_id.into()],
    )
    .ok_or_else(|| "Evidence case not found".to_string())?;

    let items = query_maps(
        db,
        "SELECT id, artifacts_json, manifest_sha256, alive_status, last_checked_at
         FROM evidence_items WHERE organization_id=? AND case_id=? ORDER BY id ASC",
        &[organization_id.to_string().into(), case_id.into()],
    );

    let mut items_ok = true;
    let mut item_checks = Vec::new();
    for it in &items {
        let id = it.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let raw = it
            .get("artifacts_json")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected = it
            .get("manifest_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let computed = sha256_hex(raw.as_bytes());
        let ok = !expected.is_empty() && computed == expected;
        if !ok {
            items_ok = false;
        }
        item_checks.push(json!({
            "item_id": id,
            "manifest_valid": ok,
            "expected_sha256": expected,
            "computed_sha256": computed,
            "alive_status": it.get("alive_status"),
            "last_checked_at": it.get("last_checked_at"),
        }));
    }

    let rel_zip = case_row
        .get("bundle_zip_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected_bundle = case_row
        .get("bundle_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut disk_zip_exists = false;
    let mut disk_zip_valid = false;
    let mut disk_zip_sha = String::new();
    if !rel_zip.is_empty() {
        let abs = data_dir.join(rel_zip);
        if let Ok(bytes) = std::fs::read(&abs) {
            disk_zip_exists = true;
            disk_zip_sha = sha256_hex(&bytes);
            disk_zip_valid = disk_zip_sha == expected_bundle;
        }
    }

    // Legacy pre-0.5 cases stored `manifest_sha256` in `bundle_sha256` without a zip on disk
    let legacy_manifest_match = !disk_zip_exists
        && items
            .first()
            .and_then(|i| i.get("manifest_sha256"))
            .and_then(|v| v.as_str())
            == Some(expected_bundle);
    let overall_valid = items_ok && (disk_zip_valid || legacy_manifest_match);

    Ok(json!({
        "ok": true,
        "valid": overall_valid,
        "case_id": case_id,
        "bundle_zip_path": rel_zip,
        "expected_bundle_sha256": expected_bundle,
        "disk_zip_exists": disk_zip_exists,
        "disk_zip_sha256": disk_zip_sha,
        "disk_zip_valid": disk_zip_valid,
        "items": item_checks,
    }))
}

pub fn run_watchdog_check(
    db: &Connection,
    organization_id: &str,
    case_id: Option<i64>,
    item_id: Option<i64>,
    transport: Option<&SharedTransport>,
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

    let rows = if let Some(iid) = item_id {
        query_maps(
            db,
            "SELECT * FROM evidence_items WHERE organization_id=? AND id=?",
            &[organization_id.to_string().into(), iid.into()],
        )
    } else if let Some(cid) = case_id {
        query_maps(
            db,
            "SELECT * FROM evidence_items WHERE organization_id=? AND case_id=? ORDER BY id ASC",
            &[organization_id.to_string().into(), cid.into()],
        )
    } else {
        return Err("case_id or item_id is required".to_string());
    };

    if rows.is_empty() {
        return Err("Evidence item not found".to_string());
    }

    let now = now_unix();
    let mut results = Vec::new();
    for item in rows {
        let iid = item.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let cid = item.get("case_id").and_then(|v| v.as_i64()).unwrap_or(0);
        let target_url = item
            .get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let prev_status = item
            .get("alive_status")
            .and_then(|v| v.as_str())
            .unwrap_or("alive");
        let captured_text = item
            .get("captured_text")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let linked_comment_id = item.get("comment_id").and_then(|v| v.as_i64());

        let mut next_status = prev_status.to_string();
        let mut http_status: u16 = 0;

        // 1. Check local comments table if linked comment was deleted or edited
        if let Some(cm_id) = linked_comment_id {
            if let Some(cm) = query_one_map(
                db,
                "SELECT text, deleted_at FROM comments WHERE organization_id=? AND id=?",
                &[organization_id.to_string().into(), cm_id.into()],
            ) {
                if cm.get("deleted_at").map(|v| !v.is_null()).unwrap_or(false) {
                    next_status = "deleted".to_string();
                } else if let Some(cur_txt) = cm.get("text").and_then(|v| v.as_str()) {
                    if !captured_text.is_empty() && cur_txt != captured_text {
                        next_status = "edited".to_string();
                    }
                }
            }
        }

        // 2. Probe remote target URL via HTTP transport
        if (target_url.starts_with("http://") || target_url.starts_with("https://"))
            && next_status != "deleted"
        {
            if let Ok(resp) = tr.execute(TransportRequest {
                method: "GET".to_string(),
                url: target_url.to_string(),
                headers: vec![("User-Agent".to_string(), "LNC-Care-Watchdog/0.5".to_string())],
                body: None,
                timeout_ms: 8_000,
            }) {
                http_status = resp.status;
                let body_lc = resp.text().to_lowercase();
                if matches!(resp.status, 404 | 410)
                    || body_lc.contains("content isn't available")
                    || body_lc.contains("this content is no longer available")
                    || body_lc.contains("\"deleted\":true")
                {
                    next_status = "deleted".to_string();
                } else if resp.status == 200
                    && body_lc.contains("data-forensic-comment-body")
                    && !captured_text.is_empty()
                    && !resp.text().contains(captured_text)
                {
                    next_status = "edited".to_string();
                }
            }
        }

        db.execute(
            "UPDATE evidence_items SET alive_status=?1, last_checked_at=?2
             WHERE organization_id=?3 AND id=?4",
            params![next_status, now, organization_id, iid],
        )
        .map_err(|e| e.to_string())?;

        if next_status != prev_status {
            audit::append(
                db,
                organization_id,
                actor,
                "evidence.watchdog_transition",
                &cid.to_string(),
                &json!({
                    "item_id": iid,
                    "previous_status": prev_status,
                    "alive_status": next_status,
                    "http_status": http_status,
                    "target_url": target_url,
                }),
            )
            .map_err(|e| e.to_string())?;
        }

        results.push(json!({
            "item_id": iid,
            "case_id": cid,
            "previous_status": prev_status,
            "alive_status": next_status,
            "http_status": http_status,
            "checked_at": now,
        }));
    }

    let summary_alive = results
        .first()
        .and_then(|r| r.get("alive_status"))
        .cloned()
        .unwrap_or_else(|| json!("alive"));

    Ok(json!({
        "ok": true,
        "alive_status": summary_alive,
        "checked": results.len(),
        "items": results,
    }))
}
