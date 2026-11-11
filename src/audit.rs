//! Organization-local SHA-256 integrity chain (`audit_events`), 100% compatible with Python `ensure_ascii=True` JSON.

use chrono::Utc;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Produces compact, sorted-key, ASCII-escaped JSON matching Python's
/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub fn canonical_ascii_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_ascii(value, &mut out);
    out
}

fn write_canonical_ascii(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_ascii_escaped_str(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_ascii(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_ascii_escaped_str(k, out);
                out.push(':');
                write_canonical_ascii(&map[*k], out);
            }
            out.push('}');
        }
    }
}

fn write_ascii_escaped_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) <= 0x7f => {
                out.push(c);
            }
            c if (c as u32) <= 0xffff => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => {
                let code = (c as u32) - 0x1_0000;
                let high = 0xd800 + ((code >> 10) & 0x3ff);
                let low = 0xdc00 + (code & 0x3ff);
                out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
            }
        }
    }
    out.push('"');
}

pub fn digest(previous: &str, event: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical_ascii_json(event).as_bytes());
    hex::encode(hasher.finalize())
}

pub fn append(
    db: &Connection,
    org: &str,
    actor: &str,
    action: &str,
    subject: &str,
    details: &Value,
) -> Result<(), rusqlite::Error> {
    let prev: Option<(i64, String)> = db
        .query_row(
            "SELECT sequence, event_hash FROM audit_events WHERE organization_id=?1 ORDER BY sequence DESC LIMIT 1",
            params![org],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();

    let (sequence, previous_hash) = match prev {
        Some((seq, hash)) => (seq + 1, hash),
        None => (1, "0".repeat(64)),
    };

    let created_at = Utc::now().format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string();
    let event = json!({
        "organization_id": org,
        "sequence": sequence,
        "actor": actor,
        "action": action,
        "subject": subject,
        "details": details,
        "created_at": created_at,
    });
    let details_json = canonical_ascii_json(details);
    let event_hash = digest(&previous_hash, &event);

    db.execute(
        "INSERT INTO audit_events
         (organization_id, sequence, actor, action, subject, details, created_at, previous_hash, event_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            org,
            sequence,
            actor,
            action,
            subject,
            details_json,
            created_at,
            previous_hash,
            event_hash
        ],
    )?;
    Ok(())
}

pub fn list_recent(db: &Connection, org: &str, limit: i64) -> Vec<Value> {
    let mut stmt = match db.prepare(
        "SELECT sequence, actor, action, subject, details, created_at, previous_hash, event_hash
         FROM audit_events WHERE organization_id=?1 ORDER BY sequence DESC LIMIT ?2",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map(params![org, limit], |r| {
        let details_raw: String = r.get(4)?;
        let details: Value = serde_json::from_str(&details_raw).unwrap_or_else(|_| json!({}));
        Ok(json!({
            "sequence": r.get::<_, i64>(0)?,
            "actor": r.get::<_, String>(1)?,
            "action": r.get::<_, String>(2)?,
            "subject": r.get::<_, String>(3)?,
            "details": details,
            "created_at": r.get::<_, String>(5)?,
            "previous_hash": r.get::<_, String>(6)?,
            "event_hash": r.get::<_, String>(7)?,
        }))
    }) {
        Ok(it) => it,
        Err(_) => return Vec::new(),
    };

    rows.filter_map(Result::ok).collect()
}

pub fn verify(db: &Connection, org: &str) -> Value {
    let mut previous = "0".repeat(64);
    let mut expected: i64 = 1;

    let mut stmt = match db.prepare(
        "SELECT organization_id, sequence, actor, action, subject, details, created_at, previous_hash, event_hash
         FROM audit_events WHERE organization_id=?1 ORDER BY sequence ASC",
    ) {
        Ok(s) => s,
        Err(_) => {
            return json!({"ok": false, "valid": false, "checked": 0});
        }
    };

    let iter = match stmt.query_map(params![org], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
        ))
    }) {
        Ok(it) => it,
        Err(_) => return json!({"ok": false, "valid": false, "checked": 0}),
    };

    for item in iter {
        let Ok((org_id, seq, actor, action, subject, details_raw, created_at, prev_hash, ev_hash)) =
            item
        else {
            return json!({"ok": false, "valid": false, "checked": expected - 1});
        };

        let valid = match serde_json::from_str::<Value>(&details_raw) {
            Ok(details_val) => {
                let event = json!({
                    "organization_id": org_id,
                    "sequence": seq,
                    "actor": actor,
                    "action": action,
                    "subject": subject,
                    "details": details_val,
                    "created_at": created_at,
                });
                seq == expected && prev_hash == previous && ev_hash == digest(&previous, &event)
            }
            Err(_) => false,
        };

        if !valid {
            return json!({
                "ok": false,
                "valid": false,
                "checked": expected - 1,
                "invalid_sequence": seq,
                "broken_sequence": seq,
            });
        }
        previous = ev_hash;
        expected += 1;
    }

    json!({
        "ok": true,
        "valid": true,
        "checked": expected - 1,
        "head_hash": previous,
    })
}
