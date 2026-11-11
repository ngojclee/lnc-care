//! Allowlisted runtime settings; environment overrides take precedence and report provenance explicitly.

use std::collections::HashMap;

use regex::Regex;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use url::Url;

pub const SETTING_KEYS: &[&str] = &[
    "public_base_url",
    "allowed_hosts",
    "mcp_max_scopes",
    "archive_retention_days",
];

#[derive(Debug, Clone)]
pub struct LoadedSettings {
    pub public_base_url: String,
    pub allowed_hosts: Vec<String>,
    pub mcp_max_scopes: Vec<String>,
    pub archive_retention_days: i64,
}

pub fn default_value(key: &str) -> &'static str {
    match key {
        "public_base_url" => "",
        "allowed_hosts" => "localhost,127.0.0.1,10.21.4.101,care-mcp.lengoc.me",
        "mcp_max_scopes" => "care:read,care:read:meta,care:read:tiktok,care:read:youtube",
        "archive_retention_days" => "180",
        _ => "",
    }
}

pub fn env_value(key: &str, env: &HashMap<String, String>) -> String {
    let aliases: &[&str] = match key {
        "public_base_url" => &["PUBLIC_BASE_URL"],
        "allowed_hosts" => &["ALLOWED_HOSTS"],
        "mcp_max_scopes" => &["CONNECTOR_MAX_SCOPES", "LNC_MCP_MAX_SCOPES"],
        "archive_retention_days" => &["ARCHIVE_RETENTION_DAYS"],
        _ => &[],
    };
    for name in aliases {
        if let Some(val) = env.get(*name) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

pub fn bare_origin(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err("Expected a bare HTTP(S) origin".to_string());
    }
    let parsed = Url::parse(trimmed).map_err(|_| "Expected a bare HTTP(S) origin".to_string())?;
    let scheme = parsed.scheme();
    if (scheme != "http" && scheme != "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (parsed.path() != "" && parsed.path() != "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("Expected a bare HTTP(S) origin".to_string());
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

pub fn validate(key: &str, raw_val: &Value) -> Result<String, String> {
    let mut value = match raw_val {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|x| match x {
                Value::String(s) => Some(s.trim().to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(","),
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => return Err("Invalid setting value".to_string()),
    };
    value = value.trim().to_string();

    match key {
        "public_base_url" => bare_origin(&value),
        "allowed_hosts" => {
            let mut items: Vec<String> = value
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            if items.is_empty() {
                items = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            }
            if items != vec!["*".to_string()] {
                let host_re = Regex::new(r"^[a-z0-9][a-z0-9.:-]{0,252}$").unwrap();
                if items.iter().any(|v| !host_re.is_match(v)) {
                    return Err("Expected comma-separated hostnames or IP addresses".to_string());
                }
            }
            let mut deduped = Vec::new();
            for it in items {
                if !deduped.contains(&it) {
                    deduped.push(it);
                }
            }
            Ok(deduped.join(","))
        }
        "mcp_max_scopes" => {
            let items: Vec<String> = value
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let scope_re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9:._*-]{0,63}$").unwrap();
            if items.is_empty()
                || items.iter().any(|v| !scope_re.is_match(v))
                || !items.iter().any(|v| v == "care:read")
            {
                return Err("Expected comma-separated scopes including care:read".to_string());
            }
            let mut deduped = Vec::new();
            for it in items {
                if !deduped.contains(&it) {
                    deduped.push(it);
                }
            }
            Ok(deduped.join(","))
        }
        "archive_retention_days" => {
            if value.is_empty() {
                return Ok("180".to_string());
            }
            let parsed: i64 = value
                .parse()
                .map_err(|_| "Expected retention days between 7 and 3650".to_string())?;
            if !(7..=3650).contains(&parsed) {
                return Err("Expected retention days between 7 and 3650".to_string());
            }
            Ok(parsed.to_string())
        }
        _ => Err("Unknown setting".to_string()),
    }
}

pub fn inventory(db: &Connection, org: &str, env: &HashMap<String, String>) -> Value {
    let mut stored = HashMap::new();
    if let Ok(mut stmt) =
        db.prepare("SELECT key, value FROM runtime_settings WHERE organization_id=?1")
    {
        if let Ok(rows) = stmt.query_map(params![org], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }) {
            for r in rows.flatten() {
                stored.insert(r.0, r.1);
            }
        }
    }

    let mut out = serde_json::Map::new();
    for &key in SETTING_KEYS {
        let ev = env_value(key, env);
        let (raw, src) = if !ev.is_empty() {
            (ev, "environment")
        } else if let Some(sv) = stored.get(key) {
            (sv.clone(), "database")
        } else {
            (default_value(key).to_string(), "default")
        };
        out.insert(key.to_string(), json!({"value": raw, "source": src}));
    }
    Value::Object(out)
}

pub fn load_with_sources(db: &Connection, org: &str, env: &HashMap<String, String>) -> Value {
    let inv = inventory(db, org, env);
    let pub_url = inv["public_base_url"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let hosts: Vec<String> = inv["allowed_hosts"]["value"]
        .as_str()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let scopes: Vec<String> = inv["mcp_max_scopes"]["value"]
        .as_str()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let retention: i64 = inv["archive_retention_days"]["value"]
        .as_str()
        .unwrap_or("180")
        .parse()
        .unwrap_or(180);

    let mut sources = serde_json::Map::new();
    if let Some(obj) = inv.as_object() {
        for (k, v) in obj {
            sources.insert(
                k.clone(),
                Value::String(v["source"].as_str().unwrap_or("default").to_string()),
            );
        }
    }

    json!({
        "values": {
            "public_base_url": pub_url,
            "allowed_hosts": hosts,
            "mcp_max_scopes": scopes,
            "archive_retention_days": retention,
        },
        "sources": sources,
        "settings": inv,
    })
}

pub fn load(db: &Connection, org: &str, env: &HashMap<String, String>) -> LoadedSettings {
    let full = load_with_sources(db, org, env);
    let vals = &full["values"];
    LoadedSettings {
        public_base_url: vals["public_base_url"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        allowed_hosts: vals["allowed_hosts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        mcp_max_scopes: vals["mcp_max_scopes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        archive_retention_days: vals["archive_retention_days"].as_i64().unwrap_or(180),
    }
}

pub fn save(
    db: &Connection,
    org: &str,
    values: &serde_json::Map<String, Value>,
    env: &HashMap<String, String>,
) -> Result<Value, String> {
    for (key, val) in values {
        if !SETTING_KEYS.contains(&key.as_str()) || !env_value(key, env).is_empty() {
            return Err("Unknown or environment-managed setting".to_string());
        }
        let clean = validate(key, val)?;
        db.execute(
            "INSERT INTO runtime_settings(organization_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(organization_id, key) DO UPDATE SET value=excluded.value",
            params![org, key, clean],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(load_with_sources(db, org, env))
}
