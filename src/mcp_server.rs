//! MCP connector boundary for Business MCP Hub (audience: `lnc-care`, namespace: `care__*`).
//!
//! Supports both:
//! 1. Canonical Business MCP Hub v3/v4 delegation headers (`x-mcp-hub-client-id`,
//!    `x-mcp-hub-client-scopes`, `x-mcp-hub-client-timestamp`, `x-mcp-hub-client-nonce`,
//!    `x-mcp-hub-client-signature`, optional `x-mcp-hub-app-id`).
//! 2. Compact `X-LNC-Delegation` v3/v4 HMAC-signed token header.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use regex::Regex;
use rusqlite::params;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::mcp_gateway::McpGatewayClient;
use crate::store::{self, query_maps, query_one_map};
use crate::transport::SharedTransport;
use crate::vault::Vault;
use crate::{audit, connections, evaluator, evidence, fleet, settings, worker};

type HmacSha256 = Hmac<Sha256>;

pub const AUDIENCE: &str = "lnc-care";
pub const MAX_HUB_SKEW_SECONDS: i64 = 90;
pub const NONCE_TTL_SECONDS: i64 = 300;

pub const HUB_DELEGATION_HEADERS: &[&str] = &[
    "x-mcp-hub-client-id",
    "x-mcp-hub-client-scopes",
    "x-mcp-hub-client-timestamp",
    "x-mcp-hub-client-nonce",
    "x-mcp-hub-client-signature",
];

pub const SCOPES: &[&str] = &[
    "care:read",
    "care:read:meta",
    "care:read:tiktok",
    "care:read:youtube",
    "care:write",
    "care:write:meta",
    "care:write:tiktok",
    "care:write:youtube",
];

#[derive(Debug, Clone)]
pub struct DelegationError(pub String);

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DelegationError {}

#[derive(Debug, Clone)]
pub struct McpCaller {
    pub sub: String,
    pub app_id: String,
    pub scopes: BTreeSet<String>,
}

#[derive(Clone)]
pub struct McpServerConfig {
    pub path: PathBuf,
    pub org: String,
    pub bearer_token: String,
    pub delegation_secret: String,
    pub require_delegation: bool,
    pub writes_enabled: bool,
    pub mcp_gateway: Option<McpGatewayClient>,
    pub audience: String,
    pub vault: Vault,
    pub env_map: HashMap<String, String>,
    pub transport: Option<SharedTransport>,
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

/// Canonical compact sorted-key UTF-8 JSON (`ensure_ascii=False`, `separators=(",",":")`).
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_utf8(value, &mut out);
    out
}

fn write_canonical_utf8(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            if let Ok(encoded) = serde_json::to_string(s) {
                out.push_str(&encoded);
            } else {
                out.push_str("\"\"");
            }
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_utf8(item, out);
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
                out.push_str(&serde_json::to_string(k).unwrap_or_else(|_| "\"\"".to_string()));
                out.push(':');
                write_canonical_utf8(&map[*k], out);
            }
            out.push('}');
        }
    }
}

pub fn tool_scopes_map() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut m = BTreeMap::new();
    // Read tools (`care:read`)
    for name in [
        "shops_list",
        "channels_list",
        "posts_list",
        "post_get",
        "comments_list",
        "comment_thread",
        "conversations_list",
        "messages_list",
        "leads_list",
        "handoffs_list",
        "stats_series",
        "inbox_summary",
        "evidence_case_get",
        "ads_context_lookup",
        "fleet_runtimes_list",
        "playbooks_list",
    ] {
        m.insert(name, vec!["care:read"]);
    }
    // Internal triage / CRM / forensic write tools + guarded external provider write tools (`care:read`, `care:write`)
    for name in [
        "comment_evaluate",
        "evaluation_feedback_set",
        "comment_flag_set",
        "reply_draft_create",
        "lead_upsert",
        "ticket_handoff",
        "archive_request",
        "evidence_capture",
        "evidence_watchdog_check",
        "channel_webhook_subscribe",
        "fleet_runtime_probe",
        "playbook_upsert",
        "comment_reply",
        "comment_hide_set",
        "comment_private_reply",
        "message_reply",
    ] {
        m.insert(name, vec!["care:read", "care:write"]);
    }
    m
}

fn known_scopes_set() -> BTreeSet<String> {
    SCOPES.iter().map(|s| (*s).to_string()).collect()
}

fn claim_nonce(path: &Path, org: &str, nonce: &str, expires_at: i64) -> Result<(), DelegationError> {
    let now = now_unix();
    let db = store::connect(path).map_err(|e| DelegationError(e.to_string()))?;
    db.execute_batch("BEGIN IMMEDIATE;")
        .map_err(|e| DelegationError(e.to_string()))?;
    let _ = db.execute(
        "DELETE FROM delegation_nonces WHERE organization_id=?1 AND expires_at<=?2",
        params![org, now],
    );
    let ins = db.execute(
        "INSERT INTO delegation_nonces (organization_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
        params![org, nonce, expires_at],
    );
    match ins {
        Ok(_) => {
            db.execute_batch("COMMIT;")
                .map_err(|e| DelegationError(e.to_string()))?;
            Ok(())
        }
        Err(_) => {
            let _ = db.execute_batch("ROLLBACK;");
            Err(DelegationError("Replayed delegation nonce".to_string()))
        }
    }
}

fn hmac_sha256_bytes(secret: &str, data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hub_headers(
    path: &Path,
    org: &str,
    headers: &HashMap<String, String>,
    secret: &str,
    max_scopes: &[String],
    audience: &str,
) -> Result<McpCaller, DelegationError> {
    if secret.is_empty() {
        return Err(DelegationError(
            "Delegation secret is not configured".to_string(),
        ));
    }
    if HUB_DELEGATION_HEADERS.iter().any(|name| {
        headers
            .get(*name)
            .map(|v| v.trim().is_empty())
            .unwrap_or(true)
    }) {
        return Err(DelegationError(
            "Incomplete Business MCP Hub delegation headers".to_string(),
        ));
    }

    let client_id = headers["x-mcp-hub-client-id"].trim();
    let app_id = headers
        .get("x-mcp-hub-app-id")
        .map(|s| s.trim())
        .unwrap_or("");
    let client_re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$").unwrap();
    let app_re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$").unwrap();
    if !client_re.is_match(client_id) || (!app_id.is_empty() && !app_re.is_match(app_id)) {
        return Err(DelegationError(
            "Invalid delegation client_id or app_id".to_string(),
        ));
    }

    let scope_re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9:._*-]{0,63}$").unwrap();
    let scopes_set: BTreeSet<String> = headers["x-mcp-hub-client-scopes"]
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if scopes_set.is_empty() || scopes_set.iter().any(|s| !scope_re.is_match(s)) {
        return Err(DelegationError("Invalid delegation scopes".to_string()));
    }

    let nonce = headers["x-mcp-hub-client-nonce"].trim();
    let nonce_re = Regex::new(r"^[A-Za-z0-9_-]{20,128}$").unwrap();
    if !nonce_re.is_match(nonce) {
        return Err(DelegationError("Invalid delegation nonce".to_string()));
    }

    let timestamp: i64 = headers["x-mcp-hub-client-timestamp"]
        .trim()
        .parse()
        .map_err(|_| DelegationError("Invalid delegation timestamp".to_string()))?;

    let now = now_unix();
    if (now - timestamp).abs() > MAX_HUB_SKEW_SECONDS {
        return Err(DelegationError(
            "Delegation timestamp expired or skewed".to_string(),
        ));
    }

    let max_set: BTreeSet<String> = max_scopes.iter().cloned().collect();
    if !scopes_set.is_subset(&max_set) {
        return Err(DelegationError(
            "Delegated scopes exceed connector max_scopes".to_string(),
        ));
    }

    let scopes_csv: String = scopes_set.iter().cloned().collect::<Vec<_>>().join(",");
    let envelope = if !app_id.is_empty() {
        format!("v4\n{audience}\n{client_id}\n{app_id}\n{timestamp}\n{nonce}\n{scopes_csv}")
    } else {
        format!("v3\n{audience}\n{client_id}\n{timestamp}\n{nonce}\n{scopes_csv}")
    };
    let expected_hex = hex::encode(hmac_sha256_bytes(secret, envelope.as_bytes()));
    let provided_sig = headers["x-mcp-hub-client-signature"]
        .trim()
        .to_ascii_lowercase();
    if expected_hex.as_bytes().ct_eq(provided_sig.as_bytes()).unwrap_u8() != 1 {
        return Err(DelegationError("Invalid delegation signature".to_string()));
    }

    claim_nonce(path, org, nonce, now + NONCE_TTL_SECONDS)?;
    let known = known_scopes_set();
    let effective: BTreeSet<String> = scopes_set
        .intersection(&max_set)
        .cloned()
        .filter(|s| known.contains(s))
        .collect();
    Ok(McpCaller {
        sub: client_id.to_string(),
        app_id: app_id.to_string(),
        scopes: effective,
    })
}

fn decode_b64url_flexible(input: &str) -> Result<Vec<u8>, DelegationError> {
    let clean = input.trim().trim_end_matches('=');
    B64_URL
        .decode(clean)
        .map_err(|_| DelegationError("Malformed X-LNC-Delegation".to_string()))
}

pub fn verify_delegation(
    path: &Path,
    org: &str,
    header: Option<&str>,
    secret: &str,
    require_delegation: bool,
    max_scopes: &[String],
    headers: Option<&HashMap<String, String>>,
    audience: &str,
) -> Result<McpCaller, DelegationError> {
    if let Some(hdrs) = headers {
        if HUB_DELEGATION_HEADERS.iter().any(|k| hdrs.contains_key(*k)) {
            return verify_hub_headers(path, org, hdrs, secret, max_scopes, audience);
        }
    }

    let max_set: BTreeSet<String> = max_scopes.iter().cloned().collect();
    let known = known_scopes_set();

    let Some(raw_header) = header.filter(|s| !s.trim().is_empty()) else {
        if require_delegation {
            return Err(DelegationError("Missing X-LNC-Delegation".to_string()));
        }
        let effective: BTreeSet<String> = max_set.intersection(&known).cloned().collect();
        return Ok(McpCaller {
            sub: "direct-bearer".to_string(),
            app_id: String::new(),
            scopes: effective,
        });
    };

    if secret.is_empty() {
        return Err(DelegationError(
            "Delegation secret is not configured".to_string(),
        ));
    }

    let (raw_part, sig_part) = raw_header
        .split_once('.')
        .ok_or_else(|| DelegationError("Malformed X-LNC-Delegation".to_string()))?;
    let payload_bytes = decode_b64url_flexible(raw_part)?;
    let sig_bytes = decode_b64url_flexible(sig_part)?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| DelegationError("Malformed X-LNC-Delegation".to_string()))?;

    let expected = hmac_sha256_bytes(secret, &payload_bytes);
    if sig_bytes.ct_eq(&expected).unwrap_u8() != 1 {
        let expected_canon = hmac_sha256_bytes(secret, canonical_json(&payload).as_bytes());
        if sig_bytes.ct_eq(&expected_canon).unwrap_u8() != 1 {
            return Err(DelegationError("Invalid delegation signature".to_string()));
        }
    }

    let now = now_unix();
    let v = payload.get("v").and_then(|x| x.as_i64()).unwrap_or(0);
    let iss = payload.get("iss").and_then(|x| x.as_str()).unwrap_or("");
    let aud = payload.get("aud").and_then(|x| x.as_str()).unwrap_or("");
    if (v != 3 && v != 4) || iss != "lnc-v3" || aud != audience {
        return Err(DelegationError("Invalid delegation claims".to_string()));
    }
    let sub = payload
        .get("sub")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DelegationError("Missing delegation identity or nonce".to_string()))?;
    let nonce = payload
        .get("nonce")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DelegationError("Missing delegation identity or nonce".to_string()))?;

    let iat = payload.get("iat").and_then(|x| x.as_i64()).unwrap_or(0);
    let exp = payload.get("exp").and_then(|x| x.as_i64()).unwrap_or(0);
    if iat > now + 30 || exp <= now || exp - iat > 300 {
        return Err(DelegationError(
            "Delegation expired or TTL invalid".to_string(),
        ));
    }

    let mut parsed_scopes = BTreeSet::new();
    if let Some(arr) = payload.get("scopes").or_else(|| payload.get("scope")) {
        match arr {
            Value::Array(items) => {
                for it in items {
                    if let Some(s) = it.as_str() {
                        let t = s.trim();
                        if !t.is_empty() {
                            parsed_scopes.insert(t.to_string());
                        }
                    }
                }
            }
            Value::String(s) => {
                for tok in s.replace(',', " ").split_whitespace() {
                    if !tok.is_empty() {
                        parsed_scopes.insert(tok.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    let effective: BTreeSet<String> = parsed_scopes
        .intersection(&max_set)
        .cloned()
        .filter(|s| known.contains(s))
        .collect();

    claim_nonce(path, org, nonce, exp)?;
    let app_id = payload
        .get("app_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    Ok(McpCaller {
        sub: sub.to_string(),
        app_id,
        scopes: effective,
    })
}

fn require_tool_scopes<'a>(
    caller: &'a McpCaller,
    tool: &str,
    extra: &[String],
) -> Result<&'a McpCaller, String> {
    let scopes_map = tool_scopes_map();
    let base = scopes_map
        .get(tool)
        .ok_or_else(|| format!("Unknown tool: {tool}"))?;
    for req in base {
        if !caller.scopes.contains(*req) {
            return Err(format!("Insufficient scope for {tool}"));
        }
    }
    for req in extra {
        if !caller.scopes.contains(req) {
            return Err(format!("Insufficient scope for {tool}"));
        }
    }
    Ok(caller)
}

fn guarded_comment_write<F>(
    path: &Path,
    org: &str,
    caller: &McpCaller,
    tool: &str,
    comment_id: i64,
    idempotency_key: &str,
    request_payload: &Value,
    writes_enabled: bool,
    f: F,
) -> Result<Value, String>
where
    F: FnOnce(&rusqlite::Connection, &McpCaller, &Map<String, Value>) -> Result<Value, String>,
{
    if idempotency_key.trim().len() < 6 {
        return Err("idempotency_key_required".to_string());
    }
    let req_hash = hex::encode(Sha256::digest(canonical_json(request_payload).as_bytes()));

    let cm = {
        let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
        let row = query_one_map(
            &db,
            "SELECT cm.*, c.provider, c.adapter, c.approved, c.reply_policy
             FROM comments cm
             JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
             WHERE cm.organization_id=? AND cm.id=?",
            &[org.to_string().into(), comment_id.into()],
        )
        .ok_or_else(|| "comment_or_channel_not_authorized".to_string())?;
        if row.get("approved").and_then(|v| v.as_i64()).unwrap_or(0) == 0 {
            return Err("comment_or_channel_not_authorized".to_string());
        }
        row
    };

    if cm.get("adapter").and_then(|v| v.as_str()).unwrap_or("") != "meta_api" {
        return Err("channel_adapter_unsupported".to_string());
    }
    let provider = cm
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("meta");
    require_tool_scopes(caller, tool, &[format!("care:write:{provider}")])?;

    let db = store::connect(path).map_err(|e| e.to_string())?;
    db.execute_batch("BEGIN IMMEDIATE;")
        .map_err(|e| e.to_string())?;
    let outcome: Result<Value, String> = (|| {
        if let Some(existing) = query_one_map(
            &db,
            "SELECT * FROM write_operations WHERE organization_id=? AND idempotency_key=?",
            &[org.to_string().into(), idempotency_key.to_string().into()],
        ) {
            let ex_tool = existing.get("tool").and_then(|v| v.as_str()).unwrap_or("");
            let ex_hash = existing
                .get("request_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if ex_tool != tool || ex_hash != req_hash {
                return Err("idempotency_key_conflict".to_string());
            }
            if let Some(res_str) = existing
                .get("result_json")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(res_str) {
                    return Ok(parsed);
                }
            }
        }
        if !writes_enabled {
            return Err("provider_writes_disabled".to_string());
        }
        let res = f(&db, caller, &cm)?;
        db.execute(
            "INSERT OR REPLACE INTO write_operations
             (organization_id, idempotency_key, tool, request_hash, result_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                org,
                idempotency_key,
                tool,
                req_hash,
                serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string()),
                now_unix(),
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(res)
    })();

    match outcome {
        Ok(v) => {
            db.execute_batch("COMMIT;").map_err(|e| e.to_string())?;
            Ok(v)
        }
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

fn guarded_conversation_write<F>(
    path: &Path,
    org: &str,
    caller: &McpCaller,
    tool: &str,
    conversation_id: i64,
    idempotency_key: &str,
    request_payload: &Value,
    writes_enabled: bool,
    f: F,
) -> Result<Value, String>
where
    F: FnOnce(&rusqlite::Connection, &McpCaller, &Map<String, Value>) -> Result<Value, String>,
{
    if idempotency_key.trim().len() < 6 {
        return Err("idempotency_key_required".to_string());
    }
    let req_hash = hex::encode(Sha256::digest(canonical_json(request_payload).as_bytes()));

    let conv = {
        let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
        let row = query_one_map(
            &db,
            "SELECT cv.*, c.provider, c.adapter, c.approved, c.reply_policy
             FROM conversations cv
             JOIN channels c ON c.id=cv.channel_id AND c.organization_id=cv.organization_id
             WHERE cv.organization_id=? AND cv.id=?",
            &[org.to_string().into(), conversation_id.into()],
        )
        .ok_or_else(|| "conversation_or_channel_not_authorized".to_string())?;
        if row.get("approved").and_then(|v| v.as_i64()).unwrap_or(0) == 0 {
            return Err("conversation_or_channel_not_authorized".to_string());
        }
        row
    };

    if conv.get("adapter").and_then(|v| v.as_str()).unwrap_or("") != "meta_api" {
        return Err("channel_adapter_unsupported".to_string());
    }
    let provider = conv
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("meta");
    require_tool_scopes(caller, tool, &[format!("care:write:{provider}")])?;

    let db = store::connect(path).map_err(|e| e.to_string())?;
    db.execute_batch("BEGIN IMMEDIATE;")
        .map_err(|e| e.to_string())?;
    let outcome: Result<Value, String> = (|| {
        if let Some(existing) = query_one_map(
            &db,
            "SELECT * FROM write_operations WHERE organization_id=? AND idempotency_key=?",
            &[org.to_string().into(), idempotency_key.to_string().into()],
        ) {
            let ex_tool = existing.get("tool").and_then(|v| v.as_str()).unwrap_or("");
            let ex_hash = existing
                .get("request_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if ex_tool != tool || ex_hash != req_hash {
                return Err("idempotency_key_conflict".to_string());
            }
            if let Some(res_str) = existing
                .get("result_json")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(res_str) {
                    return Ok(parsed);
                }
            }
        }
        if !writes_enabled {
            return Err("provider_writes_disabled".to_string());
        }
        let res = f(&db, caller, &conv)?;
        db.execute(
            "INSERT OR REPLACE INTO write_operations
             (organization_id, idempotency_key, tool, request_hash, result_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                org,
                idempotency_key,
                tool,
                req_hash,
                serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string()),
                now_unix(),
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(res)
    })();

    match outcome {
        Ok(v) => {
            db.execute_batch("COMMIT;").map_err(|e| e.to_string())?;
            Ok(v)
        }
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

fn opt_i64(args: &Map<String, Value>, key: &str) -> Option<i64> {
    match args.get(key) {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn req_i64(args: &Map<String, Value>, key: &str) -> Result<i64, String> {
    opt_i64(args, key).ok_or_else(|| format!("Missing or invalid integer argument: {key}"))
}

fn opt_str<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

fn opt_bool(args: &Map<String, Value>, key: &str, default: bool) -> bool {
    match args.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1"),
        Some(Value::Number(n)) => n.as_i64().map(|x| x != 0).unwrap_or(default),
        _ => default,
    }
}

fn req_bool(args: &Map<String, Value>, key: &str) -> Result<bool, String> {
    match args.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(format!("Invalid boolean argument: {key}")),
        },
        _ => Err(format!("Missing boolean argument: {key}")),
    }
}

fn execute_tool(
    cfg: &McpServerConfig,
    caller: &McpCaller,
    raw_name: &str,
    args: &Map<String, Value>,
) -> Result<Value, String> {
    let tool = raw_name.strip_prefix("care__").unwrap_or(raw_name);
    let path = &cfg.path;
    let org = &cfg.org;
    let actor = format!("mcp:{}", caller.sub);

    match tool {
        "shops_list" => {
            require_tool_scopes(caller, "shops_list", &[])?;
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(json!({ "shops": store::shops(&db, org) }))
        }
        "channels_list" => {
            require_tool_scopes(caller, "channels_list", &[])?;
            let shop_id = opt_i64(args, "shop_id");
            let approved_only = opt_bool(args, "approved_only", true);
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(json!({
                "channels": store::channels(&db, org, shop_id, approved_only)
            }))
        }
        "posts_list" => {
            require_tool_scopes(caller, "posts_list", &[])?;
            let channel_id = opt_i64(args, "channel_id");
            let shop_id = opt_i64(args, "shop_id");
            let kind = opt_str(args, "kind");
            let limit = opt_i64(args, "limit").unwrap_or(25).clamp(1, 100);
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(json!({
                "posts": store::posts_list(&db, org, channel_id, shop_id, kind, limit)
            }))
        }
        "post_get" => {
            require_tool_scopes(caller, "post_get", &[])?;
            let post_id = req_i64(args, "post_id")?;
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            let post = store::post_detail(&db, org, post_id)
                .ok_or_else(|| "post_not_found".to_string())?;
            Ok(json!({ "post": post }))
        }
        "comments_list" => {
            require_tool_scopes(caller, "comments_list", &[])?;
            let shop_id = opt_i64(args, "shop_id");
            let channel_id = opt_i64(args, "channel_id");
            let post_id = opt_i64(args, "post_id");
            let status = opt_str(args, "status");
            let bucket = opt_str(args, "bucket");
            let assignment = opt_str(args, "assignment");
            let search = opt_str(args, "search");
            let limit = opt_i64(args, "limit").unwrap_or(50).clamp(1, 100);
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(json!({
                "comments": store::comments_list(
                    &db, org, shop_id, channel_id, post_id, status, bucket, assignment, search, limit
                )
            }))
        }
        "comment_thread" => {
            require_tool_scopes(caller, "comment_thread", &[])?;
            let comment_id = req_i64(args, "comment_id")?;
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            let thread = store::comment_thread(&db, org, comment_id)
                .ok_or_else(|| "comment_not_found".to_string())?;
            Ok(json!({ "thread": thread }))
        }
        "conversations_list" => {
            require_tool_scopes(caller, "conversations_list", &[])?;
            let shop_id = opt_i64(args, "shop_id");
            let channel_id = opt_i64(args, "channel_id");
            let status = opt_str(args, "status");
            let limit = opt_i64(args, "limit").unwrap_or(50).clamp(1, 100);
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(json!({
                "conversations": store::conversations_list(&db, org, shop_id, channel_id, status, limit)
            }))
        }
        "messages_list" => {
            require_tool_scopes(caller, "messages_list", &[])?;
            let conversation_id = req_i64(args, "conversation_id")?;
            let limit = opt_i64(args, "limit").unwrap_or(50).clamp(1, 200);
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            let conv = query_one_map(
                &db,
                "SELECT * FROM conversations WHERE organization_id=? AND id=?",
                &[org.clone().into(), conversation_id.into()],
            )
            .ok_or_else(|| "conversation_not_found".to_string())?;
            Ok(json!({
                "conversation": conv,
                "messages": store::messages_list(&db, org, conversation_id, limit),
            }))
        }
        "leads_list" => {
            require_tool_scopes(caller, "leads_list", &[])?;
            let shop_id = opt_i64(args, "shop_id");
            let status = opt_str(args, "status");
            let limit = opt_i64(args, "limit").unwrap_or(50).clamp(1, 100);
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(json!({
                "leads": store::leads_list(&db, org, shop_id, None, status, limit)
            }))
        }
        "handoffs_list" => {
            require_tool_scopes(caller, "handoffs_list", &[])?;
            let shop_id = opt_i64(args, "shop_id");
            let status = opt_str(args, "status");
            let limit = opt_i64(args, "limit").unwrap_or(50).clamp(1, 100);
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(json!({
                "handoffs": store::handoffs_list(&db, org, shop_id, status, limit)
            }))
        }
        "stats_series" => {
            require_tool_scopes(caller, "stats_series", &[])?;
            let channel_id = opt_i64(args, "channel_id");
            let post_id = opt_i64(args, "post_id");
            let days = opt_i64(args, "days").unwrap_or(30);
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(store::stats_series(&db, org, channel_id, post_id, days))
        }
        "inbox_summary" => {
            require_tool_scopes(caller, "inbox_summary", &[])?;
            let shop_id = opt_i64(args, "shop_id");
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(store::inbox_summary(&db, org, shop_id))
        }
        "evidence_case_get" => {
            require_tool_scopes(caller, "evidence_case_get", &[])?;
            let case_id = req_i64(args, "case_id")?;
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            let case_row = query_one_map(
                &db,
                "SELECT * FROM evidence_cases WHERE organization_id=? AND id=?",
                &[org.clone().into(), case_id.into()],
            )
            .ok_or_else(|| "evidence_case_not_found".to_string())?;
            let items: Vec<Value> = query_maps(
                &db,
                "SELECT * FROM evidence_items WHERE organization_id=? AND case_id=? ORDER BY id",
                &[org.clone().into(), case_id.into()],
            )
            .into_iter()
            .map(|mut m| {
                let artifacts = m
                    .get("artifacts_json")
                    .and_then(|v| v.as_str())
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    .unwrap_or_else(|| json!({}));
                m.insert("artifacts".to_string(), artifacts);
                Value::Object(m)
            })
            .collect();
            Ok(json!({ "case": case_row, "items": items }))
        }
        "ads_context_lookup" => {
            require_tool_scopes(caller, "ads_context_lookup", &[])?;
            let gw = cfg
                .mcp_gateway
                .as_ref()
                .ok_or_else(|| "mcp_gateway_not_configured".to_string())?;
            let tool_name = opt_str(args, "tool_name")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "tool_name is required".to_string())?;
            let sub_args = args.get("arguments");
            gw.call_tool(tool_name, sub_args).map_err(|e| e.code)
        }
        "fleet_runtimes_list" => {
            require_tool_scopes(caller, "fleet_runtimes_list", &[])?;
            let shop_id = opt_i64(args, "shop_id");
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            let mut sql = String::from("SELECT * FROM account_runtimes WHERE organization_id=?");
            let mut pvec: Vec<rusqlite::types::Value> = vec![org.clone().into()];
            if let Some(sid) = shop_id {
                sql.push_str(" AND (shop_id=? OR shop_id IS NULL)");
                pvec.push(sid.into());
            }
            sql.push_str(" ORDER BY id ASC");
            let runtimes: Vec<Value> = query_maps(&db, &sql, &pvec)
                .into_iter()
                .map(Value::Object)
                .collect();
            let leases: Vec<Value> = query_maps(
                &db,
                "SELECT * FROM runtime_leases WHERE organization_id=? ORDER BY id DESC LIMIT 30",
                &[org.clone().into()],
            )
            .into_iter()
            .map(Value::Object)
            .collect();
            Ok(json!({ "runtimes": runtimes, "leases": leases }))
        }
        "playbooks_list" => {
            require_tool_scopes(caller, "playbooks_list", &[])?;
            let shop_id = opt_i64(args, "shop_id");
            let channel_id = opt_i64(args, "channel_id");
            let db = store::connect_readonly(path).map_err(|e| e.to_string())?;
            Ok(json!({
                "playbooks": fleet::playbooks_list(&db, org, shop_id, channel_id)
            }))
        }
        "comment_evaluate" => {
            require_tool_scopes(caller, "comment_evaluate", &[])?;
            let comment_id = req_i64(args, "comment_id")?;
            let threshold = opt_i64(args, "threshold");
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                let res =
                    evaluator::evaluate_and_persist(db, org, comment_id, threshold, &actor)?;
                audit::append(
                    db,
                    org,
                    &actor,
                    "comment.evaluated",
                    &comment_id.to_string(),
                    &json!({
                        "overall_score": res.get("overall_score"),
                        "recommended_action": res.get("recommended_action"),
                    }),
                )
                .map_err(|e| e.to_string())?;
                Ok(res)
            })
        }
        "evaluation_feedback_set" => {
            require_tool_scopes(caller, "evaluation_feedback_set", &[])?;
            let comment_id = req_i64(args, "comment_id")?;
            let label = opt_str(args, "label")
                .ok_or_else(|| "label is required".to_string())?;
            let agreed = req_bool(args, "agreed")?;
            let human_decision = opt_i64(args, "human_decision");
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                let res = evaluator::record_feedback(
                    db,
                    org,
                    comment_id,
                    Some(label),
                    Some(agreed),
                    human_decision,
                    &actor,
                )?;
                audit::append(
                    db,
                    org,
                    &actor,
                    "comment.feedback_recorded",
                    &comment_id.to_string(),
                    &json!({
                        "label": label,
                        "agreed": agreed,
                        "human_decision": human_decision,
                    }),
                )
                .map_err(|e| e.to_string())?;
                Ok(res)
            })
        }
        "comment_flag_set" => {
            require_tool_scopes(caller, "comment_flag_set", &[])?;
            let comment_id = req_i64(args, "comment_id")?;
            let status = opt_str(args, "status").unwrap_or("needs_reply");
            if !store::COMMENT_STATUSES.contains(&status) {
                return Err("invalid_comment_status".to_string());
            }
            let bucket = opt_str(args, "bucket");
            if let Some(b) = bucket {
                if !store::COMMENT_BUCKETS.contains(&b) {
                    return Err("invalid_comment_bucket".to_string());
                }
            }
            let assigned_to = opt_str(args, "assigned_to");
            let note = opt_str(args, "note");
            let now = now_unix();
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                let exists = db
                    .query_row(
                        "SELECT 1 FROM comments WHERE organization_id=?1 AND id=?2",
                        params![org, comment_id],
                        |r| r.get::<_, i64>(0),
                    )
                    .is_ok();
                if !exists {
                    return Err("comment_not_found".to_string());
                }
                let cur = query_one_map(
                    db,
                    "SELECT * FROM comment_states WHERE organization_id=? AND comment_id=?",
                    &[org.clone().into(), comment_id.into()],
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
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                      status=excluded.status,
                      bucket=excluded.bucket,
                      assigned_to=excluded.assigned_to,
                      note=excluded.note,
                      updated_by=excluded.updated_by,
                      updated_at=excluded.updated_at",
                    params![
                        org,
                        comment_id,
                        status,
                        eff_bucket,
                        eff_assigned,
                        eff_note,
                        actor,
                        now
                    ],
                )
                .map_err(|e| e.to_string())?;
                audit::append(
                    db,
                    org,
                    &actor,
                    "comment.state_updated",
                    &comment_id.to_string(),
                    &json!({
                        "status": status,
                        "bucket": eff_bucket,
                        "assigned_to": eff_assigned,
                    }),
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({
                    "ok": true,
                    "comment_id": comment_id,
                    "status": status,
                    "bucket": eff_bucket,
                }))
            })
        }
        "reply_draft_create" => {
            require_tool_scopes(caller, "reply_draft_create", &[])?;
            let comment_id = req_i64(args, "comment_id")?;
            let clean_text = opt_str(args, "text")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "draft_text_required".to_string())?;
            let kind = opt_str(args, "kind").unwrap_or("public");
            if !matches!(kind, "public" | "private_dm") {
                return Err("invalid_draft_kind".to_string());
            }
            let strategy_summary = opt_str(args, "strategy_summary").unwrap_or("").trim();
            let now = now_unix();
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                let exists = db
                    .query_row(
                        "SELECT 1 FROM comments WHERE organization_id=?1 AND id=?2",
                        params![org, comment_id],
                        |r| r.get::<_, i64>(0),
                    )
                    .is_ok();
                if !exists {
                    return Err("comment_not_found".to_string());
                }
                db.execute(
                    "INSERT INTO reply_drafts
                     (organization_id, comment_id, kind, strategy_summary, text, created_by, status, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'draft', ?7, ?8)",
                    params![
                        org,
                        comment_id,
                        kind,
                        strategy_summary,
                        clean_text,
                        actor,
                        now,
                        now
                    ],
                )
                .map_err(|e| e.to_string())?;
                let draft_id = db.last_insert_rowid();
                audit::append(
                    db,
                    org,
                    &actor,
                    "reply_draft.created",
                    &draft_id.to_string(),
                    &json!({ "comment_id": comment_id, "kind": kind }),
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({
                    "ok": true,
                    "draft_id": draft_id,
                    "comment_id": comment_id,
                    "kind": kind,
                    "status": "draft",
                }))
            })
        }
        "lead_upsert" => {
            require_tool_scopes(caller, "lead_upsert", &[])?;
            let clean_name = opt_str(args, "customer_name")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "customer_name_required".to_string())?;
            let source = opt_str(args, "source").unwrap_or("comment");
            if !matches!(source, "comment" | "dm" | "meta_lead_ad" | "manual") {
                return Err("invalid_lead_source".to_string());
            }
            let shop_id = opt_i64(args, "shop_id");
            let channel_id = opt_i64(args, "channel_id");
            let external_id = opt_str(args, "external_id").unwrap_or("").trim();
            let contact_handle = opt_str(args, "contact_handle").unwrap_or("").trim();
            let phone = opt_str(args, "phone").unwrap_or("").trim();
            let email = opt_str(args, "email").unwrap_or("").trim();
            let intent_score = args
                .get("intent_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(85.0);
            let status = opt_str(args, "status").unwrap_or("new");
            if !matches!(
                status,
                "new" | "qualified" | "contacted" | "converted" | "archived"
            ) {
                return Err("invalid_lead_status".to_string());
            }
            let notes = opt_str(args, "notes").unwrap_or("").trim();
            let now = now_unix();
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                let existing_id: Option<i64> = if !external_id.is_empty() {
                    db.query_row(
                        "SELECT id FROM leads WHERE organization_id=?1 AND external_id=?2",
                        params![org, external_id],
                        |r| r.get(0),
                    )
                    .ok()
                } else {
                    None
                };
                let lead_id = if let Some(lid) = existing_id {
                    db.execute(
                        "UPDATE leads
                         SET customer_name=?1, contact_handle=?2, phone=?3, email=?4,
                             intent_score=?5, status=?6, notes=?7, updated_at=?8
                         WHERE organization_id=?9 AND id=?10",
                        params![
                            clean_name,
                            contact_handle,
                            phone,
                            email,
                            intent_score,
                            status,
                            notes,
                            now,
                            org,
                            lid
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    lid
                } else {
                    db.execute(
                        "INSERT INTO leads
                         (organization_id, shop_id, channel_id, source, external_id, customer_name,
                          contact_handle, phone, email, intent_score, status, notes, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                        params![
                            org,
                            shop_id,
                            channel_id,
                            source,
                            external_id,
                            clean_name,
                            contact_handle,
                            phone,
                            email,
                            intent_score,
                            status,
                            notes,
                            now,
                            now
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    db.last_insert_rowid()
                };
                audit::append(
                    db,
                    org,
                    &actor,
                    "lead.upserted",
                    &lead_id.to_string(),
                    &json!({ "source": source, "status": status }),
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({ "ok": true, "lead_id": lead_id, "status": status }))
            })
        }
        "ticket_handoff" => {
            require_tool_scopes(caller, "ticket_handoff", &[])?;
            let clean_summary = opt_str(args, "summary")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "handoff_summary_required".to_string())?;
            let priority = opt_str(args, "priority").unwrap_or("normal");
            if !matches!(priority, "low" | "normal" | "high" | "urgent") {
                return Err("invalid_handoff_priority".to_string());
            }
            let assignee_raw = opt_str(args, "assignee").unwrap_or("care-team");
            let eff_assignee = if assignee_raw.trim().is_empty() {
                "care-team"
            } else {
                assignee_raw.trim()
            };
            let shop_id = opt_i64(args, "shop_id");
            let channel_id = opt_i64(args, "channel_id");
            let comment_id = opt_i64(args, "comment_id");
            let conversation_id = opt_i64(args, "conversation_id");
            let ctx_json = args
                .get("context")
                .filter(|v| v.is_object())
                .and_then(|v| serde_json::to_string(v).ok())
                .unwrap_or_else(|| "{}".to_string());
            let now = now_unix();
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                db.execute(
                    "INSERT INTO ticket_handoffs
                     (organization_id, shop_id, channel_id, comment_id, conversation_id,
                      priority, assignee, summary, context_json, status, created_by, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'open', ?10, ?11, ?12)",
                    params![
                        org,
                        shop_id,
                        channel_id,
                        comment_id,
                        conversation_id,
                        priority,
                        eff_assignee,
                        clean_summary,
                        ctx_json,
                        actor,
                        now,
                        now
                    ],
                )
                .map_err(|e| e.to_string())?;
                let ticket_id = db.last_insert_rowid();
                if let Some(cid) = conversation_id {
                    let _ = db.execute(
                        "UPDATE conversations SET status='handed_off', assigned_to=?1, updated_at=?2 WHERE organization_id=?3 AND id=?4",
                        params![eff_assignee, now, org, cid],
                    );
                }
                audit::append(
                    db,
                    org,
                    &actor,
                    "ticket.handed_off",
                    &ticket_id.to_string(),
                    &json!({
                        "priority": priority,
                        "assignee": assignee_raw,
                        "comment_id": comment_id,
                        "conversation_id": conversation_id,
                    }),
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({
                    "ok": true,
                    "handoff_id": ticket_id,
                    "priority": priority,
                    "status": "open",
                }))
            })
        }
        "archive_request" => {
            require_tool_scopes(caller, "archive_request", &[])?;
            let post_id = req_i64(args, "post_id")?;
            let include_screenshot = opt_bool(args, "include_screenshot", true);
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                let exists = db
                    .query_row(
                        "SELECT 1 FROM posts WHERE organization_id=?1 AND id=?2",
                        params![org, post_id],
                        |r| r.get::<_, i64>(0),
                    )
                    .is_ok();
                if !exists {
                    return Err("post_not_found".to_string());
                }
                let mut job_ids = vec![worker::enqueue_job(
                    db,
                    org,
                    "archive_media",
                    &json!({ "post_id": post_id }),
                    0,
                )
                .map_err(|e| e.to_string())?];
                if include_screenshot {
                    job_ids.push(
                        worker::enqueue_job(
                            db,
                            org,
                            "screenshot",
                            &json!({ "post_id": post_id }),
                            0,
                        )
                        .map_err(|e| e.to_string())?,
                    );
                }
                audit::append(
                    db,
                    org,
                    &actor,
                    "post.archive_requested",
                    &post_id.to_string(),
                    &json!({ "job_ids": job_ids }),
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({ "ok": true, "post_id": post_id, "job_ids": job_ids }))
            })
        }
        "evidence_capture" => {
            require_tool_scopes(caller, "evidence_capture", &[])?;
            let target_url = opt_str(args, "target_url").unwrap_or("");
            let title = opt_str(args, "title").unwrap_or("");
            let comment_id = opt_i64(args, "comment_id");
            let case_id = opt_i64(args, "case_id");
            store::with_write_tx_str(path, |db| {
                connections::capture_forensic_evidence_on_disk(
                    db,
                    path,
                    org,
                    target_url,
                    title,
                    comment_id,
                    case_id,
                    &actor,
                    cfg.transport.as_ref(),
                )
            })
        }
        "evidence_watchdog_check" => {
            require_tool_scopes(caller, "evidence_watchdog_check", &[])?;
            let case_id = opt_i64(args, "case_id");
            let item_id = opt_i64(args, "item_id");
            let data_dir = evidence::resolve_data_dir(path);
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                let watchdog = evidence::run_watchdog_check(
                    db,
                    org,
                    case_id,
                    item_id,
                    cfg.transport.as_ref(),
                    &actor,
                )?;
                let custody = if let Some(cid) = case_id {
                    evidence::verify_case_custody(db, &data_dir, org, cid).ok()
                } else {
                    None
                };
                Ok(json!({
                    "ok": true,
                    "watchdog": watchdog,
                    "custody": custody,
                }))
            })
        }
        "channel_webhook_subscribe" => {
            require_tool_scopes(caller, "channel_webhook_subscribe", &[])?;
            let channel_id = req_i64(args, "channel_id")?;
            let fields = opt_str(args, "fields").unwrap_or("feed,messages,mention");
            let now = now_unix();
            store::with_write_tx_str(path, |db| -> Result<Value, String> {
                let exists = db
                    .query_row(
                        "SELECT 1 FROM channels WHERE organization_id=?1 AND id=?2 AND approved=1",
                        params![org, channel_id],
                        |r| r.get::<_, i64>(0),
                    )
                    .is_ok();
                if !exists {
                    return Err("channel_not_authorized".to_string());
                }
                let job_id = worker::enqueue_job(
                    db,
                    org,
                    "backfill",
                    &json!({ "channel_id": channel_id, "subscribe_fields": fields }),
                    0,
                )
                .map_err(|e| e.to_string())?;
                db.execute(
                    "UPDATE channels SET webhook_subscribed_at=?1, webhook_fields=?2, webhook_error=''
                     WHERE organization_id=?3 AND id=?4",
                    params![now, fields, org, channel_id],
                )
                .map_err(|e| e.to_string())?;
                audit::append(
                    db,
                    org,
                    &actor,
                    "channel.webhook_subscribed",
                    &channel_id.to_string(),
                    &json!({ "fields": fields, "job_id": job_id }),
                )
                .map_err(|e| e.to_string())?;
                Ok(json!({
                    "ok": true,
                    "channel_id": channel_id,
                    "webhook_subscribed": true,
                    "webhook_fields": fields,
                    "job_id": job_id,
                }))
            })
        }
        "fleet_runtime_probe" => {
            require_tool_scopes(caller, "fleet_runtime_probe", &[])?;
            let runtime_id = req_i64(args, "runtime_id")?;
            fleet::probe_runtime(
                path,
                org,
                runtime_id,
                cfg.transport.as_ref(),
                &cfg.env_map,
                &actor,
            )
        }
        "playbook_upsert" => {
            require_tool_scopes(caller, "playbook_upsert", &[])?;
            let name = opt_str(args, "name")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "name is required".to_string())?;
            let playbook_id = opt_i64(args, "playbook_id");
            let shop_id = opt_i64(args, "shop_id");
            let channel_id = opt_i64(args, "channel_id");
            let threshold = opt_i64(args, "auto_suggest_threshold").unwrap_or(80);
            let auto_consult = opt_bool(args, "auto_consult_enabled", false);
            let knowledge_md = opt_str(args, "consultation_knowledge_md").unwrap_or("");
            let forbidden: Vec<String> = args
                .get("forbidden_topics")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            store::with_write_tx_str(path, |db| {
                fleet::upsert_playbook(
                    db,
                    org,
                    playbook_id,
                    shop_id,
                    channel_id,
                    name,
                    threshold,
                    auto_consult,
                    knowledge_md,
                    &forbidden,
                    &actor,
                )
            })
        }
        "comment_reply" => {
            let comment_id = req_i64(args, "comment_id")?;
            let clean_text = opt_str(args, "text")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "reply_text_required".to_string())?;
            let idem_key = opt_str(args, "idempotency_key").unwrap_or("");
            guarded_comment_write(
                path,
                org,
                caller,
                "comment_reply",
                comment_id,
                idem_key,
                &json!({ "comment_id": comment_id, "text": clean_text }),
                cfg.writes_enabled,
                |db, c, _cm| {
                    let now = now_unix();
                    let sub_actor = format!("mcp:{}", c.sub);
                    let res_id = format!("meta_reply_{comment_id}_{now}");
                    db.execute(
                        "INSERT INTO comment_actions
                         (organization_id, comment_id, kind, actor, idempotency_key, provider_result_id, status, payload_json, created_at)
                         VALUES (?1, ?2, 'reply', ?3, ?4, ?5, 'completed', ?6, ?7)",
                        params![
                            org,
                            comment_id,
                            sub_actor,
                            idem_key,
                            res_id,
                            json!({ "text": clean_text }).to_string(),
                            now
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    let action_id = db.last_insert_rowid();
                    db.execute(
                        "INSERT INTO comment_states (organization_id, comment_id, status, updated_by, updated_at)
                         VALUES (?1, ?2, 'replied', ?3, ?4)
                         ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                          status='replied', updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                        params![org, comment_id, sub_actor, now],
                    )
                    .map_err(|e| e.to_string())?;
                    audit::append(
                        db,
                        org,
                        &sub_actor,
                        "comment.replied",
                        &comment_id.to_string(),
                        &json!({ "action_id": action_id, "idempotency_key": idem_key }),
                    )
                    .map_err(|e| e.to_string())?;
                    Ok(json!({
                        "ok": true,
                        "action_id": action_id,
                        "comment_id": comment_id,
                        "status": "replied",
                    }))
                },
            )
        }
        "comment_hide_set" => {
            let comment_id = req_i64(args, "comment_id")?;
            let hidden = req_bool(args, "hidden")?;
            let idem_key = opt_str(args, "idempotency_key").unwrap_or("");
            guarded_comment_write(
                path,
                org,
                caller,
                "comment_hide_set",
                comment_id,
                idem_key,
                &json!({ "comment_id": comment_id, "hidden": hidden }),
                cfg.writes_enabled,
                |db, c, _cm| {
                    let now = now_unix();
                    let kind = if hidden { "hide" } else { "unhide" };
                    let sub_actor = format!("mcp:{}", c.sub);
                    let res_id = format!("meta_{kind}_{comment_id}_{now}");
                    db.execute(
                        "INSERT INTO comment_actions
                         (organization_id, comment_id, kind, actor, idempotency_key, provider_result_id, status, payload_json, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'completed', ?7, ?8)",
                        params![
                            org,
                            comment_id,
                            kind,
                            sub_actor,
                            idem_key,
                            res_id,
                            json!({ "hidden": hidden }).to_string(),
                            now
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    let action_id = db.last_insert_rowid();
                    db.execute(
                        "UPDATE comments SET is_hidden=?1 WHERE organization_id=?2 AND id=?3",
                        params![if hidden { 1 } else { 0 }, org, comment_id],
                    )
                    .map_err(|e| e.to_string())?;
                    if hidden {
                        db.execute(
                            "INSERT INTO comment_states (organization_id, comment_id, status, updated_by, updated_at)
                             VALUES (?1, ?2, 'hidden', ?3, ?4)
                             ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                              status='hidden', updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                            params![org, comment_id, sub_actor, now],
                        )
                        .map_err(|e| e.to_string())?;
                    }
                    audit::append(
                        db,
                        org,
                        &sub_actor,
                        &format!("comment.{kind}"),
                        &comment_id.to_string(),
                        &json!({ "action_id": action_id, "hidden": hidden, "idempotency_key": idem_key }),
                    )
                    .map_err(|e| e.to_string())?;
                    Ok(json!({
                        "ok": true,
                        "action_id": action_id,
                        "comment_id": comment_id,
                        "hidden": hidden,
                    }))
                },
            )
        }
        "comment_private_reply" => {
            let comment_id = req_i64(args, "comment_id")?;
            let clean_text = opt_str(args, "text")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "private_reply_text_required".to_string())?;
            let idem_key = opt_str(args, "idempotency_key").unwrap_or("");
            guarded_comment_write(
                path,
                org,
                caller,
                "comment_private_reply",
                comment_id,
                idem_key,
                &json!({ "comment_id": comment_id, "text": clean_text }),
                cfg.writes_enabled,
                |db, c, _cm| {
                    let now = now_unix();
                    let sub_actor = format!("mcp:{}", c.sub);
                    let res_id = format!("meta_dm_{comment_id}_{now}");
                    db.execute(
                        "INSERT INTO comment_actions
                         (organization_id, comment_id, kind, actor, idempotency_key, provider_result_id, status, payload_json, created_at)
                         VALUES (?1, ?2, 'private_reply', ?3, ?4, ?5, 'completed', ?6, ?7)",
                        params![
                            org,
                            comment_id,
                            sub_actor,
                            idem_key,
                            res_id,
                            json!({ "text": clean_text }).to_string(),
                            now
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    let action_id = db.last_insert_rowid();
                    audit::append(
                        db,
                        org,
                        &sub_actor,
                        "comment.private_replied",
                        &comment_id.to_string(),
                        &json!({ "action_id": action_id, "idempotency_key": idem_key }),
                    )
                    .map_err(|e| e.to_string())?;
                    Ok(json!({
                        "ok": true,
                        "action_id": action_id,
                        "comment_id": comment_id,
                        "kind": "private_reply",
                    }))
                },
            )
        }
        "message_reply" => {
            let conversation_id = req_i64(args, "conversation_id")?;
            let clean_text = opt_str(args, "text")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "message_text_required".to_string())?;
            let idem_key = opt_str(args, "idempotency_key").unwrap_or("");
            guarded_conversation_write(
                path,
                org,
                caller,
                "message_reply",
                conversation_id,
                idem_key,
                &json!({ "conversation_id": conversation_id, "text": clean_text }),
                cfg.writes_enabled,
                |db, c, conv| {
                    let now = now_unix();
                    let sub_actor = format!("mcp:{}", c.sub);
                    let ext_id = format!("out_msg_{conversation_id}_{now}_{}", random_hex(3));
                    let channel_id = conv.get("channel_id").and_then(|v| v.as_i64()).unwrap_or(0);
                    db.execute(
                        "INSERT INTO messages
                         (organization_id, conversation_id, channel_id, external_id, direction,
                          sender_id, sender_name, text, status, created_at)
                         VALUES (?1, ?2, ?3, ?4, 'outbound', ?5, 'LNC Care', ?6, 'sent', ?7)",
                        params![
                            org,
                            conversation_id,
                            channel_id,
                            ext_id,
                            sub_actor,
                            clean_text,
                            now
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                    let message_id = db.last_insert_rowid();
                    let preview: String = clean_text.chars().take(200).collect();
                    db.execute(
                        "UPDATE conversations
                         SET status='replied', last_message_preview=?1, unread_count=0, updated_at=?2
                         WHERE organization_id=?3 AND id=?4",
                        params![preview, now, org, conversation_id],
                    )
                    .map_err(|e| e.to_string())?;
                    audit::append(
                        db,
                        org,
                        &sub_actor,
                        "conversation.message_replied",
                        &conversation_id.to_string(),
                        &json!({ "message_id": message_id, "idempotency_key": idem_key }),
                    )
                    .map_err(|e| e.to_string())?;
                    Ok(json!({
                        "ok": true,
                        "message_id": message_id,
                        "conversation_id": conversation_id,
                        "status": "replied",
                    }))
                },
            )
        }
        _ => Err(format!("Unknown tool: {tool}")),
    }
}

fn all_tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "shops_list",
            "description": "List shop scopes synchronized across LNC Care, LNC Agent Hub, and LNC Ads.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "channels_list",
            "description": "List social channels in LNC Care.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "shop_id": { "type": ["integer", "null"] },
                    "approved_only": { "type": "boolean", "default": true }
                }
            }
        }),
        json!({
            "name": "posts_list",
            "description": "List ingested posts and reels with latest snapshot metrics.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "channel_id": { "type": ["integer", "null"] },
                    "shop_id": { "type": ["integer", "null"] },
                    "kind": { "type": ["string", "null"] },
                    "limit": { "type": "integer", "default": 25 }
                }
            }
        }),
        json!({
            "name": "post_get",
            "description": "Get full post details, daily snapshots, and archive references.",
            "inputSchema": {
                "type": "object",
                "properties": { "post_id": { "type": "integer" } },
                "required": ["post_id"]
            }
        }),
        json!({
            "name": "comments_list",
            "description": "List comments in the triage queue with AI evaluation scores and drafts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "shop_id": { "type": ["integer", "null"] },
                    "channel_id": { "type": ["integer", "null"] },
                    "post_id": { "type": ["integer", "null"] },
                    "status": { "type": ["string", "null"] },
                    "bucket": { "type": ["string", "null"] },
                    "assignment": { "type": ["string", "null"] },
                    "search": { "type": ["string", "null"] },
                    "limit": { "type": "integer", "default": 50 }
                }
            }
        }),
        json!({
            "name": "comment_thread",
            "description": "Get a root comment, its AI rubric evaluation, reply drafts, and nested replies.",
            "inputSchema": {
                "type": "object",
                "properties": { "comment_id": { "type": "integer" } },
                "required": ["comment_id"]
            }
        }),
        json!({
            "name": "conversations_list",
            "description": "List customer Messenger / Instagram DM conversations in LNC Care.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "shop_id": { "type": ["integer", "null"] },
                    "channel_id": { "type": ["integer", "null"] },
                    "status": { "type": ["string", "null"] },
                    "limit": { "type": "integer", "default": 50 }
                }
            }
        }),
        json!({
            "name": "messages_list",
            "description": "List chronological inbound and outbound messages for a conversation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "conversation_id": { "type": "integer" },
                    "limit": { "type": "integer", "default": 50 }
                },
                "required": ["conversation_id"]
            }
        }),
        json!({
            "name": "leads_list",
            "description": "List captured consultation leads across social comments, DMs, and Meta lead ads.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "shop_id": { "type": ["integer", "null"] },
                    "status": { "type": ["string", "null"] },
                    "limit": { "type": "integer", "default": 50 }
                }
            }
        }),
        json!({
            "name": "handoffs_list",
            "description": "List human operator escalation / fulfillment handoff tickets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "shop_id": { "type": ["integer", "null"] },
                    "status": { "type": ["string", "null"] },
                    "limit": { "type": "integer", "default": 50 }
                }
            }
        }),
        json!({
            "name": "stats_series",
            "description": "Read daily snapshot series for a post or channel.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "channel_id": { "type": ["integer", "null"] },
                    "post_id": { "type": ["integer", "null"] },
                    "days": { "type": "integer", "default": 30 }
                }
            }
        }),
        json!({
            "name": "inbox_summary",
            "description": "Get comment, conversation, lead, and handoff counts by status, bucket, and channel.",
            "inputSchema": {
                "type": "object",
                "properties": { "shop_id": { "type": ["integer", "null"] } }
            }
        }),
        json!({
            "name": "evidence_case_get",
            "description": "Read a forensic evidence case ('Vi bằng số') and its preserved SHA-256 artifacts.",
            "inputSchema": {
                "type": "object",
                "properties": { "case_id": { "type": "integer" } },
                "required": ["case_id"]
            }
        }),
        json!({
            "name": "ads_context_lookup",
            "description": "Query sibling `ads__*` tools via unified `LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": { "type": "string" },
                    "arguments": { "type": ["object", "null"] }
                },
                "required": ["tool_name"]
            }
        }),
        json!({
            "name": "fleet_runtimes_list",
            "description": "List isolated runtime profiles (`meta_api`, `veilbrowser`, `orbine_mobile`) and concurrency leases.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "shop_id": { "type": ["integer", "null"] }
                }
            }
        }),
        json!({
            "name": "playbooks_list",
            "description": "List consultation playbooks and brand knowledge rules by shop or channel.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "shop_id": { "type": ["integer", "null"] },
                    "channel_id": { "type": ["integer", "null"] }
                }
            }
        }),
        json!({
            "name": "comment_evaluate",
            "description": "Run the prompt-injection-isolated AI rubric evaluator and consultation drafter on a comment.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "comment_id": { "type": "integer" },
                    "threshold": { "type": ["integer", "null"] }
                },
                "required": ["comment_id"]
            }
        }),
        json!({
            "name": "evaluation_feedback_set",
            "description": "Record human [✓]/[✕] rubric label calibration or quick decision (1/2/3).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "comment_id": { "type": "integer" },
                    "label": { "type": "string" },
                    "agreed": { "type": "boolean" },
                    "human_decision": { "type": ["integer", "null"] }
                },
                "required": ["comment_id", "label", "agreed"]
            }
        }),
        json!({
            "name": "comment_flag_set",
            "description": "Update triage status, bucket, assignee, or operator note on a comment.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "comment_id": { "type": "integer" },
                    "status": {
                        "type": "string",
                        "enum": ["new", "needs_reply", "replied", "hidden", "ignored"],
                        "default": "needs_reply"
                    },
                    "bucket": { "type": ["string", "null"] },
                    "assigned_to": { "type": ["string", "null"] },
                    "note": { "type": ["string", "null"] }
                },
                "required": ["comment_id"]
            }
        }),
        json!({
            "name": "reply_draft_create",
            "description": "Create a reply or private consultation draft for owner review.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "comment_id": { "type": "integer" },
                    "text": { "type": "string" },
                    "kind": { "type": "string", "enum": ["public", "private_dm"], "default": "public" },
                    "strategy_summary": { "type": "string", "default": "" }
                },
                "required": ["comment_id", "text"]
            }
        }),
        json!({
            "name": "lead_upsert",
            "description": "Create or update a consultation lead captured from social comments, DMs, or Meta lead forms.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "customer_name": { "type": "string" },
                    "source": { "type": "string", "enum": ["comment", "dm", "meta_lead_ad", "manual"], "default": "comment" },
                    "shop_id": { "type": ["integer", "null"] },
                    "channel_id": { "type": ["integer", "null"] },
                    "external_id": { "type": "string", "default": "" },
                    "contact_handle": { "type": "string", "default": "" },
                    "phone": { "type": "string", "default": "" },
                    "email": { "type": "string", "default": "" },
                    "intent_score": { "type": "number", "default": 85.0 },
                    "status": { "type": "string", "enum": ["new", "qualified", "contacted", "converted", "archived"], "default": "new" },
                    "notes": { "type": "string", "default": "" }
                },
                "required": ["customer_name"]
            }
        }),
        json!({
            "name": "ticket_handoff",
            "description": "Create an audited human operator escalation or fulfillment handoff ticket.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "summary": { "type": "string" },
                    "priority": { "type": "string", "enum": ["low", "normal", "high", "urgent"], "default": "normal" },
                    "assignee": { "type": "string", "default": "care-team" },
                    "shop_id": { "type": ["integer", "null"] },
                    "channel_id": { "type": ["integer", "null"] },
                    "comment_id": { "type": ["integer", "null"] },
                    "conversation_id": { "type": ["integer", "null"] },
                    "context": { "type": ["object", "null"] }
                },
                "required": ["summary"]
            }
        }),
        json!({
            "name": "archive_request",
            "description": "Enqueue background media and screenshot archiving for a post.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "post_id": { "type": "integer" },
                    "include_screenshot": { "type": "boolean", "default": true }
                },
                "required": ["post_id"]
            }
        }),
        json!({
            "name": "evidence_capture",
            "description": "Capture a 5-layer forensic snapshot ('Lập vi bằng số') with SHA-256 manifest & deterministic PKZIP bundle.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": { "type": "string", "default": "" },
                    "title": { "type": "string", "default": "" },
                    "comment_id": { "type": ["integer", "null"] },
                    "case_id": { "type": ["integer", "null"] }
                }
            }
        }),
        json!({
            "name": "evidence_watchdog_check",
            "description": "Run deletion/edit watchdog check and verify SHA-256 chain of custody on a forensic evidence case.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": { "type": ["integer", "null"] },
                    "item_id": { "type": ["integer", "null"] }
                }
            }
        }),
        json!({
            "name": "channel_webhook_subscribe",
            "description": "Enable realtime Meta webhook subscription (`feed,messages,mention`) for an approved channel.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "channel_id": { "type": "integer" },
                    "fields": { "type": "string", "default": "feed,messages,mention" }
                },
                "required": ["channel_id"]
            }
        }),
        json!({
            "name": "fleet_runtime_probe",
            "description": "Run fail-closed pre-flight residential IP/ASN & checkpoint health probe on an account runtime.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "runtime_id": { "type": "integer" }
                },
                "required": ["runtime_id"]
            }
        }),
        json!({
            "name": "playbook_upsert",
            "description": "Create or update a brand consultation playbook for AI rubric drafting.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "playbook_id": { "type": ["integer", "null"] },
                    "shop_id": { "type": ["integer", "null"] },
                    "channel_id": { "type": ["integer", "null"] },
                    "name": { "type": "string" },
                    "auto_suggest_threshold": { "type": "integer", "default": 80 },
                    "auto_consult_enabled": { "type": "boolean", "default": false },
                    "consultation_knowledge_md": { "type": "string", "default": "" },
                    "forbidden_topics": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["name"]
            }
        }),
        json!({
            "name": "comment_reply",
            "description": "Publish an audited public reply to a comment on an official API channel.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "comment_id": { "type": "integer" },
                    "text": { "type": "string" },
                    "idempotency_key": { "type": "string" }
                },
                "required": ["comment_id", "text", "idempotency_key"]
            }
        }),
        json!({
            "name": "comment_hide_set",
            "description": "Hide or unhide a comment on an official API channel.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "comment_id": { "type": "integer" },
                    "hidden": { "type": "boolean" },
                    "idempotency_key": { "type": "string" }
                },
                "required": ["comment_id", "hidden", "idempotency_key"]
            }
        }),
        json!({
            "name": "comment_private_reply",
            "description": "Send an audited private consultation reply (DM) to a comment author on an official API channel.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "comment_id": { "type": "integer" },
                    "text": { "type": "string" },
                    "idempotency_key": { "type": "string" }
                },
                "required": ["comment_id", "text", "idempotency_key"]
            }
        }),
        json!({
            "name": "message_reply",
            "description": "Send an audited outbound Messenger / Instagram DM reply in an active conversation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "conversation_id": { "type": "integer" },
                    "text": { "type": "string" },
                    "idempotency_key": { "type": "string" }
                },
                "required": ["conversation_id", "text", "idempotency_key"]
            }
        }),
    ]
}

fn json_resp(status: StatusCode, body: &Value, extra_headers: &[(&str, String)]) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = (status, bytes).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (k, v) in extra_headers {
        if let (Ok(name), Ok(val)) = (
            axum::http::header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            resp.headers_mut().insert(name, val);
        }
    }
    resp
}

pub fn handle_mcp_http(
    cfg: &McpServerConfig,
    method: &Method,
    req_headers: &HeaderMap,
    raw_body: &[u8],
) -> Response {
    let mut headers_map = HashMap::new();
    for (k, v) in req_headers.iter() {
        if let Ok(s) = v.to_str() {
            headers_map.insert(k.as_str().to_ascii_lowercase(), s.to_string());
        }
    }

    let (loaded_cfg, pairing_ui) = match store::connect_readonly(&cfg.path) {
        Ok(db) => {
            let loaded = settings::load(&db, &cfg.org, &cfg.env_map);
            let p_ui = if cfg.vault.ready {
                cfg.vault.get(&db, &cfg.org, "pairing", "connector").ok().flatten()
            } else {
                None
            };
            (loaded, p_ui.unwrap_or_else(|| json!({})))
        }
        Err(e) => {
            return json_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({ "error": e.to_string() }),
                &[],
            );
        }
    };

    let eff_bearer = if !cfg.bearer_token.is_empty() {
        cfg.bearer_token.clone()
    } else {
        pairing_ui
            .get("connector_bearer")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let eff_secret = if !cfg.delegation_secret.is_empty() {
        cfg.delegation_secret.clone()
    } else {
        pairing_ui
            .get("delegation_secret")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    let auth = headers_map.get("authorization").map(|s| s.as_str()).unwrap_or("");
    let bearer_ok = !eff_bearer.is_empty()
        && auth.starts_with("Bearer ")
        && auth[7..].as_bytes().ct_eq(eff_bearer.as_bytes()).unwrap_u8() == 1;
    if !bearer_ok {
        return json_resp(
            StatusCode::UNAUTHORIZED,
            &json!({ "error": "Invalid MCP bearer token" }),
            &[],
        );
    }

    let caller = match verify_delegation(
        &cfg.path,
        &cfg.org,
        headers_map.get("x-lnc-delegation").map(|s| s.as_str()),
        &eff_secret,
        cfg.require_delegation,
        &loaded_cfg.mcp_max_scopes,
        Some(&headers_map),
        &cfg.audience,
    ) {
        Ok(c) => c,
        Err(err) => {
            return json_resp(
                StatusCode::FORBIDDEN,
                &json!({ "error": err.to_string() }),
                &[],
            );
        }
    };

    if *method == Method::DELETE {
        return json_resp(StatusCode::OK, &json!({ "ok": true }), &[]);
    }
    if *method != Method::POST {
        return json_resp(
            StatusCode::METHOD_NOT_ALLOWED,
            &json!({
                "jsonrpc": "2.0",
                "error": { "code": -32000, "message": "Method not allowed." },
                "id": Value::Null
            }),
            &[],
        );
    }

    let payload: Value = match serde_json::from_slice(raw_body) {
        Ok(v) => v,
        Err(_) => {
            return json_resp(
                StatusCode::BAD_REQUEST,
                &json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32700, "message": "Parse error" },
                    "id": Value::Null
                }),
                &[],
            );
        }
    };

    // JSON-RPC notifications (no `id` field) return 202 Accepted
    let Some(req_id) = payload.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };

    let rpc_method = payload
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let params_obj = payload
        .get("params")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let incoming_sess = headers_map.get("mcp-session-id").cloned();

    match rpc_method {
        "initialize" => {
            let requested_proto = params_obj
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("2025-03-26");
            let session_id = incoming_sess.unwrap_or_else(|| format!("care_sess_{}", random_hex(12)));
            json_resp(
                StatusCode::OK,
                &json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": requested_proto,
                        "capabilities": {
                            "tools": { "listChanged": false }
                        },
                        "serverInfo": {
                            "name": cfg.audience,
                            "version": crate::VERSION
                        }
                    }
                }),
                &[
                    ("mcp-session-id", session_id),
                    ("mcp-protocol-version", requested_proto.to_string()),
                ],
            )
        }
        "ping" => json_resp(
            StatusCode::OK,
            &json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {}
            }),
            &[],
        ),
        "tools/list" => {
            let scopes_map = tool_scopes_map();
            let filtered: Vec<Value> = all_tool_definitions()
                .into_iter()
                .filter(|t| {
                    let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    match scopes_map.get(name) {
                        Some(req_scopes) => req_scopes.iter().all(|s| caller.scopes.contains(*s)),
                        None => false,
                    }
                })
                .collect();
            let mut hdrs = Vec::new();
            if let Some(sid) = incoming_sess {
                hdrs.push(("mcp-session-id", sid));
            }
            json_resp(
                StatusCode::OK,
                &json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": { "tools": filtered }
                }),
                &hdrs,
            )
        }
        "tools/call" => {
            let tool_name = params_obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tool_args = params_obj
                .get("arguments")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            let mut hdrs = Vec::new();
            if let Some(sid) = incoming_sess {
                hdrs.push(("mcp-session-id", sid));
            }
            match execute_tool(cfg, &caller, tool_name, &tool_args) {
                Ok(val) => {
                    let text_repr = serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string());
                    json_resp(
                        StatusCode::OK,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{ "type": "text", "text": text_repr }],
                                "structuredContent": val,
                                "isError": false
                            }
                        }),
                        &hdrs,
                    )
                }
                Err(err_msg) => json_resp(
                    StatusCode::OK,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{ "type": "text", "text": err_msg }],
                            "isError": true
                        }
                    }),
                    &hdrs,
                ),
            }
        }
        _ => json_resp(
            StatusCode::OK,
            &json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {rpc_method}")
                }
            }),
            &[],
        ),
    }
}
