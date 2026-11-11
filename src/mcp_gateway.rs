//! Unified outbound MCP Gateway client (`lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand::{Rng, RngCore};
use serde_json::{json, Value};
use url::Url;

use crate::transport::{SharedTransport, TransportRequest, TransportResponse, UreqTransport};

pub const ALLOWED_CROSS_APP_PREFIXES: &[&str] = &["ads__"];
pub const DEFAULT_MCP_PROTOCOL_VERSION: &str = "2025-03-26";

#[derive(Debug, Clone)]
pub struct McpGatewayError {
    pub code: String,
    pub status: u16,
}

impl McpGatewayError {
    pub fn new(code: impl Into<String>, status: u16) -> Self {
        Self {
            code: code.into(),
            status,
        }
    }
}

impl std::fmt::Display for McpGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}

impl std::error::Error for McpGatewayError {}

#[derive(Debug, Clone)]
pub struct McpGatewayConfig {
    pub gateway_url: String,
    pub api_key: String,
}

pub fn mcp_gateway_config(env: &HashMap<String, String>) -> Result<Option<McpGatewayConfig>, String> {
    let raw_url = env
        .get("LNC_MCP_GATEWAY_URL")
        .map(|s| s.trim())
        .unwrap_or_default();
    let hub_url = env
        .get("LNC_AGENT_HUB_URL")
        .map(|s| s.trim().trim_end_matches('/'))
        .unwrap_or_default();
    let gateway_url = if !raw_url.is_empty() {
        raw_url.to_string()
    } else if !hub_url.is_empty() {
        format!("{hub_url}/mcp")
    } else {
        String::new()
    };
    if gateway_url.is_empty() {
        return Ok(None);
    }
    let parsed = Url::parse(&gateway_url)
        .map_err(|_| "LNC_MCP_GATEWAY_URL must be a valid HTTP(S) URL".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("LNC_MCP_GATEWAY_URL must be a valid HTTP(S) URL".to_string());
    }
    let api_key = env
        .get("LNC_AGENT_HUB_API_KEY")
        .map(|s| s.trim())
        .unwrap_or_default()
        .to_string();
    Ok(Some(McpGatewayConfig {
        gateway_url,
        api_key,
    }))
}

struct GatewaySessionState {
    session_id: Option<String>,
    initialized: bool,
    protocol_version: String,
}

#[derive(Clone)]
pub struct McpGatewayClient {
    pub cfg: McpGatewayConfig,
    transport: SharedTransport,
    state: Arc<Mutex<GatewaySessionState>>,
}

fn random_hex_12() -> String {
    let mut buf = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

impl McpGatewayClient {
    pub fn new(cfg: McpGatewayConfig, transport: Option<SharedTransport>) -> Self {
        Self {
            cfg,
            transport: transport.unwrap_or_else(UreqTransport::shared),
            state: Arc::new(Mutex::new(GatewaySessionState {
                session_id: None,
                initialized: false,
                protocol_version: DEFAULT_MCP_PROTOCOL_VERSION.to_string(),
            })),
        }
    }

    pub fn status_summary(&self) -> Value {
        let (has_session, proto_ver) = match self.state.lock() {
            Ok(st) => (st.session_id.is_some(), st.protocol_version.clone()),
            Err(_) => (false, DEFAULT_MCP_PROTOCOL_VERSION.to_string()),
        };
        json!({
            "configured": !self.cfg.gateway_url.is_empty(),
            "has_api_key": !self.cfg.api_key.is_empty(),
            "has_session": has_session,
            "protocol_version": proto_ver,
            "gateway_url": self.cfg.gateway_url,
            "route": "lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)",
            "allowed_prefixes": ALLOWED_CROSS_APP_PREFIXES,
        })
    }

    pub fn reset_session(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.session_id = None;
            st.initialized = false;
        }
    }

    fn base_headers(&self) -> Vec<(String, String)> {
        vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", self.cfg.api_key),
            ),
            (
                "Accept".to_string(),
                "application/json, text/event-stream".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Request-Id".to_string(), format!("req_{}", random_hex_12())),
        ]
    }

    fn decode_rpc_body(
        res: &TransportResponse,
        expected_id: Option<i64>,
    ) -> Result<Value, McpGatewayError> {
        let content_type = res.header("content-type").unwrap_or_default().to_ascii_lowercase();
        let body_text = res.text();
        let rpc_data: Value = if content_type.contains("text/event-stream") {
            let data_lines: Vec<&str> = body_text
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if data_lines.is_empty() {
                return Err(McpGatewayError::new("mcp_gateway_empty_stream", 502));
            }
            let parsed_events: Vec<Value> = data_lines
                .into_iter()
                .filter_map(|raw| serde_json::from_str::<Value>(raw).ok())
                .filter(|v| v.is_object())
                .collect();
            if parsed_events.is_empty() {
                return Err(McpGatewayError::new("mcp_gateway_invalid_stream_json", 502));
            }
            if let Some(exp) = expected_id {
                parsed_events
                    .iter()
                    .rev()
                    .find(|ev| ev.get("id").and_then(|v| v.as_i64()) == Some(exp))
                    .cloned()
                    .unwrap_or_else(|| parsed_events.last().cloned().unwrap())
            } else {
                parsed_events.last().cloned().unwrap()
            }
        } else if res.body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&res.body)
                .map_err(|_| McpGatewayError::new("mcp_gateway_invalid_json", 502))?
        };

        if let Some(err) = rpc_data.get("error") {
            let msg = err
                .get("message")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| err.to_string());
            return Err(McpGatewayError::new(msg, 502));
        }
        Ok(rpc_data
            .get("result")
            .filter(|r| r.is_object())
            .cloned()
            .unwrap_or_else(|| json!({})))
    }

    fn ensure_session(
        &self,
        force: bool,
        stale_session_id: Option<&str>,
    ) -> Result<(Option<String>, String), McpGatewayError> {
        let mut st = self.state.lock().unwrap();
        if st.initialized && !force {
            return Ok((st.session_id.clone(), st.protocol_version.clone()));
        }
        if force
            && stale_session_id.is_some()
            && st.initialized
            && st.session_id.is_some()
            && st.session_id.as_deref() != stale_session_id
        {
            return Ok((st.session_id.clone(), st.protocol_version.clone()));
        }

        st.initialized = false;
        st.session_id = None;

        let init_id: i64 = rand::thread_rng().gen_range(100_000..1_000_000);
        let init_payload = json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": {
                "protocolVersion": DEFAULT_MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "lnc-care",
                    "version": crate::VERSION,
                },
            },
        });
        let init_res = self
            .transport
            .execute(TransportRequest {
                method: "POST".to_string(),
                url: self.cfg.gateway_url.clone(),
                headers: self.base_headers(),
                body: Some(serde_json::to_vec(&init_payload).unwrap_or_default()),
                timeout_ms: 12_000,
            })
            .map_err(|_| McpGatewayError::new("mcp_gateway_unreachable", 503))?;

        if init_res.status == 401 || init_res.status == 403 {
            return Err(McpGatewayError::new(
                "mcp_gateway_unauthorized",
                init_res.status,
            ));
        }
        if init_res.status >= 400 {
            return Err(McpGatewayError::new(
                format!("mcp_gateway_http_{}", init_res.status),
                502,
            ));
        }

        let init_result = Self::decode_rpc_body(&init_res, Some(init_id))?;
        let mut sid = init_res
            .header("mcp-session-id")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
        let negotiated_ver = init_result
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_MCP_PROTOCOL_VERSION)
            .to_string();

        let mut notify_headers = self.base_headers();
        notify_headers.push(("MCP-Protocol-Version".to_string(), negotiated_ver.clone()));
        if let Some(ref s) = sid {
            notify_headers.push(("Mcp-Session-Id".to_string(), s.clone()));
        }
        let notify_payload = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        });
        let notify_res = self
            .transport
            .execute(TransportRequest {
                method: "POST".to_string(),
                url: self.cfg.gateway_url.clone(),
                headers: notify_headers,
                body: Some(serde_json::to_vec(&notify_payload).unwrap_or_default()),
                timeout_ms: 12_000,
            })
            .map_err(|_| McpGatewayError::new("mcp_gateway_unreachable", 503))?;

        if notify_res.status == 401 || notify_res.status == 403 {
            return Err(McpGatewayError::new(
                "mcp_gateway_unauthorized",
                notify_res.status,
            ));
        }
        if notify_res.status >= 400 {
            return Err(McpGatewayError::new(
                format!("mcp_gateway_http_{}", notify_res.status),
                502,
            ));
        }

        if let Some(refreshed) = notify_res
            .header("mcp-session-id")
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            sid = Some(refreshed.to_string());
        }

        st.session_id = sid.clone();
        st.protocol_version = negotiated_ver.clone();
        st.initialized = true;
        Ok((sid, negotiated_ver))
    }

    fn rpc(&self, method: &str, params: Value) -> Result<Value, McpGatewayError> {
        if self.cfg.api_key.is_empty() {
            return Err(McpGatewayError::new(
                "mcp_gateway_api_key_not_configured",
                409,
            ));
        }
        let (mut sid, mut proto_ver) = self.ensure_session(false, None)?;

        for attempt in 0..2 {
            let req_id: i64 = rand::thread_rng().gen_range(100_000..1_000_000);
            let mut headers = self.base_headers();
            headers.push(("MCP-Protocol-Version".to_string(), proto_ver.clone()));
            if let Some(ref s) = sid {
                headers.push(("Mcp-Session-Id".to_string(), s.clone()));
            }
            let payload = json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params,
            });
            let res = self
                .transport
                .execute(TransportRequest {
                    method: "POST".to_string(),
                    url: self.cfg.gateway_url.clone(),
                    headers,
                    body: Some(serde_json::to_vec(&payload).unwrap_or_default()),
                    timeout_ms: 12_000,
                })
                .map_err(|_| McpGatewayError::new("mcp_gateway_unreachable", 503))?;

            if res.status == 401 || res.status == 403 {
                return Err(McpGatewayError::new("mcp_gateway_unauthorized", res.status));
            }
            if (res.status == 400 || res.status == 404) && attempt == 0 {
                let stale = sid.clone();
                let next = self.ensure_session(true, stale.as_deref())?;
                sid = next.0;
                proto_ver = next.1;
                continue;
            }
            if res.status >= 400 {
                return Err(McpGatewayError::new(
                    format!("mcp_gateway_http_{}", res.status),
                    502,
                ));
            }

            if let Some(refreshed) = res
                .header("mcp-session-id")
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if sid.as_deref() != Some(refreshed) {
                    if let Ok(mut st) = self.state.lock() {
                        st.session_id = Some(refreshed.to_string());
                    }
                }
            }
            return Self::decode_rpc_body(&res, Some(req_id));
        }

        Err(McpGatewayError::new(
            "mcp_gateway_session_retry_exhausted",
            502,
        ))
    }

    pub fn list_tools(&self, prefix: &str) -> Result<Vec<Value>, McpGatewayError> {
        let res = self.rpc("tools/list", json!({}))?;
        let tools = res
            .get("tools")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(tools
            .into_iter()
            .filter(|t| {
                t.get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| n.starts_with(prefix))
                    .unwrap_or(false)
            })
            .collect())
    }

    pub fn call_tool(
        &self,
        tool_name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, McpGatewayError> {
        let clean_name = tool_name.trim();
        if !ALLOWED_CROSS_APP_PREFIXES
            .iter()
            .any(|p| clean_name.starts_with(*p))
        {
            return Err(McpGatewayError::new("cross_app_tool_not_allowed", 403));
        }
        let args_val = arguments
            .filter(|v| v.is_object())
            .cloned()
            .unwrap_or_else(|| json!({}));
        let res = self.rpc(
            "tools/call",
            json!({"name": clean_name, "arguments": args_val}),
        )?;
        let is_err = res.get("isError").and_then(|v| v.as_bool()).unwrap_or(false);
        let contents = res
            .get("content")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut parsed_items: Vec<Value> = Vec::new();
        for item in contents {
            if item.get("type").and_then(|v| v.as_str()) == Some("text") {
                let txt = item.get("text").and_then(|v| v.as_str()).unwrap_or_default();
                if let Ok(parsed) = serde_json::from_str::<Value>(txt) {
                    parsed_items.push(parsed);
                } else {
                    parsed_items.push(Value::String(txt.to_string()));
                }
            } else {
                parsed_items.push(item);
            }
        }

        if is_err {
            let detail = match parsed_items.first() {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => "mcp_tool_execution_error".to_string(),
            };
            return Err(McpGatewayError::new(detail, 422));
        }

        let data = if parsed_items.len() == 1 {
            parsed_items.into_iter().next().unwrap()
        } else {
            Value::Array(parsed_items)
        };
        Ok(json!({
            "ok": true,
            "gateway_url": self.cfg.gateway_url,
            "tool": clean_name,
            "data": data,
        }))
    }
}
