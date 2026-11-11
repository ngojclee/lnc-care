//! Pluggable synchronous HTTP transport (backed by `ureq` + `rustls` in production, mockable in tests).

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TransportRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TransportResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl TransportResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers.get(&lower).map(|s| s.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        if self.body.is_empty() {
            return Ok(serde_json::json!({}));
        }
        serde_json::from_slice(&self.body)
    }
}

pub trait HttpTransport: Send + Sync {
    fn execute(&self, req: TransportRequest) -> Result<TransportResponse, String>;
}

pub type SharedTransport = Arc<dyn HttpTransport>;

pub struct UreqTransport;

impl UreqTransport {
    pub fn shared() -> SharedTransport {
        Arc::new(Self)
    }
}

impl HttpTransport for UreqTransport {
    fn execute(&self, req: TransportRequest) -> Result<TransportResponse, String> {
        let timeout = Duration::from_millis(req.timeout_ms.max(500));
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(Duration::from_secs(5).min(timeout))
            .timeout(timeout)
            .build();

        let mut ureq_req = agent.request(&req.method.to_ascii_uppercase(), &req.url);
        for (k, v) in &req.headers {
            ureq_req = ureq_req.set(k, v);
        }

        let call_res = match &req.body {
            Some(bytes) => ureq_req.send_bytes(bytes),
            None => ureq_req.call(),
        };

        let resp = match call_res {
            Ok(r) => r,
            Err(ureq::Error::Status(_code, r)) => r,
            Err(ureq::Error::Transport(t)) => return Err(t.to_string()),
        };

        let status = resp.status();
        let mut headers = HashMap::new();
        for name in resp.headers_names() {
            if let Some(val) = resp.header(&name) {
                headers.insert(name.to_ascii_lowercase(), val.to_string());
            }
        }
        let mut body = Vec::new();
        resp.into_reader()
            .take(16 * 1024 * 1024)
            .read_to_end(&mut body)
            .map_err(|e| e.to_string())?;

        Ok(TransportResponse {
            status,
            headers,
            body,
        })
    }
}

pub struct FnTransport<F>(pub F)
where
    F: Fn(TransportRequest) -> Result<TransportResponse, String> + Send + Sync + 'static;

impl<F> HttpTransport for FnTransport<F>
where
    F: Fn(TransportRequest) -> Result<TransportResponse, String> + Send + Sync + 'static,
{
    fn execute(&self, req: TransportRequest) -> Result<TransportResponse, String> {
        (self.0)(req)
    }
}

pub fn mock_transport<F>(f: F) -> SharedTransport
where
    F: Fn(TransportRequest) -> Result<TransportResponse, String> + Send + Sync + 'static,
{
    Arc::new(FnTransport(f))
}

pub fn build_url_with_params(base_url: &str, params: &[(&str, String)]) -> String {
    if params.is_empty() {
        return base_url.to_string();
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        serializer.append_pair(k, v);
    }
    let qs = serializer.finish();
    if qs.is_empty() {
        base_url.to_string()
    } else if base_url.contains('?') {
        format!("{base_url}&{qs}")
    } else {
        format!("{base_url}?{qs}")
    }
}
