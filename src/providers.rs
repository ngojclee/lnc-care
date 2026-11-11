//! Provider OAuth, channel discovery, and Graph/TikTok/YouTube API transport.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::transport::{build_url_with_params, SharedTransport, TransportRequest, UreqTransport};

pub const META_VERSION: &str = "v22.0";
pub const TIKTOK_VERSION: &str = "v1.3";
pub const YOUTUBE_VERSION: &str = "v3";

pub const META_SCOPES: &[&str] = &[
    "pages_show_list",
    "pages_read_engagement",
    "pages_read_user_content",
    "pages_manage_engagement",
    "pages_manage_metadata",
    "read_insights",
    "instagram_basic",
    "instagram_manage_comments",
    "instagram_manage_insights",
    "business_management",
];

#[derive(Debug, Clone)]
pub struct ProviderError {
    pub code: String,
    pub status: u16,
}

impl ProviderError {
    pub fn new(code: impl Into<String>, status: u16) -> Self {
        Self {
            code: code.into(),
            status,
        }
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}

impl std::error::Error for ProviderError {}

impl From<rusqlite::Error> for ProviderError {
    fn from(e: rusqlite::Error) -> Self {
        Self::new(e.to_string(), 500)
    }
}

impl From<crate::vault::VaultError> for ProviderError {
    fn from(e: crate::vault::VaultError) -> Self {
        Self::new(e.0, 500)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct Providers {
    transport: SharedTransport,
}

impl Providers {
    pub fn new(transport: Option<SharedTransport>) -> Self {
        Self {
            transport: transport.unwrap_or_else(UreqTransport::shared),
        }
    }

    pub fn authorize(
        &self,
        provider: &str,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<String, ProviderError> {
        match provider {
            "meta" => Ok(build_url_with_params(
                &format!("https://www.facebook.com/{META_VERSION}/dialog/oauth"),
                &[
                    ("client_id", client_id.to_string()),
                    ("redirect_uri", redirect_uri.to_string()),
                    ("state", state.to_string()),
                    ("response_type", "code".to_string()),
                    ("scope", META_SCOPES.join(",")),
                ],
            )),
            "tiktok" => Ok(build_url_with_params(
                "https://business-api.tiktok.com/portal/auth",
                &[
                    ("app_id", client_id.to_string()),
                    ("redirect_uri", redirect_uri.to_string()),
                    ("state", state.to_string()),
                ],
            )),
            "youtube" => Ok(build_url_with_params(
                "https://accounts.google.com/o/oauth2/v2/auth",
                &[
                    ("client_id", client_id.to_string()),
                    ("redirect_uri", redirect_uri.to_string()),
                    ("response_type", "code".to_string()),
                    (
                        "scope",
                        "https://www.googleapis.com/auth/youtube.force-ssl".to_string(),
                    ),
                    ("access_type", "offline".to_string()),
                    ("prompt", "consent".to_string()),
                    ("state", state.to_string()),
                ],
            )),
            _ => Err(ProviderError::new("provider_not_supported", 422)),
        }
    }

    pub fn exchange(
        &self,
        provider: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code: &str,
    ) -> Result<Value, ProviderError> {
        match provider {
            "meta" => {
                let url = build_url_with_params(
                    &format!("https://graph.facebook.com/{META_VERSION}/oauth/access_token"),
                    &[
                        ("client_id", client_id.to_string()),
                        ("client_secret", client_secret.to_string()),
                        ("redirect_uri", redirect_uri.to_string()),
                        ("code", code.to_string()),
                    ],
                );
                let res = self
                    .transport
                    .execute(TransportRequest {
                        method: "GET".to_string(),
                        url,
                        headers: vec![("Accept".to_string(), "application/json".to_string())],
                        body: None,
                        timeout_ms: 15_000,
                    })
                    .map_err(|_| ProviderError::new("oauth_exchange_failed", 502))?;
                if res.status != 200 {
                    return Err(ProviderError::new("oauth_exchange_failed", 502));
                }
                let data = res
                    .json()
                    .map_err(|_| ProviderError::new("oauth_exchange_failed", 502))?;
                let short_token = data
                    .get("access_token")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| ProviderError::new("oauth_exchange_failed", 502))?;

                let ll_url = build_url_with_params(
                    &format!("https://graph.facebook.com/{META_VERSION}/oauth/access_token"),
                    &[
                        ("grant_type", "fb_exchange_token".to_string()),
                        ("client_id", client_id.to_string()),
                        ("client_secret", client_secret.to_string()),
                        ("fb_exchange_token", short_token.to_string()),
                    ],
                );
                if let Ok(ll_res) = self.transport.execute(TransportRequest {
                    method: "GET".to_string(),
                    url: ll_url,
                    headers: vec![("Accept".to_string(), "application/json".to_string())],
                    body: None,
                    timeout_ms: 15_000,
                }) {
                    if ll_res.status == 200 {
                        if let Ok(ll_json) = ll_res.json() {
                            if let Some(ll_tok) = ll_json
                                .get("access_token")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                            {
                                let exp = ll_json
                                    .get("expires_in")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(5_184_000);
                                return Ok(json!({"access_token": ll_tok, "expires_in": exp}));
                            }
                        }
                    }
                }
                let exp = data
                    .get("expires_in")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(5_184_000);
                Ok(json!({"access_token": short_token, "expires_in": exp}))
            }
            "tiktok" => {
                let body_bytes = serde_json::to_vec(&json!({
                    "app_id": client_id,
                    "secret": client_secret,
                    "auth_code": code,
                }))
                .unwrap_or_default();
                let res = self
                    .transport
                    .execute(TransportRequest {
                        method: "POST".to_string(),
                        url: format!(
                            "https://business-api.tiktok.com/open_api/{TIKTOK_VERSION}/oauth2/access_token/"
                        ),
                        headers: vec![
                            ("Content-Type".to_string(), "application/json".to_string()),
                            ("Accept".to_string(), "application/json".to_string()),
                        ],
                        body: Some(body_bytes),
                        timeout_ms: 15_000,
                    })
                    .map_err(|_| ProviderError::new("oauth_exchange_failed", 502))?;
                if res.status != 200 {
                    return Err(ProviderError::new("oauth_exchange_failed", 502));
                }
                let data = res
                    .json()
                    .map_err(|_| ProviderError::new("oauth_exchange_failed", 502))?;
                let payload = data.get("data").cloned().unwrap_or_else(|| json!({}));
                let tok = payload
                    .get("access_token")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| ProviderError::new("oauth_exchange_failed", 502))?;
                let exp = payload
                    .get("expires_in")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(86400 * 30);
                Ok(json!({"access_token": tok, "expires_in": exp}))
            }
            "youtube" => {
                let mut form = url::form_urlencoded::Serializer::new(String::new());
                form.append_pair("client_id", client_id);
                form.append_pair("client_secret", client_secret);
                form.append_pair("redirect_uri", redirect_uri);
                form.append_pair("code", code);
                form.append_pair("grant_type", "authorization_code");
                let encoded = form.finish().into_bytes();
                let res = self
                    .transport
                    .execute(TransportRequest {
                        method: "POST".to_string(),
                        url: "https://oauth2.googleapis.com/token".to_string(),
                        headers: vec![
                            (
                                "Content-Type".to_string(),
                                "application/x-www-form-urlencoded".to_string(),
                            ),
                            ("Accept".to_string(), "application/json".to_string()),
                        ],
                        body: Some(encoded),
                        timeout_ms: 15_000,
                    })
                    .map_err(|_| ProviderError::new("oauth_exchange_failed", 502))?;
                if res.status != 200 {
                    return Err(ProviderError::new("oauth_exchange_failed", 502));
                }
                let data = res
                    .json()
                    .map_err(|_| ProviderError::new("oauth_exchange_failed", 502))?;
                let tok = data
                    .get("access_token")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| ProviderError::new("oauth_exchange_failed", 502))?;
                let refresh = data
                    .get("refresh_token")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let exp = data
                    .get("expires_in")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(3600);
                Ok(json!({
                    "access_token": tok,
                    "refresh_token": refresh,
                    "expires_in": exp,
                }))
            }
            _ => Err(ProviderError::new("provider_not_supported", 422)),
        }
    }

    pub fn discover(&self, provider: &str, access_token: &str) -> Result<(Vec<Value>, bool), ProviderError> {
        if provider != "meta" {
            return Ok((Vec::new(), false));
        }
        let url = build_url_with_params(
            &format!("https://graph.facebook.com/{META_VERSION}/me/accounts"),
            &[
                (
                    "fields",
                    "id,name,username,followers_count,access_token,tasks,instagram_business_account{id,username,name,followers_count}".to_string(),
                ),
                ("limit", "50".to_string()),
            ],
        );
        let res = self
            .transport
            .execute(TransportRequest {
                method: "GET".to_string(),
                url,
                headers: vec![
                    ("Authorization".to_string(), format!("Bearer {access_token}")),
                    ("Accept".to_string(), "application/json".to_string()),
                ],
                body: None,
                timeout_ms: 15_000,
            })
            .map_err(|_| ProviderError::new("provider_discovery_failed", 502))?;

        if res.status == 401 {
            return Err(ProviderError::new("provider_unauthorized", 401));
        }
        if res.status != 200 {
            return Err(ProviderError::new("provider_discovery_failed", 502));
        }
        let body = res
            .json()
            .map_err(|_| ProviderError::new("provider_discovery_failed", 502))?;
        let pages = body
            .get("data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut channels = Vec::new();
        for p in pages {
            let page_id = p
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            if page_id.is_empty() {
                continue;
            }
            let page_token = p
                .get("access_token")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(access_token);
            let followers = p
                .get("followers_count")
                .or_else(|| p.get("fan_count"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            channels.push(json!({
                "external_id": page_id,
                "name": p.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or(&format!("Page {page_id}")),
                "handle": p.get("username").and_then(|v| v.as_str()).unwrap_or(""),
                "kind": "fb_page",
                "adapter": "meta_api",
                "followers_count": followers,
                "linked_external_id": Value::Null,
                "page_access_token": page_token,
                "eligible": true,
            }));

            if let Some(ig) = p.get("instagram_business_account").and_then(|v| v.as_object()) {
                if let Some(ig_id_raw) = ig.get("id").and_then(|v| v.as_str()) {
                    let ig_id = ig_id_raw.trim();
                    if !ig_id.is_empty() {
                        let uname = ig
                            .get("username")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let fallback_name = if uname.is_empty() {
                            format!("@{ig_id}")
                        } else {
                            format!("@{uname}")
                        };
                        let ig_name = ig
                            .get("name")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or(&fallback_name);
                        let handle = if uname.is_empty() {
                            String::new()
                        } else {
                            format!("@{uname}")
                        };
                        let ig_followers = ig
                            .get("followers_count")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        channels.push(json!({
                            "external_id": ig_id,
                            "name": ig_name,
                            "handle": handle,
                            "kind": "ig_account",
                            "adapter": "meta_api",
                            "followers_count": ig_followers,
                            "linked_external_id": page_id,
                            "page_access_token": page_token,
                            "eligible": true,
                        }));
                    }
                }
            }
        }
        let truncated = body
            .get("paging")
            .and_then(|p| p.get("next"))
            .map(|n| !n.is_null())
            .unwrap_or(false);
        Ok((channels, truncated))
    }

    pub fn fetch_channel_posts(
        &self,
        kind: &str,
        external_id: &str,
        token: &str,
        limit: i64,
    ) -> Result<Vec<Value>, ProviderError> {
        let clamped = limit.clamp(1, 50).to_string();
        let now = now_unix();
        match kind {
            "fb_page" => {
                let url = build_url_with_params(
                    &format!("https://graph.facebook.com/{META_VERSION}/{external_id}/published_posts"),
                    &[
                        (
                            "fields",
                            "id,message,permalink_url,created_time,attachments{media_type,url,media}"
                                .to_string(),
                        ),
                        ("limit", clamped),
                    ],
                );
                let res = self
                    .transport
                    .execute(TransportRequest {
                        method: "GET".to_string(),
                        url,
                        headers: vec![
                            ("Authorization".to_string(), format!("Bearer {token}")),
                            ("Accept".to_string(), "application/json".to_string()),
                        ],
                        body: None,
                        timeout_ms: 15_000,
                    })
                    .map_err(|_| ProviderError::new("provider_posts_fetch_failed", 502))?;
                if res.status != 200 {
                    return Err(ProviderError::new("provider_posts_fetch_failed", 502));
                }
                let body = res
                    .json()
                    .map_err(|_| ProviderError::new("provider_posts_fetch_failed", 502))?;
                let rows = body
                    .get("data")
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
                let url = build_url_with_params(
                    &format!("https://graph.facebook.com/{META_VERSION}/{external_id}/media"),
                    &[
                        (
                            "fields",
                            "id,caption,media_type,media_url,thumbnail_url,permalink,timestamp,like_count,comments_count"
                                .to_string(),
                        ),
                        ("limit", clamped),
                    ],
                );
                let res = self
                    .transport
                    .execute(TransportRequest {
                        method: "GET".to_string(),
                        url,
                        headers: vec![
                            ("Authorization".to_string(), format!("Bearer {token}")),
                            ("Accept".to_string(), "application/json".to_string()),
                        ],
                        body: None,
                        timeout_ms: 15_000,
                    })
                    .map_err(|_| ProviderError::new("provider_posts_fetch_failed", 502))?;
                if res.status != 200 {
                    return Err(ProviderError::new("provider_posts_fetch_failed", 502));
                }
                let body = res
                    .json()
                    .map_err(|_| ProviderError::new("provider_posts_fetch_failed", 502))?;
                let rows = body
                    .get("data")
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

    pub fn fetch_post_comments(
        &self,
        kind: &str,
        post_external_id: &str,
        token: &str,
        limit: i64,
    ) -> Result<Vec<Value>, ProviderError> {
        let clamped = limit.clamp(1, 100).to_string();
        let now = now_unix();
        match kind {
            "fb_page" => {
                let url = build_url_with_params(
                    &format!("https://graph.facebook.com/{META_VERSION}/{post_external_id}/comments"),
                    &[
                        (
                            "fields",
                            "id,from,message,created_time,parent,is_hidden,comment_count,like_count"
                                .to_string(),
                        ),
                        ("filter", "stream".to_string()),
                        ("limit", clamped),
                    ],
                );
                let res = self
                    .transport
                    .execute(TransportRequest {
                        method: "GET".to_string(),
                        url,
                        headers: vec![
                            ("Authorization".to_string(), format!("Bearer {token}")),
                            ("Accept".to_string(), "application/json".to_string()),
                        ],
                        body: None,
                        timeout_ms: 15_000,
                    })
                    .map_err(|_| ProviderError::new("provider_comments_fetch_failed", 502))?;
                if res.status != 200 {
                    return Err(ProviderError::new("provider_comments_fetch_failed", 502));
                }
                let body = res
                    .json()
                    .map_err(|_| ProviderError::new("provider_comments_fetch_failed", 502))?;
                let rows = body
                    .get("data")
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
                let url = build_url_with_params(
                    &format!("https://graph.facebook.com/{META_VERSION}/{post_external_id}/comments"),
                    &[
                        (
                            "fields",
                            "id,text,username,timestamp,hidden,like_count".to_string(),
                        ),
                        ("limit", clamped),
                    ],
                );
                let res = self
                    .transport
                    .execute(TransportRequest {
                        method: "GET".to_string(),
                        url,
                        headers: vec![
                            ("Authorization".to_string(), format!("Bearer {token}")),
                            ("Accept".to_string(), "application/json".to_string()),
                        ],
                        body: None,
                        timeout_ms: 15_000,
                    })
                    .map_err(|_| ProviderError::new("provider_comments_fetch_failed", 502))?;
                if res.status != 200 {
                    return Err(ProviderError::new("provider_comments_fetch_failed", 502));
                }
                let body = res
                    .json()
                    .map_err(|_| ProviderError::new("provider_comments_fetch_failed", 502))?;
                let rows = body
                    .get("data")
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
}
