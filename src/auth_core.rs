//! Blueprint v2.0 auth core for LNC Care: Argon2id management key, server-side sessions
//! (12h idle / 7d max / durable `session_epoch`), same-origin CSRF checks, sealed OIDC
//! transaction cookies, and cookie helpers. No secret ever leaves this module in a response.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_COOKIE: &str = "lnc_care_sess";
pub const OIDC_TX_COOKIE: &str = "lnc_care_oidc_tx";
pub const SESSION_IDLE_SECS: i64 = 12 * 60 * 60;
pub const SESSION_MAX_SECS: i64 = 7 * 24 * 60 * 60;
pub const OIDC_TX_TTL_SECS: i64 = 300;
const EPOCH_KEY: &str = "__session_epoch";
/// Throttle for sliding-idle writes so polling endpoints stay read-mostly.
const TOUCH_AFTER_SECS: i64 = 30;

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

pub fn argon2id() -> Argon2<'static> {
    let params = Params::new(65_536, 3, 4, None).expect("Argon2id parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_argon2id(secret: &str) -> Result<String, String> {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| e.to_string())?;
    argon2id()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify_argon2id(secret: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    argon2id().verify_password(secret.as_bytes(), &parsed).is_ok()
}

pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn hmac_hex_bytes(key: &[u8], msg: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

pub fn random_urlsafe(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    B64_URL.encode(buf)
}

/// Authentication digest stored for machine API keys: `hmac1:` + HMAC-SHA256(pepper, raw).
pub fn api_key_digest(pepper: &[u8; 32], raw: &str) -> String {
    format!("hmac1:{}", hmac_hex_bytes(pepper, raw.as_bytes()))
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

pub fn cookie_header(
    name: &str,
    value: &str,
    path: &str,
    max_age: i64,
    secure: bool,
) -> String {
    let sec = if secure { "; Secure" } else { "" };
    format!("{name}={value}; HttpOnly; SameSite=Lax; Path={path}; Max-Age={max_age}{sec}")
}

pub fn clear_cookie_header(name: &str, path: &str, secure: bool) -> String {
    let sec = if secure { "; Secure" } else { "" };
    format!("{name}=; HttpOnly; SameSite=Lax; Path={path}; Max-Age=0{sec}")
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(header::COOKIE).iter() {
        let Ok(s) = val.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k.trim() == name && !v.trim().is_empty() {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Server-side sessions (`management_sessions`) with durable `session_epoch`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub token_hash: String,
    pub auth_method: String,
    pub username: String,
    pub session_epoch: i64,
    pub idle_expires_at: i64,
    pub max_expires_at: i64,
}

pub fn current_epoch(db: &Connection, org: &str) -> i64 {
    db.query_row(
        "SELECT value FROM runtime_settings WHERE organization_id=?1 AND key=?2",
        params![org, EPOCH_KEY],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|v| v.trim().parse::<i64>().ok())
    .unwrap_or(1)
}

pub fn bump_epoch(db: &Connection, org: &str) -> Result<i64, rusqlite::Error> {
    let next = current_epoch(db, org) + 1;
    db.execute(
        "INSERT INTO runtime_settings(organization_id, key, value) VALUES (?1, ?2, ?3)
         ON CONFLICT(organization_id, key) DO UPDATE SET value=excluded.value",
        params![org, EPOCH_KEY, next.to_string()],
    )?;
    db.execute(
        "DELETE FROM management_sessions WHERE organization_id=?1",
        params![org],
    )?;
    Ok(next)
}

/// Mints a session and returns the raw opaque token (only its SHA-256 is persisted).
pub fn create_session(
    db: &Connection,
    org: &str,
    auth_method: &str,
    username: &str,
    now: i64,
    idle_secs: i64,
    max_secs: i64,
) -> Result<String, rusqlite::Error> {
    db.execute(
        "DELETE FROM management_sessions WHERE organization_id=?1
         AND (idle_expires_at <= ?2 OR max_expires_at <= ?2)",
        params![org, now],
    )?;
    let token = random_urlsafe(32);
    let epoch = current_epoch(db, org);
    db.execute(
        "INSERT INTO management_sessions
         (token_hash, organization_id, auth_method, username, session_epoch,
          created_at, last_seen_at, idle_expires_at, max_expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8)",
        params![
            sha256_hex(&token),
            org,
            auth_method,
            username,
            epoch,
            now,
            now + idle_secs,
            now + max_secs
        ],
    )?;
    Ok(token)
}

pub fn lookup_session(
    db: &Connection,
    org: &str,
    token: &str,
    now: i64,
    touch: bool,
    idle_secs: i64,
) -> Option<SessionInfo> {
    if token.len() < 20 {
        return None;
    }
    let token_hash = sha256_hex(token);
    let row: Option<(String, String, i64, i64, i64, i64)> = db
        .query_row(
            "SELECT auth_method, username, session_epoch, last_seen_at, idle_expires_at, max_expires_at
             FROM management_sessions WHERE token_hash=?1 AND organization_id=?2",
            params![token_hash, org],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten();
    let (auth_method, username, epoch, last_seen, idle_exp, max_exp) = row?;
    if epoch != current_epoch(db, org) || idle_exp <= now || max_exp <= now {
        let _ = db.execute(
            "DELETE FROM management_sessions WHERE token_hash=?1",
            params![token_hash],
        );
        return None;
    }
    let mut idle_out = idle_exp;
    if touch && now - last_seen >= TOUCH_AFTER_SECS {
        idle_out = (now + idle_secs).min(max_exp);
        let _ = db.execute(
            "UPDATE management_sessions SET last_seen_at=?2, idle_expires_at=?3 WHERE token_hash=?1",
            params![token_hash, now, idle_out],
        );
    }
    Some(SessionInfo {
        token_hash,
        auth_method,
        username,
        session_epoch: epoch,
        idle_expires_at: idle_out,
        max_expires_at: max_exp,
    })
}

pub fn delete_session_by_token(db: &Connection, token: &str) {
    let _ = db.execute(
        "DELETE FROM management_sessions WHERE token_hash=?1",
        params![sha256_hex(token)],
    );
}

// ---------------------------------------------------------------------------
// Sealed blobs (OIDC transaction cookie): AES-256-GCM with AAD, HKDF subkey
// ---------------------------------------------------------------------------

pub fn seal_blob(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad })
        .map_err(|_| "seal failed".to_string())?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    Ok(B64_URL.encode(blob))
}

pub fn open_blob(key: &[u8; 32], aad: &[u8], sealed: &str) -> Result<Vec<u8>, String> {
    let raw = B64_URL.decode(sealed.trim()).map_err(|_| "bad blob".to_string())?;
    if raw.len() < 13 {
        return Err("bad blob".to_string());
    }
    let (nonce, ct) = raw.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| "open failed".to_string())
}

// ---------------------------------------------------------------------------
// Same-origin verification (X-Forwarded-Host is never consulted)
// ---------------------------------------------------------------------------

/// Lowercase host without port; handles `[::1]:8000`.
pub fn host_only(authority: &str) -> String {
    let a = authority.trim().to_ascii_lowercase();
    if let Some(rest) = a.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("").to_string();
    }
    a.split(':').next().unwrap_or("").to_string()
}

pub fn url_host(value: &str) -> Option<String> {
    Url::parse(value.trim())
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase()))
}

#[derive(Debug, PartialEq, Eq)]
pub enum OriginVerdict {
    SameOrigin,
    /// Neither Origin nor Referer was sent (non-browser / old client).
    Absent,
    CrossOrigin,
}

/// `allowed_hosts` = lowercase hostnames that count as "us" (validated `Host`, PUBLIC_BASE_URL,
/// OIDC redirect host). Spoofed `X-Forwarded-Host` is not part of this set.
pub fn origin_verdict(headers: &HeaderMap, allowed_hosts: &[String]) -> OriginVerdict {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
    {
        if !matches!(site.as_str(), "same-origin" | "none") {
            return OriginVerdict::CrossOrigin;
        }
    }
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let candidate = origin.or_else(|| {
        headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    });
    let Some(candidate) = candidate else {
        return OriginVerdict::Absent;
    };
    match url_host(candidate) {
        Some(h) if allowed_hosts.iter().any(|a| a == &h) => OriginVerdict::SameOrigin,
        _ => OriginVerdict::CrossOrigin,
    }
}

pub fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

pub fn last4(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn origin_spoof_with_forwarded_host_is_cross_origin() {
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, HeaderValue::from_static("https://evil.attacker"));
        h.insert("x-forwarded-host", HeaderValue::from_static("evil.attacker"));
        assert_eq!(
            origin_verdict(&h, &["care-mcp.lengoc.me".to_string()]),
            OriginVerdict::CrossOrigin
        );
        let mut ok = HeaderMap::new();
        ok.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://care-mcp.lengoc.me"),
        );
        assert_eq!(
            origin_verdict(&ok, &["care-mcp.lengoc.me".to_string()]),
            OriginVerdict::SameOrigin
        );
    }

    #[test]
    fn argon2id_roundtrip_and_blob_seal_with_aad() {
        let phc = hash_argon2id("correct horse battery").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
        assert!(verify_argon2id("correct horse battery", &phc));
        assert!(!verify_argon2id("wrong", &phc));
        let key = [7u8; 32];
        let sealed = seal_blob(&key, b"oidc_tx:v1", b"payload").unwrap();
        assert_eq!(open_blob(&key, b"oidc_tx:v1", &sealed).unwrap(), b"payload");
        assert!(open_blob(&key, b"other", &sealed).is_err());
    }
}
