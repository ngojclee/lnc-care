//! AES-256-GCM envelope storage (`secret_envelopes`), byte-for-byte compatible with Python `Vault` v1.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use rusqlite::{params, Connection};
use serde_json::{json, Value};

use crate::audit::canonical_ascii_json;

#[derive(Debug, Clone)]
pub struct VaultError(pub String);

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for VaultError {}

pub fn parse_master_key(value: &str) -> Result<[u8; 32], VaultError> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VaultError(
            "LNC_MASTER_KEY must contain exactly 64 hexadecimal characters".to_string(),
        ));
    }
    let bytes = hex::decode(trimmed)
        .map_err(|_| VaultError("LNC_MASTER_KEY must contain valid hex".to_string()))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[derive(Clone)]
pub struct Vault {
    key: [u8; 32],
    #[allow(dead_code)]
    previous_key: Option<[u8; 32]>,
    pub ready: bool,
}

impl Vault {
    pub fn new(key: Option<&str>, previous_key: Option<&str>) -> Result<Self, VaultError> {
        let default_hex = "00".repeat(32);
        let raw = key.filter(|s| !s.trim().is_empty()).unwrap_or(&default_hex);
        let parsed_key = parse_master_key(raw)?;
        let parsed_prev = match previous_key.filter(|s| !s.trim().is_empty()) {
            Some(pk) => Some(parse_master_key(pk)?),
            None => None,
        };
        Ok(Self {
            key: parsed_key,
            previous_key: parsed_prev,
            ready: true,
        })
    }

    pub fn aad(org: &str, kind: &str, subject: &str) -> Vec<u8> {
        canonical_ascii_json(&json!(["lnc-care-v1", org, kind, subject])).into_bytes()
    }

    pub fn seal(&self, org: &str, kind: &str, subject: &str, value: &Value) -> Result<String, VaultError> {
        if !value.is_object() {
            return Err(VaultError("Expected JSON object payload".to_string()));
        }
        let plain = canonical_ascii_json(value).into_bytes();
        if plain.len() > 65536 {
            return Err(VaultError("Credential payload exceeds limit".to_string()));
        }
        let aad = Self::aad(org, kind, subject);

        let mut data_key = [0u8; 32];
        let mut kn_bytes = [0u8; 12];
        let mut dn_bytes = [0u8; 12];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut data_key);
        rng.fill_bytes(&mut kn_bytes);
        rng.fill_bytes(&mut dn_bytes);

        let master_cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| VaultError("Invalid master key length".to_string()))?;
        let data_cipher = Aes256Gcm::new_from_slice(&data_key)
            .map_err(|_| VaultError("Invalid data key length".to_string()))?;

        let enc_key = master_cipher
            .encrypt(
                Nonce::from_slice(&kn_bytes),
                Payload {
                    msg: &data_key,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError("Envelope key encryption failed".to_string()))?;

        let enc_data = data_cipher
            .encrypt(
                Nonce::from_slice(&dn_bytes),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError("Envelope payload encryption failed".to_string()))?;

        // Match exact compact envelope format `{"v":1,"kn":...,"dn":...,"key":...,"data":...}`
        let env_str = format!(
            "{{\"v\":1,\"kn\":\"{}\",\"dn\":\"{}\",\"key\":\"{}\",\"data\":\"{}\"}}",
            B64.encode(kn_bytes),
            B64.encode(dn_bytes),
            B64.encode(enc_key),
            B64.encode(enc_data),
        );
        Ok(env_str)
    }

    pub fn open(&self, org: &str, kind: &str, subject: &str, envelope: &str) -> Result<Value, VaultError> {
        let unreadable = || {
            VaultError("Credential store is unreadable; restore the correct key or backup".to_string())
        };
        let item: Value = serde_json::from_str(envelope).map_err(|_| unreadable())?;
        if item.get("v").and_then(|v| v.as_i64()) != Some(1) {
            return Err(unreadable());
        }
        let kn = B64
            .decode(item.get("kn").and_then(|v| v.as_str()).ok_or_else(unreadable)?)
            .map_err(|_| unreadable())?;
        let dn = B64
            .decode(item.get("dn").and_then(|v| v.as_str()).ok_or_else(unreadable)?)
            .map_err(|_| unreadable())?;
        let enc_key = B64
            .decode(item.get("key").and_then(|v| v.as_str()).ok_or_else(unreadable)?)
            .map_err(|_| unreadable())?;
        let enc_data = B64
            .decode(item.get("data").and_then(|v| v.as_str()).ok_or_else(unreadable)?)
            .map_err(|_| unreadable())?;

        if kn.len() != 12 || dn.len() != 12 {
            return Err(unreadable());
        }

        let aad = Self::aad(org, kind, subject);
        let master_cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| unreadable())?;
        let data_key = master_cipher
            .decrypt(
                Nonce::from_slice(&kn),
                Payload {
                    msg: &enc_key,
                    aad: &aad,
                },
            )
            .map_err(|_| unreadable())?;

        let data_cipher = Aes256Gcm::new_from_slice(&data_key).map_err(|_| unreadable())?;
        let plain = data_cipher
            .decrypt(
                Nonce::from_slice(&dn),
                Payload {
                    msg: &enc_data,
                    aad: &aad,
                },
            )
            .map_err(|_| unreadable())?;

        let val: Value = serde_json::from_slice(&plain).map_err(|_| unreadable())?;
        if !val.is_object() {
            return Err(unreadable());
        }
        Ok(val)
    }

    pub fn put(
        &self,
        db: &Connection,
        org: &str,
        kind: &str,
        subject: &str,
        value: &Value,
    ) -> Result<(), VaultError> {
        let envelope = self.seal(org, kind, subject, value)?;
        db.execute(
            "INSERT INTO secret_envelopes(organization_id, kind, subject, envelope) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(organization_id, kind, subject) DO UPDATE SET envelope=excluded.envelope",
            params![org, kind, subject, envelope],
        )
        .map_err(|e| VaultError(e.to_string()))?;
        Ok(())
    }

    pub fn get(
        &self,
        db: &Connection,
        org: &str,
        kind: &str,
        subject: &str,
    ) -> Result<Option<Value>, VaultError> {
        let row: Result<String, rusqlite::Error> = db.query_row(
            "SELECT envelope FROM secret_envelopes WHERE organization_id=?1 AND kind=?2 AND subject=?3",
            params![org, kind, subject],
            |r| r.get(0),
        );
        match row {
            Ok(env_str) => Ok(Some(self.open(org, kind, subject, &env_str)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(VaultError(e.to_string())),
        }
    }

    pub fn delete(&self, db: &Connection, org: &str, kind: &str, subject: &str) {
        let _ = db.execute(
            "DELETE FROM secret_envelopes WHERE organization_id=?1 AND kind=?2 AND subject=?3",
            params![org, kind, subject],
        );
    }

    pub fn verify_master(&self, db: &Connection, org: &str) -> Result<(), VaultError> {
        self.initialize(db, org)
    }

    pub fn initialize(&self, db: &Connection, org: &str) -> Result<(), VaultError> {
        let existing = self.get(db, org, "system", "master-check")?;
        let count: i64 = db
            .query_row(
                "SELECT count(*) FROM secret_envelopes WHERE organization_id=?1",
                params![org],
                |r| r.get(0),
            )
            .map_err(|e| VaultError(e.to_string()))?;

        let expected = json!({"service": "lnc-care", "v": 1});
        match existing {
            None => {
                if count > 0 {
                    return Err(VaultError("Credential key check is missing".to_string()));
                }
                self.put(db, org, "system", "master-check", &expected)?;
            }
            Some(val) => {
                if val != expected {
                    return Err(VaultError("Credential key check is invalid".to_string()));
                }
            }
        }
        Ok(())
    }

    pub fn rewrap(&self, db: &Connection, org: &str, new_key_hex: &str) -> Result<usize, VaultError> {
        let replacement = parse_master_key(new_key_hex)?;
        let replacement_cipher = Aes256Gcm::new_from_slice(&replacement)
            .map_err(|_| VaultError("Invalid replacement key".to_string()))?;
        let current_cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| VaultError("Invalid current key".to_string()))?;

        let mut stmt = db
            .prepare("SELECT kind, subject, envelope FROM secret_envelopes WHERE organization_id=?1")
            .map_err(|e| VaultError(e.to_string()))?;
        let rows: Vec<(String, String, String)> = stmt
            .query_map(params![org], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| VaultError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| VaultError(e.to_string()))?;

        let mut rng = rand::thread_rng();
        for (kind, subject, env_str) in &rows {
            // Verify full envelope integrity first
            let _ = self.open(org, kind, subject, env_str)?;
            let mut item: Value = serde_json::from_str(env_str)
                .map_err(|_| VaultError("Invalid envelope JSON".to_string()))?;
            let aad = Self::aad(org, kind, subject);
            let kn = B64
                .decode(item["kn"].as_str().unwrap_or_default())
                .map_err(|_| VaultError("Invalid nonce".to_string()))?;
            let enc_key = B64
                .decode(item["key"].as_str().unwrap_or_default())
                .map_err(|_| VaultError("Invalid wrapped key".to_string()))?;
            let data_key = current_cipher
                .decrypt(
                    Nonce::from_slice(&kn),
                    Payload {
                        msg: &enc_key,
                        aad: &aad,
                    },
                )
                .map_err(|_| VaultError("Failed to unwrap data key".to_string()))?;

            let mut new_kn = [0u8; 12];
            rng.fill_bytes(&mut new_kn);
            let rewrapped = replacement_cipher
                .encrypt(
                    Nonce::from_slice(&new_kn),
                    Payload {
                        msg: &data_key,
                        aad: &aad,
                    },
                )
                .map_err(|_| VaultError("Failed to rewrap data key".to_string()))?;

            item["kn"] = Value::String(B64.encode(new_kn));
            item["key"] = Value::String(B64.encode(rewrapped));
            let updated_env = canonical_ascii_json(&item);
            db.execute(
                "UPDATE secret_envelopes SET envelope=?1 WHERE organization_id=?2 AND kind=?3 AND subject=?4",
                params![updated_env, org, kind, subject],
            )
            .map_err(|e| VaultError(e.to_string()))?;
        }
        Ok(rows.len())
    }
}
