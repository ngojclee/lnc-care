"""AES-GCM envelope storage; ownership is authenticated with every record."""
import base64
import json
import os
import re
import sqlite3

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultError(Exception):
    pass


def master(value: str) -> bytes:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise VaultError("LNC_MASTER_KEY must contain exactly 64 hexadecimal characters")
    return bytes.fromhex(value)


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decoded(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


class Vault:
    def __init__(self, key: str | None = None, previous_key: str | None = None):
        self._key = master(key or ("00" * 32))
        self._previous_key = master(previous_key) if previous_key else None
        self.ready = True

    @staticmethod
    def aad(org: str, kind: str, subject: str) -> bytes:
        return json.dumps(["lnc-care-v1", org, kind, subject], separators=(",", ":")).encode()

    def seal(self, org: str, kind: str, subject: str, value: dict) -> str:
        plain = json.dumps(value, separators=(",", ":")).encode()
        if len(plain) > 65536:
            raise VaultError("Credential payload exceeds limit")
        aad, data_key = self.aad(org, kind, subject), AESGCM.generate_key(bit_length=256)
        key_nonce, data_nonce = os.urandom(12), os.urandom(12)
        envelope = {
            "v": 1,
            "kn": encoded(key_nonce),
            "dn": encoded(data_nonce),
            "key": encoded(AESGCM(self._key).encrypt(key_nonce, data_key, aad)),
            "data": encoded(AESGCM(data_key).encrypt(data_nonce, plain, aad)),
        }
        return json.dumps(envelope, separators=(",", ":"))

    def open(self, org: str, kind: str, subject: str, envelope: str) -> dict:
        try:
            item, aad = json.loads(envelope), self.aad(org, kind, subject)
            if item["v"] != 1:
                raise ValueError("Unknown envelope version")
            key = AESGCM(self._key).decrypt(decoded(item["kn"]), decoded(item["key"]), aad)
            plain = AESGCM(key).decrypt(decoded(item["dn"]), decoded(item["data"]), aad)
            value = json.loads(plain)
            if not isinstance(value, dict):
                raise TypeError("Expected object")
            return value
        except (ValueError, TypeError, KeyError, InvalidTag, UnicodeError) as exc:
            raise VaultError("Credential store is unreadable; restore the correct key or backup") from exc

    def put(self, db: sqlite3.Connection, org: str, kind: str, subject: str, value: dict) -> None:
        envelope = self.seal(org, kind, subject, value)
        db.execute(
            """INSERT INTO secret_envelopes(organization_id,kind,subject,envelope) VALUES (?,?,?,?)
               ON CONFLICT(organization_id,kind,subject) DO UPDATE SET envelope=excluded.envelope""",
            (org, kind, subject, envelope),
        )

    def get(self, db: sqlite3.Connection, org: str, kind: str, subject: str) -> dict | None:
        row = db.execute(
            """SELECT envelope FROM secret_envelopes
               WHERE organization_id=? AND kind=? AND subject=?""",
            (org, kind, subject),
        ).fetchone()
        return self.open(org, kind, subject, row["envelope"]) if row else None

    def delete(self, db: sqlite3.Connection, org: str, kind: str, subject: str) -> None:
        db.execute(
            "DELETE FROM secret_envelopes WHERE organization_id=? AND kind=? AND subject=?",
            (org, kind, subject),
        )

    def verify_master(self, db: sqlite3.Connection, org: str) -> None:
        self.initialize(db, org)

    def initialize(self, db: sqlite3.Connection, org: str) -> None:
        db.execute("BEGIN IMMEDIATE")
        existing = self.get(db, org, "system", "master-check")
        count = db.execute("SELECT count(*) FROM secret_envelopes WHERE organization_id=?", (org,)).fetchone()[0]
        if existing is None:
            if count:
                raise VaultError("Credential key check is missing")
            self.put(db, org, "system", "master-check", {"service": "lnc-care", "v": 1})
        elif existing != {"service": "lnc-care", "v": 1}:
            raise VaultError("Credential key check is invalid")

    def rewrap(self, db: sqlite3.Connection, org: str, new_key: str) -> int:
        replacement = master(new_key)
        rows = db.execute("SELECT * FROM secret_envelopes WHERE organization_id=?", (org,)).fetchall()
        for row in rows:
            self.open(org, row["kind"], row["subject"], row["envelope"])
            item = json.loads(row["envelope"])
            aad = self.aad(org, row["kind"], row["subject"])
            key = AESGCM(self._key).decrypt(decoded(item["kn"]), decoded(item["key"]), aad)
            nonce = os.urandom(12)
            item.update(kn=encoded(nonce), key=encoded(AESGCM(replacement).encrypt(nonce, key, aad)))
            db.execute(
                """UPDATE secret_envelopes SET envelope=?
                   WHERE organization_id=? AND kind=? AND subject=?""",
                (json.dumps(item, separators=(",", ":")), org, row["kind"], row["subject"]),
            )
        return len(rows)
