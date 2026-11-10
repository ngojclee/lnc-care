"""Authenticated server-to-server LAN bridge, peer SSO tickets, and LNC Ads fallback client."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from fastapi import HTTPException, Request

from . import store

PEER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,80}$")
MAX_SKEW_SECONDS = 60
SSO_TTL_SECONDS = 60
DEFAULT_INTERNAL_HOSTS = frozenset({
    "10.21.4.101",
    "lnc-care",
    "lnc-care-lnc-care-1",
    "lnm-ads",
    "lnc-ads",
    "lnm-ads-lnm-ads-1",
    "localhost",
    "127.0.0.1",
    "::1",
    "testserver",
})


class BridgeClientError(Exception):
    def __init__(self, code: str, status: int = 502):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class BridgeConfig:
    secret: str
    self_id: str
    peers: dict[str, str]
    ads_internal_url: str
    internal_hosts: frozenset[str]


def _bare_origin(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"Invalid peer origin URL: {value!r}")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def bridge_config(environ=os.environ) -> BridgeConfig | None:
    secret = environ.get("LNC_INTERNAL_BRIDGE_SECRET", "").strip()
    if not secret:
        return None
    if len(secret) < 32:
        raise RuntimeError("LNC_INTERNAL_BRIDGE_SECRET must be at least 32 characters")

    raw_peers = environ.get("LNC_INTERNAL_BRIDGE_PEERS", "").strip()
    ads_public_default = environ.get("LNC_ADS_PUBLIC_URL", "https://ads-mcp.lengoc.me").strip()
    ads_internal = _bare_origin(
        environ.get("LNC_ADS_INTERNAL_URL", "http://10.21.4.101:8480").strip()
        or "http://10.21.4.101:8480"
    )

    peers: dict[str, str] = {}
    if raw_peers:
        for entry in raw_peers.split(","):
            item = entry.strip()
            if not item:
                continue
            if "=" in item:
                pid, purl = item.split("=", 1)
                pid = pid.strip().lower()
                if not PEER_ID_RE.fullmatch(pid):
                    raise RuntimeError(f"Invalid bridge peer id: {pid!r}")
                peers[pid] = _bare_origin(purl)
            else:
                pid = item.lower()
                if not PEER_ID_RE.fullmatch(pid):
                    raise RuntimeError(f"Invalid bridge peer id: {pid!r}")
                default_url = (
                    ads_public_default
                    if pid == "lnc-ads"
                    else f"https://{pid}.lengoc.me"
                )
                peers[pid] = _bare_origin(default_url)
    else:
        peers["lnc-ads"] = _bare_origin(ads_public_default)

    extra_hosts = {
        h.strip().lower()
        for h in environ.get("LNC_INTERNAL_BRIDGE_HOSTS", "").split(",")
        if h.strip()
    }
    return BridgeConfig(
        secret=secret,
        self_id=environ.get("LNC_INTERNAL_BRIDGE_SELF_ID", "lnc-care").strip() or "lnc-care",
        peers=peers,
        ads_internal_url=ads_internal,
        internal_hosts=DEFAULT_INTERNAL_HOSTS | extra_hosts,
    )


def canonical_payload(
    peer: str,
    timestamp: str,
    nonce: str,
    method: str,
    path_with_query: str,
    body: bytes,
) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{peer}\n{timestamp}\n{nonce}\n{method.upper()}\n{path_with_query}\n{body_hash}"


def sign_request(
    secret: str,
    peer: str,
    timestamp: str,
    nonce: str,
    method: str,
    path_with_query: str,
    body: bytes = b"",
) -> str:
    msg = canonical_payload(peer, timestamp, nonce, method, path_with_query, body)
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _consume_nonce(db_path: Path, org: str, key: str, expires_at: int) -> bool:
    now = int(time.time())
    with store.connect(db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "DELETE FROM bridge_nonces WHERE organization_id=? AND expires_at<=?",
            (org, now),
        )
        try:
            db.execute(
                "INSERT INTO bridge_nonces(organization_id, nonce, expires_at) VALUES (?,?,?)",
                (org, key, expires_at),
            )
            return True
        except store.sqlite3.IntegrityError:
            return False


def authenticate(
    cfg: BridgeConfig | None,
    request: Request,
    body: bytes,
    db_path: Path,
    org: str,
) -> str:
    if cfg is None:
        raise HTTPException(503, "internal_bridge_not_configured")
    peer = request.headers.get("x-lnc-bridge-peer", "").strip().lower()
    ts_str = request.headers.get("x-lnc-bridge-timestamp", "").strip()
    nonce = request.headers.get("x-lnc-bridge-nonce", "").strip()
    sig = request.headers.get("x-lnc-bridge-signature", "").strip().lower()

    if peer not in cfg.peers or not NONCE_RE.fullmatch(nonce) or len(sig) != 64:
        raise HTTPException(401, "bridge_unauthorized")
    try:
        ts = int(ts_str)
    except ValueError:
        raise HTTPException(401, "bridge_timestamp_invalid") from None
    now = int(time.time())
    if abs(now - ts) > MAX_SKEW_SECONDS:
        raise HTTPException(401, "bridge_timestamp_expired")

    path_with_query = request.url.path
    if request.url.query:
        path_with_query = f"{path_with_query}?{request.url.query}"

    expected = sign_request(cfg.secret, peer, ts_str, nonce, request.method, path_with_query, body)
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(401, "bridge_signature_invalid")

    if not _consume_nonce(db_path, org, f"req:{peer}:{nonce}", now + MAX_SKEW_SECONDS * 2):
        raise HTTPException(401, "bridge_nonce_replayed")
    return peer


def mint_sso_ticket(
    cfg: BridgeConfig | None,
    *,
    audience: str,
    subject: str = "owner",
    ttl: int = SSO_TTL_SECONDS,
) -> str:
    if cfg is None:
        raise HTTPException(503, "internal_bridge_not_configured")
    if audience not in cfg.peers:
        raise HTTPException(404, "bridge_peer_unknown")
    now = int(time.time())
    payload = {
        "v": 1,
        "iss": cfg.self_id,
        "aud": audience,
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(24),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(cfg.secret.encode("utf-8"), b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def consume_sso_ticket(
    cfg: BridgeConfig | None,
    ticket: str,
    db_path: Path,
    org: str,
) -> dict:
    if cfg is None:
        raise HTTPException(503, "internal_bridge_not_configured")
    if not isinstance(ticket, str) or "." not in ticket or len(ticket) > 2048:
        raise HTTPException(401, "sso_ticket_invalid")
    b64, sig = ticket.split(".", 1)
    expected = hmac.new(cfg.secret.encode("utf-8"), b64.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig.lower()):
        raise HTTPException(401, "sso_ticket_invalid")
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except Exception:
        raise HTTPException(401, "sso_ticket_invalid") from None

    now = int(time.time())
    if (
        not isinstance(payload, dict)
        or payload.get("v") != 1
        or payload.get("aud") != cfg.self_id
        or payload.get("iss") not in cfg.peers
        or not isinstance(payload.get("jti"), str)
        or not NONCE_RE.fullmatch(payload["jti"])
        or not isinstance(payload.get("exp"), int)
        or not isinstance(payload.get("iat"), int)
        or payload["iat"] > now + 15
        or payload["exp"] <= now
    ):
        raise HTTPException(401, "sso_ticket_expired_or_invalid")

    if not _consume_nonce(db_path, org, f"sso:{payload['jti']}", int(payload["exp"]) + 60):
        raise HTTPException(401, "sso_ticket_replayed")
    return payload


def safe_relative_next(next_path: str | None, default: str = "/admin/#inbox") -> str:
    val = (next_path or "").strip()
    if (
        not val
        or not val.startswith("/")
        or val.startswith("//")
        or "\\" in val
        or "\r" in val
        or "\n" in val
    ):
        return default
    parsed = urlsplit(val)
    if parsed.scheme or parsed.netloc:
        return default
    return val


def validate_peer_return_to(cfg: BridgeConfig, peer: str, return_to: str) -> str:
    peer_origin = cfg.peers.get(peer)
    if not peer_origin:
        raise HTTPException(404, "bridge_peer_unknown")
    val = (return_to or "").strip()
    if not val:
        return f"{peer_origin}/admin/"
    parsed = urlsplit(val)
    if parsed.username or parsed.password or any(c.isspace() for c in val):
        raise HTTPException(422, "Invalid return_to URL")
    candidate_origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    loopback_ok = parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")
    if candidate_origin != peer_origin and not loopback_ok:
        raise HTTPException(403, "return_to origin does not match peer allowlist")
    return val


def append_query_params(url: str, extra: dict[str, str]) -> str:
    parsed = urlsplit(url)
    existing = parsed.query
    added = urlencode({k: v for k, v in extra.items() if v is not None})
    merged_query = f"{existing}&{added}" if existing and added else (existing or added)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, merged_query, parsed.fragment))


class AdsBridgeClient:
    """Signed LAN fallback client to LNC Ads (`/api/internal/bridge/*`) while LNC-Agent-Hub upgrades."""

    def __init__(self, cfg: BridgeConfig, *, transport=None):
        self.cfg = cfg
        self._client = httpx.Client(timeout=8.0, transport=transport)

    def _call(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        timeout: float = 6.0,
    ) -> dict:
        query_str = urlencode({k: v for k, v in (params or {}).items() if v is not None})
        path_with_query = f"{path}?{query_str}" if query_str else path
        raw_body = (
            json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if json_body is not None
            else b""
        )
        ts = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        sig = sign_request(
            self.cfg.secret,
            self.cfg.self_id,
            ts,
            nonce,
            method,
            path_with_query,
            raw_body,
        )
        headers = {
            "Accept": "application/json",
            "X-LNC-Bridge-Peer": self.cfg.self_id,
            "X-LNC-Bridge-Timestamp": ts,
            "X-LNC-Bridge-Nonce": nonce,
            "X-LNC-Bridge-Signature": sig,
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        url = f"{self.cfg.ads_internal_url}{path_with_query}"
        try:
            res = self._client.request(
                method.upper(),
                url,
                content=raw_body if json_body is not None else None,
                headers=headers,
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise BridgeClientError("ads_bridge_unreachable", 503) from exc

        data = res.json() if res.content else {}
        if res.status_code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else None
            raise BridgeClientError(str(detail or f"ads_bridge_http_{res.status_code}"), res.status_code)
        return data if isinstance(data, dict) else {"data": data}

    def status(self) -> dict:
        return self._call("GET", "/api/internal/bridge/status", timeout=3.0)

    def list_shops(self) -> list[dict]:
        return self._call("GET", "/api/internal/bridge/shops").get("shops", [])

    def ensure_shop(self, name: str) -> dict:
        return self._call("POST", "/api/internal/bridge/shops", json_body={"name": name})

    def list_connections(self, *, shop: str | None = None, provider: str | None = None) -> list[dict]:
        return self._call(
            "GET",
            "/api/internal/bridge/connections",
            params={"shop": shop, "provider": provider},
        ).get("connections", [])

    def bind_shop(self, connection_id: int, shop: str) -> dict:
        return self._call(
            "POST",
            f"/api/internal/bridge/connections/{connection_id}/bind-shop",
            json_body={"shop": shop},
        )

    def list_channels(self, shop: str, *, provider: str | None = None) -> dict:
        return self._call(
            "GET",
            "/api/internal/bridge/channels",
            params={"shop": shop, "provider": provider},
            timeout=10.0,
        )

    def start_oauth(
        self,
        *,
        provider: str,
        shop: str,
        label: str = "",
        connection_id: int | None = None,
        include_care_scopes: bool = True,
        extra_scopes: str = "",
        return_to: str = "",
    ) -> dict:
        body: dict = {
            "provider": provider,
            "shop": shop,
            "label": label,
            "include_care_scopes": include_care_scopes,
            "extra_scopes": extra_scopes,
            "return_to": return_to,
        }
        if connection_id is not None:
            body["connection_id"] = connection_id
        return self._call("POST", "/api/internal/bridge/oauth/start", json_body=body)

    def platform_call(
        self,
        *,
        shop: str,
        connection_id: int,
        method: str = "GET",
        path: str,
        params: dict | None = None,
        body: dict | None = None,
        use_page_token: bool = False,
        page_id: str = "",
    ) -> dict:
        return self._call(
            "POST",
            "/api/internal/bridge/platform-call",
            json_body={
                "shop": shop,
                "connection_id": connection_id,
                "method": method.upper(),
                "path": path,
                "params": params,
                "body": body,
                "use_page_token": use_page_token,
                "page_id": page_id,
            },
            timeout=10.0,
        )

    def verify_meta_signature(self, raw_body: bytes, signature_header: str) -> dict:
        return self._call(
            "POST",
            "/api/internal/bridge/meta/verify-signature",
            json_body={
                "raw_body_b64": base64.b64encode(raw_body).decode("ascii"),
                "signature_header": signature_header,
            },
            timeout=3.5,
        )
