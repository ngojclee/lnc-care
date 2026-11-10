"""LNC Agent Hub shared Platform Vault, encrypted local lease cache, Universal SSO, and LAN bridge fallback.

Design guarantees for `lnc-care`:
1. Independent Service Identity: authenticates to LNC Agent Hub (`http://10.21.4.101:8380`)
   using `LNC_AGENT_HUB_API_KEY` (`svc:lnc-care`).
2. 100% Standalone Survival (Encrypted Local Vault Cache, TTL = 900s):
   Every provider app secret and connection token leased via `POST /v1/platform/connections/:id/lease`
   is encrypted into `lnc-care`'s local SQLite `Vault` (`secret_envelopes`).
   - If `lnc-ads` is shut down, `lnc-care` runs 100% independently.
   - If `LNC-Agent-Hub` restarts briefly, `lnc-care` continues serving webhooks, inbox, and replies
     from its encrypted local cache without interruption.
3. Login Anywhere, Use Everywhere:
   Shops, OAuth apps, and connections created in `LNC-Agent-Hub`, `lnc-ads`, or `lnc-care`
   upsert/pull bidirectionally scoped by `shop` (e.g. `LuxeClaw`).
4. Automatic LAN Bridge Fallback:
   While `LNC-Agent-Hub` `/v1/platform/*` returns `404` during rollout, `lnc-care` automatically
   falls back to `lnc-ads` (`http://10.21.4.101:8480/api/internal/bridge/*`) for shop/channel
   discovery, OAuth start, platform calls, and Meta webhook signature verification.
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import HTTPException

from . import audit, internal_bridge, store
from .vault import Vault

DEFAULT_LEASE_TTL_SECONDS = 900
STATUS_CACHE_TTL_SECONDS = 30
CARE_PROVIDERS = ("meta", "tiktok", "youtube")


class AgentHubError(Exception):
    def __init__(self, code: str, status: int = 502):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class AgentHubConfig:
    url: str
    public_url: str
    api_key: str
    self_id: str = "lnc-care"
    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS


def _bare_origin(value: str, env_name: str) -> str:
    val = value.strip()
    if not val:
        return ""
    parsed = urlsplit(val)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"{env_name} must be a bare HTTP(S) origin")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def agent_hub_config(environ=os.environ) -> AgentHubConfig | None:
    url = _bare_origin(environ.get("LNC_AGENT_HUB_URL", ""), "LNC_AGENT_HUB_URL")
    public_url = _bare_origin(environ.get("LNC_AGENT_HUB_PUBLIC_URL", ""), "LNC_AGENT_HUB_PUBLIC_URL")
    api_key = environ.get("LNC_AGENT_HUB_API_KEY", "").strip()
    if not url and not api_key:
        return None
    if api_key and not url:
        raise RuntimeError("LNC_AGENT_HUB_URL is required when LNC_AGENT_HUB_API_KEY is set")
    return AgentHubConfig(
        url=url,
        public_url=public_url or url,
        api_key=api_key,
        self_id=environ.get("LNC_INTERNAL_BRIDGE_SELF_ID", "lnc-care").strip() or "lnc-care",
    )


class AgentHubClient:
    def __init__(
        self,
        cfg: AgentHubConfig,
        *,
        ads_bridge: internal_bridge.AdsBridgeClient | None = None,
        transport=None,
    ):
        self.cfg = cfg
        self.ads_bridge = ads_bridge
        self._client = httpx.Client(timeout=5.0, transport=transport)
        self._lock = threading.Lock()
        self._cached_status: dict | None = None
        self._cached_status_at: float = 0.0
        self.last_sync_at: int | None = None
        self.last_sync_source: str | None = None
        self.last_warning: str | None = None

    def _headers(self, *, auth: bool = True) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "X-Request-Id": f"req_{secrets.token_hex(13)}",
        }
        if auth and self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        auth: bool = True,
        timeout: float = 4.0,
    ) -> httpx.Response:
        url = f"{self.cfg.url}{path}"
        return self._client.request(
            method,
            url,
            params=params,
            json=json_body,
            headers=self._headers(auth=auth),
            timeout=timeout,
        )

    def status_summary(self, *, force: bool = False) -> dict:
        now = time.monotonic()
        with self._lock:
            if (
                not force
                and self._cached_status
                and (now - self._cached_status_at) < STATUS_CACHE_TTL_SECONDS
            ):
                return dict(self._cached_status)

        reachable = False
        platform_ready = False
        principal_key = None
        hub_version = None
        mode = "awaiting_api_key"

        try:
            if self.cfg.api_key:
                res = self._request("GET", "/v1/platform/status", timeout=2.5)
                if res.status_code == 200:
                    data = res.json() if res.content else {}
                    reachable = True
                    platform_ready = bool(data.get("ok", True))
                    principal_key = data.get("principal_key")
                    hub_version = data.get("version")
                    mode = "vault_synced"
                elif res.status_code == 404:
                    h = self._request("GET", "/health", auth=False, timeout=2.0)
                    reachable = h.status_code == 200
                    mode = "awaiting_hub_upgrade" if reachable else "local_cache_fallback"
                elif res.status_code in (401, 403):
                    reachable = True
                    mode = "auth_error"
                else:
                    mode = "local_cache_fallback"
            else:
                h = self._request("GET", "/health", auth=False, timeout=2.0)
                reachable = h.status_code == 200
                mode = "awaiting_api_key" if reachable else "local_cache_fallback"
        except httpx.HTTPError:
            reachable = False
            mode = "local_cache_fallback"

        bridge_ready = False
        if not platform_ready and self.ads_bridge is not None:
            try:
                bst = self.ads_bridge.status()
                bridge_ready = bool(bst.get("ok"))
                if bridge_ready and mode in (
                    "awaiting_hub_upgrade",
                    "awaiting_api_key",
                    "local_cache_fallback",
                ):
                    mode = "ads_bridge_fallback"
            except internal_bridge.BridgeClientError:
                bridge_ready = False

        public_origin = self.cfg.public_url or self.cfg.url
        sso_path = (
            "/api/auth/sso/redirect?peer=lnc-agent-hub"
            if (self.cfg.api_key and platform_ready and public_origin)
            else None
        )
        summary = {
            "configured": True,
            "has_api_key": bool(self.cfg.api_key),
            "url": self.cfg.url,
            "public_url": public_origin,
            "reachable": reachable,
            "platform_api_ready": platform_ready,
            "bridge_fallback_ready": bridge_ready,
            "mode": mode,
            "principal_key": principal_key,
            "hub_version": hub_version,
            "sso_path": sso_path,
            "last_sync_at": self.last_sync_at,
            "last_sync_source": self.last_sync_source,
            "last_warning": self.last_warning,
        }
        with self._lock:
            self._cached_status = summary
            self._cached_status_at = now
        return dict(summary)

    def _invalidate_status_cache(self) -> None:
        with self._lock:
            self._cached_status = None
            self._cached_status_at = 0.0

    # --- Best-effort outbound push hooks ("Login Anywhere, Use Everywhere") ---

    def try_push_shop(self, name: str) -> bool:
        pushed = False
        if self.cfg.api_key:
            try:
                res = self._request(
                    "POST", "/v1/platform/shops", json_body={"name": name, "metadata": {}}
                )
                if res.status_code in (200, 201):
                    return True
                if res.status_code != 404:
                    self.last_warning = f"shop_push_http_{res.status_code}"
            except httpx.HTTPError:
                self.last_warning = "hub_unreachable_cached_locally"
        if not pushed and self.ads_bridge is not None:
            try:
                self.ads_bridge.ensure_shop(name)
                return True
            except internal_bridge.BridgeClientError:
                pass
        return False

    def try_push_app(self, db_path: Path, org: str, provider: str, vault: Vault) -> bool:
        if not self.cfg.api_key or provider not in ("meta", "tiktok", "youtube"):
            return False
        try:
            with store.connect_readonly(db_path) as db:
                row = db.execute(
                    "SELECT * FROM provider_apps WHERE organization_id=? AND provider=?",
                    (org, provider),
                ).fetchone()
                secret = vault.get(db, org, "app", provider) if row else None
            if not row or not secret or not secret.get("client_secret"):
                return False
            res = self._request(
                "PUT",
                f"/v1/platform/apps/{provider}",
                json_body={
                    "client_id": row["client_id"],
                    "client_secret": secret.get("client_secret", ""),
                    "project_id": row["project_id"] or "",
                    "webhook_verify_token": row["webhook_verify_token"] or "",
                    "source_app": self.cfg.self_id,
                },
            )
            if res.status_code in (200, 201):
                return True
            self.last_warning = f"app_push_http_{res.status_code}"
        except httpx.HTTPError:
            self.last_warning = "hub_unreachable_cached_locally"
        return False

    def try_push_connection(
        self, db_path: Path, org: str, connection_id: int, vault: Vault
    ) -> str | None:
        if not self.cfg.api_key:
            return None
        try:
            with store.connect_readonly(db_path) as db:
                conn = db.execute(
                    "SELECT * FROM provider_connections WHERE organization_id=? AND id=?",
                    (org, connection_id),
                ).fetchone()
                if not conn:
                    return None
                runtime = db.execute(
                    "SELECT * FROM connection_runtime WHERE organization_id=? AND connection_id=?",
                    (org, connection_id),
                ).fetchone()
                link = db.execute(
                    "SELECT hub_connection_id FROM hub_connection_links WHERE organization_id=? AND connection_id=?",
                    (org, connection_id),
                ).fetchone()
                if link and str(link["hub_connection_id"]).startswith("ads_bridge:"):
                    return None
                shop_rows = db.execute(
                    """SELECT DISTINCT s.name FROM shops s
                       WHERE s.organization_id=? AND (
                           EXISTS (SELECT 1 FROM shop_connection_bindings scb
                                   WHERE scb.organization_id=s.organization_id AND scb.shop_id=s.id AND scb.connection_id=?)
                           OR EXISTS (SELECT 1 FROM channel_shop_bindings csb
                                      JOIN channels ch ON ch.organization_id=csb.organization_id AND ch.id=csb.channel_id
                                      WHERE csb.organization_id=s.organization_id AND csb.shop_id=s.id
                                      AND ch.connection_id=? AND ch.approved=1)
                       ) ORDER BY s.name""",
                    (org, connection_id, connection_id),
                ).fetchall()
                token = (
                    vault.get(db, org, "connection", str(connection_id))
                    if conn["state"] == "verified"
                    else None
                )

            payload: dict = {
                "provider": conn["provider"],
                "label": conn["label"],
                "state": conn["state"],
                "expires_at": int(runtime["expires_at"])
                if runtime and runtime["expires_at"]
                else None,
                "shops": [str(r["name"]) for r in shop_rows],
                "source_app": self.cfg.self_id,
            }
            if link and link["hub_connection_id"]:
                payload["hub_connection_id"] = str(link["hub_connection_id"])
            if token and token.get("access_token"):
                payload["token"] = token

            res = self._request("POST", "/v1/platform/connections/upsert", json_body=payload)
            if res.status_code not in (200, 201):
                self.last_warning = f"connection_push_http_{res.status_code}"
                return None
            data = res.json()
            hub_id = str(data.get("hub_connection_id") or "").strip()
            hub_rev = int(data.get("revision") or 1)
            if hub_id:
                now = int(time.time())
                with store.connect(db_path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        """INSERT INTO hub_connection_links
                           (organization_id, connection_id, hub_connection_id, hub_revision, leased_at)
                           VALUES (?, ?, ?, ?, ?)
                           ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                            hub_connection_id=excluded.hub_connection_id,
                            hub_revision=excluded.hub_revision,
                            leased_at=excluded.leased_at""",
                        (org, connection_id, hub_id, hub_rev, now),
                    )
                return hub_id
        except httpx.HTTPError:
            self.last_warning = "hub_unreachable_cached_locally"
        return None

    # --- Resilient Encrypted Local Vault Lease Cache (TTL = 900s) ---

    def ensure_fresh_token(
        self,
        db_path: Path,
        org: str,
        vault: Vault,
        connection_id: int,
        *,
        force: bool = False,
    ) -> bool:
        """Refresh local encrypted Vault token from LNC-Agent-Hub when TTL (900s) or expiry requires.

        Never raises on network/Hub errors so `lnc-care` survives 100% standalone on local cache.
        """
        if not self.cfg.api_key:
            return False
        now = int(time.time())
        with store.connect_readonly(db_path) as db:
            link = db.execute(
                """SELECT hub_connection_id, hub_revision, leased_at
                   FROM hub_connection_links WHERE organization_id=? AND connection_id=?""",
                (org, connection_id),
            ).fetchone()
            if not link or str(link["hub_connection_id"]).startswith("ads_bridge:"):
                return False
            conn = db.execute(
                "SELECT provider, state FROM provider_connections WHERE organization_id=? AND id=?",
                (org, connection_id),
            ).fetchone()
            runtime = db.execute(
                "SELECT expires_at, app_revision FROM connection_runtime WHERE organization_id=? AND connection_id=?",
                (org, connection_id),
            ).fetchone()
            local_token = vault.get(db, org, "connection", str(connection_id))

        if not conn:
            return False

        needs_lease = (
            force
            or local_token is None
            or runtime is None
            or runtime["expires_at"] is None
            or int(runtime["expires_at"]) <= now + 120
            or int(link["leased_at"]) <= now - self.cfg.lease_ttl_seconds
        )
        if not needs_lease:
            return True

        try:
            res = self._request(
                "POST",
                f"/v1/platform/connections/{link['hub_connection_id']}/lease",
                json_body={"purpose": "provider_api", "force_refresh": bool(force)},
                timeout=4.0,
            )
            if res.status_code != 200:
                self.last_warning = f"lease_http_{res.status_code}"
                return False
            data = res.json()
            token = data.get("token")
            if not isinstance(token, dict) or not token.get("access_token"):
                return False
            expires_at = int(data.get("expires_at") or (now + 3600))
            hub_rev = int(data.get("revision") or link["hub_revision"] or 1)
            with store.connect(db_path) as db:
                db.execute("BEGIN IMMEDIATE")
                app_row = db.execute(
                    "SELECT revision FROM provider_apps WHERE organization_id=? AND provider=?",
                    (org, conn["provider"]),
                ).fetchone()
                app_rev = int(app_row["revision"]) if app_row else 1
                vault.put(db, org, "connection", str(connection_id), token)
                for page_id, ptok in (data.get("page_tokens") or {}).items():
                    if ptok:
                        vault.put(
                            db,
                            org,
                            "channel_token",
                            f"{conn['provider']}:{page_id}",
                            {"access_token": str(ptok)},
                        )
                db.execute(
                    """INSERT INTO connection_runtime
                       (organization_id, connection_id, revision, app_revision, expires_at, last_error)
                       VALUES (?, ?, 1, ?, ?, NULL)
                       ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                        revision=revision+1,
                        app_revision=excluded.app_revision,
                        expires_at=excluded.expires_at,
                        last_error=NULL""",
                    (org, connection_id, app_rev, expires_at),
                )
                db.execute(
                    "UPDATE provider_connections SET state='verified' WHERE organization_id=? AND id=?",
                    (org, connection_id),
                )
                db.execute(
                    """UPDATE hub_connection_links
                       SET hub_revision=?, leased_at=?
                       WHERE organization_id=? AND connection_id=?""",
                    (hub_rev, now, org, connection_id),
                )
            self.last_warning = None
            return True
        except httpx.HTTPError:
            self.last_warning = "hub_unreachable_serving_local_cache"
            return False

    # --- Shared OAuth Start (Hub primary -> LNC Ads Bridge fallback) ---

    def start_shared_oauth(
        self,
        *,
        provider: str,
        shop: str,
        label: str = "",
        return_to: str = "",
        extra_scopes: str = "",
    ) -> dict | None:
        if self.cfg.api_key:
            try:
                res = self._request(
                    "POST",
                    "/v1/platform/oauth/start",
                    json_body={
                        "provider": provider,
                        "shop": shop,
                        "label": label,
                        "include_care_scopes": True,
                        "extra_scopes": extra_scopes,
                        "return_to": return_to,
                        "caller_app": self.cfg.self_id,
                    },
                    timeout=4.0,
                )
                if res.status_code == 200:
                    return {**res.json(), "via": "agent_hub"}
            except httpx.HTTPError:
                pass
        if self.ads_bridge is not None and provider in ("meta", "tiktok"):
            try:
                started = self.ads_bridge.start_oauth(
                    provider=provider,
                    shop=shop,
                    label=label,
                    include_care_scopes=True,
                    extra_scopes=extra_scopes,
                    return_to=return_to,
                )
                return {**started, "via": "ads_bridge_fallback"}
            except internal_bridge.BridgeClientError:
                pass
        return None

    # --- Meta Webhook Signature Verification (Local Vault -> Hub -> LNC Ads Bridge) ---

    def verify_meta_webhook(
        self,
        db_path: Path,
        org: str,
        vault: Vault,
        raw_body: bytes,
        signature_header: str,
        *,
        env_secret: str = "",
    ) -> bool:
        if not signature_header or not signature_header.startswith("sha256="):
            return False

        # 1. Zero-hop local encrypted Vault / env secret check (100% standalone)
        with store.connect_readonly(db_path) as db:
            secret_env = vault.get(db, org, "app", "meta")
        app_secret = (
            secret_env.get("client_secret", "")
            if secret_env and secret_env.get("client_secret")
            else env_secret
        )
        if app_secret:
            expected = (
                "sha256=" + hmac.new(app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
            )
            return hmac.compare_digest(signature_header, expected)

        # 2. LNC-Agent-Hub `/v1/platform/meta/verify-signature`
        if self.cfg.api_key:
            try:
                res = self._request(
                    "POST",
                    "/v1/platform/meta/verify-signature",
                    json_body={
                        "raw_body_b64": base64.b64encode(raw_body).decode("ascii"),
                        "signature_header": signature_header,
                    },
                    timeout=3.0,
                )
                if res.status_code == 200:
                    return bool(res.json().get("valid"))
            except httpx.HTTPError:
                pass

        # 3. Automatic LAN fallback to `lnc-ads` `/api/internal/bridge/meta/verify-signature`
        if self.ads_bridge is not None:
            try:
                res = self.ads_bridge.verify_meta_signature(raw_body, signature_header)
                return bool(res.get("valid"))
            except internal_bridge.BridgeClientError:
                pass

        return False

    # --- Bidirectional Sync with Automatic LNC Ads LAN Bridge Fallback ---

    def sync(self, db_path: Path, org: str, vault: Vault | None) -> dict:
        if vault is None:
            raise AgentHubError("master_key_not_configured", 503)

        hub_status_code: int | None = None
        if self.cfg.api_key:
            try:
                st = self._request("GET", "/v1/platform/status", timeout=4.0)
                hub_status_code = st.status_code
            except httpx.HTTPError as exc:
                self._invalidate_status_cache()
                if self.ads_bridge is not None:
                    return self._sync_via_ads_bridge(db_path, org, reason="hub_unreachable")
                raise AgentHubError("agent_hub_unreachable", 503) from exc

        if hub_status_code == 200:
            return self._sync_via_agent_hub(db_path, org, vault)

        if hub_status_code in (401, 403):
            self._invalidate_status_cache()
            raise AgentHubError("agent_hub_unauthorized", 403)

        # Automatic fallback to LNC Ads LAN Bridge while Hub `/v1/platform/*` returns 404 or awaits API key
        if self.ads_bridge is not None and hub_status_code in (None, 404):
            return self._sync_via_ads_bridge(
                db_path,
                org,
                reason="hub_platform_404" if hub_status_code == 404 else "awaiting_hub_api_key",
            )

        if not self.cfg.api_key:
            raise AgentHubError("agent_hub_api_key_not_configured", 409)
        if hub_status_code == 404:
            self._invalidate_status_cache()
            raise AgentHubError("agent_hub_platform_routes_not_deployed", 503)
        self._invalidate_status_cache()
        raise AgentHubError("agent_hub_unavailable", 502)

    def _sync_via_agent_hub(self, db_path: Path, org: str, vault: Vault) -> dict:
        pushed_shops = 0
        pushed_apps = 0
        pushed_connections = 0
        pulled_shops = 0
        pulled_apps = 0
        pulled_connections = 0

        with store.connect_readonly(db_path) as db:
            local_shops = [str(r["name"]) for r in store.shops(db, org)]
            local_apps = [
                str(r["provider"])
                for r in db.execute(
                    "SELECT provider FROM provider_apps WHERE organization_id=?", (org,)
                ).fetchall()
            ]
            local_conns = [
                int(r["id"])
                for r in db.execute(
                    "SELECT id FROM provider_connections WHERE organization_id=? ORDER BY id",
                    (org,),
                ).fetchall()
            ]

        for sname in local_shops:
            if self.try_push_shop(sname):
                pushed_shops += 1
        for prov in local_apps:
            if self.try_push_app(db_path, org, prov, vault):
                pushed_apps += 1
        for cid in local_conns:
            if self.try_push_connection(db_path, org, cid, vault):
                pushed_connections += 1

        # Pull remote shops -> local
        try:
            r_shops = self._request("GET", "/v1/platform/shops", timeout=4.0)
            if r_shops.status_code == 200:
                for item in r_shops.json().get("shops", []):
                    rname = str(item.get("name") or "").strip()
                    if not rname:
                        continue
                    with store.connect(db_path) as db:
                        db.execute("BEGIN IMMEDIATE")
                        exists = db.execute(
                            "SELECT 1 FROM shops WHERE organization_id=? AND LOWER(name)=LOWER(?)",
                            (org, rname),
                        ).fetchone()
                        if not exists:
                            db.execute(
                                "INSERT INTO shops(organization_id, name) VALUES (?, ?)",
                                (org, rname),
                            )
                            pulled_shops += 1
        except httpx.HTTPError as exc:
            raise AgentHubError("agent_hub_sync_interrupted", 502) from exc

        # Pull remote OAuth apps -> local encrypted Vault
        try:
            r_apps = self._request("GET", "/v1/platform/apps", timeout=4.0)
            if r_apps.status_code == 200:
                apps_map = r_apps.json().get("apps", {})
                for prov, meta in apps_map.items():
                    if prov not in CARE_PROVIDERS or not meta.get("configured"):
                        continue
                    with store.connect_readonly(db_path) as db:
                        local_row = db.execute(
                            "SELECT revision FROM provider_apps WHERE organization_id=? AND provider=?",
                            (org, prov),
                        ).fetchone()
                        local_sec = vault.get(db, org, "app", prov) if local_row else None
                    if local_row and local_sec and local_sec.get("client_secret"):
                        continue
                    cred_res = self._request(
                        "GET", f"/v1/platform/apps/{prov}/credentials", timeout=4.0
                    )
                    if cred_res.status_code != 200:
                        continue
                    cred = cred_res.json()
                    if not cred.get("client_id") or not cred.get("client_secret"):
                        continue
                    rev = int(cred.get("revision") or 1)
                    with store.connect(db_path) as db:
                        db.execute("BEGIN IMMEDIATE")
                        db.execute(
                            """INSERT INTO provider_apps
                               (organization_id, provider, client_id, project_id, webhook_verify_token, revision)
                               VALUES (?, ?, ?, ?, ?, ?)
                               ON CONFLICT(organization_id, provider) DO UPDATE SET
                                client_id=excluded.client_id,
                                project_id=excluded.project_id,
                                webhook_verify_token=CASE
                                  WHEN excluded.webhook_verify_token!='' THEN excluded.webhook_verify_token
                                  ELSE provider_apps.webhook_verify_token
                                END,
                                revision=excluded.revision""",
                            (
                                org,
                                prov,
                                str(cred["client_id"]),
                                str(cred.get("project_id") or ""),
                                str(cred.get("webhook_verify_token") or ""),
                                rev,
                            ),
                        )
                        vault.put(
                            db,
                            org,
                            "app",
                            prov,
                            {"client_secret": str(cred["client_secret"])},
                        )
                        pulled_apps += 1
        except httpx.HTTPError as exc:
            raise AgentHubError("agent_hub_sync_interrupted", 502) from exc

        # Pull remote connections & lease verified tokens into local encrypted Vault
        try:
            r_conns = self._request("GET", "/v1/platform/connections", timeout=5.0)
            if r_conns.status_code == 200:
                for rc in r_conns.json().get("connections", []):
                    hub_id = str(rc.get("hub_connection_id") or "").strip()
                    prov = str(rc.get("provider") or "").strip()
                    label = str(rc.get("label") or "").strip()
                    state = str(rc.get("state") or "pending_review").strip()
                    if not hub_id or prov not in CARE_PROVIDERS or not label:
                        continue
                    if state not in ("not_connected", "pending_review", "verified", "expired"):
                        state = "pending_review"
                    hub_rev = int(rc.get("revision") or 1)

                    with store.connect(db_path) as db:
                        db.execute("BEGIN IMMEDIATE")
                        link_row = db.execute(
                            "SELECT connection_id FROM hub_connection_links WHERE organization_id=? AND hub_connection_id=?",
                            (org, hub_id),
                        ).fetchone()
                        if link_row:
                            local_id = int(link_row["connection_id"])
                            is_new = False
                        else:
                            by_label = db.execute(
                                """SELECT id FROM provider_connections
                                   WHERE organization_id=? AND provider=? AND LOWER(label)=LOWER(?)
                                   ORDER BY id LIMIT 1""",
                                (org, prov, label),
                            ).fetchone()
                            if by_label:
                                local_id = int(by_label["id"])
                                is_new = False
                            else:
                                ins = db.execute(
                                    """INSERT INTO provider_connections(organization_id, provider, label, state)
                                       VALUES (?, ?, ?, ?)""",
                                    (
                                        org,
                                        prov,
                                        label,
                                        "pending_review" if state == "verified" else state,
                                    ),
                                )
                                local_id = int(ins.lastrowid)
                                db.execute(
                                    """INSERT OR IGNORE INTO connection_runtime
                                       (organization_id, connection_id, revision, app_revision)
                                       VALUES (?, ?, 1, 1)""",
                                    (org, local_id),
                                )
                                is_new = True
                            db.execute(
                                """INSERT INTO hub_connection_links
                                   (organization_id, connection_id, hub_connection_id, hub_revision, leased_at)
                                   VALUES (?, ?, ?, ?, 0)
                                   ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                                    hub_connection_id=excluded.hub_connection_id""",
                                (org, local_id, hub_id, hub_rev),
                            )

                        for sname in rc.get("shops", []) or []:
                            srow = db.execute(
                                "SELECT id FROM shops WHERE organization_id=? AND LOWER(name)=LOWER(?)",
                                (org, str(sname).strip()),
                            ).fetchone()
                            if srow:
                                db.execute(
                                    "INSERT OR IGNORE INTO shop_connection_bindings VALUES (?, ?, ?)",
                                    (org, int(srow["id"]), local_id),
                                )

                    if state == "verified":
                        leased = self.ensure_fresh_token(db_path, org, vault, local_id, force=is_new)
                        if leased and is_new:
                            pulled_connections += 1
                    elif is_new:
                        pulled_connections += 1
        except httpx.HTTPError as exc:
            raise AgentHubError("agent_hub_sync_interrupted", 502) from exc

        self.last_sync_at = int(time.time())
        self.last_sync_source = "lnc-agent-hub"
        self.last_warning = None
        self._invalidate_status_cache()

        summary = {
            "ok": True,
            "source": "lnc-agent-hub",
            "pushed_shops": pushed_shops,
            "pushed_apps": pushed_apps,
            "pushed_connections": pushed_connections,
            "pulled_shops": pulled_shops,
            "pulled_apps": pulled_apps,
            "pulled_connections": pulled_connections,
            "pulled_channels": 0,
            "synced_at": self.last_sync_at,
        }
        with store.connect(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            audit.append(db, org, "owner", "hub.vault_synced", "lnc-agent-hub", summary)
        return summary

    def _sync_via_ads_bridge(self, db_path: Path, org: str, *, reason: str) -> dict:
        """Automatic LAN fallback sync from `lnc-ads` (`10.21.4.101:8480/api/internal/bridge/*`)."""
        assert self.ads_bridge is not None
        try:
            remote_shops = self.ads_bridge.list_shops()
            remote_conns = self.ads_bridge.list_connections()
        except internal_bridge.BridgeClientError as exc:
            raise AgentHubError(exc.code, exc.status) from exc

        pushed_shops = 0
        pulled_shops = 0
        pulled_connections = 0
        pulled_channels = 0
        now = int(time.time())
        today = datetime.now(UTC).strftime("%Y-%m-%d")

        # 1. Sync shops bidirectionally
        remote_shop_names = {str(s.get("name") or "").strip().lower() for s in remote_shops}
        with store.connect_readonly(db_path) as db:
            local_shops = [str(r["name"]) for r in store.shops(db, org)]

        for sname in local_shops:
            if sname.lower() not in remote_shop_names:
                try:
                    self.ads_bridge.ensure_shop(sname)
                    pushed_shops += 1
                except internal_bridge.BridgeClientError:
                    pass

        shop_map: dict[str, int] = {}
        with store.connect(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            for item in remote_shops:
                rname = str(item.get("name") or "").strip()
                if not rname:
                    continue
                row = db.execute(
                    "SELECT id, name FROM shops WHERE organization_id=? AND LOWER(name)=LOWER(?)",
                    (org, rname),
                ).fetchone()
                if row:
                    shop_map[rname] = int(row["id"])
                else:
                    cur = db.execute(
                        "INSERT INTO shops(organization_id, name) VALUES (?, ?)", (org, rname)
                    )
                    shop_map[rname] = int(cur.lastrowid)
                    pulled_shops += 1
            for r in store.shops(db, org):
                shop_map[str(r["name"])] = int(r["id"])

        # 2. Upsert care-compatible connections (`meta`, `tiktok`, `youtube`)
        conn_id_map: dict[int, int] = {}
        with store.connect(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            for rc in remote_conns:
                prov = str(rc.get("provider") or "").strip()
                if prov not in CARE_PROVIDERS:
                    continue
                remote_cid = int(rc["id"])
                bridge_key = f"ads_bridge:{remote_cid}"
                label = str(rc.get("label") or f"{prov}-{remote_cid}").strip()
                state = str(rc.get("state") or "verified").strip()
                if state not in ("not_connected", "pending_review", "verified", "expired"):
                    state = "pending_review"

                link_row = db.execute(
                    "SELECT connection_id FROM hub_connection_links WHERE organization_id=? AND hub_connection_id=?",
                    (org, bridge_key),
                ).fetchone()
                if link_row:
                    local_cid = int(link_row["connection_id"])
                    db.execute(
                        "UPDATE provider_connections SET state=?, label=? WHERE organization_id=? AND id=?",
                        (state, label, org, local_cid),
                    )
                else:
                    by_label = db.execute(
                        """SELECT id FROM provider_connections
                           WHERE organization_id=? AND provider=? AND LOWER(label)=LOWER(?)
                           ORDER BY id LIMIT 1""",
                        (org, prov, label),
                    ).fetchone()
                    if by_label:
                        local_cid = int(by_label["id"])
                        db.execute(
                            "UPDATE provider_connections SET state=? WHERE organization_id=? AND id=?",
                            (state, org, local_cid),
                        )
                    else:
                        ins = db.execute(
                            """INSERT INTO provider_connections(organization_id, provider, label, state)
                               VALUES (?, ?, ?, ?)""",
                            (org, prov, label, state),
                        )
                        local_cid = int(ins.lastrowid)
                        pulled_connections += 1
                    db.execute(
                        """INSERT INTO hub_connection_links
                           (organization_id, connection_id, hub_connection_id, hub_revision, leased_at)
                           VALUES (?, ?, ?, 1, ?)
                           ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                            hub_connection_id=excluded.hub_connection_id,
                            leased_at=excluded.leased_at""",
                        (org, local_cid, bridge_key, now),
                    )

                db.execute(
                    """INSERT INTO connection_runtime
                       (organization_id, connection_id, revision, app_revision, expires_at, last_success)
                       VALUES (?, ?, 1, 1, ?, ?)
                       ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                        expires_at=COALESCE(excluded.expires_at, connection_runtime.expires_at),
                        last_success=excluded.last_success""",
                    (org, local_cid, rc.get("expires_at"), now),
                )
                conn_id_map[remote_cid] = local_cid
                for s_item in rc.get("shops") or []:
                    sname = str(s_item.get("name") if isinstance(s_item, dict) else s_item).strip()
                    for k_name, sid in shop_map.items():
                        if k_name.lower() == sname.lower():
                            db.execute(
                                "INSERT OR IGNORE INTO shop_connection_bindings VALUES (?, ?, ?)",
                                (org, sid, local_cid),
                            )

        # 3. Discover & bind shared channels (Facebook Pages, Instagram Professional, TikTok) per shop
        for shop_name, local_shop_id in list(shop_map.items()):
            try:
                ch_resp = self.ads_bridge.list_channels(shop_name)
            except internal_bridge.BridgeClientError:
                continue
            remote_channels = ch_resp.get("channels") or []
            if not remote_channels:
                continue
            with store.connect(db_path) as db:
                db.execute("BEGIN IMMEDIATE")
                for ch in remote_channels:
                    prov = str(ch.get("provider") or "meta").strip()
                    if prov not in CARE_PROVIDERS:
                        continue
                    raw_kind = str(ch.get("kind") or ch.get("channel_type") or "fb_page").strip()
                    kind_map = {
                        "facebook_page": "fb_page",
                        "page": "fb_page",
                        "fb_page": "fb_page",
                        "instagram_business": "ig_account",
                        "instagram": "ig_account",
                        "ig_account": "ig_account",
                        "tiktok_identity": "tt_account",
                        "tiktok": "tt_account",
                        "tt_account": "tt_account",
                    }
                    kind = kind_map.get(raw_kind, "fb_page" if prov == "meta" else "tt_account")
                    ext_id = str(
                        ch.get("external_id")
                        or ch.get("channel_id")
                        or ch.get("page_id")
                        or ch.get("ig_id")
                        or ch.get("id")
                        or ""
                    ).strip()
                    name = str(ch.get("name") or ch.get("username") or ext_id).strip()
                    if not ext_id or not name:
                        continue
                    username = str(ch.get("username") or ch.get("handle") or "").strip()
                    handle = f"@{username.lstrip('@')}" if username else ""
                    remote_conn_id = ch.get("connection_id")
                    local_cid = (
                        conn_id_map.get(int(remote_conn_id))
                        if remote_conn_id is not None and int(remote_conn_id) in conn_id_map
                        else None
                    )
                    adapter = "meta_api" if prov == "meta" else "browser_ingest"
                    followers = int(
                        ch.get("followers_count")
                        or ch.get("fan_count")
                        or ch.get("followers")
                        or 0
                    )

                    existing = db.execute(
                        "SELECT id FROM channels WHERE organization_id=? AND provider=? AND external_id=?",
                        (org, prov, ext_id),
                    ).fetchone()
                    if existing:
                        channel_id = int(existing["id"])
                        db.execute(
                            """UPDATE channels
                               SET connection_id=COALESCE(?, connection_id),
                                   name=?,
                                   handle=CASE WHEN ?!='' THEN ? ELSE handle END,
                                   approved=1,
                                   last_synced_at=?
                               WHERE organization_id=? AND id=?""",
                            (local_cid, name, handle, handle, now, org, channel_id),
                        )
                    else:
                        ins_ch = db.execute(
                            """INSERT INTO channels
                               (organization_id, connection_id, provider, adapter, kind, external_id,
                                name, handle, approved, reply_policy, last_synced_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'draft_only', ?)""",
                            (org, local_cid, prov, adapter, kind, ext_id, name, handle, now),
                        )
                        channel_id = int(ins_ch.lastrowid)
                        pulled_channels += 1

                    db.execute(
                        "INSERT OR IGNORE INTO channel_shop_bindings VALUES (?, ?, ?)",
                        (org, local_shop_id, channel_id),
                    )
                    if local_cid:
                        disc_item = {
                            "external_id": ext_id,
                            "name": name,
                            "handle": handle,
                            "kind": kind,
                            "adapter": adapter,
                            "followers_count": followers,
                        }
                        db.execute(
                            """INSERT OR REPLACE INTO discovered_channels
                               (organization_id, connection_id, external_id, channel_json, connection_revision, discovered_at)
                               VALUES (?, ?, ?, ?, 1, ?)""",
                            (org, local_cid, ext_id, json.dumps(disc_item), now),
                        )
                    db.execute(
                        """INSERT INTO channel_snapshots
                           (organization_id, channel_id, snapshot_date, followers_count, posts_count, captured_at)
                           VALUES (?, ?, ?, ?, 0, ?)
                           ON CONFLICT(organization_id, channel_id, snapshot_date) DO UPDATE SET
                            followers_count=CASE
                              WHEN excluded.followers_count > 0 THEN excluded.followers_count
                              ELSE channel_snapshots.followers_count
                            END""",
                        (org, channel_id, today, followers, now),
                    )

        self.last_sync_at = now
        self.last_sync_source = "lnc-ads-bridge"
        self.last_warning = reason
        self._invalidate_status_cache()

        summary = {
            "ok": True,
            "source": "lnc-ads-bridge",
            "fallback_reason": reason,
            "pushed_shops": pushed_shops,
            "pushed_apps": 0,
            "pushed_connections": 0,
            "pulled_shops": pulled_shops,
            "pulled_apps": 0,
            "pulled_connections": pulled_connections,
            "pulled_channels": pulled_channels,
            "synced_at": now,
        }
        with store.connect(db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            audit.append(db, org, "owner", "hub.bridge_fallback_synced", "lnc-ads", summary)
        return summary

    # --- Universal 3-Way Operator SSO via LNC Agent Hub ---

    def mint_sso_redirect_url(
        self, *, audience: str, next_path: str, subject: str = "owner"
    ) -> str:
        if not self.cfg.api_key:
            raise HTTPException(503, "agent_hub_api_key_not_configured")
        try:
            res = self._request(
                "POST",
                "/v1/platform/sso/mint",
                json_body={
                    "audience": audience,
                    "subject": subject,
                    "next_path": next_path,
                },
                timeout=3.5,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(503, "agent_hub_sso_unavailable") from exc
        if res.status_code != 200:
            raise HTTPException(503, "agent_hub_sso_unavailable")
        data = res.json()
        consume_url = str(data.get("consume_url") or "").strip()
        if consume_url:
            return consume_url
        ticket = str(data.get("ticket") or "").strip()
        if not ticket:
            raise HTTPException(503, "agent_hub_sso_unavailable")
        base = self.cfg.public_url or self.cfg.url
        return f"{base}/v1/platform/sso/consume?{urlencode({'ticket': ticket, 'next': next_path})}"

    def redeem_sso_ticket(self, ticket: str) -> dict:
        if not self.cfg.api_key:
            raise HTTPException(503, "agent_hub_api_key_not_configured")
        try:
            res = self._request(
                "POST",
                "/v1/platform/sso/redeem",
                json_body={
                    "ticket": ticket,
                    "audience": self.cfg.self_id,
                },
                timeout=3.5,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(503, "agent_hub_sso_unavailable") from exc
        if res.status_code != 200:
            raise HTTPException(401, "sso_ticket_expired_or_invalid")
        data = res.json()
        if not data.get("ok") or data.get("audience") != self.cfg.self_id:
            raise HTTPException(401, "sso_ticket_invalid")
        return {
            "iss": str(data.get("issuer") or "lnc-agent-hub"),
            "aud": self.cfg.self_id,
            "sub": str(data.get("subject") or "owner"),
        }
