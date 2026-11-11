"""Unified outbound MCP Gateway client (`lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)`)."""
from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ALLOWED_CROSS_APP_PREFIXES = ("ads__",)
DEFAULT_MCP_PROTOCOL_VERSION = "2025-03-26"

try:
    CLIENT_VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text(encoding="utf-8").strip() or "0.3.0.2"
except OSError:
    CLIENT_VERSION = "0.3.0.2"


class McpGatewayError(Exception):
    def __init__(self, code: str, status: int = 502):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class McpGatewayConfig:
    gateway_url: str
    api_key: str


def mcp_gateway_config(environ=os.environ) -> McpGatewayConfig | None:
    raw_url = environ.get("LNC_MCP_GATEWAY_URL", "").strip()
    hub_url = environ.get("LNC_AGENT_HUB_URL", "").strip().rstrip("/")
    gateway_url = raw_url or (f"{hub_url}/mcp" if hub_url else "")
    api_key = environ.get("LNC_AGENT_HUB_API_KEY", "").strip()
    if not gateway_url:
        return None
    parsed = urlsplit(gateway_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise RuntimeError("LNC_MCP_GATEWAY_URL must be a valid HTTP(S) URL")
    return McpGatewayConfig(gateway_url=gateway_url, api_key=api_key)


class McpGatewayClient:
    """Calls sibling MCP tools (`ads__*`) strictly through `LNC-Agent-Hub (/mcp)` with stateful `Mcp-Session-Id` caching."""

    def __init__(self, cfg: McpGatewayConfig, *, transport=None):
        self.cfg = cfg
        self._client = httpx.Client(timeout=12.0, transport=transport)
        self._lock = threading.Lock()
        self._session_id: str | None = None
        self._initialized: bool = False
        self._protocol_version: str = DEFAULT_MCP_PROTOCOL_VERSION

    def status_summary(self) -> dict:
        return {
            "configured": bool(self.cfg.gateway_url),
            "has_api_key": bool(self.cfg.api_key),
            "has_session": bool(self._session_id),
            "protocol_version": self._protocol_version,
            "gateway_url": self.cfg.gateway_url,
            "route": "lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)",
            "allowed_prefixes": list(ALLOWED_CROSS_APP_PREFIXES),
        }

    def reset_session(self) -> None:
        with self._lock:
            self._session_id = None
            self._initialized = False

    def _base_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.cfg.api_key}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "X-Request-Id": f"req_{secrets.token_hex(12)}",
        }

    @staticmethod
    def _decode_rpc_body(res: httpx.Response, *, expected_id: int | None = None) -> dict:
        content_type = (res.headers.get("content-type") or "").lower()
        body_text = res.text.strip()
        if "text/event-stream" in content_type:
            data_lines = [
                line[5:].strip()
                for line in body_text.splitlines()
                if line.startswith("data:") and line[5:].strip()
            ]
            if not data_lines:
                raise McpGatewayError("mcp_gateway_empty_stream", 502)
            parsed_events = []
            for raw_line in data_lines:
                try:
                    obj = json.loads(raw_line)
                    if isinstance(obj, dict):
                        parsed_events.append(obj)
                except ValueError:
                    continue
            if not parsed_events:
                raise McpGatewayError("mcp_gateway_invalid_stream_json", 502)
            rpc_data = next(
                (ev for ev in reversed(parsed_events) if expected_id is not None and ev.get("id") == expected_id),
                parsed_events[-1],
            )
        else:
            try:
                rpc_data = res.json() if res.content else {}
            except ValueError as exc:
                raise McpGatewayError("mcp_gateway_invalid_json", 502) from exc

        if "error" in rpc_data:
            err = rpc_data["error"]
            msg = err.get("message", "mcp_gateway_rpc_error") if isinstance(err, dict) else str(err)
            raise McpGatewayError(str(msg), 502)
        result = rpc_data.get("result")
        return result if isinstance(result, dict) else {}

    def _ensure_session(
        self,
        *,
        force: bool = False,
        stale_session_id: str | None = None,
    ) -> tuple[str | None, str]:
        with self._lock:
            if self._initialized and not force:
                return self._session_id, self._protocol_version
            if (
                force
                and stale_session_id is not None
                and self._initialized
                and self._session_id
                and self._session_id != stale_session_id
            ):
                return self._session_id, self._protocol_version

            self._initialized = False
            self._session_id = None

            init_id = secrets.randbelow(900_000) + 100_000
            init_payload = {
                "jsonrpc": "2.0",
                "id": init_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": DEFAULT_MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "lnc-care",
                        "version": CLIENT_VERSION,
                    },
                },
            }
            try:
                init_res = self._client.post(
                    self.cfg.gateway_url,
                    json=init_payload,
                    headers=self._base_headers(),
                )
            except httpx.HTTPError as exc:
                raise McpGatewayError("mcp_gateway_unreachable", 503) from exc

            if init_res.status_code in (401, 403):
                raise McpGatewayError("mcp_gateway_unauthorized", init_res.status_code)
            if init_res.status_code >= 400:
                raise McpGatewayError(f"mcp_gateway_http_{init_res.status_code}", 502)

            init_result = self._decode_rpc_body(init_res, expected_id=init_id)
            sid = (init_res.headers.get("mcp-session-id") or "").strip() or None
            negotiated_ver = (
                str(init_result.get("protocolVersion") or DEFAULT_MCP_PROTOCOL_VERSION).strip()
                or DEFAULT_MCP_PROTOCOL_VERSION
            )

            notify_headers = self._base_headers()
            notify_headers["MCP-Protocol-Version"] = negotiated_ver
            if sid:
                notify_headers["Mcp-Session-Id"] = sid
            notify_payload = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
            try:
                notify_res = self._client.post(
                    self.cfg.gateway_url,
                    json=notify_payload,
                    headers=notify_headers,
                )
            except httpx.HTTPError as exc:
                raise McpGatewayError("mcp_gateway_unreachable", 503) from exc

            if notify_res.status_code in (401, 403):
                raise McpGatewayError("mcp_gateway_unauthorized", notify_res.status_code)
            if notify_res.status_code >= 400:
                raise McpGatewayError(f"mcp_gateway_http_{notify_res.status_code}", 502)

            refreshed_sid = (notify_res.headers.get("mcp-session-id") or "").strip()
            if refreshed_sid:
                sid = refreshed_sid

            self._session_id = sid
            self._protocol_version = negotiated_ver
            self._initialized = True
            return sid, negotiated_ver

    def _rpc(self, method: str, params: dict) -> dict:
        if not self.cfg.api_key:
            raise McpGatewayError("mcp_gateway_api_key_not_configured", 409)

        sid, proto_ver = self._ensure_session()
        for attempt in range(2):
            req_id = secrets.randbelow(900_000) + 100_000
            headers = self._base_headers()
            headers["MCP-Protocol-Version"] = proto_ver
            if sid:
                headers["Mcp-Session-Id"] = sid
            payload = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params,
            }
            try:
                res = self._client.post(self.cfg.gateway_url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                raise McpGatewayError("mcp_gateway_unreachable", 503) from exc

            if res.status_code in (401, 403):
                raise McpGatewayError("mcp_gateway_unauthorized", res.status_code)

            if res.status_code in (400, 404) and attempt == 0:
                sid, proto_ver = self._ensure_session(force=True, stale_session_id=sid)
                continue

            if res.status_code >= 400:
                raise McpGatewayError(f"mcp_gateway_http_{res.status_code}", 502)

            refreshed_sid = (res.headers.get("mcp-session-id") or "").strip()
            if refreshed_sid and refreshed_sid != sid:
                with self._lock:
                    self._session_id = refreshed_sid

            return self._decode_rpc_body(res, expected_id=req_id)

        raise McpGatewayError("mcp_gateway_session_retry_exhausted", 502)

    def list_tools(self, *, prefix: str = "ads__") -> list[dict]:
        res = self._rpc("tools/list", {})
        tools = res.get("tools") or []
        return [t for t in tools if str(t.get("name", "")).startswith(prefix)]

    def call_tool(self, tool_name: str, arguments: dict | None = None) -> dict:
        clean_name = tool_name.strip()
        if not any(clean_name.startswith(p) for p in ALLOWED_CROSS_APP_PREFIXES):
            raise McpGatewayError("cross_app_tool_not_allowed", 403)
        res = self._rpc("tools/call", {"name": clean_name, "arguments": arguments or {}})
        is_err = bool(res.get("isError"))
        contents = res.get("content") or []
        parsed_items = []
        for item in contents:
            if item.get("type") == "text":
                txt = item.get("text", "")
                try:
                    parsed_items.append(json.loads(txt))
                except Exception:
                    parsed_items.append(txt)
            else:
                parsed_items.append(item)
        if is_err:
            detail = parsed_items[0] if parsed_items else "mcp_tool_execution_error"
            raise McpGatewayError(str(detail), 422)
        return {
            "ok": True,
            "gateway_url": self.cfg.gateway_url,
            "tool": clean_name,
            "data": parsed_items[0] if len(parsed_items) == 1 else parsed_items,
        }
