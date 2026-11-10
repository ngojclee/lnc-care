"""Unified outbound MCP Gateway client (`lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)`)."""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

ALLOWED_CROSS_APP_PREFIXES = ("ads__",)


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
    """Calls sibling MCP tools (`ads__*`) strictly through `LNC-Agent-Hub (/mcp)`."""

    def __init__(self, cfg: McpGatewayConfig, *, transport=None):
        self.cfg = cfg
        self._client = httpx.Client(timeout=12.0, transport=transport)

    def status_summary(self) -> dict:
        return {
            "configured": bool(self.cfg.gateway_url),
            "has_api_key": bool(self.cfg.api_key),
            "gateway_url": self.cfg.gateway_url,
            "route": "lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)",
            "allowed_prefixes": list(ALLOWED_CROSS_APP_PREFIXES),
        }

    def _rpc(self, method: str, params: dict) -> dict:
        if not self.cfg.api_key:
            raise McpGatewayError("mcp_gateway_api_key_not_configured", 409)
        headers = {
            "Authorization": f"Bearer {self.cfg.api_key}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "X-Request-Id": f"req_{secrets.token_hex(12)}",
        }
        payload = {
            "jsonrpc": "2.0",
            "id": secrets.randbelow(900_000) + 100_000,
            "method": method,
            "params": params,
        }
        try:
            res = self._client.post(self.cfg.gateway_url, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise McpGatewayError("mcp_gateway_unreachable", 503) from exc

        if res.status_code in (401, 403):
            raise McpGatewayError("mcp_gateway_unauthorized", res.status_code)
        if res.status_code >= 400:
            raise McpGatewayError(f"mcp_gateway_http_{res.status_code}", 502)

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
            rpc_data = json.loads(data_lines[-1])
        else:
            rpc_data = res.json() if res.content else {}

        if "error" in rpc_data:
            msg = rpc_data["error"].get("message", "mcp_gateway_rpc_error")
            raise McpGatewayError(str(msg), 502)
        return rpc_data.get("result") or {}

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
