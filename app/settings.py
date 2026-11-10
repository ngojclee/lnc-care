"""Allowlisted runtime settings; environment overrides are reported explicitly."""
import os
import re
from urllib.parse import urlsplit

SPECS = {
    "public_base_url": "PUBLIC_BASE_URL",
    "allowed_hosts": "ALLOWED_HOSTS",
    "mcp_max_scopes": "CONNECTOR_MAX_SCOPES",
    "archive_retention_days": "ARCHIVE_RETENTION_DAYS",
}
ENV_ALIASES = {
    "public_base_url": ("PUBLIC_BASE_URL",),
    "allowed_hosts": ("ALLOWED_HOSTS",),
    "mcp_max_scopes": ("CONNECTOR_MAX_SCOPES", "LNC_MCP_MAX_SCOPES"),
    "archive_retention_days": ("ARCHIVE_RETENTION_DAYS",),
}
DEFAULTS = {
    "public_base_url": "",
    "allowed_hosts": "localhost,127.0.0.1,10.21.4.101,care-mcp.lengoc.me",
    "mcp_max_scopes": "care:read,care:read:meta,care:read:tiktok,care:read:youtube",
    "archive_retention_days": "180",
}


def env_value(key: str, env=None) -> str:
    source = env if env is not None else os.environ
    for env_name in ENV_ALIASES.get(key, (SPECS.get(key, ""),)):
        val = str(source.get(env_name, "")).strip()
        if val:
            return val
    return ""


def origin(value: str) -> str:
    if not value:
        return ""
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(c.isspace() for c in value)
    ):
        raise ValueError("Expected a bare HTTP(S) origin")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid port") from exc
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def validate(key: str, value) -> str:
    if isinstance(value, (list, tuple)):
        value = ",".join(str(x).strip() for x in value if str(x).strip())
    value = str(value).strip()
    if key == "public_base_url":
        return origin(value)
    if key == "allowed_hosts":
        items = [v.strip().lower() for v in value.split(",") if v.strip()]
        if not items:
            items = ["localhost", "127.0.0.1"]
        if items != ["*"] and any(not re.fullmatch(r"[a-z0-9][a-z0-9.:-]{0,252}", v) for v in items):
            raise ValueError("Expected comma-separated hostnames or IP addresses")
        return ",".join(dict.fromkeys(items))
    if key == "mcp_max_scopes":
        items = [v.strip() for v in value.split(",") if v.strip()]
        if (
            not items
            or not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._*-]{0,63}", v) for v in items)
            or "care:read" not in items
        ):
            raise ValueError("Expected comma-separated scopes including care:read")
        return ",".join(dict.fromkeys(items))
    if key == "archive_retention_days":
        if not value:
            return "180"
        if not value.isdigit() or not 7 <= int(value) <= 3650:
            raise ValueError("Expected retention days between 7 and 3650")
        return str(int(value))
    raise ValueError("Unknown setting")


def inventory(db, org: str, env=None) -> dict:
    stored = {
        r["key"]: r["value"]
        for r in db.execute("SELECT key,value FROM runtime_settings WHERE organization_id=?", (org,))
    }
    out = {}
    for key in SPECS:
        ev = env_value(key, env)
        if ev:
            raw = ev
            src = "environment"
        elif key in stored:
            raw = stored[key]
            src = "database"
        else:
            raw = DEFAULTS[key]
            src = "default"
        out[key] = {"value": raw, "source": src}
    return out


def load_with_sources(db, org: str, env=None) -> dict:
    inv = inventory(db, org, env)
    values = {
        "public_base_url": inv["public_base_url"]["value"],
        "allowed_hosts": [
            h.strip() for h in inv["allowed_hosts"]["value"].split(",") if h.strip()
        ],
        "mcp_max_scopes": [
            s.strip() for s in inv["mcp_max_scopes"]["value"].split(",") if s.strip()
        ],
        "archive_retention_days": int(inv["archive_retention_days"]["value"] or 180),
    }
    sources = {k: v["source"] for k, v in inv.items()}
    return {"values": values, "sources": sources}


def load(db, org: str, env=None) -> dict:
    return load_with_sources(db, org, env)["values"]


def save(db, org: str, values: dict, env=None) -> dict:
    for key, value in values.items():
        if key not in SPECS or env_value(key, env):
            raise ValueError("Unknown or environment-managed setting")
        clean = validate(key, value)
        db.execute(
            """INSERT INTO runtime_settings(organization_id,key,value) VALUES (?,?,?)
               ON CONFLICT(organization_id,key) DO UPDATE SET value=excluded.value""",
            (org, key, clean),
        )
    return load_with_sources(db, org, env)
