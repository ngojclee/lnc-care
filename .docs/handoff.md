# Handoff — LNC Care (`v0.3.0.3`)

Updated: 2026-11-11.
Status: **LIVE** on `http://10.21.4.101:8482` and `https://care-mcp.lengoc.me` (Portainer `portainer-fr4` Stack `#59` `lnc-care` on endpoint `paris3` `#4`, Gitea `apps/lnc-care` + GitHub mirror `ngojclee/lnc-care`, FR Caddy Fleet + FR/VN Unbound DNS live, full-width `lnc-internal-app-blueprint` UI + `#keys` API/Management key contract, 26 `care__*` tools live on Business MCP Hub + LNC-Agent-Hub, `21/21` `pytest` passing).

## UI & Blueprint Architecture (`lnc-internal-app-blueprint` Full Standard)

1. **LN UI Engine lite Shell (`app/public/{index.html, login.html, style.css, app.js}`)**:
   - Dual light/dark token contract (`:root, [data-theme="light"]` and `[data-theme="dark"]`) derived from `lnc-care`'s paper-sketch rose-terracotta icon (`#F2CEC2` / `#5E2419`), guarded `<head>` theme script, and autohide 4px scrollbars.
   - Pixel-aligned `56px` `.side-brand` + `.topbar` divider, 12 hash-slug pages (`overview`, `inbox`, `conversations`, `posts`, `evidence`, `fleet`, `channels`, `rules`, `connector`, `audit`, `keys`, `settings`), exact 3-row `.side-foot` (`#app-build` -> `#theme-toggle` -> `#signout`), `lite-select` rounded popups on every `<select>`, toasts, confirmation modals, copy chips, and 100% English operator UI copy.
   - High-DPI `lnc-icon` assets served at `/icon.svg`, `/icon.png` (`1024x1024`), `/favicon.ico` (`16..256`), and mirrored in `docs/icon.{svg,png,ico}`.
2. **The API Page (`#keys`) & `env_or_cfg` Pairing (`app/main.py`, `app/store.py`, `app/mcp_server.py`)**:
   - Service API keys (`GET|POST /api/keys`, `POST /api/keys/{id}/copy`, `PATCH /api/keys/{id}`, `POST /api/keys/{id}/toggle`, `POST /api/keys/{id}/revoke`, `DELETE /api/keys/{id}`) stored as SHA-256 hashes in `api_keys` with Vault-encrypted copy envelopes and cookie-free `Bearer` authentication on `GET /api/status`.
   - Bootstrap-to-runtime management key ownership (`CARE_ADMIN_BOOTSTRAP_KEY` + PBKDF2 `__mgmt_state` + `POST /api/mgmt/rotate` with fail-closed corruption protection and `Env managed` lock when `MANAGEMENT_KEY` is set).
   - Write-only Hub pairing secrets (`connector_bearer`, `delegation_secret`) persisted in Vault via `POST /api/settings` when not locked by environment.

## Ecosystem Architecture (`LNC-Agent-Hub + Business MCP Hub + LNC Ads v1.2.0`)

1. **Shared Platform Vault + 100% Standalone Survival (`app/agent_hub.py`)**:
   - Primary control plane: `LNC_AGENT_HUB_URL=http://10.21.4.101:8380` (`LNC_AGENT_HUB_API_KEY`, principal `svc:lnc-care`).
   - **Login Anywhere, Use Everywhere**: shops, OAuth app credentials, and connections created in `LNC-Agent-Hub`, `LNC Ads`, or `LNC Care` sync bidirectionally via `/v1/platform/*`.
   - **Encrypted Local Lease Cache (`TTL = 900s`)**: tokens leased from `POST /v1/platform/connections/:id/lease` are encrypted inside `lnc-care`'s own SQLite `Vault` (`secret_envelopes`) using `LNC_MASTER_KEY`, ensuring 100% standalone operation if `lnc-ads` is offline or `LNC-Agent-Hub` restarts.
   - **Automatic LAN Bridge Fallback (`app/internal_bridge.py`)**: while `LNC-Agent-Hub` `/v1/platform/*` returns `404`, `lnc-care` automatically falls back to `lnc-ads` (`http://10.21.4.101:8480/api/internal/bridge/*`, signed with `LNC_INTERNAL_BRIDGE_SECRET`) for shop/channel sync, OAuth start, Graph API calls, and Meta webhook signature verification.
   - Admin endpoints: `GET /api/admin/hub/status`, `POST /api/admin/hub/sync`, `POST /api/admin/oauth/shared/start`.

2. **Unified MCP Routing (`app/mcp_server.py` + `app/mcp_gateway.py`)**:
   - Inbound `/mcp` (and `/mcp/`) exposes **26 `care__*` tools** (`audience = lnc-care`) behind `Bearer LNC_CONNECTOR_TOKEN` + Business MCP Hub v3/v4 HMAC headers (`x-mcp-hub-client-*` or `X-LNC-Delegation`) with single-use SQLite nonce replay protection.
   - Outbound cross-app `ads__*` tool calls (`care__ads_context_lookup` / `POST /api/admin/mcp-gateway/call`) route strictly through `LNC_MCP_GATEWAY_URL=http://10.21.4.101:8380/mcp` (`LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)`) with automatic MCP Streamable HTTP session handshake (`initialize` + `notifications/initialized`), thread-safe `Mcp-Session-Id` caching, and 1x automatic re-initialization on HTTP `400`/`404` session expiry.

3. **3-Way Universal Operator SSO & Meta Webhooks (`app/main.py`)**:
   - `GET /api/auth/sso/redirect?peer=lnc-agent-hub|lnc-ads` and `GET /api/auth/sso/consume` redeem both `lnc_sso_*` tickets (`LNC-Agent-Hub`) and single-use HMAC peer tickets (`lnc-ads`), paired with English topbar buttons `Open Agent Hub ↗` and `Open LNC Ads ↗`.
   - `POST /webhooks/meta` verifies `X-Hub-Signature-256` across 3 tiers: local encrypted `Vault` -> `LNC-Agent-Hub` `/v1/platform/meta/verify-signature` -> `lnc-ads` `/api/internal/bridge/meta/verify-signature`.

## Key Files to Read First
1. `AGENTS.md`
2. `.docs/plan.md` & `.docs/multi-account-antidetect-plan.md`
3. `.docs/task.md`
4. `app/agent_hub.py`, `app/internal_bridge.py`, `app/mcp_gateway.py`, `app/mcp_server.py`, `app/main.py`
