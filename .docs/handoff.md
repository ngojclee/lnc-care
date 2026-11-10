# Handoff — LNC Care (`v0.2.0.0`)

Updated: 2026-11-10.
Status: **LIVE** on `http://10.21.4.101:8482` and `https://care-mcp.lengoc.me` (Portainer `portainer-fr4` Stack `#59` `lnc-care` on endpoint `paris3` `#4`, Gitea `apps/lnc-care` + GitHub mirror `ngojclee/lnc-care`, FR Caddy Fleet + FR/VN Unbound DNS live, `15/15` `pytest` passing).

## Ecosystem Architecture (`LNC-Agent-Hub + Business MCP Hub + LNC Ads v1.2.0`)

1. **Shared Platform Vault + 100% Standalone Survival (`app/agent_hub.py`)**:
   - Primary control plane: `LNC_AGENT_HUB_URL=http://10.21.4.101:8380` (`LNC_AGENT_HUB_API_KEY`, principal `svc:lnc-care`).
   - **Login Anywhere, Use Everywhere**: shops, OAuth app credentials, and connections created in `LNC-Agent-Hub`, `LNC Ads`, or `LNC Care` sync bidirectionally via `/v1/platform/*`.
   - **Encrypted Local Lease Cache (`TTL = 900s`)**: tokens leased from `POST /v1/platform/connections/:id/lease` are encrypted inside `lnc-care`'s own SQLite `Vault` (`secret_envelopes`) using `LNC_MASTER_KEY`, ensuring 100% standalone operation if `lnc-ads` is offline or `LNC-Agent-Hub` restarts.
   - **Automatic LAN Bridge Fallback (`app/internal_bridge.py`)**: while `LNC-Agent-Hub` `/v1/platform/*` returns `404`, `lnc-care` automatically falls back to `lnc-ads` (`http://10.21.4.101:8480/api/internal/bridge/*`, signed with `LNC_INTERNAL_BRIDGE_SECRET`) for shop/channel sync, OAuth start, Graph API calls, and Meta webhook signature verification.
   - Admin endpoints: `GET /api/admin/hub/status`, `POST /api/admin/hub/sync`, `POST /api/admin/oauth/shared/start`.

2. **Unified MCP Routing (`app/mcp_server.py` + `app/mcp_gateway.py`)**:
   - Inbound `/mcp` (and `/mcp/`) exposes **26 `care__*` tools** (`audience = lnc-care`) behind `Bearer LNC_CONNECTOR_TOKEN` + Business MCP Hub v3/v4 HMAC headers (`x-mcp-hub-client-*` or `X-LNC-Delegation`) with single-use SQLite nonce replay protection.
   - Outbound cross-app `ads__*` tool calls (`care__ads_context_lookup` / `POST /api/admin/mcp-gateway/call`) route strictly through `LNC_MCP_GATEWAY_URL=http://10.21.4.101:8380/mcp` (`LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)`).

3. **3-Way Universal Operator SSO & Meta Webhooks (`app/main.py`)**:
   - `GET /api/auth/sso/redirect?peer=lnc-agent-hub|lnc-ads` and `GET /api/auth/sso/consume` redeem both `lnc_sso_*` tickets (`LNC-Agent-Hub`) and single-use HMAC peer tickets (`lnc-ads`), paired with English topbar buttons `Open Agent Hub ↗` and `Open LNC Ads ↗`.
   - `POST /webhooks/meta` verifies `X-Hub-Signature-256` across 3 tiers: local encrypted `Vault` -> `LNC-Agent-Hub` `/v1/platform/meta/verify-signature` -> `lnc-ads` `/api/internal/bridge/meta/verify-signature`.

## Key Files to Read First
1. `AGENTS.md`
2. `.docs/plan.md` & `.docs/multi-account-antidetect-plan.md`
3. `.docs/task.md`
4. `app/agent_hub.py`, `app/internal_bridge.py`, `app/mcp_gateway.py`, `app/mcp_server.py`, `app/main.py`
