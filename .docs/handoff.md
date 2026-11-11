# Handoff — LNC Care (`v0.4.0.0`)

Updated: 2026-11-11.
Status: **LIVE** on `http://10.21.4.101:8482` and `https://care-mcp.lengoc.me` (`VERSION 0.4.0.0` — **100% Native Rust Backend `Axum 0.7` + `Rusqlite 0.32` WAL**, legacy Python removed, Portainer `portainer-fr4` Stack `#59` `lnc-care` on endpoint `paris3` `#4`, Gitea `apps/lnc-care` + GitHub mirror `ngojclee/lnc-care`, FR Caddy Fleet + FR/VN Unbound DNS live, full-width `lnc-internal-app-blueprint` UI + `#keys` API/Management key contract, 26 `care__*` tools live on Business MCP Hub + LNC-Agent-Hub, `20/20` `cargo test` passing).

## Rust Backend Architecture (`src/*.rs` — 1:1 Drop-In Replacement)

1. **Single Native Binary (`src/main.rs` + `src/lib.rs`)**:
   - Subcommands: `lnc-care serve` (Axum HTTP server on `:8000`), `lnc-care worker` (5s background job loop), `lnc-care healthcheck` (container probe), and `lnc-care rotate-vault` (online AES-256-GCM master key rotation).
   - Multi-stage `Dockerfile`: `rust:1-slim-bookworm` (`cargo build --release --locked --bin lnc-care && strip`) -> `debian:bookworm-slim` running as non-root `10001:10001` with `read_only: true` and `cap_drop: [ALL]`.
   - Zero-migration SQLite WAL compatibility (`src/store.rs`, `src/vault.rs`, `src/audit.rs`): reads and writes the exact existing `/data/care.db` (`AES-256-GCM` `secret_envelopes` v1 with AAD `["lnc-care-v1", org, kind, subject]`, PBKDF2-HMAC-SHA256 `200,000`-round `__mgmt_state`, and canonical ASCII SHA-256 `audit_events` hash chain).

2. **UI & Blueprint Architecture (`public/{index.html, login.html, style.css, app.js}`, `src/routes.rs`)**:
   - Full-width LN UI Engine lite shell (`:root, [data-theme="light"]` and `[data-theme="dark"]` rose-terracotta palette `#F2CEC2` / `#5E2419`), pixel-aligned `56px` `.side-brand` + `.topbar` divider, 12 hash-slug pages (`overview`, `inbox`, `conversations`, `posts`, `evidence`, `fleet`, `channels`, `rules`, `connector`, `audit`, `keys`, `settings`), exact 3-row `.side-foot`, `lite-select` popups, and 100% English operator UI copy.
   - High-DPI `lnc-icon` assets served at `/icon.svg`, `/icon.png` (`1024x1024`), `/favicon.ico` (`16..256`), and mirrored in `docs/icon.{svg,png,ico}`.
   - Service API keys (`care_*` SHA-256 hashes + Vault copy envelopes + cookie-free `Bearer` on `GET /api/status`), bootstrap-to-runtime PBKDF2 management key rotation (`POST /api/mgmt/rotate` with fail-closed corruption protection), and `env_or_cfg` Hub pairing secrets.

3. **Ecosystem Alignment (`src/agent_hub.rs`, `src/internal_bridge.rs`, `src/mcp_server.rs`, `src/mcp_gateway.rs`)**:
   - **Shared Platform Vault + 900s Encrypted Local Lease Cache**: syncs shops, OAuth app credentials, and connections from `LNC-Agent-Hub` (`http://10.21.4.101:8380/v1/platform/*`), caching leased tokens inside local `secret_envelopes` (`TTL = 900s`) for 100% standalone survival, with automatic LAN bridge fallback to `lnc-ads` (`http://10.21.4.101:8480/api/internal/bridge/*`).
   - **Unified MCP Routing**: inbound `/mcp` and `/mcp/` (zero-redirect) expose all **26 `care__*` tools** (`audience = lnc-care`) behind `Bearer LNC_CONNECTOR_TOKEN` + Business MCP Hub v3/v4 HMAC headers (`x-mcp-hub-client-*` or `X-LNC-Delegation`) + SQLite `delegation_nonces` replay guard; outbound `McpGatewayClient` routes `ads__*` lookups via `http://10.21.4.101:8380/mcp` with stateful `Mcp-Session-Id` caching and 1x `400`/`404` auto re-initialization.
   - **3-Way Universal SSO & 3-Tier Meta Webhook Verification**: `/api/auth/sso/{redirect,consume}` (`lnc_sso_*` + HMAC peer tickets) and `/webhooks/meta` (`X-Hub-Signature-256` across local Vault -> Agent Hub -> Ads LAN bridge).

## Key Files to Read First
1. `AGENTS.md`
2. `.docs/plan.md` & `.docs/multi-account-antidetect-plan.md`
3. `.docs/task.md`
4. `src/routes.rs`, `src/agent_hub.rs`, `src/internal_bridge.rs`, `src/mcp_gateway.rs`, `src/mcp_server.rs`, `tests/contract_suite.rs`
