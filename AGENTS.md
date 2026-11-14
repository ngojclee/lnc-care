# LNC Care project instructions

Status: LIVE ON PORTAINER `10.21.4.101:8482` & `https://care-mcp.lengoc.me` (2026-11-11, `VERSION 0.6.0.0`, **100% Native Rust Backend (`Axum 0.7` + `Rusqlite 0.32` WAL)**, Phase 1 + Phase 2 Forensic PKZIP/Webhooks/Watchdog + Phase 2b Multi-Account Fleet `VeilBrowser`/`Orbine` + Phase 3 Guarded Provider Writes/Readback + TikTok Business & YouTube Official APIs + Phase 4 `lnm-care` Skill complete, Gitea `apps/lnc-care` + GitHub mirror `ngojclee/lnc-care`, Portainer `portainer-fr4` Stack `#59` `lnc-care` on endpoint `paris3` `#4`, FR Caddy Fleet + FR/VN Unbound DNS live, full-width `lnc-internal-app-blueprint` LN UI Engine lite + `#keys` API/Management key contract + 32 `care__*` MCP tools, `23/23` `cargo test` passing). Read `.docs/handoff.md` first, then `.docs/plan.md`, `.docs/multi-account-antidetect-plan.md`, `.docs/task.md`, and `.docs/reports/release-v0.6.0.0.md`.

Purpose: care console for OWNED social channels (Facebook Pages, Instagram
professional accounts, later TikTok business accounts and YouTube): ingest
posts and comments through official APIs, keep daily metric snapshots and a
media/screenshot archive per post, triage comments in an inbox, and reply /
hide through guarded, audited writes. Publishing stays in Postiz
(`lnc-postiz`); external competitor tracking stays in SocialTrak.

Conventions (same family as `lnc-ads`):

- `lnc-internal-app-blueprint` Shape 0 (Native Rust): Rust `Axum 0.7` + `Rusqlite 0.32` (WAL) + vanilla
  `public/` UI at `/admin` with hash-slug pages, `/login.html`,
  `/api/auth/status`, `/health`, `/api/admin/*`. Single `/app/lnc-care` binary (`serve`, `worker`, `healthcheck`, `rotate-vault`). English-only operator UI.
- `business-mcp-connector`: one app-owned `/mcp` with Hub v3/v4 HMAC
  delegation, nonce replay guard, per-tool scopes, deny unknown tools.
  Audience `lnc-care`, Hub namespace `care__*`.
- Encrypted vault keyed by `LNC_MASTER_KEY`; provider tokens never in MCP
  args, plan, Git, logs or chat. Reference implementation of vault,
  delegation, OAuth and provider isolation: `D:\Python\projects\lnc-ads\app\`
  (copy patterns, do not import across repos).
- Version `x.y.z.k` in `VERSION`; bump with each commit; RTK for long output.
- Reads and ingestion first. Replies/hides are guarded writes: scope +
  idempotency key + audit + per-channel reply policy (draft-for-approval by
  default). No auto-reply without an explicit, audited rule the owner enabled.
- Webhook endpoints (`/webhooks/meta`) are public but verify Meta's
  `X-Hub-Signature-256` with the app secret and the subscription verify
  token; reject otherwise. Long-running screenshot/archive work runs in a
  separate worker service, never inside the request path.
- Deployment target proposal (verify at execution): Docker host
  `10.21.4.101`, port `8482`, domain `care-mcp.lengoc.me` via NPM FR. The
  webhook path must be reachable from Meta (public), while `/admin` and
  `/mcp` keep the internal access list. Production requires owner approval
  per `release-portainer-app`.
- Skill ownership: user-facing skill is `lnm-care`; repo/app/audience stay
  `lnc-care`.

Blueprint v2.0 admin/auth contract (0.7.0.0):

- Sign-in: Keycloak OIDC (`/api/auth/oidc/login` -> `/callback`, Authorization Code + PKCE S256, `OIDC_ALLOWED_USERS` allowlist fail-closed) plus break-glass `MANAGEMENT_KEY` (Argon2id, 8 failures / 5 min / IP -> 429). Legacy PBKDF2 runtime keys are upgraded to Argon2id on first successful sign-in.
- Sessions are server-side (`management_sessions`): cookie `lnc_care_sess` `HttpOnly; SameSite=Lax; Secure(auto)`, `SESSION_IDLE_TTL_SECONDS` (12h) / `SESSION_MAX_TTL_SECONDS` (7d) and a durable `session_epoch` (rotate management key / `POST /api/mgmt/revoke-sessions` kills every cookie). `POST /api/auth/logout` is local-only (never calls the IdP).
- CSRF: per-session `X-CSRF-Token` held in JS memory only + same-origin `Origin`/`Referer`/`Sec-Fetch-Site` check; `X-Forwarded-Host` is never trusted. Query-string secrets (`?token=`) are rejected with 400. `MANAGEMENT_KEY` is not an API bearer.
- Crypto: vault stays AES-256-GCM envelope under `LNC_MASTER_KEY` (+ `LNC_PREVIOUS_MASTER_KEY` decrypt fallback, zero data loss); HKDF-SHA256 subkeys (`csrf`, `oidc-tx`, `api-key-pepper`). New/rotated API keys store `hmac1:` HMAC-SHA256 digests; pre-upgrade SHA-256 rows keep authenticating; Copy needs the vault envelope (legacy rows: `Rotate to enable Copy`).
- Admin nav: domain pages -> `#api-keys` -> `#mcp-connectors` -> `#settings` (LLM Providers is hidden: lnc-care has no AI consumer). Aliases `#keys`/`#connector` redirect. Every credential row exposes Copy · Rotate · Revoke · Remove (`POST .../copy` is audited, rate limited 15 / 5 min / IP, `no-store`).
- Inbound `/mcp` pairing is managed under `/api/mcp-connectors/inbound-mcp/{copy,rotate,revoke,test}` and `DELETE`; revoking returns 403 `mcp_connector_revoked`.
