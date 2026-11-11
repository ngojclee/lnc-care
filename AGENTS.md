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
