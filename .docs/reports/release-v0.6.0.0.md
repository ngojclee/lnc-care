# Release Report — LNC Care `v0.6.0.0`

- **Date**: 2026-11-11
- **Service / Audience**: `lnc-care` (Hub namespace `care__*`, 32 MCP tools)
- **Runtime**: 100% Native Rust (`Axum 0.7` + `Rusqlite 0.32` WAL, single `/app/lnc-care` binary on `debian:bookworm-slim`)
- **Deployment Target**: Portainer `portainer-fr4` (`10.21.4.101:9443`), Endpoint `paris3` (`#4`), GitOps Stack `#59` (`lnc-care`)
- **Endpoints**:
  - LAN: `http://10.21.4.101:8482`
  - Public / Internal HTTPS (FR Caddy Fleet + FR/VN Unbound DNS): `https://care-mcp.lengoc.me`
  - Public Webhook Endpoint: `https://care-mcp.lengoc.me/webhooks/meta`
  - Unified MCP Route: `LNC-Agent-Hub (:8380/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-care (/mcp)`

---

## 1. Milestone Summary (`Phase 1` → `Phase 4` Complete)

| Phase | Scope | Verification Evidence |
|---|---|---|
| **Phase 1** | Meta OAuth & discovery, bounded posts/comments/insights poller, 12-label AI Consultation Rubric + prompt-injection shield + `[✓]/[✕]` human calibration, split-pane Inbox UI, AES-256-GCM Vault, SHA-256 hash-chained audit log | Covered by Rust integration contract suite |
| **Ecosystem & Blueprint** | `LNC-Agent-Hub` `/v1/platform/*` Vault sync + `900s` encrypted local SQLite cache + `lnc-ads` LAN Bridge fallback, 3-way Universal SSO, stateful `Mcp-Session-Id` gateway client, full-width LN UI Engine lite + `#keys` management/API key contract | Live synced with `LNC-Agent-Hub` (`:8380`) & `Business MCP Hub` (`:8790`) |
| **Rust 1:1 Rewrite (`v0.4.0.0`)** | Replaced legacy Python/FastAPI runtime with native Rust (`src/*.rs`), 100% wire-compatible with live `/data/care.db` | Zero-downtime migration on Stack `#59` |
| **Phase 2 (`v0.5.0.0`)** | Realtime Meta webhook subscription & inline materialization, worker media/HTML/screenshot archiving + `archive_retention_days` pruning, 5-layer Forensic Evidence Vault deterministic IEEE CRC-32 PKZIP bundle + SHA-256 custody check + `+6h/+24h/+72h` alive/edited/deleted watchdog | `test_phase2_webhook_materialization_archive_pruning_and_forensic_zip_watchdog` |
| **Phase 2b (`v0.5.0.0`)** | Multi-account `VeilBrowser` & `Orbine` mobile fleet adapters, atomic `BEGIN IMMEDIATE` concurrency leases (`MAX_CONCURRENT_BROWSER_SESSIONS`), pre-flight IP/ASN/checkpoint gate, circuit breaker + Cygnus Telegram alert (`Cygnus_Assitance_Bot` topic `7410`), daily UTC budgets, and Consultation Playbooks | `test_phase2b_fleet_leases_preflight_circuit_breaker_telegram_budgets_and_playbooks` |
| **Phase 3 & 4 (`v0.6.0.0`)** | Guarded external provider writes (`comment_reply`, `comment_hide_set`, `comment_private_reply`, `message_reply`) with GET readback verification, `draft_only` -> `approved` -> `sent` workflow, per-provider write gates (`PROVIDER_WRITES_{META,TIKTOK,YOUTUBE}_ENABLED`), IG top-level/hidden/7-day DM guards, TikTok Business v1.3 & YouTube Data API v3 official discovery + polling, and shared `lnm-care` skill activation | `23/23` `cargo test` (`1` unit + `22` integration tests) passing |

---

## 2. Security & Safety Controls

1. **Fail-Closed Write Gates**:
   - Production defaults to `PROVIDER_WRITES_ENABLED=false` (draft-for-approval mode). Each provider can be independently toggled via `PROVIDER_WRITES_META_ENABLED`, `PROVIDER_WRITES_TIKTOK_ENABLED`, and `PROVIDER_WRITES_YOUTUBE_ENABLED`.
   - Channels default to `reply_policy='draft_only'`: MCP agents cannot publish unapproved text (`reply_policy_requires_approval`) unless referencing an operator-approved `draft_id` (`status='approved'`).
   - Every external write requires `care:write:<provider>`, an `idempotency_key` (`write_operations` table), and records `provider_result_id` + `readback_verified` in `comment_actions` and the SHA-256 `audit_events` chain.
2. **Strict Personal & Browser-Lane Isolation**:
   - Any channel with `adapter != 'meta_api'` (`veilbrowser`, `orbine_mobile`, `browser_ingest`) or `account_role` in `('personal_main', 'evidence_scout')` hard-refuses automated writes (`channel_adapter_unsupported` / `role_read_only`).
   - Checkpoints or residential IP mismatches immediately trip `trip_circuit_breaker` (`health_status='checkpointed'`) and notify operators via Cygnus Telegram without ever attempting to bypass or solve CAPTCHAs.
3. **Container Hardening**:
   - Runs as non-root `10001:10001` with `read_only: true`, `no-new-privileges:true`, and `cap_drop: [ALL]`. Secrets remain encrypted in SQLite `secret_envelopes` (`AES-256-GCM`) keyed by `LNC_MASTER_KEY`.

---

## 3. Remaining Owner-Action Items (External Consents)

- **Meta App Review (`1821062268930458`)**: Complete Meta App Dashboard permission grants (`pages_read_user_content`, `pages_manage_metadata`, `pages_manage_engagement`, `read_insights`, `instagram_basic`, `instagram_manage_comments`, `instagram_manage_insights`) and Business Asset User Profile Access review so non-anonymized commenter names and live Graph writes unlock when `PROVIDER_WRITES_META_ENABLED=true`.
- **Optional Browser Fleet Endpoints**: Populate `VEILBROWSER_API_URL` / `ORBINE_API_URL` / `CYGNUS_AUTH_KEY` on Portainer Stack `#59` when onboarding read-only personal profiles or physical ARM64 consultant devices.
