# Handoff — LNC Care (`v0.6.0.0`)

Updated: 2026-11-11.
Status: **LIVE** on `http://10.21.4.101:8482` and `https://care-mcp.lengoc.me` (`VERSION 0.6.0.0` — **100% Native Rust Backend `Axum 0.7` + `Rusqlite 0.32` WAL**, Phase 1 + Phase 2 + Phase 2b + Phase 3 + Phase 4 complete, Portainer `portainer-fr4` Stack `#59` `lnc-care` on endpoint `paris3` `#4`, Gitea `apps/lnc-care` + GitHub mirror `ngojclee/lnc-care`, FR Caddy Fleet + FR/VN Unbound DNS live, full-width `lnc-internal-app-blueprint` UI + `#keys` API/Management key contract, **32 `care__*` tools** on `/mcp`, `lnm-care` skill activated, `23/23` `cargo test` passing).

## Rust Backend Architecture (`src/*.rs` — Native Phase 1 → Phase 4)

1. **Single Native Binary (`src/main.rs` + `src/lib.rs`)**:
   - Subcommands: `lnc-care serve` (Axum HTTP server on `:8000`), `lnc-care worker` (5s background job loop wired with Vault + Agent Hub + Ads LAN Bridge), `lnc-care healthcheck` (container probe), and `lnc-care rotate-vault` (online AES-256-GCM master key rotation).
   - Multi-stage `Dockerfile`: `rust:1-slim-bookworm` (`cargo build --release --locked --bin lnc-care && strip`) -> `debian:bookworm-slim` running as non-root `10001:10001` with `read_only: true` and `cap_drop: [ALL]`.
   - Zero-migration SQLite WAL compatibility (`src/store.rs`, `src/vault.rs`, `src/audit.rs`): reads and writes `/data/care.db` (`AES-256-GCM` `secret_envelopes` v1 with AAD `["lnc-care-v1", org, kind, subject]`, PBKDF2-HMAC-SHA256 `200,000`-round `__mgmt_state`, and canonical ASCII SHA-256 `audit_events` hash chain).

2. **Phase 2 — Realtime Webhooks, Worker Archive & 5-Layer Forensic Evidence Vault (`src/evidence.rs`, `src/worker.rs`, `src/connections.rs`, `src/providers.rs`)**:
   - **Realtime Meta Webhooks & Subscriptions**: `POST /api/admin/channels/:id/subscribe` (`care__channel_webhook_subscribe`) subscribes Page `/{page_id}/subscribed_apps` (`feed`); `/webhooks/meta` verifies `X-Hub-Signature-256`, deduplicates raw payload SHA-256, and enqueues worker materialization (`process_meta_webhook_change` handling `feed`/`comments`/`mentions`/`messages`, `remove`/`delete` verbs, and immediate AI evaluation).
   - **Worker Media/Screenshot Archive & Retention**: downloads media/HTML/screenshots into `/data/archive/post_<id>/` with SHA-256 & byte size, exponential retry backoff (`max_attempts`), and automatic `archive_retention_days` pruning (`prune_expired_archives`).
   - **5-Layer Forensic Evidence Vault & Watchdog**: pure-Rust IEEE CRC-32 deterministic PKZIP builder (`build_deterministic_zip`) writing `manifest.json`, `forensic_report.md`, `layer1_immutable_ids.json`, `layer2_thread_snapshot.json`, `layer3_dom_snapshot.html`, `layer3_network_trace.har.json`, `layer4_media/*`, and `case_<id>_bundle.zip` under `/data/evidence/case_<id>/`; exposes `.zip` export (`GET /api/admin/evidence/:id/export`), SHA-256 custody check (`GET /api/admin/evidence/:id/verify`), and `+6h/+24h/+72h` `evidence_watchdog` alive/edited/deleted checks (`POST /api/admin/evidence/:id/check`).

3. **Phase 2b — Multi-Account Fleet, Concurrency Leases, Circuit Breaker & Playbooks (`src/fleet.rs`, `src/evaluator.rs`)**:
   - **Adapters & Leases**: `VeilBrowser` (`VEILBROWSER_API_URL`) and `Orbine` (`ORBINE_API_URL`) adapters with atomic `BEGIN IMMEDIATE` SQLite concurrency leases (`MAX_CONCURRENT_BROWSER_SESSIONS`, default `4`), pre-flight outbound IP/ASN/checkpoint gate (`probe_runtime`), daily UTC read/write budgets, and jittered `±35%` browser polling (`source='browser'`, `verified=0`).
   - **Safety Gates & Cygnus Alerting**: `personal_main` and `evidence_scout` roles fail closed on any write (`role_read_only` / `channel_adapter_unsupported`); checkpoints or IP mismatches trip `trip_circuit_breaker` (`health_status='checkpointed'`) and fire a Telegram alert via Cygnus Gateway (`CYGNUS_GATEWAY_URL`, bot `Cygnus_Assitance_Bot`, topic `7410`) until manual operator `Resume`.
   - **Consultation Playbooks**: `GET/POST /api/admin/playbooks` (`care__playbooks_list`, `care__playbook_upsert`) injects brand voice, pricing policy, escalation rules, and forbidden phrases directly into `evaluator.rs` consultation reasoning and drafts.

4. **Phase 3 — Guarded External Provider Writes + Multi-Platform Official APIs (`src/providers.rs`, `src/connections.rs`, `src/mcp_server.rs`, `src/routes.rs`)**:
   - **Official TikTok Business v1.3 & YouTube Data API v3**: full OAuth exchange, channel discovery (`tt_account`, `yt_channel`), bounded video/post + comment + reply polling, and moderation/reply endpoints alongside Meta Graph (`fb_page`, `ig_account`).
   - **Guarded Writes + Readback Verification**: `comment_reply`, `comment_hide_set`, `comment_private_reply`, and `message_reply` execute real external provider calls (via Vault token or `lnc-ads` LAN Bridge `platform_call`), verify public replies/hides via GET readback (`readback_verified`), transition `reply_drafts` (`draft -> approved -> sent` with `sent_action_id`), enforce per-provider env gates (`PROVIDER_WRITES_{META,TIKTOK,YOUTUBE}_ENABLED`), and enforce IG platform limits (no nested reply, no reply on hidden comment, 7-day private reply window).

5. **UI, MCP & Skill Surface (`public/*`, `\\10.21.2.2\data\_agentsync\skills\lnm-care\SKILL.md`)**:
   - Full-width LN UI Engine lite shell across all 12 hash-slug pages (`#inbox` now includes direct `Send public reply` / `Send private DM` buttons and `readback verified` action history when provider writes are enabled).
   - **32 `care__*` MCP Tools** (`16` read + `16` write) documented in `lnm-care/SKILL.md` and release report `.docs/reports/release-v0.6.0.0.md`.

## Key Files to Read First
1. `AGENTS.md`
2. `.docs/plan.md` & `.docs/multi-account-antidetect-plan.md`
3. `.docs/task.md` & `.docs/reports/release-v0.6.0.0.md`
4. `src/providers.rs`, `src/connections.rs`, `src/evidence.rs`, `src/fleet.rs`, `src/mcp_server.rs`, `src/routes.rs`, `tests/contract_suite.rs`
