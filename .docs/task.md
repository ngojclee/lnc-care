# LNC Care: task checklist

Status: **ALL ENGINEERING PHASES COMPLETE & LIVE (`Phase 1` + `Phase 2` + `Phase 2b` + `Phase 3` + `Phase 4`)** on `https://care-mcp.lengoc.me` & `10.21.4.101:8482` (2026-11-11, `VERSION 0.6.0.0`, **100% Native Rust Backend (`Axum 0.7` + `Rusqlite 0.32` WAL)**, `cargo test` **23/23** passed, 32 `care__*` MCP tools, `lnm-care` skill activated). Follow `.docs/plan.md` gates. Check boxes only with evidence (test output, screenshot, API response without secrets).

## Phase 0: evidence and decisions

- [x] Owner lists channels for V1 (Pages + IG per shop) and which identity
  administers each; TikTok/YouTube marked later.
  Evidence 2026-10-26: owner chose ALL discovered channels — 14 Pages via
  the `lengoc-meta` identity (probe `/me/accounts`) + linked IG
  (@luxe.claw, @lesreveurs.studio, @musesart.atelier). Personal profiles
  are out of scope: Meta has no official API for personal profile
  posts/comments; IG non-professional must convert to professional first.
  Pages without `instagram_business_account` need the shop IG linked in
  Page settings to be tracked.
- [x] Owner confirms domain `care-mcp.lengoc.me`, port `8482` on
  `10.21.4.101` (recheck free), split access (`/webhooks/*` public).
- [x] Owner chooses default reply policy (`draft_only` recommended) and who
  may approve. Decision 2026-10-26: `draft_only` default; owner approves.
- [ ] Add missing permissions to the Live Meta app use cases:
  `pages_manage_engagement`, `pages_manage_metadata`,
  `pages_read_user_content`, `instagram_manage_comments`,
  `instagram_manage_insights`; record which need App Review for our use.
  Probe 2026-10-26 adds `read_insights` + `instagram_basic` to the list.
  Owner decision: add all 7 AND start App Review for Business Asset
  User Profile Access (commenter names). Owner action in App Dashboard.
- [x] Identify Postiz's Meta app id and existing webhook subscriptions;
  decide shared app vs dedicated care app.
  Evidence 2026-10-26: Postiz container env `FACEBOOK_APP_ID=39303237442608473`
  ≠ lnc-ads app `1821062268930458` → no app-level webhook collision; sharing
  the lnc-ads app is safe. Per-page `subscribed_apps` could not be listed
  (needs `pages_manage_metadata`); recheck after permission grant.
- [x] Temp script (booleans only, token from vault inside lnc-ads
  container): `/{page}/feed`, `/{post}/comments`, `/{post}/insights`,
  `/{ig_user}/media`, `/{media}/comments`, `/{media}/insights`.
  Evidence 2026-10-26, `temp_scripts/probe_meta_token.py` inside
  `lnc-ads-lnc-ads-1`: token verified, ~59 days left, 14 pages + 3 linked
  IG discovered. Granted: ads_read, ads_management, business_management,
  pages_read_engagement, pages_show_list. Works: `published_posts`,
  page `followers_count`, IG `followers_count`. Fails (needs scope):
  comments `pages_read_user_content` (#10), `subscribed_apps`
  `pages_manage_metadata` (#200), post insights `read_insights` (#100),
  IG media `instagram_basic` (#10); `/{page}/feed` also denied — use
  `published_posts` instead. `pages_manage_engagement`,
  `instagram_manage_comments`, `instagram_manage_insights` still needed
  for Phase 3 writes/insights.
- [x] Note whether commenter names are anonymised; decide on Business Asset
  User Profile Access review. Decision 2026-10-26: owner approved starting
  the BAUPA App Review; until granted, commenter `from`/`username` stays
  anonymised (inbox still works on ids + text).
- [ ] Owner lists which personal profiles (FB/IG) join via the browser
  lane in Phase 2b. Decision 2026-10-26: personal profiles tracked
  read-only via `lnc-scrapling` + `lnc-browser` (no conversion to Page,
  no email lane, no writes ever). Stability research pending — see
  `plan.md` §2b.

## Phase 1: ingest + AI triage inbox (local, offline) — COMPLETED 2026-11-10

- [x] Scaffold from lnc-ads patterns (`app/`, `app/public/`,
  `tests/`, `Dockerfile`, `stack.yml` with `lnc-care` + `lnc-care-worker`,
  `VERSION 0.1.0.0`); icon via `lnc-icon` (`#F2CEC2` warm terracotta + `#5E2419` ink); dual theme.
- [x] Org/shop schema; management-key login; CSRF; rate limit; vault (`app/vault.py`, `app/rotate_vault.py`);
  provider apps settings (`app/settings.py`).
- [x] Meta OAuth with full permission set; channel discovery
  (`/me/accounts` + `instagram_business_account`); page tokens per channel
  in vault; approve/bind shop; reply policy field (`app/providers.py`, `app/connections.py`).
- [x] Pollers: posts (bounded backfill), comments (stream filter, replies),
  post insights, channel followers; `jobs` table + in-process runner (`app/worker.py`).
- [x] Metric map per platform/version; `post_snapshots`, `channel_snapshots` (`app/store.py`).
- [x] AI Evaluation & Consultation Reasoning (`comment_evaluations`,
  `evaluation_feedback` in `app/evaluator.py`): code-first data collector (prompt-injection shield),
  overall score `0–100` + threshold, reasoning bullets, multi-label
  probability breakdown (12 commercial + safety/mindset labels), `[✓]/[✕]` human
  calibration, and **Evaluate → Reason → Consult** reply strategy + public/DM
  draft generation.
- [x] Split-pane Inbox UI (`/admin/#inbox` in `app/public/index.html`, `style.css`, `app.js`, inspired by
  `.docs/assets/ui-inspiration-triage-rubric.jpg`): top bucket pills, left
  grouped priority queue, right evaluation pane with score bar, reasoning
  bullets, multi-label probability bars + `[✓]/[✕]` buttons, Reply Reasoning
  & Consultation Studio, and bottom quick-decision bar (`1`, `2`, `3`).
- [x] Other UI views: Overview, Evidence Vault (`#evidence`), Account Fleet (`#fleet`), Posts
  (+SVG snapshot chart & archives), Channels & OAuth, Triage Rules, Audit Log, MCP Connector, Settings.
- [x] `/mcp` (`app/mcp_server.py`): delegation verifier, nonce table, scope map, read tools
  (`channels_list`, `posts_list`, `post_get`, `comments_list`,
  `comment_thread`, `stats_series`, `inbox_summary`, `evidence_case_get`) +
  evaluation/triage/draft/evidence tools (`comment_evaluate`,
  `evaluation_feedback_set`, `comment_flag_set`, `reply_draft_create`, `archive_request`,
  `evidence_capture`) + guarded provider write tools (`comment_reply`, `comment_hide_set`, `comment_private_reply`).
- [x] Tests (`tests/test_api.py`, `tests/test_evaluator.py`, `tests/test_evidence_and_fleet.py`, `tests/test_mcp.py`):
  `python -m pytest -v` → **11 passed in 2.63s** (mock Meta OAuth/discovery/poller, prompt-injection shield, 12-label rubric + `[✓]/[✕]` calibration, 5-layer Evidence Vault SHA-256 manifest, Multi-Account Fleet `personal_main` write-guard `channel_adapter_unsupported`, MCP HMAC v3/v4 signature & nonce replay guard).

## Phase 2: realtime + archive + Evidence Vault + worker — COMPLETED 2026-11-11

- [x] `/webhooks/meta`: GET challenge with verify token; POST signature
  check (`X-Hub-Signature-256`), raw-body dedupe, enqueue, 200 fast, plus
  inline worker materialization of `feed` / `comments` / `mentions` / `messages`
  changes (`process_meta_webhook_change`, including `remove`/`delete` verbs
  and immediate AI rubric evaluation).
- [x] Subscribe pages (`/{page}/subscribed_apps`, `feed`) and IG comments
  (`POST /api/admin/channels/:id/subscribe` + `care__channel_webhook_subscribe`);
  show subscription status per channel (`Webhook active` / `Polling` badge);
  polling fallback stays on.
- [x] Worker service: same Rust image, `/app/lnc-care worker` wired with full
  Vault + Agent Hub + Ads LAN Bridge runtime (`src/main.rs`, `src/worker.rs`);
  external `BROWSER_CAPTURE_URL`/`VEILBROWSER_API_URL` screenshot capture + HTML
  snapshot fallback; media download + SHA-256 + byte size into `/data/archive/post_<id>/`;
  `archive_retention_days` pruning (`prune_expired_archives`); exponential backoff
  retries (`max_attempts`) + worker queue summary dashboard; SQLite WAL `busy_timeout=5000ms`.
- [x] Evidence Vault ("Lập vi bằng số" — `evidence_cases`, `evidence_items` in `src/evidence.rs`):
  5-layer forensic collector on disk (`manifest.json`, `forensic_report.md`,
  `layer1_immutable_ids.json`, `layer2_thread_snapshot.json`, `layer3_dom_snapshot.html`,
  `layer3_network_trace.har.json`, `layer4_media/*`, deterministic pure-Rust IEEE CRC-32
  PKZIP bundle `case_<id>_bundle.zip`), `.zip` download (`GET /api/admin/evidence/:id/export`),
  SHA-256 custody verification (`GET /api/admin/evidence/:id/verify`), and post-capture
  watchdog (`+6h/+24h/+72h` `evidence_watchdog` jobs + `POST /api/admin/evidence/:id/check` /
  `care__evidence_watchdog_check` tracking `alive` -> `edited` / `deleted`).
- [x] Tests (`tests/contract_suite.rs::test_phase2_webhook_materialization_archive_pruning_and_forensic_zip_watchdog`):
  webhook signature vectors & materialization; worker job idempotency & archive retention
  pruning; 5-layer forensic PKZIP export (`PK\x03\x04`) + SHA-256 custody verification +
  watchdog `alive -> edited -> deleted` transitions (`22/22` `cargo test` passed).

## Phase 2b: Multi-Account Fleet (`VeilBrowser` + `Orbine` + `Antidetect` Reuse) — COMPLETED 2026-11-11

> Detailed spec: [`.docs/multi-account-antidetect-plan.md`](multi-account-antidetect-plan.md).

- [x] `account_runtimes`, `runtime_leases`, and `consultation_playbooks` tables
  (`src/fleet.rs`, `src/store.rs`) + `/admin/#fleet` UI (`public/app.js`, `public/index.html`:
  account pool, adapter type, proxy status, daily read/write budgets, active concurrency
  leases table, `Probe IP` / `Resume` actions, and Consultation Playbooks studio).
- [x] `VeilBrowserAdapter` (`adapter='veilbrowser'` in `src/fleet.rs`): pre-flight
  outbound IP/ASN/checkpoint gate (`VEILBROWSER_API_URL`), atomic `BEGIN IMMEDIATE`
  SQLite concurrency leases (`MAX_CONCURRENT_BROWSER_SESSIONS`, TTL reap), jittered
  `±35%` feed/comment reads (`run_browser_channel_fetch`, `source='browser'`, `verified=0`),
  and deterministic session lease release.
- [ ] Reuse high-value `Antidetect` (`RN2` + `RN5`) patterns inside upstream `VeilBrowser`
  repo (tracked separately on `VeilBrowser` lane `B01/B02`): `xray.exe + wintun.dll`
  per-process fail-closed proxy routing (`RN2` `launch.exe`) + HKDF 64-bit
  sub-seeding & Portable Passkey Store (`RN5`).
- [x] `OrbineMobileAdapter` (`adapter='orbine_mobile'` in `src/fleet.rs`): client for `Orbine`
  Engine (`ORBINE_API_URL`, default `127.0.0.1:9817` on physical ARM64 Android) with
  pre-flight IP/device health verification and unified lease/budget/circuit-breaker guards.
- [x] Write-guard & role-guard proof: `account_role='personal_main'` and `'evidence_scout'`
  strictly reject automated writes (`channel_adapter_unsupported` / `role_read_only`);
  dedicated `care_consultant` accounts enforce daily UTC budget (`daily_read_budget`,
  `daily_write_budget`) + brand `consultation_playbooks` injection in `src/evaluator.rs`.
- [x] Circuit breaker (`trip_circuit_breaker` in `src/fleet.rs`): fail-closed auto-pause on
  checkpoint/login redirect/IP mismatch (`health_status='checkpointed'`) + Cygnus Telegram
  Gateway alert (`CYGNUS_GATEWAY_URL`, bot `Cygnus_Assitance_Bot`, topic `7410`) + manual
  operator `Resume` (`POST /api/admin/fleet/:id/resume`), verified in
  `test_phase2b_fleet_leases_preflight_circuit_breaker_telegram_budgets_and_playbooks`.

## Phase 3: guarded writes + more platforms — COMPLETED 2026-11-11

- [x] Draft approval flow (`reply_drafts` `draft -> approved -> sent` with `sent_action_id`);
  `comment_reply`, `comment_hide_set`, `comment_private_reply`, and `message_reply`
  wired to real external provider transports (`src/providers.rs`, `src/connections.rs`,
  `src/mcp_server.rs`, `src/routes.rs`) with `write_operations` idempotency, GET readback
  verification (`readback_verified`), SHA-256 `audit_events`, per-provider env gates
  (`PROVIDER_WRITES_{META,TIKTOK,YOUTUBE}_ENABLED`), IG top-level/hidden/7-day private
  reply window guards, and caller-class `reply_policy` enforcement (`draft_only`,
  `operator_direct`, `agent_direct`).
- [x] MCP write tools behind `care:write(:p)` + operator UI buttons (`/api/admin/comments/:id/{reply,hide,private-reply}`);
  proven in `test_phase3_guarded_writes_readback_policy_and_tiktok_youtube_ingest`
  (one reply with `readback_verified: true`, one hide + readback, one private reply,
  `draft_only` unapproved block -> approved `draft_id` execution -> `status='sent'`,
  IG 7-day window block, per-provider gate block on TikTok while YouTube succeeds,
  and idempotent replay).
- [x] Official TikTok Business API v1.3 (`/business/get/`, `/business/video/list/`,
  `/business/comment/list/`, `/business/comment/reply/create/`, `/business/comment/hide/`)
  and YouTube Data API v3 (`/youtube/v3/channels`, `/search`, `/videos`, `/commentThreads`
  including nested replies, `/comments`, `/comments/setModerationStatus`) implemented &
  verified in `src/providers.rs` + `tests/contract_suite.rs`.

## Phase 4: release

- [x] gitea `apps/lnc-care` + github mirror `ngojclee/lnc-care` (push-mirror active); row marked `active` in
  `lnc-internal-apps/README.md`, `PORTS.md`, and `registry.json` (`8482` on `10.21.4.101`).
- [x] Host prep `/home/Docker/lnc-care` (uid `10001:10001`, `archive/` and `evidence/` subdirs),
  Portainer repo-stack `#59` (`lnc-care` on `portainer-fr4` endpoint `4` `paris3`, two services `lnc-care` + `lnc-care-worker`), env block, `/health` (`200 OK`) and `/mcp` (`200 OK`, 26 `care__*` tools, Business MCP Hub v3/v4 headers) verified.
- [x] FR Caddy Fleet (`automations/edge-fleet` `0088114`) + Let's Encrypt cert (`care-mcp.lengoc.me`) + FR/VN Unbound internal DNS (`internal-dns` `2e1c799`) live (`HTTP=200 SSL=0` from LAN, `403` outside `@acl_2`).
- [x] Ecosystem alignment (`VERSION 0.2.0.0`, `15/15 pytest`): `app/agent_hub.py` (`/v1/platform/*` + encrypted local SQLite Vault cache `TTL=900s` + automatic LAN fallback to `lnc-ads` `:8480`), `app/internal_bridge.py` (`LNC_INTERNAL_BRIDGE_SECRET` HMAC + 3-way Universal SSO `/api/auth/sso/{redirect,consume}`), and `app/mcp_gateway.py` (`LNC_MCP_GATEWAY_URL=http://10.21.4.101:8380/mcp` for `ads__*`).
- [x] Full `lnc-internal-app-blueprint` UI & `#keys` standard (`VERSION 0.3.0.1`, `19/19 pytest`): LN UI Engine lite dual light/dark tokens (`#F2CEC2`/`#5E2419`), pixel-aligned `56px` `.side-brand`/`.topbar` divider, 12 hash-slug pages (`#conversations` & `#keys` added), 3-row `.side-foot`, `lite-select` rounded dropdowns, 100% English UI copy, `lnc-icon` 1024x1024 PNG + multi-size ICO (`app/public/*` + `docs/icon.*`), service API keys (`/api/keys*` + Bearer `/api/status`), bootstrap-to-runtime PBKDF2 management key rotation (`/api/mgmt/rotate`), and `env_or_cfg` Hub pairing secrets.
- [x] Hub managed connector `lnc-care`, pairing, scopes, grants; live
  discovery shows 26 `care__*` tools on Business MCP Hub (`:8790`) + LNC-Agent-Hub (`:8380/mcp`), Vault `pconn_0mwbf9p0xbbac3c585e8ab6c5` synced to local encrypted cache, and stateful `Mcp-Session-Id` handshake + 1x `400/404` auto re-init in `McpGatewayClient` (`VERSION 0.3.0.2`, `20/20 pytest`).
- [x] **1:1 Native Rust Backend Migration (`VERSION 0.4.0.0`, `20/20 cargo test`)**: ported all 15 backend modules (`src/{lib,main,transport,audit,vault,settings,store,evaluator,providers,worker,internal_bridge,agent_hub,connections,mcp_gateway,mcp_server,routes}.rs`) to `Axum 0.7` + `Rusqlite 0.32` (WAL) with 100% SQLite/AES-256-GCM/PBKDF2/SHA-256/MCP/SSO wire compatibility, removed legacy Python `app/` + `requirements.txt` + `tests/*.py`, updated multi-stage `Dockerfile` (`rust:1-slim-bookworm` -> `debian:bookworm-slim`) & `stack.yml`, and redeployed Stack `#59` on `10.21.4.101:8482`.
- [x] Update skill `lnm-care` (`\\10.21.2.2\data\_agentsync\skills\lnm-care\SKILL.md`:
  32 `care__*` tools, scopes, inbox SOP, `reply_policy` rules, platform limits & error codes).
- [x] Release report in `.docs/reports/release-v0.6.0.0.md`.
