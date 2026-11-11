# LNC Care: task checklist

Status: Phase 1 + Ecosystem Alignment (`LNC-Agent-Hub` + `Business MCP Hub` + `LNC Ads v1.2.0`) + Full-Width `lnc-internal-app-blueprint` UI Standard COMPLETED & LIVE on `https://care-mcp.lengoc.me` (2026-11-11, `VERSION 0.3.0.3`, `pytest` 21/21 passed). Follow `.docs/plan.md` gates. Check boxes only with evidence (test output, screenshot, API response without secrets).

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

## Phase 2: realtime + archive + Evidence Vault + worker

- [ ] `/webhooks/meta`: GET challenge with verify token; POST signature
  check (`X-Hub-Signature-256`), raw-body dedupe, enqueue, 200 fast.
- [ ] Subscribe pages (`/{page}/subscribed_apps`, `feed`) and IG comments;
  show subscription status per channel; polling fallback stays on.
- [ ] Worker service: same image, `python -m app.worker`; Playwright
  Chromium; screenshot public permalinks; media download + sha256;
  retention; failure dashboard; SQLite `busy_timeout`.
- [ ] Evidence Vault ("Lập vi bằng số" — `evidence_cases`, `evidence_items`):
  5-layer forensic collector (numerical UIDs/post/comment IDs, full comment
  tree expansion, full-page + viewport screenshots + MHTML/DOM + Playwright
  trace/HAR with UTC headers, original media download, SHA-256 manifest + ZIP
  export) and post-capture watchdog (+6h/+24h/+72h alive/edited/deleted check).
- [ ] Tests: webhook signature vectors; worker job idempotency; evidence
  bundle manifest + SHA-256 verification.

## Phase 2b: Multi-Account Fleet (`VeilBrowser` + `Orbine` + `Antidetect` Reuse)

> Detailed spec: [`.docs/multi-account-antidetect-plan.md`](multi-account-antidetect-plan.md).

- [ ] `account_runtimes`, `runtime_leases`, and `consultation_playbooks` tables
  + `/admin/#fleet` UI (account pool, adapter type, proxy status, daily
  read/write budgets, active leases, health badges).
- [ ] `VeilBrowserAdapter` (`adapter='veilbrowser'`): integrate with
  `veilbrowser__*` MCP (`profiles_list`, `sessions_prepare_start`,
  `sessions_start`, pre-flight outbound IP/ASN check, jittered feed/comment
  reads, `sessions_stop`) under bounded concurrency leases.
- [ ] Reuse high-value `Antidetect` (`RN2` + `RN5`) patterns in `VeilBrowser`
  (tracked with `VeilBrowser` lane `B01/B02`): `xray.exe + wintun.dll`
  per-process fail-closed proxy routing (`RN2` `launch.exe`) + HKDF 64-bit
  sub-seeding & Portable Passkey Store (`RN5`).
- [ ] `OrbineMobileAdapter` (`adapter='orbine_mobile'`): client for `Orbine`
  Engine (`127.0.0.1:9817` on physical ARM64 Android) reusing `RN1`
  `devices.json` (2,638 OEM catalog), `xray` TPROXY (`dokodemo-door` +
  `XRAY_FAILSAFE_WD` fail-closed watchdog), and 63 split-APK corpus.
- [ ] Write-guard & role-guard proof: `account_role='personal_main'` strictly
  rejects automated writes (`channel_adapter_unsupported` / `role_read_only`);
  dedicated `care_consultant` accounts enforce daily budget + score/confidence
  threshold.
- [ ] Circuit breaker: auto-pause runtime on checkpoint/login redirect/proxy
  mismatch (`health_status='checkpointed'`) + Telegram alert
  (`lnc-cygnus-telegram-notify`); manual resume in `#fleet` page.

## Phase 3: guarded writes + more platforms

- [ ] Draft approval flow; `comment_reply`, `comment_hide_set`,
  `comment_private_reply` with idempotency, readback, audit; env gate per
  provider; channel policy enforcement by caller class (operator/agent).
- [ ] MCP write tools behind `care:write(:p)`; prove one reply, one
  hide/unhide, one private reply on a test post; idempotent replay.
- [ ] TikTok business-account reads once scopes approved; YouTube reads
  (separate consent) if owner wants.

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
- [ ] Update skill `lnm-care` (tool surface, inbox workflow, reply policy,
  errors) and cross-links in `lnm-ads`/`lnm-accounts`.
- [ ] Release report in `.docs/reports/`.
