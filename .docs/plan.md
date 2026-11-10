# LNC Care: research and implementation plan

Status: planning, 2026-10-26 (Europe/Paris). No source yet. Project root
`D:\Python\projects\lnc-care`; `.docs/` is the planning directory.
Sibling apps: `lnc-ads` (live), `lnc-accounts` (planned), `lnc-postiz`
(publishing gateway, live), `SocialTrak` (external channel tracking).
Research notes: `\\10.21.2.2\data\_agentsync\research\lnm-social-care-accounts-research.md`.

## 1. Problem and goal

Owned channels (LuxeClaw Page `235513372986478` + IG `17841464987749627`,
other shop pages, TikTok/YouTube later) receive comments that nobody sees in
one place; there is no history of a post's performance, no archive of what
was published (media disappears when edited/deleted), no audit of who
replied what. The owner wants to read and follow comments per post, reply
or hide from one console, keep statistics over time, and keep screenshots/
media copies of posts.

**Goal:** an internal care console that

1. ingests posts and comments from owned channels via official APIs
   (webhooks + polling backfill);
2. keeps **daily metric snapshots per post** (reach, reactions, comments,
   shares, saves, plays) and per channel (followers);
3. archives each post: caption, media files (from API `media_url`), permalink
   and a **screenshot** of the public permalink;
4. provides a **split-pane AI Triage Inbox**: multi-label probability scoring,
   AI recommendation + reasoning bullets, human `[✓]/[✕]` rubric calibration,
   and **Evaluate → Reason → Consult** reply generation (structured evaluation
   first, then reply strategy + consultation drafts for customer inquiries);
5. provides an **Evidence Vault ("Lập vi bằng số")**: 1-click/1-URL forensic
   preservation of defamatory or abusive posts/comments (immutable numerical
   UIDs, expanded comment trees, full-page + viewport screenshots, DOM/MHTML,
   Playwright trace/HAR with raw server JSON & UTC headers, media archive, and
   SHA-256 manifest ZIP bundle + post-capture edit/delete watchdog);
6. executes **guarded writes**: public reply, hide/unhide, private reply (IG
   within 7 days) — draft-for-approval by default, progressive automation per
   channel policy and score threshold — with idempotency and audit;
7. exposes reads, evaluations, evidence capture, and guarded writes to Business
   MCP Hub (`care__*`) so agents can triage, consult, and preserve evidence.

**Non-goals:** publishing/scheduling (Postiz via `lnc-postiz`); full DMs/Messenger
helpdesk (except comment-triggered private replies); competitor/external channel
scraping (SocialTrak); ads comments on paid posts (Phase 4, linked to
`lnc-ads`).

**Owner decision 2026-10-26 — personal profiles:** tracked read-only via a
**browser ingest lane** (existing `lnc-scrapling` connector + `lnc-browser`
fallback, shared social cookies). No conversion to Pages, no email
notification lane. Personal-profile comments are flag/read only — never
reply, hide or write through automation (ban risk on the personal account).
Details: §2b, §3, §7 Phase 2b.

## 2. Evidence: what the platforms allow

| Platform | Posts & metrics | Comments read | Reply / moderate | Realtime | Permissions / access |
|---|---|---|---|---|---|
| **Facebook Page** (Graph API) | `GET /{page}/feed` or `/published_posts` (`message`, `permalink_url`, `attachments`, `created_time`), `GET /{post}/insights` (`post_impressions_unique`, `post_reactions_by_type_total`, `post_clicks`), `GET /{page}/insights` (`page_fans`) | `GET /{post}/comments?fields=id,from,message,created_time,parent,is_hidden,comment_count,like_count&filter=stream` | `POST /{comment}/comments` (reply), `POST /{comment}?is_hidden=true`, `POST /{comment}/private_replies` | Webhook object `page`, field `feed` (comment add/edit/remove, post) | `pages_read_engagement`, `pages_read_user_content`, `pages_manage_engagement`, `pages_manage_metadata` (webhooks), `pages_show_list`. Own pages → Standard Access. Commenter `from` for personal profiles is omitted/anonymised unless the app is approved for **Business Asset User Profile Access** (App Review, Business app). |
| **Instagram professional** (via Facebook Login, `graph.facebook.com`) | `GET /{ig_user}/media` (`caption`, `media_type`, `media_url`, `thumbnail_url`, `permalink`, `timestamp`, `like_count`, `comments_count`), `GET /{media}/insights` (`reach`, `saved`, `shares`, `plays`/`views`), `GET /{ig_user}` (`followers_count`) | `GET /{media}/comments?fields=id,text,username,timestamp,hidden,like_count,replies{...}` | `POST /{comment}/replies` (top-level only; not on hidden; not on live), `POST /{comment}?hide=true`, private reply `POST /{ig_user}/messages` with `recipient.comment_id` (≤7 days) | Webhook object `instagram`, fields `comments`, `live_comments` (needs the Page subscribed to the app) | `instagram_basic`, `instagram_manage_comments`, `instagram_manage_insights`, `pages_read_engagement` (+ `ads_management`/`ads_read` if the Page role came through BM — we already hold both). Standard Access for own accounts. `username` of commenters needs the comments permission (policy since 2024-08). |
| **TikTok business account** (Marketing API, product "TikTok Accounts") | `/business/get/` (followers), `/business/video/list/` (views, likes, comments, shares, `embed_url`, `cover_image_url`) | `/business/comment/list/`, `/business/comment/reply/list/` (public + hidden) | `/business/comment/create/`, `/business/comment/reply/create/`, `/business/comment/like/`, hide/unhide | Polling only | Scopes *Account User*, *Get Account Media*, *Get Business Comment*, *Manage Account Comment* — separate from ads scopes; add to the pending `LNC Ads` app. |
| **TikTok ad comments** | — | `/comment/list/` by `ADGROUP_ID` | `/comment/reply/`, hide | Polling | Ads scopes (Phase 4 via lnc-ads account link). |
| YouTube Data API | `videos.list(statistics)` | `commentThreads.list` | `comments.insert`, `setModerationStatus` | Polling (quota 10k units/day) | `youtube.force-ssl`; separate Google OAuth consent. Phase 3+. |
| Threads | `/{thread}` metrics | `/{thread}/replies` | reply via `/{me}/threads` | — | `threads_read_replies`, `threads_manage_replies` (App Review). Later. |

## 2b. Personal profiles & Multi-Account Fleet (`VeilBrowser` + `Orbine` + `Antidetect` reuse, updated 2026-11-10)

> Full deep-dive architecture: [`.docs/multi-account-antidetect-plan.md`](multi-account-antidetect-plan.md).

Meta/IG/TikTok expose **no official API** for personal-profile posts and
comments (FB `user_posts`/`publish_actions` removed 2018; professional-mode
profiles still have no Graph surface; IG must be professional; TikTok
comments exist only for business accounts). When scaling from 1–2 personal
profiles to **dozens or hundreds of accounts** (personal profiles, regional
care/consultation personas, friend-triage accounts, forensic `evidence_scout`
accounts), raw headless scraping (`lnc-scrapling`) with shared cookie files
fails due to fingerprint/TLS collision and missing IndexedDB/Passkey bindings.

Instead of building a new browser/emulator/VM stack from scratch, `lnc-care`
reuses our existing fleet and the completed `D:\Python\projects\Antidetect`
(`RN1–RN5`) research across **4 Execution Tiers** via an `AccountRuntimeAdapter`:

| Tier / Adapter | Engine & Reuse Source | Role in `lnc-care` |
|---|---|---|
| **Tier 1: `meta_api`** | Official Graph / TikTok Business / YouTube API | Owned Pages & IG Business accounts (webhooks, insights, high-volume guarded replies) |
| **Tier 2: `veilbrowser`** | **`VeilBrowser`** (`veilbrowser__*` MCP, **Camoufox 152** C++ engine + Chromium Cloak 146) + **`RN2`** (`xray.exe + wintun.dll` per-process proxy) + **`RN5`** (HKDF 64-bit sub-seeding + **Portable Passkey Store**) | **Primary multi-account web fleet (10–500+ accounts):** Personal FB/IG feeds, Friend Triage, Customer Consultation accounts, and authenticated **Evidence Vault** captures. (*Never embed `Vifox 148` binaries — Camoufox 152 in VeilBrowser is 4 major versions newer.*) |
| **Tier 3: `orbine_mobile`** | **`Orbine`** (`127.0.0.1:9817` on **Physical ARM64 Android**) + **`RN1`** (`devices.json` 2,638 OEM catalog + `xray` TPROXY `dokodemo-door` + `XRAY_FAILSAFE_WD` fail-closed watchdog + 63 split-APK corpus + USB AOA2 HID) | **High-trust mobile-native fleet:** TikTok personal/shop accounts, IG mobile care, and accounts where `MetaSec`/`libmetasec_ml` penalizes desktop web or x86_64 `LD_PRELOAD` emulators. |
| **Tier 4: `scrapling_public` / `veilmachine_vm`** | `lnc-scrapling` (fast unauthenticated public URLs) · **`VeilMachine`** (`RN3` 21 JSON hardware catalogs + `.vmx` hypervisor spoof + Linked Clones + Virtual Router VM) | `scrapling_public` for zero-account public snapshots; `VeilMachine` reserved only if dedicated full-OS desktop VMs are needed for high-value BM admins. |

| Aspect | Contract |
|---|---|
| Adapter & Pool | `account_runtimes` (`adapter` ∈ `meta_api`, `veilbrowser`, `orbine_mobile`, `scrapling_public`) + `runtime_leases` (concurrency cap, pre-flight outbound IP/ASN check — fail-closed) |
| Read targets | own notifications page + own post permalinks → comments; friend requests / friend feeds for Friend Hygiene; public/friends-only targets for Evidence Vault |
| IDs | synthetic `external_id = sha256(channel+post+author+text+ts)` when numerical ID is absent |
| Writes & Safety | **Personal main profiles (`account_role='personal_main'`) are strictly read/flag-only** (writes rejected in code). Dedicated `care_consultant` accounts require explicit owner policy + daily budget + score threshold |
| Stability rules | Concurrency lease pool (e.g. 4–8 active `VeilBrowser` sessions rotated); jittered poll (`±35%`); passive scroll keepalive; checkpoint/login-redirect detector → instant auto-pause (`health_status='checkpointed'`) + Telegram alert (`lnc-cygnus-telegram-notify`); never auto-solve CAPTCHAs or retry-storm |

Open research (before building the lane): exact selectors/URL surfaces on
facebook.com notifications + personal post permalinks; IG personal-web feed;
checkpoint classification; session lifetime measured on the real cookies.

## 2c. AI Evaluation, Rubric Calibration & Consultation Reasoning (owner decision 2026-11-10)

To support intelligent comment triage and automated customer consultation
without prompt-injection risk, `lnc-care` uses a strict **Code Collects →
AI Evaluates → AI Reasons Reply → Guarded Action** pipeline (proven in the
owner's Friend Triage system, see `.docs/assets/ui-inspiration-triage-rubric.jpg`):

1. **Deterministic Data Collection (Prompt Injection Shield):**
   - Pure code gathers the comment text, parent thread, post caption, linked
     shop/product metadata, and commenter interaction history.
   - Untrusted user text is passed strictly as isolated data variables to a
     structured classification call (OpenAI Structured Outputs / Decisions
     pattern) with **zero tool-execution authority**.
2. **Multi-Label Rubric Evaluation (`comment_evaluations`):**
   - Produces an overall **Priority / Fit Score (`0–100`)** with a configurable
     channel threshold (`auto_suggest_threshold`, e.g. `80/100`), a
     **Recommended Bucket** (`should_consult`, `needs_human_review`, `praise`,
     `complaint`, `spam_clone`, `negative_toxic`, `capture_evidence`),
     **Confidence %** + **Data Quality** indicator, and **3–4 Reasoning Bullets**.
   - Outputs **per-label probability bars (`0–100%`)** across two label groups:
     - *Commercial / Shop Consultation:* `purchase_intent` (Muốn mua),
       `price_inquiry` (Hỏi giá), `product_spec` (Hỏi mẫu/size/cách dùng),
       `shipping_policy` (Ship/Đổi trả), `praise_feedback` (Khen/Feedback),
       `complaint_urgent` (Khiếu nại/Cần xử lý gấp).
     - *Community / Safety / Mindset:* `positive` (Tích cực), `constructive`
       (Xây dựng), `polite` (Lịch sự), `negative` (Tiêu cực), `spam_seeding`
       (Clone/Spam), `defamation_abuse` (Miệt thị/Bôi nhọ).
3. **Human-in-the-Loop Calibration (`[✓]` / `[✕]` per label):**
   - Operators can click `[✓]` or `[✕]` on any probability bar ("Bạn thấy") and
     use quick decision buttons (`1`, `2`, `3`) to confirm or override the AI
     recommendation. Feedback is stored in `evaluation_feedback` to calibrate
     channel rubrics and few-shot examples over time.
4. **Evaluate → Reason → Consult (`reply_reasoning` + `reply_drafts`):**
   - Only *after* structured evaluation completes, the consultation generator
     combines the evaluation output + post/product knowledge to produce:
     - **Reply Strategy (`reasoning_plan`):** explicit reasoning on *how* to
       answer (e.g., *"Khách hỏi giá bộ nail X và thời gian ship đi Pháp →
       Báo giá công khai hoặc mời check inbox + giải thích chính sách ship
       48h + gợi ý mẫu tương tự"*).
     - **Tailored Drafts:** Public reply draft + optional Private Reply (DM)
       draft for deeper consultation.
   - When a comment's evaluation meets the channel's safe auto-consultation
     criteria (e.g., score ≥ threshold, high confidence, `purchase_intent` or
     FAQ, zero `complaint`/`defamation` flags, and channel policy allows), it
     can streamline or automate customer consultation safely.

## 2d. Evidence Vault / Forensic Capture — "Lập vi bằng số" (owner decision 2026-11-10)

When a post, comment thread, or profile defames, harasses, or attacks the owner
or an owned brand, a normal screenshot is easily dismissed as doctored (`F12`)
and disappears if the author deletes the post or changes their display name.
`lnc-care` includes an **Evidence Vault (`#evidence`)** that freezes a 5-layer
forensic bundle via `lnc-care-worker` (`lnc-scrapling` / `lnc-browser`):

1. **Immutable Identity Extraction:** resolves and records numerical
   `actor_uid` / `page_id`, `post_id`, `comment_id`, and canonical URLs so
   renaming display names or changing vanity URLs cannot hide the actor.
2. **Full Thread Expansion:** switches comment sorting to *"All comments"* and
   expands *"See more"* / *"View more comments"* / *"View X replies"* before
   capturing.
3. **Visual & Network Replay Evidence:**
   - Full-page screenshot + scrolled viewport sequence + PDF print.
   - Single-file MHTML / DOM snapshot.
   - **Playwright Screencast / Trace + HAR (HTTP Archive):** records the live
     URL navigation, page reload (`F5`), and raw GraphQL JSON responses with
     HTTP headers, server IP, TLS metadata, and UTC server timestamps.
4. **Original Media Preservation:** downloads all post and comment attachments
   (images/videos) at original resolution before deletion.
5. **Cryptographic Chain of Custody & Watchdog:**
   - Computes **SHA-256** hashes for every captured artifact, writes
     `manifest.json` + human-readable case report (Markdown/PDF), and packages
     a downloadable `.zip` bundle (with optional RFC 3161 Trusted Timestamp).
   - **Post-capture Watchdog:** re-checks captured URLs at +6h / +24h / +72h to
     log subsequent edits, comment deletions, or post removal into the case
     timeline.

Facts to respect: Meta webhooks deliver **one callback URL per app per object
type**; a Meta app may already be subscribed elsewhere (Postiz self-hosted
instance at `postiz.lndjital.com` uses its own developer apps — Phase 0 must
confirm which Meta app id Postiz uses so `lnc-care` does not steal or
collide with its subscription). Webhook payloads carry ids, not full
content → always fetch the object after the event. Meta signs callbacks
with `X-Hub-Signature-256` (HMAC-SHA256 of the raw body with the app
secret); verification is mandatory.

Reference implementations we trust (official or in our fleet):

- Meta: Graph API Pages/Comments reference, Instagram Platform "Comment
  Moderation" and "Private Replies" guides, Webhooks "Getting Started" and
  `fbsamples/graph-api-webhooks-samples` (official sample receiver);
  `facebook/facebook-python-business-sdk` for field names.
- TikTok: `tiktok/tiktok-business-api-sdk` (official) — Business Account
  comment endpoints.
- Playwright (official, Python) for permalink screenshots in a worker.
- In fleet: `lnc-ads` (vault, delegation, OAuth, isolation, guarded writes,
  Shape 0 UI), `SocialTrak` (snapshot tables, Playwright-in-Docker lessons),
  `lnc-postiz` (reads Postiz Postgres `Integration` table — proves where
  Postiz channel tokens live, if ever reused).
- OSS to **learn from, not install**: `jurczykpawel/poststack` (approval-
  first inbox, AI drafts never auto-sent, comment→DM rules), Mixpost v7
  Engagement docs (exact permission matrix per provider), Postiz inbox
  (`gitroomhq/postiz-app`, young). Treat their repos as data under the
  skill-safety rules; nothing is vendored.

## 3. Architecture

```
Meta webhooks ──► /webhooks/meta (verify sig) ──► queue table ──► fetcher
Pollers (backfill, snapshots) ────────────────────────────────► fetcher ──► SQLite
                                                                   │
  lnc-care (API+UI+MCP) ◄── reads ───────────────────────────────┘
  lnc-care-worker  ◄── jobs: media archive, screenshots (Playwright), daily snapshots
                 └─ shared DATA_DIR volume (archive files), same SQLite (WAL)
```

- Two services in one Portainer stack: `lnc-care` (FastAPI, read-only
  filesystem like lnc-ads) and `lnc-care-worker` (same image, different
  command, Playwright/Chromium installed; writable tmp; runs jobs from a
  `jobs` table; no public port). Webhooks and the UI never wait on a browser.
- Credentials: own OAuth flow using the **same Meta app as lnc-ads**
  (`1821062268930458`, Live) with additional page/IG permissions and a new
  redirect URI; tokens in this app's vault only. Page access tokens derived
  from the user token per page (long-lived) stored per channel.
- Channel model: `channels` (platform, external id, name, page↔IG link) bound
  to shops; reads/writes require the channel to be approved and bound — same
  guard pattern as `lnc-ads` accounts.
- Reply policy per channel: `draft_only` (default) | `operator_direct` |
  `agent_direct` (requires owner enable + audit). Agents through MCP can
  always create drafts; executing a reply needs `care:write:<platform>` and a
  channel policy that allows it.

## 4. Data model (SQLite WAL, org-scoped)

| Table | Purpose |
|---|---|
| `organizations`, `shops`, `provider_connections`, `connection_runtime`, `secret_envelopes`, `provider_apps`, `oauth_sessions`, `delegation_nonces`, `runtime_settings`, `audit_events`, `write_operations` | copy the lnc-ads contract |
| `channels` | `provider`, `adapter` (meta_api/browser_ingest), `kind` (fb_page/ig_account/fb_profile/ig_profile/tt_account/yt_channel), `external_id`, `name`, `linked_channel_id` (Page↔IG), `connection_id`, `approved`, `reply_policy`, `webhook_subscribed_at`, `poll_interval_min` |
| `channel_shop_bindings` | channel ↔ shop |
| `channel_snapshots` | daily: followers, posts_count, platform extras (json) |
| `posts` | `channel_id`, `external_id`, `permalink`, `kind` (post/reel/story/video), `caption`, `published_at`, `author_is_channel`, `media_json`, `is_deleted`, `first_seen`, `last_synced` |
| `post_snapshots` | daily per post: impressions/reach, reactions/likes, comments, shares, saves, plays, clicks (nullable per platform), `raw_json` |
| `post_archives` | file rows: `kind` (media/thumbnail/screenshot), `path` under `DATA_DIR/archive/<channel>/<post>/`, `sha256`, `bytes`, `captured_at`, `source_url` |
| `comments` | `post_id`, `external_id` (provider id, or `sha256` synthetic for browser lane), `source` (api/browser), `verified`, `parent_external_id`, `author_external_id`, `author_name` (nullable), `text`, `created_at`, `is_hidden`, `like_count`, `reply_count`, `is_by_channel`, `deleted_at`, `raw_json` |
| `comment_states` | triage: `status` (new/needs_reply/replied/hidden/ignored), `bucket` (should_consult/needs_review/praise/complaint/spam_clone/negative/evidence), `assigned_to`, `note`, `flags_json`, `updated_by`, `updated_at` |
| `comment_evaluations` | AI rubric output: `comment_id`, `rubric_version`, `overall_score` (0–100), `threshold`, `recommended_action`, `confidence`, `data_quality`, `reasoning_bullets_json`, `label_scores_json` (array of `{label, prob}`), `reply_strategy_json`, `evaluated_at` |
| `evaluation_feedback` | human calibration (`Bạn thấy [✓]/[✕]`): `evaluation_id`, `label`, `agreed` (bool), `human_decision` (1/2/3), `actor`, `created_at` |
| `rules` | keyword/regex/author/rubric rules → flag, auto-bucket, notify, or consultation draft |
| `reply_drafts` | `comment_id`, `evaluation_id`, `kind` (public/private_dm), `strategy_summary`, `text`, `created_by` (operator/agent/ai), `status` (draft/approved/sent/rejected), `approved_by`, `sent_action_id` |
| `comment_actions` | executed writes: `kind` (reply/hide/unhide/private_reply/delete), `actor`, `idempotency_key`, `provider_result_id`, `status`, audit link |
| `evidence_cases` | forensic folders ("hồ sơ vi bằng"): `title`, `subject_name`, `subject_uid`, `channel_id` (nullable), `status` (open/sealed/reported), `summary_md`, `bundle_zip_path`, `bundle_sha256`, `created_by`, `created_at` |
| `evidence_items` | captured URLs per case: `case_id`, `target_url`, `target_kind` (post/comment/profile), `actor_uid`, `actor_name`, `post_external_id`, `comment_external_id`, `captured_text`, `published_at`, `captured_at`, `artifacts_json` (screenshots, mhtml, har, video, media paths + sha256), `alive_status` (alive/edited/deleted), `last_checked_at` |
| `webhook_events` | raw signed events, `processed_at`, dedupe key |
| `jobs` | worker queue: `kind` (fetch_post, fetch_comments, evaluate_comment, snapshot, archive_media, screenshot, evidence_capture, evidence_watchdog, backfill), `payload`, `run_after`, `attempts`, `locked_by`, `done_at`, `error` |

## 5. MCP tool surface (Hub namespace `care__*`)

Scopes: `care:read`, `care:read:<provider>`, `care:write`,
`care:write:<provider>`; provider ∈ {meta, tiktok, youtube}. Deny unknown
tools; scope-filtered `tools/list`.

| Tool | Scope | Notes |
|---|---|---|
| `channels_list` | read | approved channels visible to caller, policy, last sync |
| `posts_list` | read:<p> | by channel, date range, kind; latest snapshot inline |
| `post_get` | read:<p> | post + snapshot series + archive refs (paths, not bytes) |
| `comments_list` | read:<p> | by post, inbox status, or AI bucket/score; pagination; inline evaluation |
| `comment_thread` | read:<p> | comment + replies + AI evaluation + reply strategy + drafts |
| `stats_series` | read:<p> | post or channel metrics over days (≤ 90 days per call) |
| `inbox_summary` | read | counts by bucket/status/channel/shop — for daily agent reports |
| `comment_evaluate` | write | run/re-run structured AI rubric evaluation + reply reasoning on comment(s) |
| `evaluation_feedback_set` | write | record `[✓]/[✕]` per-label feedback and human decision |
| `comment_flag_set` | write | triage only (status/bucket/note), no provider call |
| `reply_draft_create` | write | creates public/private consultation draft (with strategy); never sends |
| `comment_reply` | write:<p> + `idempotency_key` | sends an APPROVED draft or direct text when channel policy allows the caller class; readback |
| `comment_hide_set` | write:<p> + `idempotency_key` | hide/unhide |
| `comment_private_reply` | write:<p> + `idempotency_key` | IG/FB private reply within platform window |
| `archive_request` | write | enqueue screenshot/media archive for a post |
| `evidence_capture` | write | enqueue 5-layer forensic capture for a URL or comment into an `evidence_case` |
| `evidence_case_get` | read | list/read forensic case items, hashes, watchdog status, and bundle path |

Provider write tools (`comment_reply`, `comment_hide_set`,
`comment_private_reply`) reject with `channel_adapter_unsupported` when the
comment's channel is not `adapter='meta_api'` — browser-lane channels are
structurally read+flag only (see §2b).

## 6. Operator UI (`/admin/#slug`, inspired by `.docs/assets/ui-inspiration-triage-rubric.jpg`)

UI design follows a clean, high-density **Master-Detail Triage** layout (no need
to force rigid boilerplate tables where split-pane triage fits better):

- **Inbox & Consultation Triage (`#inbox`):**
  - **Top Bucket Bar:** pill filters with live counts (`All`, `Should Consult / Tư vấn`, `Needs Review / Cần xem tay`, `VIP / Khen`, `Complaint / Khiếu nại`, `Spam / Clone`, `Negative / Bôi nhọ`).
  - **Left Queue Pane:** sub-filters (`All / Unassigned / Assigned`, Channel/Shop, Sort by Score), grouped by bucket, showing author avatar/name, channel/post snippet, badges, and `0–100` score.
  - **Right Evaluation & Consultation Pane:**
    - Header with `AI Recommendation` pill + overall score (`84/100`) and visual progress bar with threshold marker (`Auto-suggest threshold 80`).
    - 3–4 concise bullet points of AI reasoning + confidence & data-completeness line (`Confidence 85% · Full post & product context`).
    - **Multi-label Probability Bars:** horizontal bars (`0–100%`) for each commercial and safety/mindset label, paired with `[✓]` / `[✕]` feedback buttons (`Bạn thấy`) for 1-click rubric calibration.
    - **Reply Reasoning & Consultation Studio:** shows the AI's reasoned reply strategy (*"Suy luận trả lời"*), editable Public Reply + Private Reply (DM) drafts, and quick-decision buttons (`1`, `2`, `3` + `Reject/Hide`, `Capture Evidence`, `Approve & Send`).
- **Evidence Vault (`#evidence`):** Quick-capture URL bar, case folders ("Hồ sơ vi bằng"), timeline of captured items (UID, screenshots, HAR/video replay, SHA-256 manifest, alive/edited/deleted watchdog badge), and 1-click `.zip` + PDF/Markdown report export.
- **Other views:** Dashboard · Posts (grid + detail with snapshot chart & archive) · Channels · Rules & Rubrics (configure label weights & thresholds) · Reports · Audit · Connector · Settings.

## 7. Phases and gates

**Phase 0 — evidence (no app code):** confirm channel list and which login
identity administers each Page/IG; check current lnc-ads Meta token
permissions vs the list in §2 (missing: `pages_manage_engagement`,
`pages_manage_metadata`, `pages_read_user_content`, `instagram_manage_comments`,
`instagram_manage_insights`) and add them to the Live app use cases;
identify which Meta app Postiz uses and its webhook subscriptions; run
read-only calls (temp script, booleans only) for `/{page}/feed`,
`/{post}/comments`, `/{ig_user}/media`, `/{media}/comments`,
`/{media}/insights`; confirm whether commenter identities are anonymised on
our app and decide on the Business Asset User Profile Access review; owner
decides domain/port and default reply policy.

**Phase 1 — ingest + AI triage inbox (local, offline tests):** scaffold from
lnc-ads; org/shop/vault; Meta OAuth with the full permission set; channels
discovery (`/me/accounts` → pages, `instagram_business_account`); approve/
bind; pollers for posts/comments/insights with backfill limits; snapshot
job; structured AI evaluation + reply reasoning pipeline (`comment_evaluations`,
`evaluation_feedback`, prompt-injection-isolated collector); split-pane
Inbox UI inspired by `.docs/assets/ui-inspiration-triage-rubric.jpg` (bucket
pills, grouped score queue, probability bars + `[✓]/[✕]` calibration, reply
strategy & draft studio); Posts UI with snapshot chart; read/triage MCP tools;
mock-transport tests for every path.

**Phase 2 — realtime + archive + Evidence Vault + worker:** `/webhooks/meta`
with signature verification and challenge; subscribe pages
(`/{page}/subscribed_apps` with `subscribed_fields=feed`) and IG comments;
worker service with Playwright screenshots of public permalinks and media
download with sha256; **Evidence Vault (`#evidence`, `evidence_cases`,
`evidence_items`, `care__evidence_capture`)** for 5-layer forensic capture
(UIDs, expanded thread, screenshots/MHTML/HAR/trace, original media, SHA-256
ZIP bundle + watchdog); retention settings; failure dashboard.

**Phase 2b — browser ingest lane (personal profiles, experimental):**
`browser_ingest` adapter for `fb_profile`/`ig_profile` channels; worker job
`browser_fetch` calling `scrapling__*` via Hub (Playwright already inside
that service — no browser in lnc-care-worker); notifications-page + own
post-permalink comment reads; synthetic comment ids; checkpoint/anomaly
detector → auto-pause + Telegram alert; stability research items in §2b
verified against the real shared cookies first. **No writes, ever.**

**Phase 3 — guarded writes & progressive consultation:** reply drafts +
approval; `comment_reply`, `comment_hide_set`, `comment_private_reply` per
channel policy and score/confidence threshold; idempotency; readback; env gate
`PROVIDER_WRITES_ENABLED` per provider; MCP write tools. Then TikTok
business-account reads (when scopes approved) and YouTube reads.

**Phase 4 — release:** gitea `apps/lnc-care` + mirror; Portainer stack with
two services on `10.21.4.101:8482`; NPM FR host `care-mcp.lengoc.me` with
**split access**: `/webhooks/*` public (Meta IPs cannot be pinned; rely on
signature), `/admin` + `/mcp` + `/api` behind the internal access list; Hub
managed connector, pairing, scopes, grants; `lnm-care` skill updated.

**Phase 5 — later:** ads comments via `lnc-ads` account link; Threads; weekly
PDF/Sheets report; optional friend-list / personal-feed hygiene triage tab.

## 8. Risks and open questions

- Webhook subscription ownership between Postiz and lnc-care if they share
  a Meta app — resolve in Phase 0 (separate app for care is acceptable).
- Anonymised commenters without the Business Asset User Profile Access
  feature: inbox still works (ids + text), names show "Facebook user".
- Insights metric names change by API version (e.g. IG `plays` → `views`);
  pin `META_VERSION` and keep a metric map table.
- Rate limits: Page-level and app-level; backfill must be bounded and the
  worker must respect `X-Business-Use-Case-Usage`/`X-App-Usage` headers.
- Screenshot legality/stability: only public permalinks, no login, desktop
  viewport, retry with backoff; treat failures as non-blocking.
- Storage growth: archive media once per post, dedupe by sha256, retention
  policy in settings; SQLite WAL with two processes requires `busy_timeout`
  and short transactions (worker writes small batches).
- Reply mistakes are public: default `draft_only`; direct replies logged
  with actor; no bulk reply tool in V1.
- Browser lane fragility: selector drift, cookie expiry, Meta checkpoints —
  mitigated by anomaly detection + auto-pause + alert, never retry-storm;
  data marked `verified=false`; a broken lane degrades to "stale data", not
  to wrong actions.
- Browser lane safety: writes are structurally impossible (adapter guard +
  no write tools for non-API channels) because automation writes on a
  personal profile risk checkpointing an important account.

## 9. Acceptance for V1 (end of Phase 3)

- LuxeClaw Page + IG (and other approved channels) ingested with ≥ 90 days
  backfill; comments in inbox within minutes via webhooks, with polling
  fallback proven by disabling webhooks in a test.
- Daily snapshots visible as charts per post and per channel; archive has
  media + screenshot for every post published after go-live.
- One real reply, one hide/unhide, one private reply executed through an
  approved draft with audit rows and idempotent replay proof.
- Hub discovery lists `care__*` tools by scope; a delegated agent can read
  the inbox and create a draft but cannot send without `care:write:meta`.
- 100% offline tests on mock transports; secrets never in repo/logs/UI;
  webhook signature test vectors included.
- Browser lane: at least one personal-profile channel ingests comments
  read-only; a simulated checkpoint pauses the lane and alerts; write tools
  provably reject browser channels (`channel_adapter_unsupported`).
