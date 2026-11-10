# Handoff — LNC Care (start here in a fresh conversation)

Prepared 2026-10-26 by the planning session. This repo is EMPTY of code on
purpose; you own implementation from Phase 0. Authorization state: local
development is expected to be approved by the owner when he opens your
conversation; production, provider credentials, webhook subscriptions, DNS,
Hub grants remain gated.

## Read in this order (≤ 20 minutes)

1. `AGENTS.md` (this repo) — boundaries.
2. `.docs/plan.md` — architecture (app + worker), data model, tool surface,
   phases, platform evidence table.
3. `.docs/task.md` — checklist; tick with evidence only.
4. Skills: `lnc-internal-app-blueprint` (Shape 0 contract, UI rules incl.
   flush-table 18px padding, dual theme), `business-mcp-connector` (read the
   three Hub docs it points to), `release-portainer-app`, `lnc-icon`,
   `w5-versioningconvention`, `w13-skill-safety-review`.
5. Reference code: `D:\Python\projects\lnc-ads\app\` — `vault.py`,
   `mcp_server.py` (delegation, scope filtering, guarded_write, idempotency),
   `connections.py` (OAuth, isolation, context re-check), `store.py`,
   `settings.py`, `providers.py`, `tests/test_mcp.py`. Also
   `D:\Python\projects\SocialTrak` for snapshot tables and Playwright-in-
   Docker lessons, and `D:\Python\projects\lnc-postiz\app\postiz_upstream.py`
   for how Postiz channel inventory is read (information only).
6. Research: `\\10.21.2.2\data\_agentsync\research\lnm-social-care-accounts-research.md`
   (sections A, B, D) and the quarantined OSS copies under
   `\\10.21.2.2\data\_agentsync\research\` if you clone `poststack` /
   `postiz-app` for reading — follow `README-QUARANTINE.md` rules there
   (read only, rename upstream `CLAUDE.md`/`AGENTS.md` to `*.upstream.txt`,
   never install or run their installers).

## Decisions already taken (do not reopen without the owner)

- Repo/app/audience/namespace: `lnc-care`, Hub tools `care__*`. User-facing
  skill: `lnm-care` (stub exists at
  `C:\Users\ngocl\.agents\skills\lnm-care\SKILL.md`; update at release).
- Shape 0 (FastAPI + SQLite + vanilla UI) plus a separate worker service in
  the same stack for Playwright screenshots / media archive. English UI.
- Scope V1: owned Facebook Pages + Instagram professional accounts.
  TikTok business accounts and YouTube after V1. Publishing stays in Postiz;
  DMs out of scope; external channel tracking stays in SocialTrak.
- Same Meta app as lnc-ads (`1821062268930458`, Live) with extra page/IG
  permissions and its own OAuth grant/redirect in this app — unless Phase 0
  shows a webhook collision with Postiz, in which case a dedicated Meta app
  for care is acceptable. Tokens never shared across apps.
- Reply policy per channel, default `draft_only`; writes guarded (scope +
  idempotency + approval + audit); no auto-reply rules in V1.
- Proposed deploy: `10.21.4.101:8482`, `care-mcp.lengoc.me`, NPM FR with
  `/webhooks/*` public (signature-verified) and everything else behind the
  internal access list. Verify port free immediately before deploy.

## Open items you must settle with the owner first (Phase 0)

- Channel list for V1 and administering identities.
- Which Meta app Postiz uses and its webhook subscriptions.
- Default reply policy and approvers; retention for archives.
- Whether to request Business Asset User Profile Access (commenter names).

## Working rules

- Project root = this directory; docs in `.docs/`; temp scripts in
  `temp_scripts/` (never print tokens; booleans only).
- Never put provider tokens in MCP args, Git, logs, chat or summaries.
- Webhook handler must verify `X-Hub-Signature-256` before any processing
  and answer within seconds; heavy work goes to the `jobs` table.
- Use RTK for long output. Commit with VERSION bump. No Git remote, deploy,
  webhook subscription or Hub change until the owner says so. Do not edit
  Business MCP Hub, lnc-ads, lnc-postiz or lnc-accounts from this
  conversation.
- Run `w13-skill-safety-review` before using any new external skill/repo.

## First actions suggested

1. Confirm the open items above with the owner.
2. Phase 0 temp script against the existing lnc-ads Meta token (inside the
   lnc-ads container over ssh `llm`, `Vault(key)`, booleans/counts only):
   `/{page}/feed?limit=3`, `/{post}/comments`, `/{ig_user}/media?limit=3`,
   `/{media}/comments`, `/{media}/insights`. Record which permissions are
   missing.
3. Scaffold Phase 1 from lnc-ads patterns; first commit `0.1.0.0`.

## Report format when you hand back

Repo path, branch, commit, push status (none expected until approved),
tests run, what was proven live vs offline, remaining dirty files, open
decisions. Do not infer PR/deploy status from passing tests.
