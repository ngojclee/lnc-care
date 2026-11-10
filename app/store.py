"""Organization-scoped SQLite WAL store for LNC Care."""
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

PROVIDERS = ("meta", "tiktok", "youtube")
ADAPTERS = ("meta_api", "browser_ingest", "veilbrowser", "orbine_mobile", "scrapling_public")
CHANNEL_ADAPTERS = ADAPTERS
CHANNEL_KINDS = ("fb_page", "ig_account", "fb_profile", "ig_profile", "tt_account", "yt_channel")
REPLY_POLICIES = ("draft_only", "operator_direct", "agent_direct")
COMMENT_STATUSES = ("new", "needs_reply", "replied", "hidden", "ignored")
COMMENT_BUCKETS = (
    "should_consult",
    "needs_review",
    "praise",
    "complaint",
    "spam_clone",
    "negative",
    "evidence",
)

SCHEMA = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    UNIQUE (organization_id, name),
    UNIQUE (organization_id, id)
);

CREATE TABLE IF NOT EXISTS provider_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    provider TEXT NOT NULL CHECK (provider IN ('meta', 'tiktok', 'youtube')),
    label TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('not_connected', 'pending_review', 'verified', 'expired')),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, id, provider)
);

CREATE TABLE IF NOT EXISTS provider_apps (
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    provider TEXT NOT NULL CHECK (provider IN ('meta', 'tiktok', 'youtube')),
    client_id TEXT NOT NULL,
    project_id TEXT NOT NULL DEFAULT '',
    webhook_verify_token TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL,
    PRIMARY KEY (organization_id, provider)
);

CREATE TABLE IF NOT EXISTS connection_runtime (
    organization_id TEXT NOT NULL,
    connection_id INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    app_revision INTEGER NOT NULL,
    expires_at INTEGER,
    last_success INTEGER,
    last_error TEXT,
    PRIMARY KEY (organization_id, connection_id),
    FOREIGN KEY (organization_id, connection_id) REFERENCES provider_connections(organization_id, id)
);

CREATE TABLE IF NOT EXISTS oauth_sessions (
    state_hash TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    connection_id INTEGER NOT NULL,
    session_hash TEXT NOT NULL,
    app_revision INTEGER NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (organization_id, connection_id) REFERENCES provider_connections(organization_id, id)
);

CREATE TABLE IF NOT EXISTS discovered_channels (
    organization_id TEXT NOT NULL,
    connection_id INTEGER NOT NULL,
    external_id TEXT NOT NULL,
    channel_json TEXT NOT NULL,
    connection_revision INTEGER NOT NULL,
    discovered_at INTEGER NOT NULL,
    PRIMARY KEY (organization_id, connection_id, external_id),
    FOREIGN KEY (organization_id, connection_id) REFERENCES provider_connections(organization_id, id)
);

CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    connection_id INTEGER,
    provider TEXT NOT NULL CHECK (provider IN ('meta', 'tiktok', 'youtube')),
    adapter TEXT NOT NULL DEFAULT 'meta_api'
      CHECK (adapter IN ('meta_api', 'browser_ingest', 'veilbrowser', 'orbine_mobile', 'scrapling_public')),
    kind TEXT NOT NULL CHECK (kind IN ('fb_page', 'ig_account', 'fb_profile', 'ig_profile', 'tt_account', 'yt_channel')),
    external_id TEXT NOT NULL,
    name TEXT NOT NULL,
    handle TEXT NOT NULL DEFAULT '',
    linked_channel_id INTEGER,
    approved INTEGER NOT NULL DEFAULT 0 CHECK (approved IN (0, 1)),
    reply_policy TEXT NOT NULL DEFAULT 'draft_only'
      CHECK (reply_policy IN ('draft_only', 'operator_direct', 'agent_direct')),
    auto_suggest_threshold INTEGER NOT NULL DEFAULT 80 CHECK (auto_suggest_threshold BETWEEN 1 AND 100),
    webhook_subscribed_at INTEGER,
    poll_interval_min INTEGER NOT NULL DEFAULT 15 CHECK (poll_interval_min >= 1),
    last_synced_at INTEGER,
    UNIQUE (organization_id, provider, external_id),
    UNIQUE (organization_id, id)
);

CREATE TABLE IF NOT EXISTS channel_shop_bindings (
    organization_id TEXT NOT NULL,
    shop_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    PRIMARY KEY (organization_id, shop_id, channel_id),
    FOREIGN KEY (organization_id, shop_id) REFERENCES shops(organization_id, id),
    FOREIGN KEY (organization_id, channel_id) REFERENCES channels(organization_id, id)
);

CREATE TABLE IF NOT EXISTS operator_channel_preferences (
    organization_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    shop_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    channel_id INTEGER NOT NULL,
    PRIMARY KEY (organization_id, operator_id, shop_id, provider),
    FOREIGN KEY (organization_id, shop_id, channel_id)
      REFERENCES channel_shop_bindings(organization_id, shop_id, channel_id)
);

CREATE TABLE IF NOT EXISTS channel_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    channel_id INTEGER NOT NULL,
    snapshot_date TEXT NOT NULL,
    followers_count INTEGER NOT NULL DEFAULT 0,
    posts_count INTEGER NOT NULL DEFAULT 0,
    extras_json TEXT NOT NULL DEFAULT '{}',
    captured_at INTEGER NOT NULL,
    UNIQUE (organization_id, channel_id, snapshot_date),
    FOREIGN KEY (organization_id, channel_id) REFERENCES channels(organization_id, id)
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    channel_id INTEGER NOT NULL,
    external_id TEXT NOT NULL,
    permalink TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'post' CHECK (kind IN ('post', 'reel', 'story', 'video')),
    caption TEXT NOT NULL DEFAULT '',
    published_at INTEGER NOT NULL,
    author_is_channel INTEGER NOT NULL DEFAULT 1 CHECK (author_is_channel IN (0, 1)),
    media_json TEXT NOT NULL DEFAULT '[]',
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),
    first_seen INTEGER NOT NULL,
    last_synced INTEGER NOT NULL,
    UNIQUE (organization_id, channel_id, external_id),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, channel_id) REFERENCES channels(organization_id, id)
);

CREATE TABLE IF NOT EXISTS post_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    post_id INTEGER NOT NULL,
    snapshot_date TEXT NOT NULL,
    impressions INTEGER NOT NULL DEFAULT 0,
    reach INTEGER NOT NULL DEFAULT 0,
    reactions INTEGER NOT NULL DEFAULT 0,
    comments_count INTEGER NOT NULL DEFAULT 0,
    shares INTEGER NOT NULL DEFAULT 0,
    saves INTEGER NOT NULL DEFAULT 0,
    plays INTEGER NOT NULL DEFAULT 0,
    clicks INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL DEFAULT '{}',
    captured_at INTEGER NOT NULL,
    UNIQUE (organization_id, post_id, snapshot_date),
    FOREIGN KEY (organization_id, post_id) REFERENCES posts(organization_id, id)
);

CREATE TABLE IF NOT EXISTS post_archives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    post_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('media', 'thumbnail', 'screenshot')),
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    bytes INTEGER NOT NULL DEFAULT 0,
    captured_at INTEGER NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (organization_id, post_id) REFERENCES posts(organization_id, id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    post_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    external_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'api' CHECK (source IN ('api', 'browser')),
    verified INTEGER NOT NULL DEFAULT 1 CHECK (verified IN (0, 1)),
    parent_external_id TEXT,
    author_external_id TEXT NOT NULL DEFAULT '',
    author_name TEXT NOT NULL DEFAULT 'Social User',
    author_meta TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    is_hidden INTEGER NOT NULL DEFAULT 0 CHECK (is_hidden IN (0, 1)),
    like_count INTEGER NOT NULL DEFAULT 0,
    reply_count INTEGER NOT NULL DEFAULT 0,
    is_by_channel INTEGER NOT NULL DEFAULT 0 CHECK (is_by_channel IN (0, 1)),
    deleted_at INTEGER,
    raw_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (organization_id, channel_id, external_id),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, post_id) REFERENCES posts(organization_id, id),
    FOREIGN KEY (organization_id, channel_id) REFERENCES channels(organization_id, id)
);

CREATE TABLE IF NOT EXISTS comment_states (
    organization_id TEXT NOT NULL,
    comment_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'new'
      CHECK (status IN ('new', 'needs_reply', 'replied', 'hidden', 'ignored')),
    bucket TEXT NOT NULL DEFAULT 'needs_review'
      CHECK (bucket IN ('should_consult', 'needs_review', 'praise', 'complaint', 'spam_clone', 'negative', 'evidence')),
    assigned_to TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    flags_json TEXT NOT NULL DEFAULT '[]',
    human_decision INTEGER,
    updated_by TEXT NOT NULL DEFAULT 'system',
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (organization_id, comment_id),
    FOREIGN KEY (organization_id, comment_id) REFERENCES comments(organization_id, id)
);

CREATE TABLE IF NOT EXISTS comment_evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    comment_id INTEGER NOT NULL,
    rubric_version TEXT NOT NULL DEFAULT 'v1',
    overall_score REAL NOT NULL DEFAULT 50.0,
    threshold INTEGER NOT NULL DEFAULT 80,
    recommended_action TEXT NOT NULL DEFAULT 'needs_review',
    tier_label TEXT NOT NULL DEFAULT 'Tier 3/5: Review',
    confidence INTEGER NOT NULL DEFAULT 75,
    data_quality TEXT NOT NULL DEFAULT 'Full post & comment context',
    reasoning_bullets_json TEXT NOT NULL DEFAULT '[]',
    label_scores_json TEXT NOT NULL DEFAULT '[]',
    reply_strategy_json TEXT NOT NULL DEFAULT '{}',
    evaluated_at INTEGER NOT NULL,
    UNIQUE (organization_id, comment_id),
    FOREIGN KEY (organization_id, comment_id) REFERENCES comments(organization_id, id)
);

CREATE TABLE IF NOT EXISTS evaluation_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    comment_id INTEGER NOT NULL,
    label TEXT NOT NULL,
    agreed INTEGER NOT NULL CHECK (agreed IN (0, 1)),
    human_decision INTEGER,
    actor TEXT NOT NULL DEFAULT 'owner',
    created_at INTEGER NOT NULL,
    UNIQUE (organization_id, comment_id, label),
    FOREIGN KEY (organization_id, comment_id) REFERENCES comments(organization_id, id)
);

CREATE TABLE IF NOT EXISTS consultation_playbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    shop_id INTEGER,
    channel_id INTEGER,
    name TEXT NOT NULL,
    auto_suggest_threshold INTEGER NOT NULL DEFAULT 80,
    auto_consult_enabled INTEGER NOT NULL DEFAULT 0 CHECK (auto_consult_enabled IN (0, 1)),
    consultation_knowledge_md TEXT NOT NULL DEFAULT '',
    forbidden_topics_json TEXT NOT NULL DEFAULT '[]',
    updated_at INTEGER NOT NULL,
    UNIQUE (organization_id, id)
);

CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    match_kind TEXT NOT NULL DEFAULT 'keyword' CHECK (match_kind IN ('keyword', 'regex', 'author')),
    flag TEXT NOT NULL DEFAULT 'flagged',
    auto_status TEXT NOT NULL DEFAULT 'needs_reply'
      CHECK (auto_status IN ('new', 'needs_reply', 'replied', 'hidden', 'ignored')),
    auto_bucket TEXT NOT NULL DEFAULT 'needs_review'
      CHECK (auto_bucket IN ('should_consult', 'needs_review', 'praise', 'complaint', 'spam_clone', 'negative', 'evidence')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS reply_drafts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    comment_id INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'public' CHECK (kind IN ('public', 'private_dm')),
    strategy_summary TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    created_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'sent', 'rejected')),
    approved_by TEXT,
    sent_action_id INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, comment_id) REFERENCES comments(organization_id, id)
);

CREATE TABLE IF NOT EXISTS comment_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    comment_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('reply', 'hide', 'unhide', 'private_reply', 'delete')),
    actor TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    provider_result_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'completed',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    UNIQUE (organization_id, idempotency_key),
    FOREIGN KEY (organization_id, comment_id) REFERENCES comments(organization_id, id)
);

CREATE TABLE IF NOT EXISTS evidence_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    title TEXT NOT NULL,
    subject_name TEXT NOT NULL DEFAULT '',
    subject_uid TEXT NOT NULL DEFAULT '',
    channel_id INTEGER,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'sealed', 'reported')),
    summary_md TEXT NOT NULL DEFAULT '',
    bundle_zip_path TEXT NOT NULL DEFAULT '',
    bundle_sha256 TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'owner',
    created_at INTEGER NOT NULL,
    UNIQUE (organization_id, id)
);

CREATE TABLE IF NOT EXISTS evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    case_id INTEGER NOT NULL,
    comment_id INTEGER,
    target_url TEXT NOT NULL,
    target_kind TEXT NOT NULL DEFAULT 'comment' CHECK (target_kind IN ('post', 'comment', 'profile')),
    actor_uid TEXT NOT NULL DEFAULT '',
    actor_name TEXT NOT NULL DEFAULT '',
    post_external_id TEXT NOT NULL DEFAULT '',
    comment_external_id TEXT NOT NULL DEFAULT '',
    captured_text TEXT NOT NULL DEFAULT '',
    published_at INTEGER,
    captured_at INTEGER NOT NULL,
    artifacts_json TEXT NOT NULL DEFAULT '{}',
    manifest_sha256 TEXT NOT NULL DEFAULT '',
    alive_status TEXT NOT NULL DEFAULT 'alive' CHECK (alive_status IN ('alive', 'edited', 'deleted')),
    last_checked_at INTEGER NOT NULL,
    FOREIGN KEY (organization_id, case_id) REFERENCES evidence_cases(organization_id, id)
);

CREATE TABLE IF NOT EXISTS account_runtimes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    shop_id INTEGER,
    label TEXT NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('facebook', 'instagram', 'tiktok', 'youtube')),
    account_role TEXT NOT NULL DEFAULT 'care_consultant'
      CHECK (account_role IN ('owned_page', 'personal_main', 'care_consultant', 'friend_hygiene', 'evidence_scout')),
    adapter TEXT NOT NULL DEFAULT 'veilbrowser'
      CHECK (adapter IN ('meta_api', 'veilbrowser', 'orbine_mobile', 'scrapling_public')),
    runtime_profile_id TEXT NOT NULL,
    expected_exit_ip TEXT NOT NULL DEFAULT '',
    expected_country TEXT NOT NULL DEFAULT 'FR',
    health_status TEXT NOT NULL DEFAULT 'healthy'
      CHECK (health_status IN ('healthy', 'warming', 'leased', 'cooldown', 'checkpointed', 'disabled')),
    consecutive_anomalies INTEGER NOT NULL DEFAULT 0,
    daily_read_budget INTEGER NOT NULL DEFAULT 120,
    daily_write_budget INTEGER NOT NULL DEFAULT 20,
    reads_today INTEGER NOT NULL DEFAULT 0,
    writes_today INTEGER NOT NULL DEFAULT 0,
    last_lease_at INTEGER,
    last_checkpoint_reason TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    UNIQUE (organization_id, adapter, runtime_profile_id),
    UNIQUE (organization_id, id)
);

CREATE TABLE IF NOT EXISTS runtime_leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    runtime_id INTEGER NOT NULL,
    job_id INTEGER,
    worker_id TEXT NOT NULL,
    leased_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    released_at INTEGER,
    exit_ip_verified INTEGER NOT NULL DEFAULT 1 CHECK (exit_ip_verified IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed', 'aborted_anomaly')),
    FOREIGN KEY (organization_id, runtime_id) REFERENCES account_runtimes(organization_id, id)
);

CREATE TABLE IF NOT EXISTS webhook_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    provider TEXT NOT NULL DEFAULT 'meta',
    dedupe_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    processed_at INTEGER,
    UNIQUE (organization_id, dedupe_key)
);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    kind TEXT NOT NULL CHECK (kind IN (
        'fetch_post', 'fetch_comments', 'evaluate_comment', 'snapshot',
        'archive_media', 'screenshot', 'evidence_capture', 'evidence_watchdog',
        'browser_fetch', 'backfill'
    )),
    payload_json TEXT NOT NULL DEFAULT '{}',
    run_after INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    locked_by TEXT,
    done_at INTEGER,
    error TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    sequence INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    PRIMARY KEY (organization_id, sequence)
);

CREATE TABLE IF NOT EXISTS runtime_settings (
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (organization_id, key)
);

CREATE TABLE IF NOT EXISTS secret_envelopes (
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    envelope TEXT NOT NULL,
    PRIMARY KEY (organization_id, kind, subject)
);

CREATE TABLE IF NOT EXISTS delegation_nonces (
    organization_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (organization_id, nonce)
);

CREATE TABLE IF NOT EXISTS write_operations (
    organization_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    tool TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json TEXT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (organization_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_channels_org ON channels(organization_id, provider);
CREATE INDEX IF NOT EXISTS idx_posts_channel ON posts(organization_id, channel_id, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(organization_id, post_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_channel ON comments(organization_id, channel_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comment_states_bucket ON comment_states(organization_id, bucket, status);
CREATE INDEX IF NOT EXISTS idx_jobs_pending ON jobs(organization_id, done_at, run_after);
"""


@contextmanager
def connect(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    try:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def connect_readonly(path: Path):
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        yield db
    finally:
        db.close()


def initialize(path: Path, organization_id: str, organization_name: str) -> None:
    with connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript(SCHEMA)
        db.execute(
            "INSERT OR IGNORE INTO organizations (id, name) VALUES (?, ?)",
            (organization_id, organization_name),
        )


def shops(db: sqlite3.Connection, organization_id: str) -> list[dict]:
    return [
        dict(row)
        for row in db.execute(
            "SELECT id, name FROM shops WHERE organization_id=? ORDER BY name", (organization_id,)
        )
    ]


def channels(
    db: sqlite3.Connection,
    organization_id: str,
    shop_id: int | None = None,
    approved_only: bool = False,
) -> list[dict]:
    query = """
        SELECT c.*,
               conn.state AS connection_state,
               s.shop_id AS bound_shop_id,
               (SELECT GROUP_CONCAT(b.shop_id) FROM channel_shop_bindings b
                WHERE b.channel_id=c.id AND b.organization_id=c.organization_id) AS bound_shop_ids,
               (SELECT followers_count FROM channel_snapshots cs
                WHERE cs.channel_id=c.id AND cs.organization_id=c.organization_id
                ORDER BY cs.snapshot_date DESC LIMIT 1) AS followers_count,
               (SELECT COUNT(*) FROM posts p
                WHERE p.channel_id=c.id AND p.organization_id=c.organization_id) AS posts_count,
               (SELECT COUNT(*) FROM comments cm
                WHERE cm.channel_id=c.id AND cm.organization_id=c.organization_id) AS comments_count
        FROM channels c
        LEFT JOIN provider_connections conn
          ON conn.id=c.connection_id AND conn.organization_id=c.organization_id
        LEFT JOIN channel_shop_bindings s
          ON s.channel_id=c.id AND s.organization_id=c.organization_id AND s.shop_id=?
        WHERE c.organization_id=?
    """
    params: list = [shop_id, organization_id]
    if approved_only:
        query += " AND c.approved=1"
        if shop_id is not None:
            query += " AND s.shop_id IS NOT NULL"
    rows = db.execute(query + " ORDER BY c.provider, c.name", tuple(params)).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["approved"] = bool(item["approved"])
        item["followers_count"] = item["followers_count"] or 0
        item["posts_count"] = item["posts_count"] or 0
        item["comments_count"] = item["comments_count"] or 0
        item["selectable"] = bool(
            item["approved"]
            and (shop_id is None or item["bound_shop_id"] is not None)
        )
        result.append(item)
    return result


def posts_list(
    db: sqlite3.Connection,
    organization_id: str,
    *,
    channel_id: int | None = None,
    shop_id: int | None = None,
    kind: str | None = None,
    limit: int = 50,
) -> list[dict]:
    query = """
        SELECT p.*, c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter
        FROM posts p
        JOIN channels c ON c.id=p.channel_id AND c.organization_id=p.organization_id
        WHERE p.organization_id=? AND c.approved=1
    """
    params: list = [organization_id]
    if channel_id is not None:
        query += " AND p.channel_id=?"
        params.append(channel_id)
    if shop_id is not None:
        query += """ AND EXISTS (
            SELECT 1 FROM channel_shop_bindings b
            WHERE b.organization_id=p.organization_id AND b.channel_id=p.channel_id AND b.shop_id=?
        )"""
        params.append(shop_id)
    if kind:
        query += " AND p.kind=?"
        params.append(kind)
    query += " ORDER BY p.published_at DESC, p.id DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, tuple(params)).fetchall()
    items = []
    for row in rows:
        post = dict(row)
        post["media"] = json.loads(post.pop("media_json", "[]") or "[]")
        snap = db.execute(
            """SELECT snapshot_date, impressions, reach, reactions, comments_count, shares, saves, plays, clicks
               FROM post_snapshots WHERE organization_id=? AND post_id=?
               ORDER BY snapshot_date DESC LIMIT 1""",
            (organization_id, post["id"]),
        ).fetchone()
        post["latest_snapshot"] = dict(snap) if snap else None
        archives = [
            dict(a)
            for a in db.execute(
                """SELECT id, kind, path, sha256, bytes, captured_at, source_url
                   FROM post_archives WHERE organization_id=? AND post_id=? ORDER BY id""",
                (organization_id, post["id"]),
            ).fetchall()
        ]
        post["archives"] = archives
        items.append(post)
    return items


def post_detail(db: sqlite3.Connection, organization_id: str, post_id: int) -> dict | None:
    row = db.execute(
        """SELECT p.*, c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy
           FROM posts p
           JOIN channels c ON c.id=p.channel_id AND c.organization_id=p.organization_id
           WHERE p.organization_id=? AND p.id=?""",
        (organization_id, post_id),
    ).fetchone()
    if not row:
        return None
    post = dict(row)
    post["media"] = json.loads(post.pop("media_json", "[]") or "[]")
    post["snapshots"] = [
        dict(s)
        for s in db.execute(
            """SELECT snapshot_date, impressions, reach, reactions, comments_count, shares, saves, plays, clicks
               FROM post_snapshots WHERE organization_id=? AND post_id=?
               ORDER BY snapshot_date ASC""",
            (organization_id, post_id),
        ).fetchall()
    ]
    post["archives"] = [
        dict(a)
        for a in db.execute(
            """SELECT id, kind, path, sha256, bytes, captured_at, source_url
               FROM post_archives WHERE organization_id=? AND post_id=? ORDER BY id""",
            (organization_id, post_id),
        ).fetchall()
    ]
    return post


def enrich_comment(db: sqlite3.Connection, organization_id: str, row: sqlite3.Row | dict) -> dict:
    item = dict(row)
    item.pop("raw_json", None)
    state = db.execute(
        "SELECT * FROM comment_states WHERE organization_id=? AND comment_id=?",
        (organization_id, item["id"]),
    ).fetchone()
    if state:
        item["status"] = state["status"]
        item["bucket"] = state["bucket"]
        item["assigned_to"] = state["assigned_to"]
        item["note"] = state["note"]
        item["flags"] = json.loads(state["flags_json"] or "[]")
        item["human_decision"] = state["human_decision"]
        item["state_updated_by"] = state["updated_by"]
        item["state_updated_at"] = state["updated_at"]
    else:
        item["status"] = "new"
        item["bucket"] = "needs_review"
        item["assigned_to"] = ""
        item["note"] = ""
        item["flags"] = []
        item["human_decision"] = None
        item["state_updated_by"] = "system"
        item["state_updated_at"] = item["created_at"]

    ev = db.execute(
        "SELECT * FROM comment_evaluations WHERE organization_id=? AND comment_id=?",
        (organization_id, item["id"]),
    ).fetchone()
    feedback_map = {
        f["label"]: bool(f["agreed"])
        for f in db.execute(
            "SELECT label, agreed FROM evaluation_feedback WHERE organization_id=? AND comment_id=?",
            (organization_id, item["id"]),
        ).fetchall()
    }
    if ev:
        labels = json.loads(ev["label_scores_json"] or "[]")
        for lbl in labels:
            lbl["human_agreed"] = feedback_map.get(lbl["key"])
        item["evaluation"] = {
            "id": ev["id"],
            "rubric_version": ev["rubric_version"],
            "overall_score": round(float(ev["overall_score"]), 1),
            "threshold": ev["threshold"],
            "recommended_action": ev["recommended_action"],
            "tier_label": ev["tier_label"],
            "confidence": ev["confidence"],
            "data_quality": ev["data_quality"],
            "reasoning_bullets": json.loads(ev["reasoning_bullets_json"] or "[]"),
            "label_scores": labels,
            "reply_strategy": json.loads(ev["reply_strategy_json"] or "{}"),
            "evaluated_at": ev["evaluated_at"],
        }
    else:
        item["evaluation"] = None

    drafts = [
        dict(d)
        for d in db.execute(
            """SELECT id, kind, strategy_summary, text, created_by, status, approved_by, created_at, updated_at
               FROM reply_drafts WHERE organization_id=? AND comment_id=? ORDER BY id DESC""",
            (organization_id, item["id"]),
        ).fetchall()
    ]
    item["drafts"] = drafts
    return item


def comments_list(
    db: sqlite3.Connection,
    organization_id: str,
    *,
    shop_id: int | None = None,
    channel_id: int | None = None,
    post_id: int | None = None,
    status: str | None = None,
    bucket: str | None = None,
    assignment: str | None = None,
    search: str | None = None,
    limit: int = 100,
) -> list[dict]:
    query = """
        SELECT cm.*,
               p.caption AS post_caption, p.permalink AS post_permalink, p.kind AS post_kind,
               c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy,
               c.auto_suggest_threshold,
               COALESCE(ev.overall_score, 50.0) AS sort_score
        FROM comments cm
        JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
        JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
        LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
        LEFT JOIN comment_evaluations ev ON ev.comment_id=cm.id AND ev.organization_id=cm.organization_id
        WHERE cm.organization_id=?
    """
    params: list = [organization_id]
    if shop_id is not None:
        query += """ AND EXISTS (
            SELECT 1 FROM channel_shop_bindings b
            WHERE b.organization_id=cm.organization_id AND b.channel_id=cm.channel_id AND b.shop_id=?
        )"""
        params.append(shop_id)
    if channel_id is not None:
        query += " AND cm.channel_id=?"
        params.append(channel_id)
    if post_id is not None:
        query += " AND cm.post_id=?"
        params.append(post_id)
    if status:
        query += " AND COALESCE(st.status, 'new')=?"
        params.append(status)
    if bucket and bucket != "all":
        query += " AND COALESCE(st.bucket, 'needs_review')=?"
        params.append(bucket)
    if assignment == "unassigned":
        query += " AND COALESCE(st.assigned_to, '')=''"
    elif assignment == "assigned":
        query += " AND COALESCE(st.assigned_to, '')!=''"
    if search:
        query += " AND (LOWER(cm.text) LIKE ? OR LOWER(cm.author_name) LIKE ?)"
        q = f"%{search.strip().lower()}%"
        params.extend((q, q))
    query += " ORDER BY sort_score DESC, cm.created_at DESC, cm.id DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, tuple(params)).fetchall()
    return [enrich_comment(db, organization_id, r) for r in rows]


def comment_thread(db: sqlite3.Connection, organization_id: str, comment_id: int) -> dict | None:
    row = db.execute(
        """SELECT cm.*,
                  p.caption AS post_caption, p.permalink AS post_permalink, p.kind AS post_kind,
                  c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy,
                  c.auto_suggest_threshold
           FROM comments cm
           JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
           JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
           WHERE cm.organization_id=? AND cm.id=?""",
        (organization_id, comment_id),
    ).fetchone()
    if not row:
        return None
    root = enrich_comment(db, organization_id, row)
    replies = [
        enrich_comment(db, organization_id, r)
        for r in db.execute(
            """SELECT cm.*,
                      p.caption AS post_caption, p.permalink AS post_permalink, p.kind AS post_kind,
                      c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy,
                      c.auto_suggest_threshold
               FROM comments cm
               JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
               JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
               WHERE cm.organization_id=? AND cm.parent_external_id=?
               ORDER BY cm.created_at ASC""",
            (organization_id, root["external_id"]),
        ).fetchall()
    ]
    root["replies"] = replies
    return root


def inbox_summary(db: sqlite3.Connection, organization_id: str, shop_id: int | None = None) -> dict:
    where = "WHERE cm.organization_id=?"
    params: list = [organization_id]
    if shop_id is not None:
        where += """ AND EXISTS (
            SELECT 1 FROM channel_shop_bindings b
            WHERE b.organization_id=cm.organization_id AND b.channel_id=cm.channel_id AND b.shop_id=?
        )"""
        params.append(shop_id)
    by_status = {s: 0 for s in COMMENT_STATUSES}
    for row in db.execute(
        f"""SELECT COALESCE(st.status, 'new') AS s, COUNT(*) AS cnt
            FROM comments cm
            LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
            {where} GROUP BY s""",
        tuple(params),
    ):
        by_status[row["s"]] = row["cnt"]

    by_bucket = {b: 0 for b in COMMENT_BUCKETS}
    for row in db.execute(
        f"""SELECT COALESCE(st.bucket, 'needs_review') AS b, COUNT(*) AS cnt
            FROM comments cm
            LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
            {where} GROUP BY b""",
        tuple(params),
    ):
        by_bucket[row["b"]] = row["cnt"]

    assignment = {"all": sum(by_status.values()), "unassigned": 0, "assigned": 0}
    for row in db.execute(
        f"""SELECT CASE WHEN COALESCE(st.assigned_to, '')='' THEN 'unassigned' ELSE 'assigned' END AS a,
                   COUNT(*) AS cnt
            FROM comments cm
            LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
            {where} GROUP BY a""",
        tuple(params),
    ):
        assignment[row["a"]] = row["cnt"]

    by_channel = [
        dict(r)
        for r in db.execute(
            f"""SELECT c.id AS channel_id, c.name AS channel_name, c.provider, c.kind, c.adapter,
                       COUNT(cm.id) AS total_comments,
                       SUM(CASE WHEN COALESCE(st.status, 'new') IN ('new', 'needs_reply') THEN 1 ELSE 0 END) AS open_comments
                FROM channels c
                LEFT JOIN comments cm ON cm.channel_id=c.id AND cm.organization_id=c.organization_id
                LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
                WHERE c.organization_id=?
                GROUP BY c.id ORDER BY open_comments DESC, c.name ASC""",
            (organization_id,),
        ).fetchall()
    ]
    return {
        "total": sum(by_status.values()),
        "by_status": by_status,
        "by_bucket": by_bucket,
        "assignment": assignment,
        "by_channel": by_channel,
    }


def stats_series(
    db: sqlite3.Connection,
    organization_id: str,
    *,
    channel_id: int | None = None,
    post_id: int | None = None,
    days: int = 30,
) -> dict:
    days = max(1, min(90, int(days)))
    if post_id is not None:
        rows = [
            dict(r)
            for r in db.execute(
                """SELECT snapshot_date, impressions, reach, reactions, comments_count, shares, saves, plays, clicks
                   FROM post_snapshots WHERE organization_id=? AND post_id=?
                   ORDER BY snapshot_date DESC LIMIT ?""",
                (organization_id, post_id, days),
            ).fetchall()
        ]
        return {"kind": "post", "post_id": post_id, "series": list(reversed(rows))}
    if channel_id is not None:
        rows = [
            dict(r)
            for r in db.execute(
                """SELECT snapshot_date, followers_count, posts_count
                   FROM channel_snapshots WHERE organization_id=? AND channel_id=?
                   ORDER BY snapshot_date DESC LIMIT ?""",
                (organization_id, channel_id, days),
            ).fetchall()
        ]
        return {"kind": "channel", "channel_id": channel_id, "series": list(reversed(rows))}
    return {"kind": "none", "series": []}
