//! Organization-scoped SQLite WAL store for LNC Care (`care.db`).

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::{params, params_from_iter, Connection, OpenFlags, Row};
use serde_json::{json, Map, Value};

pub const PROVIDERS: &[&str] = &["meta", "tiktok", "youtube"];
pub const ADAPTERS: &[&str] = &[
    "meta_api",
    "browser_ingest",
    "veilbrowser",
    "orbine_mobile",
    "scrapling_public",
];
pub const CHANNEL_ADAPTERS: &[&str] = ADAPTERS;
pub const CHANNEL_KINDS: &[&str] = &[
    "fb_page",
    "ig_account",
    "fb_profile",
    "ig_profile",
    "tt_account",
    "yt_channel",
];
pub const REPLY_POLICIES: &[&str] = &["draft_only", "operator_direct", "agent_direct"];
pub const COMMENT_STATUSES: &[&str] = &["new", "needs_reply", "replied", "hidden", "ignored"];
pub const COMMENT_BUCKETS: &[&str] = &[
    "should_consult",
    "needs_review",
    "praise",
    "complaint",
    "spam_clone",
    "negative",
    "evidence",
];

pub const SCHEMA: &str = r#"
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

CREATE TABLE IF NOT EXISTS bridge_nonces (
    organization_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (organization_id, nonce)
);

CREATE TABLE IF NOT EXISTS hub_connection_links (
    organization_id TEXT NOT NULL,
    connection_id INTEGER NOT NULL,
    hub_connection_id TEXT NOT NULL,
    hub_revision INTEGER NOT NULL DEFAULT 1,
    leased_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, connection_id),
    UNIQUE (organization_id, hub_connection_id),
    FOREIGN KEY (organization_id, connection_id) REFERENCES provider_connections(organization_id, id)
);

CREATE TABLE IF NOT EXISTS shop_connection_bindings (
    organization_id TEXT NOT NULL,
    shop_id INTEGER NOT NULL,
    connection_id INTEGER NOT NULL,
    PRIMARY KEY (organization_id, shop_id, connection_id),
    FOREIGN KEY (organization_id, shop_id) REFERENCES shops(organization_id, id),
    FOREIGN KEY (organization_id, connection_id) REFERENCES provider_connections(organization_id, id)
);

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    channel_id INTEGER NOT NULL,
    external_id TEXT NOT NULL,
    participant_id TEXT NOT NULL DEFAULT '',
    participant_name TEXT NOT NULL DEFAULT 'Customer',
    status TEXT NOT NULL DEFAULT 'open'
      CHECK (status IN ('open', 'pending_reply', 'replied', 'handed_off', 'closed')),
    assigned_to TEXT NOT NULL DEFAULT '',
    last_message_preview TEXT NOT NULL DEFAULT '',
    unread_count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    UNIQUE (organization_id, channel_id, external_id),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, channel_id) REFERENCES channels(organization_id, id)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    conversation_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    external_id TEXT NOT NULL,
    direction TEXT NOT NULL DEFAULT 'inbound'
      CHECK (direction IN ('inbound', 'outbound')),
    sender_id TEXT NOT NULL DEFAULT '',
    sender_name TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    attachments_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'delivered',
    created_at INTEGER NOT NULL,
    UNIQUE (organization_id, channel_id, external_id),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, conversation_id) REFERENCES conversations(organization_id, id),
    FOREIGN KEY (organization_id, channel_id) REFERENCES channels(organization_id, id)
);

CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    shop_id INTEGER,
    channel_id INTEGER,
    source TEXT NOT NULL DEFAULT 'comment'
      CHECK (source IN ('comment', 'dm', 'meta_lead_ad', 'manual')),
    external_id TEXT NOT NULL DEFAULT '',
    customer_name TEXT NOT NULL,
    contact_handle TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    intent_score REAL NOT NULL DEFAULT 80.0,
    status TEXT NOT NULL DEFAULT 'new'
      CHECK (status IN ('new', 'qualified', 'contacted', 'converted', 'archived')),
    notes TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (organization_id, id)
);

CREATE TABLE IF NOT EXISTS ticket_handoffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    shop_id INTEGER,
    channel_id INTEGER,
    comment_id INTEGER,
    conversation_id INTEGER,
    priority TEXT NOT NULL DEFAULT 'normal'
      CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    assignee TEXT NOT NULL DEFAULT 'care-team',
    summary TEXT NOT NULL,
    context_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open'
      CHECK (status IN ('open', 'acknowledged', 'resolved')),
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (organization_id, id)
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

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    label TEXT NOT NULL,
    prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled', 'disabled', 'revoked')),
    created_at INTEGER NOT NULL,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, key_hash)
);

CREATE INDEX IF NOT EXISTS idx_channels_org ON channels(organization_id, provider);
CREATE INDEX IF NOT EXISTS idx_posts_channel ON posts(organization_id, channel_id, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(organization_id, post_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_channel ON comments(organization_id, channel_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comment_states_bucket ON comment_states(organization_id, bucket, status);
CREATE INDEX IF NOT EXISTS idx_jobs_pending ON jobs(organization_id, done_at, run_after);
"#;

pub fn connect(path: &Path) -> Result<Connection, rusqlite::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let db = Connection::open(path)?;
    db.busy_timeout(Duration::from_secs(10))?;
    db.execute_batch("PRAGMA foreign_keys=ON;")?;
    Ok(db)
}

pub fn connect_readonly(path: &Path) -> Result<Connection, rusqlite::Error> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let db = Connection::open_with_flags(path, flags)?;
    db.busy_timeout(Duration::from_secs(5))?;
    Ok(db)
}

pub fn with_write_tx<T, E, F>(path: &Path, f: F) -> Result<T, E>
where
    E: From<rusqlite::Error>,
    F: FnOnce(&Connection) -> Result<T, E>,
{
    let db = connect(path)?;
    db.execute_batch("BEGIN IMMEDIATE;")?;
    match f(&db) {
        Ok(val) => {
            db.execute_batch("COMMIT;")?;
            Ok(val)
        }
        Err(err) => {
            let _ = db.execute_batch("ROLLBACK;");
            Err(err)
        }
    }
}

pub fn with_write_tx_str<T, F>(path: &Path, f: F) -> Result<T, String>
where
    F: FnOnce(&Connection) -> Result<T, String>,
{
    let db = connect(path).map_err(|e| e.to_string())?;
    db.execute_batch("BEGIN IMMEDIATE;")
        .map_err(|e| e.to_string())?;
    match f(&db) {
        Ok(val) => {
            db.execute_batch("COMMIT;").map_err(|e| e.to_string())?;
            Ok(val)
        }
        Err(err) => {
            let _ = db.execute_batch("ROLLBACK;");
            Err(err)
        }
    }
}

fn ensure_column(
    db: &Connection,
    table: &str,
    column: &str,
    ddl_suffix: &str,
) -> Result<(), rusqlite::Error> {
    let mut stmt = db.prepare(&format!("PRAGMA table_info({table})"))?;
    let exists = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|c| c.eq_ignore_ascii_case(column));
    if !exists {
        db.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {ddl_suffix}"),
            [],
        )?;
    }
    Ok(())
}

pub fn initialize(path: &Path, organization_id: &str, organization_name: &str) -> Result<(), rusqlite::Error> {
    let db = connect(path)?;
    let _ = db.query_row("PRAGMA journal_mode=WAL;", [], |r| r.get::<_, String>(0));
    db.execute_batch(SCHEMA)?;
    // Additive Phase 2 / Phase 2b migrations (safe & idempotent on live `/data/care.db`)
    ensure_column(&db, "channels", "webhook_fields", "TEXT NOT NULL DEFAULT ''")?;
    ensure_column(&db, "channels", "webhook_error", "TEXT NOT NULL DEFAULT ''")?;
    ensure_column(
        &db,
        "account_runtimes",
        "budget_date",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        &db,
        "account_runtimes",
        "last_exit_ip",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        &db,
        "account_runtimes",
        "proxy_mode",
        "TEXT NOT NULL DEFAULT 'xray_tun_failclosed'",
    )?;
    ensure_column(&db, "jobs", "max_attempts", "INTEGER NOT NULL DEFAULT 3")?;
    db.execute(
        "INSERT OR IGNORE INTO organizations (id, name) VALUES (?1, ?2)",
        params![organization_id, organization_name],
    )?;
    Ok(())
}

pub fn row_to_map(row: &Row<'_>) -> Result<Map<String, Value>, rusqlite::Error> {
    let mut map = Map::new();
    for idx in 0..row.as_ref().column_count() {
        let name = row.as_ref().column_name(idx)?.to_string();
        let val = match row.get_ref(idx)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(i) => Value::Number(i.into()),
            ValueRef::Real(f) => serde_json::Number::from_f64(f)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            ValueRef::Text(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
            ValueRef::Blob(bytes) => Value::String(hex::encode(bytes)),
        };
        map.insert(name, val);
    }
    Ok(map)
}

pub fn query_maps(
    db: &Connection,
    sql: &str,
    params_slice: &[rusqlite::types::Value],
) -> Vec<Map<String, Value>> {
    let Ok(mut stmt) = db.prepare(sql) else {
        return Vec::new();
    };
    let Ok(iter) = stmt.query_map(params_from_iter(params_slice.iter()), row_to_map) else {
        return Vec::new();
    };
    iter.filter_map(Result::ok).collect()
}

pub fn query_one_map(
    db: &Connection,
    sql: &str,
    params_slice: &[rusqlite::types::Value],
) -> Option<Map<String, Value>> {
    let mut stmt = db.prepare(sql).ok()?;
    stmt.query_row(params_from_iter(params_slice.iter()), row_to_map)
        .ok()
}

pub fn shops(db: &Connection, organization_id: &str) -> Vec<Value> {
    query_maps(
        db,
        "SELECT id, name FROM shops WHERE organization_id=? ORDER BY name",
        &[organization_id.to_string().into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect()
}

pub fn channels(
    db: &Connection,
    organization_id: &str,
    shop_id: Option<i64>,
    approved_only: bool,
) -> Vec<Value> {
    let mut query = String::from(
        "SELECT c.*,
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
         WHERE c.organization_id=?",
    );
    let shop_param = match shop_id {
        Some(sid) => rusqlite::types::Value::Integer(sid),
        None => rusqlite::types::Value::Null,
    };
    let params_vec = vec![shop_param, organization_id.to_string().into()];
    if approved_only {
        query.push_str(" AND c.approved=1");
        if shop_id.is_some() {
            query.push_str(" AND s.shop_id IS NOT NULL");
        }
    }
    query.push_str(" ORDER BY c.provider, c.name");

    query_maps(db, &query, &params_vec)
        .into_iter()
        .map(|mut item| {
            let approved = item.get("approved").and_then(|v| v.as_i64()).unwrap_or(0) != 0;
            let bound_present = item
                .get("bound_shop_id")
                .map(|v| !v.is_null())
                .unwrap_or(false);
            item.insert("approved".to_string(), Value::Bool(approved));
            let followers = item
                .get("followers_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let posts_cnt = item
                .get("posts_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let comments_cnt = item
                .get("comments_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let webhook_subscribed = item
                .get("webhook_subscribed_at")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                > 0;
            item.insert("webhook_subscribed".to_string(), Value::Bool(webhook_subscribed));
            item.insert("followers_count".to_string(), json!(followers));
            item.insert("posts_count".to_string(), json!(posts_cnt));
            item.insert("comments_count".to_string(), json!(comments_cnt));
            item.insert(
                "selectable".to_string(),
                Value::Bool(approved && (shop_id.is_none() || bound_present)),
            );
            Value::Object(item)
        })
        .collect()
}

pub fn jobs_summary(db: &Connection, organization_id: &str) -> Value {
    let pending: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE organization_id=?1 AND done_at IS NULL",
            params![organization_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let completed: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE organization_id=?1 AND done_at IS NOT NULL AND error IS NULL",
            params![organization_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let failed: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE organization_id=?1 AND error IS NOT NULL",
            params![organization_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let archives_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM post_archives WHERE organization_id=?1",
            params![organization_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let recent_failures: Vec<Value> = query_maps(
        db,
        "SELECT id, kind, attempts, error, run_after FROM jobs
         WHERE organization_id=? AND error IS NOT NULL
         ORDER BY id DESC LIMIT 10",
        &[organization_id.to_string().into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();

    json!({
        "pending": pending,
        "completed": completed,
        "failed": failed,
        "archives_count": archives_count,
        "recent_failures": recent_failures,
    })
}

pub fn posts_list(
    db: &Connection,
    organization_id: &str,
    channel_id: Option<i64>,
    shop_id: Option<i64>,
    kind: Option<&str>,
    limit: i64,
) -> Vec<Value> {
    let mut query = String::from(
        "SELECT p.*, c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter
         FROM posts p
         JOIN channels c ON c.id=p.channel_id AND c.organization_id=p.organization_id
         WHERE p.organization_id=? AND c.approved=1",
    );
    let mut params_vec: Vec<rusqlite::types::Value> = vec![organization_id.to_string().into()];
    if let Some(cid) = channel_id {
        query.push_str(" AND p.channel_id=?");
        params_vec.push(cid.into());
    }
    if let Some(sid) = shop_id {
        query.push_str(
            " AND EXISTS (
                SELECT 1 FROM channel_shop_bindings b
                WHERE b.organization_id=p.organization_id AND b.channel_id=p.channel_id AND b.shop_id=?
            )",
        );
        params_vec.push(sid.into());
    }
    if let Some(k) = kind.filter(|s| !s.is_empty()) {
        query.push_str(" AND p.kind=?");
        params_vec.push(k.to_string().into());
    }
    query.push_str(" ORDER BY p.published_at DESC, p.id DESC LIMIT ?");
    params_vec.push(limit.clamp(1, 200).into());

    query_maps(db, &query, &params_vec)
        .into_iter()
        .map(|mut post| {
            let pid = post.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
            let media_raw = post
                .remove("media_json")
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "[]".to_string());
            let media: Value = serde_json::from_str(&media_raw).unwrap_or_else(|_| json!([]));
            post.insert("media".to_string(), media);

            let snap = query_one_map(
                db,
                "SELECT snapshot_date, impressions, reach, reactions, comments_count, shares, saves, plays, clicks
                 FROM post_snapshots WHERE organization_id=? AND post_id=?
                 ORDER BY snapshot_date DESC LIMIT 1",
                &[organization_id.to_string().into(), pid.into()],
            );
            post.insert(
                "latest_snapshot".to_string(),
                snap.map(Value::Object).unwrap_or(Value::Null),
            );

            let archives: Vec<Value> = query_maps(
                db,
                "SELECT id, kind, path, sha256, bytes, captured_at, source_url
                 FROM post_archives WHERE organization_id=? AND post_id=? ORDER BY id",
                &[organization_id.to_string().into(), pid.into()],
            )
            .into_iter()
            .map(Value::Object)
            .collect();
            post.insert("archives".to_string(), Value::Array(archives));
            Value::Object(post)
        })
        .collect()
}

pub fn post_detail(db: &Connection, organization_id: &str, post_id: i64) -> Option<Value> {
    let mut post = query_one_map(
        db,
        "SELECT p.*, c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy
         FROM posts p
         JOIN channels c ON c.id=p.channel_id AND c.organization_id=p.organization_id
         WHERE p.organization_id=? AND p.id=?",
        &[organization_id.to_string().into(), post_id.into()],
    )?;
    let media_raw = post
        .remove("media_json")
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "[]".to_string());
    post.insert(
        "media".to_string(),
        serde_json::from_str(&media_raw).unwrap_or_else(|_| json!([])),
    );

    let snapshots: Vec<Value> = query_maps(
        db,
        "SELECT snapshot_date, impressions, reach, reactions, comments_count, shares, saves, plays, clicks
         FROM post_snapshots WHERE organization_id=? AND post_id=?
         ORDER BY snapshot_date ASC",
        &[organization_id.to_string().into(), post_id.into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();
    post.insert("snapshots".to_string(), Value::Array(snapshots));

    let archives: Vec<Value> = query_maps(
        db,
        "SELECT id, kind, path, sha256, bytes, captured_at, source_url
         FROM post_archives WHERE organization_id=? AND post_id=? ORDER BY id",
        &[organization_id.to_string().into(), post_id.into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();
    post.insert("archives".to_string(), Value::Array(archives));

    Some(Value::Object(post))
}

pub fn enrich_comment(db: &Connection, organization_id: &str, mut item: Map<String, Value>) -> Value {
    item.remove("raw_json");
    let cid = item.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let created_at = item.get("created_at").cloned().unwrap_or(json!(0));

    if let Some(state) = query_one_map(
        db,
        "SELECT * FROM comment_states WHERE organization_id=? AND comment_id=?",
        &[organization_id.to_string().into(), cid.into()],
    ) {
        item.insert(
            "status".to_string(),
            state.get("status").cloned().unwrap_or_else(|| json!("new")),
        );
        item.insert(
            "bucket".to_string(),
            state
                .get("bucket")
                .cloned()
                .unwrap_or_else(|| json!("needs_review")),
        );
        item.insert(
            "assigned_to".to_string(),
            state.get("assigned_to").cloned().unwrap_or_else(|| json!("")),
        );
        item.insert(
            "note".to_string(),
            state.get("note").cloned().unwrap_or_else(|| json!("")),
        );
        let flags_raw = state
            .get("flags_json")
            .and_then(|v| v.as_str())
            .unwrap_or("[]");
        item.insert(
            "flags".to_string(),
            serde_json::from_str(flags_raw).unwrap_or_else(|_| json!([])),
        );
        item.insert(
            "human_decision".to_string(),
            state.get("human_decision").cloned().unwrap_or(Value::Null),
        );
        item.insert(
            "state_updated_by".to_string(),
            state
                .get("updated_by")
                .cloned()
                .unwrap_or_else(|| json!("system")),
        );
        item.insert(
            "state_updated_at".to_string(),
            state.get("updated_at").cloned().unwrap_or(created_at),
        );
    } else {
        item.insert("status".to_string(), json!("new"));
        item.insert("bucket".to_string(), json!("needs_review"));
        item.insert("assigned_to".to_string(), json!(""));
        item.insert("note".to_string(), json!(""));
        item.insert("flags".to_string(), json!([]));
        item.insert("human_decision".to_string(), Value::Null);
        item.insert("state_updated_by".to_string(), json!("system"));
        item.insert("state_updated_at".to_string(), created_at);
    }

    let mut feedback_map: HashMap<String, bool> = HashMap::new();
    for fb in query_maps(
        db,
        "SELECT label, agreed FROM evaluation_feedback WHERE organization_id=? AND comment_id=?",
        &[organization_id.to_string().into(), cid.into()],
    ) {
        if let Some(lbl) = fb.get("label").and_then(|v| v.as_str()) {
            let agreed = fb.get("agreed").and_then(|v| v.as_i64()).unwrap_or(0) != 0;
            feedback_map.insert(lbl.to_string(), agreed);
        }
    }

    if let Some(ev) = query_one_map(
        db,
        "SELECT * FROM comment_evaluations WHERE organization_id=? AND comment_id=?",
        &[organization_id.to_string().into(), cid.into()],
    ) {
        let labels_raw = ev
            .get("label_scores_json")
            .and_then(|v| v.as_str())
            .unwrap_or("[]");
        let mut labels: Vec<Value> = serde_json::from_str(labels_raw).unwrap_or_default();
        for lbl in &mut labels {
            if let Some(obj) = lbl.as_object_mut() {
                let key = obj.get("key").and_then(|v| v.as_str()).unwrap_or_default();
                let agreed_val = match feedback_map.get(key) {
                    Some(&b) => Value::Bool(b),
                    None => Value::Null,
                };
                obj.insert("human_agreed".to_string(), agreed_val);
            }
        }
        let raw_score = ev
            .get("overall_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(50.0);
        let rounded_score = (raw_score * 10.0).round() / 10.0;
        let bullets_raw = ev
            .get("reasoning_bullets_json")
            .and_then(|v| v.as_str())
            .unwrap_or("[]");
        let strat_raw = ev
            .get("reply_strategy_json")
            .and_then(|v| v.as_str())
            .unwrap_or("{}");

        item.insert(
            "evaluation".to_string(),
            json!({
                "id": ev.get("id").cloned().unwrap_or(Value::Null),
                "rubric_version": ev.get("rubric_version").cloned().unwrap_or_else(|| json!("v1")),
                "overall_score": rounded_score,
                "threshold": ev.get("threshold").cloned().unwrap_or_else(|| json!(80)),
                "recommended_action": ev.get("recommended_action").cloned().unwrap_or_else(|| json!("needs_review")),
                "tier_label": ev.get("tier_label").cloned().unwrap_or_else(|| json!("")),
                "confidence": ev.get("confidence").cloned().unwrap_or_else(|| json!(75)),
                "data_quality": ev.get("data_quality").cloned().unwrap_or_else(|| json!("")),
                "reasoning_bullets": serde_json::from_str::<Value>(bullets_raw).unwrap_or_else(|_| json!([])),
                "label_scores": labels,
                "reply_strategy": serde_json::from_str::<Value>(strat_raw).unwrap_or_else(|_| json!({})),
                "evaluated_at": ev.get("evaluated_at").cloned().unwrap_or_else(|| json!(0)),
            }),
        );
    } else {
        item.insert("evaluation".to_string(), Value::Null);
    }

    let drafts: Vec<Value> = query_maps(
        db,
        "SELECT id, kind, strategy_summary, text, created_by, status, approved_by, sent_action_id, created_at, updated_at
         FROM reply_drafts WHERE organization_id=? AND comment_id=? ORDER BY id DESC",
        &[organization_id.to_string().into(), cid.into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();
    item.insert("drafts".to_string(), Value::Array(drafts));

    let actions: Vec<Value> = query_maps(
        db,
        "SELECT id, kind, actor, idempotency_key, provider_result_id, status, payload_json, created_at
         FROM comment_actions WHERE organization_id=? AND comment_id=? ORDER BY id DESC LIMIT 20",
        &[organization_id.to_string().into(), cid.into()],
    )
    .into_iter()
    .map(|mut act| {
        let payload = act
            .get("payload_json")
            .and_then(|v| v.as_str())
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .unwrap_or_else(|| json!({}));
        act.insert("payload".to_string(), payload);
        Value::Object(act)
    })
    .collect();
    item.insert("actions".to_string(), Value::Array(actions));

    Value::Object(item)
}

#[allow(clippy::too_many_arguments)]
pub fn comments_list(
    db: &Connection,
    organization_id: &str,
    shop_id: Option<i64>,
    channel_id: Option<i64>,
    post_id: Option<i64>,
    status: Option<&str>,
    bucket: Option<&str>,
    assignment: Option<&str>,
    search: Option<&str>,
    limit: i64,
) -> Vec<Value> {
    let mut query = String::from(
        "SELECT cm.*,
                p.caption AS post_caption, p.permalink AS post_permalink, p.kind AS post_kind,
                c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy,
                c.auto_suggest_threshold,
                COALESCE(ev.overall_score, 50.0) AS sort_score
         FROM comments cm
         JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
         JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
         LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
         LEFT JOIN comment_evaluations ev ON ev.comment_id=cm.id AND ev.organization_id=cm.organization_id
         WHERE cm.organization_id=?",
    );
    let mut params_vec: Vec<rusqlite::types::Value> = vec![organization_id.to_string().into()];

    if let Some(sid) = shop_id {
        query.push_str(
            " AND EXISTS (
                SELECT 1 FROM channel_shop_bindings b
                WHERE b.organization_id=cm.organization_id AND b.channel_id=cm.channel_id AND b.shop_id=?
            )",
        );
        params_vec.push(sid.into());
    }
    if let Some(cid) = channel_id {
        query.push_str(" AND cm.channel_id=?");
        params_vec.push(cid.into());
    }
    if let Some(pid) = post_id {
        query.push_str(" AND cm.post_id=?");
        params_vec.push(pid.into());
    }
    if let Some(st) = status.filter(|s| !s.is_empty()) {
        query.push_str(" AND COALESCE(st.status, 'new')=?");
        params_vec.push(st.to_string().into());
    }
    if let Some(bk) = bucket.filter(|s| !s.is_empty() && *s != "all") {
        query.push_str(" AND COALESCE(st.bucket, 'needs_review')=?");
        params_vec.push(bk.to_string().into());
    }
    if let Some(asgn) = assignment {
        if asgn == "unassigned" {
            query.push_str(" AND COALESCE(st.assigned_to, '')=''");
        } else if asgn == "assigned" {
            query.push_str(" AND COALESCE(st.assigned_to, '')!=''");
        }
    }
    if let Some(q_raw) = search.map(str::trim).filter(|s| !s.is_empty()) {
        query.push_str(" AND (LOWER(cm.text) LIKE ? OR LOWER(cm.author_name) LIKE ?)");
        let pat = format!("%{}%", q_raw.to_lowercase());
        params_vec.push(pat.clone().into());
        params_vec.push(pat.into());
    }
    query.push_str(" ORDER BY sort_score DESC, cm.created_at DESC, cm.id DESC LIMIT ?");
    params_vec.push(limit.clamp(1, 200).into());

    query_maps(db, &query, &params_vec)
        .into_iter()
        .map(|row| enrich_comment(db, organization_id, row))
        .collect()
}

pub fn comment_thread(db: &Connection, organization_id: &str, comment_id: i64) -> Option<Value> {
    let row = query_one_map(
        db,
        "SELECT cm.*,
                p.caption AS post_caption, p.permalink AS post_permalink, p.kind AS post_kind,
                c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy,
                c.auto_suggest_threshold
         FROM comments cm
         JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
         JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
         WHERE cm.organization_id=? AND cm.id=?",
        &[organization_id.to_string().into(), comment_id.into()],
    )?;
    let ext_id = row
        .get("external_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let mut root = enrich_comment(db, organization_id, row);
    let replies: Vec<Value> = if ext_id.is_empty() {
        Vec::new()
    } else {
        query_maps(
            db,
            "SELECT cm.*,
                    p.caption AS post_caption, p.permalink AS post_permalink, p.kind AS post_kind,
                    c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy,
                    c.auto_suggest_threshold
             FROM comments cm
             JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
             JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
             WHERE cm.organization_id=? AND cm.parent_external_id=?
             ORDER BY cm.created_at ASC",
            &[organization_id.to_string().into(), ext_id.into()],
        )
        .into_iter()
        .map(|r| enrich_comment(db, organization_id, r))
        .collect()
    };
    if let Some(obj) = root.as_object_mut() {
        obj.insert("replies".to_string(), Value::Array(replies));
    }
    Some(root)
}

pub fn inbox_summary(db: &Connection, organization_id: &str, shop_id: Option<i64>) -> Value {
    let mut where_clause = String::from("WHERE cm.organization_id=?");
    let mut params_vec: Vec<rusqlite::types::Value> = vec![organization_id.to_string().into()];
    if let Some(sid) = shop_id {
        where_clause.push_str(
            " AND EXISTS (
                SELECT 1 FROM channel_shop_bindings b
                WHERE b.organization_id=cm.organization_id AND b.channel_id=cm.channel_id AND b.shop_id=?
            )",
        );
        params_vec.push(sid.into());
    }

    let mut by_status = Map::new();
    for &s in COMMENT_STATUSES {
        by_status.insert(s.to_string(), json!(0));
    }
    let mut total: i64 = 0;
    for r in query_maps(
        db,
        &format!(
            "SELECT COALESCE(st.status, 'new') AS s, COUNT(*) AS cnt
             FROM comments cm
             LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
             {where_clause} GROUP BY s"
        ),
        &params_vec,
    ) {
        if let Some(s) = r.get("s").and_then(|v| v.as_str()) {
            let cnt = r.get("cnt").and_then(|v| v.as_i64()).unwrap_or(0);
            by_status.insert(s.to_string(), json!(cnt));
            total += cnt;
        }
    }

    let mut by_bucket = Map::new();
    for &b in COMMENT_BUCKETS {
        by_bucket.insert(b.to_string(), json!(0));
    }
    for r in query_maps(
        db,
        &format!(
            "SELECT COALESCE(st.bucket, 'needs_review') AS b, COUNT(*) AS cnt
             FROM comments cm
             LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
             {where_clause} GROUP BY b"
        ),
        &params_vec,
    ) {
        if let Some(b) = r.get("b").and_then(|v| v.as_str()) {
            let cnt = r.get("cnt").and_then(|v| v.as_i64()).unwrap_or(0);
            by_bucket.insert(b.to_string(), json!(cnt));
        }
    }

    let mut unassigned: i64 = 0;
    let mut assigned: i64 = 0;
    for r in query_maps(
        db,
        &format!(
            "SELECT CASE WHEN COALESCE(st.assigned_to, '')='' THEN 'unassigned' ELSE 'assigned' END AS a,
                    COUNT(*) AS cnt
             FROM comments cm
             LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
             {where_clause} GROUP BY a"
        ),
        &params_vec,
    ) {
        let cnt = r.get("cnt").and_then(|v| v.as_i64()).unwrap_or(0);
        match r.get("a").and_then(|v| v.as_str()) {
            Some("assigned") => assigned = cnt,
            Some("unassigned") => unassigned = cnt,
            _ => {}
        }
    }

    let by_channel: Vec<Value> = query_maps(
        db,
        "SELECT c.id AS channel_id, c.name AS channel_name, c.provider, c.kind, c.adapter,
                COUNT(cm.id) AS total_comments,
                COALESCE(SUM(CASE WHEN COALESCE(st.status, 'new') IN ('new', 'needs_reply') THEN 1 ELSE 0 END), 0) AS open_comments
         FROM channels c
         LEFT JOIN comments cm ON cm.channel_id=c.id AND cm.organization_id=c.organization_id
         LEFT JOIN comment_states st ON st.comment_id=cm.id AND st.organization_id=cm.organization_id
         WHERE c.organization_id=?
         GROUP BY c.id ORDER BY open_comments DESC, c.name ASC",
        &[organization_id.to_string().into()],
    )
    .into_iter()
    .map(Value::Object)
    .collect();

    let conversations_open: i64 = match shop_id {
        Some(sid) => db
            .query_row(
                "SELECT COUNT(*) FROM conversations cv
                 WHERE cv.organization_id=?1 AND cv.status IN ('open', 'pending_reply')
                   AND EXISTS (
                       SELECT 1 FROM channel_shop_bindings b
                       WHERE b.organization_id=cv.organization_id AND b.channel_id=cv.channel_id AND b.shop_id=?2
                   )",
                params![organization_id, sid],
                |r| r.get(0),
            )
            .unwrap_or(0),
        None => db
            .query_row(
                "SELECT COUNT(*) FROM conversations cv
                 WHERE cv.organization_id=?1 AND cv.status IN ('open', 'pending_reply')",
                params![organization_id],
                |r| r.get(0),
            )
            .unwrap_or(0),
    };

    let leads_new: i64 = match shop_id {
        Some(sid) => db
            .query_row(
                "SELECT COUNT(*) FROM leads WHERE organization_id=?1 AND status IN ('new', 'qualified') AND shop_id=?2",
                params![organization_id, sid],
                |r| r.get(0),
            )
            .unwrap_or(0),
        None => db
            .query_row(
                "SELECT COUNT(*) FROM leads WHERE organization_id=?1 AND status IN ('new', 'qualified')",
                params![organization_id],
                |r| r.get(0),
            )
            .unwrap_or(0),
    };

    let handoffs_open: i64 = match shop_id {
        Some(sid) => db
            .query_row(
                "SELECT COUNT(*) FROM ticket_handoffs WHERE organization_id=?1 AND status IN ('open', 'acknowledged') AND shop_id=?2",
                params![organization_id, sid],
                |r| r.get(0),
            )
            .unwrap_or(0),
        None => db
            .query_row(
                "SELECT COUNT(*) FROM ticket_handoffs WHERE organization_id=?1 AND status IN ('open', 'acknowledged')",
                params![organization_id],
                |r| r.get(0),
            )
            .unwrap_or(0),
    };

    json!({
        "total": total,
        "by_status": by_status,
        "by_bucket": by_bucket,
        "assignment": {
            "all": total,
            "unassigned": unassigned,
            "assigned": assigned,
        },
        "by_channel": by_channel,
        "conversations_open": conversations_open,
        "leads_new": leads_new,
        "handoffs_open": handoffs_open,
    })
}

pub fn conversations_list(
    db: &Connection,
    organization_id: &str,
    shop_id: Option<i64>,
    channel_id: Option<i64>,
    status: Option<&str>,
    limit: i64,
) -> Vec<Value> {
    let mut query = String::from(
        "SELECT cv.*, c.name AS channel_name, c.provider, c.kind AS channel_kind, c.adapter, c.reply_policy
         FROM conversations cv
         JOIN channels c ON c.id=cv.channel_id AND c.organization_id=cv.organization_id
         WHERE cv.organization_id=?",
    );
    let mut params_vec: Vec<rusqlite::types::Value> = vec![organization_id.to_string().into()];
    if let Some(sid) = shop_id {
        query.push_str(
            " AND EXISTS (
                SELECT 1 FROM channel_shop_bindings b
                WHERE b.organization_id=cv.organization_id AND b.channel_id=cv.channel_id AND b.shop_id=?
            )",
        );
        params_vec.push(sid.into());
    }
    if let Some(cid) = channel_id {
        query.push_str(" AND cv.channel_id=?");
        params_vec.push(cid.into());
    }
    if let Some(st) = status.filter(|s| !s.is_empty()) {
        query.push_str(" AND cv.status=?");
        params_vec.push(st.to_string().into());
    }
    query.push_str(" ORDER BY cv.updated_at DESC, cv.id DESC LIMIT ?");
    params_vec.push(limit.clamp(1, 100).into());

    query_maps(db, &query, &params_vec)
        .into_iter()
        .map(Value::Object)
        .collect()
}

pub fn messages_list(
    db: &Connection,
    organization_id: &str,
    conversation_id: i64,
    limit: i64,
) -> Vec<Value> {
    query_maps(
        db,
        "SELECT m.* FROM messages m
         WHERE m.organization_id=? AND m.conversation_id=?
         ORDER BY m.created_at ASC, m.id ASC LIMIT ?",
        &[
            organization_id.to_string().into(),
            conversation_id.into(),
            limit.clamp(1, 200).into(),
        ],
    )
    .into_iter()
    .map(|mut item| {
        let raw = item
            .remove("attachments_json")
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "[]".to_string());
        item.insert(
            "attachments".to_string(),
            serde_json::from_str(&raw).unwrap_or_else(|_| json!([])),
        );
        Value::Object(item)
    })
    .collect()
}

pub fn leads_list(
    db: &Connection,
    organization_id: &str,
    shop_id: Option<i64>,
    channel_id: Option<i64>,
    status: Option<&str>,
    limit: i64,
) -> Vec<Value> {
    let mut query = String::from("SELECT * FROM leads WHERE organization_id=?");
    let mut params_vec: Vec<rusqlite::types::Value> = vec![organization_id.to_string().into()];
    if let Some(sid) = shop_id {
        query.push_str(" AND shop_id=?");
        params_vec.push(sid.into());
    }
    if let Some(cid) = channel_id {
        query.push_str(" AND channel_id=?");
        params_vec.push(cid.into());
    }
    if let Some(st) = status.filter(|s| !s.is_empty()) {
        query.push_str(" AND status=?");
        params_vec.push(st.to_string().into());
    }
    query.push_str(" ORDER BY updated_at DESC, id DESC LIMIT ?");
    params_vec.push(limit.clamp(1, 100).into());

    query_maps(db, &query, &params_vec)
        .into_iter()
        .map(|mut item| {
            let raw = item
                .remove("metadata_json")
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "{}".to_string());
            item.insert(
                "metadata".to_string(),
                serde_json::from_str(&raw).unwrap_or_else(|_| json!({})),
            );
            Value::Object(item)
        })
        .collect()
}

pub fn handoffs_list(
    db: &Connection,
    organization_id: &str,
    shop_id: Option<i64>,
    status: Option<&str>,
    limit: i64,
) -> Vec<Value> {
    let mut query = String::from("SELECT * FROM ticket_handoffs WHERE organization_id=?");
    let mut params_vec: Vec<rusqlite::types::Value> = vec![organization_id.to_string().into()];
    if let Some(sid) = shop_id {
        query.push_str(" AND shop_id=?");
        params_vec.push(sid.into());
    }
    if let Some(st) = status.filter(|s| !s.is_empty()) {
        query.push_str(" AND status=?");
        params_vec.push(st.to_string().into());
    }
    query.push_str(" ORDER BY updated_at DESC, id DESC LIMIT ?");
    params_vec.push(limit.clamp(1, 100).into());

    query_maps(db, &query, &params_vec)
        .into_iter()
        .map(|mut item| {
            let raw = item
                .remove("context_json")
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "{}".to_string());
            item.insert(
                "context".to_string(),
                serde_json::from_str(&raw).unwrap_or_else(|_| json!({})),
            );
            Value::Object(item)
        })
        .collect()
}

pub fn stats_series(
    db: &Connection,
    organization_id: &str,
    channel_id: Option<i64>,
    post_id: Option<i64>,
    days: i64,
) -> Value {
    let clamped_days = days.clamp(1, 90);
    if let Some(pid) = post_id {
        let mut rows: Vec<Value> = query_maps(
            db,
            "SELECT snapshot_date, impressions, reach, reactions, comments_count, shares, saves, plays, clicks
             FROM post_snapshots WHERE organization_id=? AND post_id=?
             ORDER BY snapshot_date DESC LIMIT ?",
            &[organization_id.to_string().into(), pid.into(), clamped_days.into()],
        )
        .into_iter()
        .map(Value::Object)
        .collect();
        rows.reverse();
        return json!({"kind": "post", "post_id": pid, "series": rows});
    }
    if let Some(cid) = channel_id {
        let mut rows: Vec<Value> = query_maps(
            db,
            "SELECT snapshot_date, followers_count, posts_count
             FROM channel_snapshots WHERE organization_id=? AND channel_id=?
             ORDER BY snapshot_date DESC LIMIT ?",
            &[organization_id.to_string().into(), cid.into(), clamped_days.into()],
        )
        .into_iter()
        .map(Value::Object)
        .collect();
        rows.reverse();
        return json!({"kind": "channel", "channel_id": cid, "series": rows});
    }
    json!({"kind": "none", "series": []})
}
