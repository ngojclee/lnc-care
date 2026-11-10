"""OAuth connections, channel discovery, bounded pollers, Evidence Vault, and multi-account fleet."""
import hashlib
import json
import secrets
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from . import audit, evaluator, store
from .providers import META_VERSION, TIKTOK_VERSION, YOUTUBE_VERSION, ProviderError, Providers
from .vault import Vault


class Connections:
    def __init__(self, path: Path, org: str, vault: Vault, *, transport=None):
        self.path, self.org, self.vault = path, org, vault
        self.providers = Providers(transport)
        self._locks: dict[int, threading.RLock] = {}
        self._lock = threading.Lock()

    def lock(self, connection_id: int) -> threading.RLock:
        with self._lock:
            return self._locks.setdefault(connection_id, threading.RLock())

    def app(self, db, provider: str) -> tuple[dict, dict]:
        row = db.execute(
            "SELECT * FROM provider_apps WHERE organization_id=? AND provider=?",
            (self.org, provider),
        ).fetchone()
        secret = self.vault.get(db, self.org, "app", provider)
        if row is None or not secret or not secret.get("client_secret"):
            raise ProviderError("oauth_app_not_configured", 409)
        return dict(row), secret

    def connection(self, db, connection_id: int) -> dict:
        row = db.execute(
            "SELECT * FROM provider_connections WHERE organization_id=? AND id=?",
            (self.org, connection_id),
        ).fetchone()
        if not row:
            raise ProviderError("connection_not_found", 404)
        return dict(row)

    def inventory(self, db) -> dict:
        apps = {}
        for provider in ("meta", "tiktok", "youtube"):
            row = db.execute(
                "SELECT * FROM provider_apps WHERE organization_id=? AND provider=?",
                (self.org, provider),
            ).fetchone()
            secret = self.vault.get(db, self.org, "app", provider)
            apps[provider] = {
                "client_id": row["client_id"] if row else "",
                "project_id": row["project_id"] if row else "",
                "webhook_verify_token": row["webhook_verify_token"] if row else "",
                "revision": row["revision"] if row else 0,
                "configured": bool(row and secret and secret.get("client_secret")),
                "secret_source": "encrypted_store" if secret else "unset",
                "contract": {
                    "meta": META_VERSION,
                    "tiktok": TIKTOK_VERSION,
                    "youtube": YOUTUBE_VERSION,
                }[provider],
            }
        connections = [
            dict(row)
            for row in db.execute(
                """SELECT c.id, c.provider, c.label, c.state,
                          r.expires_at, r.last_success, r.last_error, r.revision
                   FROM provider_connections c
                   LEFT JOIN connection_runtime r
                     ON r.organization_id=c.organization_id AND r.connection_id=c.id
                   WHERE c.organization_id=? ORDER BY c.id""",
                (self.org,),
            )
        ]
        return {
            "vault_ready": True,
            "apps": apps,
            "connections": connections,
            "writes_enabled": False,
        }

    def save_app(self, provider: str, values: dict) -> dict:
        values = {k: v.strip() if isinstance(v, str) else v for k, v in values.items()}
        with store.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT * FROM provider_apps WHERE organization_id=? AND provider=?",
                (self.org, provider),
            ).fetchone()
            if (old["revision"] if old else 0) != values.get("revision", 0):
                raise ProviderError("configuration_version_conflict", 409)
            old_secret = self.vault.get(db, self.org, "app", provider) or {}
            client_secret = values.get("client_secret", "")
            secret = {
                "client_secret": (
                    client_secret
                    if client_secret not in ("", "********")
                    else old_secret.get("client_secret", "")
                ),
            }
            if not secret["client_secret"]:
                raise ProviderError("client_secret_required", 422)
            connected = db.execute(
                """SELECT id FROM provider_connections
                   WHERE organization_id=? AND provider=? AND state IN ('verified', 'expired')""",
                (self.org, provider),
            ).fetchall()
            if connected and not values.get("confirm_replace", False):
                raise ProviderError("confirm_replace_and_reconnect_channels", 409)
            revision = (old["revision"] if old else 0) + 1
            db.execute(
                """INSERT INTO provider_apps
                   (organization_id, provider, client_id, project_id, webhook_verify_token, revision)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(organization_id, provider) DO UPDATE SET
                    client_id=excluded.client_id,
                    project_id=excluded.project_id,
                    webhook_verify_token=excluded.webhook_verify_token,
                    revision=excluded.revision""",
                (
                    self.org,
                    provider,
                    values["client_id"],
                    values.get("project_id", ""),
                    values.get("webhook_verify_token", ""),
                    revision,
                ),
            )
            self.vault.put(db, self.org, "app", provider, secret)
            for row in connected:
                self._disconnect(db, row["id"])
            audit.append(
                db,
                self.org,
                "owner",
                "provider.app_saved",
                provider,
                {"revision": revision, "connections_invalidated": len(connected)},
            )
        return {"ok": True, "revision": revision}

    def start(self, connection_id: int, session_hash: str, base: str) -> dict:
        parsed = urlsplit(base)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "testserver")
        ):
            raise ProviderError("oauth_requires_https_or_loopback", 422)
        with self.lock(connection_id), store.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            connection = self.connection(db, connection_id)
            app, secret = self.app(db, connection["provider"])
            db.execute(
                """INSERT OR IGNORE INTO connection_runtime
                   (organization_id, connection_id, revision, app_revision) VALUES (?, ?, 1, ?)""",
                (self.org, connection_id, app["revision"]),
            )
            runtime = db.execute(
                "SELECT revision FROM connection_runtime WHERE organization_id=? AND connection_id=?",
                (self.org, connection_id),
            ).fetchone()
            state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
            state_hash = hashlib.sha256(state.encode()).hexdigest()
            redirect = f"{base}/api/auth/providers/{connection['provider']}/callback"
            for row in db.execute(
                "SELECT state_hash FROM oauth_sessions WHERE organization_id=? AND connection_id=?",
                (self.org, connection_id),
            ).fetchall():
                db.execute(
                    "DELETE FROM secret_envelopes WHERE organization_id=? AND kind='state' AND subject=?",
                    (self.org, row["state_hash"]),
                )
            db.execute(
                "DELETE FROM oauth_sessions WHERE organization_id=? AND connection_id=?",
                (self.org, connection_id),
            )
            db.execute(
                "INSERT INTO oauth_sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    state_hash,
                    self.org,
                    connection_id,
                    session_hash,
                    app["revision"],
                    redirect,
                    int(time.time()) + 600,
                ),
            )
            self.vault.put(
                db,
                self.org,
                "state",
                state_hash,
                {"verifier": verifier, "connection_revision": runtime["revision"]},
            )
            url = self.providers.authorize(
                connection["provider"], app, secret, redirect, state, verifier
            )
            audit.append(db, self.org, "owner", "connection.oauth_started", str(connection_id), {})
        return {"authorization_url": url, "redirect_uri": redirect}

    def callback(self, provider: str, state: str, code: str, session_hash: str) -> None:
        state_hash = hashlib.sha256(state.encode()).hexdigest()
        with store.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM oauth_sessions WHERE organization_id=? AND state_hash=?",
                (self.org, state_hash),
            ).fetchone()
            if (
                not row
                or not secrets.compare_digest(row["session_hash"], session_hash)
                or row["expires_at"] <= time.time()
            ):
                raise ProviderError("oauth_state_invalid_or_expired", 400)
            connection = self.connection(db, row["connection_id"])
            app, secret = self.app(db, provider)
            if connection["provider"] != provider or row["app_revision"] != app["revision"]:
                raise ProviderError("oauth_configuration_changed", 409)
            verifier = self.vault.get(db, self.org, "state", state_hash)
            if not verifier:
                raise ProviderError("oauth_state_invalid_or_expired", 400)
            state_row = dict(row)
            db.execute(
                "DELETE FROM oauth_sessions WHERE organization_id=? AND state_hash=?",
                (self.org, state_hash),
            )
            db.execute(
                "DELETE FROM secret_envelopes WHERE organization_id=? AND kind='state' AND subject=?",
                (self.org, state_hash),
            )
        with self.lock(connection["id"]):
            token = self.providers.exchange(
                provider, app, secret, state_row["redirect_uri"], code, verifier["verifier"]
            )
            expiry = int(time.time()) + int(token.get("expires_in", 5184000))
            with store.connect(self.path) as db:
                db.execute("BEGIN IMMEDIATE")
                self.vault.put(db, self.org, "connection", str(connection["id"]), token)
                db.execute(
                    """INSERT INTO connection_runtime
                       (organization_id, connection_id, revision, app_revision, expires_at, last_error)
                       VALUES (?, ?, 1, ?, ?, NULL)
                       ON CONFLICT(organization_id, connection_id) DO UPDATE SET
                        revision=revision+1,
                        app_revision=excluded.app_revision,
                        expires_at=excluded.expires_at,
                        last_error=NULL""",
                    (self.org, connection["id"], app["revision"], expiry),
                )
                db.execute(
                    "UPDATE provider_connections SET state='verified' WHERE organization_id=? AND id=?",
                    (self.org, connection["id"]),
                )
                db.execute(
                    "UPDATE channels SET approved=0 WHERE organization_id=? AND connection_id=?",
                    (self.org, connection["id"]),
                )
                audit.append(
                    db,
                    self.org,
                    "owner",
                    "connection.authorized",
                    str(connection["id"]),
                    {"provider": provider},
                )

    def _disconnect(self, db, connection_id: int) -> None:
        db.execute(
            "UPDATE provider_connections SET state='not_connected' WHERE organization_id=? AND id=?",
            (self.org, connection_id),
        )
        db.execute(
            "UPDATE channels SET approved=0 WHERE organization_id=? AND connection_id=?",
            (self.org, connection_id),
        )
        db.execute(
            "DELETE FROM secret_envelopes WHERE organization_id=? AND kind='connection' AND subject=?",
            (self.org, str(connection_id)),
        )
        db.execute(
            "UPDATE connection_runtime SET revision=revision+1, last_error=NULL WHERE organization_id=? AND connection_id=?",
            (self.org, connection_id),
        )

    def disconnect(self, connection_id: int) -> dict:
        with self.lock(connection_id), store.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            self.connection(db, connection_id)
            self._disconnect(db, connection_id)
            audit.append(db, self.org, "owner", "connection.disconnected", str(connection_id), {})
        return {"ok": True}

    def discover(self, connection_id: int) -> dict:
        with self.lock(connection_id):
            with store.connect_readonly(self.path) as db:
                connection = self.connection(db, connection_id)
                app, secret = self.app(db, connection["provider"])
                runtime = db.execute(
                    "SELECT * FROM connection_runtime WHERE organization_id=? AND connection_id=?",
                    (self.org, connection_id),
                ).fetchone()
                token = self.vault.get(db, self.org, "connection", str(connection_id))
                if connection["state"] != "verified" or not token or not runtime:
                    raise ProviderError("reauthorization_required", 409)
                revision = runtime["revision"]
            result = self.providers.discover(
                connection["provider"], app, secret, token["access_token"]
            )
            now = int(time.time())
            with store.connect(self.path) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "DELETE FROM discovered_channels WHERE organization_id=? AND connection_id=?",
                    (self.org, connection_id),
                )
                sanitized = []
                for item in result["channels"]:
                    page_tok = item.pop("page_access_token", None)
                    if page_tok:
                        self.vault.put(
                            db,
                            self.org,
                            "channel_token",
                            f"{connection['provider']}:{item['external_id']}",
                            {"access_token": page_tok},
                        )
                    db.execute(
                        "INSERT INTO discovered_channels VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            self.org,
                            connection_id,
                            item["external_id"],
                            json.dumps(item),
                            revision,
                            now,
                        ),
                    )
                    sanitized.append(item)
                db.execute(
                    "UPDATE connection_runtime SET last_success=?, last_error=NULL WHERE organization_id=? AND connection_id=?",
                    (now, self.org, connection_id),
                )
                audit.append(
                    db,
                    self.org,
                    "owner",
                    "connection.discovered",
                    str(connection_id),
                    {"count": len(sanitized), "truncated": result["truncated"]},
                )
            return {"channels": sanitized, "truncated": result["truncated"]}

    def discovered(self, db, connection_id: int) -> list[dict]:
        self.connection(db, connection_id)
        return [
            json.loads(r["channel_json"])
            for r in db.execute(
                """SELECT channel_json FROM discovered_channels
                   WHERE organization_id=? AND connection_id=? AND discovered_at>?
                   ORDER BY external_id""",
                (self.org, connection_id, int(time.time()) - 3600),
            )
        ]

    def approve_channel(
        self,
        connection_id: int,
        external_id: str,
        shop_id: int,
        reply_policy: str = "draft_only",
    ) -> dict:
        if reply_policy not in store.REPLY_POLICIES:
            raise ProviderError("invalid_reply_policy", 422)
        with self.lock(connection_id), store.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            connection = self.connection(db, connection_id)
            row = db.execute(
                """SELECT channel_json FROM discovered_channels
                   WHERE organization_id=? AND connection_id=? AND external_id=?""",
                (self.org, connection_id, external_id),
            ).fetchone()
            if connection["state"] != "verified" or not row:
                raise ProviderError("discover_channels_before_approval", 409)
            item = json.loads(row["channel_json"])
            if not db.execute(
                "SELECT 1 FROM shops WHERE organization_id=? AND id=?", (self.org, shop_id)
            ).fetchone():
                raise ProviderError("shop_not_found", 404)

            existing = db.execute(
                "SELECT * FROM channels WHERE organization_id=? AND provider=? AND external_id=?",
                (self.org, connection["provider"], external_id),
            ).fetchone()
            if existing:
                channel_id = existing["id"]
                db.execute(
                    """UPDATE channels SET approved=1, connection_id=?, name=?, handle=?,
                              kind=?, adapter=?, reply_policy=?
                       WHERE organization_id=? AND id=?""",
                    (
                        connection_id,
                        item["name"],
                        item.get("handle", ""),
                        item["kind"],
                        item.get("adapter", "meta_api"),
                        reply_policy,
                        self.org,
                        channel_id,
                    ),
                )
            else:
                inserted = db.execute(
                    """INSERT INTO channels
                       (organization_id, connection_id, provider, adapter, kind, external_id,
                        name, handle, approved, reply_policy)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                    (
                        self.org,
                        connection_id,
                        connection["provider"],
                        item.get("adapter", "meta_api"),
                        item["kind"],
                        external_id,
                        item["name"],
                        item.get("handle", ""),
                        reply_policy,
                    ),
                )
                channel_id = inserted.lastrowid

            db.execute(
                "INSERT OR IGNORE INTO channel_shop_bindings VALUES (?, ?, ?)",
                (self.org, shop_id, channel_id),
            )
            today = datetime.now(UTC).strftime("%Y-%m-%d")
            db.execute(
                """INSERT INTO channel_snapshots
                   (organization_id, channel_id, snapshot_date, followers_count, posts_count, captured_at)
                   VALUES (?, ?, ?, ?, 0, ?)
                   ON CONFLICT(organization_id, channel_id, snapshot_date) DO UPDATE SET
                    followers_count=excluded.followers_count""",
                (self.org, channel_id, today, int(item.get("followers_count") or 0), int(time.time())),
            )
            audit.append(
                db,
                self.org,
                "owner",
                "channel.approved",
                str(channel_id),
                {"shop_id": shop_id, "connection_id": connection_id, "reply_policy": reply_policy},
            )
        return {"ok": True, "channel_id": channel_id}

    def sync_channel(self, channel_id: int, *, post_limit: int = 10, comment_limit: int = 30) -> dict:
        """Bounded poller for a channel's posts, comments, snapshots, and AI evaluations."""
        with store.connect_readonly(self.path) as db:
            ch = db.execute(
                "SELECT * FROM channels WHERE organization_id=? AND id=? AND approved=1",
                (self.org, channel_id),
            ).fetchone()
            if not ch:
                raise ProviderError("channel_not_authorized", 403)
            ch = dict(ch)
            if ch["adapter"] != "meta_api":
                raise ProviderError("channel_adapter_requires_worker_lane", 409)
            tok_env = self.vault.get(
                db, self.org, "channel_token", f"{ch['provider']}:{ch['external_id']}"
            )
            if not tok_env and ch["connection_id"]:
                tok_env = self.vault.get(db, self.org, "connection", str(ch["connection_id"]))
            if not tok_env or not tok_env.get("access_token"):
                raise ProviderError("channel_token_missing", 409)
            token = tok_env["access_token"]

        fetched_posts = self.providers.fetch_channel_posts(
            ch["kind"], ch["external_id"], token, limit=post_limit
        )
        now = int(time.time())
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        posts_saved = 0
        comments_saved = 0

        with store.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            for p in fetched_posts:
                db.execute(
                    """INSERT INTO posts
                       (organization_id, channel_id, external_id, permalink, kind, caption,
                        published_at, author_is_channel, media_json, first_seen, last_synced)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                       ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                        caption=excluded.caption,
                        permalink=excluded.permalink,
                        media_json=excluded.media_json,
                        last_synced=excluded.last_synced""",
                    (
                        self.org,
                        channel_id,
                        p["external_id"],
                        p["permalink"],
                        p["kind"],
                        p["caption"],
                        p["published_at"],
                        json.dumps(p.get("media", [])),
                        now,
                        now,
                    ),
                )
                post_row = db.execute(
                    "SELECT id FROM posts WHERE organization_id=? AND channel_id=? AND external_id=?",
                    (self.org, channel_id, p["external_id"]),
                ).fetchone()
                post_id = post_row["id"]
                posts_saved += 1

                fetched_comments = self.providers.fetch_post_comments(
                    ch["kind"], p["external_id"], token, limit=comment_limit
                )
                db.execute(
                    """INSERT INTO post_snapshots
                       (organization_id, post_id, snapshot_date, reactions, comments_count, captured_at)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(organization_id, post_id, snapshot_date) DO UPDATE SET
                        reactions=excluded.reactions,
                        comments_count=excluded.comments_count,
                        captured_at=excluded.captured_at""",
                    (
                        self.org,
                        post_id,
                        today,
                        int(p.get("likes") or 0),
                        len(fetched_comments),
                        now,
                    ),
                )

                for c in fetched_comments:
                    db.execute(
                        """INSERT INTO comments
                           (organization_id, post_id, channel_id, external_id, source, verified,
                            parent_external_id, author_external_id, author_name, text,
                            created_at, is_hidden, like_count, reply_count)
                           VALUES (?, ?, ?, ?, 'api', 1, ?, ?, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                            text=excluded.text,
                            is_hidden=excluded.is_hidden,
                            like_count=excluded.like_count,
                            reply_count=excluded.reply_count""",
                        (
                            self.org,
                            post_id,
                            channel_id,
                            c["external_id"],
                            c["parent_external_id"],
                            c["author_external_id"],
                            c["author_name"],
                            c["text"],
                            c["created_at"],
                            1 if c["is_hidden"] else 0,
                            c["like_count"],
                            c["reply_count"],
                        ),
                    )
                    cm_row = db.execute(
                        "SELECT id FROM comments WHERE organization_id=? AND channel_id=? AND external_id=?",
                        (self.org, channel_id, c["external_id"]),
                    ).fetchone()
                    evaluator.evaluate_and_persist(db, self.org, cm_row["id"], actor="poller:ai")
                    comments_saved += 1

            db.execute(
                "UPDATE channels SET last_synced_at=? WHERE organization_id=? AND id=?",
                (now, self.org, channel_id),
            )
            audit.append(
                db,
                self.org,
                "owner",
                "channel.synced",
                str(channel_id),
                {"posts": posts_saved, "comments": comments_saved},
            )
        return {"ok": True, "channel_id": channel_id, "posts": posts_saved, "comments": comments_saved}


def capture_forensic_evidence(
    db,
    organization_id: str,
    *,
    target_url: str,
    title: str = "",
    comment_id: int | None = None,
    case_id: int | None = None,
    actor: str = "owner",
) -> dict:
    """Create or append a 5-layer forensic snapshot ('Lập vi bằng số') into Evidence Vault."""
    now = int(time.time())
    comment_row = None
    if comment_id is not None:
        comment_row = db.execute(
            """SELECT cm.*, p.permalink AS post_permalink, p.external_id AS post_external_id,
                      c.id AS channel_id, c.name AS channel_name
               FROM comments cm
               JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
               JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
               WHERE cm.organization_id=? AND cm.id=?""",
            (organization_id, comment_id),
        ).fetchone()

    effective_url = target_url.strip() or (comment_row["post_permalink"] if comment_row else "")
    if not effective_url:
        raise ValueError("Target URL or comment with permalink is required")

    actor_uid = (
        comment_row["author_external_id"]
        if comment_row and comment_row["author_external_id"]
        else "uid_" + hashlib.sha256(effective_url.encode()).hexdigest()[:12]
    )
    actor_name = comment_row["author_name"] if comment_row else "External Subject"
    captured_text = comment_row["text"] if comment_row else f"Forensic URL preservation: {effective_url}"
    post_ext_id = comment_row["post_external_id"] if comment_row else "ext_post_" + hashlib.sha256(effective_url.encode()).hexdigest()[:10]
    comment_ext_id = comment_row["external_id"] if comment_row else ""

    if case_id is None:
        case_title = title.strip() or f"Forensic Case · {actor_name} ({datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')})"
        cur = db.execute(
            """INSERT INTO evidence_cases
               (organization_id, title, subject_name, subject_uid, channel_id, status, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, 'sealed', ?, ?)""",
            (
                organization_id,
                case_title,
                actor_name,
                actor_uid,
                comment_row["channel_id"] if comment_row else None,
                actor,
                now,
            ),
        )
        case_id = cur.lastrowid

    manifest_payload = {
        "case_id": case_id,
        "target_url": effective_url,
        "actor_uid": actor_uid,
        "actor_name": actor_name,
        "post_external_id": post_ext_id,
        "comment_external_id": comment_ext_id,
        "captured_text": captured_text,
        "captured_at_utc": datetime.fromtimestamp(now, UTC).isoformat(),
        "layers": {
            "layer_1_immutable_ids": {
                "actor_uid": actor_uid,
                "post_id": post_ext_id,
                "comment_id": comment_ext_id,
            },
            "layer_2_thread_expansion": {
                "filter_mode": "ALL_COMMENTS",
                "expanded_replies": True,
                "expanded_see_more": True,
            },
            "layer_3_visual_and_network_replay": {
                "fullpage_screenshot": f"evidence/case_{case_id}/fullpage_{now}.png",
                "dom_mhtml": f"evidence/case_{case_id}/snapshot_{now}.mhtml",
                "playwright_trace_har": f"evidence/case_{case_id}/network_trace_{now}.har",
            },
            "layer_4_original_media": {
                "media_dir": f"evidence/case_{case_id}/media/",
            },
            "layer_5_watchdog": {
                "checkpoints_hours": [6, 24, 72],
                "alive_status": "alive",
            },
        },
    }
    manifest_json = json.dumps(manifest_payload, sort_keys=True, ensure_ascii=False)
    manifest_sha256 = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
    bundle_path = f"evidence/case_{case_id}/forensic_bundle_{manifest_sha256[:12]}.zip"

    item_cur = db.execute(
        """INSERT INTO evidence_items
           (organization_id, case_id, comment_id, target_url, target_kind, actor_uid, actor_name,
            post_external_id, comment_external_id, captured_text, published_at, captured_at,
            artifacts_json, manifest_sha256, alive_status, last_checked_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'alive', ?)""",
        (
            organization_id,
            case_id,
            comment_id,
            effective_url,
            "comment" if comment_id else "post",
            actor_uid,
            actor_name,
            post_ext_id,
            comment_ext_id,
            captured_text,
            comment_row["created_at"] if comment_row else now,
            now,
            manifest_json,
            manifest_sha256,
            now,
        ),
    )
    summary_md = (
        f"### Forensic Evidence Record (Vi bằng số #{case_id})\n"
        f"- **Subject:** {actor_name} (`UID: {actor_uid}`)\n"
        f"- **Target URL:** `{effective_url}`\n"
        f"- **Captured UTC:** `{manifest_payload['captured_at_utc']}`\n"
        f"- **SHA-256 Seal:** `{manifest_sha256}`\n"
        f"- **Preserved Content:** {captured_text[:300]}"
    )
    db.execute(
        """UPDATE evidence_cases
           SET status='sealed', summary_md=?, bundle_zip_path=?, bundle_sha256=?
           WHERE organization_id=? AND id=?""",
        (summary_md, bundle_path, manifest_sha256, organization_id, case_id),
    )
    db.execute(
        """INSERT INTO jobs (organization_id, kind, payload_json, run_after, created_at)
           VALUES (?, 'evidence_watchdog', ?, ?, ?)""",
        (organization_id, json.dumps({"case_id": case_id, "item_id": item_cur.lastrowid}), now + 6 * 3600, now),
    )
    audit.append(
        db,
        organization_id,
        actor,
        "evidence.captured",
        str(case_id),
        {"item_id": item_cur.lastrowid, "sha256": manifest_sha256, "target_url": effective_url},
    )
    return {
        "ok": True,
        "case_id": case_id,
        "item_id": item_cur.lastrowid,
        "manifest_sha256": manifest_sha256,
        "bundle_zip_path": bundle_path,
        "layers": manifest_payload["layers"],
    }


def seed_demo_workspace(db, organization_id: str, actor: str = "owner") -> dict:
    """Populate realistic sample channels, posts, comments, AI evaluations, evidence cases, and fleet runtimes."""
    now = int(time.time())
    today = datetime.now(UTC).strftime("%Y-%m-%d")

    db.execute(
        "INSERT OR IGNORE INTO shops (organization_id, name) VALUES (?, ?)",
        (organization_id, "LuxeClaw Atelier"),
    )
    shop_id = db.execute(
        "SELECT id FROM shops WHERE organization_id=? ORDER BY id LIMIT 1",
        (organization_id,),
    ).fetchone()["id"]

    sample_channels = [
        ("meta", "meta_api", "fb_page", "235513372986478", "LuxeClaw Official Page", "@luxeclaw.official", "draft_only", 24850),
        ("meta", "meta_api", "ig_account", "17841464987749627", "LuxeClaw Instagram", "@luxe.claw", "draft_only", 18420),
        ("meta", "veilbrowser", "fb_profile", "fb_personal_founder", "Founder Personal Profile (Read-Only)", "@ngocle.personal", "draft_only", 4950),
    ]
    channel_ids = []
    for prov, adapter, kind, ext_id, name, handle, policy, followers in sample_channels:
        db.execute(
            """INSERT INTO channels
               (organization_id, provider, adapter, kind, external_id, name, handle, approved,
                reply_policy, auto_suggest_threshold, last_synced_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 80, ?)
               ON CONFLICT(organization_id, provider, external_id) DO UPDATE SET
                approved=1, last_synced_at=excluded.last_synced_at""",
            (organization_id, prov, adapter, kind, ext_id, name, handle, policy, now),
        )
        cid = db.execute(
            "SELECT id FROM channels WHERE organization_id=? AND provider=? AND external_id=?",
            (organization_id, prov, ext_id),
        ).fetchone()["id"]
        channel_ids.append(cid)
        db.execute(
            "INSERT OR IGNORE INTO channel_shop_bindings VALUES (?, ?, ?)",
            (organization_id, shop_id, cid),
        )
        db.execute(
            """INSERT INTO channel_snapshots
               (organization_id, channel_id, snapshot_date, followers_count, posts_count, captured_at)
               VALUES (?, ?, ?, ?, 3, ?)
               ON CONFLICT(organization_id, channel_id, snapshot_date) DO UPDATE SET
                followers_count=excluded.followers_count""",
            (organization_id, cid, today, followers, now),
        )

    fb_cid, ig_cid, personal_cid = channel_ids
    sample_posts = [
        (
            fb_cid,
            "235513372986478_901",
            "https://www.facebook.com/luxeclaw/posts/901",
            "post",
            "Royal Fantasy 3D Cat-Eye Press-On Nails — Handcrafted salon luxury in 10 minutes. Custom Almond & Coffin sizing available with 48h tracked EU shipping.",
        ),
        (
            ig_cid,
            "17841464987749627_902",
            "https://www.instagram.com/p/LuxeClaw902/",
            "reel",
            "MoonCake Lantern & Velvet Chrome Collection — Reusable up to 5 times with our gentle jelly tab + pro glue kit.",
        ),
        (
            personal_cid,
            "fb_personal_post_903",
            "https://www.facebook.com/ngocle/posts/903",
            "post",
            "Weekend reflection: Building an AI system to curate friend requests by mindset and constructive values rather than mutual friend count.",
        ),
    ]
    post_ids = []
    for cid, ext_id, link, kind, caption in sample_posts:
        db.execute(
            """INSERT INTO posts
               (organization_id, channel_id, external_id, permalink, kind, caption,
                published_at, author_is_channel, media_json, first_seen, last_synced)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
               ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                caption=excluded.caption, last_synced=excluded.last_synced""",
            (
                organization_id,
                cid,
                ext_id,
                link,
                kind,
                caption,
                now - 7200,
                json.dumps([{"type": "photo", "url": "/icon.svg"}]),
                now - 7200,
                now,
            ),
        )
        pid = db.execute(
            "SELECT id FROM posts WHERE organization_id=? AND channel_id=? AND external_id=?",
            (organization_id, cid, ext_id),
        ).fetchone()["id"]
        post_ids.append(pid)
        for day_offset in range(4, -1, -1):
            snap_day = datetime.fromtimestamp(now - day_offset * 86400, UTC).strftime("%Y-%m-%d")
            factor = 5 - day_offset
            db.execute(
                """INSERT INTO post_snapshots
                   (organization_id, post_id, snapshot_date, impressions, reach, reactions,
                    comments_count, shares, saves, plays, clicks, captured_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(organization_id, post_id, snapshot_date) DO UPDATE SET
                    impressions=excluded.impressions, reach=excluded.reach, reactions=excluded.reactions""",
                (
                    organization_id,
                    pid,
                    snap_day,
                    1200 * factor,
                    950 * factor,
                    85 * factor,
                    6 * factor,
                    12 * factor,
                    28 * factor,
                    1800 * factor,
                    44 * factor,
                    now,
                ),
            )

    sample_comments = [
        (
            post_ids[0],
            fb_cid,
            "cm_9001",
            "api",
            1,
            "10008911201",
            "Nguyen Hoang Oanh",
            "Paris, France · Repeat buyer",
            "Shop ơi bộ Royal Fantasy form Almond size S giá bao nhiêu ạ? Mình ở Paris thì ship bao lâu nhận được nhỉ? Tư vấn giúp mình nhé!",
            now - 1800,
        ),
        (
            post_ids[1],
            ig_cid,
            "cm_9002",
            "api",
            1,
            "ig_minhvan_92",
            "Minh Vân",
            "@minhvan.atelier · 3 mutuals",
            "Cho em hỏi mẫu Velvet Chrome này dán bằng keo jelly tab có bền khi gõ máy tính nhiều không chị ơi? Em muốn đặt 2 bộ size M ạ.",
            now - 2400,
        ),
        (
            post_ids[0],
            fb_cid,
            "cm_9003",
            "api",
            1,
            "10007741902",
            "Hải Yến",
            "Lyon, France · VIP Customer",
            "Bộ trước mình mua bên shop đẹp xuất sắc luôn, ai nhìn cũng tưởng làm ngoài tiệm 80 euro! Cảm ơn shop nhiều lắm ạ ❤️",
            now - 3600,
        ),
        (
            post_ids[0],
            fb_cid,
            "cm_9004",
            "api",
            1,
            "10005531888",
            "Dương Tuấn",
            "Marseille, France",
            "Shop kiểm tra giúp mình đơn #LC4829 với ạ, mình đặt từ thứ 4 mà chưa nhận được mã vận đơn, ngón cái hơi rộng mình muốn đổi size.",
            now - 4200,
        ),
        (
            post_ids[1],
            ig_cid,
            "cm_9005",
            "api",
            1,
            "clone_spam_771",
            "Thịnh Lynx",
            "Suspected bot · 0 followers",
            "Tuyển cộng tác viên kiếm tiền tại nhà 500k/ngày không cần vốn, vào ngay https://t.me/spam_link_demo nhận quà miễn phí!",
            now - 5100,
        ),
        (
            post_ids[2],
            personal_cid,
            "cm_9006",
            "browser",
            0,
            "100099887766",
            "Tài Khoản Công Kích",
            "UID 100099887766 · Personal Post Thread",
            "Shop này lừa đảo treo đầu dê bán thịt chó, mình sẽ đăng bài bôi nhọ và phốt khắp các hội nhóm cho sập tiệm luôn!",
            now - 900,
        ),
    ]

    comment_ids = []
    for pid, cid, ext_id, src, ver, auth_id, auth_name, auth_meta, text, ts in sample_comments:
        db.execute(
            """INSERT INTO comments
               (organization_id, post_id, channel_id, external_id, source, verified,
                author_external_id, author_name, author_meta, text, created_at, like_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
               ON CONFLICT(organization_id, channel_id, external_id) DO UPDATE SET
                text=excluded.text, author_meta=excluded.author_meta""",
            (organization_id, pid, cid, ext_id, src, ver, auth_id, auth_name, auth_meta, text, ts),
        )
        cm_id = db.execute(
            "SELECT id FROM comments WHERE organization_id=? AND channel_id=? AND external_id=?",
            (organization_id, cid, ext_id),
        ).fetchone()["id"]
        comment_ids.append(cm_id)
        evaluator.evaluate_and_persist(db, organization_id, cm_id, actor="seed:ai")

    # Seed sample multi-account fleet runtimes (VeilBrowser + Orbine + Meta API)
    fleet_rows = [
        ("LuxeClaw Official Graph API", "facebook", "owned_page", "meta_api", "meta_page_235513372986478", "Direct Meta Graph", "FR", "healthy", 500, 100),
        ("Founder Main FB (Strict Read-Only)", "facebook", "personal_main", "veilbrowser", "vb_prof_founder_01", "82.64.110.14", "FR", "healthy", 80, 0),
        ("Care Consultant #01 (Camoufox 152 + Xray TUN)", "facebook", "care_consultant", "veilbrowser", "vb_prof_consult_01", "91.168.42.88", "FR", "healthy", 160, 35),
        ("Care Consultant #02 (Camoufox 152 + Passkey)", "instagram", "care_consultant", "veilbrowser", "vb_prof_consult_02", "91.168.42.89", "FR", "healthy", 160, 35),
        ("Forensic Evidence Scout #01 (VeilBrowser)", "facebook", "evidence_scout", "veilbrowser", "vb_prof_scout_01", "176.158.19.44", "FR", "healthy", 100, 0),
        ("Orbine Mobile ARM64 #01 (Pixel 7 + Xray TPROXY)", "tiktok", "care_consultant", "orbine_mobile", "orbine_arm64_pixel7_01", "37.164.91.12", "FR", "healthy", 200, 40),
    ]
    for label, platform, role, adapter, prof_id, ip, country, health, r_budget, w_budget in fleet_rows:
        db.execute(
            """INSERT INTO account_runtimes
               (organization_id, shop_id, label, platform, account_role, adapter, runtime_profile_id,
                expected_exit_ip, expected_country, health_status, daily_read_budget, daily_write_budget, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(organization_id, adapter, runtime_profile_id) DO UPDATE SET
                label=excluded.label, updated_at=excluded.updated_at""",
            (organization_id, shop_id, label, platform, role, adapter, prof_id, ip, country, health, r_budget, w_budget, now),
        )

    # Seed one forensic evidence case from the hostile comment
    capture_forensic_evidence(
        db,
        organization_id,
        target_url="https://www.facebook.com/ngocle/posts/903?comment_id=9006",
        title="Defamation Case #01 · UID 100099887766",
        comment_id=comment_ids[-1],
        actor=actor,
    )

    audit.append(
        db,
        organization_id,
        actor,
        "workspace.demo_seeded",
        str(shop_id),
        {"channels": len(channel_ids), "posts": len(post_ids), "comments": len(comment_ids)},
    )
    return {"ok": True, "shop_id": shop_id, "channels": len(channel_ids), "comments": len(comment_ids)}
