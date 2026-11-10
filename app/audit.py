"""Organization-local integrity chain, not an externally anchored signature."""
import hashlib
import json
import sqlite3
from datetime import UTC, datetime


def canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(previous: str, event: dict) -> str:
    return hashlib.sha256((previous + "\n" + canonical(event)).encode()).hexdigest()


def append(
    db: sqlite3.Connection, org: str, actor: str, action: str, subject: str, details: dict
) -> None:
    previous = db.execute(
        "SELECT sequence,event_hash FROM audit_events WHERE organization_id=? ORDER BY sequence DESC LIMIT 1",
        (org,),
    ).fetchone()
    sequence, previous_hash = (
        (previous["sequence"] + 1, previous["event_hash"]) if previous else (1, "0" * 64)
    )
    event = {
        "organization_id": org,
        "sequence": sequence,
        "actor": actor,
        "action": action,
        "subject": subject,
        "details": details,
        "created_at": datetime.now(UTC).isoformat(),
    }
    db.execute(
        """INSERT INTO audit_events
           (organization_id,sequence,actor,action,subject,details,created_at,previous_hash,event_hash)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            org,
            sequence,
            actor,
            action,
            subject,
            canonical(details),
            event["created_at"],
            previous_hash,
            digest(previous_hash, event),
        ),
    )


def events(db: sqlite3.Connection, org: str, after: int, limit: int) -> list[dict]:
    return [
        {**dict(row), "details": json.loads(row["details"])}
        for row in db.execute(
            """SELECT sequence,actor,action,subject,details,created_at,previous_hash,event_hash
               FROM audit_events WHERE organization_id=? AND sequence>? ORDER BY sequence LIMIT ?""",
            (org, after, limit),
        )
    ]


def list_recent(db: sqlite3.Connection, org: str, limit: int = 100) -> list[dict]:
    return [
        {**dict(row), "details": json.loads(row["details"])}
        for row in db.execute(
            """SELECT sequence,actor,action,subject,details,created_at,previous_hash,event_hash
               FROM audit_events WHERE organization_id=? ORDER BY sequence DESC LIMIT ?""",
            (org, limit),
        )
    ]


def verify(db: sqlite3.Connection, org: str) -> dict:
    previous, expected = "0" * 64, 1
    for row in db.execute("SELECT * FROM audit_events WHERE organization_id=? ORDER BY sequence", (org,)):
        try:
            event = {
                key: row[key]
                for key in ("organization_id", "sequence", "actor", "action", "subject", "created_at")
            }
            event["details"] = json.loads(row["details"])
            valid = (
                row["sequence"] == expected
                and row["previous_hash"] == previous
                and row["event_hash"] == digest(previous, event)
            )
        except (ValueError, TypeError):
            valid = False
        if not valid:
            return {
                "ok": False,
                "valid": False,
                "checked": expected - 1,
                "invalid_sequence": row["sequence"],
                "broken_sequence": row["sequence"],
            }
        previous = row["event_hash"]
        expected += 1
    return {"ok": True, "valid": True, "checked": expected - 1, "head_hash": previous}
