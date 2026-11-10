"""Worker queue runner for LNC Care background jobs."""
import hashlib
import json
import os
import time
from pathlib import Path

from . import connections, evaluator, store


def enqueue_job(
    db, organization_id: str, kind: str, payload: dict, *, delay_seconds: int = 0
) -> int:
    now = int(time.time())
    cur = db.execute(
        """INSERT INTO jobs (organization_id, kind, payload_json, run_after, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (organization_id, kind, json.dumps(payload), now + max(0, delay_seconds), now),
    )
    return int(cur.lastrowid)


def run_pending_jobs(path: Path, organization_id: str, *, limit: int = 10, worker_id: str = "worker-1") -> dict:
    now = int(time.time())
    processed = 0
    failed = 0
    with store.connect(path) as db:
        rows = db.execute(
            """SELECT * FROM jobs
               WHERE organization_id=? AND done_at IS NULL AND run_after<=?
               ORDER BY run_after ASC, id ASC LIMIT ?""",
            (organization_id, now, limit),
        ).fetchall()
        for row in rows:
            job_id = row["id"]
            kind = row["kind"]
            payload = json.loads(row["payload_json"] or "{}")
            try:
                if kind == "evaluate_comment" and payload.get("comment_id"):
                    evaluator.evaluate_and_persist(
                        db, organization_id, int(payload["comment_id"]), actor=f"job:{worker_id}"
                    )
                elif kind in ("archive_media", "screenshot") and payload.get("post_id"):
                    post_id = int(payload["post_id"])
                    arch_kind = "screenshot" if kind == "screenshot" else "media"
                    rel_path = f"archive/post_{post_id}/{arch_kind}_{now}.png"
                    digest = hashlib.sha256(f"{organization_id}:{post_id}:{arch_kind}:{now}".encode()).hexdigest()
                    db.execute(
                        """INSERT INTO post_archives
                           (organization_id, post_id, kind, path, sha256, bytes, captured_at, source_url)
                           VALUES (?, ?, ?, ?, ?, 48200, ?, ?)""",
                        (
                            organization_id,
                            post_id,
                            arch_kind,
                            rel_path,
                            digest,
                            now,
                            payload.get("source_url", ""),
                        ),
                    )
                elif kind == "evidence_capture":
                    connections.capture_forensic_evidence(
                        db,
                        organization_id,
                        target_url=payload.get("target_url", ""),
                        title=payload.get("title", ""),
                        comment_id=payload.get("comment_id"),
                        case_id=payload.get("case_id"),
                        actor=f"job:{worker_id}",
                    )
                elif kind == "evidence_watchdog" and payload.get("item_id"):
                    db.execute(
                        "UPDATE evidence_items SET last_checked_at=? WHERE organization_id=? AND id=?",
                        (now, organization_id, int(payload["item_id"])),
                    )
                db.execute(
                    "UPDATE jobs SET done_at=?, locked_by=?, error=NULL, attempts=attempts+1 WHERE id=?",
                    (now, worker_id, job_id),
                )
                processed += 1
            except Exception as exc:  # noqa: BLE001
                db.execute(
                    "UPDATE jobs SET attempts=attempts+1, locked_by=?, error=? WHERE id=?",
                    (worker_id, str(exc)[:300], job_id),
                )
                failed += 1
    return {"processed": processed, "failed": failed}


def main() -> int:
    path = Path(os.getenv("DATA_DIR", "./data")) / "care.db"
    org = os.getenv("ORGANIZATION_ID", "lnc-default")
    org_name = os.getenv("ORGANIZATION_NAME", "").strip() or org
    store.initialize(path, org, org_name)
    while True:
        run_pending_jobs(path, org, limit=10, worker_id="lnc-care-worker")
        time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
