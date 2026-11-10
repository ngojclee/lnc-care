"""Offline CLI helper to rewrap encrypted envelopes under a new LNC_MASTER_KEY."""
import os
import sys
from pathlib import Path

from . import audit, store
from .vault import Vault


def main() -> int:
    old_key = os.getenv("OLD_LNC_MASTER_KEY") or os.getenv("LNC_PREVIOUS_MASTER_KEY") or ""
    new_key = os.getenv("NEW_LNC_MASTER_KEY") or os.getenv("LNC_MASTER_KEY") or ""
    org = os.getenv("ORGANIZATION_ID") or os.getenv("DEFAULT_ORG_SLUG") or "lnc-default"
    db_env = os.getenv("DATABASE_PATH")
    path = Path(db_env) if db_env else Path(os.getenv("DATA_DIR", "./data")) / "care.db"
    if not old_key or not new_key or not org:
        sys.stderr.write("Set OLD_LNC_MASTER_KEY/LNC_PREVIOUS_MASTER_KEY and NEW_LNC_MASTER_KEY/LNC_MASTER_KEY\n")
        return 2
    vault = Vault(old_key)
    with store.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        count = vault.rewrap(db, org, new_key)
        audit.append(db, org, "owner", "vault.rewrapped", "secret_envelopes", {"count": count})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
