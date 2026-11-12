"""Erasure operations (S13).

  python -m app.tools.erasure verify    # verify the external ledger chain + seals
  python -m app.tools.erasure replay    # after ANY database restore, before dispatch
  python -m app.tools.erasure deliver   # push pending kernel/provider erasures
  python -m app.tools.erasure status    # pending / overdue counts (content-free)
Exit 1 when the ledger does not verify, or (status) when any request is overdue."""
import argparse
import json
import sys

from sqlalchemy import func, select

from ..db import get_db
from ..erasure import deliver_to_kernel, ledger_entries, replay
from ..foundation import utcnow
from ..models import ErasureRequest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="app.tools.erasure")
    ap.add_argument("cmd", choices=["verify", "replay", "deliver", "status"])
    a = ap.parse_args(argv)
    if a.cmd == "verify":
        try:
            n = len(ledger_entries(verify=True))
        except ValueError as e:
            print(f"LEDGER BROKEN: {e}")
            return 1
        print(f"ledger verifies: {n} entries")
        return 0
    db = next(get_db())
    try:
        if a.cmd == "replay":
            try:
                print(json.dumps(replay(db)))
            except ValueError as e:
                print(f"LEDGER BROKEN — refusing to replay: {e}")
                return 1
            return 0
        if a.cmd == "deliver":
            print(json.dumps({"acknowledged": deliver_to_kernel(db)}))
            return 0
        pending = db.scalar(select(func.count()).select_from(ErasureRequest).where(
            ErasureRequest.kernel_acknowledged_at.is_(None), ErasureRequest.legal_hold.is_(False))) or 0
        overdue = db.scalar(select(func.count()).select_from(ErasureRequest).where(
            ErasureRequest.kernel_acknowledged_at.is_(None), ErasureRequest.legal_hold.is_(False),
            ErasureRequest.due_by < utcnow())) or 0
        print(json.dumps({"pending": pending, "overdue": overdue}))
        return 1 if overdue else 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
