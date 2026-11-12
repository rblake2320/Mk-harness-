"""Retention purge (S13).  python -m app.tools.retention run [--only key,key]
                            python -m app.tools.retention rules"""
import argparse
import json
import sys

from ..db import get_db
from ..retention import RULES, run


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="app.tools.retention")
    ap.add_argument("cmd", choices=["run", "rules"])
    ap.add_argument("--only", default="")
    a = ap.parse_args(argv)
    if a.cmd == "rules":
        print(json.dumps([{"key": r.key, "days": r.days, "policy": r.policy} for r in RULES], indent=2))
        return 0
    db = next(get_db())
    try:
        print(json.dumps(run(db, only=set(filter(None, a.only.split(","))) or None), sort_keys=True))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
