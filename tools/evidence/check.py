#!/usr/bin/env python3
"""Validate evidence records against evidence/releases/schema.yaml and verify
artifact checksums for local paths. Exit 1 on any failure. Used by CI and by
the release owner before sign-off.

    python -I tools/evidence/check.py [evidence/releases/<release-id>]
"""
import hashlib
import pathlib
import sys

import jsonschema
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = yaml.safe_load((ROOT / "evidence/releases/schema.yaml").read_text())


def check_record(path: pathlib.Path) -> list[str]:
    problems = []
    rec = yaml.safe_load(path.read_text())
    try:
        jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker()).validate(rec)
    except jsonschema.ValidationError as e:
        return [f"{path}: schema: {e.message}"]
    if rec["requirement_id"] != path.stem:
        problems.append(f"{path}: requirement_id {rec['requirement_id']} != filename")
    for ev in rec["evidence"]:
        loc = ev["location"]
        p = (ROOT / loc) if not loc.startswith(("http://", "https://")) else None
        if p is not None:
            if not p.exists():
                problems.append(f"{path}: evidence missing: {loc}")
            elif hashlib.sha256(p.read_bytes()).hexdigest() != ev["sha256"]:
                problems.append(f"{path}: checksum mismatch: {loc}")
    if rec["status"] in ("independently_verified", "production_proven") and not rec["verifier_independent_of_author"]:
        problems.append(f"{path}: {rec['status']} requires an independent verifier")
    return problems


def main() -> int:
    base = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evidence/releases"
    records = sorted(p for p in base.rglob("*.yaml") if p.name not in ("schema.yaml",))
    problems = [m for r in records for m in check_record(r)]
    for m in problems:
        print("FAIL", m)
    print(f"{len(records)} record(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
