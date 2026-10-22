#!/usr/bin/env python3
"""Release verdict computed from evidence, not prose (contract §Final sign-off).

    python -I tools/evidence/readiness.py [--release <release-id>] [--json]

Inputs
  docs/production-acceptance.md      every row's ID, gate and status cell
  evidence/releases/<release-id>/    validated records (tools/evidence/check.py)

Rules (from docs/production-completion-contract.md and the matrix §0)
  * Vocabulary is exactly: not_demonstrated < implemented < independently_verified
    < production_proven.
  * A status cell containing "Not demonstrated" anywhere is Not demonstrated:
    the parent takes the lowest child state. A cell is Independently verified
    only when it contains that phrase and no lower state.
  * Gate "Release" requires independently_verified; "Release (proven)" requires
    production_proven; decision rows (gate "Record") and commercial rows
    require independently_verified (a signed record by someone other than the
    author); rows with no gate column are release-gated by default.
  * Only an evidence record can CLOSE a row. The matrix cell may describe
    progress; a record that fails validation closes nothing. A record never
    lowers a row below what the matrix says — but a matrix claim above the
    record level without a record is reported as "unbacked".
  * Verdict is READY FOR GENERAL RELEASE WITHIN THE DEFINED SCOPE only when
    every gated row is closed at its required level by a validated record;
    otherwise NOT READY with the exact failing IDs. Unknown rows block.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs/production-acceptance.md"
LEVELS = ["not_demonstrated", "implemented", "independently_verified", "production_proven"]
ROW_RE = re.compile(r"^\| ([A-Z]{1,2}\d{1,2}) \| (.*) \|\s*$")

# Final sign-off checklist → the rows that answer each question.
CHECKLIST = [
    ("Is the full advertised consultant workflow complete?", ["F1", "F5", "F6", "F8", "F9", "W1", "W2", "W3", "W4", "W6", "W7", "P1", "P2", "X1", "X2", "X3", "X4"]),
    ("Are all approvals genuinely human-authorized and digest-bound?", ["D4", "H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8", "H9", "W5"]),
    ("Can no legacy path bypass the kernel?", ["P3", "C9"]),
    ("Is the production transport registered, permitted, and operational?", ["D1", "C1", "C2", "C9", "M1"]),
    ("Does inbound handling reliably stop unwanted follow-up?", ["D2", "C5", "C6", "C7", "C8"]),
    ("Are ambiguous external actions handled without blind retries?", ["C3", "C4"]),
    ("Are status labels accurate?", ["C3", "X2"]),
    ("Are tenant isolation, identity, and least privilege independently verified?", ["F7", "S2", "S3", "S4", "S11", "S12"]),
    ("Are credential rotation and data deletion exercised?", ["S6", "S10", "S13", "F4"]),
    ("Are restore and rollback safe from accidental re-sending?", ["O9", "O10"]),
    ("Are SLO, load, fault, and communications targets met?", ["O2", "O3", "O4", "O5", "C10"]),
    ("Are monitoring, support, and incident responsibilities staffed?", ["O6", "O7", "M3"]),
    ("Have AI safety and factuality evaluations passed?", ["A1", "A2", "A3", "A4", "A5", "A6"]),
    ("Has the interface passed usability and accessibility acceptance?", ["X5"]),
    ("Are legal, privacy, provider, and branding permissions documented?", ["D7", "S13", "M1", "M2"]),
    ("Are economics viable at the approved price?", ["M4"]),
    ("Are all product claims supported?", ["K1", "K2"]),
    ("Is every acceptance result linked to retained, commit-specific evidence?", ["*"]),
]


def level_of_cell(cell: str) -> str:
    c = cell.lower()
    if "not demonstrated" in c:
        return "not_demonstrated"
    if "production-proven" in c or "production proven" in c:
        return "production_proven"
    if "independently verified" in c and "implemented" not in c:
        return "independently_verified"
    if "implemented" in c or "independently verified" in c:
        return "implemented"
    if "see f7" in c:
        return "independently_verified"  # S11 delegates to F7's verification
    if c.startswith("n/a until"):
        return "not_demonstrated"
    return "unknown"


def required_level(gate: str, rid: str) -> str:
    g = gate.lower()
    if "proven" in g:
        return "production_proven"
    return "independently_verified"


def parse_matrix(text: str) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for line in text.splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        rid = m.group(1)
        cells = [c.strip() for c in m.group(2).split(" | ")]
        status = cells[-1]
        gate = cells[-2] if len(cells) >= 4 and cells[-2] in ("Release", "Release (proven)", "Commercial", "Record") else ""
        rows[rid] = {
            "id": rid,
            "gate": gate or "Release",
            "status_cell": status,
            "matrix_level": level_of_cell(status),
            "required": required_level(gate, rid),
        }
    return rows


def load_records(release_dir: pathlib.Path) -> dict[str, dict]:
    """Validated records only; anything check.py rejects is treated as absent."""
    if not release_dir.exists() or release_dir.name.startswith("_"):
        return {}  # templates/examples are never evidence
    sys.path.insert(0, str(ROOT / "tools/evidence"))
    import check  # noqa: PLC0415 — sibling module

    import yaml  # noqa: PLC0415

    out: dict[str, dict] = {}
    for p in sorted(release_dir.glob("*.yaml")):
        problems = check.check_record(p)
        rec = yaml.safe_load(p.read_text(encoding="utf-8"))
        rid = rec.get("requirement_id", p.stem)
        out[rid] = {"status": rec.get("status", "not_demonstrated") if not problems else "invalid", "problems": problems, "path": str(p.relative_to(ROOT))}
    return out


def evaluate(rows: dict[str, dict], records: dict[str, dict]) -> dict:
    failing, unbacked, closed = [], [], []
    for rid, row in sorted(rows.items(), key=lambda kv: (kv[0][0], int(re.sub(r"\D", "", kv[0]) or 0))):
        rec = records.get(rid)
        rec_level = rec["status"] if rec and rec["status"] in LEVELS else None
        effective = rec_level or "not_demonstrated"  # only records close rows
        row["record"] = rec
        row["effective_level"] = effective
        meets = LEVELS.index(effective) >= LEVELS.index(row["required"])
        if row["matrix_level"] == "unknown":
            failing.append({"id": rid, "why": "status cell does not use the vocabulary", "required": row["required"], "matrix": row["status_cell"]})
            continue
        if meets:
            closed.append(rid)
        else:
            failing.append({
                "id": rid,
                "required": row["required"],
                "matrix_claim": row["matrix_level"],
                "record": rec_level or ("invalid record" if rec else "no record"),
                "needed": "evidence record at %s by a verifier independent of the author" % row["required"],
            })
        if LEVELS.index(row["matrix_level"]) > LEVELS.index(effective) and row["matrix_level"] != "not_demonstrated":
            unbacked.append({"id": rid, "matrix_claim": row["matrix_level"], "record": rec_level or "none"})
    ready = not failing
    checklist = []
    for q, ids in CHECKLIST:
        if ids == ["*"]:
            ok = ready
            blocking = [f["id"] for f in failing]
        else:
            blocking = [i for i in ids if i in rows and i not in closed]
            ok = not blocking
        checklist.append({"question": q, "answer": "yes" if ok else "no", "blocking": blocking})
    return {
        "verdict": "READY FOR GENERAL RELEASE WITHIN THE DEFINED SCOPE" if ready else "NOT READY",
        "rows_total": len(rows),
        "rows_closed": len(closed),
        "failing": failing,
        "matrix_claims_without_record": unbacked,
        "checklist": checklist,
        "note": "Only validated evidence records close rows. Matrix cells describe progress; they are not evidence.",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default=None, help="release id under evidence/releases/")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rows = parse_matrix(MATRIX.read_text(encoding="utf-8"))
    records = load_records(ROOT / "evidence/releases" / a.release) if a.release else {}
    result = evaluate(rows, records)
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        print(result["verdict"])
        print(f"rows: {result['rows_total']}, closed by evidence: {result['rows_closed']}, failing: {len(result['failing'])}")
        by_claim: dict[str, list[str]] = {}
        for f in result["failing"]:
            by_claim.setdefault(f.get("matrix_claim", "unknown"), []).append(f["id"])
        for k in LEVELS + ["unknown"]:
            if k in by_claim:
                print(f"  matrix says {k:<24} but no closing record: {', '.join(by_claim[k])}")
        print("final checklist:")
        for c in result["checklist"]:
            print(f"  [{c['answer']:>3}] {c['question']}" + (f"  -> {', '.join(c['blocking'][:12])}{'...' if len(c['blocking']) > 12 else ''}" if c["blocking"] else ""))
    return 0 if result["verdict"].startswith("READY") else 1


if __name__ == "__main__":
    sys.exit(main())
