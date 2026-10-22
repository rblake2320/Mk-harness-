"""Strict live-inspection readback. This cannot authorize a restored database."""
import json
import sys
from pathlib import Path

REQUIRED = frozenset({"global_dispatch_disabled", "privacy_restore_ledger", "keyring_loads",
    "audit_chain_verified", "suppression_ledger_loaded", "credentials_unseal",
    "in_flight_marked_unknown", "pre_restore_approvals_invalidated", "reconciliation_backlog"})


def validate(text):
    rows = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    checks = {}
    summaries = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid record")
        if "check" in row:
            name = row["check"]
            if name not in REQUIRED or name in checks or type(row.get("ok")) is not bool:
                raise ValueError("unknown, duplicate or invalid check")
            checks[name] = row
        elif "gate" in row:
            summaries.append(row)
        else:
            raise ValueError("unknown structured record")
    if set(checks) != REQUIRED or len(summaries) != 1 or rows[-1] is not summaries[0]:
        raise ValueError("incomplete inspection")
    if any(not row["ok"] for name,row in checks.items() if name != "global_dispatch_disabled"):
        raise ValueError("failed recovery check")
    privacy = checks["privacy_restore_ledger"].get("detail", {})
    if privacy.get("inspection_only") is not True or privacy.get("restore_authorized") is not False:
        raise ValueError("not a live inspection")
    switch = checks["global_dispatch_disabled"]
    if switch.get("detail", {}).get("dispatch_enabled") is not (not switch["ok"]):
        raise ValueError("contradictory dispatch state")
    expected = "INSPECTION_ONLY" if switch["ok"] else "FAIL"
    if summaries[0].get("gate") != expected or summaries[0].get("apply") is not False:
        raise ValueError("contradictory inspection summary")
    return len(checks)


if __name__ == "__main__":
    try:
        count = validate(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (ValueError, OSError, IndexError, TypeError):
        raise SystemExit("invalid or failed live recovery inspection") from None
    print(f"{count} checks; live inspection only, not restore authorization")
