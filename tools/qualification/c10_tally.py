#!/usr/bin/env python3
"""C10 communications-qualification tally (docs/qualification/communications-qualification-plan.md).

    python -I tools/qualification/c10_tally.py messages.csv --window 2026-11-01..2026-11-30

Computes every acceptance condition of the contract from one CSV of per-message
records and prints a JSON verdict. Exit 0 only when all conditions pass. A failed
action is never counted as a success; an expected failure that failed visibly
within 60 s counts toward the provider-acceptance-or-visible-failure rate but
never toward device corroboration.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone

TERMINAL_VISIBLE = {"delivered", "sent", "provider_accepted", "failed", "undelivered", "suppressed", "cancelled", "expired"}
AMBIGUOUS = {"submission_unknown", "delivery_unknown", "reconciliation_required"}


def ts(s: str) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def tally(rows: list[dict], window: tuple[datetime, datetime] | None) -> dict:
    if window:
        rows = [r for r in rows if r.get("approved_at") and window[0] <= ts(r["approved_at"]) <= window[1]]
    total = len(rows)
    days = {ts(r["approved_at"]).date() for r in rows if r.get("approved_at")}
    numbers = {r["device_number"] for r in rows if r.get("device_number")}
    unapproved = [r["action_id"] for r in rows if not r.get("approval_credential_id")]
    duplicates = [r["action_id"] for r in rows if r.get("duplicate_of")]
    eligible = [r for r in rows if r.get("expected") == "delivered"]
    corroborated = []
    for r in eligible:
        a, d = ts(r.get("approved_at", "")), ts(r.get("device_seen_at", ""))
        if a and d and d - a <= timedelta(minutes=5):
            corroborated.append(r["action_id"])
    visible_60 = []
    for r in rows:
        a, p = ts(r.get("approved_at", "")), ts(r.get("provider_state_at", ""))
        if a and p and p - a <= timedelta(seconds=60) and r.get("provider_state") in TERMINAL_VISIBLE:
            visible_60.append(r["action_id"])
    ambiguous = [r for r in rows if r.get("provider_state") in AMBIGUOUS]
    unresolved_ambiguous = [r["action_id"] for r in ambiguous if r.get("ambiguous_resolution") not in ("reconciled_sent", "reconciled_not_sent", "left_unknown")]
    scenarios = {r.get("scenario") for r in rows}
    incidents = sorted({r["incident_id"] for r in rows if r.get("incident_id")})
    # Expected failures that silently "succeeded" or vice versa are mismatches, never successes.
    mismatches = [r["action_id"] for r in rows if r.get("expected") == "failed" and r.get("provider_state") == "delivered"]

    def pct(n: int, d: int) -> float:
        return 100.0 if d == 0 else round(100.0 * n / d, 3)

    checks = {
        "messages_at_least_1000": total >= 1000,
        "days_at_least_30_consecutive": len(days) >= 30 and (max(days) - min(days)).days + 1 == len(days) if days else False,
        "receiving_numbers_at_least_6": len(numbers) >= 6,
        "zero_unapproved": not unapproved,
        "zero_duplicates": not duplicates,
        "device_corroboration_ge_99pct_within_5min": pct(len(corroborated), len(eligible)) >= 99.0 and bool(eligible),
        "provider_accept_or_visible_failure_ge_99_5pct_within_60s": pct(len(visible_60), total) >= 99.5 and total > 0,
        "every_ambiguous_resolved_or_explicitly_unknown": not unresolved_ambiguous,
        "scenarios_covered": {"opt_out", "wrong_number", "failure", "recovery"} <= scenarios,
        "no_sev1_sev2_incidents": not incidents,
        "no_expected_failure_counted_as_success": not mismatches,
    }
    return {
        "window": [window[0].isoformat(), window[1].isoformat()] if window else None,
        "totals": {"messages": total, "days": len(days), "receiving_numbers": len(numbers), "eligible_for_corroboration": len(eligible),
                   "corroborated_within_5min": len(corroborated), "visible_within_60s": len(visible_60), "ambiguous": len(ambiguous)},
        "rates": {"device_corroboration_pct": pct(len(corroborated), len(eligible)), "visible_within_60s_pct": pct(len(visible_60), total)},
        "failures": {"unapproved": unapproved, "duplicates": duplicates, "unresolved_ambiguous": unresolved_ambiguous, "incidents": incidents,
                     "expected_failure_marked_delivered": mismatches},
        "checks": checks,
        "pass": all(checks.values()),
        "note": "provider receipts and device corroboration must be retained as distinct artifacts; this tally does not replace them",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--window", help="YYYY-MM-DD..YYYY-MM-DD (inclusive, UTC)")
    a = ap.parse_args()
    window = None
    if a.window:
        s, e = a.window.split("..")
        window = (datetime.fromisoformat(s).replace(tzinfo=timezone.utc), datetime.fromisoformat(e).replace(tzinfo=timezone.utc) + timedelta(days=1) - timedelta(microseconds=1))
    with open(a.csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    result = tally(rows, window)
    print(json.dumps(result, indent=2))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
