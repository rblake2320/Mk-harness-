#!/usr/bin/env python3
"""K1 competitive-study analysis (docs/qualification/competitive-study-protocol.md).

    python -I tools/qualification/k1_analysis.py randomize --participants 12 --arms mk,official,alt1,alt2 --seed 20261101
    python -I tools/qualification/k1_analysis.py analyze sessions.csv preferences.csv

Exit 0 from `analyze` only when all four acceptance conditions hold. The tool
never emits a comparative sentence unless they do, and the sentence it emits
names only the tested workflow and the tested alternatives.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys

REQUIRED_SCENARIOS = {
    "promise_capture", "daily_prioritization", "follow_up_preparation", "approval", "reply_deferral",
    "opt_out", "product_concern", "uncertain_delivery", "outcome_recording", "find_reason",
}


def latin_square(arms: list[str], participants: int, seed: int) -> list[list[str]]:
    rng = random.Random(seed)
    n = len(arms)
    base = [[arms[(i + j) % n] for j in range(n)] for i in range(n)]
    order = []
    while len(order) < participants:
        rows = base[:]
        rng.shuffle(rows)
        order.extend(rows)
    return order[:participants]


def analyze(sessions: list[dict], prefs: list[dict], mk_arm: str = "mk") -> dict:
    by_arm: dict[str, list[float]] = {}
    correct: dict[str, list[int]] = {}
    violations: dict[str, int] = {}
    scenarios = set()
    participants = set()
    for s in sessions:
        arm = s["arm"]
        participants.add(s["participant"])
        scenarios.add(s["scenario"])
        by_arm.setdefault(arm, []).append(float(s["handling_time_s"]))
        correct.setdefault(arm, []).append(int(s["correct"]))
        violations[arm] = violations.get(arm, 0) + int(s.get("violations") or 0)
    if mk_arm not in by_arm:
        return {"pass": False, "error": f"no sessions for arm {mk_arm}"}
    medians = {a: statistics.median(v) for a, v in by_arm.items()}
    others = {a: m for a, m in medians.items() if a != mk_arm}
    best_alt = min(others, key=others.get) if others else None
    reduction = (1 - medians[mk_arm] / others[best_alt]) * 100 if best_alt else 0.0
    completion = {a: 100.0 * sum(v) / len(v) for a, v in correct.items()}
    pref_counts: dict[str, int] = {}
    for p in prefs:
        pref_counts[p["preferred_arm"]] = pref_counts.get(p["preferred_arm"], 0) + 1
    n_pref = len(prefs)
    checks = {
        "participants_12": len(participants) == 12,
        "all_required_scenarios_present": REQUIRED_SCENARIOS <= scenarios,
        "median_time_reduction_ge_30pct_vs_best_alternative": best_alt is not None and reduction >= 30.0,
        "completion_ge_95pct": completion.get(mk_arm, 0.0) >= 95.0,
        "no_degradation_in_optout_approval_privacy": violations.get(mk_arm, 0) <= min((v for a, v in violations.items() if a != mk_arm), default=0),
        "preference_ge_10_of_12": n_pref == 12 and pref_counts.get(mk_arm, 0) >= 10,
    }
    ok = all(checks.values())
    return {
        "arms": sorted(by_arm),
        "median_handling_time_s": medians,
        "best_alternative": best_alt,
        "median_reduction_pct_vs_best_alternative": round(reduction, 1),
        "completion_pct": completion,
        "violations": violations,
        "preferences": pref_counts,
        "checks": checks,
        "pass": ok,
        "supported_claim": (
            f"In a 12-consultant randomized crossover study on the predefined follow-through task set, "
            f"MK's median active handling time was {round(reduction)}% lower than the best tested alternative ({best_alt}), "
            f"with {round(completion[mk_arm])}% correct completion and {pref_counts.get(mk_arm, 0)}/12 participants preferring it for that workflow. "
            f"This supports only the tested claim."
        ) if ok else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("randomize")
    r.add_argument("--participants", type=int, default=12)
    r.add_argument("--arms", default="mk,official,alt1,alt2")
    r.add_argument("--seed", type=int, required=True)
    an = sub.add_parser("analyze")
    an.add_argument("sessions")
    an.add_argument("preferences")
    a = ap.parse_args()
    if a.cmd == "randomize":
        for i, order in enumerate(latin_square(a.arms.split(","), a.participants, a.seed), 1):
            print(f"P{i:02d}: {' → '.join(order)}")
        return 0
    with open(a.sessions, newline="", encoding="utf-8") as f:
        sessions = list(csv.DictReader(f))
    with open(a.preferences, newline="", encoding="utf-8") as f:
        prefs = list(csv.DictReader(f))
    result = analyze(sessions, prefs)
    print(json.dumps(result, indent=2))
    return 0 if result.get("pass") else 1


if __name__ == "__main__":
    sys.exit(main())
