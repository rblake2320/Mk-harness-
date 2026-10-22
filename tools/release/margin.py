#!/usr/bin/env python3
"""Gross-margin gate (contract M4): ≥ 70 % at the proposed price on MEASURED costs.

    python -I tools/release/margin.py costs.yaml

costs.yaml:
    price_per_tenant_month: 49.00          # proposed price (pre-approval)
    tenants_measured: 25                   # tenants in the measurement window
    window: "2026-12"                      # YYYY-MM
    lines:
      - name: provider        ; amount: 310.00 ; measured: true  ; source: "Twilio invoice INV-…"
      - name: hosting         ; amount: 412.55 ; measured: true  ; source: "AWS Cost Explorer export …"
      - name: model           ; amount:  88.10 ; measured: true  ; source: "provider usage export …"
      - name: observability   ; amount:  61.00 ; measured: true  ; source: "…"
      - name: storage         ; amount:  12.40 ; measured: true  ; source: "…"
      - name: support_labour  ; amount: 240.00 ; measured: true  ; source: "12 h × $20 loaded"
    excluded_product_development: 18000.00  # disclosed separately, never netted

Any line with measured: false (an estimate) makes the gate fail — the contract
requires measured recurring costs.
"""
from __future__ import annotations

import json
import sys

import yaml

REQUIRED_LINES = {"provider", "hosting", "model", "observability", "storage", "support_labour"}


def evaluate(doc: dict) -> dict:
    lines = doc.get("lines", [])
    names = {l["name"] for l in lines}
    missing = sorted(REQUIRED_LINES - names)
    unmeasured = sorted(l["name"] for l in lines if not l.get("measured"))
    tenants = int(doc.get("tenants_measured", 0))
    price = float(doc.get("price_per_tenant_month", 0))
    total_cost = sum(float(l["amount"]) for l in lines)
    revenue = price * tenants
    cost_per_tenant = total_cost / tenants if tenants else float("inf")
    margin = (revenue - total_cost) / revenue * 100 if revenue > 0 else float("-inf")
    checks = {
        "all_required_cost_lines_present": not missing,
        "every_line_measured_not_estimated": not unmeasured,
        "tenants_measured_gt_0": tenants > 0,
        "price_proposed": price > 0,
        "gross_margin_ge_70pct": margin >= 70.0,
    }
    return {
        "window": doc.get("window"),
        "tenants_measured": tenants,
        "price_per_tenant_month": price,
        "recurring_cost_per_tenant_month": round(cost_per_tenant, 2) if tenants else None,
        "gross_margin_pct": round(margin, 1) if revenue > 0 else None,
        "excluded_product_development": doc.get("excluded_product_development"),
        "missing_lines": missing,
        "unmeasured_lines": unmeasured,
        "checks": checks,
        "pass": all(checks.values()),
        "note": "pricing still requires the business owner's written approval (M4 record); a passing margin is not that approval",
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    r = evaluate(doc)
    print(json.dumps(r, indent=2))
    return 0 if r["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
