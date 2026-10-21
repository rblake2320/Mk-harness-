# Final release record — template (contract §Final sign-off checklist, WP12)

Generated verdict: run `python -I tools/evidence/readiness.py --release <id>`.
The tool computes the answer to every checklist question from validated
evidence records; a human cannot answer "yes" where the tool answers "no".

## Current verdict (committed snapshot, author-run 2026-10-21)

```
NOT READY
rows: 87, closed by evidence: 0
```

Every row is open because **no evidence record exists yet** — not because the
work is absent. The matrix describes 49 rows as Implemented and 15 as having an
independently verified kernel part, but a matrix cell is prose; only a record
with an artifact checksum and a named verifier closes a row.

## When the verdict is READY, this record states

* Release commit (40-hex), deployed image digests (`mk-action-kernel`, `mk-app`)
* Qualification window (C10 30 days; O4 envelope run dates)
* Evidence index: `evidence/releases/<id>/` listing, each record's `status` and `verifier`
* Named sign-offs: release owner; legal/privacy reviewer (M1); external security reviewer (S15); business owner (M3 pricing); support owner (M4)
* The exact permitted claims from `claims-register.md`

## Owners (blocking — unassigned)

| Role | Name | Rows |
|---|---|---|
| Release owner | — | all; final checklist |
| Independent verifier (engineering) | — | every Implemented row → Independently verified |
| External security reviewer | — | S15 |
| Legal/privacy reviewer | — | S1, S2, M1, M2 |
| Qualification owner | — | C10, O2–O4, K1 |
| Business owner | — | M3 (pricing), D6, D7 |
| Support owner | — | M4, O7 on-call |
