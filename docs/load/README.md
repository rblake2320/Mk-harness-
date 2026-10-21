# Load and SLO measurement (contract O2–O4)

**Status: Implemented (tooling) — Not demonstrated (qualification).**

`mk-loadgen` (`rust/crates/mk-testkit/src/bin/mk-loadgen.rs`) and
`scripts/kernel-load.sh` drive the governed path end to end against a real
kernel stack with the Twilio simulator as transport, and emit a JSON report
with a verdict per SLO row of `docs/slo.md`. The report states `envelope_run`
explicitly and sets it only for an 8 h run at ≥20 proposal/s and ≥100 read/s.

## What is measured, how

| Row | Measurement | Method |
|---|---|---|
| O3 API p95/p99 | propose, approve (challenge + passkey assertion + approve), pending-approvals read | client-side wall time per request |
| O3 approved → dispatch start | time from approve 200 to the first `message_state` past `queued` | 100 ms polling of `GET /internal/v1/actions/{id}` |
| O3 approved → delivered | to `delivered` via the simulator's signed status callbacks | same; **simulator latency, not provider latency** |
| O3 inbound persistence | signed inbound webhook → 200 (recorded, deduped, sealed) | client-side wall time |
| O3 opt-out → blocked | STOP webhook, then an immediate proposal to the same destination must be `403 suppressed` | every 10 s, one probe |
| O4 no duplicate execution | provider message ids unique across the whole run; `mk_dead_letters`, `mk_actions_reconciliation_required`, `mk_audit_head_mismatches` read from the worker's `/metrics` at the end | |
| O4 error rate | transport errors + 5xx over all API calls | |
| O4 envelope | duration and rates vs. the contract envelope | reported; never inferred |

Kernel decisions that are *correct* under load are classified, not counted
as errors: `approvals_refused_4xx` (e.g. a STOP landed between proposal and
approval), `consent_cancelled_before_dispatch` (STOP landed after approval,
the queued send was cancelled), `proposals_rejected` (policy refusal).

## Author runs (not qualification evidence)

Same machine as the Postgres/Redis (one container, shared CPU), 4 workers,
10 tenants, 2 minutes at the contract's *rates*:

| Metric | Result |
|---|---|
| proposals / approvals / delivered | 2400 / 2398 / 2398 (2 approvals correctly refused after an opt-out race) |
| reads | 12 000, 0 errors |
| inbound webhooks | 1 200, 0 errors |
| propose p95 / p99 | 41 ms / 64 ms |
| approve p95 / p99 | 43 ms / 62 ms |
| pending-approvals read p95 / p99 | 13 ms / 21 ms |
| approved → dispatch start p95 / p99 | 0.52 s / 0.54 s |
| approved → delivered (simulator) p95 / p99 | 0.83 s / 0.85 s |
| inbound persistence p99 | 52 ms |
| opt-out probes blocked | 12 / 12 |
| duplicate provider message ids | 0 |
| dead letters / reconciliation required / audit head mismatches at end | 0 / 0 / 0 |

Report: `2026-10-21-author-run-120s-envelope-rates.json`.

What this does **not** show: 8 h at envelope, 30 min at 2×, 24 h at ½ for
leaks, 1 000 000 customer records, real provider latency and rate limits,
behaviour on the production topology, graceful rejection above capacity
(per-tenant limits are not implemented — see O2), recovery ≤ 10 min after
overload. Rows O2–O4 therefore remain **Not demonstrated**; the tooling to
produce that evidence exists and is exercised.

## Running

```sh
scripts/kernel-load.sh --duration-secs 120 --proposals-per-sec 20 --reads-per-sec 100 \
                       --inbound-per-sec 10 --tenants 10 --workers 4
# envelope (someone other than the author, on the staging topology):
scripts/kernel-load.sh --duration-secs 28800 --proposals-per-sec 20 --reads-per-sec 100 --inbound-per-sec 10 --tenants 50 --workers 4
```
