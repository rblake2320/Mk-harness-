# WP01 — Baseline record

**Baseline commit (main):** `3cf1dee215645d7f2bcfc5edf4b7ec0a92845d72` (merge of PR #31 on top of PR #30).
Recorded 2026-10-20. Everything below is classified **Implemented** at most: the
numbers are author-run results, not independent verification, and no inherited
"passed" claim is carried forward as verified evidence.

## Source of record

| Component | Location | Contract / pinned value |
|---|---|---|
| Action envelope | `contracts/action/v1/` | `mk.action.v1`; fixture digest `32137d2014708b28f72eab14fc52c58ef4d4b93ea83048c952aa5b3521ae5dc3` |
| Approval | `contracts/action/v1/approval.schema.json` | `mk.approval.v1` |
| Mobile work order / callbacks (test equipment) | `contracts/mobile/v1/` | HMAC vectors; tolerance 120 s |
| MCP tool manifest | `rust/crates/mk-mcp` | digest `bf3dcc19d369cd08cfd53b4ef13b52ed108fea88e4014b69a042c4e28721525f` |
| Policy version | `rust/crates/mk-policy` | `mk-policy/2026.10.1` |
| Kernel schema | `migrations/kernel/0001`, `0002` | 18 tables; RLS on tenant tables; per-process roles |
| Kernel role vocabulary | `backend/app/kernel/assertions.py` | consultant, tenant_admin, agent, platform_operator |

Contracts that the completion contract requires and that **do not exist yet**:
`contracts/inbound/v1`, `contracts/commitments/v1`, `contracts/outcomes/v1`
(directories created empty in this PR; schemas authored in WP04/WP07).

## Author-run test results at baseline (Implemented evidence only)

| Suite | Count | Command |
|---|---|---|
| Rust workspace (nextest, real Postgres 16 + Redis 7, shared-infra group serialized) | 141 passed | `cargo nextest run --workspace` |
| Backend pytest (in-memory SQLite, respx-mocked kernel) | 165 passed | `python -m pytest` |
| Device test-equipment agent (stdlib) | 36 passed | `python -m unittest` in `tools/mobile-agent-adb` |
| Cross-language contract tests | 4 passed | `python -I contracts/tests/test_contracts.py` |
| Live smoke (8 gates + pre-flight 27/27) | pass | `scripts/kernel-live-smoke.sh` (in CI from PR #32) |
| fmt / clippy -D warnings / cargo deny / cargo audit | clean | — |

## Known divergences carried into the work packages

- Kernel action state machine lacks `submission_started`, `provider_accepted`,
  `submission_unknown`, `delivery_unknown` (C3) — WP07.
- FastAPI mints both proposal and approval assertions (H6 trust gap) — WP06.
- Single application master key, no KMS/envelope (S6) — WP09.
- Verifier previously demanded Redis + master key (fixed in PR #32).
- Housekeeping cadence is tick-based in the worker; not time-based — WP09.
- Approver roles include `manager`, which the application does not yet issue — WP06.

## What this baseline does not claim

No production transport, no inbound path, no consultant-facing workflow, no
threat model, no external security review, no SLO measurement, no legal or
provider authorization. See `docs/production-acceptance.md` §11.
