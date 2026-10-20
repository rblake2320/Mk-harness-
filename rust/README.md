# MK Rust Action Kernel

The Rust action kernel is the **sole executable authority for governed
external actions** in MK. FastAPI stays the application and AI layer; nothing
in Python can send a message, create an appointment, or talk to a device agent
without passing through this kernel.

Every consequential action follows one inspectable path:

```
proposal → schema validation → identity verification → deterministic policy
→ current permission and suppression → exact human approval → durable enqueue
→ dispatch-time recheck → idempotent adapter execution → authenticated result
→ tamper-evident audit
```

Four rules, enforced by construction:

1. **Models propose; deterministic code authorizes.** `mk-policy` is pure and
   never parses free text for intent. Prompt injection in `rendered_text` is
   data (tested).
2. **Approval is bound to the exact action.** An approval commits to the
   RFC 8785 canonical digest of the stored envelope and is consumed exactly
   once by an atomic `UPDATE … WHERE consumed_at IS NULL` (8-way race tested).
3. **Least privilege.** Tool allowlist is a reviewed Rust constant with no
   generic HTTP/SQL/shell tool; the adapter trait is sealed; egress is an
   explicit allowlist with SSRF checks; every tenant table has RLS.
4. **Fail closed.** No DB → no dispatch. No approval → no dispatch. No
   permission, suppressed, expired, kill switch → no dispatch. Unknown schema
   version, tool, state string, or enum value → rejected.

## Workspace

| Crate | Role | Tests |
|---|---|---|
| `mk-domain` | IDs, closed vocabularies, the action state machine | 16 (incl. 2 property tests: terminal states absorb, completion implies approval path) |
| `mk-crypto` | RFC 8785 JCS, SHA-256, HMAC `hmac-sha256-v1`, nonce window, Ed25519 actor assertions, AES-256-GCM sealing | 31 (incl. JCS round-trip/insertion-order property tests, alg:none/forged/expired assertions) |
| `mk-contracts` | Serde DTOs, embedded JSON Schemas, canonical action digest, mobile contracts | 20 + 3 (all 6 published HMAC vectors sign/verify identically; every mutation rejected) |
| `mk-policy` | `evaluate` / `recheck_at_dispatch` / `check_approver`, consent rules, tool allowlist | 22 (full deny matrix, suppression > permission, retry reuses only its own consumed approval) |
| `mk-audit` | Per-tenant hash chain, verifier, forbidden-key scan | 6 (every tamper class detected incl. consistent tail rewrite; random single-field mutation property test) |
| `mk-store` | PostgreSQL repos, tenant-scoped tx + RLS, atomic approval consume, outbox, leases, nonces, idempotency, adapter credentials | 1 + 10 against real Postgres (concurrent consume, RLS probe with raw SQL, audit immutability trigger, rotation overlap/revoke) |
| `mk-queue` | Backoff/retry classes, Redis Streams (sharded, consumer group, XAUTOCLAIM), outbox relay | 3 + 2 against real Redis+Postgres (relay crash after XADD → duplicate, never loss) |
| `mk-adapters` | Sealed `ActionAdapter`, `mobile-adapter-v1`, egress allowlist, contract simulator | 2 + 4 (signed delivery, retry class by status, forged secret rejected, SSRF cases) |
| `mk-worker` | Dispatch: lock → lease → recheck → consume → `StartDispatch` → commit → adapter → persist; housekeeping | 5 end-to-end (duplicate delivery absorbed, late revocation → suppressed, kill switch, transient retry, dead-letter + linked replay) |
| `mk-api` | Axum internal API, actor-assertion auth + jti single-use, RFC 9457 problems, authenticated callbacks, kill switches, metrics | 2 HTTP e2e (forged/replayed assertions, agent cannot approve, digest-bound approval, worker + callbacks, replay/stale/forged/duplicate callbacks, rotation cutoff, revoke, chain verify, no PII in metrics) |
| `mk-mcp` | Five-tool MCP server on the official `rmcp` SDK; pinned manifest digest | 1 + 1 protocol round-trip (unknown tool, invalid args, redaction, kernel rejection, oversized args) |
| `mk-testkit` | Fake clock, fixtures, `mk-devkeys` | — |

**Total: 129 tests, all passing**, plus `contracts/tests/test_contracts.py`
(Python reproduces the Rust action digest and every HMAC vector).

Quality gate (CI runs the same): `cargo fmt --check`, `cargo clippy
--workspace --all-targets --all-features -D warnings` with pedantic lints and
`unwrap_used`/`expect_used`/`panic` denied in library code, `cargo nextest`,
`cargo deny`, `cargo audit`, container build + Trivy scan, CycloneDX SBOM.

## Binaries

| Binary | Purpose |
|---|---|
| `mk-action-api` | Internal HTTP API (`/internal/v1`, `/adapter/v1`, health, metrics) |
| `mk-outbox-relay` | PostgreSQL outbox → Redis Streams |
| `mk-action-worker` | Consumer; the only process that calls an adapter |
| `mk-audit-verifier` | Daily chain verification; non-zero exit on any break |
| `mk-mcp-server` | stdio MCP server over the API |
| `mk-simulator` | Mobile adapter contract simulator (dev/CI only) |
| `mk-devkeys` | Dev keypair/assertion minting (dev only) |

## Running locally

```bash
# Postgres 16 and Redis 7 reachable; then:
cd rust
cargo build --release --bins
eval $(./target/release/mk-devkeys gen | sed 's/^/export /')      # prints MK_ASSERTION_KEYS, DEV_PRIVATE_KEY, MK_MASTER_KEY
export MK_DATABASE_URL=postgres://postgres@127.0.0.1:5432/mk MK_REDIS_URL=redis://127.0.0.1:6379
export RUST_ACTION_KERNEL_ENABLED=1 MK_RUN_MIGRATIONS=1
./target/release/mk-action-api &                                  # 127.0.0.1:8090
./target/release/mk-outbox-relay &
MK_MOBILE_INTAKE_URL=http://127.0.0.1:8787/sim/v1/work-orders MK_EGRESS_AUTHORITIES=127.0.0.1:8787 \
  MK_ALLOW_LOOPBACK_HTTP=1 ./target/release/mk-action-worker &
# register an adapter via the API (tenant_admin assertion), then:
MK_SIM_SECRET=<enrollment_secret> MK_SIM_TENANT=<tenant> MK_SIM_CALLBACK_BASE=http://127.0.0.1:8090 ./target/release/mk-simulator
```

Mint assertions with `mk-devkeys assert $DEV_PRIVATE_KEY <tenant> <user> agent`
(or `manager`, `tenant_admin`). Tests: `MK_TEST_DATABASE_URL=… MK_TEST_REDIS_URL=… cargo test --workspace`;
without those variables the integration suites skip and the pure suites run.

## Trust boundaries (what is trusted, what is data)

* **FastAPI → kernel:** a per-request Ed25519 actor assertion (`iss`
  `mk-fastapi`, `aud` `mk-action-kernel`, ≤ 60 s, single-use `jti` for writes,
  key rotation by `kid`). The body's `tenant_id`/`requested_by` are overwritten
  from the assertion. Only the public key is mounted into the kernel.
* **Kernel → device agent:** `hmac-sha256-v1` over the exact wire bytes, with
  the enrollment secret issued once at registration and stored only
  AES-256-GCM sealed under `tenant:adapter:credential` AAD.
* **Device agent → kernel:** same HMAC, ±120 s window, durable nonce
  (`kernel.adapter_nonces`, unique per tenant+adapter), monotonic and idempotent
  state application. Revoke kills dispatch and callbacks immediately.
* **MCP → kernel:** five tools, none side-effecting; `approve_action` does not
  exist; outputs redacted; manifest digest pinned.
* **RAG / Laya / Jev:** evidence digests only. They never appear in `mk-policy`.

## Spec conformance and known gaps

Delivered per the build specification: PRs 1–9 of the pull-request sequence,
Phases 0–5 of the migration plan, and the shadow/cutover controls of Phase 6
(`RUST_ACTION_KERNEL_ENABLED`, global and per-tenant kill switches).

Deviations and gaps — read these before claiming anything is "done":

| Item | Status |
|---|---|
| Python contract compatibility | `contracts/tests/test_contracts.py` reproduces digests and vectors. FastAPI side delivered: `backend/app/kernel/` (Ed25519 assertion minting, kernel client) and `backend/app/routes/agent_ops.py` (`/api/agent-ops/*` proxy). **No Python fallback**: kernel unreachable or unconfigured → 503. The proxied body is validated against `contracts/action/v1` in `backend/tests/test_agent_ops.py`. |
| TypeScript contract compatibility | **Not written**; schemas are checked in for the SDK to consume |
| `sqlx prepare --check` | Deliberately not used. Queries are runtime-checked `sqlx::query` and every statement is exercised against real Postgres in CI; this keeps `sqlx-macros` (and the MySQL driver + `rsa` it drags in) out of the compiled graph. `RUSTSEC-2023-0071` is ignored for that reason with `cargo tree -i rsa` empty. |
| HMAC timestamp tolerance | Kernel default 120 s per spec; the legacy Python path used 300 s. Configurable via `MK_CALLBACK_TOLERANCE_SECS`; vectors are tolerance-independent. **Doc/code divergence flagged**: `contracts/mobile/v1/README.md` still says 300 s. |
| OpenTelemetry/OTLP | Structured JSON `tracing` + Prometheus metrics are in; OTLP export and W3C trace propagation to adapters are **not wired** |
| Temporal | Not adopted (per spec) |
| External anchoring of audit roots | `ChainHead::root_commitment()` is the value to anchor; the anchoring job is **not written** |
| Mobile adapter reconcile | v1 agents have no status query; `reconcile` returns `Unknown` and actions wait in `reconciliation_required` for an operator |
| `jti` single-use | Durable and shared: `kernel.assertion_jtis` (migration 0002), `INSERT … ON CONFLICT DO NOTHING` before the handler transaction, fail-closed on store error; proven across two API instances in `http_e2e.rs` and across pools in `postgres.rs`. Worker housekeeping purges expired rows. |
| `verified_on_device` | Always `false` (schema const; code never sets it). `tools/mobile-agent-adb/` is a real-device agent (Android over ADB) with an evidence bundle + hash chain; `docs/real-device-acceptance.md` is the human procedure. **No real-device run has been performed yet**; `scripts/kernel-live-smoke.sh` proves the round trip with the agent in dry-run. |
| Per-process DB identities | `deploy/kernel/roles.sql` creates one LOGIN per process type inheriting exactly one privilege role; compose uses them; the live smoke runs every process on its own login and checks least privilege (gate 7). Migration 0002 revokes outbox `UPDATE` from api/worker. |
| Tenant kill switch on default policy | **Bug found by the live smoke, fixed in this PR**: `policy::load` returned defaults before reading `kill_switches`, so tenants without a `policy_versions` row could not be stopped. Regression test `tenant_kill_switch_applies_without_policy_row`. |
| Load/chaos suites | Crash-recovery and race tests exist; sustained load, Postgres failover, Redis restart and noisy-neighbour tests are **not written** |
| Legal compliance | Technical controls here (consent records, opt-out text, contact hours, suppression) do **not** by themselves establish legal compliance for outreach. |
