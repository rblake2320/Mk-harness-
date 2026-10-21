# Published capacity limits (contract O2)

Status: **Implemented** (author-run tests only). Not *Independently verified*;
the envelope numbers below are design limits, not measured production capacity.

## Envelope (contract O2)

| Dimension | Envelope |
|---|---|
| Businesses (tenants) | 1,000, ≤10 users each |
| Customer records | 1,000,000 |
| Reads | 100 rps (system) |
| Writes / proposals | 20 rps (system) |
| Dispatch | 10/s, subject to provider limits |

## Enforced limits (per kernel API replica)

| Limit | Env | Default | Over the limit |
|---|---|---|---|
| Per-tenant reads (GET `/internal/v1/*`) | `MK_TENANT_READ_RPS` / `MK_TENANT_READ_BURST` | 20 rps / burst 40 | `429 TENANT_RATE_LIMITED`, `Retry-After: <s>` |
| Per-tenant writes (non-GET `/internal/v1/*`) | `MK_TENANT_WRITE_RPS` / `MK_TENANT_WRITE_BURST` | 5 rps / burst 10 | `429 TENANT_RATE_LIMITED`, `Retry-After: <s>` |
| Replica in-flight | `MK_MAX_INFLIGHT` | 256 concurrent | `503 OVER_CAPACITY`, `Retry-After: 1`, refused immediately (no queueing) |
| Request body | compiled | 256 KiB | `413` |
| Request time | compiled | 20 s | `504` |

Effective system limit = per-replica value × API replicas (`desired_count` in
`infra/terraform`). Two replicas: one tenant may burst to 80 reads / 20 writes
before refusal — still inside the system envelope only if few tenants burst at
once; the in-flight cap is the backstop.

Properties (tested — `crates/mk-api/src/limits.rs` unit tests (7),
`http_e2e::per_tenant_limits_and_graceful_rejection_above_capacity`,
`backend/tests/test_agent_ops.py::test_kernel_capacity_refusals_pass_through_with_retry_after`):

* The tenant bucket is charged only after the actor assertion's signature
  verifies: an unauthenticated or forged caller gets 401 and spends nothing.
* A refused request costs no database write (charged before jti consumption).
* Tenants and read/write classes are isolated; one noisy tenant never starves another.
* **Never shed**: provider webhooks (an inbound STOP must always be recorded),
  adapter callbacks (they settle sends already made), health and metrics.
* FastAPI forwards 429/503 and a numeric `Retry-After` unchanged and never retries a write.
* `mk_requests_rejected_total{code=tenant_read|tenant_write|over_capacity}` is exported.

## Not demonstrated

* Measured capacity at 1,000 tenants / 1,000,000 records (data-volume run).
* Limits tuned from production traffic.
* Per-tenant dispatch-rate limits beyond the contact frequency cap and provider throttling.
