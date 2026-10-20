# Deploying the MK action kernel

Processes (one image, separate process types and DB roles):

| Process | Binary | DB role | Needs Redis |
|---|---|---|---|
| API | `mk-action-api` | `mk_kernel_api` | no |
| Outbox relay | `mk-outbox-relay` | `mk_kernel_relay` | yes |
| Worker | `mk-action-worker` | `mk_kernel_worker` | yes |
| Audit verifier (daily job) | `mk-audit-verifier` | `mk_kernel_readonly` | no |
| MCP sidecar (stdio) | `mk-mcp-server` | none (talks to API) | no |

Environment:

| Variable | Used by | Notes |
|---|---|---|
| `MK_DATABASE_URL` | all | `postgres://role:pw@host/db`; role per process type |
| `MK_REDIS_URL` | relay, worker | `redis://host:6379` |
| `MK_MASTER_KEY` | api, worker | base64 32 bytes; same key as FastAPI `MASTER_KEY`. **Not** given to the verifier |
| `MK_ASSERTION_KEYS` | api | `kid=<base64url Ed25519 public key>,...`; FastAPI holds the private keys |
| `MK_BIND` | api | default `127.0.0.1:8090`; never expose publicly |
| `MK_CALLBACK_TOLERANCE_SECS` | api | default 120 |
| `RUST_ACTION_KERNEL_ENABLED` | api | `1` to enqueue; unset = shadow mode (evaluate + record only) |
| `MK_RUN_MIGRATIONS` | api | `1` to run `migrations/kernel` on boot (migrator role) |
| `MK_MOBILE_INTAKE_URL` | worker | template, e.g. `https://adapters.internal/agents/{agent_id}/work-orders` |
| `MK_EGRESS_AUTHORITIES` | worker | comma list of `host[:port]` the worker may call |
| `MK_WORKER_ID`, `MK_WORKER_BATCH`, `MK_LEASE_SECS` | worker, relay | identity and tuning |
| `MK_KERNEL_URL`, `MK_ASSERTION_FILE`, `MK_KNOWLEDGE_URL` | mcp | API base, path to a host-refreshed assertion, optional read-only KB |

Hardening expected from the orchestrator: read-only root filesystem,
`cap_drop: [ALL]`, `no-new-privileges`, memory/CPU/PID limits, egress limited
to PostgreSQL, Redis, the telemetry collector and `MK_EGRESS_AUTHORITIES`.

Kill switches: `POST /internal/v1/kill-switch/global` (role `platform_operator`)
and `POST /internal/v1/kill-switch/tenant` (role `tenant_admin`). Both disable
dispatch without disabling reads; the worker also stops dispatching whenever
the database (and therefore audit persistence) is unreachable.

---

## Production runbook

### 0. Generate secrets (once per environment)

```powershell
pwsh -File scripts\kernel-secrets.ps1 -EnvFile .env     # Windows (CSPRNG, owner-only ACL)
# or: scripts/kernel-secrets.sh .env                     # Linux/macOS
```

Produces `POSTGRES_PASSWORD`, `JWT_SECRET`, `MASTER_KEY`, the Ed25519 pair
(`MK_ASSERTION_KEYS` public → kernel; `KERNEL_ASSERTION_PRIVATE_KEY` private →
FastAPI only), and the four `MK_DB_*_PASSWORD` login passwords. Leaves
`RUST_ACTION_KERNEL_ENABLED=0`. Fill `MK_MOBILE_INTAKE_URL` (https) and
`MK_EGRESS_AUTHORITIES` by hand. Template: `deploy/kernel/.env.kernel.example`.

### 1. Bring up (order is enforced by compose `depends_on`)

```bash
docker compose -f docker-compose.yml -f docker-compose.kernel.yml up -d
# kernel-migrate (schema owner) → kernel-roles (LOGIN identities) → kernel-api / kernel-relay / kernel-worker → api
docker compose --profile verify run --rm kernel-verifier     # audit chains, read-only identity
```

### 2. Pre-flight (every deploy; blocks enabling)

```bash
KERNEL_URL=http://kernel-api:8090 APP_URL=https://<app> PG_HOST=db PG_DB=mkharness \
PG_ADMIN_URL=postgres://mk:$POSTGRES_PASSWORD@db/mkharness \
MK_PREFLIGHT_EMAIL=<ops user> MK_PREFLIGHT_PASSWORD=… \
scripts/kernel-preflight.sh                 # 27 checks: liveness, assertion pairing, schema head,
                                            # least-privilege identities, kill switches, audit chain, compose hygiene
scripts/kernel-preflight.sh --for-enable    # + requires deploy/kernel/ACCEPTANCE.md: every field filled with a real
                                            #   value (placeholders, bad hashes, missing negatives are rejected) and
                                            #   `Result: ACCEPTED` exactly
```

The pre-flight is itself exercised by `scripts/kernel-live-smoke.sh` (gate 8)
and therefore by CI on every PR.

### 3. Enable dispatch (only after `--for-enable` passes)

1. `RUST_ACTION_KERNEL_ENABLED=1` on **kernel-api only**; `docker compose up -d kernel-api`.
2. Confirm the global switch is on and every tenant switch is as intended:
   `psql $RO_URL -c "SELECT scope, tenant_id, dispatch_enabled FROM kernel.kill_switches"`.
3. Enable one pilot tenant; keep others off via `POST /api/agent-ops/kill-switch/tenant {"dispatch_enabled":false}` as tenant admin.
4. Watch `kernel-worker` logs for `dispatched` / `housekeeping` lines and the `/metrics` decision counters.

### 4. Stop / rollback (fastest first)

| Scope | Action | Effect |
|---|---|---|
| One tenant | `POST /api/agent-ops/kill-switch/tenant {"dispatch_enabled":false}` (tenant_admin) | queued + new actions for that tenant denied at dispatch and at proposal |
| Everyone | `POST /api/agent-ops/kill-switch/global {"dispatch_enabled":false}` (user listed in `KERNEL_PLATFORM_OPERATORS`) | all dispatch stops; reads/approvals keep working |
| Everyone, out-of-band | `psql $ADMIN -c "UPDATE kernel.kill_switches SET dispatch_enabled=false WHERE scope='global'"` | same, when the app is unreachable |
| Shadow mode | unset `RUST_ACTION_KERNEL_ENABLED`, `up -d kernel-api` | proposals evaluated/audited, never enqueued |
| Code rollback | redeploy previous image tag | migrations are additive; no down-migration needed for 0001/0002 |

The worker also stops dispatching on its own whenever Postgres is unreachable
(audit persistence is a precondition of execution).

### 5. Key rotation

* **Assertion key**: add `k2=<pub>` to `MK_ASSERTION_KEYS` (comma list), redeploy
  kernel-api; switch FastAPI to `KERNEL_ASSERTION_KID=k2` + new private key;
  after ≥2 minutes (assertion life 30 s + skew) remove `k1`.
* **Adapter secret**: `POST /api/agent-ops/adapters/{id}/rotate` (overlap window
  returned); update the device agent's `MK_AGENT_SECRET`; old secret dies at
  `not_after`.
* **DB login passwords**: rerun `kernel-roles` with new `MK_DB_*_PASSWORD`
  (`ALTER ROLE … PASSWORD`), then restart the matching process.
* **MASTER_KEY**: sealed adapter credentials are AES-GCM under it; rotation
  needs a decrypt–re-encrypt pass (not yet scripted). `kernel-secrets` therefore
  **never** rotates it under `-Force`/`--force`; `-RotateMasterKey` refuses when a
  key exists unless `-IAcceptCredentialLoss` is given (fresh environments, or after
  revoking and re-enrolling every adapter).

### 6. What "production-ready" still does not mean

`verified_on_device` is `false` until a reviewed `ACCEPTANCE.md` exists. OTLP
export, external anchoring of audit roots, and load/chaos suites are open items
in `rust/README.md`. Technical controls here do not by themselves establish
legal compliance for outreach.
