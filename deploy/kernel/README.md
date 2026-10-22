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
| `MK_DB_HOST`, `MK_DB_USER`, `MK_DB_PASSWORD`, `MK_DB_NAME`, `MK_DB_PORT` | all | alternative to `MK_DATABASE_URL` (composed in-process, `sslmode=require`); the orchestrator injects these so no password-bearing URL is written anywhere |
| `MK_DB_SSLROOTCERT` | all | path to the database CA bundle (RDS global bundle). **Required in production**: switches to `sslmode=verify-full` and makes the client trust that CA alone instead of the bundled webpki roots |
| `MK_REDIS_URL` | relay, worker | `redis://host:6379` |
| `MK_MASTER_KEY` | api, worker, keyctl, restore-gate | base64 32 bytes; same key as FastAPI `MASTER_KEY`. Legacy seal (keyring version 0) and HMAC destination fingerprints. **Not** given to the verifier |
| `MK_KEK` | api, worker, keyctl, restore-gate | base64 32 bytes key-encryption key (from the secrets manager / KMS data key). Wraps the per-version data keys in `kernel.key_versions` (migration 0005). Empty = legacy master-key-only seal: allowed for development, logged at start, **refused by production pre-flight** |
| `MK_KEK_ID` | same | identifier recorded on each wrapped version; default `kek-1`. Change it together with the KEK value |
| `MK_FINGERPRINT_KEYS` | api, keyctl | optional `kid=base64(32 bytes),...` destination-fingerprint keys; **first entry is current**. Unset = `m0` = `MK_MASTER_KEY` (pre-0008 behaviour). Rotation order and `mk-keyctl fingerprint-status / fingerprint-rekey / fingerprint-prune`: `docs/runbooks/key-compromise.md` |
| `MK_TENANT_READ_RPS` / `MK_TENANT_READ_BURST` | api | per-tenant GET budget per replica (default 20 / 40); over → `429 TENANT_RATE_LIMITED` + `Retry-After` |
| `MK_TENANT_WRITE_RPS` / `MK_TENANT_WRITE_BURST` | api | per-tenant non-GET budget per replica (default 5 / 10) |
| `MK_MAX_INFLIGHT` | api | concurrent `/internal/v1` requests per replica (default 256); full → `503 OVER_CAPACITY` + `Retry-After: 1`. Webhooks, adapter callbacks and health are never shed. Published envelope: `docs/load/limits.md` |
| `MK_LEGACY_SEAL_RETIRED` | same | `1` after `mk-keyctl reencrypt` reports zero rows under version 0: the process then refuses to unseal legacy ciphertext at all |
| `MK_ASSERTION_KEYS` | api | `kid=<base64url Ed25519 public key>,...`; FastAPI holds the private keys |
| `MK_BIND` | api | default `127.0.0.1:8090`; never expose publicly |
| `MK_CALLBACK_TOLERANCE_SECS` | api | default 120 |
| `RUST_ACTION_KERNEL_ENABLED` | api | `1` to enqueue; unset = shadow mode (evaluate + record only) |
| `MK_APPROVAL_RP_ID` | api | WebAuthn relying-party id = the approval UI's effective domain (e.g. `app.example.com`). **Required.** Every approve needs a kernel-verified passkey assertion over a challenge bound to the action digest (migration 0003) |
| `MK_APPROVAL_ORIGINS` | api | comma list of exact origins allowed in `clientDataJSON` (`https://app.example.com`); each must be within `MK_APPROVAL_RP_ID` |
| `MK_ALLOW_UNBOUND_APPROVAL` | api | **development only.** `1` lets the API start without an RP id; approvals are then recorded with `human_binding=unbound`. Never set in staging or production; pre-flight refuses it |
| `MK_APPROVAL_ALLOW_NO_UV` | api | development only; accept assertions without the user-verified flag |
| `MK_PUBLIC_WEBHOOK_BASE` | api, worker | public base URL the messaging provider calls (`https://hooks.example.com`). Webhook signatures are verified over this URL — never over `Host`/`X-Forwarded-*`. The worker uses it to build each message's `StatusCallback` |
| `MK_TWILIO_API_BASE` | worker | `https://api.twilio.com` in production; the simulator's address in staging/smoke. Empty = provider adapter disabled |
| `MK_EGRESS_AUTHORITIES` | worker | must include `api.twilio.com` for the provider adapter (the tool allowlist pins it) |
| `MK_RUN_MIGRATIONS` | api | `1` to run `migrations/kernel` on boot (migrator role) |
| `MK_MOBILE_INTAKE_URL` | worker | template, e.g. `https://adapters.internal/agents/{agent_id}/work-orders` |
| `MK_EGRESS_AUTHORITIES` | worker | comma list of `host[:port]` the worker may call |
| `MK_WORKER_ID`, `MK_WORKER_BATCH`, `MK_LEASE_SECS` | worker, relay | identity and tuning |
| `MK_METRICS_BIND` | worker | `/metrics` listener, default `127.0.0.1:9100`; empty disables. Aggregates only, no identifiers (`deploy/observability/README.md`) |
| `MK_METRICS_SAMPLE_SECS` | worker | gauge sampler period, default 15 (min 5); one tenant transaction per tenant per sample |
| `MK_KERNEL_URL`, `MK_ASSERTION_FILE`, `MK_KNOWLEDGE_URL` | mcp | API base, path to a host-refreshed assertion, optional read-only KB |

Hardening expected from the orchestrator: read-only root filesystem,
`cap_drop: [ALL]`, `no-new-privileges`, memory/CPU/PID limits, egress limited
to PostgreSQL, Redis, the telemetry collector and `MK_EGRESS_AUTHORITIES`.

Kill switches: `POST /internal/v1/kill-switch/global` (role `platform_operator`)
and `POST /internal/v1/kill-switch/tenant` (role `tenant_admin`). Both disable
dispatch without disabling reads; the worker also stops dispatching whenever
the database (and therefore audit persistence) is unreachable.

## Production runbook

Every step below is a human operator action. Nothing in this section is
performed by the application or by an agent, and no step enables dispatch
except the last one, which requires the platform operator's passkey.

### Bring-up (first deployment or new environment)

0. Generate secrets once per environment (CSPRNG, owner-only file ACL; never commit the file):

   ```powershell
   pwsh -File scripts\kernel-secrets.ps1 -EnvFile .env     # Windows
   # or: scripts/kernel-secrets.sh .env                     # Linux/macOS
   ```

   Produces `POSTGRES_PASSWORD`, `JWT_SECRET`, `MASTER_KEY`, the Ed25519 pair
   (`MK_ASSERTION_KEYS` public → kernel; `KERNEL_ASSERTION_PRIVATE_KEY` private →
   FastAPI only) and the four `MK_DB_*_PASSWORD` login passwords, and leaves
   `RUST_ACTION_KERNEL_ENABLED=0`. Add `MK_KEK` from the secrets manager / KMS.
   Template: `deploy/kernel/.env.kernel.example`. In AWS the same values live in
   Secrets Manager (`infra/terraform`), never in a file.
   Local/compose bring-up (order enforced by `depends_on`):

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.kernel.yml up -d
   # kernel-migrate (schema owner) → kernel-roles (LOGIN identities) → kernel-api / kernel-relay / kernel-worker → api
   docker compose --profile verify run --rm kernel-verifier     # audit chains, read-only identity
   ```

1. Create the database roles from `deploy/kernel/roles.sql` (owner, migrator,
   api, worker, relay, readonly logins) and set each process's `MK_DATABASE_URL`
   to its own login. Never run a process as the owner.
2. Generate secrets in the secrets manager, never in files or compose:
   `MK_MASTER_KEY` (32 bytes), `MK_KEK` (32 bytes, or a KMS data key),
   the FastAPI→kernel Ed25519 assertion key pair (`mk-devkeys gen`; the kernel
   holds only the public half in `MK_ASSERTION_KEYS`).
3. Run migrations once with the migrator login: `MK_RUN_MIGRATIONS=1 mk-action-api`
   (or `sqlx migrate` against `migrations/kernel`). Then create the first
   wrapped data-key version **before any process starts**: `mk-keyctl rotate
   "initial"` (owner login, `MK_KEK` set). `mk-keyctl status` must show
   `current_version=1`; without this step processes seal under the legacy
   single master key (version 0), which pre-flight refuses for production.
4. Run the pre-flight (`scripts/kernel-preflight.sh --for-enable`). With `--for-enable` it also requires: no `MK_ALLOW_UNBOUND_APPROVAL`/`MK_APPROVAL_ALLOW_NO_UV`, `MK_APPROVAL_RP_ID`/`ORIGINS` set, `MK_KEK` with exactly one active key version, `MK_LEGACY_SEAL_RETIRED=1`, a readable `MK_DB_SSLROOTCERT`, an https `MK_PUBLIC_WEBHOOK_BASE`, `MK_TWILIO_API_BASE=https://api.twilio.com`, no destination row orphaned from `MK_FINGERPRINT_KEYS`, and `mk-restore-gate` (report mode) agreeing the environment is recoverable. Required: RLS
   on every `kernel.*` table, per-process logins in place, `MK_APPROVAL_RP_ID`
   and `MK_APPROVAL_ORIGINS` set, `MK_ALLOW_UNBOUND_APPROVAL` unset, `MK_KEK` set,
   `MK_PUBLIC_WEBHOOK_BASE` set and equal to the URL configured at the provider.

   ```bash
   KERNEL_URL=http://kernel-api:8090 APP_URL=https://<app> PG_HOST=db PG_DB=mkharness \
   PG_ADMIN_URL=postgres://mk:$POSTGRES_PASSWORD@db/mkharness \
   MK_PREFLIGHT_EMAIL=<ops user> MK_PREFLIGHT_PASSWORD=… \
   scripts/kernel-preflight.sh                 # liveness, assertion pairing, schema head, least-privilege
                                               # identities, RLS, kill switches, audit chain, compose hygiene
   scripts/kernel-preflight.sh --for-enable    # + a reviewed deploy/kernel/ACCEPTANCE.md (no placeholders,
                                               #   negatives present, `Result: ACCEPTED` exactly)
   ```

   Pre-flight is exercised by `scripts/kernel-live-smoke.sh` and so by CI on every PR.
5. Start `mk-action-api`, `mk-outbox-relay`, `mk-action-worker`,
   `mk-audit-verifier` with `RUST_ACTION_KERNEL_ENABLED` **unset** (shadow mode)
   and the global kill switch **disabled** (its default on a fresh database).
6. Register a passkey for every approver and for the platform operator
   (`/approval-credentials/register/*`). Approvals and kill-switch re-enable are
   impossible without them.

### Enable sequence (first dispatch, or after any restore / incident)

1. `mk-restore-gate --restored-at <RFC3339 of the data's last known-good point>`
   in report mode. Every check must be `ok: true`; otherwise stop here.
2. Review the reconciliation backlog it prints; resolve every
   `reconciliation_required` action against provider records before anything
   else is sent to those customers.
3. Confirm inbound health is green (`/internal/v1/inbound/health`), the provider
   webhook URL matches `MK_PUBLIC_WEBHOOK_BASE`, and one signed test callback
   from the provider is accepted (`twilio_sim` is for staging only).
4. Set `RUST_ACTION_KERNEL_ENABLED=1` and restart `mk-action-api`.
5. The platform operator enables the global switch with a passkey step-up:
   `POST /internal/v1/kill-switch/global/challenge` → sign → `POST
   /internal/v1/kill-switch/global {enabled:true, assertion}`. The audit chain
   records who, when and under which credential.
6. Tenants are enabled one at a time (`/kill-switch/tenant`), never in bulk,
   and only for tenants whose sender identity is registered and whose
   consultants have completed the consent attestation.

### Stop / rollback

* **Stop everything now:** `POST /internal/v1/kill-switch/global {enabled:false}`
  (no passkey needed to disable — stopping is always allowed). In-flight
  provider calls finish; nothing new is dispatched. Then follow
  `docs/runbooks/incident-unapproved-or-duplicate-send.md`.
* **Stop one tenant:** `POST /internal/v1/kill-switch/tenant`.
* **Out-of-band stop** (application unreachable): `psql $ADMIN -c "UPDATE kernel.kill_switches SET dispatch_enabled=false WHERE scope='global'"`.
* **Shadow mode:** unset `RUST_ACTION_KERNEL_ENABLED` and restart kernel-api — proposals are evaluated and audited, never enqueued.
* The worker also stops dispatching on its own whenever Postgres is unreachable (audit persistence is a precondition of execution).
* **Roll back a release:** disable the global switch, deploy the previous
  images, run the restore gate in report mode, re-enable through the enable
  sequence. Migrations are forward-only; a release that needs a schema
  rollback is handled as a restore (`docs/runbooks/restore-without-resend.md`).

### Envelope key rotation (`mk-keyctl`, contract S6/S10)

Runs with the owner login and the same `MK_MASTER_KEY` / `MK_KEK` / `MK_KEK_ID`
as the API. Every step is idempotent and resumable.

```sh
mk-keyctl status                 # versions, which is active, rows still under other versions
mk-keyctl rotate "quarterly"     # new DEK wrapped by MK_KEK → active; previous → retiring
                                 # restart api + worker so they load the new ring (old data stays readable)
mk-keyctl reencrypt              # re-seal every sealed column under the active version; safe to interrupt and rerun
                                 # prints `unreadable: N` for rows no loaded key can open — N must be 0 before the next step
mk-keyctl retire <old-version>   # refused while any row is still under <old-version>
```

Rotating the **KEK** itself: set the new `MK_KEK`/`MK_KEK_ID` alongside the
old one is not supported by design — instead `rotate` under the new KEK (the
new version is wrapped by it), `reencrypt`, `retire` the versions wrapped by the
old KEK, then destroy the old KEK in the secrets manager.

Retiring the **legacy** master-key seal (version 0): after `reencrypt` reports
`kernel.*: rows_not_under_current=0` for every table, set
`MK_LEGACY_SEAL_RETIRED=1` on api and worker and run `mk-keyctl retire 0`.
`MK_MASTER_KEY` is still required for destination fingerprints.

### Other credential rotation

* **Assertion key**: add `k2=<pub>` to `MK_ASSERTION_KEYS` (comma list), redeploy
  kernel-api; switch FastAPI to `KERNEL_ASSERTION_KID=k2` + new private key;
  after ≥ 2 minutes (assertion life 30 s + skew) remove `k1`.
* **Adapter secret**: `POST /api/agent-ops/adapters/{id}/rotate` (overlap window
  returned); update the device agent's `MK_AGENT_SECRET`; the old secret dies at
  `not_after`.
* **DB login passwords**: rerun `kernel-roles` with new `MK_DB_*_PASSWORD`
  (`ALTER ROLE … PASSWORD`), then restart the matching process.
* **`MASTER_KEY`**: sealed data no longer depends on it once the legacy seal is
  retired (above), but destination fingerprints do; its rotation re-fingerprints
  suppressions and is **Not demonstrated** (`docs/runbooks/key-compromise.md`).
  `kernel-secrets` never rotates it under `-Force`/`--force`; `-RotateMasterKey`
  refuses when a key exists unless `-IAcceptCredentialLoss` is given.

Technical controls here do not by themselves establish legal compliance for
outreach (`docs/release/legal-provider-gate.md`).

### Restore (never re-send)

`docs/runbooks/restore-without-resend.md`. The gate binary is
`mk-restore-gate`; it never enables dispatch.
