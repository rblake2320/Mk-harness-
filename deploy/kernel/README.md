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
| `MK_MASTER_KEY` | api, worker | base64 32 bytes; same key as FastAPI `MASTER_KEY` |
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
| `MK_KERNEL_URL`, `MK_ASSERTION_FILE`, `MK_KNOWLEDGE_URL` | mcp | API base, path to a host-refreshed assertion, optional read-only KB |

Hardening expected from the orchestrator: read-only root filesystem,
`cap_drop: [ALL]`, `no-new-privileges`, memory/CPU/PID limits, egress limited
to PostgreSQL, Redis, the telemetry collector and `MK_EGRESS_AUTHORITIES`.

Kill switches: `POST /internal/v1/kill-switch/global` (role `platform_operator`)
and `POST /internal/v1/kill-switch/tenant` (role `tenant_admin`). Both disable
dispatch without disabling reads; the worker also stops dispatching whenever
the database (and therefore audit persistence) is unreachable.
