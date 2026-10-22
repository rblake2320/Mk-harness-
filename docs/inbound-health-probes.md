# Public inbound health checks (C8)

With the Twilio adapter configured, the worker checks the configured public
inbound webhook every 15 seconds, independently of Redis dispatch traffic.
`MK_EGRESS_AUTHORITIES` must include both the Twilio authority and the public
webhook authority. `MK_PUBLIC_WEBHOOK_BASE` must be an HTTPS origin; loopback HTTP
is available only in explicitly configured local test environments. Redirects
are refused. Terraform and local stack scripts include the webhook authority.

Each active sender gets its own random, 10-second probe generation with an exact
form-body digest. The worker commits issuance and releases its DB connection
before HTTP. It signs the form with that sender's provider credential, over the
configured public URL. The same inbound route used by provider messages verifies
signature, account, sender and issued digest, then commits the receipt before
acknowledgement. The worker additionally reads back the exact receipt: a proxy
returning HTTP 200 cannot establish health. Replay and expired generations fail.

Probe traffic creates no customer messages, consent, suppressions or meaning
tasks and makes no Twilio API/SMS call. Current state is bounded to one row per
sender. The API role can only record receipt; it cannot issue or confirm health.
The scheduler admits at most 16 tenants and 32 HTTP requests concurrently. Each
tenant claims at most 32 senders per cycle; the short receipt deadline begins
after HTTP capacity is acquired. An isolated tenant failure does not abort the
remaining businesses. An active sender must have its dedicated inbound number;
a service-only identity without that number cannot pass the probe.
`POST /internal/v1/inbound/health` still accepts failure reports, but `ok: true`
is refused. A signed administrator assertion is not a network probe.

All active senders must have a confirmed receipt within 60 seconds. Monitor
silence becomes stale even without an explicit failure. Staleness latches
recovery; fresh checks alone do not resume dispatch while inbound events remain
unprocessed. The scheduled worker clears the recovery latch only once the queue
is drained. An explicit administrative pause still needs explicit resume.
Normal expiry, consent and revocation checks run before health deferral.
Only consultant, manager and tenant-admin principals can read or acknowledge the
inbound processing backlog; agent-only, unrecognized and empty roles are refused.

Inspect `GET /api/agent-ops/inbound/health` for `dispatch_blocked` and
`pending_events`. Reasons include `inbound_unverified`, `inbound_stale`,
`inbound_recovery_pending`, and `inbound_paused`. Read-only operators may inspect
`kernel.inbound_probes.last_error` and timestamps. Never edit those records to
make a release gate green. Restore the route, signature configuration, database
commit path or monitor, then process the backlog and verify recovery.

Author-run real-network test:
`public_inbound_probes_require_committed_receipts_and_drain_before_recovery`
in `rust/crates/mk-api/tests/http_e2e.rs`. It exercises API and worker DB roles
with one connection each, fake-200/missing-receipt, invalid signature, redirect,
replay, multiple senders, monitor silence, pending-event drain, and forbidden
API health writes. A fleet subscenario checks 1,000 distinct businesses plus one
broken-key tenant, asserting 1,000 committed receipts, failure isolation and a
cycle shorter than 45 seconds (leaving 15 seconds for scheduling). This is a
bounded local probe-capacity test, not O2/O4 production load or soak evidence.
Clock aging is injected in isolated test rows. Independent
staging must additionally exercise the deployed DNS/TLS/public ingress and real
provider enrollment; the local test is not such a qualification record.
