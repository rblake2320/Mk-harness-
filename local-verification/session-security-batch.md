# Persistent sessions and kernel revocation — S2 / H9 engineering batch

Source: `abe3bb787a66738cb02ba6db93f7f17c92110fd7`, PR37 branch.
Author-run local verification, 2026-10-22. No independent staging or production
qualification is claimed. S2 remains open for MFA login and sensitive-action
step-up; all 87 release rows still require their specified qualification.

## Observed defects and repairs

- Initial S2 tests found no session-list/revocation API and same-second reusable
  refresh credentials. Persistent session IDs now govern both access and
  refresh, including tenant/user binding and expiry. Refresh uses an atomic
  one-use nonce; reuse revokes the whole session. SDK refresh is single-flight,
  persists the replacement before reload and never replays an old-session
  operation under a different login.
- Local logout, password change, account deletion and user/session revocation
  now commit a durable kernel-delivery record. The worker leases delivery across
  replicas, retries with bounded backoff, and survives loss of the requesting
  JWT/process. Only a validated 201 revocation receipt confirms completion;
  outages/malformed receipts remain pending. Pending delivery older than 60 s
  fails readiness. Read-only/safety status never implies provider cancellation
  of a send already in flight.
- A real kernel regression reproduced dispatch through a revoked session when
  the revocation timestamp preceded an approval committed by an in-flight
  request. `s2-approval-race-red.log` records the simulator accepting the send.
  Irreversible revocation is now checked regardless of approval timestamp;
  targeted and full-suite retests block that send with zero provider calls.
- `session_revoker` is a dedicated, route-restricted service role. Real kernel
  tests refuse reads, passkey enrollment, proposals, approval challenges,
  switch changes, combined-role escalation and missing explicit session scope.
  A real queued passkey approval is cancelled, its session denied and repeated
  delivery acknowledged without sending. Legacy `jwt:` sessions and their queued
  approvals are retired at authentication/dispatch during rollout.
- Native browser testing found mobile Sign out hidden, then a 404px-wide signed-
  out page in a 360px viewport. Both were repaired and retested at 360/360.
- Mobile type-check exposed a missing declared `expo-constants` dependency,
  missing composer style and call to a removed follow-up SDK method. The app now
  uses the current governed draft API and distinguishes a saved draft from a send.

## Retained receiving checks

- Rust workspace: **216 passed**, PostgreSQL + Redis, serial test execution,
  exit 0 (`s2-rust-final.log`); Clippy warnings denied, exit 0
  (`s2-clippy-final.log`). The earlier compile failure used nonexistent simulator
  `stop` methods; the simulator types clean up through Drop. The first scoped-
  role test exposed Axum's nested path rewriting; the guard now checks OriginalUri.
- Python: **294 passed**, no skips. Session-focused tests include concurrent
  refresh reuse, two-worker delivery leases, file-backed database reopen,
  delivery recovery, six invalid receipts, cross-user refusal, password/delete/
  user-wide revocation, stable kernel session identity and delayed readiness.
- Web: **22 passed** including mobile sign-out confirmed/pending/offline cases,
  refresh coalescing, delayed 401s, no post-logout resurrection, no cross-login
  replay and accessibility checks (`s2-web-final.json`). Production build passed.
- Expo TypeScript: exit 0 (`s2-mobile-final.log`). Native-app interaction and full
  X2 mobile parity remain in the implementation/verification queue.
- Native Python Playwright at the source pin (`s2-browser-abe3bb7/`): actual
  browser -> FastAPI -> Rust -> PostgreSQL, URL redirection only, no mocked
  responses. One forced-invalid access token triggers exactly one successful
  refresh; reload retains the rotated token. Revoked access/refresh return 401,
  the other session remains 200, mobile logout clears storage, and a new login
  works. Zero page errors; authenticated and signed-out document widths 360px.
- Exact stack readback (`s2-stack-abe3bb7/stack-summary.json`): 3/3 app sessions
  revoked, 3/3 delivery records confirmed, 3 kernel revocations; actual runtime
  role `mk_kernel_api`. Owned processes and isolated kernel/app databases removed.

`s2-sessions-red-redacted.xml` preserves the initial failing assertions with
synthetic JWT strings removed. The original remains locally in ignored
`.local-tools/s2-raw/`; no real credential was used. Other intermediate failures
and corrected reruns are retained, not relabelled as successful executions.
Artifact SHA-256 values are in `session-security-manifest.json`.

Rollout order and exact local recipe: `tools/verification/README.md`. The existing
shared task-owned PostgreSQL/Redis and built-web preview remain available for the
next acceptance batches. No real messaging provider, model API, paid deployment,
human participant or independent verifier was invoked by this batch.
