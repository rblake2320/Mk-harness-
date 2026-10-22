# Resolving an uncertain submission (C4)

An uncertain submission is not a failed message. Do not resend it, invent a
provider ID, or mark it delivered because a time limit expired.

The worker checks recorded provider message IDs every 30 seconds. Checks bind
the provider account, sender, destination and ID; lost POST responses can also
be recovered by authenticated callbacks bound to the original action and attempt.
Body/date search is advisory and never establishes identity or absence.

## Administrator workflow

1. Open Inbox → Uncertain deliveries. Review the action reference, provider
   reference and provider state. Refresh first if a stale/error warning is shown.
2. If submission is still unknown or no provider ID exists, no resolution control
   is offered. Keep the exception open and investigate provider evidence. Neither
   a free-text note nor a generic exception dismissal can release replacement.
3. A tenant administrator with a registered user-verified passkey may resolve:
   - `provider_accepted`, `sent`, `delivered`: **close without replacement**.
     This records the provider evidence; it is not proof that the recipient read it.
   - `failed`: **permit a newly approved replacement**. This does not send.
4. The passkey binds the tenant, original action and action digest, delivery
   attempt, provider ID, observed state, and decision. Changed evidence requires
   another review. A failed or stale assertion consumes its challenge.
5. Any further send requires a fresh review and approval after the resolution.
   Previously queued approvals to the same destination are cancelled at dispatch
   with `approval_predates_resolution`, never silently released. The original
   action stays terminal; replay is available only after `replacement_permitted`
   and creates an unapproved draft.

The worker enforces the destination hold across contact IDs, sender identities,
action IDs and idempotency keys within the tenant and channel. Fingerprint key
rotation preserves matching. A different tenant or destination is not held by
this exception. Human decisions are append-only, tenant-isolated and audited.

## Interfaces and verification

- `POST /api/agent-ops/actions/{id}/resolution-challenge` takes `decision`.
- `POST /api/agent-ops/actions/{id}/resolve-submission` takes the same decision,
  `operation_digest` and the four WebAuthn assertion fields. The application only
  relays these; the kernel is the verifier and requires a tenant administrator.
- A configured approval RP with required user verification is mandatory; the
  unbound development approval mode cannot resolve submissions.
- Internal counterparts live under `/internal/v1/actions/{id}`. The Inbox queue
  supplies resolution options only to authorized administrators with sufficient
  provider evidence.

Author-run checks: real-Postgres `http_e2e` test
`uncertainty_gate_and_passkey_resolution_enforce_provider_evidence_and_no_replay`,
`backend/tests/test_delivery_exceptions.py`, and
`tools/verification/submission_resolution_browser.py`. Browser verification uses
explicit HTTP fixtures plus Chromium's virtual passkey; it verifies real ES256
assertions but is not live-provider staging evidence. See
`local-verification/submission-resolution-batch.md` for retained results.
