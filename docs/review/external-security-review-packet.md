# External security review — engagement packet (contract S15, WP10)

**Status: Implemented (packet). S15 is Not demonstrated until a qualified
external reviewer delivers findings and retests the fixes.** A coding-agent
review does not satisfy S15; this packet exists so the engagement can start
the day a reviewer is contracted.

## 1. Scope (all in scope; nothing may be excluded by the reviewer's choice)

| Component | Where | What a compromise would mean |
|---|---|---|
| Rust action kernel: API, worker, relay, verifier, operator tools | `rust/crates/*`, `migrations/kernel`, `deploy/kernel` | unauthorized or duplicate send, approval forgery, suppression bypass, cross-tenant read |
| Human-approval authority (WebAuthn, challenges, revocation) | `rust/crates/mk-crypto/src/webauthn.rs`, `mk-store/src/human_approval.rs`, `mk-api/src/routes/human_approval.rs`, `docs/identity-and-approval.md` | an approval minted without a human gesture |
| Messaging adapter + provider webhooks | `rust/crates/mk-adapters/src/twilio*.rs`, `mk-api/src/routes/messaging.rs`, `contracts/inbound/v1` | forged delivery/inbound events, lost opt-outs |
| FastAPI application (proposal service, drafting, customers, inbound meaning) | `backend/app` | prompt-injection reaching an action, PII handling, assertion key misuse |
| Web interface + SDK | `web/src`, `packages/sdk` | approval UX deception, digest substitution |
| Envelope encryption, key tooling, restore gate | `mk-crypto/src/keyring.rs`, `mk-store/src/keys.rs`, `mk-worker/src/bin/{keyctl,restore_gate}.rs` | secret recovery, restore that re-sends |
| Deployment and IaC | `infra/terraform`, `.github/workflows`, `deploy/` | secret exposure, public kernel surface, unsigned artifacts |
| Recovery procedures | `docs/runbooks/` | procedures that permit re-sending or lose suppressions |

Out of scope: nothing in this repository. Third-party services (Twilio, AWS)
are in scope as *configured by this repository*, not as services.

## 2. Invariants to attack (the reviewer should try to break each)

1. **No send without a consumed, digest-exact, human-bound approval.** Try: replayed assertions, agent-role principals, forged WebAuthn (wrong rpIdHash, origin, counter regression, transplanted credential, challenge for another action/digest), race between edit and approve, approval TTL, kill-switch toggles mid-dispatch.
2. **No duplicate submission after an ambiguous provider response.** Try: kill the worker between provider accept and persistence (drill F2), 5xx then success (F3), lease expiry, Redis loss (F5), restore (F6).
3. **Suppression beats everything and is immediate.** Try: STOP racing a dispatch (C6 advisory lock), STOP for a number shared across tenants (migration 0006), opt-out via a *forged* webhook, lifting a suppression as an agent.
4. **Tenant isolation under runtime logins.** Try: every route with another tenant's ids, SQL as each process login without tenant context, outbox/lease sweeps, metrics and logs for identifiers.
5. **The proposal service cannot approve.** Try: with the FastAPI assertion private key in hand, mint anything that passes `/approve` or `/kill-switch/global {enabled:true}`.
6. **Secrets never leave sealed storage.** Try: logs, audit payloads, metrics, error bodies, provider callbacks, restore gate output, Terraform state.
7. **Prompt injection cannot reach an action.** Try: customer messages / notes / documents that attempt to approve, redirect, change destination, call tools, or exfiltrate another customer's data through a draft (`backend/app/drafting.py` leak checks, A-row harness).
8. **The restore path cannot re-send.** Try: restored outbox + Redis, approvals created before the restore point, in-flight actions.

## 3. Reviewer access

* Repository at a named commit (read); a staging environment built from
  `infra/terraform/envs/staging` with the Twilio simulator; one tenant per
  reviewer with admin, approver (passkey registered via `mk-softauthn` or a
  real authenticator) and agent principals; database read access as
  `mk_readonly_login` **and** as the owner login (insider model T7).
* Logs, metrics, audit export (`/api/audit/export.jsonl`) for their tenant.
* No production data of any kind.

## 4. Deliverables required from the reviewer

* Findings with severity (critical / high / medium / low) using the contract's
  definitions: any finding capable of unauthorized dispatch, cross-tenant
  disclosure, approval forgery or suppression bypass is at least **high**.
* For each finding: reproduction steps, affected commit, proposed fix class.
* **Retest** of every fix on the fix commit, signed by the same reviewer.
* A statement of independence from the author.

## 5. Release rule (verbatim from the contract)

Zero unresolved critical; zero unresolved high; no unresolved medium capable
of unauthorized dispatch, cross-tenant disclosure, approval forgery, or
suppression bypass; lower findings documented with owners and deadlines;
fixes retested by the reviewer.

## 6. Evidence record

`evidence/releases/<id>/S15.yaml` with the signed report as `evidence[]`,
`verifier_independent_of_author: true`, and the retest report as a second
artifact. The matrix row S15 moves only when `tools/evidence/check.py` accepts
that record.

## 7. Known gaps to disclose to the reviewer up front

* Master-key rotation does not re-fingerprint destination-keyed suppressions
  (`docs/runbooks/key-compromise.md`).
* Per-tenant rate limits and graceful rejection above capacity are not implemented (O2).
* OpenTelemetry tracing is absent (O6).
* IaC has never been applied; the staging environment must be built first.
* `MK_ALLOW_UNBOUND_APPROVAL=1` exists for development; pre-flight (PR #32) is
  the control that refuses it in production.
