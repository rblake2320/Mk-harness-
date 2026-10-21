# Runbook — Suspected unapproved or duplicate send (contract O7, O10)

**Status:** *Implemented* (text). *Independently verified* requires a game-day
record under `evidence/releases/<id>/gameday-*.json` with a second person
executing it against staging.

A paging alert (`MKUnapprovedSendSuspected`, `MKDuplicateSendSuspected`,
`deploy/observability/alerts.yml`) or any human report that a customer received
a message that was not approved, was sent twice, or went to the wrong person.

## 0. Stop first, investigate second (≤ 2 min)

```sh
# Disabling never needs a passkey. This stops every tenant's dispatch; the worker
# finishes provider calls already in flight and acknowledges nothing new.
curl -X POST "$KERNEL/internal/v1/kill-switch/global" -H "authorization: Bearer $OPERATOR_ASSERTION" \
     -d '{"enabled":false,"reason":"incident <id>"}'
```

If only one tenant is affected and the evidence is unambiguous, the tenant
switch may be used instead — but default to global.

## 1. Preserve evidence (before anyone "fixes" data)

* `mk-audit-verifier --tenant <tenant>` → chain verification result saved.
* Export: `GET /internal/v1/actions/{id}` for every suspect action,
  `kernel.message_deliveries` + `kernel.delivery_events` rows for them,
  `kernel.approvals` rows (including `human_binding`, credential id), the
  worker/relay/api logs for the window (logs contain no PII; action ids only).
* Provider side: Twilio message resource(s) by SID — `to`, `date_sent`,
  `status`, `num_segments`.
* Save all of it to `evidence/incidents/<id>/` (never in git history of the
  product repo; it is customer data).

## 2. Classify

| Finding | Meaning | Where to look |
|---|---|---|
| Action has `state=completed`, one `message_deliveries` row, one provider SID, customer saw 2 messages | **Provider-side duplicate** (carrier retry) | provider support ticket; no kernel defect |
| Two `message_deliveries` rows with distinct `attempt` for one action | **Kernel retry after ambiguous submission** — must be impossible (`DeliveryState` fold + `submission_unknown`); P0 defect | `dispatch.rs`, drill F2/F3 |
| Two actions, same `idempotency_key`, both completed | **Idempotency bypass** — P0 | `actions.rs` unique `(tenant_id, idempotency_key)` |
| Action completed with `approvals.decision != approved` or `human_binding = unbound` in production | **Unapproved send** — P0, also a pre-flight failure | `human_approval.rs`; `MK_ALLOW_UNBOUND_APPROVAL` must be unset |
| Action completed after a `suppressions` row for the destination existed | **Opt-out race** — P0 | C6 advisory lock path; `cancel_pending` |
| Recipient ≠ `arguments.to` | **Destination mismatch** — P0, possible cross-tenant exposure | `destination_hash`, RLS |

Any P0 keeps the global switch **off** until the fix is deployed, the fault
drill passes, and the release owner signs.

## 3. Customer remediation

* The consultant who owns the customer is told the same day, with the exact
  text that was sent and when. The consultant, not the platform, decides the
  apology.
* If the customer had opted out: record the suppression if missing (`POST
  /internal/v1/suppressions`, reason `incident_<id>`), and treat the event as a
  compliance incident under `docs/legal-review.md` (TCPA exposure is the
  consultant's and the platform's; counsel is informed).
* No automated "sorry" message is ever sent by the system.

## 4. Re-enable

Only through the enable sequence in `deploy/kernel/README.md` (restore gate in
report mode → review → passkey step-up), after the postmortem names the root
cause and the test that now covers it.

## 5. Postmortem (within 5 working days)

Template: timeline, blast radius (tenants, customers, messages), root cause,
why the controls did not catch it, the new test or alert, and the matrix rows
whose status changed. Stored under `evidence/incidents/<id>/postmortem.md`.
