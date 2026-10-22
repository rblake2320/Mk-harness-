# Post-erasure billing state fences

Source: `81dfbfad8f21addce9340675202db96ebd862963`, 2026-10-22. Author-run
engineering evidence only; no live Stripe operation or independent S13 closure.

## Failed, repaired, retested

Seven regressions reproduced late-event resurrection: checkout callbacks changed
the erased account's provider reference, subscription callbacks reactivated it,
payment callbacks rewrote its billing history, and a later referral payment
created a Stripe customer and credit for an already-erased referrer. HTTP mocks
retained these external-call observations without contacting Stripe.

The first direct-SQL test (`billing-privacy-pg-red`) used an unqualified table
name and failed on the fixture's restricted search path; that is not a valid
security reproduction. The corrected schema-qualified test
(`billing-privacy-pg-red-v2`) reproduced both missing write/isolation fences.

The application now ignores these late billing mutations and skips erased or
inactive referral participants. Additive migration `0004_billing_erasure_fence`
serializes billing writes with erasure, refuses new/rebound/active records, and
permits only terminal mirror cleanup. Terminal mirror updates do not confirm
any provider task. Older applied migrations were not edited.

## Worked

- **406** application/contract/readiness/scanner checks passed in
  `billing-privacy-full-green` (including the seven new regressions).
- **64** PostgreSQL/integration checks passed in
  `billing-privacy-pg-full-green-v2`. Direct tests cover six invalid SQL writes,
  terminal cleanup with downstream tasks still pending, stale-snapshot refusal,
  a writer waiting across erasure commit, and upgrade of existing erased data
  from migration 0003 to 0004. The newer runtime refuses an old migration ledger
  until the separate migrator upgrades it.
- **139** deployment/image-gate regressions passed on the owning Windows host
  in `billing-privacy-gate-regression`.
- Actual previous app image `mk-app-acceptance:scanned-runtime-v4` failed the
  new shipped-image drill at its first valid late checkout webhook: the billing
  mirror changed after deletion. Report and container log:
  `billing-privacy-image-red`. This is a real HTTP/PostgreSQL reproduction.
- Repaired image **sha256:863e8ddf88ba57ffd96d2a2e7a5e7038a520f37d5ea9c709593f2a2c2f66668b**
  passed the shipped-image drill (`billing-privacy-image-green`): all six signed
  late callbacks returned 200 while the billing mirror stayed unchanged; MFA
  and fresh-step-up gates remained effective; deleted sessions returned 401;
  receipt access remained available; pre-deletion dump/restore plus independently
  retained ledger replay removed private active data; restored billing
  reactivation was refused. Both red and green drills removed their own random
  databases, containers and networks.
- The image ran as UID/GID 65532 with a read-only root and all capabilities
  dropped. It received only a synthetic webhook secret and **no Stripe API key**.
  No external customer, subscription, credit or charge was created or deleted.
- Complete image scan: **71 components, zero findings at every severity**.
  CycloneDX inventory, full vulnerability JSON and layer/image hashes are
  retained in `billing-privacy-image-security`.
- The final readiness result remains **0/87 closed**. Billing customer and
  subscription tasks remain visibly pending, alongside the other downstream
  obligations; no provider receipt was invented from a local status value.

Provider cleanup, durable creation-race recovery, restricted holds, retention,
external custody and independent live qualification remain work items, not
claims completed by this fence patch. See the application-erasure runbook.

## Deployment-plan CI completion follow-up

PR head **7fcbee20527d92224b0f4370f17d1c0b1108db6b** passed **all 11 jobs**:
application run **39764115754** and kernel run **39764115773**. Receipts are
`deployment-plan-{app,kernel}-ci-v2.json`. The downloaded real Linux plan
control (`deployment-plan-ci-control-v2`) passed all **16 checks**. Its recorded
source `c5ec33071c55f91c9bbf40f7157fb5a1f91e45a9` is GitHub's tested PR merge
checkout; these PR checks are not a main-push deployment qualification.

The first plan-review CI for PR head `228e97b` remains a failure: the app job
failed because the provider lock was absent from source control; its kernel
workflow completed successfully. Completed receipts are retained with the
`deployment-plan-*-ci-v1-complete.json` names. The lock correction, clean-export
test and successful rerun are not substituted for that failed historical run.
