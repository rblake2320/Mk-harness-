# Billing provisioning, cleanup and Tokio advisory follow-up

Source: `5fb0ec35511a11f53b63a45f5ff04d82d167c4bd` (billing), including
`6f0e7e2d1a64bc53f98e89824e64908a443bce96` (Tokio). Author-run controls,
2026-10-22. No external billing customer, subscription or charge was changed.
No independent release YAML was created. Readiness remains 0/87 closed.

## Worked

- 440 application/contract/readiness/image-policy tests:
  `billing-provision-full-green-v2.{log,xml}`.
- 116 targeted billing/privacy/security tests, including metadata binding,
  in-flight account deletion, identical creation retry bytes/key, expired-key
  read-only recovery and refusal of missing/ambiguous/deleted search results:
  `billing-provision-targeted-green-v2.{log,xml}`.
- 67 PostgreSQL/cross-service integration tests:
  `billing-provision-pg-full-green-v2.{log,xml}`. Restricted SQL cannot rewrite
  provision identity/time or a bound customer, delete an intent, or insert after
  erasure. Concurrent insert waits for deletion then refuses. The old 0003 schema
  upgrades through additive 0004/0005 without rewriting old migrations. Explicit
  adoption remains supported and validated.
- Real HTTP/process crash control in `test_app_billing_privacy.py`: kill the
  delivery process after the simulated provider deletes the customer but before
  its response. PostgreSQL retains a pending leased task. Restart confirms by
  authenticated tombstone readback: **one DELETE, two GETs, zero creates**, two
  attempts and one confirmed task. This also runs in mandatory PostgreSQL CI.
- 139 deployment/image-policy regression tests:
  `billing-provision-gates-green.{log,xml}`. Staged source secret scan: zero leaks.
- Final application image `mk-app-acceptance:billing-provision-v3`, image ID
  `sha256:c73eb7360758d70a0ff5eebe94edaabe5c94681e9fa03fa813487cbfb30390ad`,
  passed actual HTTP/MFA, restart, deletion, six signed late billing callbacks,
  real pg_dump/restore and separately pinned erasure replay, audit/log canary
  checks and owned-target cleanup (`billing-provision-image-green/report.json`).
  This image drill supplies no Stripe API key; provider cleanup is separately
  exercised at the intercepted HTTP boundary and by the process fixture.
- Final application image scan: 71 components, zero findings at every severity;
  full vulnerability report and CycloneDX SBOM in
  `billing-provision-image-security-v3/`. The earlier v1/v2 images/scans are
  retained as intermediate verification equipment, not the final source image.
- Tokio 1.54.1: all 236 Rust tests passed with the original locked dependency
  edges preserved (`tokio-regression-green-v3.log`). The crate download SHA-256
  matches Cargo.lock: `b52fd3255258d26fac7264ab5a76b53c13367136dc011d3d6ad4f8ed070396a3`.
  Final kernel image `mk-kernel-acceptance:tokio-patched`, image ID
  `sha256:57914862e1b88af0ad7f3efabfc49c987b0170dd0d3e47a3ef09518ae2ce3aa0`,
  has zero HIGH/CRITICAL findings (23 MEDIUM, 8 LOW); full report/SBOM retained in
  `tokio-image-security/`. Dependency-level advisory enforcement is separately
  checked by CI cargo-deny/audit, not inferred from the runtime OS scan.
- Patched kernel image runtime drill passed actual dump/restore, missing/future
  ledger refusals and valid replay with dispatch disabled; provider recovery with
  Redis unavailable survived SIGKILL and recovered one active receipt with two
  DELETE attempts, zero sends and backup still pending. All eight audit events,
  metrics and logs were free of synthetic private canaries. Owned targets were
  removed (`tokio-kernel-image-green-v2/report.json`).
- Tokio source 6f0e7e2 passed all 11 PR CI jobs: app run 39768007775 and kernel
  run 39768007783, including cargo-deny/audit, image scans and isolated live
  smoke. Final receipts are `tokio-{app,kernel}-ci-v2.json`. These checks precede
  the billing source 5fb0ec3 and do not certify that subsequent source.

## Observed failures and repairs

- Original billing creation race failed both response-received and response-lost
  cases: there was no committed intent before provider acceptance
  (`billing-provision-red.{log,xml}`). The new immutable provision is committed
  first, and erasure queues it even before the customer ID is known. Both cases
  now create zero checkout sessions after deletion.
- First PostgreSQL attempt rejected model/SQL unique-constraint drift; its old
  erasure fixture also omitted required anonymization fields. Both fixtures and
  the new migration were corrected, without weakening runtime schema validation
  (`billing-provision-pg-green-v1`, then passing v2/process/full-v2).
- The first broader PostgreSQL run found duplicate-table failure during explicit
  public-schema adoption. The new unapplied migration now adopts the existing
  table and still installs/validates its guards. Retained first full run: 65 pass,
  1 failure; corrected full run: 67 pass.
- Previous PR head f55def3 app CI passed (39765826063), but kernel CI
  39765826040 correctly failed the newly published RUSTSEC-2026-0384 Tokio
  interval race. The gate was not waived. See retained `tokio-advisory-red.log`
  and the upstream [repair](https://github.com/tokio-rs/tokio/pull/8692).
- Local cargo-deny was unavailable; the first offline test lacked the patched
  crate, and direct WSL download timed out. A Windows download from the official
  crate host matched the locked checksum, then the complete offline Rust suite
  passed. These failed attempts remain in the corresponding logs. CI supplies
  the installed advisory tools.
- First kernel-image drill invocation lacked its required disposable-cluster
  DSN and stopped before database/provider work; its log is retained. The
  corrected invocation uses the labelled owned cluster and a separate output.

## Boundaries retained by implementation

Creation sends only opaque ownership metadata; Checkout collects email. Retry
POSTs stop at 23 hours, before Stripe's documented >=24-hour key expiry. Older
intents use read-only search plus exact GET; an empty search never confirms
absence. Cleanup validates the immutable account/provision association, validates
live provider metadata, persists the customer ID before DELETE, and requires
exact deleted readback. A subscription task requires exact customer-bound GET
showing canceled; no separate refund/invoice/proration mutation is introduced.
Provider errors are closed codes, not retained response content.

Legacy provider references without creation ownership proof are blocked without
HTTP. Simulator receipt success is not real-provider or legal-retention approval.
Sender cleanup, backup retention, restricted holds, external custody and the
independent staging/production requirements remain tracked in S13/O9 and the
acceptance matrix. Do not change their release status based on this batch.

Follow-up acceptance tests immediately after this source pin reproduced two
restore gaps: an intent created after the backup disappears, and an intent in
the backup loses a customer ID accepted later. The tombstone-only v1 ledger does
not preserve these external obligations. `billing-restore-red.{log,xml}` retains
both failures; repair is the next O9/S13 batch. The 440-pass result above applies
to the recorded source pin and does not include these subsequently added tests.
