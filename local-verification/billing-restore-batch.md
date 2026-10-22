# Post-backup billing obligation recovery

Source `1294e98b9f1fbdbaf9e73d9ea7323794c9265349`, 2026-10-22.
Author-run tests on disposable databases and local images; no real provider
request or independently verified release evidence. S13/O9 remain unclosed.

## Failed, repaired, retested

The preceding billing source persisted creation correctly in the active database,
but its v1 erasure ledger carried only account/customer tombstones. Both new
acceptance cases failed (`billing-restore-red.{log,xml}`): restoring an earlier
backup lost either the entire billing intent or its later accepted customer ID.

Ledger v2 now carries opaque creation identity/time and the known provider ID.
Replay validates ownership, timestamps, duplicate IDs and conflicts before
applying cleanup-only bindings. It never creates an active business intent,
tenant or user. The new additive migration binds recovered rows to immutable
account tombstones and prevents owner/time/customer rebinding or deletion. An
unknown provider ID may be filled once after validated recovery.

V1 ledgers are refused rather than treated as complete external-obligation
records. Operators must quiesce intake, billing creation and cleanup workers,
then export and independently retain a fresh v2 ledger/hash/freshness bound.
This is an explicit format transition, not backward-compatible proof of old
ledger completeness. No old applied migration was edited.

## Worked

- 451 application, contract, readiness and image-policy tests:
  `billing-restore-full-green.{log,xml}`.
- 68 PostgreSQL/cross-service integration tests:
  `billing-restore-pg-full-green.{log,xml}`. This includes the original creation
  and erasure fences, historical-schema upgrade, explicit adoption, process
  crash recovery, and new immutable cleanup-binding SQL controls.
- 43 targeted restore/provider tests (`billing-restore-green-v2`): backups before
  the intent, before provider acceptance, and before the entire account exists;
  preview makes no binding, repeated replay is idempotent, and readback of the
  exact previously deleted customer confirms cleanup with one GET and no POST
  or DELETE. Re-export preserves the recovered binding.
- Negative controls refuse v1, crossed tenant/user, future creation time,
  malformed provider paths, extra content fields and duplicate intent/customer
  IDs. Prior provider controls retain stale-lease and false-success refusals.
- 139 release/image-gate regressions (`billing-restore-gates-green`). Staged
  source secret scan found no leaks.
- Final image `mk-app-acceptance:billing-restore-v2`:
  `sha256:e978bb19186824391888a5e5f8a6f3da867646bc1124ec6e4db7753f60677f8c`.
  Actual HTTP/MFA, restart, deletion, late billing callbacks and audit/log
  canaries passed. The new `--billing-restore` drill takes a real pg_dump,
  records a synthetic accepted billing identity afterward, deletes, exports,
  restores, and replays twice. The exact binding and one pending task survive;
  no business intent is recreated. All owned targets were removed. See
  `billing-restore-image-green-v2/report.json`.
- Final image scan: 71 components; zero findings at every severity. Full report
  and CycloneDX SBOM: `billing-restore-image-security-v2/`. The first image and
  scan are retained; the final image also includes the updated quiescence comment.

The preceding billing/Tokio source at PR head
`c31235645d515269430ced72914abf4e369badad` passed all 11 CI jobs: app 39769297994,
kernel 39769297948. Full receipts are `billing-provision-{app,kernel}-ci-v1.json`.
These runs precede this ledger repair; subsequent CI must be tracked separately.

This batch repairs the observed billing-obligation loss. General opt-out and
revocation recovery, sender-resource cleanup, independent custody/retention and
staging/production qualification remain separate tracked work; no row was
closed on the strength of these author-run controls.
