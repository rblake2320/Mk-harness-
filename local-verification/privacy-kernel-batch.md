# S13 kernel bridge: retained author-run evidence

Source: `8578864cf47bec42af4a8308822a678bf097e374`, draft PR37. Synthetic fixtures,
owned disposable PostgreSQL/Redis and containers only. No external sends or paid
deployment. This is implementation verification; S13 remains open.

## Observed failures and repairs

- **Failed:** the erasure route initially returned 404 (`privacy-kernel-red.log`).
  Added the narrowly scoped privacy service role, immutable subject requests,
  exclusive tenant transaction and canonical-content scrubbing.
- **Failed:** an authenticated late delivery callback returned 410 after erasure
  (`privacy-kernel-late-receipt-red.log`). Repaired both the early store lookup and
  callback fold; the late receipt now persists redacted metadata and returns 200.
- **Failed:** uppercase compact contact UUIDs survived deletion while the bridge
  reported success (`privacy-bridge-identity-red.xml`). Canonical UUID parsing is
  now shared by action matching and database fencing. All four UUID spellings
  pass the real application-runtime to kernel-runtime integration test.
- Retained intermediate logs include a test import error, an intentionally invalid
  purpose fixture corrected to match the contract, and lint errors repaired before
  the final full run. These are not counted as passing scenarios.

## Final verification

| Check | Result | Artifact |
|---|---|---|
| Full Rust workspace with PostgreSQL/Redis | 223 passed | `privacy-kernel-workspace-v2.log` |
| All-target/all-feature clippy | Clean | `privacy-kernel-clippy-v4.log` |
| Python backend/contracts/readiness | 351 passed | `privacy-kernel-app-v2.xml` |
| PostgreSQL boundary/erasure/cross-service | 31 passed | `privacy-kernel-postgres-v1.xml` |
| Final UUID and metadata canaries | Four passed | `privacy-bridge-v4.xml` |
| GitHub application CI | All four jobs succeeded at source pin | `privacy-kernel-ci-app-8578864.json` |
| GitHub kernel CI | All six jobs succeeded at source pin | `privacy-kernel-ci-rust-8578864.json` |

Kernel image `sha256:c38e52fd75a19db946922acad6ef2a0c6372072499f969441df0a6c368ab3dd7`
ran as 65532 with a read-only root, all capabilities dropped, and a restricted
database login. Real signed HTTP erased the canonical bytes; read and re-intake
returned 410 and cross-route service access returned 403. See
`privacy-kernel-image-8578864/report.json` and the reproducible
`tools/verification/kernel_privacy_image.py` helper retained with this bundle.

App image `sha256:b718c0c34485295b88e812037136895b8e59201ce78a95d35ac9559db7e1c309`
passed actual MFA, customer/export, restart, account deletion, receipt download and
restore-ledger replay through PostgreSQL. Its real browser render cleared auth,
showed pending downstream work, had no console errors and no 360px overflow.
The fresh 360px screenshot was visually inspected. See
`privacy-kernel-app-image-8578864/report.json` and retained PNGs.

Both image drills removed their own recorded containers, networks, databases and
logins. No raw private receipt token, backup body, generated signing key or provider
credential is retained. Images and the task-owned shared test clusters remain.

## Acceptance status

The readiness checker reports **0/87 closed; NOT READY** in
`privacy-kernel-readiness.json`. Kernel erasure preserves uncertain submissions
for reconciliation and reports sender/provider cleanup explicitly pending. Provider
consumption, vendor backups, holds, retention, protected recovery anchors, independent
staging and production qualification remain separate work. No release YAML or
independent verification claim was fabricated. Source is on PR37, not main.
