# S13 / O9: kernel deletion recovery evidence

Runtime source: `74cb83726932ba4231358b13777e20138b61a7f9`, draft PR37.
Author-run synthetic data on owned disposable databases and containers only.
No production traffic, real provider deletion, paid deployment or release closure.

## Reproduced failure and repair

`privacy-restore-gate-red-v3.xml` isolates the original defect: dispatch was
disabled and all eight existing checks passed, yet the actual gate returned PASS
without any independently retained post-backup deletion ledger. Earlier red
fixtures first corrected missing required API configuration and the default enabled
switch; they are retained as fixture failures, not evidence of the final scenario.

The gate now requires a bounded, fully validated ledger with independently supplied
SHA256/freshness pins. It checks all retained identities before writes, takes
tenant locks in sorted order, replays subjects/fences atomically and never enables
traffic. The separate live-inspection mode cannot authorize recovery or apply it.
Unknown/duplicate CLI flags and file overwrite are rejected. Source export requires
quiesced intake and independent external custody; a locally computed hash alone is
not that custody.

## Observed acceptance results

| Scenario | Outcome | Evidence |
|---|---|---|
| Full Rust workspace with PostgreSQL/Redis, pool one | Worked: 236 passed | `privacy-restore-workspace-v1.log` |
| All-target/all-feature Clippy | Worked: no warnings | `privacy-restore-clippy-v3.log` |
| Backend/contracts/readiness | Worked: 370 passed | `privacy-restore-app-v2.xml` |
| DB, app erasure, bridge/process and initial 15 recovery cases | Worked: 47 passed | `privacy-restore-postgres-v3.xml` |
| Final 17 recovery cases, including cross-tenant rollback and account revocation | Worked: 17 passed | `privacy-restore-recovery-v4.xml` |
| Live-inspection report parser | Worked: 17 passed | `privacy-restore-preflight-v1.xml` |
| Staged source secret scan | Worked: no leaks | `privacy-restore-source-secret-scan.json` |

The final 17 recovery cases and 32 other PostgreSQL cases total 49 distinct
integration scenarios; the final targeted run overlaps the earlier 47-case run.
The initial integration fixture used an invalid purpose label, then expected 403
instead of the actual correct 410 erasure response. Both fixture corrections and
the final green runs are retained. Clippy also caught a single-pattern match and
test-only unwrap lint; the final check is clean.

The actual dump precedes deletion. Restore brings canonical private bytes back;
report mode refuses them, apply mode erases them and restores destination fences
for a contact created after the backup. Old and new subject IDs cannot bypass the
fence. A deliberately injected SQL failure after the first deletion rolls back
content, tombstones, fences and audit writes across one or two tenants. Removing
only the injected fault lets the same pinned replay succeed. Account replay
restores PRINCIPAL_REVOKED while another user remains usable. Uncertain sends are
marked reconciliation_required, retain required resolution bytes and keep the
privacy gate failed; no fabricated completed erasure is recorded.

The old preflight regex misses failed checks in valid JSON when `detail` lies
between `check` and `ok`. The new parser tests all eight non-switch failures,
missing/duplicate records, malformed booleans and inconsistent summaries. It also
accepts the actual binary's inspection report. CI smoke now requires this check.

## Built image

Image ID: `sha256:15f2ceee933c2c20e925b79396b1694958599c29b9e8336d81a42fbc1c39ddf4`.
`privacy-restore-kernel-image-74cb837-v1/report.json` records the optimized binary
running as UID 65532 with read-only root and all capabilities dropped. The private
ledger uses an owned tmpfs, not a retained plaintext artifact. Actual pg_dump and
pg_restore reproduce the bytes; missing-ledger and unreplayed report modes fail;
apply and repeat report succeed, canonical bytes become empty, one destination
fence remains and dispatch stays false. Audit verification passes.

The same image repeats the provider crash drill: Redis unavailable, SIGKILL after
external effect, restart recovers one receipt, two DELETE attempts, zero sends,
zero authentication failures and provider backup still pending. All owned probe
databases, logins, containers and network were removed. The shared acceptance
clusters were preserved. Raw dumps, keys, credentials and ledger contents are not
included in this bundle.

## Release boundary

The readiness report remains 0/87 closed. These are branch-level author results,
not main/staging independent qualification. Still needed in this recovery lane:
complete opt-out/revocation external recovery, immutable custody/anchor delivery,
the approved staging target, independent timed recovery evidence and owner enable
authorization. Neither local replay nor elapsed time confirms provider backups.
