# S8: actual-image dependency repair, inventories and strict CI gates

Production-source commit: `3eb97ab3f09067397acaf8bee2f8712b7189e9b5` on draft
PR37. Verification-only clock-cutoff adjustment/runbook clarification:
`fbe016b2f81d5317d8547c65a2eea7f155497500`. No release evidence YAML or row closure is claimed.

## Observed scan outcomes

Every scan used the official Trivy 0.76.0 image, digest
`sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222`.
The vulnerability database was downloaded on 2026-10-22 (database update
2026-10-22T07:10:52Z). No Docker socket was exposed to the scanner. All severities
and intermediate failed candidates are retained, not suppressed.

| Runtime | Before | Accepted candidate | Complete inventory and report |
|---|---|---|---|
| Web | 211 findings: 2 critical, 57 high, 100 medium, 46 low, 6 unknown | 0 findings | `web-runtime-security/` |
| Application | OS: 167 findings, including 44 high; Python packages: 86 findings, including 4 critical and 43 high | 0 findings | `app-runtime-security-v4/` |
| Kernel | 50 findings, including 1 high | 23 medium, 8 low, zero high/critical/unknown | `kernel-runtime-security-v2/` |

These are scanner findings for these artifacts and this database snapshot, not a
claim that every vulnerability is discoverable. The kernel's lower-severity
findings remain visible in the full report; no risk acceptance was fabricated.

Accepted local image identities:

- Web: `sha256:fd2bf3c793bcf1ccb5ed980c779e656c27a218a5ff09d1538f18568096abdbbf`.
- Application: `sha256:66d99c7d99f27b976cc43913123eee352b3d21d5641a76a10111d39290a6a87c`.
- Kernel: `sha256:67ce89f6dbd9a4de9b6b994bc4f656b736d4356ad0687880128b772042eadb08`.

Each security summary also records the scanned image-config digest, exact
filesystem layers, archive hash, report hash and CycloneDX hash. The scanner
helper refuses a substituted filesystem or missing inventory. CI now fails any
high/critical finding, including an unfixed one, for all three runtime images.

## Repairs and tests

The web runtime moved from Nginx 1.27/Alpine 3.21 to digest-pinned Nginx
1.30.6/Alpine 3.24 slim. Its built-image SPA 200, unavailable-upstream 502,
malformed-method 400 and four sanitized access events passed without canary leaks.
The separate `web-dependency-batch.md` records 29 passing browser tests and all ten
CI jobs for the preceding locked npm update.

The application now uses full transitive hash locks, a runtime/test dependency
split, and a pinned Python 3.13.17 Alpine runtime with binary musl wheels. Actual
image inspection confirmed pip, pytest and respx absent; the application's native
libraries remain importable. An intermediate Debian/distroless candidate still
had 26 high findings and was rejected. Its successful functional drill was not
used to waive those scanner failures.

Updating FastAPI exposed an MFA bypass: `scope['route'].path` no longer included
router prefixes. The existing exhaustive security tests caught it. Registered
route-context resolution now fails closed for unmatched/ambiguous identity and
is tested with nested/reused routers and a deployment root path. No raw caller
path becomes a policy key. Initial source regressions had five failures;
the repaired run passed **398 Python/contract/readiness/scanner tests**. Both
the original failures and final JUnit/logs are retained. PostgreSQL function
fixtures also needed an explicit synthetic JWT key after PyJWT began refusing
empty keys; production already refuses missing secrets at startup. The repaired
full PostgreSQL/integration run passed **60 tests**.

The accepted application image passed real runtime-role migrations, MFA/step-up,
HTTP customer operations, restart, deletion, authenticated deletion receipts,
actual pre-deletion dump/restore and ledger replay, and URL/log privacy canaries
as UID 65532 with a read-only filesystem and all capabilities dropped.

The accepted kernel image passed actual restore and provider-recovery drills:
old content returned on pg_restore, replay erased it with dispatch still disabled;
Redis remained unavailable, the worker was SIGKILLed after the provider-side
effect, restart recovered the lease with two delete attempts, zero sends and one
active-deletion receipt. Provider backup retention remained explicitly pending.
Eight audit events, metrics and logs were checked for synthetic private canaries.

## Restore-clock diagnosis (verification equipment)

Initial kernel image attempts v2/v3 refused the external ledger at the generic
restore gate. Retained operator diagnostics were added. Attempt v4 tried Docker
copy from the tmpfs and failed; v5's diagnostic ran against the original database
while dispatch was enabled and correctly refused. Neither is a successful
restore. Attempts v6/v7/v8 passed, exposing an intermittent timing condition.

The first clock measurement used an unsupported BusyBox nanosecond format and is
invalid (`kernel-runtime-clock-check.json`). The corrected PostgreSQL timestamp
measurement (`...-v2.json`) bounded Docker behind the host by approximately
0.70–1.02 seconds. Subsequent observations also showed clock movement. A host
cutoff could therefore be later than the export it was meant to precede.

The fixture now records the ORIGINAL live database's UTC before export, retaining
that cutoff independently across restore. It never derives a cutoff from the
restored database or weakens production freshness checks. Final v9/v10 drills
passed; v10 also deliberately supplied a future cutoff and observed a freshness
refusal before using the valid pin. Recovery-command diagnostics are retained
without raw ledger contents or credentials. All owned containers, networks,
databases and roles created by each drill were removed.

Workflow lint and staged-source secret scans passed. Exact-source CI for
`3eb97ab` passed Python 3.12/3.13, PostgreSQL integration and browser jobs, but
the image-scanner job failed. Retained CI logs/artifacts show Linux bind-directory
permission denial: the capability-dropped scanner was root while the cache was
owned by the runner. The scanner now uses the actual Linux UID/GID and an explicit
`/cache` mount instead of root's private home. Nine targeted scanner tests and a
new actual-image scan passed. Scanner correction source:
`7cdedb00362ab04d7880d69870be995520cbf041`; the corrected full CI run is retained
when completed.
The artifact secret scan flagged six occurrences of the official Python public
release-signing fingerprint in full image metadata. The exact public fingerprint
was checked against the upstream Dockerfiles and narrowly excluded by value;
no artifact paths or private source directories were excluded. A synthetic
different API key remained detectable in the negative-control scan.
Independent staging verification, signed release publication and main-branch
qualification remain required; these author-run artifacts do not close S8.
