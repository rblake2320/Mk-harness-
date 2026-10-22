# C8 public inbound probes — author-run results

Source: `7e469cab02e4db789e0fd6c5efaa544b5af4efd4`, PR #37 branch.
Local engineering verification only. No release row is closed by this report.

| Check | Observed outcome | Retained artifact |
|---|---|---|
| Full Rust workspace; real PostgreSQL 16 / Redis 7; serial integration tests | Worked: 209 passed, 0 failed | `c8-final-workspace.log` |
| Clippy, full workspace/all targets, warnings denied | Worked | `c8-final-clippy.log` |
| Python backend, contracts and readiness suite | Worked: 276 passed, 0 skipped | `c8-python-retest.xml` |
| Real public-route loopback HTTP, restricted API/worker roles and one-connection pools | Worked: fake 200 without receipt, bad signature, redirect and replay refused; all active senders required; monitor silence blocks; recovery waits for pending event processing; non-human backlog access refused | `c8-probes-fleet-final.log`, `c8-final-workspace.log` |
| 1,000-business probe fleet plus one broken-key tenant | Worked: 1,000 checked / confirmed, 0 failed; one isolated tenant error; 17,881 ms targeted run, 17,746 ms full-suite repeat | same logs |
| OpenTofu 1.10.6, isolated complete module layout, signed AWS/random providers | Worked: configuration valid, 0 errors / warnings; no plan or apply | `c8-tofu-validate-final.json`, `c8-tofu-init-layout.log` |

The fleet is a bounded probe subsystem check, not the O2/O4 production load soak.
Clock aging is injected only into isolated test health rows. The route uses real
HTTP and committed PostgreSQL receipts; there is no provider API call or SMS.
The worker shares a 32-request bound, schedules 16 tenants concurrently, and
claims at most 32 senders per tenant. Tests assert a cycle under 45 seconds plus
the 15-second schedule delay. Live DNS/TLS and deployed ingress remain part of
the independent staging qualification, which requires the designated environment.

## Failures retained and repaired

- `c8-backlog-authorization-red.log`: an agent could mark an event processed
  (204), bypassing the backlog recovery condition. The API now requires an
  explicit consultant, manager or tenant-admin role for read and processing;
  mixed agent/unknown and empty-role cases are also retained in the test.
- `c8-probes-fleet.log`: the negative test initially expected 403 for an empty
  role list, but authentication correctly returned 401 before route execution.
  The expectation was narrowed to that existing authentication contract.
- `c8-final-python.xml`: 275 passed, one golden brief failed because fixed
  October 20 expectations were combined with real-clock relative windows.
  The test now fixes only the commitment-domain clock, not authentication.
  `c8-clock-retest.xml` records 10 passing targeted tests; the full rerun passes.
- Earlier Clippy output records two style errors, repaired before the final
  workspace check. Earlier probe logs are retained as intermediate runs.
- OpenTofu initialization hit WSL registry timeouts, missing read-only lock
  files and an incomplete copied module layout. The final isolated copy includes
  its relative observability input and initialized, signature-checked providers.
  No cloud resource or backend state was touched.

## Reproduction

Rust 1.97.0, Ubuntu-24.04 WSL, PostgreSQL 16 at loopback 5547 (`mk_resolution_test`,
13 migrations) and Redis 7 at loopback 6397. Set `MK_TEST_DATABASE_URL`,
`MK_TEST_REDIS_URL`, `MK_TEST_POOL_SIZE=1`, `CARGO_HTTP_MULTIPLEXING=false`:

```
cargo test --locked --workspace -- --nocapture --test-threads=1
cargo clippy --locked --workspace --all-targets -- -D warnings
python -m pytest backend/tests contracts/tests tools/evidence/test_readiness.py -q
```

The three edited local stack scripts pass `bash -n`; the modified Terraform file
passes `tofu fmt -check`. Script runtime acceptance is tracked by the subsequent
GitHub full-application smoke run. Do not run destructive reset/fault scripts
against shared services. Artifact hashes: `inbound-probes-manifest.json`.
