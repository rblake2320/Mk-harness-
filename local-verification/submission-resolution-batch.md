# C4 submission resolution — author-run results

Source: `7c51785131f99b068bf90a315e9851a8fd1c6da1`, PR #37 branch.
This is local engineering verification, not independent staging or production
evidence. No release row is closed by this report.

| Check | Observed outcome | Retained artifact |
|---|---|---|
| Full Rust workspace, real PostgreSQL 16 + Redis 7, one-connection API/worker pools, serial integration tests | Worked: 208 passed, 0 failed | `c4-resolution-workspace.log` |
| Full workspace Clippy, all targets, warnings denied | Worked | `c4-resolution-clippy.log` |
| Python backend + contract + readiness suites, Python 3.12, actual owned Redis process outage/recovery | Worked: 276 passed, 0 skipped | `c4-resolution-python.xml` |
| Proxy and owner/admin uncertainty queue checks | Worked: 4 passed | `c4-resolution-app.xml` |
| Built-web accessibility/approval suite | Worked: 11 passed | `c4-resolution-a11y.json` |
| Browser operator ceremony with native Python Playwright and Chromium virtual authenticator | Worked: 2 real ES256 assertions verified; user presence/verification set; stale evidence rejected before signing; kernel rejection retained exception; success sent nothing; width 360/360; 0 page errors | `c4-browser/resolution-browser.json`, `resolution-360.png` |

The C4 real-Postgres test exercises the restricted `mk_kernel_api` role, not an
owner bypass. It checks unknown/no-ID refusal, destination overlap across key
rotation, other-destination isolation, new-action replacement deferral without
consuming approval, role denial, changed provider evidence, bad signatures,
challenge replay/transplant, immutable resolutions, preserved terminal action
history, read status remaining unknown, no automatic send, and terminal-failure
permission producing only an unapproved replay draft. The existing reconciliation
test also runs the restricted worker role with one pooled connection.

## Failures retained and repaired

- `c4-resolution-stale-approval-red.log`: the first design released an already
  queued replacement after resolution. The repair serializes resolution with
  destination dispatch and requires approval newer than the resolution. The
  10-test HTTP retest and full workspace run pass with that assertion retained.
- `c4-resolution-http.log`: unrestricted concurrent Rust test threads raced the
  suite's global kill-switch test (9 passed, 1 blocked by `dispatch_disabled`).
  The repository already serializes shared-infrastructure tests in nextest.
  `c4-resolution-http-serial.log` uses the equivalent `--test-threads=1`: 10 passed.
- GitHub CI at `84ea979` failed a privacy assertion searching raw metrics for
  `0100`, a substring possible in a histogram timing value. The repaired check
  tests actual raw/normalized phone values and identifier-bearing labels, while
  retaining tenant/action ID rejection. Full workspace HTTP tests pass.
- `c4-resolution-first.log` records an earlier pass before the new stale-approval
  negative control was added; it is not the final acceptance result.

## Reproduction

Rust 1.97.0, Ubuntu-24.04 WSL, `CARGO_HTTP_MULTIPLEXING=false`, target cache
`/tmp/mk-release-acceptance-target`; dedicated loopback PostgreSQL at 5547 and
Redis at 6397. Fresh database `mk_resolution_test`, all 12 migrations. Run:

```
cargo test --locked --workspace -- --nocapture --test-threads=1
cargo clippy --locked --workspace --all-targets -- -D warnings
python -m pytest backend/tests contracts/tests tools/evidence/test_readiness.py -q
npm --prefix web run build
npm --prefix web run test:a11y
python tools/verification/submission_resolution_browser.py --output <evidence-dir>
```

Use `MK_TEST_DATABASE_URL`, `MK_TEST_REDIS_URL`, `MK_TEST_POOL_SIZE=1` for the
isolated test services. Browser verification uses the built Vite preview at
`http://localhost:4189` and explicit synthetic API fixtures; it contacts no real
provider or recipient. SHA-256 hashes are in `submission-resolution-manifest.json`.
