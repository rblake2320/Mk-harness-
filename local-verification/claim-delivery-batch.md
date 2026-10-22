# Claim and delivery engineering verification

Source: `9de02f4c4cfde6e011c1b282c0d76404989c051c`.
Author-run only; no independent sign-off, staging deployment or live provider
qualification is asserted. Release closure remains **0/87**.

| Scenario | Observed outcome | Evidence |
|---|---|---|
| P2 contradictory approved facts | Failed before repair: draft generated and stale draft reached proposal. Repair withholds conflicted/unannotated products before and after model await, at proposal and in edits. | p2-before.xml; p2-boundaries.xml (14 passed) |
| P2 old schema and review compatibility | Worked: additive fact table preserves legacy rows, v1 review remains callable but does not inherit v2 eligibility; strict v2 facts required. | p2-boundaries.xml |
| Windows full Python suite | Worked: 272 passed, 1 skipped (Redis binary absent). | p2-c3-c7-python-final.xml |
| Linux full backend/contract/readiness suite, including real Redis death and restart | Worked: **274 passed, zero skipped** under Python 3.12.3. | claim-delivery-linux-final.xml |
| Redis test ownership | Found unsafe fixed-port shutdown targeting an occupied port before running it. Repaired to ephemeral loopback port and owned Popen lifecycle; occupied-listener negative control and outage/recovery passed. Unrelated BPC Redis instances remained up. | claim-delivery-linux-final.xml; backend/tests/test_redis_durability.py |
| C3 exact lifecycle copy | Worked: API, SDK/UI, Rust and support/marketing references match the 15-state definitions fixture. | Python suite and Rust suite; contracts/tests/test_contracts.py |
| C4 missing callback | Worked: recorded-SID GET verified account, sender and destination, observed delivered, completed action, and created no replacement; exercised restricted mk_kernel_worker and one-connection pool. | c4-c7-rust-final.log |
| C4 lost response and signed callback recovery | Worked: unknown remains when SID absent; altered signed URL rejected; exact action/attempt callback binds SID; replay does not resend. | c4-c7-rust-final.log |
| C7 visibility and isolation | Worked: kernel queue excludes other sender owners and agent principals; app filters customer ownership and preserves pagination; 503 remains an error. | c4-c7-rust-final.log; c7-app.xml |
| Kernel regression suite | Worked: **104 tests passed**, zero failures, real PostgreSQL/Redis configured; includes real RLS role tests and 9 HTTP scenarios. | c4-c7-rust-final.log |
| Housekeeping scope | Initial suite failed because the supplied tenant subset still swept other tenants' expired leases. Scoped the SQL sweep before LIMIT; full retest passed. | c4-c7-kernel-http.log; c4-c7-kernel-http-retest.log |
| Static Rust checks | Worked: affected crates and all targets passed Clippy with warnings denied; rustfmt passed. | c4-clippy.log |
| Built web | Worked: TypeScript/Vite build; 11 automated accessibility/approval tests. This suite uses API fixtures. | c3-c7-a11y.json |
| C7 browser component | Worked: two pages of uncertainty, no generic dismiss/resend, failed refresh keeps entries plus stale warning, zero page errors, document width 360px at 360px viewport. Explicit mocked API fixtures, not a live provider test. | delivery-queue-browser.json; delivery-queue-desktop.png; delivery-queue-360.png |

`claim-delivery-manifest.json` pins retained artifact bytes. Initial failures are
retained, including a test setup error (`SessionLocal` vs `_SessionLocal`) before
the two app queue tests passed. Intermediate logs are not the final verdict.

The API/security-testing skills guided strict input/identity binding and negative
controls. The webapp-testing skill required rendering and interaction checks.

## Reproduction

Use repository-pinned Rust 1.97.0. Set MK_TEST_DATABASE_URL and MK_TEST_REDIS_URL
to disposable instances; set MK_TEST_POOL_SIZE=1. Never run fault tests against a
shared/user database. Run from rust/:

```text
cargo fmt --all --check
cargo clippy --locked -p mk-worker -p mk-api -p mk-adapters -p mk-store -p mk-contracts --all-targets -- -D warnings
cargo test --locked -p mk-adapters -p mk-api -p mk-worker -p mk-store -p mk-contracts -- --nocapture
```

The Linux Python environment used backend/requirements.txt plus PyYAML and
an unpacked Ubuntu Redis 7.0.15 binary. No host Redis service was installed.
Run from repository root:

```text
python -m pytest backend/tests contracts/tests tools/evidence/test_readiness.py -q
python -I contracts/tests/test_contracts.py
python tools/verification/delivery_queue_browser.py --output local-verification
```

This batch does not finish C4: operator step-up resolution and a kernel-side
replacement gate are the next active engineering work. C8 public probing and
the remaining matrix work continue. Deployment account/domain/spending authority,
Twilio enrollment, independent reviewers, human studies and observation windows
still require the actual external inputs; no evidence records were fabricated.
