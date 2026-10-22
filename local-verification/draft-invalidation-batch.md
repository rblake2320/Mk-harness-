# H2 / W5 draft invalidation — author-run results

Source: `d9c46f2ebe392b45915477cb9215cf3fc0064444`, PR #37 branch.
No release row is closed by these author-run local checks.

| Scenario | Observed outcome | Retained artifact |
|---|---|---|
| Queued draft edit; old approval revocation; cancelled action dispatch; old/new idempotency keys; operator replay; new-version fresh passkey; late provider-accepted edit | Worked under restricted API DB role: old version cancelled, zero old-version provider calls; replacement remains unapproved until fresh passkey, then exactly one simulator call; late edit refused | `h2-invalidation-kernel-v6.log` |
| Concurrent intake vs edit, 16 races; human approval vs edit, 8 races | Worked: old actions refused or cancelled, no live approvals after edit, zero simulator calls | same targeted log; `h2-rust-final.log` |
| Legacy direct INSERT bypassing Rust intake helpers | Worked: invalidated version refused by DB trigger; a valid old-binary insert accepted, indexed and subsequently cancelled | same targeted log |
| Existing action backfill and runtime privileges | Worked: 1 pre-migration draft link recovered, 0 missing references; API cannot update/delete fences, worker cannot insert them | `h2-migration-readback.json` |
| Action committed between migrations 14 and 15 | Worked: isolated real Postgres upgrade reproduced 1 missing reference, migration 16 recovered it; repeat backfill retained exactly 1; disposable DB removed | `h2-rollout-upgrade.json` |
| App edit with no local ActionLink; timeout, denial, unavailable kernel, wrong-version receipt, malformed receipt, in-flight response, cross-tenant edit | Worked: no new version committed on refusal/uncertainty; no write retry; valid withdrawal permits version 2; invalid content does not withdraw the old draft | `h2-app-targeted-v2.xml` (16 passed) |
| Full Rust workspace with real Postgres/Redis | Worked: 213 passed, 0 failed, 0 ignored, exit 0 | `h2-rust-final.log` |
| Clippy all workspace targets, warnings denied | Worked | `h2-clippy-final.log` |
| Full Python backend/contracts/readiness | Worked: 277 passed, 0 skipped | `h2-python-full.xml` |
| Built web accessibility and interaction suite | Worked: 15 passed | `h2-web-tests.json` |
| Native two-tab browser, one-byte edit after approval, fresh proposal/signature, late edit refusal, Close interaction at 360px | Worked: 2 distinct ES256 assertions verified, 0 browser errors, document width 360px | `h2-browser-scroll-check/draft-edit-browser.json`; inspected screenshots in `h2-browser/` |

## Failure and escape analysis

The original edit route only created a new `DraftVersion`. That changed the new
digest but left the old queued action and its approval live. Earlier W5 tests
compared digests without attempting cancellation or dispatch of the old version.
The initial regression failed because the invalidation endpoint was absent
(`h2-invalidation-red.log`). The repaired route requires a confirmed, exact-version
kernel withdrawal receipt before committing its new version.

The sweep covered proposal idempotency, operator replay, concurrent approval,
dispatch, missing application ActionLinks, mixed-version rollout, RLS and the UI's
post-proposal editing controls. Intake and invalidation share a transaction-held
version lock; action locks serialize approval and dispatch against cancellation.
Append-only tenant-scoped fences prevent reopening. Database triggers enforce the
same boundary for older intake binaries and register references atomically with
action insertion. A provider-accepted/in-flight action is never labelled cancelled.

Intermediate failures are retained: the first implementation run omitted migration
registration (`h2-invalidation-kernel.log`); v3 expected `completed` immediately
after provider acceptance, but the actual state correctly remained `dispatching`
pending callback; the test expectation was corrected. The first Clippy run found
a collapsible condition, fixed before the final run. The first full Rust suite
passed all 213 tests, but its outer shell's expanded PIPESTATUS check failed;
the final independent command uses pipefail and exits 0. A first native-browser
fixture omitted commitment `kind`, causing the brief render to fail; its corrected
fixture passes. The extra Close control was tested because it fell below the
initial screenshot; it passed without a CSS change.

The browser HTTP state is explicitly synthetic; native Chromium generates real
virtual-authenticator signatures. App boundary tests use mocked kernel replies;
Rust tests use real PostgreSQL, Redis and the HTTP provider simulator. None is a
live Twilio SMS or an independent staging release record. Qualifying staging
verification remains blocked on designated environment/domain/spending authority
and an independent verifier; no YAML closure record was fabricated.

Reproduction: workspace Rust test/Clippy commands from `inbound-probes-batch.md`,
the full Python suite, `npm --prefix web run build`, `npm --prefix web run test:a11y`,
and the native-browser/upgrade commands in `tools/verification/README.md`.
Artifact hashes are in `draft-invalidation-manifest.json`.
