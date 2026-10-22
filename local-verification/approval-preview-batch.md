# H1 / H8 approval preview — author-run results

Source: `3c9b45f631e4a74323ec5e284ba789ad51d6f348`, PR #37 branch.
No release row is closed by these local author-run checks.

| Check | Observed outcome | Retained artifact |
|---|---|---|
| Exact selected sender, schedule, policy lifetime, permission observation without a brief link, missing-sender refusal | Worked: 3 application tests | `h1-outreach-retest.xml`; full suite below includes the added missing-sender assertion |
| Real PostgreSQL policy flips, current self-approval display, policy change after preview, human passkey approval and agent-preview refusal | Worked | `h1-h8-kernel-final.log` |
| Full Rust workspace, real PostgreSQL/Redis, serial integration tests | Worked: 210 passed, 0 failed | `h1-h8-workspace.log` |
| Full workspace Clippy/all targets/warnings denied | Worked | `h1-h8-clippy.log` |
| Full Python backend/contracts/readiness suite | Worked: 276 passed, 0 skipped | `h1-h8-python.xml` |
| Built web accessibility and approval checks | Worked: 14 passed | `h1-h8-a11y.json` |
| Native Chromium virtual-passkey browser ceremony | Worked: two ES256 assertions verified, stale digest and UV downgrade rejected before signing, policy denial retains pending item, keyboard approval, success remains after queue refresh, 360px document width, no page errors | `h1-h8-browser/approval-browser.json`, two inspected screenshots |

`h1-sender-binding-red.xml` retains the original failure: with two owned sending
identities, the preview displayed the first number instead of the number selected
on the action. The kernel now returns the bound sender ID and schedule; the app
uses that exact ID. It never substitutes another identity when the selected one
is absent. The UI disables approval when sender details are unavailable.

`h1-h8-kernel.log` retains a test setup error: multiple policy snapshots used the
same unique version label. Each fixture snapshot now has a distinct version;
the final test toggles deny/allow/deny/allow and challenges an actual later denial.

Reproduce with the Rust/Python commands in `inbound-probes-batch.md`, then
`npm --prefix web run build`, `npm --prefix web run test:a11y`, and
`python tools/verification/approval_browser.py --output <evidence-dir>` against
the production preview on localhost:4189. Browser HTTP endpoints are explicit
fixtures, not live staging. No provider API or SMS call is made. Kernel policy
authority is exercised separately against real PostgreSQL.

H2's complete edit-to-invalidation workflow remains in the implementation queue;
the existing stale-digest browser guard is not labelled as that full workflow.
Hashes are in `approval-preview-manifest.json`.
