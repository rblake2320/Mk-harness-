# MK acceptance engineering: local verification, 2026-10-21

Release verdict: **NOT READY; 0/87 rows closed.**

PR #36 was merged to main at `80e08d0ab9e9f149e0c365d29b60a6311f26f7df`.
The follow-up source is `4f103085252c34073b4480482c5c485a992bbd22` on
`codex/mk-release-acceptance-20261021`. These are author-run Windows results
against that working tree, subsequently committed at the named source revision.
They are not signed independent staging records, container qualification, or
production observations. No release-row YAML was created or upgraded.

## Changes and observed outcomes

| Scenario | Outcome | Retained evidence |
|---|---|---|
| F2: ordinary, YES, date-request and injected inbound replies with absent, revoked or suppressed consent; replay each | Worked: 12 cases create no consent, call no permission-grant endpoint and lift no suppression | backend-final.xml; backend/tests/test_inbound.py |
| W7: suppression before/after brief generation and STOP/hold/product-concern processing | Original tests failed: existing brief kept active permission and approval controls. Repair mirrors confirmed kernel suppression, revokes active local consent for permanent stops and refreshes permission on read. Retests retain source, show blocked outreach and hide approval | backend-final.xml; backend/tests/test_commitments_brief.py and test_inbound.py |
| F7/S11: bounded search with tenant and owner predicates, literal percent/underscore, injection string, phone/email, pagination and invalid input | Worked: all 7 search tests passed | backend-final.xml; backend/tests/test_customer_search.py |
| Production web build, actual FastAPI and isolated SQLite | Worked: 52 own customers, 1 excluded foreign customer, 50+2 pagination, exact/empty/clear search; 4 POST searches with terms in request bodies; 0 browser errors | search-browser.json; search-desktop.png |
| Customer list at 360px | Initial rendering clipped action controls. Stacked-card repair passed: document width 360px and Open/Edit/Delete control bounds inside viewport | search-360.png; search-browser.json |
| C5 direct CI contract entrypoint | Original runner executed only 4 tests because two definitions followed the runner. Moved runner to the end; all 6 now execute. Invalid inbound dates also exposed missing optional format dependencies; declared jsonschema[format] and retained negative controls | contracts/tests/test_contracts.py; contract-readiness.xml |
| Complete backend suite | Worked after repair: 239 passed; 1 skipped | backend-final.xml |
| Initial full backend run | Failed: 237 passed, 2 UTF-8 decoding failures, 1 skipped. Explicit UTF-8 reads repaired both; targeted rerun 2 passed before final full suite | backend-tests.xml; backend-utf8-retest.xml |
| Redis durability test | Blocked locally: test skipped because redis-server binary is unavailable; this scenario was not executed in this Windows run | backend-final.xml skip reason |
| Contract/readiness/economics suite | Worked: 21 passed | contract-readiness.xml |
| Built-web automated accessibility/approval/brief suite | Worked: 11 passed; includes absent/suppressed brief controls. API fixtures and authenticator are mocked in this suite | a11y.json |
| Evidence checker | Worked for the existing example only: 1 record, 0 problems. evidence/releases contains schema, README and _example/H7.yaml, not a release evidence package | tools/evidence/check.py invocation |
| Release readiness | Expected refusal: exit 1, NOT READY, 87 rows, 0 closed; cp1252 console regression also passes | readiness.json; contract-readiness.xml |

The code-review skill guided inspection of the real entrypoints and regressions;
the webapp-testing skill required built-page inspection. That inspection exposed
and led to the 360px customer-action repair.

## Commands and environment

Python 3.13.5 in .venv, backend/requirements.txt plus pytest, PyYAML and
Playwright; local SQLite. Web build: `npm run build` (TypeScript + Vite passed).

```text
# repository root, using .venv Python
python -m pytest tools/evidence contracts/tests tools/release -q --junitxml=local-verification/contract-readiness.xml
python -I contracts/tests/test_contracts.py
python -I tools/evidence/check.py
python -I tools/evidence/readiness.py --json
python tools/verification/customer_search_browser.py --output local-verification
# backend/
python -m pytest tests -q --tb=short --junitxml=../local-verification/backend-final.xml
# web/
npm run build
npm run test:a11y
```

The project Playwright 1.49.1 initially failed before test execution because its
pinned Chromium binary was missing. Its installer stalled after download and was
stopped without deleting caches. The successful 11-test run used the existing
PW_CHROMIUM_PATH override with Chromium build 1248. Python Playwright used its
installed Chromium. The Windows with_server helper initially failed to launch
the path; explicit foreground servers on loopback 8019/4189 succeeded.
See tools/verification/README.md for the real-API browser setup. Synthetic test
databases and process-local keys/tokens are excluded from the committed artifacts.

## Remaining release work

This is one engineering batch, not completion of the owner's 87-row request.
Remaining engineering is listed in matrix section 11 and the individual cells.
No AWS infrastructure was applied. Read-only AWS authentication succeeded, but
designated separate staging/production accounts,
domain and spending ceiling are awaiting owner input. Twilio onboarding, legal
decisions, named operators, independent verification/reviews, human studies,
real annotated/live-model evaluations and production measurement windows remain
outstanding. O2/O3/O4 still require actual production observation records.
