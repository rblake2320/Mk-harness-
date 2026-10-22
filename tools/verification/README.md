# Local customer-search browser check

This is author-run development verification, not release-row closure. It creates
two synthetic tenants and 53 customers through a real FastAPI server, then uses
the production web build. Only the API transport URL is redirected; responses
are not mocked. It does not invoke a model or messaging provider.

Install backend requirements and Python Playwright in an isolated virtual
environment, then install Chromium with that interpreter:
`python -m playwright install chromium`. Build the web app with `npm run build`.

Start the API on loopback port 8019 with a disposable SQLite database,
fresh process-local JWT_SECRET and base64-encoded 32-byte MASTER_KEY,
and CORS_ORIGINS=http://127.0.0.1:4189. Do not use a production database,
provider credentials or an existing .env. The API command is:

```text
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8019
```

Run the command from a directory with no .env (adjust --app-dir to the checkout's
absolute backend path when necessary). From web/, start the built preview:

```text
npx vite preview --host 127.0.0.1 --port 4189 --strictPort
```

Then, from the repository root:

```text
python tools/verification/customer_search_browser.py --output local-verification
```

Checks: tenant exclusion, 50+2 pagination, literal exact-result lookup, empty
results, clearing search, request-body search terms, and visible customer
Open/Edit/Delete controls inside a 360px viewport. Outputs: search-browser.json,
search-desktop.png and search-360.png. Tokens are neither printed nor saved.
Keep the disposable database out of version control and stop the two owned
servers after the check. Do not treat this check as full mobile-app parity or a
manual screen-reader review.

## Uncertain-delivery browser component

With the production web preview running on port 4189:

```text
python tools/verification/delivery_queue_browser.py --output local-verification
```

This uses explicit API fixtures (not the live kernel) and native Python Playwright.
It checks pagination, visible uncertainty, no resend/dismiss, fail-visible refresh,
and 360px layout. The real PostgreSQL/provider-simulator path is tested separately
by `mk-api::http_e2e`; do not present the fixture browser check as a live-provider run.

## Approval and resolution passkeys

Against the same built preview, run:

```text
python tools/verification/approval_browser.py --output local-verification/h1-h8-browser
python tools/verification/draft_edit_browser.py --output local-verification/h2-browser
python tools/verification/submission_resolution_browser.py --output local-verification/c4-browser
```

These native Python Playwright checks install ephemeral Chromium virtual
authenticators and cryptographically verify their ES256 assertions. HTTP data
is explicitly synthetic. The approval check covers selected sender/schedule,
self-approval refusal, stale digest, UV downgrade, keyboard approval, persistent
feedback and a 360px viewport. The kernel's real-Postgres tests separately enforce
policy and passkey authority. None of these scripts sends to a real provider.

The draft-edit check keeps the editor open in one tab while approving in another,
then changes one byte, confirms old-version withdrawal, proposes the new version
and verifies its distinct passkey assertion. It also checks a refused late edit
and that Close remains reachable at 360px. Its HTTP state is explicitly a fixture;
the kernel suite tests actual transaction serialization, role isolation and sends.

Deploy migrations `0014_draft_invalidation.sql` through `0016_draft_rollout_backfill.sql`
with the new kernel before the application edit route. They backfill draft/action
references from existing canonical requests and enforce fences at database insert
even for an older intake binary during rollout. Do not drop these guards during
rollback; use the kill switch and a roll-forward repair. A lost withdrawal response leaves the application
version unchanged; repeating withdrawal is safe and never reopens a fence.
The final backfill covers old-binary inserts that committed between migration 14
and installation of the insert guard in migration 15.
