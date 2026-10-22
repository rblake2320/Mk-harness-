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
python tools/verification/submission_resolution_browser.py --output local-verification/c4-browser
```

These native Python Playwright checks install ephemeral Chromium virtual
authenticators and cryptographically verify their ES256 assertions. HTTP data
is explicitly synthetic. The approval check covers selected sender/schedule,
self-approval refusal, stale digest, UV downgrade, keyboard approval, persistent
feedback and a 360px viewport. The kernel's real-Postgres tests separately enforce
policy and passkey authority. Neither script sends to a real provider.
