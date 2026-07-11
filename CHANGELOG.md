# Changelog

All notable changes to MK Copilot (Consultant Studio) are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`VERSION` at the repo root is the single source of truth for the current version.
Keep `backend/app/main.py`, `web/package.json`, and `mobile/app.json` in sync with it.

---

## [Unreleased]

See `ROADMAP.md` and `PARKED.md` for planned and deliberately deferred work.

### Added
- Standalone Draft 2020-12 schemas for mobile work orders, device pings,
  execution state, completion, and failure callbacks.
- Public non-secret HMAC conformance vector and an upstream source lock that
  explicitly records the absence of a concrete adapter or device evidence.
- Loopback-only mobile-adapter simulator with signed callbacks and deterministic
  accept, reject, first-attempt failure, and unsupported-action modes.

### Changed
- Production boundaries now validate outbound work orders and inbound device
  callbacks against the published schemas.
- Adapter delivery retries transient transport and HTTP failures up to three
  attempts with a fresh signed nonce per attempt.

### Verified
- Contract/simulator implementation commit [`4c825bc`](https://github.com/rblake2320/Mk-harness-/commit/4c825bcf1a4e67deb63f0d235d1fbf22a6bda00a).
- Clean repo-local backend suite: 142 passed, 1 Redis-dependent skip.
- Agent Operations integration and contract suites: 17 passed.
- Ruff and `pip-audit -r backend/requirements.txt` passed on July 11, 2026.
- No concrete mobile adapter or real phone was exercised.

## [1.7.0] — 2026-07-10

### Added
- Tenant-scoped Agent Operations work orders for SMS follow-up, appointment booking,
  order status, recruiting outreach, and social posting.
- Admin-controlled phone-adapter registration with one-time device secrets,
  AES-GCM storage, HMAC request signing, timestamp bounds, and nonce replay
  protection.
- Mandatory human approval before dispatch and an atomic dispatch claim that
  prevents duplicate approval sends.
- Operator-attested contact permissions for outbound SMS/DM tasks, including a
  keyed destination fingerprint, evidence digest, expiry, and revocation gate.
- Permanent contact suppressions that survive permission revocation and are
  rechecked immediately before dispatch.
- Exact allowlists for adapter and customer-portal authorities, with HTTPS-only
  URL validation and private/reserved IP-literal rejection.
- Tenant-scoped database audit hash chain and verification/tail endpoints.
- Alembic core baseline plus an Agent Operations migration; runtime
  `create_all()` was removed.
- `LOG.md`, `WHY.md`, and `PARKED.md` for change evidence, decision rationale,
  restoration conditions, and deferred claims.

### Security
- Updated pinned dependencies to versions that produced a clean `pip-audit` on
  July 10, 2026, including FastAPI 0.139.0, Starlette 1.3.1, PyJWT 2.13.0,
  cryptography 48.0.1, python-multipart 0.0.31, and Pillow 12.2.0.
- Removed pre-existing unused imports so repository-wide Ruff checks pass.

### Verified
- Implementation commit [`8af28b7`](https://github.com/rblake2320/Mk-harness-/commit/8af28b71425c5b15aa4a6f73c463b22c97cd87dd).
- Account portability/erasure follow-up [`fde98ec`](https://github.com/rblake2320/Mk-harness-/commit/fde98ecaaa890a5d22a76d8c7cc54aca232f040d).
- Disabled-by-default environment gate [`0a03142`](https://github.com/rblake2320/Mk-harness-/commit/0a03142e970e5b21b142ca3e6129e8e8328c5b53).
- Vendor-neutral naming, suppressions, and migrations [`1888499`](https://github.com/rblake2320/Mk-harness-/commit/188849924b3db5d21f79d9bc2b756af83971705f).
- Clean repo-local Python environment: 135 passed, 1 skipped.
- Agent Operations integration suite: 10 passed; migration suite: 2 passed.
- `pip-audit -r backend/requirements.txt`: no known vulnerabilities found.
- `npm ci && npm run build`: production build passed; npm audit reported zero.
- Real PhoneClaw device/adapter execution was not performed; generated envelopes
  explicitly report `verified_on_device: false`.

## [1.6.2] — 2026-07-01

### Fixed — self-audit of v1.6.1 against real-world failure, not happy paths
- **Redis death after startup no longer takes down the API.** v1.6.1 made the
  Redis path reachable in production for the first time (dependency added) but
  the rate limiter and brute-force helpers had no runtime exception handling:
  a Redis outage mid-flight crashed every login and every rate-limited AI
  endpoint with an unhandled ConnectionError. Verified against a REAL
  redis-server killed mid-run — not a mock. All Redis operations now degrade
  per-call to the in-process fallback (lockout still engages during the
  outage) and automatically resume Redis-backed limiting when it returns, with
  an error log throttled to once per minute.
- **`pv` claim comparison is now constant-time** (`hmac.compare_digest`) in
  both `get_current_user` and `/auth/refresh`.

### Verified empirically (no mocks)
- Login timing oracle: median 161.5 ms (real argon2 verify, wrong password)
  vs 162.7 ms (dummy verify, unknown email) — 1.01x ratio; the paths are
  indistinguishable.
- New `tests/test_redis_durability.py`: spawns a real redis-server, kills it
  mid-test, asserts login/chat survive, asserts brute-force lockout still
  fires during the outage, revives Redis, asserts Redis-backed limiting
  resumes without restart. Skips only where the redis-server binary is
  absent; CI now installs it so the test always runs there.

## [1.6.1] — 2026-07-01

### Security
- **Session invalidation on password change**: every JWT (access *and* refresh)
  now carries a `pv` claim — a SHA-256 fingerprint of the current password
  hash. Changing the password instantly kills all previously issued tokens,
  with no server-side session store and no schema change. Enforced in both
  `get_current_user` and `/auth/refresh`.
- **User-enumeration timing oracle closed**: login now performs a dummy
  argon2id verification when the email does not exist, equalising the timing
  of the "no such user" and "wrong password" paths.
- **Redis features now actually shippable**: `redis==5.2.1` added to
  requirements (previously the documented Redis-backed rate limiting and
  brute-force lockout could never activate in the Docker image because the
  package was absent). If `REDIS_URL` is set but Redis is unreachable, the
  fallback now logs an ERROR instead of degrading silently.
- Stricter `MASTER_KEY` parsing (`base64` with `validate=True`).
- Redis rate limiter: unique sorted-set members (eliminates the
  same-timestamp collision that could under-count requests).

### Fixed
- `test_forged_jwt_returns_401` imported `python-jose`, which is not a project
  dependency — the suite could never fully pass from a clean install. Rewritten
  against PyJWT (the actual dependency). Suite is now 123/123 from
  `pip install -r requirements.txt` alone.
- Privacy policy corrected to match the implementation: passwords are argon2id
  (not "bcrypt cost 12"); authentication is Bearer JWT in session storage (not
  an "HttpOnly session cookie"). Inaccurate statements in a legal document are
  a compliance liability.
- README CI badge pointed at `rblake2320/mk-harness`; repository is
  `rblake2320/Mk-harness-`. Badge fixed; stale test counts (58 / 31) updated
  to 123 in README and CLAUDE.md.

### Performance
- `_sanitize_image` no longer round-trips every pixel through a Python list
  (up to ~2.4M tuples per upload). Re-encoding the converted RGB image already
  writes a metadata-free JPEG; the EXIF-strip guarantee is unchanged and still
  covered by tests.

### Tests
- +3 red-team tests: pre-change access token rejected, pre-change refresh
  token rejected, and a token forged with the correct secret but missing the
  `pv` claim rejected.

## [1.4.0] — 2026-06-25

Web client — first real, demo-able pass. The React/Vite app now compiles and builds
(it never had before — `node_modules` had never been installed). Scoped to the
"minimum demo-able" surface for creator/community outreach.

### Added
- **SDK extended** (`packages/sdk`) to match the backend: `signup(..., {ref})`, consent
  (`getSkinConsent`/`grantSkinConsent`/`getCustomerConsent`/`revokeSkinConsent`), billing
  (`getBilling`/`getPlans`/`checkout`/`billingPortal`), skin-data (`exportSkinData`/
  `deleteSkinData`), `suggestions`, and a structured **`ApiError`** (carries `status` +
  `detail.code`) so the UI can branch on the consent gate's machine-readable codes.
- **SB 243 AI disclosure** (`components/AiDisclosure.tsx`): a once-per-session notice modal
  before the first AI surface, a persistent non-dismissible strip on every AI surface, and
  a per-output `AI` badge on chat messages and skin results. The server-side `ai_disclosure`
  now renders visibly in the skin result.
- **Billing view** — plans (annual-first), current status/trial, Stripe Checkout hand-off,
  customer-portal link, and a shareable **referral link** (`/?ref=CODE`) with earned-credit
  display.
- **Referral capture** — `?ref=` in the URL pre-selects signup and is attributed on signup.
- **Consent-gated skin analysis** — the Skin view catches the backend's 403 consent codes
  and raises the operator / customer consent modal (showing the exact consent text), then
  retries. No analysis happens until consent is recorded.
- **Power Hour** — the daily-suggestions endpoint surfaces as a "reach out today" card at
  the top of My Customers, each with a one-click AI follow-up draft.
- Mobile-responsive throughout (plan grid, Power Hour rows, modals collapse on phones).

### Verified
- `tsc -b --noEmit` clean; `vite build` succeeds (175 kB JS / 5.5 kB CSS gzipped ~57 kB).

---

## [1.3.0] — 2026-06-24

Revenue infrastructure. The product is consent-gated, compliance-audited, and test-covered;
this is the Stripe layer that turns it into a business. Annual-first, 90-day trial, referral
flywheel — matching the unit economics in `STRATEGY.md`.

### Added
- **Stripe billing via REST (`app/billing.py`)** — no SDK dependency; calls Stripe over
  httpx so the same respx test harness covers it, and webhook signatures are verified with
  our own HMAC-SHA256 (`verify_webhook` / `sign_payload`).
- **Billing routes (`routes/billing.py`)**: `POST /api/billing/checkout` (hosted Stripe
  Checkout, annual-first, 90-day trial), `GET /api/billing/me` (status + referral),
  `GET /api/billing/plans` (configured tier:interval), `POST /api/billing/portal`
  (Stripe customer portal), `POST /api/billing/webhook` (lifecycle + referral engine).
- **Subscription model** — mirrors Stripe state (`none → trialing → active → past_due →
  canceled`), driven entirely by webhooks. One per user.
- **Referral program** — every user gets a `referral_code`; signup accepts `?ref=`; the
  referrer earns a $5 credit on the referred user's *first paid invoice*, ledgered in
  `ReferralCredit` and pushed to their Stripe customer balance. Idempotent (one credit per
  referred user).
- **Entitlement gate (`app/entitlements.py`)** — `require_active_subscription` dependency,
  a no-op until `BILLING_ENFORCED=1` flips it on at launch (then unsubscribed → HTTP 402).
- **Config** — `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICES` (JSON
  `tier:interval → price_id` map), `BILLING_TRIAL_DAYS`, `BILLING_ENFORCED`,
  `REFERRAL_CREDIT_CENTS`, success/cancel/portal URLs. All from env — nothing hardcoded.

### Tests
- 51 → 58. New: referral-code issuance, plans listing, checkout session creation, unknown-
  plan rejection, webhook signature rejection, full lifecycle (trialing → active),
  referral credit on first payment + idempotency.

---

## [1.2.0] — 2026-06-24

Customer skin-data privacy core. Closes the launch-blocking gaps from
`SECURITY-PRIVACY.md` so the skin-analysis feature is clean to demo, launch, and put in
front of acquirers without a liability asterisk. Driven by Washington's My Health My Data
Act, which gives individuals a private right of action over derived skin attributes
(undertone, Fitzpatrick type) — one rep's pre-consent analyses are potential plaintiffs.

### Added
- **Consent capture** — `ConsentRecord` model + `app/consent.py` (versioned text, SHA-256
  integrity hashing, gate helpers). `POST /api/consent/skin` records operator and
  per-customer consent; `GET /api/consent/skin` and `/api/consent/skin/customer/{id}`
  report status and return the exact text to display; `DELETE /api/consent/skin` revokes.
- **Consent gate on skin analysis** — `require_skin_consent()` runs *before the photo is
  read*; missing consent returns `403` with a machine-readable code
  (`operator_consent_required` / `customer_consent_required`). Re-consent is forced when
  `SKIN_CONSENT_VERSION` bumps.
- **AI disclosure** — every skin analyze response and history row carries a persistent
  `ai_disclosure` field.
- **Subject-rights endpoints** — `GET /api/me/skin-data/export` (MHMDA access/portability:
  analyses + customer skin profiles + consent trail) and `DELETE /api/me/skin-data`
  (purges analyses, clears derived `Customer` skin fields, returns a deletion receipt;
  optional `?customer_id=` to scope to one customer).

### Changed
- **Photo retention made explicit** — raw bytes and sanitized base64 are `del`-eted after
  use; an `AuditLog` `skin.analyze` row records `photo_discarded=1`. No raw image is ever
  persisted (this was already true; now enforced and audited).

### Tests
- 45 → 51. New: consent gate (operator + customer), consent status/grant/revoke flow,
  export, deletion receipt + purge verification, cross-user skin-data isolation.

---

## [1.1.0] — 2026-06-24

The multi-brand and consultant-intelligence release. This is the version that turns a
single-brand chat harness into a brand-agnostic platform with per-consultant analytics
and a daily revenue-driving workflow.

### Added
- **Brand-agnostic architecture** (`backend/app/brands/`). Frozen `BrandConfig` dataclass
  per brand, a registry with fallback, and `get_skills(brand_name)` to build system
  prompts dynamically. Adding a brand is now one config file.
- **Power Hour daily suggestions** — `GET /api/customers/suggestions` returns the 5 most
  overdue customers (null `last_contact` first, then oldest), with urgency labels. This
  is the core daily revenue workflow that drives retention.
- **Consultant analytics** — new `ConsultantProfile` table tracking skill usage,
  conversation counts, skin analyses, compliance flags, and business context (tenure,
  team size, Star Consultant wholesale progress). Exposed via `GET/PATCH /api/profile/me`.
- **Skin profile in CRM** — Customer model now stores `skin_undertone`,
  `fitzpatrick_type`, and a full `skin_profile_json`. The follow-up writer uses these to
  recommend the right product variant months after an analysis.
- **Local PanDerm integration** — when `SKIN_ANALYSIS_URL` is set, skin analysis routes
  to a local medical foundation model (port 8101) at zero API cost; the photo never
  leaves local hardware. A compliance gate strips all oncology output and falls back to
  cloud vision on any failure.
- **STRATEGY.md** — full go-to-market plan: pricing, revenue math, competitive
  positioning, growth phases, unit economics.

### Changed
- **FTC income-claim filter expanded to 58 patterns.** Added: "quit your 9-to-5",
  "make money in your sleep", "no ceiling", "four or five figure", "the money keeps
  coming", and brand-specific "five figure passive" / "four figure residual".
- `response_has_income_claim(text, brand_name)` now checks universal patterns plus
  brand-specific extras (two-layer filter).
- Chat and customer routes look up the tenant's brand and build skills per-brand.

### Fixed
- `ConsultantProfile` integer fields defaulting to `None` on fresh in-memory objects
  (SQLAlchemy Python-side defaults not applied pre-flush). Constructor now sets explicit
  zero defaults and `db.flush()` runs after insert; all increments use `(x or 0) + 1`.

### Tests
- 34 → 45 tests. New coverage: FTC phrases, brand config integrity, Power Hour
  (4 tests), consultant profile tracking (3 tests).

---

## [1.0.0] — 2026 (initial)

### Added
- Model-agnostic FastAPI backend with automatic provider failover
  (anthropic → openai → gemini → ollama).
- Multi-tenant auth (JWT), AES-256-GCM envelope encryption for API keys with AAD
  binding ciphertext to `tenant:user:provider`.
- SSE streaming chat, skills-based system prompts, per-tenant key policy
  (central / byo / both).
- CRM (customers, conversations), skin analysis with server-side compliance filter
  (`SKIN_FORBIDDEN_TERMS`, EXIF stripping, post-response forbidden-term check).
- React/Vite web, Expo React Native mobile, shared TypeScript SDK.
- FTC income-claim filter (52 patterns).
