# Changelog

All notable changes to MK Copilot (Consultant Studio) are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`VERSION` at the repo root is the single source of truth for the current version.
Keep `backend/app/main.py`, `web/package.json`, and `mobile/app.json` in sync with it.

---

## [Unreleased]

### Planned
See `ROADMAP.md` for the forward plan.

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
