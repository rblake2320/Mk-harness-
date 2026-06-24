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
