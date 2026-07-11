# Consultant Studio — Model-Agnostic AI Harness for Beauty Consultants

[![CI](https://github.com/rblake2320/Mk-harness-/actions/workflows/ci.yml/badge.svg)](https://github.com/rblake2320/Mk-harness-/actions/workflows/ci.yml)

Push-button AI for independent beauty consultants: sales coaching, party
planning, customer follow-ups, social content, and photo-based **cosmetic**
skin observations — pluggable with **any** model (Anthropic, OpenAI, Gemini,
Ollama/local, or any OpenAI-compatible endpoint). No custom-trained models
required.

## What's in the box

```
mk-harness/
├── backend/          FastAPI · Postgres · multi-tenant · JWT auth
│   ├── app/providers/   The harness core: 4 adapters + router + failover
│   └── tests/           136 tests (auth, crypto, isolation, adapters, e2e, red team)
├── packages/sdk/     Shared TypeScript SDK (web + mobile)
├── web/              React + Vite web client (dark "vanity mirror" UI)
├── mobile/           Expo React Native client (camera skin analysis)
└── docker-compose.yml
```

## The harness (why this is model-agnostic)

Every provider implements one interface (`app/providers/base.py`):
`complete()`, `stream()`, `default_model()`. The router resolves which key to
use, executes, meters tokens/cost, and **fails over automatically** on
retryable errors (429/5xx/529) in the order anthropic → openai → gemini →
ollama. Adding a provider = one adapter file + catalog entries. The OpenAI
adapter accepts a custom `base_url`, so Azure OpenAI, vLLM, and LM Studio work
today with zero new code.

## Key management — both modes, per team

Each tenant (team/unit) picks a `key_policy` at signup:

| Policy    | Behavior |
|-----------|----------|
| `central` | Company/team keys only (tenant key or server env key). Consultants can't add keys. |
| `byo`     | Each consultant must bring their own key. |
| `both`    | Resolution order: consultant key → tenant key → server env key. |

Keys are encrypted at rest with **AES-256-GCM** under a `MASTER_KEY` env
secret; the AAD binds each ciphertext to `tenant:user:provider`, so a row
copied across scopes will not decrypt. Keys are never returned by any API
after being saved.

## Skin analysis — compliance by construction

- Images are validated, **EXIF/GPS-stripped**, downscaled, and re-encoded
  server-side before any model sees them.
- The system prompt restricts output to 8 cosmetic observation categories and
  bans diagnosis/treatment language (FDA/FTC cosmetic line).
- The response is **validated server-side**: forbidden medical terms → the
  result is discarded with a 502 (never stored, never shown); unknown
  categories are filtered; the disclaimer is enforced by the server, not the
  model. Tests cover the "model leaks a diagnosis" case.

## Run it

```bash
cd mk-harness
cat > .env << 'ENV'
POSTGRES_PASSWORD=$(openssl rand -hex 24)
JWT_SECRET=$(openssl rand -hex 48)
MASTER_KEY=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
# Optional central keys (leave blank to require BYO):
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
OLLAMA_BASE_URL=
ENV
docker compose up --build
# Web app: http://localhost:8080  (create your team on first visit)
```

Local development without Docker:

```bash
cd backend && pip install -r requirements.txt
alembic upgrade head
MK_ALLOW_DEV_SECRETS=1 JWT_SECRET=dev-secret-dev-secret-dev-secret-123 \
  MASTER_KEY=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())") \
  uvicorn app.main:app --reload --port 8000
cd ../web && npm install && npm run dev   # http://localhost:5173 (proxies /api)
```

Mobile:

```bash
cd mobile && npm install
# set extra.apiUrl in app.json to your API host, then:
npx expo start
```

## Governed Mobile Workflows

The `/api/agent-ops` surface queues five workflow types: SMS follow-up, appointment
booking, order-status lookup, recruiting outreach, and social posting. Every
work order is tenant-scoped, checked by the existing content guards, and held
for explicit human approval before dispatch. Device registration is admin-only;
adapter secrets are returned once, stored with AES-GCM, and used for HMAC-signed
delivery, ping, and result callbacks with replay protection.

Outbound SMS and direct-message tasks also require an active, matching contact
permission record. The record stores a keyed destination fingerprint, asserted
basis, evidence digest, expiry, and revocation status. It is an operator
attestation, not independent verification that consent satisfies federal, state,
platform, or campaign-specific requirements. Review the current
[FTC Telemarketing Sales Rule guidance](https://www.ftc.gov/business-guidance/resources/complying-telemarketing-sales-rule)
and [FCC AI voice ruling](https://docs.fcc.gov/public/attachments/FCC-24-17A1.pdf)
with qualified counsel before enabling consumer outreach.

This integration targets an operator-controlled adapter. The upstream
[PhoneClaw repository](https://github.com/rohanarun/phoneclaw) documents
JavaScript ClawScript helpers but does not publish a remote webhook protocol.
Generated envelopes therefore state `verified_on_device: false` until the exact
adapter build is exercised on a real device. Voice calling and a production
mobile adapter are not implemented in this release.

Configure exact authorities before registering devices or using portal-based
workflows. Include a port when the URL uses a non-default port:

```bash
AGENT_OPERATIONS_ENABLED=false
AGENT_OPERATIONS_WEBHOOK_HOSTS=adapter.example.com
AGENT_OPERATIONS_TARGET_HOSTS=booking.example.com,carrier.example.com
AGENT_OPERATIONS_PUBLIC_BASE_URL=https://harness.example.com
AGENT_OPERATIONS_DISPATCH_TIMEOUT_SECONDS=10
```

Agent Operations is disabled by default; the API router is not mounted until
the deployment explicitly enables it. Its audit is a tenant-scoped database
hash chain. It detects
modification, deletion, truncation, or reordering relative to its retained head,
but it is not digitally signed, externally anchored, WORM storage, legal proof,
or a regulatory authorization. See [WHY.md](WHY.md) and [PARKED.md](PARKED.md)
for the decisions and deferred claims.

## Tests

```bash
cd backend && python -m pytest -v    # 136 collected in the v1.7.0 release run
```

Provider adapters are tested against each vendor's documented wire format
with HTTP-level simulation (respx) — **mocking exists only in the test
suite**; product code always talks to real endpoints. End-to-end tests drive
the live ASGI app: streaming chat persistence + metering, automatic failover
(Anthropic 529 → OpenAI), key-policy enforcement, tenant isolation,
EXIF stripping, and skin-compliance rejection.

## Security model

- argon2id password hashing; JWT access (30 min) + refresh (14 d) tokens
- Password change invalidates **all** previously issued tokens (a `pv`
  fingerprint claim binds every token to the current password hash — no
  session store required)
- Constant-time login path (dummy argon2 verify on unknown emails — no
  user-enumeration timing oracle)
- Per-user sliding-window rate limiting — Redis-backed when `REDIS_URL` is
  set (multi-replica safe; `redis` ships in requirements), with an in-process
  fallback that logs a loud error if Redis was configured but unreachable
- Tenant isolation enforced in every query (tested cross-tenant 404s)
- Audit log on signup, member add, key changes
- CORS locked to configured origins; uploads capped (default 8 MB) and
  re-encoded; startup **fails fast** if `JWT_SECRET`/`MASTER_KEY` are missing

## Production notes (read before launch)

1. **Migrations:** Alembic owns runtime schema creation. Fresh containers run
   `alembic upgrade head` before the API starts. For a database created by
   v1.6.2 or earlier, take a backup, verify it matches the v1.6.2 model schema,
   then run `alembic stamp 0001` followed by `alembic upgrade head` once before
   deploying v1.7.0. Never stamp an unverified or partially migrated database.
2. **TLS:** terminate at your load balancer or put Caddy/Traefik in front of
   the web container.
3. **Key rotation:** to rotate `MASTER_KEY`, decrypt-reencrypt provider_keys
   rows in a maintenance script (AAD stays stable); to rotate `JWT_SECRET`,
   all sessions are invalidated — schedule accordingly.
4. **Model prices** live in `app/providers/base.py` (`MODEL_CATALOG`).
   Update as vendors change pricing; unknown models meter tokens at $0.
5. **App stores:** the Expo client ships via EAS Build; camera/photo
   permission strings are already configured in `app.json`.

## Honest constraints

Verified in a clean repo-local environment on July 10, 2026: 135 tests passed
and 1 environment-dependent Redis durability test skipped. The focused
Agent Operations suite passed 10/10, two migration tests passed, Ruff reported
no violations, `pip-audit` reported
no known vulnerabilities in the pinned requirements, and the web production
build completed after `npm ci` with zero npm audit findings. This
release was not exercised against a real PhoneClaw device, a deployed adapter,
live AI-provider endpoints, an iOS/Android simulator, or production
infrastructure. First-run instructions are in "Run it" above.
