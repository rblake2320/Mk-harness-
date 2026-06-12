# Consultant Studio — Model-Agnostic AI Harness for Beauty Consultants

[![CI](https://github.com/rblake2320/mk-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/rblake2320/mk-harness/actions/workflows/ci.yml)

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
│   └── tests/           31 tests (auth, crypto, isolation, adapters, e2e)
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

## Tests

```bash
cd backend && python -m pytest -v    # 31 tests
```

Provider adapters are tested against each vendor's documented wire format
with HTTP-level simulation (respx) — **mocking exists only in the test
suite**; product code always talks to real endpoints. End-to-end tests drive
the live ASGI app: streaming chat persistence + metering, automatic failover
(Anthropic 529 → OpenAI), key-policy enforcement, tenant isolation,
EXIF stripping, and skin-compliance rejection.

## Security model

- argon2id password hashing; JWT access (30 min) + refresh (14 d) tokens
- Per-user sliding-window rate limiting (in-process; swap store for Redis
  when running >1 API replica — interface is one function in `ratelimit.py`)
- Tenant isolation enforced in every query (tested cross-tenant 404s)
- Audit log on signup, member add, key changes
- CORS locked to configured origins; uploads capped (default 8 MB) and
  re-encoded; startup **fails fast** if `JWT_SECRET`/`MASTER_KEY` are missing

## Production notes (read before launch)

1. **Migrations:** schema is created via `create_all` for v1. Before your
   first breaking schema change, adopt Alembic (`alembic init`, autogenerate
   against `app.models.Base`). Models already use portable types.
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

Built and verified in a sandboxed container: backend test suite (31/31),
live server smoke test, and web production build all pass here. What I could
not do from the container: hit OpenAI/Gemini live endpoints (network
egress), run an iOS/Android simulator (Expo client is code-complete and
mirrors the tested web flows through the same SDK, but needs a device run),
or deploy to your infrastructure. First-run checklist is in "Run it" above.
