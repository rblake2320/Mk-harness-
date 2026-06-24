# CLAUDE.md — mk-harness

Project-specific instructions for Claude Code working in this repository.

## Project overview

**Consultant Studio** is a model-agnostic AI harness for independent beauty consultants.  
Stack: FastAPI backend · React/Vite web · Expo React Native mobile · shared TypeScript SDK.

Key invariant: **the rest of the application never names a provider**. All LLM traffic flows
through `backend/app/providers/` only. Any change that leaks provider names into routes,
models, or the SDK is wrong.

---

## Common commands

### Backend
```bash
cd backend
pip install -r requirements.txt

# Dev server (SQLite, no Docker needed)
MK_ALLOW_DEV_SECRETS=1 \
JWT_SECRET=dev-secret-dev-secret-dev-secret-123 \
MASTER_KEY=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())") \
uvicorn app.main:app --reload --port 8000

# Tests (51 tests, all in-process — no live endpoints required)
python -m pytest -v
```

### Web
```bash
cd web
npm install
npm run dev        # http://localhost:5173 — proxies /api to :8000
npm run build      # production build
npx tsc -b --noEmit  # type-check only
```

### Mobile
```bash
cd mobile
npm install
npx expo start     # requires Expo Go on device or simulator
```

### Full stack (Docker)
```bash
# create .env from README "Run it" section, then:
docker compose up --build
# web: http://localhost:8080
```

---

## Architecture in one page

```
Request
  └─ routes/chat.py  (auth, rate-limit, conversation persistence)
       └─ providers/router.py  (key resolution → failover chain)
            ├─ AnthropicAdapter   anthropic_openai.py
            ├─ OpenAIAdapter      anthropic_openai.py  (accepts custom base_url)
            ├─ GeminiAdapter      gemini_ollama.py
            └─ OllamaAdapter      gemini_ollama.py
```

**Failover order:** anthropic → openai → gemini → ollama (on 429/5xx/529)

**Key policy** (per tenant):

| Policy  | Behavior |
|---------|----------|
| central | Tenant or server env key only; consultants cannot add keys |
| byo     | Each consultant must supply their own key |
| both    | User key → tenant key → server env key (fallback chain) |

Keys are AES-256-GCM encrypted at rest. AAD binds ciphertext to `tenant:user:provider` —
a copied row will not decrypt in a different scope.

---

## Where things live

| What | Where |
|------|-------|
| Provider interface + MODEL_CATALOG | `backend/app/providers/base.py` |
| Failover + key resolution | `backend/app/providers/router.py` |
| Anthropic + OpenAI adapters | `backend/app/providers/anthropic_openai.py` |
| Gemini + Ollama adapters | `backend/app/providers/gemini_ollama.py` |
| Skills (system prompts) | `backend/app/skills.py` |
| DB models (9 tables) | `backend/app/models.py` |
| API key crypto | `backend/app/crypto.py` |
| JWT auth | `backend/app/security.py` |
| Skin compliance rules | `backend/app/skills.py` (`SKIN_FORBIDDEN_TERMS`) |
| Shared TS SDK | `packages/sdk/src/index.ts` |
| Web views | `web/src/views/` |

---

## Testing rules

- Tests live in `backend/tests/`. **Do not mock the database** — fixtures use an in-memory
  SQLite engine (`conftest.py`). This matches the "no mock/prod divergence" rule.
- Provider wire-format tests use `respx` HTTP mocking (no live endpoints); product code
  always talks to real endpoints — never add `respx` outside `tests/`.
- Every new route needs a test for: happy path, auth failure (401), and cross-tenant
  isolation (second user/tenant gets 404).
- Run `python -m pytest -v` — all 51 must pass before any commit.

---

## Adding a provider

1. Create `backend/app/providers/<name>.py` implementing `ProviderAdapter`
   (`complete`, `stream`, `default_model`).
2. Add model entries to `MODEL_CATALOG` in `base.py`.
3. Register the adapter in `router.py` (`PROVIDER_MAP` + `DEFAULT_CHAIN`).
4. Add wire-format tests in `tests/test_providers.py`.
5. No changes needed in routes, models, SDK, or web.

## Adding a skill

One entry in the `SKILLS` dict in `backend/app/skills.py`:
```python
"my_skill": {
    "label": "Human-readable name",
    "system": _BASE + " Role: ...",
},
```
No other changes required.

---

## Skin analysis — compliance guardrails (do not weaken)

- `SKIN_FORBIDDEN_TERMS` in `skills.py` must never be removed or shortened.
- Server-side compliance check in `routes/skin.py` runs *after* the model responds —
  forbidden terms → 502, result discarded, never stored.
- EXIF stripping happens in `routes/skin.py` before the image reaches any adapter.
- The `see_professional` field is the only safe escape valve for ambiguous cases.

---

## Schema migrations

v1 uses `Base.metadata.create_all`. Before any breaking schema change, init Alembic:
```bash
cd backend
alembic init alembic
# edit alembic/env.py to import app.models.Base
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

---

## Environment variables

| Variable | Required | Notes |
|----------|----------|-------|
| `JWT_SECRET` | Yes | ≥48 hex chars; rotating invalidates all sessions |
| `MASTER_KEY` | Yes | base64-encoded 32 bytes; rotation needs decrypt-reencrypt script |
| `POSTGRES_PASSWORD` | Prod | Not needed for SQLite dev |
| `ANTHROPIC_API_KEY` | No | Central key mode |
| `OPENAI_API_KEY` | No | Central key mode |
| `GEMINI_API_KEY` | No | Central key mode |
| `OLLAMA_BASE_URL` | No | Local model endpoint |
| `MK_ALLOW_DEV_SECRETS` | Dev only | Disables secret-length enforcement |
| `RATE_LIMIT_PER_MINUTE` | No | Default 30 |
