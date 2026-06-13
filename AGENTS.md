# AGENTS.md — Provider & Skill Reference

This document describes every AI agent surface in the harness: the four LLM provider
adapters, the failover router, and the six consultant-facing skills.

---

## Provider Adapters

All adapters live in `backend/app/providers/` and implement the `ProviderAdapter` ABC
defined in `base.py`. The interface is three methods:

| Method | Signature | Notes |
|--------|-----------|-------|
| `complete` | `async (req: ChatRequest) → ChatResult` | Full response |
| `stream` | `(req: ChatRequest) → AsyncIterator[StreamChunk]` | SSE streaming |
| `default_model` | `(vision: bool) → str` | Returns model ID for the task type |

The rest of the application **only speaks these types**. Routes never import an adapter
directly — they go through `router.py`.

---

### Anthropic (`AnthropicAdapter`)

**File:** `backend/app/providers/anthropic_openai.py`

| Model | Input $/M | Output $/M | Vision |
|-------|-----------|------------|--------|
| `claude-sonnet-4-6` | $3.00 | $15.00 | Yes |
| `claude-haiku-4-5-20251001` | $1.00 | $5.00 | Yes |

- Uses the Anthropic Messages API (`/v1/messages`).
- Streaming: `stream=true` SSE, event types `content_block_delta` and `message_delta`.
- Vision: images passed as `{"type": "image", "source": {"type": "base64", ...}}` in the
  `content` array.
- Default text model: `claude-sonnet-4-6`. Default vision model: `claude-sonnet-4-6`.
- Retryable errors: 429, 529, 500, 502, 503, 504.

---

### OpenAI (`OpenAIAdapter`)

**File:** `backend/app/providers/anthropic_openai.py`

| Model | Input $/M | Output $/M | Vision |
|-------|-----------|------------|--------|
| `gpt-4o` | $2.50 | $10.00 | Yes |
| `gpt-4o-mini` | $0.15 | $0.60 | Yes |

- Uses the OpenAI Chat Completions API (`/v1/chat/completions`).
- Streaming: `stream=true` SSE, `delta.content` chunks, `[DONE]` sentinel.
- Vision: `{"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,..."}}`.
- `base_url` override: pass any OpenAI-compatible endpoint (Azure OpenAI, vLLM, LM Studio)
  via the `ProviderKey.base_url` field — zero new code.
- Default text model: `gpt-4o-mini`. Default vision model: `gpt-4o`.
- Retryable errors: 429, 500, 502, 503, 504.

---

### Gemini (`GeminiAdapter`)

**File:** `backend/app/providers/gemini_ollama.py`

| Model | Input $/M | Output $/M | Vision |
|-------|-----------|------------|--------|
| `gemini-2.0-flash` | $0.10 | $0.40 | Yes |
| `gemini-1.5-pro` | $1.25 | $5.00 | Yes |

- Uses the Google Generative Language API
  (`generativelanguage.googleapis.com/v1beta/models/{model}:...`).
- Streaming: `streamGenerateContent` endpoint with SSE.
- Vision: inline data parts `{"inlineData": {"mimeType": "...", "data": "..."}}`.
- System instruction passed as `systemInstruction.parts[0].text`.
- Default text model: `gemini-2.0-flash`. Default vision model: `gemini-2.0-flash`.
- Retryable errors: 429, 500, 502, 503, 504.

---

### Ollama (`OllamaAdapter`)

**File:** `backend/app/providers/gemini_ollama.py`

| Model | Cost | Vision |
|-------|------|--------|
| `llama3.1` | $0 (local) | No |
| `llama3.2-vision` | $0 (local) | Yes |

- Talks to a local Ollama instance (`OLLAMA_BASE_URL`, default `http://localhost:11434`).
- Uses `/api/chat` (streaming NDJSON) and `/api/generate`.
- No API key required; set `OLLAMA_BASE_URL` if not on localhost.
- Vision: images as base64 strings in the `images` array of the message.
- Default text model: `llama3.1`. Default vision model: `llama3.2-vision`.
- Not included in the cloud failover chain; used only when explicitly requested or when
  all cloud providers have failed and Ollama is configured.

---

## Router & Failover (`router.py`)

**File:** `backend/app/providers/router.py`

### Key resolution

```
request arrives with (user_id, tenant_id, provider_hint)
  │
  ├─ key_policy = "central"  → use tenant key or server env key
  ├─ key_policy = "byo"      → require user key; 400 if missing
  └─ key_policy = "both"     → user key → tenant key → server env key
```

Decrypted keys are **never logged or returned to clients**. AES-256-GCM decryption
uses AAD = `f"{tenant_id}:{user_id}:{provider}"` — a key from one scope will not
decrypt in another.

### Failover chain

Default chain: `anthropic → openai → gemini → ollama`

On a `ProviderError(retryable=True)` (429/5xx/529), the router tries the next provider
in the chain that has a resolvable key. If all fail, the last error is re-raised as a
502. Failover is **transparent to routes** — they always receive a `ChatResult` or
stream.

Usage is recorded after every successful call:
```
UsageRecord(user_id, provider, model, key_scope, input_tokens, output_tokens, cost_usd)
```

---

## Skills (System Prompts)

**File:** `backend/app/skills.py`

Skills are named system-prompt presets selected per-conversation. Adding a skill is one
dict entry — no code changes anywhere else.

| Key | Label | Purpose |
|-----|-------|---------|
| `assistant` | General assistant | Catch-all for business questions |
| `product_qa` | Product Q&A | Skin-type matching, application techniques, catalog coaching |
| `sales_coach` | Sales coach | Objection handling, booking scripts, ethical direct-sales |
| `follow_up` | Follow-up writer | Drafts customer texts/emails (check-in + reorder variants) |
| `party_planner` | Party planner | Run-of-show agendas, hostess coaching, post-party follow-up |
| `social` | Social content | Captions, reel scripts, 30-day calendars with FTC disclosures |

All skills share a `_BASE` preamble that enforces:
- No invented product claims, prices, or ingredients
- No medical advice
- Warm, concrete, brief tone

---

## Skin Analysis Agent

**System prompt:** `SKIN_ANALYSIS_SYSTEM` in `backend/app/skills.py`  
**Route:** `backend/app/routes/skin.py`

This is a separate agentic surface with stricter constraints than chat skills.

### Pipeline

```
Client upload
  └─ validate MIME + size (≤8 MB)
       └─ strip EXIF/GPS (re-encode through clean pixel buffer via Pillow)
            └─ downscale to ≤1568×1568, re-encode as JPEG
                 └─ vision model (any adapter with vision=True)
                      └─ parse JSON response
                           └─ server-side compliance check (SKIN_FORBIDDEN_TERMS)
                                ├─ PASS → store in skin_analyses, return to client
                                └─ FAIL → 502, discard, never stored
```

### Output contract (JSON)

```json
{
  "observations": [
    {"category": "<one of 8>", "level": "low|moderate|notable", "note": "<one sentence>"}
  ],
  "care_focus": ["<2-4 cosmetic care categories>"],
  "routine_suggestion": {"am": ["<steps>"], "pm": ["<steps>"]},
  "consultant_talking_points": ["<2-3 compliant sentences>"],
  "see_professional": false,
  "disclaimer": "Cosmetic observations only — not medical advice or a diagnosis."
}
```

### Allowed observation categories (8)

`hydration` · `oiliness` · `visible_texture` · `tone_evenness` ·
`fine_lines` · `pore_visibility` · `under_eye_appearance` · `radiance`

### Forbidden terms (server-enforced, never shown to client)

`acne vulgaris` · `rosacea` · `eczema` · `psoriasis` · `melanoma` · `carcinoma` ·
`dermatitis` · `infection` · `disease` · `diagnos*` · `prescription` · `tretinoin` ·
`accutane` · `antibiotic` · `steroid`

If any forbidden term appears in the model's response, the result is **discarded** and
a 502 is returned. The `see_professional=true` flag is the only compliant exit for
ambiguous observations.

---

## MODEL_CATALOG

All pricing lives in `backend/app/providers/base.py`. Update here when vendors change
rates — no adapter code changes required.

```python
MODEL_CATALOG: dict[str, dict] = {
    "claude-sonnet-4-6":         {"provider": "anthropic", "in": 3.00,  "out": 15.00, "vision": True},
    "claude-haiku-4-5-20251001": {"provider": "anthropic", "in": 1.00,  "out": 5.00,  "vision": True},
    "gpt-4o":                    {"provider": "openai",    "in": 2.50,  "out": 10.00, "vision": True},
    "gpt-4o-mini":               {"provider": "openai",    "in": 0.15,  "out": 0.60,  "vision": True},
    "gemini-2.0-flash":          {"provider": "gemini",    "in": 0.10,  "out": 0.40,  "vision": True},
    "gemini-1.5-pro":            {"provider": "gemini",    "in": 1.25,  "out": 5.00,  "vision": True},
    "llama3.2-vision":           {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": True},
    "llama3.1":                  {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": False},
}
```

Unknown models still record token counts but meter at $0 cost.
