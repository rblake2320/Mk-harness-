# Evaluation harness (contract rows A1–A6)

`python -m tests.evaluations.run` evaluates the deployed pipeline stages against annotated
case sets and prints one line per row with the measured metric, the threshold from
`docs/production-acceptance.md`, and the case count. It exits non-zero when any row with
an available evaluator misses its threshold.

## What this harness proves — and what it does not

| Row | Stage evaluated | Mode |
|-----|-----------------|------|
| A1 | `commitments.parse_extractor_output` — validator stage: does the pipeline accept exactly the annotated commitments and reject hallucinated ones? | replay (recorded model output) or live (`--live`) |
| A2 | `drafting.assemble` — does any assembled draft reference another customer's name, number or notes? | replay / live |
| A3 | `drafting.assemble` — does the pipeline accept any unsupported or paraphrased claim? | replay / live |
| A4 | inbound reply classifier (opt-out / escalation) | **evaluator not available until WP07 lands the inbound state model**; always reported *Not demonstrated* |
| A5 | `drafting.assemble` + `parse_extractor_output` under adversarial inputs — any change of recipient, approval, permission, or controlled claim? | replay / live |
| A6 | `commitments.date_text_present` / `window_for` — invented dates dropped, abstention rate reported | replay / live |

**Replay mode** feeds recorded `model_output` to the *deterministic* stages. It proves that
the pipeline's acceptance logic is correct on the annotated set; it does **not** measure
model recall (a model that returns nothing scores 100 % precision and 0 % recall; recall is
reported from the case annotations so a silent extractor fails A1).

**Live mode** (`--live --provider anthropic|openai|gemini|ollama`) calls the real provider
with the same system prompts the product uses, then runs the same validators. It needs the
provider key in the environment and spends tokens. Live-mode results are what the matrix
rows A1–A6 require.

## Case sets (`cases/*.jsonl`)

| File | Cases | Required by contract | Status |
|------|------:|---------------------:|--------|
| a1_commitments.jsonl | seed | 500 | **seed only — collection of the 500-case annotated set is not done** |
| a2_customer_context.jsonl | seed | 500 | seed only |
| a3_product_claims.jsonl | seed | 500 | seed only |
| a4_optout_escalation.jsonl | seed | 500 | seed only; no evaluator yet |
| a5_prompt_injection.jsonl | seed | 500 | seed only |
| a6_dates.jsonl | seed | included in A1 | seed only |

Run `python -m tests.evaluations.run --counts` for exact counts. **Until each set reaches
its contracted size and the live run is executed and recorded under
`evidence/releases/<release>/`, rows A1–A6 remain Not demonstrated.** Seed cases are
synthetic and author-written; they are a harness check, not acceptance evidence.

## Case format

Each line is one JSON object. Common fields: `id`, `description`, `tags`.

- **A1/A6** `{"source": "<conversation text>", "now_local": "2026-10-20T09:00:00-05:00",
  "model_output": "<raw JSON the extractor returned>",
  "expected": [{"kind":..., "relative_window":..., "absolute_date":..., "evidence_quote":...}],
  "expect_abstain_dates": true|false}`
- **A2/A3/A5 (draft)** `{"customer": {"name":..., "phone":...}, "others": [{"name":..., "phone":...}],
  "claims": [{"claim_id":..., "product_id":..., "approved_text":...}],
  "model_output": "<raw JSON>", "expect": "draft"|"refuse",
  "forbidden_substrings": [...]}`
- **A4** `{"inbound_text": ..., "expected_class": "opt_out"|"ambiguous_opt_out"|"escalation"|"ordinary"}`

Adding cases never lowers a threshold. Thresholds live in `run.py::THRESHOLDS` and must
match the matrix.
