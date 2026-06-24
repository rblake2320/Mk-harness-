# Consultant Studio — Monster Move Strategy
*Source: R Blake · June 24, 2026 · Confidential*
*Annotated & fact-checked against the actual codebase on June 24, 2026.*

> **Status:** This is the scale-up / exit thesis. The unit-economics and positioning live in
> `STRATEGY.md`; the market reality in `TRENDS.md`; the legal posture in `SECURITY-PRIVACY.md`.
> This document is the "go big" layer on top. Two items here are **open decisions, not done
> deals** — see the reality check below before executing them.

---

## Engineering reality check (verified June 24, 2026)

The original draft was directionally accurate about the code. Verified against the repo:

| Claim in draft | Verified? | Note |
|---|---|---|
| Model-agnostic harness w/ failover (Anthropic 529 → OpenAI) | ✅ True | `providers/router.py` |
| AES-256-GCM key encryption, AAD per `tenant:user:provider` | ✅ True | `crypto.py` |
| argon2id password hashing, JWT access + refresh | ✅ True | `security.py` |
| EXIF/GPS stripping + server-side skin compliance | ✅ True | `routes/skin.py` |
| 58-pattern FTC income-claim filter | ✅ True | `skills.py` (now two-layer, brand-aware) |
| Per-user sliding-window rate limiting, Redis-ready | ✅ True | `ratelimit.py` (in-process, swap noted) |
| No Stripe / billing / subscription mgmt | ✅ True (gap) | Roadmap "Now" |
| **"31 tests"** | ❌ **Stale** | Actually **45 (MK) / 46 (Avon)** as of v1.1.0 / v1.0.0 |
| Revenue is $0, model unvalidated in market | ✅ True | The honest gap |

**Net:** the architecture claims hold up. The only factual error was the test count (corrected
in README/CLAUDE). Treat the market-size and exit-multiple figures as **cited illustrations,
not forecasts** — penetration assumptions (3–5%) are aggressive and unproven until we have
live subscribers.

---

## Two open decisions that need your call (do not execute unilaterally)

### Decision 1 — Merge the two repos into one "Consultant Studio" monorepo?

The draft's headline move. **This contradicts the earlier deliberate choice to keep
`Mk-harness-` and `avon-harness` as separate repos** ("make a new github and make an AVON
pair to this… don't mess up old github"). The tradeoff:

- **For merging:** single codebase, one deploy, cross-brand data moat in one place, and
  *platform* valuation multiples instead of *point-solution* multiples at exit.
- **Against merging:** the brand-agnostic `BrandConfig` architecture already delivers most
  of the engineering benefit (a brand = one config file). Separate repos = separate blast
  radius, separate deploy cadence, and they can still share a backend via a submodule or a
  published package. Merging now is real refactor work with no revenue upside yet.

**Recommendation:** keep them separate until there's a paying-customer reason to merge.
Extract the shared backend into a package later if/when a third brand lands. This is a
reversible-later decision; don't pay the merge cost before validation.

### Decision 2 — File a provisional patent on the compliance filter?

The "server-side discard-before-persist of non-compliant AI output" method is plausibly
novel, but **novelty requires a real prior-art search and a patent attorney** — I can't
assess patentability and I can't file. If you want to pursue it, the move is: provisional
application before any public press, drafted by counsel. Flagging it as a real-world legal
action, not a code task.

---

## Market opportunity (cited)

- **AI in beauty/cosmetics:** ~$5.3B in 2026, ~21% CAGR (researchandmarkets). Incumbents
  (L'Oréal ModiFace, Perfect Corp, Revieve) are consumer/brand-enterprise facing — **none
  operate in rep-enablement.** That gap is the business.
- **US direct selling:** $34.7B retail sales (2024), 5.4M participants (DSA 2025 study).
- **Teamzy benchmark:** ~$550K ARR, 5 employees, bootstrapped, ~$1.7M valuation, $29.99/mo,
  no AI / no skin / no compliance (GetLatka). At $9.99 with more capability we undercut 3x
  while overdelivering. Their ARR implies ~1,527 subs — the displaceable CRM-niche universe.
- **TAM (MK + Avon US reps):** ~300K–500K. At $9.99 and 3% → ~$1.07–1.78M MRR; blended w/
  Leader/Director upsell at 5% → $3M+ MRR. *(Aggressive; unvalidated.)*

---

## The 5 moves

1. **Platform positioning ("Consultant Studio"/neutral brand)** — *pending Decision 1.* Even
   without a repo merge, market the offering under a neutral, multi-brand name so we're "a
   direct sales AI platform," not "an Avon app" — acquirers pay platform multiples.
2. **90-day free, annual-first funnel** — Stripe on day one; annual ($89/yr) front-and-center,
   monthly as upgrade path; day-80 conversion email; day-90 downgrade to read-only free tier;
   $5 referral credit (refer 10 → free year). Matches the 9:1 LTV:CAC in STRATEGY.md.
3. **Exploit the "Anele is broken" window NOW (Months 1–2)** — comparison landing page +
   "what actually works" YouTube + free Leader accounts to 20–30 active Avon-group voices.
   Time-limited: closes if LG H&H patches or acquires. (Detail in `avon-harness/STRATEGY.md`.)
4. **Build the data moat deliberately** — collect (with consent, per `SECURITY-PRIVACY.md`):
   skill-usage patterns, compliance-flag stats, aggregate skin-profile distribution,
   follow-up→reorder attribution, reorder velocity. Two monetizations: (a) attributable-GMV
   proof for acquirers, (b) independent rep-customer dataset additive to brands' own app data.
5. **Acquisition play at Month 12–18** — vertical AI SaaS commanding ~5–14x revenue (NRR>120%
   ~11.7x median, Windsor Drake/SEG 2026). Buyer universe below.

### Buyer universe
- **LG H&H / The Avon Company** — owns the US rep network, already tried & failed at AI
  (Anele). Most obvious acquirer for the Avon module.
- **Mary Kay Inc.** — has Mirror Me / Interactive Catalog, no rep-enablement AI.
- **Natura&Co (NTCO3)** — owns Avon LatAm; US rep skin data is additive.
- **Betterware/BeFra** — just did a $250M Tupperware-LatAm acquisition; consolidating the space.
- **PE financial buyers** — ~58% of SaaS transactions; bolt-on to raise portfolio retention.

---

## Exit scenarios (illustrative, not forecasts)

| ARR at Exit | 5x | 8x | 14x |
|---|---|---|---|
| $360K | $1.8M | $2.9M | $5.0M |
| $600K | $3.0M | $4.8M | $8.4M |
| $1.2M | $6.0M | $9.6M | $16.8M |
| $2.4M | $12.0M | $19.2M | $33.6M |

Multiples per current vertical-SaaS M&A comps; actual outcome depends on NRR, growth rate,
and how defensible the compliance/data moat proves at diligence.

---

## 90-day execution sprint (the part that's actually actionable now)

These are repo-level tasks that do **not** depend on the merge decision and are reflected in
`ROADMAP.md` "Now":

- **Weeks 1–3 — revenue infra:** Stripe (subs + annual + referral credit); usage-metering
  dashboard (token cost per user/team); Redis rate limiting for multi-replica; mobile device
  test (Expo EAS, iOS+Android).
- **Weeks 4–6 — launch prep:** Anele comparison landing page; "what actually works" video;
  identify 40–50 active MK+Avon group voices for free-Leader outreach.
- **Weeks 7–10 — first wave:** 90-day trial funnel live w/ annual conversion sequence;
  activate first ~20 creator accounts; surface reorder-attribution in-product; track NPS at
  D30/D60/D90.
- **Weeks 11–12 — milestone review:** 100 trials → validate conversion; 50 paid → PMF signal,
  begin enterprise outreach; $5K MRR → fundable seed story; $10K MRR → acqui-hire conversation.

---

## Risks (with the one that matters most)

| Risk | Severity | Mitigation |
|---|---|---|
| Avon fixes/replaces Anele before we scale | **High** | Run the Anele narrative Months 1–2, not Month 6 |
| Mary Kay ships its own rep AI | Medium | Compliance filter + skin CRM are ahead; launch fast |
| Model API cost spikes hurt margin | Medium | Local Ollama/PanDerm path already in harness |
| Seasonal Avon rep churn | Medium | Annual prepay from day 1; spring onboarding flow |
| Privacy/consent gap (skin data) | **High** | Close `SECURITY-PRIVACY.md` gaps BEFORE real customer photos |

The Tupperware lesson is the thesis in one sentence: it died because it never built digital
tools for its sellers and watched them leave. We are the tool that absence creates demand for.

---

## Bottom line

Architecture is real and verified. The strategy docs are sound. The gap is **revenue
infrastructure + the first paying subscribers**, not code quality. Do the 90-day sprint, run
the Anele window now, and hold the two big decisions (repo merge, patent) for a deliberate
call rather than reflex. This is a $1M–$25M outcome depending on execution velocity — with the
honest caveat that every number above is unvalidated until subscriber #1.
