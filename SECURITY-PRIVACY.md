# Security & Privacy Posture
*Last updated: June 24, 2026. Re-verify legal landscape quarterly.*
*This is engineering documentation, not legal advice. Have counsel review before any
production launch that handles real customer data.*

This product stores customer PII, customer photos (for skin analysis), and **attributes
derived from those photos** (undertone, Fitzpatrick skin type). In 2026 that derived data
is legally sensitive. This document records what the law requires, what we already do,
and the concrete gaps to close before scaled customer-data handling.

---

## The single biggest liability: derived skin data is "consumer health data"

**Washington's My Health My Data Act (MHMDA, RCW 19.373)** explicitly covers data
"derived or inferred" by algorithms from photos. Our `skin_undertone`, `fitzpatrick_type`,
and `skin_profile_json` fields fall squarely inside that definition. MHMDA:
- Triggers **regardless of whether the person is identified**.
- Requires **separate opt-in consents**: one to *collect*, one to *share*, and a signed
  authorization to *sell*.
- Carries a **private right of action** via Washington's Consumer Protection Act
  (treble damages up to $25K + fees). First class action filed Feb 2025.

Nevada and Connecticut have similar consumer-health-data regimes. This is the controlling
constraint for the skin-analysis feature.

### Biometric laws (secondary but real)
- **Illinois BIPA** covers a "scan of face geometry" *only if the person can be identified*
  (*Castelaz v. Estée Lauder*, Jan 2024, dismissed a cosmetics face-analysis claim on this
  ground). Still requires **written opt-in** + a **public retention policy**; damages
  $1,000 / $5,000 per person (per-person cap, SB 2979, Aug 2024).
- **Texas CUBI** is AG-enforced only, but aggressive post-*Meta* ($1.4B, Jul 2024).
- **Posture: get written opt-in for skin analysis regardless of state.** It's the floor
  that satisfies all of them.

### General state privacy laws (~19 in effect by 2026)
CCPA/CPRA, Virginia VCDPA, Colorado CPA, Texas, Maryland MODPA, plus IN/KY/RI from Jan
2026. All except CA/UT require **opt-in for sensitive/biometric data**. **Maryland MODPA
bans selling sensitive data even with consent.** As the platform we are a **processor /
service provider** and need **Data Processing Agreements** (VCDPA-model + CCPA §7051 terms)
with subcontractor flow-down to any LLM/vision vendor in the chain.

### AI-specific (lighter, but note one)
- AI-generated marketing copy alone needs no disclosure.
- **Chatbots need disclosure** (California SB 243, live Jan 2026) — a user must be told
  they're talking to AI. Our chat UI must carry an AI disclosure.
- EU AI Act high-risk obligations delayed to Dec 2027; Colorado AI Act replaced (eff. Jan
  2027); Texas TRAIGA + California AB 2013 live Jan 2026. None block us today; track them.

### FTC
Operation AI Comply narrowed (Rytr set aside Dec 2025) but **income-claim enforcement is
live** (Air AI banned Mar 2026). Our income-claim filter is the right call. Also: **never
train AI on customer photos without renewed consent** — FTC has ordered *algorithmic
disgorgement* (deletion of models trained on improperly obtained data).

---

## What we already do right

- **Local-first skin analysis.** When `SKIN_ANALYSIS_URL` is set, photos are processed on
  local hardware (PanDerm, port 8101) and **never leave the machine**. Strongest possible
  data-minimization posture.
- **EXIF stripping** before any image reaches a provider (removes GPS/device metadata).
- **Compliance gate** strips all medical/oncology output; only cosmetic dimensions are kept.
- **Encryption at rest** for API keys (AES-256-GCM, AAD-bound to `tenant:user:provider`).
- **Multi-tenant isolation** enforced and tested (cross-tenant access returns 404).
- **Derive-then-keep-attributes** is already the data shape — we store the derived profile,
  not a pipeline that hoards raw images in the DB.

---

## Gaps to close before scaled customer-data handling

Tracked as roadmap items (see ROADMAP.md "Now").

1. **Consent capture.** Add an explicit, logged opt-in the consultant collects from the
   customer before skin analysis ("I consent to a photo-based skin analysis"). Store the
   consent record (who, when, scope) alongside the customer. Required by MHMDA + BIPA.
2. **AI disclosure in chat UI.** Visible "You're chatting with an AI assistant" notice
   (California SB 243).
3. **Raw photo retention enforcement.** Confirm and enforce: raw photo is processed in
   memory, derived attributes stored, **raw image discarded by default**. If any caching
   exists, auto-purge on a published schedule (≤ 3 years, BIPA cap; sooner is better).
4. **Data deletion + export endpoints.** `DELETE /api/customers/{id}` cascading to all
   derived skin data; `GET /api/account/export`. Honor deletion within **45 days** with
   vendor pass-through.
5. **Published privacy policy + retention schedule.** Public-facing, plain-language.
   BIPA specifically requires a publicly available retention/destruction policy.
6. **DPAs with any cloud LLM/vision vendor**, with subcontractor flow-down terms.
7. **No-training guarantee.** Contractually and technically ensure customer photos are
   never used to train models without fresh, specific consent.
8. **Per-tenant data-residency option** for the privacy-sensitive segment (local PanDerm
   already enables the strongest version of this).

---

## Operating rules (do not weaken)

- `SKIN_FORBIDDEN_TERMS` and the post-response compliance check stay. Medical output is
  discarded server-side, never stored.
- The income-claim filter (58 patterns, two-layer) stays. It is now a liability shield for
  the individual rep, not a nicety.
- Local PanDerm is the recommended production configuration for any privacy-sensitive
  deployment. Cloud vision is the fallback, not the default, where customer photos are
  involved.
- Secrets only in environment / `~/.secrets` (chmod 600). Never inline, never tracked.
