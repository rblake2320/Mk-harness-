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

## Implemented in v1.2.0 — the skin-data compliance core

These were the launch-blocking gaps. They now ship and are covered by tests.

1. ✅ **Consent capture.** `ConsentRecord` table + `POST /api/consent/skin`. Two subjects:
   *operator* (consultant accepts the data terms — gates the whole feature) and *customer*
   (per-customer consent before their photo is analyzed). Each grant stores the SHA-256 of
   the exact text shown and the version; mirrored to `AuditLog`. The skin route calls
   `require_skin_consent()` **before the photo is read** — missing consent returns `403`
   with a machine-readable code (`operator_consent_required` / `customer_consent_required`)
   so the client raises the right modal. Material text changes bump `SKIN_CONSENT_VERSION`,
   which forces re-consent. Text lives in `app/consent.py`.
2. ✅ **AI disclosure on skin output.** Every analyze response and history row carries a
   persistent `ai_disclosure` ("AI-generated cosmetic estimate — not medical advice…").
   *(The chat-UI "you're talking to AI" banner for California SB 243 is a separate
   frontend item — see "Still open".)*
3. ✅ **Photo retention enforcement.** Raw bytes are `del`-eted right after sanitize/encode,
   the sanitized base64 is `del`-eted after use, and an `AuditLog` `skin.analyze` row records
   `photo_discarded=1`. No raw image is ever persisted — only the derived cosmetic result.
4. ✅ **Deletion + export endpoints.** `DELETE /api/me/skin-data` (optionally `?customer_id=`)
   purges `SkinAnalysis` rows and clears the derived `Customer` skin fields, returns a
   deletion **receipt**; `GET /api/me/skin-data/export` returns everything stored
   (analyses + customer skin profiles + the consent trail) for MHMDA access/portability.
   Synchronous — the 45-day deadline is trivially met. Revocation: `DELETE /api/consent/skin`.

## Still open (next sprint — only acute with paying enterprise tenants)

5. **Chat-UI AI disclosure banner** (California SB 243) — frontend "you're chatting with AI".
6. **Published privacy policy + retention schedule.** Public-facing, plain-language. BIPA
   requires a publicly available retention/destruction policy.
7. **DPAs with any cloud LLM/vision vendor**, with subcontractor flow-down terms.
8. **No-training guarantee.** Contractually + technically ensure customer photos are never
   used to train models without fresh, specific consent.
9. **Per-tenant data-residency option** for the privacy-sensitive segment (local PanDerm
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
