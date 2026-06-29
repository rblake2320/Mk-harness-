"""Consultant-facing skills: curated system prompts for the jobs direct-sales
consultants actually do.  Skill = system prompt + output contract.

Brand awareness: call get_skills(brand_name) to get the full dict for any brand.
The module-level SKILLS constant is the Mary Kay default for backward compat.

LEGAL GUARDRAIL — skin analysis is COSMETIC ONLY. The prompt forbids diagnosis,
disease naming, and treatment claims (FDA/FTC line for cosmetics). The guardrail
lives server-side so no client can bypass it.
"""
from .brands.registry import get_brand

# ---------------------------------------------------------------------------
# Universal FTC income-claim patterns — apply to ALL direct-sales brands.
# Sources:
#   FTC Act §5; 16 CFR Part 437 (Business Opportunity Rule)
#   FTC September 2024 MLM Income Disclosure Staff Report
#   FTC January 2025 Proposed Earnings Claim Rule (16 CFR Part 462)
#   FTC March 2024 Letter to DSSRC (Greisman)
#   FTC Operation AI Comply (September 2024 — AI income-claim enforcement)
#   DSSRC August 2020 Earnings Claims Guidance
#   FTC v. LifeWave (April 2026); FTC v. IM Mastery Academy (May 2025)
#   FTC v. Forever Living (April 2026); FTC v. Farmasi participant (April 2026)
#   FTC 2024 Business Guidance on MLM (Q13, Q18, Q24)
#
# Standard: ANY statement from which a reasonable person could infer a minimum
# income level = earnings claim requiring substantiation (FTC Act §5).
# ---------------------------------------------------------------------------
UNIVERSAL_INCOME_PATTERNS: list[str] = [
    # Explicit guarantee / will-earn claims
    "guaranteed income",
    "guaranteed earnings",
    "guaranteed to make",
    "guaranteed to earn",
    "will make $",
    "will earn $",
    "you will make",
    "you will earn",
    "earn up to $",
    "make up to $",
    "make $1,000",
    "make $5,000",
    "make $10,000",
    "earn $1,000",
    "earn $5,000",
    "earn $10,000",
    "average earnings",
    "typical earnings",
    "average income",
    "most consultants earn",
    "most consultants make",
    "promise you",
    # FTC/DSSRC income-type descriptors
    "passive income",
    "residual income",
    "replacement income",
    "full-time income",
    "career-level income",
    "life-changing income",
    "unlimited income",
    "six-figure income",
    "seven-figure income",
    "six-figure earning",
    "seven-figure earning",
    "six figures",
    "seven figures",
    # FTC/DSSRC lifestyle & aspiration phrases
    "quit your job",
    "quit your 9-to-5",       # FTC 2024 Business Guidance — named verbatim
    "fire your boss",
    "retire early",
    "retire from your job",
    "be set for life",
    "financial freedom",
    "financial independence",
    "time and financial freedom",
    "be your own boss",
    "make more money than you",
    "part-time work and full-time pay",
    "income will never go away",
    "no limit to the amount",
    "no ceiling",              # unlimited earnings framing — FTC enforcement cases
    "make an incredible income",
    "extraordinary level of success",
    "life of your dreams",
    "get everything you ever wanted",
    # FTC enforcement phrases (exact quotes from cases)
    "make money in your sleep",        # FTC v. IM Mastery Academy, May 2025
    "the money keeps coming",          # FTC v. LifeWave, April 2026
    "four or five figure",             # DSSRC Case #61-2022 (Mary Kay)
]

# Keep module-level alias for code that imports INCOME_CLAIM_PATTERNS directly.
INCOME_CLAIM_PATTERNS = UNIVERSAL_INCOME_PATTERNS


def get_income_patterns(brand_name: str = "mary_kay") -> list[str]:
    """Universal patterns + any brand-specific additions."""
    brand = get_brand(brand_name)
    return UNIVERSAL_INCOME_PATTERNS + brand.extra_income_patterns


def response_has_income_claim(
    text: str, brand_name: str = "mary_kay"
) -> tuple[bool, str]:
    """Return (True, matched_phrase) if text contains an FTC-regulated income claim.

    Uses case-insensitive substring match against universal + brand-specific patterns.
    FTC standard: any statement from which a reasonable person could infer a minimum
    income level is an earnings claim requiring substantiation (FTC Act §5).
    """
    low = text.lower()
    for phrase in get_income_patterns(brand_name):
        if phrase in low:
            return True, phrase
    return False, ""


# ---------------------------------------------------------------------------
# System-prompt leak detection (brand-agnostic fingerprints)
# ---------------------------------------------------------------------------
_PROMPT_FINGERPRINTS = [
    "verified price facts below",
    "verified mary kay prices",
    "mk price facts",
    "operating guidelines but cannot share",
    "catalog 2026-01-03",
    "star consultant requires $1,800 wholesale",
    "direct recruits to the income disclosure statement",
]

_PROMPT_LEAK_REPLY = (
    "I have operating guidelines for this assistant, but I'm not able to share their contents. "
    "How can I help you with your business today?"
)


def response_leaks_system_prompt(text: str) -> bool:
    """Return True if the response reproduces distinctive system prompt text."""
    low = text.lower()
    return any(fp in low for fp in _PROMPT_FINGERPRINTS)


# ---------------------------------------------------------------------------
# Skill builders
# ---------------------------------------------------------------------------

def get_skills(brand_name: str = "mary_kay") -> dict[str, dict]:
    """Return the full skills dict for a brand."""
    brand = get_brand(brand_name)
    base = brand.base_system()
    return {
        "assistant": {
            "label": "General assistant",
            "system": base + " Answer anything about running a beauty consulting business: "
            "products, parties, customer care, social posts, time management, goal setting.",
        },
        "product_qa": {
            "label": "Product Q&A",
            "system": base + " Role: product knowledge coach. Explain product categories, "
            "skin-type matching, application techniques, and how to present benefits "
            "honestly. Flag any claim that would need verification against the current "
            "official catalog, and remind the consultant that prices and availability "
            "change — check the latest company materials before quoting a customer.",
        },
        "sales_coach": {
            "label": "Sales coach",
            "system": base + " Role: direct-sales coach for independent consultants. Help with "
            "objection handling, closing language, booking parties, team building, and "
            "weekly activity planning. Give scripts the consultant can say verbatim. "
            "Keep everything ethical: no pressure tactics, no income claims.",
        },
        "follow_up": {
            "label": "Follow-up writer",
            "system": base + " Role: customer follow-up writer. Given customer context (name, "
            "purchase history, preferences, last contact), draft a short personal text or "
            "email the consultant can send as-is. Warm, never pushy, one clear next step. "
            "Offer 2 variants: a light check-in and a reorder/upsell angle."
            + brand.follow_up_coaching,
        },
        "party_planner": {
            "label": "Party planner",
            "system": base + " Role: beauty party planner. Build run-of-show agendas, themes, "
            "icebreakers, demo sequences, hostess coaching scripts, and post-party "
            "follow-up plans. Output checklists with timing.",
        },
        "social": {
            "label": "Social content",
            "system": base + " Role: social media content creator for a consultant's personal "
            "page. Write captions, hooks, reel scripts, and 30-day content calendars. "
            "Always include a compliant disclosure style ('Independent Beauty Consultant') "
            "and never fabricate before/after results.",
        },
    }


# Module-level default (Mary Kay) — keeps existing imports working.
SKILLS: dict[str, dict] = get_skills("mary_kay")


# ---------------------------------------------------------------------------
# Skin analysis — separate contract because output is structured JSON.
# ---------------------------------------------------------------------------
SKIN_ANALYSIS_SYSTEM = (
    "You are a cosmetic skin observation assistant for beauty consultants. "
    "You analyze a face photo and report COSMETIC observations only.\n"
    "HARD RULES:\n"
    "1. NEVER diagnose, name, or suggest any medical condition or disease "
    "(no acne vulgaris, rosacea, eczema, melanoma, infection, etc.).\n"
    "2. NEVER recommend medication or treatment. Cosmetic care categories only.\n"
    "3. If you observe anything that could be a health concern, set "
    "see_professional=true and say only: 'Some areas may benefit from a "
    "dermatologist's opinion' — nothing more specific.\n"
    "4. Use only these observation categories: hydration, oiliness, visible_texture, "
    "tone_evenness, fine_lines, pore_visibility, under_eye_appearance, radiance.\n"
    "5. Recommend product CATEGORIES (e.g., 'hydrating serum', 'gentle exfoliant'), "
    "never specific products, brands or medical-sounding ingredients.\n"
    "Respond with a single JSON object exactly matching:\n"
    "{\n"
    '  "observations": [{"category": "<one of the 8>", "level": "low|moderate|notable",'
    ' "note": "<one plain sentence>"}],\n'
    '  "care_focus": ["<2-4 cosmetic care categories>"],\n'
    '  "routine_suggestion": {"am": ["<steps>"], "pm": ["<steps>"]},\n'
    '  "consultant_talking_points": ["<2-3 warm, compliant sentences>"],\n'
    '  "see_professional": false,\n'
    '  "disclaimer": "Cosmetic observations only — not medical advice or a diagnosis."\n'
    "}"
)

SKIN_ALLOWED_CATEGORIES = {
    "hydration", "oiliness", "visible_texture", "tone_evenness",
    "fine_lines", "pore_visibility", "under_eye_appearance", "radiance",
}

# Words that must never appear in a skin result shown to a customer.
SKIN_FORBIDDEN_TERMS = {
    "acne vulgaris", "rosacea", "eczema", "psoriasis", "melanoma", "carcinoma",
    "dermatitis", "infection", "disease", "diagnos", "prescription", "tretinoin",
    "accutane", "antibiotic", "steroid",
}


def skin_result_is_compliant(result_text: str) -> tuple[bool, str]:
    low = result_text.lower()
    for term in SKIN_FORBIDDEN_TERMS:
        if term in low:
            return False, term
    return True, ""
