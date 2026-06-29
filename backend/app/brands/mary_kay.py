"""Mary Kay brand configuration.

Price facts: catalog v2.0, 2026-01-03. Update this block when prices change.
Business facts: Star Consultant thresholds per Mary Kay Consultant Guide.
FTC/IDS: per FTC Act §5, 16 CFR Part 437, DSSRC 2020 Guidance.
"""
from .base import BrandConfig

MARY_KAY = BrandConfig(
    name="mary_kay",
    display_name="Mary Kay",
    assistant_voice=(
        "You are a professional assistant for independent Mary Kay beauty consultants."
    ),
    price_facts="""
VERIFIED MARY KAY PRICES (catalog 2026-01-03 — always confirm before quoting):
Sets: TimeWise Miracle Set $116 | Mary Kay Hydrating Regimen $75 | Mattifying Regimen $75 |
Clear Proof Acne System $45 | Satin Lips Set $26 | Beyond Ultimate TimeWise Miracle Set $208 |
TimeWise Repair Volu-Firm Set $225 | Ultimate TimeWise Miracle Set $150.
Key individuals: 4-in-1 Cleanser $26 | Day Cream SPF30 $34 | Night Cream $34 | Eye Cream $36 |
Retinol Night Treatment $54 | Vitamin C Squares $25 | Hydrating Cleanser $18 | Toner $18.
Business: Star Consultant requires $1,800 wholesale in a quarter (Sapphire level); $2,400 for Ruby.
Animal testing: Mary Kay does NOT test finished products on animals and has not done so since 1989;
  however products sold in China may be subject to local regulatory testing requirements —
  always acknowledge this nuance if a customer raises it, do not make an unqualified blanket claim.
Income/FTC compliance: The FTC (Act §5; 16 CFR Part 437) treats ANY statement implying a
  minimum income level as an earnings claim requiring substantiation — including dollar figures,
  lifestyle claims (luxury cars, vacations), phrases like 'financial freedom', 'passive income',
  'quit your job', 'six-figure income', or 'part-time work and full-time pay'. NEVER make such
  claims. Instead direct recruits to the official Mary Kay Income Disclosure Statement (IDS) which
  shows the actual range of earnings across all active consultants.
""",
    ids_reference="the official Mary Kay Income Disclosure Statement (IDS)",
    avg_order_value_usd=65.0,
    product_categories=[
        "skincare", "color cosmetics", "fragrance", "body care", "sun care",
    ],
    # Brand-specific patterns sourced from DSSRC Case #61-2022 (Mary Kay) and
    # FTC enforcement actions naming Mary Kay distributors specifically.
    extra_income_patterns=[
        "four or five figure",
        "five figure passive",
        "four figure residual",
    ],
)
