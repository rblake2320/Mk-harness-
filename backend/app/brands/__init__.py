"""Brand configuration layer — one file per direct-sales brand.

Adding a new brand (e.g. Avon):
  1. Create backend/app/brands/avon.py with an `AVON = BrandConfig(...)` instance.
  2. Register it in registry.py: BRANDS["avon"] = AVON
  3. Set brand="avon" on the Tenant row at signup.

Everything else — auth, CRM, providers, FTC filter, skin analysis — is brand-agnostic.
"""
