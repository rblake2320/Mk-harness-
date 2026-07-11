"""MK Consultant Harness API."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .config import get_settings, require_secret
from .db import init_engine
from .routes import (
    account,
    auth,
    billing,
    chat,
    consent,
    customers,
    keys,
    profile,
    skin,
    skindata,
    usage,
)

_PRIVACY_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy — Consultant Studio</title>
<style>body{font-family:system-ui,sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem;line-height:1.6}
h1{font-size:1.6rem}h2{font-size:1.1rem;margin-top:2rem}p,li{color:#333}</style>
</head>
<body>
<h1>Privacy Policy</h1>
<p><strong>Effective date:</strong> January 1, 2026 &nbsp;|&nbsp;
<strong>Last updated:</strong> June 2026</p>

<p>Consultant Studio ("we", "us", or "the Service") is an AI-powered business productivity
tool for independent beauty consultants. This policy explains what data we collect,
how we use it, and your rights.</p>

<h2>1. What we collect</h2>
<ul>
  <li><strong>Account data</strong> — name, email address, hashed password, display name.</li>
  <li><strong>Customer book</strong> — names, phone numbers, emails, and notes you enter about
      your own customers. This data belongs to you.</li>
  <li><strong>Conversation history</strong> — messages you exchange with the AI assistant,
      stored so you can continue conversations across sessions.</li>
  <li><strong>Skin analysis results</strong> — cosmetic observations derived from photos you
      upload. Photos are processed in memory and immediately discarded; only the derived
      cosmetic scores are stored. Raw images are never retained.</li>
  <li><strong>Consent records</strong> — timestamps and version hashes of consent agreements
      for skin data processing.</li>
  <li><strong>Usage data</strong> — token counts and cost estimates per AI provider call.</li>
  <li><strong>Mobile work orders</strong> — workflow inputs, generated instructions,
      device results, operator-attested contact permission metadata, and keyed
      permanent contact-suppression records.</li>
  <li><strong>Billing data</strong> — managed by Stripe. We store only a Stripe customer ID;
      card numbers never touch our servers.</li>
</ul>

<h2>2. How we use your data</h2>
<ul>
  <li>To provide the AI assistant, CRM, and skin analysis features.</li>
  <li>To enforce compliance rules (FTC income-claim filter, consent gates).</li>
  <li>To bill your subscription via Stripe.</li>
  <li>To improve service reliability and detect abuse.</li>
  <li>To stage, approve, deliver, and audit mobile work orders.</li>
</ul>
<p>We do not sell your data to third parties. We do not use your data to train AI models
without explicit consent.</p>

<h2>3. AI disclosure (California SB 243 / Washington HB 2225)</h2>
<p>The assistant in this Service is powered by artificial intelligence. It is not a human.
Every chat session begins with a disclosure to this effect. The Service is a business
productivity tool for consultants, not a social companion product.</p>

<h2>4. Health data (Washington My Health My Data Act)</h2>
<p>Skin analysis results may constitute consumer health data under the Washington My Health
My Data Act (MHMDA). We collect this data only after obtaining explicit operator consent
(from you, the consultant) and, where applicable, customer consent. Consent records are
stored with an integrity hash of the exact text agreed to. You may withdraw consent at any
time via the app settings, which immediately blocks further processing.</p>

<h2>5. Data retention</h2>
<ul>
  <li>Account and customer data: retained while your account is active, deleted within
      30 days of account deletion.</li>
  <li>Conversation history: retained for 12 months, then auto-purged.</li>
  <li>Skin analysis scores: retained while the associated customer record exists.</li>
  <li>Mobile work-order content: retained while the account is active and
      scrubbed when that account is deleted; audit digests may remain.</li>
  <li>Contact suppressions: a keyed destination fingerprint and suppression
      reason may be retained after account deletion to prevent renewed outreach.</li>
  <li>Audit logs: retained for 7 years (legal / compliance requirement).</li>
</ul>

<h2>6. Your rights</h2>
<p>Depending on your location, you may have the right to:</p>
<ul>
  <li><strong>Access</strong> — download all data we hold about you via
      <code>GET /api/account/export</code> (authenticated).</li>
  <li><strong>Portability</strong> — the export endpoint returns a machine-readable JSON
      file containing your complete account data.</li>
  <li><strong>Deletion</strong> — contact us at the address below to request account
      deletion. We will delete your data within 30 days, subject to legal holds on
      audit logs.</li>
  <li><strong>Correction</strong> — update your profile or customer records in-app at
      any time.</li>
</ul>

<h2>7. Security</h2>
<ul>
  <li>All data in transit is encrypted via TLS.</li>
  <li>API keys are encrypted at rest with AES-256-GCM; each key is bound to its
      tenant/user scope by authenticated encryption (AAD).</li>
  <li>Passwords are stored as argon2id hashes — never in plaintext or reversible form.</li>
  <li>Login brute-force protection: 5 failures per 15 minutes triggers a lockout.</li>
</ul>

<h2>8. Cookies and tracking</h2>
<p>We do not use advertising cookies or third-party tracking pixels. Authentication uses
short-lived JSON Web Tokens sent as Bearer headers and held in session storage, which is
cleared when you close your browser; we set no advertising or cross-site cookies.</p>

<h2>9. Changes to this policy</h2>
<p>We will notify you of material changes via in-app notice at least 30 days before the
change takes effect.</p>

<h2>10. Contact</h2>
<p>Privacy questions or deletion requests: <a href="mailto:privacy@consultantstudio.app">
privacy@consultantstudio.app</a></p>
</body>
</html>
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    require_secret(settings)
    settings.master_key_bytes  # fail fast if missing/malformed
    init_engine()
    yield


app = FastAPI(title="MK Consultant Harness", version="1.7.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)

routers = [
    auth.router,
    chat.router,
    skin.router,
    customers.router,
    keys.router,
    usage.router,
    profile.router,
    consent.router,
    skindata.router,
    billing.router,
    account.router,
]
if get_settings().agent_operations_enabled:
    from .routes import agent_ops

    routers.append(agent_ops.router)

for r in routers:
    app.include_router(r, prefix="/api")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
def privacy_policy():
    """Public privacy policy — required by App Store and GDPR/CCPA."""
    return HTMLResponse(content=_PRIVACY_HTML)
