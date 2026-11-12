"""MK Consultant Harness API."""
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .config import get_settings, require_secret
from .db import init_engine
from .rbac import route_guard
from .routes import (
    account, agent_ops, auth, billing, chat, commitments, consent, customers, drafting, foundation, inbound, outreach,
    keys, profile, security, skin, skindata, usage,
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
  <li><strong>Billing data</strong> — managed by Stripe. We store only a Stripe customer ID;
      card numbers never touch our servers.</li>
</ul>

<h2>2. How we use your data</h2>
<ul>
  <li>To provide the AI assistant, CRM, and skin analysis features.</li>
  <li>To enforce compliance rules (FTC income-claim filter, consent gates).</li>
  <li>To bill your subscription via Stripe.</li>
  <li>To improve service reliability and detect abuse.</li>
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
{RETENTION_LIST}

<h2>6. Your rights</h2>
<p>Depending on your location, you may have the right to:</p>
<ul>
  <li><strong>Access</strong> — download all data we hold about you via
      <code>GET /api/account/export</code> (authenticated).</li>
  <li><strong>Portability</strong> — the export endpoint returns a machine-readable JSON
      file containing your complete account data.</li>
  <li><strong>Deletion</strong> — erase a customer from their page, or delete your
      account in Settings (or contact us at the address below). Erasure is immediate in
      the application; copies held by our sending system and SMS provider are erased
      within 30 days. Minimal opt-out and permission evidence is kept so an opted-out
      customer is never contacted again.</li>
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


app = FastAPI(title="MK Consultant Harness", version="1.6.2", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)

# foundation before customers: its /customers/import/* and /customers/export.csv paths
# must win over customers' /customers/{cid}.
# Every /api router runs rbac.route_guard first: authentication, MFA state, role
# permission, step-up and break-glass scope from ONE policy table (default deny).
for r in (auth.router, security.router, chat.router, skin.router, foundation.router, commitments.router,
          drafting.router, inbound.router, outreach.router, customers.router,
          keys.router, usage.router, profile.router, consent.router, skindata.router,
          billing.router, account.router, agent_ops.router):
    app.include_router(r, prefix="/api", dependencies=[Depends(route_guard)])


@app.get("/api/health")
def health():
    """Liveness only (load-balancer target health). Never touches dependencies."""
    return {"status": "ok"}


@app.get("/api/health/ready")
async def ready():
    """Readiness of the core workflow path: database reachable and, when the
    governed-action kernel is configured, the kernel's own readiness. External
    uptime checks (contract O3 availability) point here, not at `/api/health`,
    so a dead database or kernel counts as downtime. Unauthenticated by design;
    the body carries no tenant data."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import text

    from .db import get_db
    from .kernel.client import KernelUnavailable, get_kernel_client

    checks: dict[str, str] = {}
    ok = True
    try:
        db = next(get_db())
        try:
            db.execute(text("SELECT 1"))
            # H9 propagation backlog: revocations the kernel has not acknowledged for
            # more than a minute (count only — no tenant data). Alerted on in ops.
            from datetime import timedelta

            from sqlalchemy import func, select

            from .foundation import utcnow
            from .models import KernelRevocationOutbox
            stale = db.scalar(select(func.count()).select_from(KernelRevocationOutbox).where(
                KernelRevocationOutbox.delivered_at.is_(None),
                KernelRevocationOutbox.created_at < utcnow() - timedelta(seconds=60))) or 0
            checks["kernel_revocations_backlog"] = str(stale)
            # S13: erasures not acknowledged by the kernel past their 30-day due date.
            from .models import ErasureRequest
            overdue = db.scalar(select(func.count()).select_from(ErasureRequest).where(
                ErasureRequest.kernel_acknowledged_at.is_(None), ErasureRequest.legal_hold.is_(False),
                ErasureRequest.due_by < utcnow())) or 0
            checks["erasures_overdue"] = str(overdue)
        finally:
            db.close()
        checks["database"] = "ok"
    except Exception:  # noqa: BLE001 — any failure is "not ready"; detail stays in logs
        checks["database"] = "unavailable"
        ok = False
    client = get_kernel_client()
    if client.configured:
        try:
            r = await client.health_ready()
            checks["kernel"] = "ok" if r.status_code == 200 else "not_ready"
            ok = ok and r.status_code == 200
        except KernelUnavailable:
            checks["kernel"] = "unavailable"
            ok = False
    else:
        checks["kernel"] = "not_configured"
    # Security posture flags (booleans only) so pre-flight can refuse a production
    # deployment that runs without MFA or with an over-privileged database login.
    from .config import get_settings
    st = get_settings()
    checks["mfa_required"] = "true" if st.mfa_required else "false"
    checks["db_least_privilege"] = "enforced" if st.db_require_least_privilege else "off"
    return JSONResponse(status_code=200 if ok else 503, content={"status": "ready" if ok else "not_ready", "checks": checks})


@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
def privacy_policy():
    """Public privacy policy — required by App Store and GDPR/CCPA."""
    from .retention import policy_html
    # Generated from the same table the purge job enforces (no hand-written periods).
    return HTMLResponse(content=_PRIVACY_HTML.replace("{RETENTION_LIST}", policy_html()))
