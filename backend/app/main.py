"""MK Consultant Harness API."""
from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .config import get_settings, require_secret
from .db import init_engine
from .auth_sessions import revocation_worker
from .privacy_delivery import privacy_worker
from .telemetry import PrivateHttpTelemetry
from .routes import (
    account, agent_ops, auth, billing, chat, commitments, consent, customers, drafting, foundation, inbound, outreach,
    keys, mfa, profile, skin, skindata, usage,
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

<h2>5. Data deletion and retention</h2>
<p>Deletion removes active application content and revokes account access. A deletion
receipt tracks the remaining kernel, provider and backup processing; an accepted
request is not confirmation that those copies have been erased.</p>
<ul>
  <li>Engineering retention targets pending launch review: ordinary deletion requests
      within 30 days; database backups age out within 35 days.</li>
  <li>Message content: 12 months; resolved commitments and ordinary outcomes: 24 months.</li>
  <li>Content-free security and audit events: 24 months. Minimal consent proof:
      five years after last reliance. Minimal suppression identifiers remain while
      the business relationship or account is active.</li>
  <li>Provider deletion controls, automated retention jobs and any explicit legal hold
      require verification before production launch. No blanket seven-year legal
      retention requirement is asserted here.</li>
</ul>

<h2>6. Your rights</h2>
<p>Depending on your location, you may have the right to:</p>
<ul>
  <li><strong>Access</strong> — download all data we hold about you via
      <code>GET /api/account/export</code> (authenticated).</li>
  <li><strong>Portability</strong> — the export endpoint returns a machine-readable JSON
      file containing your complete account data.</li>
  <li><strong>Deletion</strong> — request deletion in Settings, save the receipt and
      check its pending stages. Provider processing, backup expiry and any reviewed
      retention exception are separate from removal of active application content.</li>
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
    settings.seal_key_list
    engine = init_engine()
    if engine.dialect.name == "postgresql":
        from sqlalchemy import text
        with engine.connect() as connection:
            writer_kid = connection.execute(text("SELECT writer_kid FROM mk_app.application_seal_policy WHERE id=1")).scalar_one()
            if writer_kid != settings.seal_key_list[0][0]:
                raise RuntimeError("Application sealing writer differs from the database fence; finish the authorized key rollout")
    stop = asyncio.Event()
    workers = [asyncio.create_task(revocation_worker(stop)), asyncio.create_task(privacy_worker(stop))]
    try:
        yield
    finally:
        stop.set()
        try:
            await asyncio.wait_for(asyncio.gather(*workers), timeout=15)
        except asyncio.TimeoutError:
            pass  # cancellation leaves the durable lease for the next worker


app = FastAPI(title="MK Consultant Harness", version="1.6.2", lifespan=lifespan)


from sqlalchemy.exc import IntegrityError  # noqa: E402


@app.exception_handler(IntegrityError)
async def database_constraint_failure(_request, exc):
    from fastapi.responses import JSONResponse
    original = exc.orig
    message = getattr(getattr(original, "diag", None), "message_primary", "")
    if getattr(original, "sqlstate", None) == "23514" and message in {
        "SEAL_WRITER_RETIRED", "SEAL_WRITE_REQUIRES_READ_COMMITTED"
    }:
        return JSONResponse(status_code=503, content={"detail": {"code": "SEAL_WRITER_RETIRED",
            "message": "This server's encryption configuration needs an operator rollout. The change was not saved."}})
    if getattr(original, "sqlstate", None) == "23514" and message in {
        "PRIVACY_SUBJECT_ERASED", "PRIVACY_WRITE_REQUIRES_READ_COMMITTED"
    }:
        return JSONResponse(status_code=409, content={"detail": {"code": "PRIVACY_WRITE_REFUSED",
            "message": "The record cannot be written under the current privacy state. The change was not saved."}})
    # Never echo SQL, parameters, encrypted data or credentials to the caller.
    return JSONResponse(status_code=500, content={"detail": "Database operation failed"})


@app.middleware('http')
async def private_auth_responses(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(PrivateHttpTelemetry)

# foundation before customers: its /customers/import/* and /customers/export.csv paths
# must win over customers' /customers/{cid}.
for r in (auth.router, mfa.router, chat.router, skin.router, foundation.router, commitments.router, drafting.router, inbound.router, outreach.router, customers.router,
          keys.router, usage.router, profile.router, consent.router, skindata.router,
          billing.router, account.router, agent_ops.router):
    app.include_router(r, prefix="/api")


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
    from sqlalchemy import text, select, func
    from datetime import datetime, timezone
    from .models import AuthRevocation, RecoveredSessionRevocation

    from .db import get_db
    from .kernel.client import KernelUnavailable, get_kernel_client

    checks: dict[str, str] = {}
    ok = True
    try:
        db = next(get_db())
        try:
            db.execute(text("SELECT 1"))
            pending = [db.scalar(select(func.min(model.created_at)).where(model.confirmed_at.is_(None)))
                       for model in (AuthRevocation, RecoveredSessionRevocation)]
            oldest = min((value for value in pending if value is not None), default=None)
            checks["recovery_security"] = "pending" if pending[1] is not None else "ok"
            ok = ok and pending[1] is None
            if oldest is not None:
                age = (datetime.now(timezone.utc) - oldest.replace(tzinfo=timezone.utc)).total_seconds()
                checks["revocation_delivery"] = "delayed" if age > 60 else "pending"
                ok = ok and age <= 60
            else:
                checks["revocation_delivery"] = "ok"
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
    return JSONResponse(status_code=200 if ok else 503, content={"status": "ready" if ok else "not_ready", "checks": checks})


@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
def privacy_policy():
    """Public privacy policy — required by App Store and GDPR/CCPA."""
    return HTMLResponse(content=_PRIVACY_HTML)
