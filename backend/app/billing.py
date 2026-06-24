"""Stripe billing via the REST API (httpx) — no SDK dependency.

We talk to Stripe over plain HTTPS so the same respx-based test harness used for LLM
providers can simulate Stripe at the HTTP boundary, and so we control webhook signature
verification ourselves (HMAC-SHA256, the documented Stripe scheme).

All secrets come from Settings (env only). Price IDs are created in the Stripe dashboard
and supplied as the STRIPE_PRICES JSON map. Nothing here is hardcoded.
"""
import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException

from .config import get_settings

_API = "https://api.stripe.com/v1"


def billing_configured() -> bool:
    return bool(get_settings().stripe_secret_key)


def _auth_headers() -> dict[str, str]:
    s = get_settings()
    if not s.stripe_secret_key:
        raise HTTPException(503, "Billing is not configured on this server.")
    return {"Authorization": f"Bearer {s.stripe_secret_key}",
            "Content-Type": "application/x-www-form-urlencoded"}


async def _post(path: str, form: list[tuple[str, str]]) -> dict:
    body = urlencode(form).encode()  # application/x-www-form-urlencoded (Stripe's wire format)
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(f"{_API}{path}", headers=_auth_headers(), content=body)
    if r.status_code >= 400:
        # Surface Stripe's error message but never leak the secret key.
        try:
            msg = r.json().get("error", {}).get("message", "Stripe error")
        except Exception:
            msg = "Stripe error"
        raise HTTPException(502, f"Stripe: {msg}")
    return r.json()


async def create_customer(email: str, user_id: str) -> str:
    data = [("email", email), ("metadata[user_id]", user_id)]
    return (await _post("/customers", data))["id"]


async def create_checkout_session(customer_id: str, price_id: str, trial_days: int,
                                  client_reference_id: str) -> dict:
    s = get_settings()
    form = [
        ("mode", "subscription"),
        ("customer", customer_id),
        ("line_items[0][price]", price_id),
        ("line_items[0][quantity]", "1"),
        ("subscription_data[trial_period_days]", str(trial_days)),
        ("client_reference_id", client_reference_id),
        ("success_url", s.billing_success_url),
        ("cancel_url", s.billing_cancel_url),
        ("allow_promotion_codes", "true"),
    ]
    return await _post("/checkout/sessions", form)


async def create_portal_session(customer_id: str) -> dict:
    s = get_settings()
    form = [("customer", customer_id), ("return_url", s.billing_portal_return_url)]
    return await _post("/billing_portal/sessions", form)


async def apply_customer_credit(customer_id: str, amount_cents: int, description: str) -> str:
    """Add account credit (negative balance transaction) toward future invoices."""
    form = [
        ("amount", str(-abs(amount_cents))),  # negative = credit to the customer
        ("currency", "usd"),
        ("description", description),
    ]
    res = await _post(f"/customers/{customer_id}/balance_transactions", form)
    return res["id"]


def verify_webhook(payload: bytes, sig_header: str, tolerance: int = 300) -> dict:
    """Verify a Stripe webhook signature and return the parsed event.

    Implements Stripe's scheme: signed_payload = "{t}.{body}", compared via HMAC-SHA256
    against the v1 signature in the Stripe-Signature header. Raises 400 on any mismatch.
    """
    secret = get_settings().stripe_webhook_secret
    if not secret:
        raise HTTPException(503, "Webhook secret not configured.")
    if not sig_header:
        raise HTTPException(400, "Missing Stripe-Signature header.")

    parts = {}
    for item in sig_header.split(","):
        if "=" in item:
            k, v = item.split("=", 1)
            parts.setdefault(k, v)
    timestamp, v1 = parts.get("t"), parts.get("v1")
    if not timestamp or not v1:
        raise HTTPException(400, "Malformed Stripe-Signature header.")

    try:
        if abs(int(time.time()) - int(timestamp)) > tolerance:
            raise HTTPException(400, "Webhook timestamp outside tolerance.")
    except ValueError:
        raise HTTPException(400, "Bad webhook timestamp.")

    signed = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, v1):
        raise HTTPException(400, "Webhook signature verification failed.")

    try:
        return json.loads(payload.decode())
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "Webhook payload is not valid JSON.")


def sign_payload(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    """Build a valid Stripe-Signature header for a payload. Used in tests and by any
    internal caller that needs to simulate Stripe; mirrors verify_webhook exactly."""
    ts = timestamp if timestamp is not None else int(time.time())
    signed = f"{ts}.".encode() + payload
    v1 = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={v1}"
