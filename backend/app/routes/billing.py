"""Subscription billing: Stripe Checkout (annual-first), customer portal, lifecycle
webhook, and the referral-credit engine.

Flow:
  POST /api/billing/checkout  -> returns a Stripe Checkout URL (90-day trial, annual-first)
  GET  /api/billing/me        -> current subscription + referral status
  GET  /api/billing/plans     -> tier:interval options the server is configured to sell
  POST /api/billing/portal    -> Stripe customer portal URL (manage / cancel)
  POST /api/billing/webhook   -> Stripe -> us: drives status + applies referral credit

Enforcement (gating AI on an active sub) lives behind settings.billing_enforced and the
require_active_subscription dependency, so it is off until launch flips it on.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import billing
from ..config import get_settings
from ..db import get_db
from ..models import AuditLog, ReferralCredit, Subscription, User
from ..security import get_current_user

router = APIRouter(prefix="/billing", tags=["billing"])

_ACTIVE = ("trialing", "active")


def _ts(unix: int | None) -> datetime | None:
    return datetime.fromtimestamp(unix, tz=timezone.utc) if unix else None


def _get_or_create_sub(db: Session, user: User) -> Subscription:
    sub = db.scalar(select(Subscription).where(Subscription.user_id == user.id))
    if not sub:
        sub = Subscription(tenant_id=user.tenant_id, user_id=user.id, status="none")
        db.add(sub)
        db.flush()
    return sub


class CheckoutIn(BaseModel):
    tier: str
    interval: str = "year"   # annual-first default


@router.get("/plans")
def plans():
    """What the server is configured to sell, derived from the STRIPE_PRICES map."""
    s = get_settings()
    keys = sorted(s.stripe_price_map.keys())
    return {
        "configured": billing.billing_configured(),
        "trial_days": s.billing_trial_days,
        "plans": [{"tier": k.split(":")[0], "interval": k.split(":")[1]} for k in keys if ":" in k],
    }


@router.get("/me")
def my_billing(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sub = db.scalar(select(Subscription).where(Subscription.user_id == user.id))
    pending = db.scalars(select(ReferralCredit).where(
        ReferralCredit.user_id == user.id)).all()
    earned_cents = sum(c.amount_cents for c in pending)
    return {
        "status": sub.status if sub else "none",
        "tier": sub.tier if sub else "",
        "interval": sub.interval if sub else "",
        "trial_end": sub.trial_end.isoformat() if sub and sub.trial_end else None,
        "current_period_end": (sub.current_period_end.isoformat()
                               if sub and sub.current_period_end else None),
        "active": bool(sub and sub.status in _ACTIVE),
        "referral_code": user.referral_code,
        "referral_credits_earned_cents": earned_cents,
        "referral_count": len(pending),
    }


@router.post("/checkout")
async def checkout(body: CheckoutIn, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    s = get_settings()
    key = f"{body.tier}:{body.interval}"
    price_id = s.stripe_price_map.get(key)
    if not price_id:
        raise HTTPException(422, f"No plan configured for '{key}'. See GET /api/billing/plans.")

    sub = _get_or_create_sub(db, user)
    if not sub.stripe_customer_id:
        sub.stripe_customer_id = await billing.create_customer(user.email, user.id)
    # Record the chosen plan now; the webhook confirms activation.
    sub.tier, sub.interval = body.tier, body.interval
    sub.updated_at = datetime.now(timezone.utc)
    db.commit()

    session = await billing.create_checkout_session(
        customer_id=sub.stripe_customer_id, price_id=price_id,
        trial_days=s.billing_trial_days, client_reference_id=user.id)
    return {"url": session.get("url"), "session_id": session.get("id")}


@router.post("/portal")
async def portal(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sub = db.scalar(select(Subscription).where(Subscription.user_id == user.id))
    if not sub or not sub.stripe_customer_id:
        raise HTTPException(404, "No billing account yet — start a subscription first.")
    session = await billing.create_portal_session(sub.stripe_customer_id)
    return {"url": session.get("url")}


# --------------------------------------------------------------------------- #
# Webhook — Stripe is the source of truth for subscription state.
# --------------------------------------------------------------------------- #
def _sub_by_customer(db: Session, customer_id: str) -> Subscription | None:
    return db.scalar(select(Subscription).where(Subscription.stripe_customer_id == customer_id))


async def _maybe_award_referral(db: Session, referred: User) -> None:
    """On a referred user's first payment, credit the referrer once."""
    if not referred.referred_by:
        return
    exists = db.scalar(select(ReferralCredit).where(
        ReferralCredit.referred_user_id == referred.id))
    if exists:
        return
    referrer = db.get(User, referred.referred_by)
    if not referrer:
        return
    s = get_settings()
    credit = ReferralCredit(
        tenant_id=referrer.tenant_id, user_id=referrer.id, referred_user_id=referred.id,
        amount_cents=s.referral_credit_cents, status="pending")
    db.add(credit)
    db.flush()
    # Ensure the referrer has a Stripe customer to hold the credit, then apply it.
    ref_sub = _get_or_create_sub(db, referrer)
    try:
        if not ref_sub.stripe_customer_id:
            ref_sub.stripe_customer_id = await billing.create_customer(referrer.email, referrer.id)
        txn = await billing.apply_customer_credit(
            ref_sub.stripe_customer_id, s.referral_credit_cents,
            f"Referral credit: {referred.email}")
        credit.status = "applied"
        credit.stripe_txn_id = txn
        credit.applied_at = datetime.now(timezone.utc)
    except HTTPException:
        # Leave as pending; a retry/backfill job can apply it later.
        pass


@router.post("/webhook")
async def webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    event = billing.verify_webhook(payload, request.headers.get("Stripe-Signature", ""))
    etype = event.get("type", "")
    obj = event.get("data", {}).get("object", {})

    if etype == "checkout.session.completed":
        user_id = obj.get("client_reference_id")
        customer_id = obj.get("customer")
        sub = db.scalar(select(Subscription).where(Subscription.user_id == user_id)) if user_id else None
        if sub:
            sub.stripe_customer_id = customer_id or sub.stripe_customer_id
            sub.stripe_subscription_id = obj.get("subscription") or sub.stripe_subscription_id
            if sub.status == "none":
                sub.status = "trialing" if get_settings().billing_trial_days > 0 else "active"
            sub.updated_at = datetime.now(timezone.utc)
            db.add(AuditLog(tenant_id=sub.tenant_id, user_id=user_id,
                            action="billing.checkout", detail=sub.tier))

    elif etype in ("customer.subscription.created", "customer.subscription.updated"):
        sub = _sub_by_customer(db, obj.get("customer", ""))
        if sub:
            sub.stripe_subscription_id = obj.get("id") or sub.stripe_subscription_id
            sub.status = obj.get("status", sub.status)
            sub.trial_end = _ts(obj.get("trial_end")) or sub.trial_end
            sub.current_period_end = _ts(obj.get("current_period_end")) or sub.current_period_end
            sub.updated_at = datetime.now(timezone.utc)

    elif etype == "customer.subscription.deleted":
        sub = _sub_by_customer(db, obj.get("customer", ""))
        if sub:
            sub.status = "canceled"
            sub.updated_at = datetime.now(timezone.utc)

    elif etype in ("invoice.paid", "invoice.payment_succeeded"):
        sub = _sub_by_customer(db, obj.get("customer", ""))
        if sub:
            if not sub.first_paid_at:
                sub.first_paid_at = datetime.now(timezone.utc)
            if sub.status in ("none", "trialing", "past_due"):
                sub.status = "active"
            sub.updated_at = datetime.now(timezone.utc)
            referred = db.get(User, sub.user_id)
            if referred:
                await _maybe_award_referral(db, referred)

    db.commit()
    return {"received": True}
