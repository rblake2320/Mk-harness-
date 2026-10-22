"""Crash-safe customer creation; the immutable intent is also the erasure anchor."""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select, update

from . import billing
from .models import BillingProvision, ErasureRequest


def account_available(db, user):
    db.refresh(user)
    return user.is_active and not db.scalar(select(ErasureRequest.id).where(
        ErasureRequest.tenant_id == user.tenant_id, ErasureRequest.subject_kind == "account",
        ErasureRequest.subject_id == user.id))


async def provision_customer(db, user):
    # The account lock serializes intent creation with erasure. Release before
    # HTTP. Concurrent callers share the same immutable idempotency identity.
    db.refresh(user, with_for_update=True)
    if not account_available(db, user):
        raise HTTPException(410, "Billing account is unavailable.")
    row = db.scalar(select(BillingProvision).where(BillingProvision.user_id == user.id,
        BillingProvision.tenant_id == user.tenant_id))
    if row is None:
        row = BillingProvision(tenant_id=user.tenant_id, user_id=user.id)
        db.add(row)
        db.flush()
    identity = row.id, row.tenant_id, row.user_id
    created = row.created_at.replace(tzinfo=timezone.utc) if row.created_at.tzinfo is None else row.created_at
    customer = row.stripe_customer_id
    db.commit()
    if customer is None:
        # Stripe may forget idempotency keys after 24h. Never POST an old intent.
        if datetime.now(timezone.utc) - created >= timedelta(hours=23):
            customer = await billing.find_customer(*identity)
        else:
            customer = await billing.create_customer(*identity)
        db.execute(update(BillingProvision).where(BillingProvision.id == identity[0],
            BillingProvision.stripe_customer_id.is_(None)).values(stripe_customer_id=customer))
        db.commit()
        db.refresh(row)
        if row.stripe_customer_id != customer:
            raise HTTPException(502, "BILLING_CUSTOMER_BINDING_INVALID")
    if not account_available(db, user):
        raise HTTPException(410, "Billing account is unavailable.")
    return customer
