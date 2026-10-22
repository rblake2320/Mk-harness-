"""Late billing events must not undo an account's erasure boundary."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import uuid

import httpx
import pytest
import respx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from starlette.requests import Request

from app import billing
from app.models import Base, ErasureRequest, ReferralCredit, Subscription, Tenant, User
from app.routes import billing as routes


@pytest.fixture
def erased_billing(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'billing-privacy.db'}")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        tenant = Tenant(name="Erased business"); db.add(tenant); db.flush()
        user_id = uuid.uuid4().hex
        user = User(id=user_id, tenant_id=tenant.id, email=f"deleted_{user_id}@deleted",
            password_hash="", display_name="", is_active=False)
        db.add(user); db.flush()
        now = datetime.now(timezone.utc)
        request = ErasureRequest(tenant_id=tenant.id, requested_by=user.id,
            subject_kind="account", subject_id=user.id, due_at=now + timedelta(days=30),
            backup_expires_at=now + timedelta(days=35))
        subscription = Subscription(tenant_id=tenant.id, user_id=user.id,
            stripe_customer_id="cus_PrivacyControl", stripe_subscription_id="sub_PrivacyControl",
            status="deletion_pending")
        db.add_all([request, subscription]); db.commit()
        yield db, user, subscription
    engine.dispose()


async def deliver(event, db):
    payload = json.dumps(event).encode()
    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}
    request = Request({"type": "http", "method": "POST", "path": "/api/billing/webhook",
        "headers": [(b"stripe-signature", billing.sign_payload(payload, "whsec_test_dummy").encode())]}, receive)
    return await routes.webhook(request, db)


@pytest.mark.parametrize("kind", ["checkout.session.completed", "customer.subscription.created",
    "customer.subscription.updated", "customer.subscription.deleted", "invoice.paid", "invoice.payment_succeeded"])
def test_late_valid_webhook_cannot_rewrite_erased_account_billing(erased_billing, kind):
    db, user, subscription = erased_billing
    before = {column.name: getattr(subscription, column.name) for column in Subscription.__table__.columns}
    event = {"type": kind, "data": {"object": {"id": "sub_NewLateObject", "customer": subscription.stripe_customer_id,
        "subscription": "sub_NewLateObject", "client_reference_id": user.id, "status": "active"}}}
    assert asyncio.run(deliver(event, db)) == {"received": True}
    db.refresh(subscription)
    after = {column.name: getattr(subscription, column.name) for column in Subscription.__table__.columns}
    # SQLite drops timezone information during readback; compare timestamps as UTC wall time.
    normalize = lambda values: {key: value.replace(tzinfo=None) if isinstance(value, datetime) else value for key, value in values.items()}
    assert normalize(after) == normalize(before)


@respx.mock
def test_future_referral_payment_cannot_recreate_deleted_referrers_billing(erased_billing):
    db, erased, subscription = erased_billing
    subscription.stripe_customer_id = None
    referred = User(tenant_id=erased.tenant_id, email="synthetic-active-referral@example.test",
        password_hash="synthetic", referred_by=erased.id)
    db.add(referred); db.commit()
    create = respx.post("https://api.stripe.com/v1/customers").mock(return_value=httpx.Response(200, json={"id": "cus_MustNotCreate"}))
    credit = respx.post("https://api.stripe.com/v1/customers/cus_MustNotCreate/balance_transactions").mock(
        return_value=httpx.Response(200, json={"id": "ibt_MustNotCreate"}))
    asyncio.run(routes._maybe_award_referral(db, referred))
    db.commit()
    assert not create.called and not credit.called
    assert not db.scalar(select(ReferralCredit.id).where(ReferralCredit.user_id == erased.id))
    assert subscription.stripe_customer_id is None
