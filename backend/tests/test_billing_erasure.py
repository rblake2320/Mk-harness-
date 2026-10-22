"""Provider-wire recovery controls. All Stripe calls are intercepted by respx."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import billing
from app.billing_erasure import BillingErasureClient, deliver_billing_erasure
from app.billing_provision import provision_customer
from app.models import Base, BillingProvision, ErasureTask, Subscription, Tenant, User
from app.privacy import erase_account

API = "https://api.stripe.com/v1"


@pytest.fixture
def pending(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'cleanup.db'}")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        tenant = Tenant(name="Synthetic billing cleanup"); db.add(tenant); db.flush()
        user = User(tenant_id=tenant.id, email="synthetic-erase@example.test", password_hash="synthetic")
        db.add(user); db.flush()
        provision = BillingProvision(tenant_id=tenant.id, user_id=user.id)
        db.add(provision); db.commit()
        request = erase_account(db, user); db.commit()
        task = db.scalar(select(ErasureTask).where(ErasureTask.request_id == request.id,
            ErasureTask.kind == "billing_provision"))
        yield db, user, provision, task
    engine.dispose()


def customer(provision, *, deleted=False):
    body = {"id": "cus_ErasureFixture", "object": "customer"}
    if deleted:
        body["deleted"] = True
    else:
        body["metadata"] = billing.provision_metadata(provision.id, provision.tenant_id, provision.user_id)
    return body


def retry_now(db, task):
    db.refresh(task)
    task.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()


@respx.mock
def test_unknown_creation_recovered_same_key_deleted_and_read_back(pending):
    db, user, provision, task = pending
    state = {"deleted": False}
    def create(request):
        form = parse_qs(request.content.decode())
        assert not any(key in form for key in ("email", "name", "phone"))
        assert request.headers["Idempotency-Key"] == f"mk-customer-v1-{provision.id}"
        return httpx.Response(200, json=customer(provision))
    def delete(request):
        with Session(db.bind) as independent:
            assert independent.get(BillingProvision, provision.id).stripe_customer_id == "cus_ErasureFixture"
        state["deleted"] = True
        return httpx.Response(200, json=customer(provision, deleted=True))
    post = respx.post(API + "/customers").mock(side_effect=create)
    get = respx.get(API + "/customers/cus_ErasureFixture").mock(
        side_effect=lambda _: httpx.Response(200, json=customer(provision, deleted=state["deleted"])))
    remove = respx.delete(API + "/customers/cus_ErasureFixture").mock(side_effect=delete)
    assert asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
    assert (post.call_count, get.call_count, remove.call_count) == (1, 2, 1)
    db.refresh(task)
    assert task.confirmed_at and task.status == "confirmed"
    assert "synthetic-erase" not in task.receipt_json
    assert json.loads(task.receipt_json)["customer_id"] == "cus_ErasureFixture"


@respx.mock
def test_lost_delete_response_retries_only_authenticated_tombstone(pending):
    db, user, provision, task = pending
    provision.stripe_customer_id = "cus_ErasureFixture"; db.commit()
    state = {"deleted": False}
    respx.get(API + "/customers/cus_ErasureFixture").mock(
        side_effect=lambda _: httpx.Response(200, json=customer(provision, deleted=state["deleted"])))
    def lost_response(request):
        state["deleted"] = True
        raise httpx.ReadTimeout("synthetic_secret_should_not_persist", request=request)
    remove = respx.delete(API + "/customers/cus_ErasureFixture").mock(side_effect=lost_response)
    assert not asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
    db.refresh(task)
    assert task.confirmed_at is None and task.last_error == "BILLING_PROVIDER_UNAVAILABLE"
    retry_now(db, task)
    assert asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
    assert remove.call_count == 1


@pytest.mark.parametrize("fault", ["cross_tenant", "cross_user", "cross_intent", "wrong_id", "missing_metadata", "404", "redirect", "deleted_string", "nonobject", "huge"])
@respx.mock
def test_ambiguous_or_crossed_customer_never_deleted_or_confirmed(pending, fault):
    db, user, provision, task = pending
    provision.stripe_customer_id = "cus_ErasureFixture"; db.commit()
    body = customer(provision)
    if fault.startswith("cross_"):
        key = {"cross_tenant": "mk_tenant", "cross_user": "mk_user", "cross_intent": "mk_provision"}[fault]
        body["metadata"][key] = "f" * 32
    if fault == "wrong_id": body["id"] = "cus_Other"
    if fault == "missing_metadata": body.pop("metadata")
    if fault == "deleted_string": body = {**customer(provision, deleted=True), "deleted": "true"}
    if fault == "nonobject": body = []
    if fault == "huge": body["content"] = "x" * 262145
    status = 404 if fault == "404" else 302 if fault == "redirect" else 200
    respx.get(API + "/customers/cus_ErasureFixture").mock(return_value=httpx.Response(status, json=body,
        headers={"Location": "https://untrusted.example.test/steal"}))
    assert not asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
    db.refresh(task)
    assert task.confirmed_at is None and task.receipt_json == "{}"
    assert len(respx.calls) == 1


@pytest.mark.parametrize("age_hours,found", [(24, True), (24, False), (48, True)])
@respx.mock
def test_expired_idempotency_uses_search_never_recreates(pending, age_hours, found):
    db, user, provision, task = pending
    provision.created_at = datetime.now(timezone.utc) - timedelta(hours=age_hours); db.commit()
    respx.get(API + "/customers/search").mock(return_value=httpx.Response(200, json={
        "object": "search_result", "data": [customer(provision)] if found else [], "has_more": False}))
    state = {"deleted": False}
    respx.get(API + "/customers/cus_ErasureFixture").mock(side_effect=lambda _:
        httpx.Response(200, json=customer(provision, deleted=state["deleted"])))
    def remove(_):
        state["deleted"] = True
        return httpx.Response(200, json=customer(provision, deleted=True))
    respx.delete(API + "/customers/cus_ErasureFixture").mock(side_effect=remove)
    assert asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id)) is found
    assert all(call.request.method != "POST" for call in respx.calls)


@respx.mock
def test_legacy_unbound_task_and_crossed_intent_make_no_provider_call(pending):
    db, user, provision, task = pending
    for kind, target in [("billing_customer", "cus_Unknown"), ("billing_provision", "a" * 32)]:
        task.kind, task.target_id = kind, target; db.commit()
        assert not asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
        assert not respx.calls
        db.refresh(task)
        assert task.last_error == "BILLING_OWNERSHIP_BINDING_REQUIRED"


@respx.mock
def test_live_lease_prevents_duplicate_delivery(pending):
    db, user, provision, task = pending
    task.lease_id = "a" * 32
    task.next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=2); db.commit()
    assert not asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
    assert not respx.calls


@respx.mock
def test_customer_created_once_across_response_loss_and_retry(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'retry.db'}"); Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        tenant = Tenant(name="Synthetic retry"); db.add(tenant); db.flush()
        user = User(tenant_id=tenant.id, email="synthetic@example.test", password_hash="synthetic")
        db.add(user); db.commit()
        keys, bodies = [], []
        def create(request):
            keys.append(request.headers["Idempotency-Key"]); bodies.append(request.content)
            if len(keys) == 1:
                raise httpx.ReadTimeout("synthetic lost response", request=request)
            row = db.scalar(select(BillingProvision))
            return httpx.Response(200, json=customer(row))
        respx.post(API + "/customers").mock(side_effect=create)
        with pytest.raises(httpx.ReadTimeout): asyncio.run(provision_customer(db, user))
        assert asyncio.run(provision_customer(db, user)) == "cus_ErasureFixture"
        assert keys[0] == keys[1] and bodies[0] == bodies[1]
        assert b"synthetic@example.test" not in bodies[0]
    engine.dispose()


@pytest.mark.parametrize("fault", ["wrong_customer", "wrong_id", "active", "canceled"])
@respx.mock
def test_subscription_receipt_requires_exact_binding_and_canceled_readback(pending, fault):
    db, user, provision, task = pending
    provision.stripe_customer_id = "cus_ErasureFixture"
    # SQLite fixture represents a mirror retained from before the erasure.
    db.add(Subscription(tenant_id=user.tenant_id, user_id=user.id, status="deletion_pending",
        stripe_customer_id="cus_ErasureFixture", stripe_subscription_id="sub_ErasureFixture"))
    task.kind, task.target_id = "billing_subscription", "sub_ErasureFixture"; db.commit()
    respx.get(API + "/customers/cus_ErasureFixture").mock(
        return_value=httpx.Response(200, json=customer(provision, deleted=True)))
    body = {"id": "sub_ErasureFixture", "object": "subscription", "customer": "cus_ErasureFixture", "status": "canceled"}
    if fault == "wrong_customer": body["customer"] = "cus_Other"
    if fault == "wrong_id": body["id"] = "sub_Other"
    if fault == "active": body["status"] = "active"
    respx.get(API + "/subscriptions/sub_ErasureFixture").mock(return_value=httpx.Response(200, json=body))
    assert asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id)) is (fault == "canceled")
    assert all(call.request.method == "GET" for call in respx.calls)


@pytest.mark.parametrize("changed", ["lease", "target"])
@respx.mock
def test_stale_worker_cannot_commit_receipt_for_changed_task(pending, changed):
    db, user, provision, task = pending
    provision.stripe_customer_id = "cus_ErasureFixture"; db.commit()
    def changed_during_http(_):
        with Session(db.bind) as independent:
            row = independent.get(ErasureTask, task.id)
            if changed == "lease": row.lease_id = "b" * 32
            else: row.target_id = "b" * 32
            independent.commit()
        return httpx.Response(200, json=customer(provision, deleted=True))
    respx.get(API + "/customers/cus_ErasureFixture").mock(side_effect=changed_during_http)
    assert not asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
    db.refresh(task)
    assert task.confirmed_at is None and task.receipt_json == "{}"


@pytest.mark.parametrize("fault", ["wrong_delete_id", "not_deleted", "readback_active", "readback_missing"])
@respx.mock
def test_delete_acceptance_requires_matching_deleted_readback(pending, fault):
    db, user, provision, task = pending
    provision.stripe_customer_id = "cus_ErasureFixture"; db.commit()
    reads = [httpx.Response(200, json=customer(provision))]
    reads.append(httpx.Response(404, json={}) if fault == "readback_missing" else
        httpx.Response(200, json=customer(provision, deleted=fault != "readback_active")))
    respx.get(API + "/customers/cus_ErasureFixture").mock(side_effect=reads)
    result = customer(provision, deleted=True)
    if fault == "wrong_delete_id": result["id"] = "cus_Other"
    if fault == "not_deleted": result["deleted"] = False
    respx.delete(API + "/customers/cus_ErasureFixture").mock(return_value=httpx.Response(200, json=result))
    assert not asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
    db.refresh(task)
    assert task.confirmed_at is None


@pytest.mark.parametrize("matches,readback", [(0, True), (1, True), (2, True), (1, False)])
@respx.mock
def test_active_customer_reconciliation_after_key_expiry_is_read_only(tmp_path, matches, readback):
    engine = create_engine(f"sqlite:///{tmp_path / 'expired.db'}"); Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        tenant = Tenant(name="Synthetic late recovery"); db.add(tenant); db.flush()
        user = User(tenant_id=tenant.id, email="synthetic@example.test", password_hash="synthetic")
        db.add(user); db.flush()
        row = BillingProvision(tenant_id=tenant.id, user_id=user.id,
            created_at=datetime.now(timezone.utc) - timedelta(hours=24))
        db.add(row); db.commit()
        respx.get(API + "/customers/search").mock(return_value=httpx.Response(200,
            json={"object": "search_result", "data": [customer(row)] * matches, "has_more": False}))
        respx.get(API + "/customers/cus_ErasureFixture").mock(return_value=httpx.Response(200,
            json=customer(row, deleted=not readback)))
        if matches == 1 and readback:
            assert asyncio.run(provision_customer(db, user)) == "cus_ErasureFixture"
        else:
            with pytest.raises(billing.HTTPException, match="BILLING_RECONCILIATION_REQUIRED"):
                asyncio.run(provision_customer(db, user))
        assert all(call.request.method == "GET" for call in respx.calls)
    engine.dispose()
