"""Leased, ownership-bound Stripe cleanup. No ambiguous response is a receipt."""
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException
from sqlalchemy import select, update

from . import billing
from .models import BillingErasureBinding, BillingProvision, ErasureRequest, ErasureTask, Subscription

BILLING_KINDS = {"billing_provision", "billing_customer", "billing_subscription"}


def resolve_binding(db, request):
    """Merge compatible original/restored identity without resurrecting accounts."""
    original = db.scalar(select(BillingProvision).where(BillingProvision.tenant_id == request.tenant_id,
        BillingProvision.user_id == request.subject_id))
    restored = db.scalar(select(BillingErasureBinding).where(BillingErasureBinding.request_id == request.id,
        BillingErasureBinding.tenant_id == request.tenant_id, BillingErasureBinding.user_id == request.subject_id))
    if original and restored:
        original_time = original.created_at.replace(tzinfo=timezone.utc) if original.created_at.tzinfo is None else original.created_at
        restored_time = restored.created_at.replace(tzinfo=timezone.utc) if restored.created_at.tzinfo is None else restored.created_at
        if original.id != restored.id or (original.stripe_customer_id and restored.stripe_customer_id
                and original.stripe_customer_id != restored.stripe_customer_id) or original_time != restored_time:
            return None
        return restored if restored.stripe_customer_id else original
    return restored or original


class BillingErasureClient:
    async def request(self, method, path, *, form=None, params=None, idempotency_key=None):
        headers = billing._auth_headers()
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False, trust_env=False) as client:
            return await client.request(method, billing._API + path, headers=headers,
                params=params, content=urlencode(form).encode() if form else None)


class Unconfirmed(Exception):
    pass


async def _body(client, method, path, **kwargs):
    response = await client.request(method, path, **kwargs)
    if response.status_code != 200 or len(response.content) > 262144:
        raise Unconfirmed("BILLING_ERASURE_UNCONFIRMED")
    try:
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError()
        return body
    except ValueError:
        raise Unconfirmed("BILLING_RESPONSE_INVALID") from None


def _deleted(body, customer):
    return body.get("id") == customer and body.get("object") == "customer" and body.get("deleted") is True


async def deliver_billing_erasure(db, client, task_id):
    task = db.get(ErasureTask, task_id)
    if task is None or task.kind not in BILLING_KINDS:
        return False
    if task.confirmed_at is not None:
        return True
    request = db.get(ErasureRequest, task.request_id)
    provision = None
    if request and request.subject_kind == "account" and task.tenant_id == request.tenant_id:
        provision = resolve_binding(db, request)
    valid = provision is not None
    if valid and task.kind == "billing_provision":
        valid = task.target_id == provision.id
    if valid and task.kind == "billing_customer":
        valid = task.target_id == provision.stripe_customer_id
    if valid and task.kind == "billing_subscription":
        sub = db.scalar(select(Subscription).where(Subscription.tenant_id == request.tenant_id,
            Subscription.user_id == request.subject_id))
        valid = bool(sub and re.fullmatch(r"sub_[A-Za-z0-9]{1,60}", task.target_id)
            and sub.stripe_subscription_id == task.target_id
            and sub.stripe_customer_id == provision.stripe_customer_id)
    if not valid:
        task.status, task.last_error = "blocked", "BILLING_OWNERSHIP_BINDING_REQUIRED"
        task.next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        db.commit()
        return False
    metadata = billing.provision_metadata(provision.id, provision.tenant_id, provision.user_id)
    identity = dict(tenant_id=request.tenant_id, request_id=request.id, kind=task.kind, target_id=task.target_id)
    claim = [ErasureTask.id == task_id, *(getattr(ErasureTask, key) == value for key, value in identity.items())]
    customer, provision_id = provision.stripe_customer_id, provision.id
    created = provision.created_at
    created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
    lease, now, attempts = uuid.uuid4().hex, datetime.now(timezone.utc), task.attempts + 1
    changed = db.execute(update(ErasureTask).where(*claim, ErasureTask.confirmed_at.is_(None),
        ErasureTask.next_attempt_at <= now).values(lease_id=lease, attempts=ErasureTask.attempts + 1,
            next_attempt_at=now + timedelta(seconds=120)).execution_options(synchronize_session=False)).rowcount
    db.commit()  # no row locks or transactions span provider calls
    if not changed:
        return False
    receipt, error = None, "BILLING_ERASURE_UNCONFIRMED"
    try:
        if customer is None:
            if now - created < timedelta(hours=23):
                body = await _body(client, "POST", "/customers",
                    form=[(f"metadata[{key}]", value) for key, value in metadata.items()],
                    idempotency_key=f"mk-customer-v1-{provision_id}")
            else:
                # Search can find a previously accepted request after key expiry.
                # No/ambiguous result is pending, never proof of non-creation.
                result = await _body(client, "GET", "/customers/search",
                    params={"query": f"metadata['mk_provision']:'{provision_id}'", "limit": "2"})
                if result.get("object") != "search_result" or result.get("has_more") is not False or not isinstance(result.get("data"), list) or len(result["data"]) != 1:
                    raise Unconfirmed("BILLING_RECONCILIATION_REQUIRED")
                body = result["data"][0]
            if not billing.bound_customer(body, metadata):
                raise Unconfirmed("BILLING_CUSTOMER_BINDING_INVALID")
            customer = body["id"]
            binding_type = type(provision)
            db.execute(update(binding_type).where(binding_type.id == provision_id,
                binding_type.stripe_customer_id.is_(None)).values(stripe_customer_id=customer))
            db.commit()  # persist the binding BEFORE deletion can hide metadata
            db.refresh(provision)
            if provision.stripe_customer_id != customer:
                raise Unconfirmed("BILLING_CUSTOMER_BINDING_INVALID")
        if not re.fullmatch(r"cus_[A-Za-z0-9]{1,60}", customer):
            raise Unconfirmed("BILLING_CUSTOMER_BINDING_INVALID")
        # A previously bound deleted resource remains retrievable. A 404 or a
        # mismatched tombstone is not equivalent to this authenticated readback.
        body = await _body(client, "GET", f"/customers/{customer}")
        if not _deleted(body, customer):
            if not billing.bound_customer(body, metadata, customer):
                raise Unconfirmed("BILLING_CUSTOMER_BINDING_INVALID")
            if identity["kind"] != "billing_subscription":
                result = await _body(client, "DELETE", f"/customers/{customer}")
                if not _deleted(result, customer):
                    raise Unconfirmed("BILLING_ERASURE_UNCONFIRMED")
                body = await _body(client, "GET", f"/customers/{customer}")
                if not _deleted(body, customer):
                    raise Unconfirmed("BILLING_ERASURE_UNCONFIRMED")
        if identity["kind"] == "billing_subscription":
            subscription = await _body(client, "GET", f"/subscriptions/{identity['target_id']}")
            if subscription.get("object") != "subscription" or subscription.get("id") != identity["target_id"] or subscription.get("customer") != customer:
                raise Unconfirmed("BILLING_SUBSCRIPTION_BINDING_INVALID")
            # Customer deletion cancels active subscriptions. Do not introduce
            # a separate cancellation/proration/invoice side effect here.
            if subscription.get("status") != "canceled":
                raise Unconfirmed("BILLING_SUBSCRIPTION_PENDING")
        receipt = {"schema": 1, "provider": "stripe", **identity, "provision_id": provision_id,
            "customer_id": customer, "outcome": "subscription_canceled" if identity["kind"] == "billing_subscription" else "customer_deleted"}
        error = ""
    except Unconfirmed as exc:
        error = str(exc)  # only the closed, source-defined codes above
    except (httpx.RequestError, HTTPException):
        error = "BILLING_PROVIDER_UNAVAILABLE"
    now = datetime.now(timezone.utc)
    written = db.execute(update(ErasureTask).where(*claim, ErasureTask.lease_id == lease).values(
        status="confirmed" if receipt else "pending", confirmed_at=now if receipt else None,
        receipt_json=json.dumps(receipt or {}, sort_keys=True), last_error=error, lease_id=None,
        next_attempt_at=now + timedelta(seconds=min(300, 2 ** min(attempts, 8))))).rowcount
    db.commit()
    return receipt is not None and written == 1


async def drain_billing_erasures(db, client, limit=25):
    ids = list(db.scalars(select(ErasureTask.id).where(ErasureTask.kind.in_(BILLING_KINDS),
        ErasureTask.confirmed_at.is_(None), ErasureTask.next_attempt_at <= datetime.now(timezone.utc))
        .order_by(ErasureTask.next_attempt_at, ErasureTask.id).limit(limit)))
    db.commit()
    confirmed = 0
    for task_id in ids:
        confirmed += int(await deliver_billing_erasure(db, client, task_id))
    return confirmed
