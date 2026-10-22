"""Durable kernel erasure delivery. Transport success is never erasure proof.

Other task kinds have separate executors; a kernel receipt cannot discharge
provider resource cancellation, backup expiry, or the external restore anchor.
"""
import json
import uuid
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from .kernel import KernelUnavailable
from .models import ErasureRequest, ErasureTask

KERNEL_KINDS = {"kernel_contact": ("customer", "contact"), "kernel_account": ("account", "account")}
COUNT_FIELDS = ("pending_provider_deletions", "pending_provider_retention", "blocked_actions", "pending_sender_cleanup")


def bound_receipt(status, body, *, tenant_id, request_id, subject_kind, subject_id):
    """Return only validated, content-free fields. Reject crossed/partial shapes."""
    if status != 201 or not isinstance(body, dict):
        return None
    expected = dict(tenant_id=tenant_id, request_id=request_id, subject_id=subject_id)
    try:
        if any(uuid.UUID(body[key]) != uuid.UUID(value) for key, value in expected.items()):
            return None
        if body["subject_kind"] != subject_kind or type(body["active_content_erased"]) is not bool:
            return None
        if any(type(body[key]) is not int or not 0 <= body[key] <= 2**63 - 1 for key in COUNT_FIELDS):
            return None
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
    return {**{key: str(uuid.UUID(value)) for key, value in expected.items()},
            "subject_kind": subject_kind, "active_content_erased": body["active_content_erased"],
            **{key: body[key] for key in COUNT_FIELDS}}


async def deliver_kernel_erasure(db, client, task_id):
    row = db.get(ErasureTask, task_id)
    if row is None or row.kind not in KERNEL_KINDS:
        return False
    if row.confirmed_at is not None:
        return True
    request = db.get(ErasureRequest, row.request_id)
    expected_app_kind, subject_kind = KERNEL_KINDS[row.kind]
    # These identities come from the immutable tombstone, never from a user
    # supplied retry payload or a mutable outbox target alone.
    try:
        if request is None or request.tenant_id != row.tenant_id or request.subject_kind != expected_app_kind or request.subject_id != row.target_id:
            raise ValueError("unbound outbox task")
        tenant_id, request_id, subject_id = (str(uuid.UUID(value)) for value in
            (request.tenant_id, request.id, request.subject_id))
    except (ValueError, AttributeError, TypeError):
        row.status = "blocked"
        row.last_error = "ERASURE_IDENTITY_INVALID"
        row.next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        db.commit()
        return False
    attempts, lease = row.attempts + 1, uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    changed = db.execute(update(ErasureTask).where(ErasureTask.id == task_id,
        ErasureTask.confirmed_at.is_(None), ErasureTask.next_attempt_at <= now).values(
            attempts=ErasureTask.attempts + 1, lease_id=lease,
            next_attempt_at=now + timedelta(seconds=max(60, client.timeout + 15)))
        .execution_options(synchronize_session=False)).rowcount
    db.commit()  # no database locks are held over network I/O
    if not changed:
        return False
    receipt, confirmed, error = None, False, "KERNEL_ERASURE_UNCONFIRMED"
    try:
        service_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"mk:privacy-erasure:{tenant_id}"))
        response = await client.call("POST", "/privacy/erase", user_id=service_id,
            tenant_id=tenant_id, roles=["privacy_eraser"], session_id=f"privacy-delivery:{lease}",
            json={"request_id": request_id, "subject_kind": subject_kind, "subject_id": subject_id})
        receipt = bound_receipt(response.status_code, response.body, tenant_id=tenant_id,
            request_id=request_id, subject_kind=subject_kind, subject_id=subject_id)
        if receipt is not None:
            confirmed = receipt["active_content_erased"] and all(receipt[key] == 0 for key in COUNT_FIELDS)
            error = "" if confirmed else "KERNEL_ERASURE_PENDING"
    except KernelUnavailable:
        error = "KERNEL_ERASURE_UNAVAILABLE"
    now = datetime.now(timezone.utc)
    written = db.execute(update(ErasureTask).where(ErasureTask.id == task_id, ErasureTask.lease_id == lease).values(
        status="confirmed" if confirmed else "pending", confirmed_at=now if confirmed else None,
        receipt_json=json.dumps(receipt or {}, sort_keys=True), last_error=error, lease_id=None,
        next_attempt_at=now + timedelta(seconds=min(300, 2 ** min(attempts, 8))))).rowcount
    db.commit()
    return confirmed and written == 1


async def drain_kernel_erasures(db, client, limit=25):
    ids = list(db.scalars(select(ErasureTask.id).where(ErasureTask.kind.in_(KERNEL_KINDS),
        ErasureTask.confirmed_at.is_(None), ErasureTask.next_attempt_at <= datetime.now(timezone.utc))
        .order_by(ErasureTask.next_attempt_at, ErasureTask.id).limit(limit)))
    db.commit()
    confirmed = 0
    for task_id in ids:
        confirmed += int(await deliver_kernel_erasure(db, client, task_id))
    return confirmed


async def privacy_worker(stop, interval=5.0, session_factory=None, client=None, billing_client=None):
    from . import db as dbmod
    from .kernel import get_kernel_client
    from .billing import billing_configured
    from .billing_erasure import BillingErasureClient, drain_billing_erasures
    factory, kernel = session_factory or dbmod._SessionLocal, client or get_kernel_client()
    stripe = billing_client or BillingErasureClient()
    while not stop.is_set():
        try:
            with factory() as db:
                await drain_kernel_erasures(db, kernel)
        except Exception as exc:
            logging.getLogger(__name__).error("privacy delivery worker failure: %s", type(exc).__name__)
        try:
            if billing_configured():
                with factory() as db:
                    await drain_billing_erasures(db, stripe)
        except Exception as exc:
            logging.getLogger(__name__).error("billing erasure worker failure: %s", type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
