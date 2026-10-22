"""Session revocation is committed locally before attempting kernel delivery.

Only an exact successful kernel receipt completes delivery. The outbox survives
the requesting session's logout and can be safely retried after a lost response.
"""
import hashlib
import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .kernel import KernelClient, KernelUnavailable, get_kernel_client
from .models import AuditLog, AuthRevocation, AuthSession


def nonce_digest(nonce: str) -> str:
    return hashlib.sha256(nonce.encode()).hexdigest()


def revoke_local(db: Session, session: AuthSession, *, by: str, reason: str) -> None:
    now = datetime.now(timezone.utc)
    changed = db.execute(update(AuthSession).where(AuthSession.id == session.id,
        AuthSession.tenant_id == session.tenant_id, AuthSession.revoked_at.is_(None)).values(revoked_at=now)).rowcount
    if changed:
        db.add(AuthRevocation(session_id=session.id, tenant_id=session.tenant_id, user_id=session.user_id))
        db.add(AuditLog(tenant_id=session.tenant_id, user_id=by, action="auth.session.revoke", detail=reason))


def valid_receipt(status: int, body: object) -> bool:
    if status != 201 or not isinstance(body, dict):
        return False
    try:
        uuid.UUID(body["revocation_id"])
        stamp = datetime.fromisoformat(body["revoked_at"].replace("Z", "+00:00"))
        return stamp.tzinfo is not None and type(body["approvals_revoked"]) is int and body["approvals_revoked"] >= 0
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


async def deliver_revocation(db: Session, client: KernelClient, row: AuthRevocation | None) -> bool:
    if row is None:
        return False
    if row.confirmed_at:
        return True
    sid, user_id, tenant_id = row.session_id, row.user_id, row.tenant_id
    attempts = row.attempts + 1
    lease = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    # Atomic lease coordinates API requests and multiple app workers. A crashed
    # delivery is retried after the lease expires; no database lock spans HTTP.
    changed = db.execute(update(AuthRevocation).where(AuthRevocation.session_id == sid,
        AuthRevocation.confirmed_at.is_(None), AuthRevocation.next_attempt_at <= now).values(
            lease_id=lease, next_attempt_at=now + timedelta(seconds=max(60, client.timeout + 15)),
            attempts=AuthRevocation.attempts + 1).execution_options(synchronize_session=False)).rowcount
    db.commit()
    if not changed:
        return False
    # Dedicated service authority is route-scoped in the kernel. Revoking the
    # target user/session cannot disable delivery. It cannot read data, register
    # passkeys, approve, propose or dispatch, even if replayed on another route.
    try:
        service_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"mk:session-revocation:{tenant_id}"))
        response = await client.call("POST", "/revocations", user_id=service_id, tenant_id=tenant_id,
            roles=["session_revoker"], session_id=f"revocation-delivery:{lease}",
            json={"session_id": sid, "user_id": str(uuid.UUID(user_id)), "reason": "application session revoked"})
    except KernelUnavailable as exc:
        error = exc.code[:80]
        confirmed = False
    else:
        confirmed = valid_receipt(response.status_code, response.body)
        error = "" if confirmed else f"KERNEL_REVOCATION_UNCONFIRMED_{response.status_code}"
    now = datetime.now(timezone.utc)
    db.execute(update(AuthRevocation).where(AuthRevocation.session_id == sid, AuthRevocation.lease_id == lease).values(
        confirmed_at=now if confirmed else None, last_error=error, lease_id=None,
        next_attempt_at=now + timedelta(seconds=min(300, 2 ** min(attempts, 8)))))
    db.commit()
    return confirmed


async def drain_revocations(db: Session, client: KernelClient, limit: int = 50) -> int:
    ids = list(db.scalars(select(AuthRevocation.session_id).where(AuthRevocation.confirmed_at.is_(None))
                         .where(AuthRevocation.next_attempt_at <= datetime.now(timezone.utc))
                         .order_by(AuthRevocation.created_at).limit(limit)))
    db.commit()  # do not hold a read transaction while awaiting the kernel
    confirmed = 0
    for sid in ids:
        row = db.get(AuthRevocation, sid)
        if row and await deliver_revocation(db, client, row):
            confirmed += 1
    return confirmed


async def revocation_worker(stop: asyncio.Event, interval: float = 5.0, session_factory=None,
                            client: KernelClient | None = None) -> None:
    """Always-on durable delivery; restart needs neither a browser nor its JWT."""
    from . import db as dbmod
    factory = session_factory or dbmod._SessionLocal
    kernel = client or get_kernel_client()
    while not stop.is_set():
        try:
            with factory() as db:
                await drain_revocations(db, kernel)
        except Exception as exc:
            # Never print JWTs, HTTP bodies, database parameters or credentials.
            logging.getLogger(__name__).error("auth revocation worker failure: %s", type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
