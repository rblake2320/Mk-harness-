"""Transactional active-store erasure and durable, content-free downstream work.

The request is not a completion certificate. Kernel/provider work, the external
restore ledger and backup expiry each need their own verified receipt. Retention
periods below are the completion contract's engineering defaults, not legal advice.
"""
import json
import jwt
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import delete, select, update, or_
from sqlalchemy.orm import Session

from .auth_sessions import revoke_local
from .config import get_settings
from .models import (
    ActionLink, AuditLog, AuthFactor, AuthRecoveryCode, AuthSession, BriefItem,
    Commitment, ConsentEvent, ConsentRecord, ConsultantProfile, ContactPreference,
    Conversation, Customer, CustomerDestination, DraftVersion, ErasureRequest,
    ErasureTask, ExceptionRecord, ImportJob, ImportRow, InboundApplication, Message,
    Outcome, ProviderKey, RetainedConsent, SenderIdentity, SkinAnalysis,
    Subscription, SuppressionEvent, Tenant, UsageRecord, User,
)


def _task(db, request, kind, target_id):
    existing = db.scalar(select(ErasureTask).where(ErasureTask.request_id == request.id,
        ErasureTask.kind == kind, ErasureTask.target_id == target_id))
    if existing is None:
        db.add(ErasureTask(request_id=request.id, tenant_id=request.tenant_id,
                           kind=kind, target_id=target_id))
        db.flush()


def _request(db, tenant_id, actor, kind, subject_id, *, stamp=None):
    existing = db.scalar(select(ErasureRequest).where(ErasureRequest.tenant_id == tenant_id,
        ErasureRequest.subject_kind == kind, ErasureRequest.subject_id == subject_id))
    stamp = stamp or datetime.now(timezone.utc)
    request = existing or ErasureRequest(tenant_id=tenant_id, requested_by=actor,
        subject_kind=kind, subject_id=subject_id, requested_at=stamp,
        due_at=stamp + timedelta(days=30), backup_expires_at=stamp + timedelta(days=35))
    if not existing:
        db.add(request); db.flush()
    _task(db, request, "restore_ledger_anchor", request.id)
    _task(db, request, "backup_expiry", request.id)
    return request


def _retain_consent(db, request, row, kind):
    if db.scalar(select(RetainedConsent.id).where(RetainedConsent.tenant_id == request.tenant_id,
            RetainedConsent.source_kind == kind, RetainedConsent.source_id == row.id)):
        return
    # Explicit allowlist: never archive names, numbers, free-form evidence refs,
    # notes, original message bodies, ciphertext or a copy of the source row.
    fields = ("channel", "evidence_digest", "effective_at", "expires_at") if kind == "outreach" else (
        "text_sha256", "granted_at")
    proof = {name: (value.isoformat() if isinstance(value, datetime) else value)
             for name in fields if (value := getattr(row, name)) is not None}
    proof["revoked_at"] = request.requested_at.isoformat()
    try:
        retain_until = request.requested_at.replace(year=request.requested_at.year + 5)
    except ValueError:  # a leap-day grant expires on February 28 five years later
        retain_until = request.requested_at.replace(year=request.requested_at.year + 5, day=28)
    db.add(RetainedConsent(tenant_id=request.tenant_id, request_id=request.id,
        source_kind=kind, source_id=row.id, proof_json=json.dumps(proof, sort_keys=True),
        retain_until=retain_until))


def erase_customer(db: Session, user: User, customer_id: str, *, replay=False) -> ErasureRequest:
    # A locked parent prevents concurrent dependent FK inserts while its graph
    # is removed. DELETE's FK checks are a second guard, not a disabled constraint.
    customer = db.scalar(select(Customer).where(Customer.id == customer_id,
        Customer.tenant_id == user.tenant_id, Customer.user_id == user.id).with_for_update())
    prior = db.scalar(select(ErasureRequest).where(ErasureRequest.tenant_id == user.tenant_id,
        ErasureRequest.subject_kind == "customer", ErasureRequest.subject_id == customer_id,
        ErasureRequest.requested_by == user.id))
    if customer is None and prior:
        return prior
    if customer is None:
        raise HTTPException(404, "Customer not found")
    request = _request(db, user.tenant_id, user.id, "customer", customer_id)
    tid, cid = user.tenant_id, customer_id
    _task(db, request, "kernel_contact", cid)
    for model, kind in ((ConsentEvent, "outreach"), (ConsentRecord, "skin")):
        for row in db.scalars(select(model).where(model.tenant_id == tid, model.customer_id == cid)):
            _retain_consent(db, request, row, kind)
        db.execute(delete(model).where(model.tenant_id == tid, model.customer_id == cid))
    # Preserve only the identifier needed to prevent renewed contact. The
    # profile FK and all free-text/person fields are removed.
    db.execute(update(SuppressionEvent).where(SuppressionEvent.tenant_id == tid,
        SuppressionEvent.customer_id == cid).values(customer_id=None, reason="privacy_erasure",
        source="privacy", created_by="", lifted_by=""))
    fingerprints = list(db.scalars(select(CustomerDestination.fingerprint).where(
        CustomerDestination.tenant_id == tid, CustomerDestination.customer_id == cid)))
    own_jobs = select(ImportJob.id).where(ImportJob.tenant_id == tid, ImportJob.user_id == user.id)
    related = ImportRow.customer_id == cid
    if fingerprints:
        related = or_(related, (ImportRow.customer_id.is_(None)) & ImportRow.job_id.in_(own_jobs)
                      & or_(ImportRow.phone_fingerprint.in_(fingerprints), ImportRow.email_fingerprint.in_(fingerprints)))
    db.execute(delete(ImportRow).where(ImportRow.tenant_id == tid, related))
    # Keep the minimum provider-event idempotency marker, preventing a replayed
    # webhook from recreating erased application records.
    db.execute(update(InboundApplication).where(InboundApplication.tenant_id == tid,
        InboundApplication.customer_id == cid).values(customer_id=None, created_json="[]", label="erased"))
    for model in (SkinAnalysis, Outcome, ExceptionRecord, ActionLink, DraftVersion,
                  BriefItem, Commitment, ContactPreference, CustomerDestination):
        db.execute(delete(model).where(model.tenant_id == tid, model.customer_id == cid))
    db.flush()
    db.execute(delete(Customer).where(Customer.id == cid, Customer.tenant_id == tid, Customer.user_id == user.id))
    db.add(AuditLog(tenant_id=tid, user_id=user.id, action="privacy.customer.active_erased",
                    detail=json.dumps({"request_id": request.id})))
    db.flush()
    return request


def erase_account(db: Session, user: User) -> ErasureRequest:
    # Serialize with team-role updates and other account deletion requests.
    db.execute(update(Tenant).where(Tenant.id == user.tenant_id).values(name=Tenant.name))
    db.refresh(user, with_for_update=True)
    uid, tid = user.id, user.tenant_id
    request = _request(db, tid, uid, "account", uid)
    for cid in list(db.scalars(select(Customer.id).where(Customer.tenant_id == tid, Customer.user_id == uid))):
        child = erase_customer(db, user, cid)
        _task(db, request, "customer_request", child.id)
    # A separate kernel account sweep covers direct agent-ops history that was
    # never linked to the application CRM, credentials and sender registrations.
    _task(db, request, "kernel_account", uid)
    for sender in db.scalars(select(SenderIdentity).where(SenderIdentity.tenant_id == tid, SenderIdentity.user_id == uid)):
        if sender.provider_resource_ref:
            _task(db, request, "provider_sender", sender.provider_resource_ref)
        db.delete(sender)
    sub = db.scalar(select(Subscription).where(Subscription.tenant_id == tid, Subscription.user_id == uid))
    if sub:
        if sub.stripe_customer_id:
            _task(db, request, "billing_customer", sub.stripe_customer_id)
        if sub.stripe_subscription_id:
            _task(db, request, "billing_subscription", sub.stripe_subscription_id)
        # External charges are not declared cancelled without provider evidence.
        sub.status = "deletion_pending"
    own_convs = select(Conversation.id).where(Conversation.tenant_id == tid, Conversation.user_id == uid)
    db.execute(delete(Message).where(Message.conversation_id.in_(own_convs)))
    jobs = select(ImportJob.id).where(ImportJob.tenant_id == tid, ImportJob.user_id == uid)
    db.execute(delete(ImportRow).where(ImportRow.tenant_id == tid, ImportRow.job_id.in_(jobs)))
    for model in (AuthRecoveryCode, AuthFactor, ProviderKey, SkinAnalysis, Conversation,
                  UsageRecord, ConsultantProfile, ImportJob):
        db.execute(delete(model).where(model.tenant_id == tid, model.user_id == uid))
    for row in db.scalars(select(ConsentRecord).where(ConsentRecord.tenant_id == tid, ConsentRecord.user_id == uid)):
        _retain_consent(db, request, row, "skin")
        db.delete(row)
    for session in db.scalars(select(AuthSession).where(AuthSession.tenant_id == tid,
            AuthSession.user_id == uid, AuthSession.revoked_at.is_(None))):
        revoke_local(db, session, by=uid, reason="account_deleted")
    user.email = f"deleted_{uid}@deleted"
    user.display_name = ""
    user.password_hash = ""
    user.referral_code = None
    user.referred_by = None
    user.is_active = False
    db.flush()
    if not db.scalar(select(User.id).where(User.tenant_id == tid, User.is_active.is_(True)).limit(1)):
        db.execute(delete(ProviderKey).where(ProviderKey.tenant_id == tid, ProviderKey.user_id.is_(None)))
        db.execute(update(Tenant).where(Tenant.id == tid).values(name="Erased business"))
    db.add(AuditLog(tenant_id=tid, user_id=uid, action="privacy.account.active_erased",
                    detail=json.dumps({"request_id": request.id})))
    db.flush()
    return request


def receipt(db: Session, request: ErasureRequest, *, with_status_token=False) -> dict:
    tasks = db.scalars(select(ErasureTask).where(ErasureTask.request_id == request.id)
                      .order_by(ErasureTask.kind, ErasureTask.id)).all()
    complete = bool(tasks) and all(task.status == "confirmed" for task in tasks)
    result = {"ok": True, "request_id": request.id, "active_store_erased": True,
            "status": "completed" if complete else "pending_downstream",
            "due_at": request.due_at.isoformat(), "backup_expires_at": request.backup_expires_at.isoformat(),
            "pending": sorted({task.kind for task in tasks if task.status != "confirmed"}),
            "detail": "Active application data erased; downstream and backup processing is pending."
                      if not complete else "Deletion processing completed."}
    if with_status_token:
        # This narrowly scoped receipt still works after account sessions are
        # revoked. It cannot authenticate any ordinary application endpoint.
        result["status_token"] = jwt.encode({"aud": "mk-erasure-status", "iss": "mk-app",
            "rid": request.id, "tid": request.tenant_id, "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(days=45)}, get_settings().jwt_secret, algorithm="HS256")
    return result


def receipt_from_token(db: Session, token: str) -> dict:
    try:
        claims = jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"],
            audience="mk-erasure-status", issuer="mk-app", options={"require": ["aud", "iss", "rid", "tid", "iat", "exp"]})
        request = db.scalar(select(ErasureRequest).where(ErasureRequest.id == claims["rid"],
                                                        ErasureRequest.tenant_id == claims["tid"]))
        if not request:
            raise ValueError("Unknown request")
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(401, "Invalid or expired deletion receipt") from None
    return receipt(db, request)
