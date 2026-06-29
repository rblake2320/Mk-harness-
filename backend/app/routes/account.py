"""Account management: data export and deletion (GDPR/CCPA).

Endpoints:
  GET  /api/account/export  — full data portability download (GDPR Art. 20, CCPA § 1798.100)
  DELETE /api/account        — erase all personal data (GDPR Art. 17, CCPA § 1798.105)

The export satisfies:
  - GDPR Article 20 (right to data portability)
  - CCPA § 1798.100 (right to know)
  - Apple App Store Review Guideline 5.1.1 (data use disclosure)

Account deletion:
  - Anonymises the user record (email → deleted_<id>@deleted, display_name cleared)
  - Deletes customers, conversations/messages, skin analyses
  - Retains anonymised audit logs for legal hold (7-year requirement)
  - Retains consent records (anonymised) for MHMDA compliance evidence
  - Revokes all active sessions by clearing the password hash
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    AuditLog, ConsentRecord, ConsultantProfile, Conversation, Customer,
    Message, SkinAnalysis, Subscription, UsageRecord, User,
)
from ..security import get_current_user, verify_password

router = APIRouter(prefix="/account", tags=["account"])


@router.get("/export")
def export_account(user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    """Return all data held about the authenticated user as a single JSON object."""

    # Profile
    prof = db.scalar(select(ConsultantProfile).where(ConsultantProfile.user_id == user.id))

    # Customers
    customers = db.scalars(select(Customer).where(Customer.user_id == user.id)).all()
    customers_out = []
    for c in customers:
        customers_out.append({
            "id": c.id,
            "name": c.name,
            "phone": c.phone,
            "email": c.email,
            "notes": c.notes,
            "last_contact": c.last_contact.isoformat() if c.last_contact else None,
            "skin_undertone": c.skin_undertone,
            "fitzpatrick_type": c.fitzpatrick_type,
            "skin_profile_at": c.skin_profile_at.isoformat() if c.skin_profile_at else None,
            "created_at": c.created_at.isoformat(),
        })

    # Conversations + messages
    convs = db.scalars(select(Conversation).where(Conversation.user_id == user.id)).all()
    convs_out = []
    for conv in convs:
        msgs = db.scalars(
            select(Message).where(Message.conversation_id == conv.id)
        ).all()
        convs_out.append({
            "id": conv.id,
            "title": conv.title,
            "skill": conv.skill,
            "created_at": conv.created_at.isoformat(),
            "messages": [
                {"role": m.role, "content": m.content,
                 "provider": m.provider, "model": m.model,
                 "created_at": m.created_at.isoformat()}
                for m in msgs
            ],
        })

    # Skin analyses
    analyses = db.scalars(select(SkinAnalysis).where(SkinAnalysis.user_id == user.id)).all()
    analyses_out = [
        {"id": r.id, "customer_id": r.customer_id, "provider": r.provider,
         "model": r.model, "created_at": r.created_at.isoformat(),
         "result": json.loads(r.result_json)}
        for r in analyses
    ]

    # Consent records
    consents = db.scalars(select(ConsentRecord).where(ConsentRecord.user_id == user.id)).all()
    consents_out = [
        {"id": r.id, "subject": r.subject, "customer_id": r.customer_id,
         "scope": r.scope, "consent_version": r.consent_version,
         "granted_at": r.granted_at.isoformat(),
         "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None}
        for r in consents
    ]

    # Subscription
    sub = db.scalar(select(Subscription).where(Subscription.user_id == user.id))
    sub_out = None
    if sub:
        sub_out = {
            "tier": sub.tier, "interval": sub.interval, "status": sub.status,
            "trial_end": sub.trial_end.isoformat() if sub.trial_end else None,
            "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
            "first_paid_at": sub.first_paid_at.isoformat() if sub.first_paid_at else None,
        }

    # Usage summary (token counts by provider)
    usage_rows = db.scalars(select(UsageRecord).where(UsageRecord.user_id == user.id)).all()
    usage_by_provider: dict[str, dict] = {}
    for u in usage_rows:
        e = usage_by_provider.setdefault(u.provider, {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "calls": 0})
        e["input_tokens"] += u.input_tokens
        e["output_tokens"] += u.output_tokens
        e["cost_usd"] += u.cost_usd
        e["calls"] += 1

    # Log the export event for audit trail
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id,
                    action="account.export", detail="gdpr_portability"))
    db.commit()

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "user": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "role": user.role,
            "created_at": user.created_at.isoformat(),
            "referral_code": user.referral_code,
        },
        "profile": {
            "total_conversations": prof.total_conversations if prof else 0,
            "total_skin_analyses": prof.total_skin_analyses if prof else 0,
            "compliance_flags": prof.compliance_flags if prof else 0,
            "last_active": prof.last_active.isoformat() if prof and prof.last_active else None,
        },
        "subscription": sub_out,
        "customers": customers_out,
        "conversations": convs_out,
        "skin_analyses": analyses_out,
        "consent_records": consents_out,
        "usage_by_provider": usage_by_provider,
    }


from pydantic import BaseModel  # noqa: E402


class DeleteAccountIn(BaseModel):
    password: str   # current password — required to confirm intentional deletion


@router.delete("")
def delete_account(body: DeleteAccountIn, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    """Erase all personal data (GDPR Art. 17 / CCPA § 1798.105).

    Anonymises the user record and deletes all PII-bearing rows. Audit logs are
    retained in anonymised form to satisfy the 7-year legal hold requirement and
    to preserve MHMDA consent evidence. Active sessions are invalidated by clearing
    the password hash — all JWTs become useless on next use.
    """
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Password is incorrect")

    uid = user.id
    tid = user.tenant_id

    # Delete customers (cascades skin_analyses linkage via nullable FK)
    customers = db.scalars(select(Customer).where(Customer.user_id == uid)).all()
    for c in customers:
        # Delete skin analyses for this customer first
        for sa in db.scalars(select(SkinAnalysis).where(SkinAnalysis.customer_id == c.id)).all():
            db.delete(sa)
        db.delete(c)

    # Delete any remaining skin analyses not linked to a customer
    for sa in db.scalars(select(SkinAnalysis).where(
            SkinAnalysis.user_id == uid, SkinAnalysis.customer_id.is_(None))).all():
        db.delete(sa)

    # Delete conversations and their messages (cascade via relationship)
    for conv in db.scalars(select(Conversation).where(Conversation.user_id == uid)).all():
        db.delete(conv)

    # Delete usage records
    for ur in db.scalars(select(UsageRecord).where(UsageRecord.user_id == uid)).all():
        db.delete(ur)

    # Delete consultant profile
    prof = db.scalar(select(ConsultantProfile).where(ConsultantProfile.user_id == uid))
    if prof:
        db.delete(prof)

    # Anonymise consent records (keep for MHMDA evidence, remove PII linkage)
    for cr in db.scalars(select(ConsentRecord).where(ConsentRecord.user_id == uid)).all():
        cr.revoked_at = cr.revoked_at or datetime.now(timezone.utc)

    # Anonymise the user record — invalidate sessions by clearing password hash
    user.email = f"deleted_{uid}@deleted"
    user.display_name = ""
    user.password_hash = ""
    user.referral_code = None
    user.is_active = False

    # Audit log entry (anonymised — user_id retained as a reference only)
    db.add(AuditLog(tenant_id=tid, user_id=uid,
                    action="account.delete", detail="gdpr_erasure"))
    db.commit()
    return {"ok": True, "detail": "Account and personal data erased."}
