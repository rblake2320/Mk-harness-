"""Account export and transactional erasure requests.

An accepted request is not a claim that provider copies or backups are erased.
Content-free audit/tombstones and minimal consent proofs are retained separately.
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
from ..privacy import erase_account, receipt, receipt_from_token

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
from pydantic import Field  # noqa: E402


class ErasureStatusIn(BaseModel):
    status_token: str = Field(min_length=1, max_length=4096)


@router.post("/erasure-status")
def erasure_status(body: ErasureStatusIn, db: Session = Depends(get_db)):
    # POST keeps this narrow receipt credential out of URLs/access logs.
    return receipt_from_token(db, body.status_token)


class DeleteAccountIn(BaseModel):
    password: str   # current password — required to confirm intentional deletion


@router.delete("", status_code=202)
def delete_account(body: DeleteAccountIn, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    """Erase active app data and persist all required downstream work."""
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Password is incorrect")
    request = erase_account(db, user)
    db.commit()
    return receipt(db, request, with_status_token=True)
