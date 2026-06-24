"""Consent capture for sensitive-data features (skin analysis).

GET  /api/consent/skin            -> current status + the exact text/version to display
POST /api/consent/skin            -> record an operator or customer consent grant
DELETE /api/consent/skin          -> revoke operator consent (e.g. account-level opt-out)

Every grant and revocation is written to the immutable ConsentRecord trail and mirrored
to the AuditLog. See app/consent.py and SECURITY-PRIVACY.md.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..consent import (
    AI_DISCLOSURE,
    CUSTOMER_CONSENT_TEXT,
    CUSTOMER_TEXT_SHA256,
    OPERATOR_CONSENT_TEXT,
    OPERATOR_TEXT_SHA256,
    SKIN_CONSENT_VERSION,
    active_customer_consent,
    active_operator_consent,
)
from ..db import get_db
from ..models import AuditLog, ConsentRecord, Customer, User
from ..security import get_current_user

router = APIRouter(prefix="/consent", tags=["consent"])


class ConsentGrant(BaseModel):
    subject: str            # "operator" | "customer"
    customer_id: str | None = None
    accepted: bool = True


@router.get("/skin")
def skin_consent_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """What to display in the consent modal, plus whether the operator has already agreed."""
    op = active_operator_consent(db, user.id)
    return {
        "version": SKIN_CONSENT_VERSION,
        "operator_consent": op is not None,
        "operator_granted_at": op.granted_at.isoformat() if op else None,
        "operator_text": OPERATOR_CONSENT_TEXT,
        "customer_text": CUSTOMER_CONSENT_TEXT,
        "ai_disclosure": AI_DISCLOSURE,
    }


@router.get("/skin/customer/{customer_id}")
def customer_consent_status(customer_id: str, user: User = Depends(get_current_user),
                            db: Session = Depends(get_db)):
    cust = db.get(Customer, customer_id)
    if not cust or cust.user_id != user.id:
        raise HTTPException(404, "Customer not found")
    cc = active_customer_consent(db, user.id, customer_id)
    return {
        "customer_id": customer_id,
        "version": SKIN_CONSENT_VERSION,
        "customer_consent": cc is not None,
        "granted_at": cc.granted_at.isoformat() if cc else None,
    }


@router.post("/skin")
def grant_skin_consent(body: ConsentGrant, user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    if body.subject not in ("operator", "customer"):
        raise HTTPException(422, "subject must be 'operator' or 'customer'")
    if not body.accepted:
        raise HTTPException(422, "Consent was not accepted")

    if body.subject == "customer":
        if not body.customer_id:
            raise HTTPException(422, "customer_id required for customer consent")
        cust = db.get(Customer, body.customer_id)
        if not cust or cust.user_id != user.id:
            raise HTTPException(404, "Customer not found")
        text_hash = CUSTOMER_TEXT_SHA256
    else:
        if body.customer_id:
            raise HTTPException(422, "operator consent must not name a customer")
        text_hash = OPERATOR_TEXT_SHA256

    rec = ConsentRecord(
        tenant_id=user.tenant_id, user_id=user.id, subject=body.subject,
        customer_id=body.customer_id, scope="skin",
        consent_version=SKIN_CONSENT_VERSION, text_sha256=text_hash,
    )
    db.add(rec)
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action="consent.grant",
                    detail=f"skin {body.subject} {body.customer_id or ''} {SKIN_CONSENT_VERSION}".strip()))
    db.commit()
    return {"ok": True, "id": rec.id, "subject": body.subject,
            "granted_at": rec.granted_at.isoformat(), "version": SKIN_CONSENT_VERSION}


@router.delete("/skin")
def revoke_operator_consent(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Revoke ALL active operator skin consents — disables skin analysis until re-granted.
    Does not delete stored data; use DELETE /api/me/skin-data for that."""
    now = datetime.now(timezone.utc)
    rows = db.scalars(select(ConsentRecord).where(
        ConsentRecord.user_id == user.id, ConsentRecord.subject == "operator",
        ConsentRecord.scope == "skin", ConsentRecord.revoked_at.is_(None))).all()
    for r in rows:
        r.revoked_at = now
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action="consent.revoke",
                    detail=f"skin operator x{len(rows)}"))
    db.commit()
    return {"ok": True, "revoked": len(rows)}
