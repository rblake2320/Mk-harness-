"""Customer skin-data subject rights: export (access/portability) and deletion.

GET    /api/me/skin-data/export   -> JSON of everything stored (MHMDA access/portability)
DELETE /api/me/skin-data          -> delete all stored skin data for this consultant,
                                     or one customer's via ?customer_id=...

Deletion cascades to: SkinAnalysis rows + the derived skin fields on Customer. Consent
records are intentionally retained (immutable proof of what was agreed) but a deletion is
written to the AuditLog and a signed-ish receipt is returned for the requester to keep.
Honor within 45 days is trivially met — this is synchronous.
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditLog, ConsentRecord, Customer, SkinAnalysis, User
from ..security import get_current_user

router = APIRouter(prefix="/me", tags=["skin-data"])


@router.get("/skin-data/export")
def export_skin_data(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Everything stored that relates to skin analysis for this consultant's book."""
    analyses = db.scalars(select(SkinAnalysis).where(SkinAnalysis.user_id == user.id)
                          .order_by(SkinAnalysis.created_at.desc())).all()
    customers = db.scalars(select(Customer).where(Customer.user_id == user.id)).all()
    consents = db.scalars(select(ConsentRecord).where(ConsentRecord.user_id == user.id,
                                                      ConsentRecord.scope == "skin")).all()
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "user_id": user.id,
        "skin_analyses": [
            {"id": a.id, "customer_id": a.customer_id,
             "created_at": a.created_at.isoformat(),
             "provider": a.provider, "model": a.model,
             "result": json.loads(a.result_json)} for a in analyses
        ],
        "customer_skin_profiles": [
            {"customer_id": c.id, "name": c.name,
             "skin_undertone": c.skin_undertone,
             "fitzpatrick_type": c.fitzpatrick_type,
             "skin_profile_json": json.loads(c.skin_profile_json) if c.skin_profile_json else None,
             "skin_profile_at": c.skin_profile_at.isoformat() if c.skin_profile_at else None}
            for c in customers
            if c.skin_undertone or c.fitzpatrick_type is not None or c.skin_profile_json
        ],
        "consent_records": [
            {"id": r.id, "subject": r.subject, "customer_id": r.customer_id,
             "version": r.consent_version, "text_sha256": r.text_sha256,
             "granted_at": r.granted_at.isoformat(),
             "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None}
            for r in consents
        ],
    }


@router.delete("/skin-data")
def delete_skin_data(customer_id: str | None = None,
                     user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Delete stored skin data. Scope to one customer with ?customer_id=, else all of the
    consultant's. Returns a deletion receipt."""
    analysis_q = select(SkinAnalysis).where(SkinAnalysis.user_id == user.id)
    customer_q = select(Customer).where(Customer.user_id == user.id)
    if customer_id:
        cust = db.get(Customer, customer_id)
        if not cust or cust.user_id != user.id:
            raise HTTPException(404, "Customer not found")
        analysis_q = analysis_q.where(SkinAnalysis.customer_id == customer_id)
        customer_q = customer_q.where(Customer.id == customer_id)

    analyses = db.scalars(analysis_q).all()
    for a in analyses:
        db.delete(a)

    cleared = 0
    for c in db.scalars(customer_q).all():
        if c.skin_undertone or c.fitzpatrick_type is not None or c.skin_profile_json or c.skin_profile_at:
            c.skin_undertone = ""
            c.fitzpatrick_type = None
            c.skin_profile_json = ""
            c.skin_profile_at = None
            cleared += 1

    receipt_at = datetime.now(timezone.utc)
    audit = AuditLog(tenant_id=user.tenant_id, user_id=user.id, action="skin_data.delete",
                     detail=f"customer={customer_id or 'ALL'} analyses={len(analyses)} cleared={cleared}")
    db.add(audit)
    db.commit()
    return {
        "ok": True,
        "receipt_id": audit.id,
        "deleted_at": receipt_at.isoformat(),
        "scope": customer_id or "all",
        "deleted_analyses": len(analyses),
        "cleared_customer_profiles": cleared,
    }
