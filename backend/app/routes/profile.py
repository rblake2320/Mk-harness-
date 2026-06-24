"""Consultant profile: skill analytics, business context, and brand data."""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ConsultantProfile, User
from ..security import get_current_user

router = APIRouter(prefix="/profile", tags=["profile"])


class ProfileUpdate(BaseModel):
    tenure_months: int | None = Field(default=None, ge=0, le=600)
    team_size: int | None = Field(default=None, ge=0)
    star_wholesale_qtd: float | None = Field(default=None, ge=0)


def _get_or_create(db: Session, user: User) -> ConsultantProfile:
    prof = db.scalar(select(ConsultantProfile).where(ConsultantProfile.user_id == user.id))
    if not prof:
        prof = ConsultantProfile(user_id=user.id, tenant_id=user.tenant_id)
        db.add(prof)
        db.commit()
    return prof


@router.get("/me")
def get_profile(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    prof = _get_or_create(db, user)
    skill_usage = json.loads(prof.skill_usage_json or "{}")
    top_skill = max(skill_usage, key=skill_usage.get) if skill_usage else None
    return {
        "total_conversations": prof.total_conversations,
        "total_skin_analyses": prof.total_skin_analyses,
        "compliance_flags": prof.compliance_flags,
        "skill_usage": skill_usage,
        "top_skill": top_skill,
        "tenure_months": prof.tenure_months,
        "team_size": prof.team_size,
        "star_wholesale_qtd": prof.star_wholesale_qtd,
        "last_active": prof.last_active.isoformat() if prof.last_active else None,
    }


@router.patch("/me")
def update_profile(body: ProfileUpdate, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    prof = _get_or_create(db, user)
    if body.tenure_months is not None:
        prof.tenure_months = body.tenure_months
    if body.team_size is not None:
        prof.team_size = body.team_size
    if body.star_wholesale_qtd is not None:
        prof.star_wholesale_qtd = body.star_wholesale_qtd
    prof.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}
