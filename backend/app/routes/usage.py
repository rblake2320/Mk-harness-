"""Usage metering: per-user totals for consultants, tenant rollup for admins."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import UsageRecord, User
from ..security import get_current_user, require_admin

router = APIRouter(prefix="/usage", tags=["usage"])


@router.get("/me")
def my_usage(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.execute(
        select(UsageRecord.provider, UsageRecord.model,
               func.sum(UsageRecord.input_tokens), func.sum(UsageRecord.output_tokens),
               func.sum(UsageRecord.cost_usd), func.count())
        .where(UsageRecord.user_id == user.id)
        .group_by(UsageRecord.provider, UsageRecord.model)).all()
    return [{"provider": p, "model": m, "input_tokens": int(i or 0),
             "output_tokens": int(o or 0), "cost_usd": round(float(c or 0), 4),
             "calls": n} for p, m, i, o, c, n in rows]


@router.get("/tenant")
def tenant_usage(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.execute(
        select(User.email, UsageRecord.provider, UsageRecord.key_scope,
               func.sum(UsageRecord.cost_usd), func.count())
        .join(User, User.id == UsageRecord.user_id)
        .where(UsageRecord.tenant_id == admin.tenant_id)
        .group_by(User.email, UsageRecord.provider, UsageRecord.key_scope)).all()
    return [{"email": e, "provider": p, "key_scope": s,
             "cost_usd": round(float(c or 0), 4), "calls": n} for e, p, s, c, n in rows]


@router.get("/budget")
def get_budget(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from ..spend import budget_cents, spent_cents
    cap = budget_cents(db, user.tenant_id)
    return {"monthly_ai_budget_cents": cap, "spent_this_month_cents": spent_cents(db, user.tenant_id),
            "capped": cap > 0, "applies_to": "company-paid AI keys; personal keys are billed to their owner"}


class BudgetIn(BaseModel):
    monthly_ai_budget_cents: int = Field(ge=0, le=10_000_000)   # 0 = no cap (explicit)


@router.put("/budget")
def set_budget(body: BudgetIn, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    from ..foundation import audit
    from ..models import Tenant
    t = db.get(Tenant, admin.tenant_id)
    old = t.monthly_ai_budget_cents
    t.monthly_ai_budget_cents = body.monthly_ai_budget_cents
    audit(db, admin.tenant_id, admin.id, "usage.budget_set", {"from_cents": old, "to_cents": body.monthly_ai_budget_cents})
    db.commit()
    return get_budget(admin, db)
