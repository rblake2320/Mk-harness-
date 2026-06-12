"""Usage metering: per-user totals for consultants, tenant rollup for admins."""
from fastapi import APIRouter, Depends
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
