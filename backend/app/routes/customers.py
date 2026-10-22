"""CRM-lite: customer book. Follow-ups come from the brief; drafting from /api/drafts."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Customer, User
from ..ratelimit import check_rate
from ..security import get_current_user
from ..privacy import erase_customer, receipt

router = APIRouter(prefix="/customers", tags=["customers"])


class CustomerIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    phone: str = ""
    email: str = ""
    notes: str = ""


def _own(db: Session, user: User, cid: str) -> Customer:
    c = db.get(Customer, cid)
    if not c or c.user_id != user.id or c.tenant_id != user.tenant_id:
        raise HTTPException(404, "Customer not found")
    return c


def _customer_dict(c: Customer) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "phone": c.phone,
        "email": c.email,
        "notes": c.notes,
        "last_contact": c.last_contact.isoformat() if c.last_contact else None,
        "skin_undertone": c.skin_undertone,
        "fitzpatrick_type": c.fitzpatrick_type,
        "skin_profile_at": c.skin_profile_at.isoformat() if c.skin_profile_at else None,
    }


@router.get("")
def list_customers(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Customer).where(Customer.user_id == user.id, Customer.tenant_id == user.tenant_id)
                      .order_by(Customer.name))
    return [_customer_dict(c) for c in rows]


class CustomerSearchIn(BaseModel):
    query: str = Field(min_length=1, max_length=120)
    offset: int = Field(default=0, ge=0, le=1_000_000)
    limit: int = Field(default=50, ge=1, le=100)


@router.post("/search")
def search_customers(body: CustomerSearchIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    """Search only this consultant's tenant-scoped records. POST keeps contact
    data out of URL/access logs; wildcard characters are treated literally."""
    term = body.query.strip()
    if not term:
        raise HTTPException(422, "Enter a customer name, phone number or email.")
    matches = or_(*(column.icontains(term, autoescape=True) for column in
                    (Customer.name, Customer.phone, Customer.email)))
    rows = db.scalars(select(Customer).where(Customer.tenant_id == user.tenant_id,
                                             Customer.user_id == user.id, matches)
                      .order_by(Customer.name, Customer.id).offset(body.offset).limit(body.limit + 1)).all()
    return {"items": [_customer_dict(c) for c in rows[:body.limit]],
            "next_offset": body.offset + body.limit if len(rows) > body.limit else None}


@router.get("/suggestions", status_code=410)
def daily_suggestions_retired(user: User = Depends(get_current_user)):
    """Retired (contract row W4): a purchase-age / days-since-contact heuristic is
    not a reason to message anyone. Follow-ups come from the rule-based brief
    (`GET /api/brief`): confirmed promises, unanswered requests, customer dates
    and exceptions — each with its source and permission state."""
    raise HTTPException(410, {"code": "RETIRED", "detail": "Use GET /api/brief. Depletion/overdue heuristics are not a follow-up reason."})


@router.get("/{cid}")
def get_customer(cid: str, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    return _customer_dict(_own(db, user, cid))


@router.post("", status_code=201)
def create_customer(body: CustomerIn, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    c = Customer(tenant_id=user.tenant_id, user_id=user.id, **body.model_dump())
    db.add(c)
    db.commit()
    return {"id": c.id}


@router.put("/{cid}")
def update_customer(cid: str, body: CustomerIn, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    c = _own(db, user, cid)
    for k, v in body.model_dump().items():
        setattr(c, k, v)
    db.commit()
    return {"ok": True}


@router.delete("/{cid}", status_code=202)
def delete_customer(cid: str, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    request = erase_customer(db, user, cid)
    db.commit()
    return receipt(db, request, with_status_token=True)


@router.post("/{cid}/touch")
def mark_contacted(cid: str, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    c = _own(db, user, cid)
    c.last_contact = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@router.post("/{cid}/follow-up", status_code=410)
async def generate_follow_up_retired(cid: str, user: User = Depends(check_rate)):
    """Retired (contract rows P1/P3): free-text AI drafting that quoted private notes
    to the model and could invent product claims. Drafting now goes through
    `POST /api/drafts` (approved-claims registry, bounded output, review tasks)."""
    raise HTTPException(410, {"code": "RETIRED", "detail": "Use POST /api/drafts (bounded drafting with approved claims)."})
