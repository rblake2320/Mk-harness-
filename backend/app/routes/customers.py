"""CRM-lite: customer book + AI follow-up generation grounded in real notes."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Customer, User
from ..providers.base import ChatMessage, ChatRequest, ProviderError
from ..providers.router import complete_with_failover
from ..ratelimit import check_rate
from ..security import get_current_user
from ..skills import SKILLS

router = APIRouter(prefix="/customers", tags=["customers"])


class CustomerIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    phone: str = ""
    email: str = ""
    notes: str = ""


def _own(db: Session, user: User, cid: str) -> Customer:
    c = db.get(Customer, cid)
    if not c or c.user_id != user.id:
        raise HTTPException(404, "Customer not found")
    return c


@router.get("")
def list_customers(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Customer).where(Customer.user_id == user.id)
                      .order_by(Customer.name))
    return [{"id": c.id, "name": c.name, "phone": c.phone, "email": c.email,
             "notes": c.notes,
             "last_contact": c.last_contact.isoformat() if c.last_contact else None}
            for c in rows]


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


@router.delete("/{cid}")
def delete_customer(cid: str, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    db.delete(_own(db, user, cid))
    db.commit()
    return {"ok": True}


@router.post("/{cid}/touch")
def mark_contacted(cid: str, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    c = _own(db, user, cid)
    c.last_contact = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


class FollowUpIn(BaseModel):
    goal: str = Field(default="warm check-in", max_length=300)
    provider: str | None = None
    model: str | None = None


@router.post("/{cid}/follow-up")
async def generate_follow_up(cid: str, body: FollowUpIn, user: User = Depends(check_rate),
                             db: Session = Depends(get_db)):
    c = _own(db, user, cid)
    context = (f"Customer: {c.name}\nNotes: {c.notes or 'none'}\n"
               f"Last contact: {c.last_contact.date().isoformat() if c.last_contact else 'unknown'}\n"
               f"Goal: {body.goal}\nConsultant name: {user.display_name}")
    req = ChatRequest(messages=[ChatMessage(role="user", content=context)],
                      system=SKILLS["follow_up"]["system"],
                      model=body.model or "", max_tokens=600, temperature=0.8)
    try:
        result = await complete_with_failover(db, user, req, provider=body.provider)
    except ProviderError as e:
        raise HTTPException(502, str(e))
    return {"drafts": result.text, "provider": result.provider, "model": result.model}
