"""CRM-lite: customer book. Follow-ups come from the brief; drafting from /api/drafts."""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..foundation import fingerprints_all, normalize, utcnow

from ..rbac import book_of, sees_whole_tenant
from ..db import get_db
from ..models import Customer, User
from ..ratelimit import check_rate
from ..security import get_current_user

router = APIRouter(prefix="/customers", tags=["customers"])


class CustomerIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    phone: str = ""
    email: str = ""
    notes: str = ""


def _own(db: Session, user: User, cid: str) -> Customer:
    c = db.get(Customer, cid)
    if not c or c.tenant_id != user.tenant_id or c.user_id != book_of(user) or c.erased_at is not None:
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
    rows = db.scalars(select(Customer).where(Customer.tenant_id == user.tenant_id,
                                             Customer.user_id == book_of(user), Customer.erased_at.is_(None))
                      .order_by(Customer.name))
    return [_customer_dict(c) for c in rows]


@router.get("/search")
def search_customers(q: str = Query(min_length=2, max_length=100), user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """Search the caller's book (F7): name substring, or an exact phone/email match
    through the destination fingerprint (raw destinations are never queried in
    plaintext). Scoped to the tenant AND the book; another book's or tenant's
    customers can never appear, whatever the query."""
    from ..models import CustomerDestination
    book, tid = book_of(user), user.tenant_id
    term = q.strip()
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    ids: dict[str, None] = {}
    for c in db.scalars(select(Customer.id).where(
            Customer.tenant_id == tid, Customer.user_id == book, Customer.erased_at.is_(None),
            Customer.name.ilike(f"%{escaped}%", escape="\\")).order_by(Customer.name).limit(50)):
        ids[c] = None
    fps: list[str] = []
    for channel in ("sms", "email"):
        if channel == "email" and "@" not in term:
            continue
        if channel == "sms" and sum(ch.isdigit() for ch in term) < 7:
            continue
        try:
            fps += fingerprints_all(tid, channel, normalize(channel, term))
        except HTTPException:
            continue   # not a usable destination: name search only
    if fps:
        for cid in db.scalars(select(CustomerDestination.customer_id).join(
                Customer, Customer.id == CustomerDestination.customer_id).where(
                CustomerDestination.tenant_id == tid, Customer.user_id == book,
                CustomerDestination.fingerprint.in_(fps), CustomerDestination.retired_at.is_(None))):
            ids[cid] = None
    rows = db.scalars(select(Customer).where(Customer.id.in_(list(ids)[:50]), Customer.tenant_id == tid,
                                             Customer.user_id == book, Customer.erased_at.is_(None))
                      .order_by(Customer.name)).all()
    return [_customer_dict(c) for c in rows]


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
    c = Customer(tenant_id=user.tenant_id, user_id=book_of(user), **body.model_dump())
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
    """Erase this customer (S13). A hard DELETE left destinations, drafts, commitments
    and skin analyses behind (SQLite) or failed on foreign keys (PostgreSQL); the
    erasure empties every content field and queues the kernel/provider part."""
    from ..erasure import deliver_to_kernel, erase_customer
    c = _own(db, user, cid)
    if c.erased_at is not None:
        raise HTTPException(404, "Customer not found")
    req = erase_customer(db, tenant_id=user.tenant_id, customer_id=c.id, requested_by=user.id)
    db.commit()
    try:
        deliver_to_kernel(db, tenant_id=user.tenant_id, limit=5)
    except Exception:  # noqa: BLE001 — delivery is retried; the request row is durable
        db.rollback()
    db.refresh(req)
    return {"ok": True, "erasure_request": req.id, "due_by": req.due_by.isoformat(),
            "kernel_acknowledged": req.kernel_acknowledged_at is not None}


@router.post("/{cid}/touch")
def mark_contacted(cid: str, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    c = _own(db, user, cid)
    c.last_contact = utcnow()
    db.commit()
    return {"ok": True}


@router.post("/{cid}/follow-up", status_code=410)
async def generate_follow_up_retired(cid: str, user: User = Depends(check_rate)):
    """Retired (contract rows P1/P3): free-text AI drafting that quoted private notes
    to the model and could invent product claims. Drafting now goes through
    `POST /api/drafts` (approved-claims registry, bounded output, review tasks)."""
    raise HTTPException(410, {"code": "RETIRED", "detail": "Use POST /api/drafts (bounded drafting with approved claims)."})
