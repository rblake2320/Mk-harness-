"""Commitments, daily brief and outcomes (WP04).

POST /api/commitments                      consultant-entered draft (or confirmed directly)
POST /api/commitments/extract              bounded AI extraction → DRAFTS only
POST /api/commitments/{id}/confirm|defer|cancel
GET  /api/commitments?customer_id=
GET  /api/brief?date=YYYY-MM-DD            deterministic, idempotent generation + ordered list
POST /api/brief/items/{id}/skip|defer|resolve
POST /api/outcomes                         business outcomes, separate from transport state
GET  /api/customers/{cid}/timeline
"""
from __future__ import annotations

import json
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..commitments import (
    EXTRACTOR_SYSTEM, KINDS, OUTCOME_KINDS, RELATIVE_WINDOWS, brief_for, confirm, create_draft, defer,
    generate_brief, parse_extractor_output, permission_snapshot, record_outcome,
)
from ..db import get_db
from ..foundation import audit, own_customer, unseal, utcnow
from ..models import BriefItem, Commitment, Customer, Outcome, User
from ..providers.base import ChatMessage, ChatRequest, ProviderError
from ..providers.router import complete_with_failover
from ..ratelimit import check_rate

router = APIRouter(tags=["commitments"])


def _own_commitment(db: Session, user: User, cid: str) -> Commitment:
    c = db.get(Commitment, cid)
    if not c or c.tenant_id != user.tenant_id or c.owner_user_id != user.id:
        raise HTTPException(404, "Commitment not found")
    return c


def _view(c: Commitment) -> dict:
    return {"id": c.id, "customer_id": c.customer_id, "kind": c.kind, "text": c.commitment_text,
            "status": c.status, "due_at": c.due_at.isoformat() if c.due_at else None,
            "due_window": [c.due_window_start.isoformat() if c.due_window_start else None,
                           c.due_window_end.isoformat() if c.due_window_end else None],
            "timezone": c.timezone, "source_type": c.source_type, "source_reference": c.source_reference,
            "evidence_digest": c.source_evidence_reference, "created_by": c.created_by,
            "confirmed_by": c.confirmed_by, "version": c.version}


class CommitmentIn(BaseModel):
    customer_id: str
    kind: str = Field(default="promise")
    text: str = Field(min_length=3, max_length=500)
    evidence_text: str = Field(min_length=1, max_length=4000, description="what was said; hashed as evidence")
    source_type: str = Field(default="consultant_note", pattern="^(consultant_note|conversation|inbound_message)$")
    source_reference: str = Field(default="", max_length=64)
    relative_window: str = "unspecified"
    absolute_date: str | None = None
    confirm_now: bool = False


@router.post("/commitments", status_code=201)
def create_commitment(body: CommitmentIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    cust = own_customer(db, user.tenant_id, user.id, body.customer_id)
    if body.relative_window not in RELATIVE_WINDOWS:
        raise HTTPException(422, "unknown relative_window")
    if body.absolute_date:
        try:
            date.fromisoformat(body.absolute_date)
        except ValueError:
            raise HTTPException(422, "absolute_date must be YYYY-MM-DD")
    c = create_draft(db, tenant_id=user.tenant_id, user_id=user.id, customer=cust, kind=body.kind, text=body.text,
                     source_type=body.source_type, source_reference=body.source_reference, source_version="",
                     evidence_text=body.evidence_text, created_by=user.id,
                     relative_window=body.relative_window, absolute_date=body.absolute_date)
    if body.confirm_now:
        confirm(db, c, user_id=user.id, text=None, due_at=None, relative_window=None)
    db.commit()
    return _view(c)


class ExtractIn(BaseModel):
    customer_id: str
    conversation_text: str = Field(min_length=10, max_length=20000)
    source_reference: str = Field(default="", max_length=64)
    provider: str | None = None
    model: str = ""


@router.post("/commitments/extract", status_code=201)
async def extract_commitments(body: ExtractIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    """Bounded extraction: the model proposes; every item is a DRAFT the consultant must
    confirm. Invented dates are dropped; quotes must be verbatim spans of the source."""
    cust = own_customer(db, user.tenant_id, user.id, body.customer_id)
    req = ChatRequest(messages=[ChatMessage(role="user", content=body.conversation_text)],
                      system=EXTRACTOR_SYSTEM, model=body.model, max_tokens=800, temperature=0.0, json_mode=True)
    try:
        result = await complete_with_failover(db, user, req, provider=body.provider, kind="extract")
    except ProviderError as e:
        raise HTTPException(502, str(e))
    drafts = parse_extractor_output(result.text, body.conversation_text)
    created = []
    for d in drafts:
        c = create_draft(db, tenant_id=user.tenant_id, user_id=user.id, customer=cust, kind=d.kind,
                         text=d.commitment_text, source_type="conversation", source_reference=body.source_reference,
                         source_version=f"{result.provider}:{result.model}", evidence_text=d.evidence_quote,
                         created_by="ai", relative_window=d.relative_window, absolute_date=d.absolute_date)
        created.append(_view(c) | {"evidence_quote": d.evidence_quote})
    db.commit()
    return {"drafts": created, "note": "Drafts only. Confirm customer, meaning and date before any of these become actionable."}


class ConfirmIn(BaseModel):
    text: str | None = Field(default=None, max_length=500)
    due_at: datetime | None = None
    relative_window: str | None = None


@router.post("/commitments/{cid}/confirm")
def confirm_commitment(cid: str, body: ConfirmIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    c = _own_commitment(db, user, cid)
    confirm(db, c, user_id=user.id, text=body.text, due_at=body.due_at, relative_window=body.relative_window)
    db.commit()
    return _view(c)


class DeferIn(BaseModel):
    due_at: datetime | None = None
    relative_window: str | None = None
    reason: str = Field(default="", max_length=200)


@router.post("/commitments/{cid}/defer")
def defer_commitment(cid: str, body: DeferIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    c = _own_commitment(db, user, cid)
    defer(db, c, user_id=user.id, due_at=body.due_at, relative_window=body.relative_window)
    record_outcome(db, tenant_id=user.tenant_id, user_id=user.id, customer_id=c.customer_id, kind="deferred",
                   commitment=None, action_link_id=None, note=body.reason)
    db.commit()
    return _view(c)


@router.post("/commitments/{cid}/cancel")
def cancel_commitment(cid: str, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    c = _own_commitment(db, user, cid)
    if c.status in ("resolved", "cancelled"):
        raise HTTPException(409, f"commitment is {c.status}")
    record_outcome(db, tenant_id=user.tenant_id, user_id=user.id, customer_id=c.customer_id, kind="cancelled",
                   commitment=c, action_link_id=None, note="")
    db.commit()
    return _view(c)


@router.get("/commitments")
def list_commitments(customer_id: str | None = None, status: str | None = None,
                     user: User = Depends(check_rate), db: Session = Depends(get_db)):
    q = select(Commitment).where(Commitment.tenant_id == user.tenant_id, Commitment.owner_user_id == user.id)
    if customer_id:
        own_customer(db, user.tenant_id, user.id, customer_id)
        q = q.where(Commitment.customer_id == customer_id)
    if status:
        q = q.where(Commitment.status == status)
    return [_view(c) for c in db.scalars(q.order_by(Commitment.created_at))]


# --------------------------------------------------------------------------- #
# Brief
# --------------------------------------------------------------------------- #
def _item_view(db: Session, it: BriefItem) -> dict:
    cust = db.get(Customer, it.customer_id)
    permission, checked_at = permission_snapshot(db, it.tenant_id, cust) if cust else ("none", utcnow())
    src = None
    if it.source_type == "commitment":
        c = db.get(Commitment, it.source_reference)
        src = _view(c) if c else None
    return {"id": it.id, "customer": {"id": cust.id, "name": cust.name} if cust else None,
            "rule": it.rule, "rank_category": it.rank_category, "source_type": it.source_type,
            "source_reference": it.source_reference, "source": src,
            "due_at": it.due_at.isoformat() if it.due_at else None, "state": it.state,
            "permission_state": permission,
            "permission_checked_at": checked_at.isoformat(),
            "permission_note": "historical observation; execution re-checks the kernel",
            "suggested_step": "Outreach is blocked. Review the suppression before any contact." if permission == "suppressed" else it.suggested_step,
            "draft_version_id": it.draft_version_id,
            "controls": (["approve", "edit"] if permission == "active" else []) + ["defer", "resolve", "skip"]}


@router.get("/brief")
def daily_brief(brief_date: str | None = Query(default=None, alias="date"),
                user: User = Depends(check_rate), db: Session = Depends(get_db)):
    try:
        d = date.fromisoformat(brief_date) if brief_date else utcnow().date()
    except ValueError:
        raise HTTPException(422, "date must be YYYY-MM-DD")
    generate_brief(db, tenant_id=user.tenant_id, user_id=user.id, brief_date=d)
    db.commit()
    items = brief_for(db, user.tenant_id, user.id, d)
    return {"date": d.isoformat(), "items": [_item_view(db, it) for it in items],
            "ranking": ["safety/opt-out attention", "overdue confirmed", "due today", "unanswered requests", "future scheduled"]}


def _own_item(db: Session, user: User, iid: str) -> BriefItem:
    it = db.get(BriefItem, iid)
    if not it or it.tenant_id != user.tenant_id or it.user_id != user.id:
        raise HTTPException(404, "Brief item not found")
    return it


@router.post("/brief/items/{iid}/skip")
def skip_item(iid: str, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    it = _own_item(db, user, iid)
    it.state, it.version = "skipped", it.version + 1
    it.audit_ref = audit(db, user.tenant_id, user.id, "brief.skip", {"item_id": it.id})
    db.commit()
    return _item_view(db, it)


class ItemDeferIn(BaseModel):
    due_at: datetime | None = None
    relative_window: str | None = None


@router.post("/brief/items/{iid}/defer")
def defer_item(iid: str, body: ItemDeferIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    it = _own_item(db, user, iid)
    if it.source_type == "commitment":
        c = _own_commitment(db, user, it.source_reference)
        defer(db, c, user_id=user.id, due_at=body.due_at, relative_window=body.relative_window)
    it.state, it.version = "deferred", it.version + 1
    it.audit_ref = audit(db, user.tenant_id, user.id, "brief.defer", {"item_id": it.id})
    db.commit()
    return _item_view(db, it)


class ItemResolveIn(BaseModel):
    outcome: str = Field(default="resolved")
    note: str = Field(default="", max_length=2000)


@router.post("/brief/items/{iid}/resolve")
def resolve_item(iid: str, body: ItemResolveIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    it = _own_item(db, user, iid)
    c = _own_commitment(db, user, it.source_reference) if it.source_type == "commitment" else None
    record_outcome(db, tenant_id=user.tenant_id, user_id=user.id, customer_id=it.customer_id, kind=body.outcome,
                   commitment=c, action_link_id=None, note=body.note)
    it.state, it.version = "resolved", it.version + 1
    it.audit_ref = audit(db, user.tenant_id, user.id, "brief.resolve", {"item_id": it.id, "outcome": body.outcome})
    db.commit()
    return _item_view(db, it)


# --------------------------------------------------------------------------- #
# Outcomes and timeline
# --------------------------------------------------------------------------- #
class OutcomeIn(BaseModel):
    customer_id: str
    kind: str
    commitment_id: str | None = None
    action_link_id: str | None = None
    note: str = Field(default="", max_length=2000)


@router.post("/outcomes", status_code=201)
def create_outcome(body: OutcomeIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    own_customer(db, user.tenant_id, user.id, body.customer_id)
    c = _own_commitment(db, user, body.commitment_id) if body.commitment_id else None
    o = record_outcome(db, tenant_id=user.tenant_id, user_id=user.id, customer_id=body.customer_id, kind=body.kind,
                       commitment=c, action_link_id=body.action_link_id, note=body.note)
    db.commit()
    return {"id": o.id, "kind": o.kind, "customer_id": o.customer_id, "commitment_id": o.commitment_id,
            "note": "business outcome; independent of transport state. A delivered message is not a resolved "
                    "commitment; a consultant-confirmed order is not verified revenue."}


@router.get("/customers/{cid}/timeline")
def timeline(cid: str, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    own_customer(db, user.tenant_id, user.id, cid)
    events = []
    for c in db.scalars(select(Commitment).where(Commitment.customer_id == cid)):
        events.append({"at": c.created_at.isoformat(), "type": "commitment", "data": _view(c)})
    for o in db.scalars(select(Outcome).where(Outcome.customer_id == cid)):
        events.append({"at": o.created_at.isoformat(), "type": "outcome",
                       "data": {"id": o.id, "kind": o.kind, "commitment_id": o.commitment_id,
                                "note": unseal(user.tenant_id, "outcome", o.note_enc) if o.note_enc else ""}})
    return sorted(events, key=lambda e: e["at"])
