"""Inbound meaning processing (WP07): `POST /api/inbound/process`.

Pulls the kernel's unprocessed inbound events for this tenant (the kernel has
already authenticated, deduplicated, and applied opt-out/hold), classifies each
with `app.inbound.classify_inbound`, creates the required application objects,
asks the kernel for a sales-follow-up hold where the contract requires one, and
marks the event processed. Idempotent: a kernel event is processed at most once
(`/inbound/{id}/processed` is single-shot) and every object created carries the
provider event id as its source reference.

The message body is handled in memory only: it is sealed into the exception /
commitment evidence fields and never logged or placed in audit metadata.
"""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..commitments import create_draft, record_outcome
from ..db import get_db
from ..foundation import audit, seal
from ..inbound import EXCEPTION_KIND, STOPS_SALES_FOLLOW_UP, classify_inbound
from ..kernel import KernelClient, KernelUnavailable, get_kernel_client
from ..kernel.assertions import roles_for
from ..models import Customer, CustomerDestination, ExceptionRecord, InboundApplication, User
from ..ratelimit import check_rate
from .agent_ops import Principal, principal

router = APIRouter(tags=["inbound"])


class ProcessIn(BaseModel):
    limit: int = 50


def _customers_for_fingerprint(db: Session, tenant_id: str, fp: str) -> list[Customer]:
    rows = db.scalars(select(CustomerDestination).where(
        CustomerDestination.tenant_id == tenant_id, CustomerDestination.channel == "sms",
        CustomerDestination.fingerprint == fp, CustomerDestination.retired_at.is_(None))).all()
    seen, out = set(), []
    for d in rows:
        if d.customer_id not in seen:
            c = db.get(Customer, d.customer_id)
            if c:
                seen.add(d.customer_id)
                out.append(c)
    return out


def _exception(db: Session, tenant_id: str, user_id: str, customer_id: str | None, kind: str, source_ref: str,
               detail: str) -> ExceptionRecord:
    aref = audit(db, tenant_id, user_id, "inbound.exception", {"kind": kind, "source_reference": source_ref,
                                                               "customer_id": customer_id})
    ex = ExceptionRecord(tenant_id=tenant_id, customer_id=customer_id, kind=kind, source_reference=source_ref,
                         detail_enc=seal(tenant_id, "exception", detail), audit_ref=aref)
    db.add(ex)
    db.flush()
    return ex


@router.post("/inbound/process")
async def process_inbound(body: ProcessIn, p: Principal = Depends(principal), user: User = Depends(check_rate),
                          client: KernelClient = Depends(get_kernel_client), db: Session = Depends(get_db)):
    """Process up to `limit` pending inbound events. Returns a per-event summary
    without message bodies."""
    try:
        r = await client.call("GET", f"/inbound/pending?limit={max(1, min(body.limit, 200))}", user_id=p.user_id,
                              tenant_id=p.tenant_id, roles=roles_for(p.app_role), session_id=p.session_id)
    except KernelUnavailable as e:
        raise HTTPException(503, {"code": e.code, "detail": e.detail})
    if r.status_code != 200:
        raise HTTPException(r.status_code, r.body)
    results = []
    for ev in r.body or []:
        event_id = str(ev["event_id"])
        source_ref = f"inbound:{ev['provider_event_id']}"
        done = db.scalar(select(InboundApplication).where(InboundApplication.tenant_id == user.tenant_id,
                                                          InboundApplication.source_reference == source_ref))
        if done is not None:
            # Applied on an earlier attempt whose kernel "processed" mark failed: only
            # retry the mark. Nothing is created twice.
            try:
                mr = await client.call("POST", f"/inbound/{event_id}/processed", user_id=p.user_id,
                                       tenant_id=p.tenant_id, roles=roles_for(p.app_role),
                                       session_id=p.session_id, json={})
            except KernelUnavailable as e:
                raise HTTPException(503, {"code": e.code, "detail": e.detail})
            results.append({"event_id": event_id, "class": done.label, "customer_id": done.customer_id,
                            "matches": None, "created": json.loads(done.created_json), "hold": done.hold_status,
                            "marked_processed": mr.status_code, "replayed": True})
            continue
        text = ev.get("body") or ""
        klass = classify_inbound(text)
        customers = _customers_for_fingerprint(db, user.tenant_id, ev["source_destination_hash"])
        customer = customers[0] if len(customers) == 1 else None
        created: list[str] = []
        if ev.get("opt_out_signal") == "explicit":
            # Kernel already suppressed; record the business outcome.
            if customer:
                record_outcome(db, tenant_id=user.tenant_id, user_id=user.id, customer_id=customer.id, kind="opted_out",
                               commitment=None, action_link_id=None, note="")
                created.append("outcome:opted_out")
            label = "opt_out"
        else:
            label = klass.label
        if len(customers) != 1 and label not in ("opt_out",):
            ex = _exception(db, user.tenant_id, user.id, None, "identity_ambiguity", source_ref,
                            f"{len(customers)} customers match the sender; message: {text}")
            created.append(f"exception:{ex.id}")
        if label in EXCEPTION_KIND:
            ex = _exception(db, user.tenant_id, user.id, customer.id if customer else None, EXCEPTION_KIND[label],
                            source_ref, f"{klass.evidence} — {text}")
            created.append(f"exception:{ex.id}")
            if customer:
                record_outcome(db, tenant_id=user.tenant_id, user_id=user.id, customer_id=customer.id,
                               kind="exception_open", commitment=None, action_link_id=None, note="")
        if label == "date_request" and customer:
            cm = create_draft(db, tenant_id=user.tenant_id, user_id=user.id, customer=customer, kind="customer_date",
                              text=f"Customer asked to be contacted later: \"{klass.evidence}\"", source_type="inbound_message",
                              source_reference=source_ref, source_version="1", evidence_text=text,
                              created_by="inbound_rules", relative_window="unspecified")
            record_outcome(db, tenant_id=user.tenant_id, user_id=user.id, customer_id=customer.id, kind="deferred",
                           commitment=cm, action_link_id=None, note="")
            created.append(f"commitment_draft:{cm.id}")
        hold = None
        if label in STOPS_SALES_FOLLOW_UP and label != "opt_out" and ev.get("disposition") != "held":
            # Contract C7: concerns and wrong-number reports stop ordinary sales
            # follow-up. The kernel owns suppression; request a non-permanent hold.
            try:
                hr = await client.call("POST", "/suppressions", user_id=p.user_id, tenant_id=p.tenant_id,
                                       roles=roles_for(p.app_role), session_id=p.session_id,
                                       json={"channel": "sms", "destination_hash": ev["source_destination_hash"],
                                             "scope": "destination", "reason": f"hold:{label}", "permanent": False,
                                             "source": "inbound_rules"})
                hold = hr.status_code
            except KernelUnavailable as e:
                raise HTTPException(503, {"code": e.code, "detail": e.detail})
        db.add(InboundApplication(tenant_id=user.tenant_id, source_reference=source_ref, kernel_event_id=event_id,
                                  label=label, customer_id=customer.id if customer else None,
                                  created_json=json.dumps(created), hold_status=hold))
        db.commit()  # application objects + ledger row are one transaction
        # Mark processed only after the application objects are committed.
        try:
            mr = await client.call("POST", f"/inbound/{event_id}/processed", user_id=p.user_id, tenant_id=p.tenant_id,
                                   roles=roles_for(p.app_role), session_id=p.session_id, json={})
        except KernelUnavailable as e:
            raise HTTPException(503, {"code": e.code, "detail": e.detail})
        results.append({"event_id": event_id, "class": label, "customer_id": customer.id if customer else None,
                        "matches": len(customers), "created": created, "hold": hold, "marked_processed": mr.status_code})
    return {"processed": len(results), "events": results}


# --------------------------------------------------------------------------- #
# Exceptions (visible queue; C7 "create visible exceptions")
# --------------------------------------------------------------------------- #
from ..foundation import own_customer, unseal, utcnow  # noqa: E402


def _ex_view(tenant_id: str, ex: ExceptionRecord) -> dict:
    return {"id": ex.id, "customer_id": ex.customer_id, "kind": ex.kind, "state": ex.state,
            "source_reference": ex.source_reference, "detail": unseal(tenant_id, "exception", ex.detail_enc) if ex.detail_enc else "",
            "created_at": ex.created_at.isoformat(), "resolved_at": ex.resolved_at.isoformat() if ex.resolved_at else None}


@router.get("/exceptions")
def list_exceptions(state: str = "open", user: User = Depends(check_rate), db: Session = Depends(get_db)):
    q = select(ExceptionRecord).where(ExceptionRecord.tenant_id == user.tenant_id)
    if state != "all":
        q = q.where(ExceptionRecord.state == state)
    out = []
    for ex in db.scalars(q.order_by(ExceptionRecord.created_at)):
        if ex.customer_id:
            try:
                own_customer(db, user.tenant_id, user.id, ex.customer_id)
            except HTTPException:
                continue  # another consultant's customer: not visible
        out.append(_ex_view(user.tenant_id, ex))
    return out


class ResolveIn(BaseModel):
    resolution: str = "resolved"   # resolved | dismissed
    note: str = ""


@router.post("/exceptions/{eid}/resolve")
def resolve_exception(eid: str, body: ResolveIn, user: User = Depends(check_rate), db: Session = Depends(get_db)):
    ex = db.get(ExceptionRecord, eid)
    if not ex or ex.tenant_id != user.tenant_id:
        raise HTTPException(404, "Exception not found")
    if ex.customer_id:
        own_customer(db, user.tenant_id, user.id, ex.customer_id)
    if body.resolution not in ("resolved", "dismissed"):
        raise HTTPException(422, "resolution must be resolved or dismissed")
    if ex.state != "open":
        raise HTTPException(409, "already closed")
    ex.state, ex.resolved_by, ex.resolved_at, ex.version = body.resolution, user.id, utcnow(), ex.version + 1
    ex.audit_ref = audit(db, user.tenant_id, user.id, "exception.resolve", {"exception_id": ex.id, "resolution": body.resolution,
                                                                           "has_note": bool(body.note)})
    db.commit()
    return _ex_view(user.tenant_id, ex)
