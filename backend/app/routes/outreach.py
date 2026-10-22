"""Outreach glue for the interface (WP08): turn an approved-claims draft into a
kernel proposal, and present pending approvals with every field the approval
screen must show (row H1).

POST /api/drafts/{id}/propose      → kernel proposal bound to the exact draft text; ActionLink
GET  /api/approvals/pending        → kernel pending items merged with app context
GET  /api/actions/{id}             → kernel action + contract message_state + app link
GET  /api/audit/export.jsonl       → (admin) application audit log, JSON lines

The kernel remains the only authority: this module never sends, approves, or
suppresses. Approval itself goes through /api/agent-ops/actions/{id}/approve
with the human's passkey assertion.
"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..commitments import permission_snapshot
from ..drafting import require_current_draft_claims
from ..foundation import audit, own_customer, preference_for, unseal, utcnow
from ..kernel import KernelClient, KernelUnavailable, get_kernel_client
from ..kernel.assertions import roles_for
from ..models import ActionLink, AuditLog, BriefItem, Commitment, Customer, CustomerDestination, DraftVersion, User
from ..ratelimit import check_rate
from ..security import require_audit_reader
from ..authorization import TEAM_REVIEWERS
from .agent_ops import Principal, _select_sender, principal

router = APIRouter(tags=["outreach"])


def _primary_sms(db: Session, tenant_id: str, customer: Customer) -> str:
    d = db.scalar(select(CustomerDestination).where(
        CustomerDestination.customer_id == customer.id, CustomerDestination.channel == "sms",
        CustomerDestination.retired_at.is_(None)).order_by(CustomerDestination.is_primary.desc(), CustomerDestination.created_at))
    if not d:
        raise HTTPException(422, {"code": "NO_SMS_DESTINATION", "detail": "customer has no SMS destination on file"})
    return unseal(tenant_id, "destination", d.value_enc)


class ProposeDraftIn(BaseModel):
    scheduled_for: str | None = Field(default=None, description="ISO-8601; omitted = as soon as policy allows")
    purpose: str = Field(default="customer_requested_follow_up", pattern=r"^[a-z][a-z0-9_]{0,59}$")


@router.post("/drafts/{did}/propose", status_code=202)
async def propose_draft(did: str, body: ProposeDraftIn, p: Principal = Depends(principal), user: User = Depends(check_rate),
                        client: KernelClient = Depends(get_kernel_client), db: Session = Depends(get_db)):
    """Propose sending this exact draft version. The kernel decides whether
    approval is required (it always is for outreach) and who may approve."""
    dv = db.get(DraftVersion, did)
    if not dv or dv.tenant_id != user.tenant_id:
        raise HTTPException(404, "Draft not found")
    cust = own_customer(db, user.tenant_id, user.id, dv.customer_id)
    require_current_draft_claims(db, user.tenant_id, dv)
    pref = preference_for(db, cust)
    if not pref or not pref.timezone:
        raise HTTPException(422, {"code": "TIMEZONE_UNKNOWN", "detail": "set the customer's timezone before proposing outreach"})
    text = unseal(user.tenant_id, "draft", dv.text_enc)
    to = _primary_sms(db, user.tenant_id, cust)
    sender_id = await _select_sender(client, p, None)
    commitment = db.get(Commitment, dv.commitment_id) if dv.commitment_id else None
    if commitment is None and dv.brief_item_id:
        it = db.get(BriefItem, dv.brief_item_id)
        if it and it.source_type == "commitment":
            commitment = db.get(Commitment, it.source_reference)
    now = utcnow()
    # Evidence vocabulary is the action contract's: the draft version is a
    # `document` (its digest = the exact text), the commitment's source is a
    # `conversation` (its evidence digest).
    evidence = [{"type": "document", "id": f"draft:{dv.id}", "digest": dv.text_digest}]
    if commitment and commitment.source_evidence_reference and commitment.source_evidence_reference.startswith("sha256:"):
        evidence.append({"type": "conversation", "id": f"commitment:{commitment.id}", "digest": commitment.source_evidence_reference})
    req: dict[str, Any] = {
        "schema_version": "mk.action.v1", "tenant_id": str(uuid.UUID(user.tenant_id)), "requested_by": str(uuid.UUID(user.id)),
        # AI-generated drafts are proposed as agent origin so the kernel's approval
        # rules (no self-approval unless tenant policy allows) apply exactly as for
        # any autonomous proposal. Consultant-authored edits are still agent-origin
        # when the base draft came from the model.
        "origin": {"type": "agent" if dv.generated_by.startswith("ai:") else "human", "session_id": p.session_id,
                   **({"model_call_id": dv.generated_by} if dv.generated_by.startswith("ai:") else {})},
        "workflow": "customer_follow_up", "action_kind": "send_sms", "tool_id": "sms.provider.send.v1",
        "resource": {"type": "contact", "id": str(uuid.UUID(cust.id))},
        "arguments": {"contact_id": str(uuid.UUID(cust.id)), "template_id": f"draft.{dv.id}", "rendered_text": text, "to": to,
                      "sender_identity_id": sender_id, "contact_tz": pref.timezone,
                      **({"scheduled_for": body.scheduled_for} if body.scheduled_for else {})},
        "purpose": body.purpose, "risk": "high", "requested_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        "idempotency_key": f"draft:{dv.id}:{dv.text_digest[7:23]}",
        "evidence": evidence,
    }
    try:
        r = await client.call("POST", "/actions", user_id=p.user_id, tenant_id=p.tenant_id,
                              roles=roles_for(p.app_role, as_agent=req["origin"]["type"] == "agent"), session_id=p.session_id, json=req)
    except KernelUnavailable as e:
        raise HTTPException(503, {"code": e.code, "detail": e.detail})
    if r.status_code not in (200, 201, 202):
        raise HTTPException(r.status_code, r.body)
    result = (r.body or {}).get("result") or {}
    aref = audit(db, user.tenant_id, user.id, "outreach.propose",
                 {"draft_version_id": dv.id, "kernel_action_id": result.get("action_id"), "text_digest": dv.text_digest,
                  "decision": (r.body or {}).get("decision", {}).get("code")})
    link = ActionLink(tenant_id=user.tenant_id, customer_id=cust.id, kernel_action_id=str(result.get("action_id", "")),
                      action_digest=str(result.get("action_digest", "")), brief_item_id=dv.brief_item_id,
                      commitment_id=commitment.id if commitment else None, draft_version_id=dv.id,
                      last_known_state=str(result.get("state", "proposed")), audit_ref=aref)
    db.add(link)
    db.commit()
    return {"action_id": link.kernel_action_id, "state": result.get("state"), "message_state": result.get("message_state"),
            "action_digest": link.action_digest, "decision": (r.body or {}).get("decision"),
            "human_steps": ["A human must approve this exact text with their passkey before anything is sent.",
                            "The kernel re-checks consent, suppression, contact hours and the kill switch at send time."]}


def _link_for(db: Session, tenant_id: str, action_id: str) -> ActionLink | None:
    return db.scalar(select(ActionLink).where(ActionLink.tenant_id == tenant_id, ActionLink.kernel_action_id == action_id))


@router.get("/delivery-exceptions")
async def delivery_exceptions(after: uuid.UUID | None = None, limit: int = Query(default=50, ge=1, le=100),
                              p: Principal = Depends(principal), user: User = Depends(check_rate),
                              client: KernelClient = Depends(get_kernel_client), db: Session = Depends(get_db)):
    """Live kernel uncertainty, not a dismissible copy of delivery truth."""
    path = f"/deliveries/exceptions?limit={limit}" + (f"&after={after}" if after else "")
    try:
        response = await client.call("GET", path, user_id=p.user_id, tenant_id=p.tenant_id,
                                     roles=roles_for(p.app_role), session_id=p.session_id)
    except KernelUnavailable as e:
        raise HTTPException(503, {"code": e.code, "detail": e.detail})
    if response.status_code != 200:
        raise HTTPException(response.status_code, response.body)
    items = []
    for item in (response.body or {}).get("items", []):
        link = _link_for(db, user.tenant_id, item["action_id"])
        if link:
            try:
                if user.role in TEAM_REVIEWERS:
                    customer = db.get(Customer, link.customer_id)
                    if not customer or customer.tenant_id != user.tenant_id:
                        continue
                else:
                    customer = own_customer(db, user.tenant_id, user.id, link.customer_id)
            except HTTPException:
                continue
        else:
            customer = None  # kernel still enforces the sender's owner
        items.append({**item, "customer_id": customer.id if customer else None,
                      "customer_name": customer.name if customer else None,
                      "message_state": "submission_unknown" if item["action_state"] == "reconciliation_required" else item["delivery_state"],
                      "replacement_allowed": False})
    return {"items": items, "next_cursor": (response.body or {}).get("next_cursor")}


@router.get("/approvals/pending")
async def pending_approvals(p: Principal = Depends(principal), user: User = Depends(check_rate),
                            client: KernelClient = Depends(get_kernel_client), db: Session = Depends(get_db)):
    """Everything the approval screen must show (H1): destination (masked), customer,
    sending business + number, exact text, purpose, supporting commitment/request,
    permission state, scheduled time, approval expiry, and the digest the approval binds to."""
    try:
        r = await client.call("GET", "/approvals/pending", user_id=p.user_id, tenant_id=p.tenant_id,
                              roles=roles_for(p.app_role), session_id=p.session_id)
        s = await client.call("GET", "/senders", user_id=p.user_id, tenant_id=p.tenant_id, roles=roles_for(p.app_role), session_id=p.session_id)
    except KernelUnavailable as e:
        raise HTTPException(503, {"code": e.code, "detail": e.detail})
    if r.status_code != 200:
        raise HTTPException(r.status_code, r.body)
    senders = {x["sender_identity_id"]: x for x in (s.body or []) if isinstance(x, dict)} if s.status_code == 200 else {}
    out = []
    for item in r.body or []:
        res, disp = item.get("result", {}), item.get("display", {})
        aid = str(res.get("action_id", ""))
        link = _link_for(db, user.tenant_id, aid)
        cust = db.get(Customer, link.customer_id) if link else None
        if cust and (cust.tenant_id != user.tenant_id or (cust.user_id != user.id and user.role not in TEAM_REVIEWERS)):
            continue  # another consultant's customer: not this approver's to see
        commitment = db.get(Commitment, link.commitment_id) if link and link.commitment_id else None
        if commitment and (commitment.tenant_id != user.tenant_id or not cust or commitment.customer_id != cust.id):
            commitment = None
        perm = None
        if cust:
            state, checked_at = permission_snapshot(db, user.tenant_id, cust)
            perm = {"state": state, "checked_at": checked_at.isoformat(),
                    "note": "historical observation; the kernel re-checks consent and suppression at send time"}
        sender = None
        sid = disp.get("sender_identity_id")
        sv = senders.get(sid)
        if sv:
            sender = {"sender_identity_id": sid, "display_name": sv.get("display_name"), "from_number": sv.get("from_number"),
                      "registration_status": sv.get("registration_status")}
        out.append({
            "action_id": aid, "action_digest": res.get("action_digest"), "state": res.get("state"), "message_state": res.get("message_state"),
            "exact_text": disp.get("rendered_text"), "destination_masked": disp.get("destination_redacted"), "channel": disp.get("channel"),
            "purpose": disp.get("purpose"), "workflow": disp.get("workflow"), "risk": disp.get("risk"),
            "customer": {"id": cust.id, "name": cust.name} if cust else None,
            "sending_business": sender,
            "supporting": {"commitment": {"id": commitment.id, "text": commitment.commitment_text, "status": commitment.status,
                                          "evidence_digest": commitment.source_evidence_reference} if commitment else None,
                           "draft_version_id": link.draft_version_id if link else None, "evidence_count": disp.get("evidence_count")},
            "permission": perm,
            "scheduled_for": disp.get("scheduled_for"),
            "approval_expires_at": disp.get("expires_at"),
            "approval_lifetime_minutes": disp.get("approval_ttl_seconds", 0) / 60,
            "can_approve": disp.get("can_approve") is True,
            "approval_denial": disp.get("approval_denial"),
            "self_approval": disp.get("self_approval") is True,
            "human_steps": ["Your passkey signs this exact text (digest shown); any edit creates a new draft that needs a new approval.",
                            "Approval is single-use and expires; the kernel re-checks policy at send time."],
        })
    return out


@router.get("/actions/{action_id}")
async def action_status(action_id: str, p: Principal = Depends(principal), user: User = Depends(check_rate),
                        client: KernelClient = Depends(get_kernel_client), db: Session = Depends(get_db)):
    try:
        uuid.UUID(action_id)
    except ValueError:
        raise HTTPException(422, "action_id is not a valid id")
    try:
        r = await client.call("GET", f"/actions/{action_id}", user_id=p.user_id, tenant_id=p.tenant_id, roles=roles_for(p.app_role), session_id=p.session_id)
    except KernelUnavailable as e:
        raise HTTPException(503, {"code": e.code, "detail": e.detail})
    if r.status_code != 200:
        raise HTTPException(r.status_code, r.body)
    link = _link_for(db, user.tenant_id, action_id)
    if link:
        own_customer(db, user.tenant_id, user.id, link.customer_id) if user.role not in TEAM_REVIEWERS else None
        st = str((r.body or {}).get("state", link.last_known_state))
        if st != link.last_known_state:
            link.last_known_state, link.version = st, link.version + 1
            db.commit()
    return {"action": r.body, "link": {"customer_id": link.customer_id, "commitment_id": link.commitment_id,
                                       "draft_version_id": link.draft_version_id, "brief_item_id": link.brief_item_id} if link else None,
            "message_state_definitions": MESSAGE_STATE_DEFINITIONS}


# Verbatim from the contract / mk-contracts::MessageState::definition — the UI shows these, never paraphrases.
MESSAGE_STATE_DEFINITIONS = {
    "proposed": "Proposed by the AI or the consultant; nothing has been authorized.",
    "awaiting_approval": "Waiting for an explicit human approval gesture.",
    "approved": "Approved by a human; not yet queued for execution.",
    "queued": "Queued for execution; policy will be re-evaluated before any send.",
    "dispatch_authorized": "Dispatch authorization obtained; no provider request has been made.",
    "submission_started": "The provider request is in flight or its outcome is not yet recorded.",
    "provider_accepted": "Provider acknowledged submission.",
    "sent": "Provider reports outbound network submission.",
    "delivered": "Supported provider/carrier receipt reports delivery.",
    "failed": "Provider reported a terminal failure.",
    "delivery_unknown": "Evidence is insufficient to say whether the message was delivered.",
    "submission_unknown": "Evidence is insufficient to say whether the message was submitted; a human must resolve before any replacement.",
    "cancelled": "Cancelled before any provider submission.",
    "denied": "Refused by policy; nothing was sent.",
    "expired": "The authorization window elapsed before execution.",
}


@router.get("/audit/export.jsonl", response_class=PlainTextResponse)
def audit_export(admin: User = Depends(require_audit_reader), db: Session = Depends(get_db)):
    """Application audit log for this tenant as JSON lines (admin). Kernel evidence
    (hash-chained action/approval/dispatch events) is exported separately with
    `mk-audit-verifier` from the read-only database identity — see deploy/kernel/README.md."""
    rows = db.scalars(select(AuditLog).where(AuditLog.tenant_id == admin.tenant_id).order_by(AuditLog.created_at)).all()
    audit(db, admin.tenant_id, admin.id, "audit.export", {"rows": len(rows)})
    db.commit()
    lines = [json.dumps({"id": a.id, "at": a.created_at.isoformat(), "user_id": a.user_id, "action": a.action,
                         "detail": json.loads(a.detail) if a.detail.startswith("{") else a.detail}, separators=(",", ":")) for a in rows]
    return "\n".join(lines) + ("\n" if lines else "")
