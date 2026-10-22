"""Governed agent operations — a thin, authenticated proxy to the Rust action kernel.

Every route here:
  1. authenticates the end user with the app JWT (``get_current_user``),
  2. mints a per-request Ed25519 actor assertion bound to that user + tenant,
  3. forwards the call to the kernel's ``/internal/v1`` API,
  4. returns the kernel's status + body verbatim.

Nothing in this file decides whether an action may run. If the kernel is not
configured or unreachable, the answer is **503** and nothing happens — there
is no Python execution path for outreach, approvals, consent, or suppression.

Identity binding: ``tenant_id`` / ``requested_by`` / contact ids in the body
are overwritten from the authenticated principal before forwarding, and the
kernel re-binds them again from the assertion, so a caller can never act in
another tenant. Cross-tenant reads come back as the kernel's 404.
"""
from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from sqlalchemy.orm import Session
from sqlalchemy import select

from ..config import get_settings
from ..db import get_db
from ..foundation import require_dispatch_timezone, preference_for_tz
from ..kernel import KernelClient, KernelUnavailable, get_kernel_client
from ..kernel.assertions import ROLE_PLATFORM_OPERATOR, roles_for
from ..models import AuthRevocation, AuthSession, Customer, User
from ..auth_sessions import revoke_local, valid_receipt
from ..ratelimit import check_rate
from ..security import get_current_user

router = APIRouter(prefix="/agent-ops", tags=["agent-ops"])


# --------------------------------------------------------------------------- #
# Principal + forwarding
# --------------------------------------------------------------------------- #
class Principal:
    __slots__ = ("user_id", "tenant_id", "app_role", "session_id")

    def __init__(self, user: User, request: Request):
        self.user_id = user.id
        self.tenant_id = user.tenant_id
        self.app_role = user.role
        # One persisted identity spans access-token refreshes, so session
        # revocation also finds every kernel approval from that login.
        self.session_id = request.state.auth_session.id


def principal(request: Request, user: User = Depends(check_rate)) -> Principal:
    return Principal(user, request)


def _problem(status: int, code: str, title: str, detail: str | None = None,
             request_id: str = "") -> JSONResponse:
    body: dict[str, Any] = {
        "type": f"urn:mk:error:{code.lower()}",
        "title": title,
        "status": status,
        "code": code,
        "request_id": request_id,
    }
    if detail:
        body["detail"] = detail
    return JSONResponse(status_code=status, content=body,
                        media_type="application/problem+json")


async def forward(
    client: KernelClient, p: Principal, method: str, path: str, *,
    json: Any | None = None, as_agent: bool = False, extra_roles: tuple[str, ...] = (),
) -> Response:
    roles = roles_for(p.app_role, as_agent=as_agent) + list(extra_roles)
    try:
        r = await client.call(
            method, path, user_id=p.user_id, tenant_id=p.tenant_id, roles=roles,
            session_id=p.session_id, json=json,
        )
    except KernelUnavailable as e:
        return _problem(503, e.code, "Action kernel unavailable", e.detail)
    headers = {"X-Request-Id": r.request_id}
    if r.retry_after and r.retry_after.isdigit() and r.status_code in (429, 503):
        headers["Retry-After"] = r.retry_after
    if r.body is None:
        return Response(status_code=r.status_code, headers=headers)
    return JSONResponse(status_code=r.status_code, content=r.body, headers=headers)


def _uuid_text(value: str, what: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(422, f"{what} is not a valid id")


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #
@router.get("/health")
async def kernel_health(p: Principal = Depends(principal),
                        client: KernelClient = Depends(get_kernel_client)):
    """Readiness of the kernel as seen from the app. Never 200 without a live kernel."""
    try:
        r = await client.health_ready()
    except KernelUnavailable as e:
        return _problem(503, e.code, "Action kernel unavailable", e.detail)
    return JSONResponse(status_code=200 if r.status_code == 200 else 503,
                        content={"kernel_status": r.status_code, "kernel": r.body,
                                 "configured": client.configured})


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
class ProposeIn(BaseModel):
    """``origin`` chooses the principal the kernel sees: ``agent`` = autonomous
    (AI proposed it; cannot self-approve), ``human`` = the signed-in user."""
    origin: str = Field(default="human", pattern="^(agent|human)$")
    request: dict[str, Any]


OUTREACH_KINDS = ("send_sms", "send_email", "send_dm", "mobile_work_order")  # mirrors mk_domain::ActionKind::is_outreach


def _contact_customer(db: Session, p: Principal, req: dict) -> Customer | None:
    """Resolve the action's contact to this consultant's customer.

    The kernel authorizes against ``resource.id``; that is the only identity this
    gate trusts. ``arguments.contact_id`` must agree with it when present — a
    proposal naming two different customers is refused rather than checked
    against the more convenient one."""
    res = req.get("resource") or {}
    if res.get("type") != "contact" or not res.get("id"):
        raise HTTPException(status_code=422, detail={"code": "outreach_resource_required",
                            "message": "Outreach actions must name the customer as resource {type: contact, id}."})
    arg_cid = (req.get("arguments") or {}).get("contact_id")
    try:
        hex_id = uuid.UUID(str(res["id"])).hex
        if arg_cid is not None and uuid.UUID(str(arg_cid)).hex != hex_id:
            raise HTTPException(status_code=422, detail={"code": "contact_mismatch",
                                "message": "arguments.contact_id does not match resource.id."})
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "contact_invalid", "message": "Customer id is not a UUID."}) from None
    c = db.get(Customer, hex_id)
    if not c or c.tenant_id != p.tenant_id:
        # Unknown here ≠ unknown to the kernel; the kernel still enforces consent for its own
        # contact id. But a timezone cannot be known for a customer this tenant does not have.
        raise HTTPException(status_code=404, detail={"code": "customer_not_found", "message": "Customer not found."})
    return c


@router.post("/actions")
async def propose(body: ProposeIn, p: Principal = Depends(principal),
                  client: KernelClient = Depends(get_kernel_client), db: Session = Depends(get_db)):
    req = dict(body.request)
    # No kernel → 503 before any local validation runs (never a local send path).
    try:
        client._require_configured()  # noqa: SLF001 — same check forward() applies
    except KernelUnavailable as e:
        return _problem(503, e.code, "Action kernel unavailable", e.detail)
    # F9: outreach to a customer whose destination timezone is unknown is blocked
    # here, before the kernel ever sees it. Non-outreach kinds are unaffected.
    if req.get("action_kind") in OUTREACH_KINDS:
        c = _contact_customer(db, p, req)
        tz = require_dispatch_timezone(db, c)
        # The kernel evaluates contact hours in the customer's own zone.
        args0 = req.get("arguments")
        if isinstance(args0, dict):
            args0["contact_tz"] = tz
    # Production SMS goes through the business's registered provider sender
    # (WP07). The sender is chosen here from the kernel's registry — never
    # supplied by the model — and bound into the proposal arguments.
    if req.get("tool_id") == "sms.provider.send.v1":
        args0 = req.get("arguments") if isinstance(req.get("arguments"), dict) else None
        if args0 is None:
            raise HTTPException(422, "arguments required")
        args0["sender_identity_id"] = await _select_sender(client, p, args0.get("sender_identity_id"))
    # Identity is bound here AND again in the kernel; body values are discarded.
    req["schema_version"] = req.get("schema_version") or "mk.action.v1"
    req["tenant_id"] = str(uuid.UUID(p.tenant_id))
    req["requested_by"] = str(uuid.UUID(p.user_id))
    req.pop("action_id", None)
    # Wire name per contracts/action/v1/action-request.schema.json is `type`.
    origin = dict(req.get("origin") or {})
    origin["type"] = body.origin
    origin.setdefault("session_id", p.session_id)
    req["origin"] = origin
    # Secrets never ride in arguments (the kernel schema also forbids them).
    args = req.get("arguments")
    if isinstance(args, dict):
        for k in ("callback_url", "password", "api_key", "token", "secret"):
            if k in args:
                raise HTTPException(422, f"arguments.{k} is forbidden")
    return await forward(client, p, "POST", "/actions", json=req,
                         as_agent=(body.origin == "agent"))


async def _select_sender(client: KernelClient, p: Principal, requested: Any) -> str:
    """Pick the registered, active sender identity for this consultant's business.
    A requested id must be one of the tenant's own; otherwise the caller's own
    sender is used; a tenant with none cannot propose provider SMS."""
    try:
        r = await client.call("GET", "/senders", user_id=p.user_id, tenant_id=p.tenant_id,
                              roles=roles_for(p.app_role), session_id=p.session_id)
    except KernelUnavailable as e:
        raise HTTPException(503, {"code": e.code, "detail": e.detail})
    senders = [s for s in (r.body or []) if isinstance(s, dict) and s.get("status") == "active"] if r.status_code == 200 else []
    if requested:
        rid = _uuid_text(str(requested), "sender_identity_id")
        if not any(s.get("sender_identity_id") == rid for s in senders):
            raise HTTPException(422, {"code": "SENDER_NOT_FOUND", "detail": "sender identity is not registered to this tenant"})
        return rid
    mine = [s for s in senders if str(s.get("owner_user_id", "")).replace("-", "") == uuid.UUID(p.user_id).hex]
    pick = mine or senders
    if not pick:
        raise HTTPException(422, {"code": "NO_SENDER_IDENTITY",
                                  "detail": "register a provider sender for this business before proposing SMS"})
    return str(pick[0]["sender_identity_id"])


@router.get("/actions/{action_id}")
async def get_action(action_id: str, p: Principal = Depends(principal),
                     client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "GET", f"/actions/{_uuid_text(action_id, 'action_id')}")


@router.post("/actions/{action_id}/cancel")
async def cancel_action(action_id: str, p: Principal = Depends(principal),
                        client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/actions/{_uuid_text(action_id, 'action_id')}/cancel")


@router.post("/actions/{action_id}/replay")
async def replay_action(action_id: str, p: Principal = Depends(principal),
                        client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/actions/{_uuid_text(action_id, 'action_id')}/replay")


# --------------------------------------------------------------------------- #
# Approvals — always minted as the human; never as an agent
# --------------------------------------------------------------------------- #
_B64URL = r"^[A-Za-z0-9_-]+$"
_B64URL_MAX = 87_382   # ≤64 KiB decoded


class WebAuthnAssertionIn(BaseModel):
    """Bytes from `navigator.credentials.get()` on the approval screen. FastAPI
    relays them untouched; only the kernel verifies (it holds the registered
    public keys and issued the challenge). FastAPI cannot forge these."""
    model_config = {"extra": "forbid"}
    credential_id: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)
    client_data_json: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)
    authenticator_data: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)
    signature: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)


class DecisionIn(BaseModel):
    action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: str | None = None
    webauthn: WebAuthnAssertionIn | None = None


class SubmissionResolutionChallengeIn(BaseModel):
    model_config = {"extra": "forbid"}
    decision: Literal["closed_no_replacement", "replacement_permitted"]


class SubmissionResolutionIn(SubmissionResolutionChallengeIn):
    operation_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    webauthn: WebAuthnAssertionIn


@router.post("/actions/{action_id}/resolution-challenge")
async def submission_resolution_challenge(action_id: str, body: SubmissionResolutionChallengeIn,
        p: Principal = Depends(principal), client: KernelClient = Depends(get_kernel_client)):
    if p.app_role != "admin":
        raise HTTPException(403, "Tenant administrator required")
    return await forward(client, p, "POST",
        f"/actions/{_uuid_text(action_id, 'action_id')}/resolution-challenge", json=body.model_dump())


@router.post("/actions/{action_id}/resolve-submission")
async def resolve_submission(action_id: str, body: SubmissionResolutionIn,
        p: Principal = Depends(principal), client: KernelClient = Depends(get_kernel_client)):
    if p.app_role != "admin":
        raise HTTPException(403, "Tenant administrator required")
    return await forward(client, p, "POST",
        f"/actions/{_uuid_text(action_id, 'action_id')}/resolve-submission", json=body.model_dump())


@router.post("/actions/{action_id}/approve")
async def approve(action_id: str, body: DecisionIn, p: Principal = Depends(principal),
                  client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/actions/{_uuid_text(action_id, 'action_id')}/approve",
                         json=body.model_dump(exclude_none=True))


@router.post("/actions/{action_id}/reject")
async def reject(action_id: str, body: DecisionIn, p: Principal = Depends(principal),
                 client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/actions/{_uuid_text(action_id, 'action_id')}/reject",
                         json=body.model_dump(exclude_none=True))


@router.get("/approvals/pending")
async def pending(p: Principal = Depends(principal),
                  client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "GET", "/approvals/pending")


# --------------------------------------------------------------------------- #
# Human-approval authority (WP06): passkey registration, approval challenges,
# revocations. Every call is a relay; the kernel is the only verifier.
# --------------------------------------------------------------------------- #
@router.post("/actions/{action_id}/approval-challenge")
async def approval_challenge(action_id: str, p: Principal = Depends(principal),
                             client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/actions/{_uuid_text(action_id, 'action_id')}/approval-challenge", json={})


@router.post("/approval-credentials/register/begin")
async def passkey_register_begin(p: Principal = Depends(principal),
                                 client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/approval-credentials/register/begin", json={})


class PasskeyFinishIn(BaseModel):
    client_data_json: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)
    attestation_object: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)
    label: str = Field(default="", max_length=80)


@router.post("/approval-credentials/register/finish")
async def passkey_register_finish(body: PasskeyFinishIn, p: Principal = Depends(principal),
                                  client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/approval-credentials/register/finish", json=body.model_dump())


@router.get("/approval-credentials")
async def passkeys(p: Principal = Depends(principal), client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "GET", "/approval-credentials")


@router.post("/approval-credentials/{row_id}/revoke")
async def passkey_revoke(row_id: str, p: Principal = Depends(principal),
                         client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", f"/approval-credentials/{_uuid_text(row_id, 'credential_row_id')}/revoke", json={})


class RevocationIn(BaseModel):
    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    user_id: str | None = None
    reason: str = Field(default="", max_length=500)


@router.post("/revocations")
async def revoke_principal(body: RevocationIn, p: Principal = Depends(principal),
                           client: KernelClient = Depends(get_kernel_client), db: Session = Depends(get_db)):
    """Revoke a kernel session or user (H9). `session_id` omitted + `user_id`
    omitted → revokes the caller's *current* kernel session."""
    payload: dict[str, Any] = {"reason": body.reason}
    if body.user_id:
        payload["user_id"] = _uuid_text(body.user_id, "user_id")
    if body.session_id:
        payload["session_id"] = body.session_id
    elif not body.user_id:
        payload["session_id"] = p.session_id
    target_user = uuid.UUID(body.user_id).hex if body.user_id else p.user_id
    if target_user != p.user_id and p.app_role != 'admin':
        raise HTTPException(403, 'Admin role required to revoke another user')
    target = db.get(User, target_user)
    if target and target.tenant_id != p.tenant_id:
        raise HTTPException(404, 'User not found')
    query = select(AuthSession).where(AuthSession.user_id == target_user, AuthSession.tenant_id == p.tenant_id)
    if payload.get('session_id'):
        query = query.where(AuthSession.id == payload['session_id'])
    elif target:
        target.is_active = False  # user-wide revocation also prevents a new login
    affected = list(db.scalars(query))
    for session in affected:
        revoke_local(db, session, by=p.user_id, reason='principal_revoked')
    db.commit()
    result = await forward(client, p, "POST", "/revocations", json=payload)
    # A user-wide receipt also acknowledges all queued per-session revocations.
    # Lost responses remain pending and the narrow outbox worker finishes them.
    import json as jsonlib
    from datetime import datetime, timezone
    try:
        confirmed = valid_receipt(result.status_code, jsonlib.loads(result.body))
    except (ValueError, TypeError):
        confirmed = False
    if confirmed:
        for session in affected:
            row = db.get(AuthRevocation, session.id)
            if row:
                row.confirmed_at = datetime.now(timezone.utc)
        db.commit()
    return result


@router.post("/approvals/{approval_id}/revoke")
async def revoke_approval(approval_id: str, p: Principal = Depends(principal),
                          client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/approvals/{_uuid_text(approval_id, 'approval_id')}/revoke")


# --------------------------------------------------------------------------- #
# Provider messaging (WP07): sender identities and inbound work queue — relays
# --------------------------------------------------------------------------- #
class SenderIn(BaseModel):
    owner_user_id: str
    display_name: str = Field(min_length=1, max_length=120)
    account_sid: str = Field(pattern=r"^AC[0-9a-fA-F]{32}$")
    auth_token: str = Field(min_length=16, max_length=256)
    from_number: str | None = Field(default=None, pattern=r"^\+[1-9][0-9]{7,14}$")
    messaging_service_sid: str | None = Field(default=None, pattern=r"^MG[0-9a-fA-F]{32}$")


@router.post("/senders")
async def register_sender(body: SenderIn, p: Principal = Depends(principal),
                          client: KernelClient = Depends(get_kernel_client)):
    """Registers a consultant business's provider sender. The auth token is
    relayed once to the kernel, which seals it; FastAPI stores nothing."""
    payload = body.model_dump(exclude_none=True)
    payload["owner_user_id"] = _uuid_text(body.owner_user_id, "owner_user_id")
    return await forward(client, p, "POST", "/senders", json=payload)


@router.get("/senders")
async def list_senders(p: Principal = Depends(principal), client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "GET", "/senders")


class RegistrationIn(BaseModel):
    registration_status: str = Field(pattern="^(unverified|pending|registered|rejected)$")
    reference: str = Field(default="", max_length=200)


@router.post("/senders/{sender_id}/registration")
async def sender_registration(sender_id: str, body: RegistrationIn, p: Principal = Depends(principal),
                              client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", f"/senders/{_uuid_text(sender_id, 'sender_id')}/registration", json=body.model_dump())


@router.get("/inbound/health")
async def inbound_health(p: Principal = Depends(principal), client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "GET", "/inbound/health")


class HealthIn(BaseModel):
    ok: bool
    reason: str = Field(default="", max_length=200)


@router.post("/inbound/health")
async def inbound_health_report(body: HealthIn, p: Principal = Depends(principal),
                                client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/inbound/health", json=body.model_dump())


@router.post("/inbound/pause")
async def inbound_pause(p: Principal = Depends(principal), client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/inbound/pause", json={})


@router.post("/inbound/resume")
async def inbound_resume(p: Principal = Depends(principal), client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/inbound/resume", json={})


# --------------------------------------------------------------------------- #
# Consent + suppression
# --------------------------------------------------------------------------- #
class GrantIn(BaseModel):
    channel: str
    destination: str = Field(min_length=1, max_length=320)  # the number/address the evidence covers; kernel hashes it
    scope: list[str]
    source: str
    proof_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    granted_at: str
    expires_at: str


@router.post("/contacts/{contact_id}/permissions")
async def grant_permission(contact_id: str, body: GrantIn, p: Principal = Depends(principal),
                           client: KernelClient = Depends(get_kernel_client)):
    cid = _uuid_text(contact_id, "contact_id")
    return await forward(client, p, "POST", f"/contacts/{cid}/permissions",
                         json=body.model_dump())


@router.post("/contacts/{contact_id}/permissions/{permission_id}/revoke")
async def revoke_permission(contact_id: str, permission_id: str,
                            p: Principal = Depends(principal),
                            client: KernelClient = Depends(get_kernel_client)):
    cid = _uuid_text(contact_id, "contact_id")
    pid = _uuid_text(permission_id, "permission_id")
    return await forward(client, p, "POST", f"/contacts/{cid}/permissions/{pid}/revoke")


class SuppressionIn(BaseModel):
    channel: str | None = None
    destination: str | None = None
    destination_hash: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")
    reason: str
    permanent: bool = True
    source: str


@router.post("/suppressions")
async def add_suppression(body: SuppressionIn, p: Principal = Depends(principal),
                          client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/suppressions", json=body.model_dump(exclude_none=True))


@router.delete("/suppressions/{suppression_id}")
async def lift_suppression(suppression_id: str, p: Principal = Depends(principal),
                           client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "DELETE",
                         f"/suppressions/{_uuid_text(suppression_id, 'suppression_id')}")


# --------------------------------------------------------------------------- #
# Adapters (mobile device agents) — tenant_admin in the kernel
# --------------------------------------------------------------------------- #
class RegisterAdapterIn(BaseModel):
    agent_id: str
    name: str
    platform: str
    version: str
    capabilities: list[str]
    allowed_actions: list[str]
    callback_authority: str


@router.post("/adapters")
async def register_adapter(body: RegisterAdapterIn, p: Principal = Depends(principal),
                           client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/adapters", json=body.model_dump())


@router.get("/adapters/{adapter_id}")
async def get_adapter(adapter_id: str, p: Principal = Depends(principal),
                      client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "GET",
                         f"/adapters/{_uuid_text(adapter_id, 'adapter_id')}")


class RotateIn(BaseModel):
    overlap_secs: int | None = None


@router.post("/adapters/{adapter_id}/rotate")
async def rotate_adapter(adapter_id: str, body: RotateIn | None = None,
                         p: Principal = Depends(principal),
                         client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/adapters/{_uuid_text(adapter_id, 'adapter_id')}/rotate",
                         json=body.model_dump(exclude_none=True) if body else None)


@router.post("/adapters/{adapter_id}/revoke")
async def revoke_adapter(adapter_id: str, p: Principal = Depends(principal),
                         client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/adapters/{_uuid_text(adapter_id, 'adapter_id')}/revoke")


# --------------------------------------------------------------------------- #
# Kill switches
# --------------------------------------------------------------------------- #
class KillSwitchIn(BaseModel):
    dispatch_enabled: bool
    webauthn: WebAuthnAssertionIn | None = None   # required by the kernel to re-enable globally


@router.post("/kill-switch/tenant")
async def tenant_kill_switch(body: KillSwitchIn, p: Principal = Depends(principal),
                             client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/kill-switch/tenant", json=body.model_dump(exclude_none=True))


@router.post("/kill-switch/global")
async def global_kill_switch(body: KillSwitchIn, p: Principal = Depends(principal),
                             client: KernelClient = Depends(get_kernel_client)):
    # The platform_operator role is minted only for ids listed in
    # KERNEL_PLATFORM_OPERATORS — never for tenant admins, never for agents.
    if p.user_id not in get_settings().platform_operator_ids:
        raise HTTPException(403, "Platform operator required")
    return await forward(client, p, "POST", "/kill-switch/global", json=body.model_dump(exclude_none=True),
                         extra_roles=(ROLE_PLATFORM_OPERATOR,))


@router.post("/kill-switch/global/challenge")
async def global_kill_switch_challenge(p: Principal = Depends(principal),
                                       client: KernelClient = Depends(get_kernel_client)):
    if p.user_id not in get_settings().platform_operator_ids:
        raise HTTPException(403, "Platform operator required")
    return await forward(client, p, "POST", "/kill-switch/global/challenge", json={},
                         extra_roles=(ROLE_PLATFORM_OPERATOR,))
