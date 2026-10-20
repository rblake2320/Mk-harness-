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

import hashlib
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..foundation import require_dispatch_timezone
from ..kernel import KernelClient, KernelUnavailable, get_kernel_client
from ..kernel.assertions import ROLE_PLATFORM_OPERATOR, roles_for
from ..models import Customer, User
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
        # Session id = stable fingerprint of the bearer token (never the token).
        auth = request.headers.get("Authorization", "")
        self.session_id = "jwt:" + hashlib.sha256(auth.encode()).hexdigest()[:24]


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
    if r.body is None:
        return Response(status_code=r.status_code, headers={"X-Request-Id": r.request_id})
    return JSONResponse(status_code=r.status_code, content=r.body,
                        headers={"X-Request-Id": r.request_id})


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


def _contact_customer(db: Session, p: Principal, req: dict) -> Customer | None:
    """Resolve the action's contact to this consultant's customer, if it names one."""
    res = req.get("resource") or {}
    cid = (req.get("arguments") or {}).get("contact_id") or (res.get("id") if res.get("type") == "contact" else None)
    if not cid:
        return None
    try:
        hex_id = uuid.UUID(str(cid)).hex
    except ValueError:
        return None
    c = db.get(Customer, hex_id)
    if not c or c.tenant_id != p.tenant_id:
        return None
    return c


@router.post("/actions")
async def propose(body: ProposeIn, p: Principal = Depends(principal),
                  client: KernelClient = Depends(get_kernel_client), db: Session = Depends(get_db)):
    req = dict(body.request)
    # F9: outreach to a customer whose destination timezone is unknown is blocked
    # here, before the kernel ever sees it. Non-outreach kinds are unaffected.
    if req.get("action_kind") in ("send_sms", "send_dm"):
        c = _contact_customer(db, p, req)
        if c is not None:
            require_dispatch_timezone(db, c)
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
    credential_id: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)
    client_data_json: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)
    authenticator_data: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)
    signature: str = Field(pattern=_B64URL, max_length=_B64URL_MAX)


class DecisionIn(BaseModel):
    action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: str | None = None
    webauthn: WebAuthnAssertionIn | None = None


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
                           client: KernelClient = Depends(get_kernel_client)):
    """Revoke a kernel session or user (H9). `session_id` omitted + `user_id`
    omitted → revokes the caller's *current* kernel session."""
    payload: dict[str, Any] = {"reason": body.reason}
    if body.user_id:
        payload["user_id"] = _uuid_text(body.user_id, "user_id")
    if body.session_id:
        payload["session_id"] = body.session_id
    elif not body.user_id:
        payload["session_id"] = p.session_id
    return await forward(client, p, "POST", "/revocations", json=payload)


@router.post("/approvals/{approval_id}/revoke")
async def revoke_approval(approval_id: str, p: Principal = Depends(principal),
                          client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST",
                         f"/approvals/{_uuid_text(approval_id, 'approval_id')}/revoke")


# --------------------------------------------------------------------------- #
# Consent + suppression
# --------------------------------------------------------------------------- #
class GrantIn(BaseModel):
    channel: str
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
    reason: str
    permanent: bool = True
    source: str


@router.post("/suppressions")
async def add_suppression(body: SuppressionIn, p: Principal = Depends(principal),
                          client: KernelClient = Depends(get_kernel_client)):
    return await forward(client, p, "POST", "/suppressions", json=body.model_dump())


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
