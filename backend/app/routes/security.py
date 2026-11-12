"""Security settings: second factors, step-up, members, revocation status and
break-glass (S2, S3, S9). Route permissions live in app/rbac.py::ROUTE_POLICY."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import identity
from ..config import get_settings
from ..db import get_db
from ..foundation import audit, utcnow
from ..models import AuthSession, BreakGlassGrant, KernelRevocationOutbox, MfaFactor, Tenant, User
from ..security import get_current_user
from .auth import validate_role_change

router = APIRouter(tags=["security"])


def _session(request: Request) -> AuthSession:
    return request.state.auth_session


def _enrollment_guard(db: Session, user: User, request: Request) -> None:
    """Adding a factor to an account that already has one is a security change
    (step-up). The FIRST factor is added from the password-verified session."""
    if identity.has_confirmed_factor(db, user.id):
        identity.require_step_up(db, user, _session(request))


def _factor_view(f: MfaFactor) -> dict:
    return {"id": f.id, "kind": f.kind, "label": f.label, "created_at": f.created_at.isoformat(),
            "last_used_at": f.last_used_at.isoformat() if f.last_used_at else None}


def _first_factor_completed(db: Session, user: User, request: Request) -> list[str] | None:
    """Enrolling the first factor proves possession of it: the session is marked
    MFA-verified and the user receives recovery codes (shown once)."""
    session = _session(request)
    first = db.scalar(select(MfaFactor.id).where(MfaFactor.user_id == user.id, MfaFactor.confirmed_at.is_not(None),
                                                 MfaFactor.revoked_at.is_(None))) is None
    now = utcnow()
    session.mfa_at = session.mfa_at or now
    session.step_up_at = now
    return identity.new_recovery_codes(db, user) if first else None


# ------------------------------------------------------------------ factors
@router.get("/security/mfa")
def list_factors(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(MfaFactor).where(MfaFactor.user_id == user.id, MfaFactor.confirmed_at.is_not(None),
                                              MfaFactor.revoked_at.is_(None))).all()
    return {"factors": [_factor_view(f) for f in rows], "methods": identity.methods_for(db, user),
            "mfa_required": get_settings().mfa_required,
            "passkeys_available": bool(get_settings().app_webauthn_rp_id and get_settings().app_webauthn_origin_list)}


@router.post("/security/mfa/totp/begin")
def totp_begin(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _enrollment_guard(db, user, request)
    f, secret, uri = identity.begin_totp(db, user)
    db.commit()
    return {"factor_id": f.id, "secret": secret, "otpauth_uri": uri,
            "human_steps": ["Add this account to your authenticator app (scan or paste the secret).",
                            "Enter the 6-digit code it shows to finish."]}


class TotpConfirmIn(BaseModel):
    factor_id: str
    code: str = Field(max_length=16)
    label: str = Field(default="Authenticator app", max_length=60)


@router.post("/security/mfa/totp/confirm")
def totp_confirm(body: TotpConfirmIn, request: Request, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    _enrollment_guard(db, user, request)
    f = db.get(MfaFactor, body.factor_id)
    if (f is None or f.user_id != user.id or f.kind != "totp" or f.confirmed_at is not None
            or f.revoked_at is not None):
        raise HTTPException(404, "Enrollment not found — start again")
    if not identity.check_totp(db, f, body.code):
        session = _session(request)
        session.mfa_failures += 1
        if session.mfa_failures >= identity.MAX_FACTOR_FAILURES:
            f.revoked_at = utcnow()
            session.mfa_failures = 0
        db.commit()
        raise HTTPException(401, {"code": "SECOND_FACTOR_INVALID", "detail": "that code was not accepted"})
    codes = _first_factor_completed(db, user, request)
    f.confirmed_at, f.label = utcnow(), body.label or f.label
    audit(db, user.tenant_id, user.id, "mfa.factor_added", {"factor": f.id, "kind": "totp"})
    db.commit()
    return {"factor": _factor_view(f), "recovery_codes": codes}


@router.post("/security/mfa/passkey/begin")
def passkey_begin(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _enrollment_guard(db, user, request)
    opts = identity.passkey_registration_options(db, user, _session(request))
    db.commit()
    return opts


class PasskeyFinishIn(BaseModel):
    credential: dict
    label: str = Field(default="Passkey", max_length=60)


@router.post("/security/mfa/passkey/finish")
def passkey_finish(body: PasskeyFinishIn, request: Request, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    _enrollment_guard(db, user, request)
    codes = None
    f = identity.passkey_register(db, user, _session(request), body.credential, body.label)
    db.flush()
    remaining_others = db.scalar(select(MfaFactor.id).where(
        MfaFactor.user_id == user.id, MfaFactor.id != f.id, MfaFactor.confirmed_at.is_not(None),
        MfaFactor.revoked_at.is_(None)))
    if remaining_others is None:
        session = _session(request)
        now = utcnow()
        session.mfa_at = session.mfa_at or now
        session.step_up_at = now
        codes = identity.new_recovery_codes(db, user)
    audit(db, user.tenant_id, user.id, "mfa.factor_added", {"factor": f.id, "kind": "webauthn"})
    db.commit()
    return {"factor": _factor_view(f), "recovery_codes": codes}


@router.post("/security/mfa/{fid}/revoke")
def revoke_factor(fid: str, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    f = db.get(MfaFactor, fid)
    if f is None or f.user_id != user.id or f.revoked_at is not None:
        raise HTTPException(404, "Factor not found")
    others = db.scalar(select(MfaFactor.id).where(MfaFactor.user_id == user.id, MfaFactor.id != f.id,
                                                  MfaFactor.confirmed_at.is_not(None), MfaFactor.revoked_at.is_(None)))
    if others is None and get_settings().mfa_required:
        raise HTTPException(409, {"code": "LAST_FACTOR", "detail": "add another factor before removing your last one"})
    f.revoked_at = utcnow()
    audit(db, user.tenant_id, user.id, "mfa.factor_removed", {"factor": f.id, "kind": f.kind})
    db.commit()
    return {"ok": True}


@router.post("/security/mfa/recovery-codes")
def regenerate_recovery_codes(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not identity.has_confirmed_factor(db, user.id):
        raise HTTPException(409, {"code": "NO_FACTOR", "detail": "add a second factor first"})
    codes = identity.new_recovery_codes(db, user)
    audit(db, user.tenant_id, user.id, "mfa.recovery_codes_regenerated", {})
    db.commit()
    return {"recovery_codes": codes}


# ------------------------------------------------------------------ step-up
class StepUpIn(BaseModel):
    method: str = Field(pattern="^(totp|webauthn|password)$")
    code: str = Field(default="", max_length=32)
    credential: dict | None = None
    password: str = Field(default="", max_length=128)


@router.post("/security/step-up")
def step_up(body: StepUpIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    session = _session(request)
    method = identity.verify_second_factor(db, user, session, method=body.method, code=body.code,
                                           credential=body.credential, password=body.password, purpose="step_up")
    audit(db, user.tenant_id, user.id, "auth.step_up", {"method": method})
    db.commit()
    window = min(max(get_settings().step_up_window_minutes, 1), 15)
    return {"ok": True, "valid_until": (session.step_up_at + timedelta(minutes=window)).isoformat()}


@router.post("/security/step-up/passkey/options")
def step_up_passkey_options(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    opts = identity.passkey_auth_options(db, user, _session(request), "step_up")
    db.commit()
    return opts


# ------------------------------------------------------------------ members
@router.get("/security/members")
def list_members(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(User).where(User.tenant_id == user.tenant_id).order_by(User.created_at)).all()
    return [{"id": u.id, "email": u.email, "display_name": u.display_name, "role": u.role,
             "works_for": u.works_for, "active": u.is_active,
             "second_factor": identity.has_confirmed_factor(db, u.id)} for u in rows]


def _member(db: Session, actor: User, uid: str) -> User:
    m = db.get(User, uid)
    if m is None or m.tenant_id != actor.tenant_id:
        raise HTTPException(404, "Member not found")
    return m


def _guard_owner(db: Session, actor: User, member: User, new_role: str | None = None) -> None:
    """Only an owner may change or deactivate an owner/admin; the last active owner
    can never be demoted or deactivated (no tenant may lose its owner)."""
    if member.role in ("owner", "admin") and actor.role != "owner":
        raise HTTPException(403, {"code": "OWNER_REQUIRED", "detail": "only the owner can change an owner or admin"})
    if member.role == "owner" and (new_role is None or new_role != "owner"):
        owners = db.scalars(select(User.id).where(User.tenant_id == actor.tenant_id, User.role == "owner",
                                                  User.is_active.is_(True))).all()
        if len(owners) <= 1:
            raise HTTPException(409, {"code": "LAST_OWNER", "detail": "a business must keep at least one active owner"})


class RoleIn(BaseModel):
    role: str
    works_for: str | None = None


@router.post("/security/members/{uid}/role")
def change_role(uid: str, body: RoleIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    m = _member(db, user, uid)
    _guard_owner(db, user, m, body.role)
    works_for = validate_role_change(db, user, body.role, body.works_for)
    if works_for == m.id:
        raise HTTPException(422, "a member cannot work for themselves")
    before = m.role
    m.role, m.works_for = body.role, works_for
    # A role change takes effect now: existing sessions carry the old role in their tokens.
    n = identity.revoke_user_sessions(db, m, by=user.id, reason="role_changed", actor=user)
    audit(db, user.tenant_id, user.id, "member.role", {"member": m.id, "from_role": before, "to_role": body.role,
                                                      "works_for": works_for, "sessions_revoked": n})
    db.commit()
    identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
    return {"id": m.id, "role": m.role, "works_for": m.works_for, "sessions_revoked": n}


@router.post("/security/members/{uid}/deactivate")
def deactivate_member(uid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    m = _member(db, user, uid)
    if m.id == user.id:
        raise HTTPException(409, {"code": "SELF_DEACTIVATION", "detail": "you cannot deactivate yourself"})
    _guard_owner(db, user, m)
    m.is_active = False
    n = identity.revoke_user_sessions(db, m, by=user.id, reason="deactivated", actor=user)
    identity.revoke_user_in_kernel(db, m, actor=user, reason="member deactivated")
    audit(db, user.tenant_id, user.id, "member.deactivate", {"member": m.id, "sessions_revoked": n})
    db.commit()
    identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
    return {"id": m.id, "active": False, "sessions_revoked": n}


@router.post("/security/members/{uid}/sessions/revoke")
def revoke_member_sessions(uid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    m = _member(db, user, uid)
    if m.role in ("owner", "admin") and user.role != "owner" and m.id != user.id:
        raise HTTPException(403, {"code": "OWNER_REQUIRED"})
    n = identity.revoke_user_sessions(db, m, by=user.id, reason="admin_revoked", actor=user)
    audit(db, user.tenant_id, user.id, "member.sessions_revoked", {"member": m.id, "sessions_revoked": n})
    db.commit()
    identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
    return {"sessions_revoked": n}


@router.get("/security/revocations")
def revocation_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    result = identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
    pending = db.scalars(select(KernelRevocationOutbox).where(
        KernelRevocationOutbox.tenant_id == user.tenant_id, KernelRevocationOutbox.delivered_at.is_(None))).all()
    return {"delivered_now": result["delivered"], "kernel_configured": not result["not_configured"],
            "pending": [{"id": r.id, "target_user_id": r.target_user_id, "session": bool(r.session_id),
                         "created_at": r.created_at.isoformat(), "attempts": r.attempts,
                         "last_error": r.last_error} for r in pending]}


# ------------------------------------------------------------------ break-glass (tenant side)
def _grant_view(g: BreakGlassGrant) -> dict:
    return {"id": g.id, "status": _status(g), "requested_by": g.requested_by, "subject_user_id": g.subject_user_id,
            "reason": g.reason, "ticket_ref": g.ticket_ref, "scope": g.scope, "duration_minutes": g.duration_minutes,
            "requested_at": g.requested_at.isoformat(), "decided_by": g.decided_by or None,
            "expires_at": g.expires_at.isoformat() if g.expires_at else None, "access_count": g.access_count}


def _status(g: BreakGlassGrant) -> str:
    if g.status == "approved" and g.expires_at is not None and identity._aware(g.expires_at) <= utcnow():
        return "expired"
    return g.status


@router.get("/security/break-glass")
def tenant_grants(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(BreakGlassGrant).where(BreakGlassGrant.tenant_id == user.tenant_id)
                      .order_by(BreakGlassGrant.requested_at.desc()).limit(100)).all()
    return [_grant_view(g) for g in rows]


def _tenant_grant(db: Session, user: User, gid: str) -> BreakGlassGrant:
    g = db.get(BreakGlassGrant, gid)
    if g is None or g.tenant_id != user.tenant_id:
        raise HTTPException(404, "Request not found")
    return g


@router.post("/security/break-glass/{gid}/approve")
def approve_grant(gid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    g = _tenant_grant(db, user, gid)
    if g.status != "pending":
        raise HTTPException(409, {"code": "NOT_PENDING", "detail": f"request is {_status(g)}"})
    if g.requested_by == user.id:
        raise HTTPException(403, {"code": "SELF_APPROVAL", "detail": "support cannot approve its own access"})
    now = utcnow()
    g.status, g.decided_by, g.decided_at = "approved", user.id, now
    g.expires_at = now + timedelta(minutes=g.duration_minutes)
    audit(db, user.tenant_id, user.id, "breakglass.approved",
          {"grant": g.id, "support_user": g.requested_by, "minutes": g.duration_minutes, "ticket": g.ticket_ref})
    db.commit()
    return _grant_view(g)


@router.post("/security/break-glass/{gid}/deny")
def deny_grant(gid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    g = _tenant_grant(db, user, gid)
    if g.status != "pending":
        raise HTTPException(409, {"code": "NOT_PENDING", "detail": f"request is {_status(g)}"})
    g.status, g.decided_by, g.decided_at = "denied", user.id, utcnow()
    audit(db, user.tenant_id, user.id, "breakglass.denied_request", {"grant": g.id})
    db.commit()
    return _grant_view(g)


def end_grant(db: Session, g: BreakGlassGrant, by: str) -> int:
    g.status, g.revoked_at, g.revoked_by = "revoked", utcnow(), by
    n = 0
    for s in db.scalars(select(AuthSession).where(AuthSession.breakglass_grant_id == g.id,
                                                  AuthSession.revoked_at.is_(None))).all():
        identity.revoke_session(db, s, by=by, reason="breakglass_revoked")
        n += 1
    return n


@router.post("/security/break-glass/{gid}/revoke")
def revoke_grant(gid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    g = _tenant_grant(db, user, gid)
    if g.status not in ("pending", "approved"):
        raise HTTPException(409, {"code": "NOT_ACTIVE", "detail": f"request is {_status(g)}"})
    n = end_grant(db, g, user.id)
    audit(db, user.tenant_id, user.id, "breakglass.revoked", {"grant": g.id, "sessions_ended": n})
    db.commit()
    return _grant_view(g)


# ------------------------------------------------------------------ break-glass (support side)
class BreakGlassRequestIn(BaseModel):
    tenant_id: str = Field(min_length=32, max_length=32)
    subject_user_id: str = Field(min_length=32, max_length=32)
    reason: str = Field(min_length=20, max_length=1000)
    ticket_ref: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._:#/-]+$")
    duration_minutes: int = Field(ge=5)


@router.post("/support/break-glass", status_code=201)
def request_grant(body: BreakGlassRequestIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if body.duration_minutes > get_settings().breakglass_max_minutes:
        raise HTTPException(422, {"code": "DURATION_TOO_LONG",
                                  "detail": f"at most {get_settings().breakglass_max_minutes} minutes"})
    tenant = db.get(Tenant, body.tenant_id)
    subject = db.get(User, body.subject_user_id)
    if tenant is None or subject is None or subject.tenant_id != tenant.id:
        raise HTTPException(404, "Tenant or user not found")
    if tenant.id == user.tenant_id:
        raise HTTPException(409, {"code": "OWN_TENANT", "detail": "use your own account for your own business"})
    g = BreakGlassGrant(tenant_id=tenant.id, subject_user_id=subject.id, requested_by=user.id, reason=body.reason,
                        ticket_ref=body.ticket_ref, duration_minutes=body.duration_minutes)
    db.add(g)
    db.flush()
    # Visible to the target tenant (who must approve) and to the support org.
    audit(db, tenant.id, user.id, "breakglass.requested",
          {"grant": g.id, "ticket": g.ticket_ref, "minutes": g.duration_minutes, "subject": subject.id})
    audit(db, user.tenant_id, user.id, "breakglass.requested", {"grant": g.id, "target_tenant": tenant.id})
    db.commit()
    return _grant_view(g)


@router.get("/support/break-glass")
def my_grants(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(BreakGlassGrant).where(BreakGlassGrant.requested_by == user.id)
                      .order_by(BreakGlassGrant.requested_at.desc()).limit(100)).all()
    return [_grant_view(g) for g in rows]


@router.post("/support/break-glass/{gid}/session")
def grant_session(gid: str, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """A read-only, non-refreshable session in the target tenant that ends when the
    grant ends. Support keeps its own identity (sub = support user id)."""
    g = db.get(BreakGlassGrant, gid)
    if g is None or g.requested_by != user.id:
        raise HTTPException(404, "Request not found")
    if _status(g) != "approved":
        raise HTTPException(409, {"code": "NOT_APPROVED", "detail": f"request is {_status(g)}"})
    if _session(request).mfa_at is None:
        raise HTTPException(403, {"code": "MFA_REQUIRED", "detail": "break-glass needs a second-factor sign-in"})
    s = identity.new_session(db, user, request, kind="breakglass", tenant_id=g.tenant_id, grant=g,
                             expires_at=identity._aware(g.expires_at))
    s.mfa_at = utcnow()
    audit(db, g.tenant_id, user.id, "breakglass.session", {"grant": g.id, "session": s.id})
    db.commit()
    return identity.token_pair(user, s, role="support")
