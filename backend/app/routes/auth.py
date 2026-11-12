"""Auth: tenant signup (creates org + owner), login with second factor, refresh
rotation, logout, sessions, member invite. Session and factor logic: app/identity.py."""
import secrets
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import identity
from ..cache import get_redis, log_redis_runtime_failure
from ..db import get_db
from ..foundation import audit, utcnow
from ..models import AuditLog, AuthSession, Tenant, User
from ..rbac import DELEGATED_ROLES, ROLES
from ..security import dummy_verify, get_current_user, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Login brute-force protection: 5 failures per email per 15 minutes → lockout.
# Redis-backed when REDIS_URL is set; in-process fallback for dev / tests.
# ---------------------------------------------------------------------------
_bf_lock = threading.Lock()
_bf_hits: dict[str, list[float]] = {}
_BF_MAX = 5
_BF_WINDOW = 900  # 15 minutes


def _check_brute_force(email: str) -> None:
    r = get_redis()
    if r is not None:
        try:
            key = f"bf:{email}"
            count = r.get(key)
            if count and int(count) >= _BF_MAX:
                raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
            return
        except HTTPException:
            raise
        except Exception as exc:
            log_redis_runtime_failure(exc)  # fall through to in-process check

    now = time.monotonic()
    with _bf_lock:
        window = [t for t in _bf_hits.get(email, []) if now - t < _BF_WINDOW]
        if len(window) >= _BF_MAX:
            raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
        _bf_hits[email] = window


def _record_failure(email: str) -> None:
    r = get_redis()
    if r is not None:
        try:
            key = f"bf:{email}"
            pipe = r.pipeline()
            pipe.incr(key)
            pipe.expire(key, _BF_WINDOW)
            pipe.execute()
            return
        except Exception as exc:
            log_redis_runtime_failure(exc)  # record in-process instead

    now = time.monotonic()
    with _bf_lock:
        hits = [t for t in _bf_hits.get(email, []) if now - t < _BF_WINDOW]
        hits.append(now)
        _bf_hits[email] = hits


def _clear_failures(email: str) -> None:
    r = get_redis()
    if r is not None:
        try:
            r.delete(f"bf:{email}")
            return
        except Exception as exc:
            log_redis_runtime_failure(exc)  # clear in-process instead

    with _bf_lock:
        _bf_hits.pop(email, None)


def _gen_referral_code(db: Session) -> str:
    """8-char uppercase code, retried on the rare collision."""
    for _ in range(5):
        code = secrets.token_hex(4).upper()
        if not db.scalar(select(User).where(User.referral_code == code)):
            return code
    return secrets.token_hex(6).upper()


class SignupIn(BaseModel):
    org_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    display_name: str = ""
    key_policy: str = "both"
    ref: str | None = None   # referral code of the inviting consultant


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    role: str
    display_name: str
    tenant_id: str
    session_id: str = ""
    # True when MFA is required and this account has no second factor yet: the
    # session reaches only the enrollment routes until one is confirmed.
    mfa_enrollment_required: bool = False


def _tokens(db: Session, user: User, session: AuthSession) -> dict:
    out = identity.token_pair(user, session)
    out["mfa_enrollment_required"] = identity.mfa_blocks(db, user, session)
    return out


@router.post("/signup", response_model=TokenOut, status_code=201)
def signup(body: SignupIn, request: Request, db: Session = Depends(get_db)):
    if body.key_policy not in ("central", "byo", "both"):
        raise HTTPException(422, "key_policy must be central, byo, or both")
    if db.scalar(select(User).where(User.email == body.email.lower())):
        raise HTTPException(409, "Email already registered")
    referred_by = None
    if body.ref:
        referrer = db.scalar(select(User).where(User.referral_code == body.ref.upper()))
        if referrer:
            referred_by = referrer.id
    tenant = Tenant(name=body.org_name, key_policy=body.key_policy)
    db.add(tenant)
    db.flush()
    user = User(tenant_id=tenant.id, email=body.email.lower(),
                password_hash=hash_password(body.password),
                display_name=body.display_name or body.email.split("@")[0], role="owner",
                referral_code=_gen_referral_code(db), referred_by=referred_by)
    db.add(user)
    db.flush()
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, action="tenant.signup",
                    detail=f"ref={body.ref}" if referred_by else ""))
    session = identity.new_session(db, user, request)
    db.commit()
    return _tokens(db, user, session)


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    """Password first. With a confirmed second factor the answer is an MFA challenge
    (`mfa_token`, 5 minutes, no access); otherwise tokens (limited to enrollment while
    MFA is required and no factor exists)."""
    _check_brute_force(body.email.lower())
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user:
        dummy_verify()  # equalise timing — no user-enumeration oracle
        _record_failure(body.email.lower())
        raise HTTPException(401, "Invalid email or password")
    if not verify_password(body.password, user.password_hash):
        _record_failure(body.email.lower())
        raise HTTPException(401, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(403, "Account deactivated")
    _clear_failures(body.email.lower())
    session = identity.new_session(db, user, request)
    if identity.has_confirmed_factor(db, user.id):
        db.commit()
        return {"mfa_required": True, "mfa_token": identity.mfa_token(session, user),
                "methods": identity.methods_for(db, user),
                "expires_in": 60 * identity.get_settings().mfa_challenge_minutes}
    db.commit()
    _retry_revocations(db, user.tenant_id)
    return _tokens(db, user, session)


class MfaVerifyIn(BaseModel):
    mfa_token: str
    method: str = Field(pattern="^(totp|webauthn|recovery)$")
    code: str = Field(default="", max_length=32)
    credential: dict | None = None


def _mfa_session(db: Session, mfa_token: str) -> tuple[User, AuthSession]:
    payload = identity._decode(mfa_token, "mfa")
    session = identity._live_session(db, payload)
    user = db.get(User, payload["sub"])
    if not user or not user.is_active or session.mfa_at is not None:
        raise HTTPException(401, "Sign in again")
    import hmac
    if not hmac.compare_digest(str(payload.get("pv") or ""), identity._pv(user)):
        raise HTTPException(401, "Sign in again")
    return user, session


@router.post("/mfa/verify", response_model=TokenOut)
def mfa_verify(body: MfaVerifyIn, db: Session = Depends(get_db)):
    user, session = _mfa_session(db, body.mfa_token)
    method = identity.verify_second_factor(db, user, session, method=body.method, code=body.code,
                                           credential=body.credential, purpose="login")
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action="auth.mfa", detail=method))
    db.commit()
    _retry_revocations(db, user.tenant_id)
    return _tokens(db, user, session)


class MfaOptionsIn(BaseModel):
    mfa_token: str


@router.post("/mfa/passkey/options")
def mfa_passkey_options(body: MfaOptionsIn, db: Session = Depends(get_db)):
    user, session = _mfa_session(db, body.mfa_token)
    opts = identity.passkey_auth_options(db, user, session, "login")
    db.commit()
    return opts


class RefreshIn(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    """Rotating refresh: each refresh token works once. Re-use of an old one means it
    leaked — the whole session is revoked."""
    payload = identity._decode(body.refresh_token, "refresh")
    session = identity._live_session(db, payload)
    user = db.get(User, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or deactivated")
    import hmac
    if not hmac.compare_digest(str(payload.get("pv") or ""), identity._pv(user)):
        raise HTTPException(401, "Session expired — please sign in again")
    rc = payload.get("rc")
    if not isinstance(rc, int) or rc != session.refresh_counter:
        identity.revoke_session(db, session, by="system", reason="refresh_token_reuse")
        db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action="auth.refresh_reuse", detail=session.id))
        db.commit()
        identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
        raise HTTPException(401, {"code": "SESSION_ENDED", "detail": "this sign-in was used elsewhere — sign in again"})
    session.refresh_counter += 1
    db.commit()
    return _tokens(db, user, session)


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    identity.revoke_session(db, request.state.auth_session, by=user.id, reason="logout")
    db.commit()
    identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
    return {"ok": True}


@router.get("/sessions")
def my_sessions(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.kind == "user")
                      .order_by(AuthSession.created_at.desc()).limit(50)).all()
    current = request.state.auth_session.id
    return [{"id": s.id, "client": s.client_label, "created_at": s.created_at.isoformat(),
             "last_seen_at": s.last_seen_at.isoformat(), "second_factor": s.mfa_at is not None,
             "current": s.id == current, "revoked": s.revoked_at is not None,
             "revoked_reason": s.revoked_reason or None} for s in rows]


@router.post("/sessions/{sid}/revoke")
def revoke_my_session(sid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.get(AuthSession, sid)
    if s is None or s.user_id != user.id or s.kind != "user":
        raise HTTPException(404, "Session not found")
    identity.revoke_session(db, s, by=user.id, reason="user_revoked")
    db.commit()
    identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
    return {"ok": True}


@router.post("/sessions/revoke-others")
def revoke_other_sessions(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    n = identity.revoke_user_sessions(db, user, by=user.id, reason="user_revoked_others",
                                      except_sid=request.state.auth_session.id)
    db.commit()
    identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
    return {"revoked": n}


def _retry_revocations(db: Session, tenant_id: str) -> None:
    """Opportunistic retry of undelivered kernel revocations (never blocks sign-in)."""
    try:
        identity.deliver_kernel_revocations(db, tenant_id=tenant_id, limit=20)
    except Exception:  # noqa: BLE001 — retry is best effort; the outbox keeps the row
        db.rollback()


class InviteIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    display_name: str = ""
    role: str = "consultant"
    works_for: str | None = None   # required for assistant/viewer: whose book they work in


def validate_role_change(db: Session, actor: User, role: str, works_for: str | None) -> str | None:
    """Shared by invite and role change. Only an owner can create owners or admins;
    assistant/viewer must name a consultant-capable member of the same tenant."""
    if role not in ROLES:
        raise HTTPException(422, f"role must be one of {', '.join(ROLES)}")
    if role in ("owner", "admin") and actor.role != "owner":
        raise HTTPException(403, {"code": "OWNER_REQUIRED", "detail": "only the owner can grant owner or admin"})
    if role in DELEGATED_ROLES:
        target = db.get(User, works_for or "")
        if (target is None or target.tenant_id != actor.tenant_id or not target.is_active
                or target.role not in ("owner", "admin", "consultant")):
            raise HTTPException(422, {"code": "WORKS_FOR_REQUIRED",
                                      "detail": "assistant/viewer must work for an active consultant in this business"})
        return target.id
    if works_for:
        raise HTTPException(422, "works_for applies only to assistant and viewer")
    return None


@router.post("/members", status_code=201)
def add_member(body: InviteIn, admin: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    works_for = validate_role_change(db, admin, body.role, body.works_for)
    if db.scalar(select(User).where(User.email == body.email.lower())):
        raise HTTPException(409, "Email already registered")
    user = User(tenant_id=admin.tenant_id, email=body.email.lower(),
                password_hash=hash_password(body.password),
                display_name=body.display_name or body.email.split("@")[0], role=body.role,
                works_for=works_for, referral_code=_gen_referral_code(db))
    db.add(user)
    db.flush()
    audit(db, admin.tenant_id, admin.id, "member.add", {"member": user.id, "role": body.role,
                                                         "works_for": works_for})
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role, "works_for": works_for}


@router.get("/me")
def me(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from ..rbac import ROLE_PERMISSIONS
    tenant = db.get(Tenant, user.tenant_id)
    session = request.state.auth_session
    grant = request.state.breakglass
    return {"id": user.id, "email": user.email, "display_name": user.display_name,
            "role": user.role, "works_for": getattr(user, "works_for", None),
            "permissions": sorted(ROLE_PERMISSIONS.get(user.role, ())) if grant is None else ["breakglass.read"],
            "tenant": {"id": tenant.id, "name": tenant.name, "key_policy": tenant.key_policy},
            "session": {"id": session.id, "second_factor": session.mfa_at is not None,
                        "mfa_enrollment_required": identity.mfa_blocks(db, user, session),
                        "methods": identity.methods_for(db, user) if grant is None else []},
            "breakglass": {"grant_id": grant.id, "expires_at": grant.expires_at.isoformat()} if grant else None}


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=128)


@router.post("/change-password")
def change_password(body: ChangePasswordIn, request: Request, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """Requires the current password and a fresh second factor (step-up). Every other
    session is revoked — locally and in the kernel — and this session gets new tokens."""
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(403, "Current password is incorrect")   # authenticated: not a token problem
    user.password_hash = hash_password(body.new_password)
    current = request.state.auth_session
    n = identity.revoke_user_sessions(db, user, by=user.id, reason="password_changed", except_sid=current.id)
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id,
                    action="auth.change_password", detail=f"sessions_revoked={n}"))
    db.commit()
    identity.deliver_kernel_revocations(db, tenant_id=user.tenant_id)
    return {"ok": True, "sessions_revoked": n, **_tokens(db, user, current)}
