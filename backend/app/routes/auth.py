"""Auth: tenant signup (creates org + admin), login, refresh, member invite."""
import hmac
import json
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..cache import get_redis, log_redis_runtime_failure
from ..db import get_db
from ..models import AuditLog, AuthFactor, AuthRevocation, AuthSession, Tenant, User
from .. import security
from ..authorization import APP_ROLES, require_known_role
from ..auth_sessions import deliver_revocation, nonce_digest, revoke_local
from ..config import get_settings
from ..kernel import KernelClient, get_kernel_client
from ..security import (
    decode_token, dummy_verify, get_current_user, hash_password, make_access_token,
    make_refresh_token, password_fingerprint, require_admin, session_for, verify_password,
)

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
    session_id: str
    mfa_state: str


def _tokens(user: User, db: Session, session: AuthSession | None = None, nonce: str | None = None,
            *, verified: bool = False) -> TokenOut:
    require_known_role(user.role)
    nonce = nonce or secrets.token_hex(32)
    if session is None:
        verified = verified or not security.mfa_required()
        now = datetime.now(timezone.utc)
        session = AuthSession(id=uuid.uuid4().hex, tenant_id=user.tenant_id, user_id=user.id,
            refresh_digest=nonce_digest(nonce), mfa_verified_at=now if verified else None,
            expires_at=now + (timedelta(days=get_settings().refresh_token_days) if verified else timedelta(minutes=10)))
        db.add(session)
    db.commit()
    factor = db.get(AuthFactor, user.id)
    mfa_state = 'verified' if session.mfa_verified_at else ('verification_required' if factor and factor.confirmed_at else 'enrollment_required')
    return TokenOut(access_token=make_access_token(user, session),
                    refresh_token=make_refresh_token(user, session, nonce),
                    role=user.role, display_name=user.display_name, tenant_id=user.tenant_id, session_id=session.id, mfa_state=mfa_state)


@router.post("/signup", response_model=TokenOut, status_code=201)
def signup(body: SignupIn, db: Session = Depends(get_db)):
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
                display_name=body.display_name or body.email.split("@")[0], role="admin",
                referral_code=_gen_referral_code(db), referred_by=referred_by)
    db.add(user)
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, action="tenant.signup",
                    detail=f"ref={body.ref}" if referred_by else ""))
    db.commit()
    return _tokens(user, db)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
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
    require_known_role(user.role)
    _clear_failures(body.email.lower())
    return _tokens(user, db)


class RefreshIn(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token, "refresh")
    user = db.get(User, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or deactivated")
    # Refresh tokens minted before a password change are dead.
    if not hmac.compare_digest(str(payload.get("pv") or ""),
                               password_fingerprint(user.password_hash)):
        raise HTTPException(401, "Session expired — please sign in again")
    session = session_for(db, payload, user)
    nonce = secrets.token_hex(32)
    changed = db.execute(update(AuthSession).where(AuthSession.id == session.id,
        AuthSession.revoked_at.is_(None), AuthSession.refresh_digest == nonce_digest(payload["jti"]))
        .values(refresh_digest=nonce_digest(nonce))).rowcount
    if changed != 1:
        revoke_local(db, session, by=user.id, reason="refresh_reuse")
        db.commit()
        raise HTTPException(401, "Refresh credential already used; session revoked")
    return _tokens(user, db, session, nonce)


@router.get("/sessions")
def sessions(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current = request.state.auth_session.id
    return [{"id": row.id, "current": row.id == current, "created_at": row.created_at,
             "expires_at": row.expires_at, "revoked_at": row.revoked_at}
            for row in db.scalars(select(AuthSession).where(AuthSession.tenant_id == user.tenant_id,
                AuthSession.user_id == user.id).order_by(AuthSession.created_at.desc()).limit(100))]


@router.post("/sessions/{sid}/revoke")
async def revoke_session(sid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db),
                         client: KernelClient = Depends(get_kernel_client)):
    session = db.get(AuthSession, sid)
    if not session or session.user_id != user.id or session.tenant_id != user.tenant_id:
        raise HTTPException(404, "Session not found")
    revoke_local(db, session, by=user.id, reason="user_requested")
    db.commit()
    confirmed = await deliver_revocation(db, client, db.get(AuthRevocation, sid))
    return JSONResponse(status_code=200 if confirmed else 202,
        content={"revoked": True, "kernel_revocation": "confirmed" if confirmed else "pending"})


@router.post("/logout")
async def logout(request: Request, user: User = Depends(security.get_authenticated_user), db: Session = Depends(get_db),
                 client: KernelClient = Depends(get_kernel_client)):
    return await revoke_session(request.state.auth_session.id, user, db, client)


class InviteIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    display_name: str = ""
    role: str = "consultant"


@router.post("/members", status_code=201)
def add_member(body: InviteIn, admin: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    if body.role not in APP_ROLES:
        raise HTTPException(422, "role must be admin, manager, consultant or auditor")
    if db.scalar(select(User).where(User.email == body.email.lower())):
        raise HTTPException(409, "Email already registered")
    user = User(tenant_id=admin.tenant_id, email=body.email.lower(),
                password_hash=hash_password(body.password),
                display_name=body.display_name or body.email.split("@")[0], role=body.role,
                referral_code=_gen_referral_code(db))
    db.add(user)
    db.add(AuditLog(tenant_id=admin.tenant_id, user_id=admin.id,
                    action="member.add", detail=body.email.lower()))
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role}


@router.get('/members')
def list_members(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [{'id': member.id, 'email': member.email, 'display_name': member.display_name,
             'role': member.role, 'is_active': member.is_active}
            for member in db.scalars(select(User).where(User.tenant_id == admin.tenant_id).order_by(User.created_at))]


class MemberAccessIn(BaseModel):
    role: Literal['admin', 'manager', 'consultant', 'auditor'] | None = None
    is_active: bool | None = None


@router.patch('/members/{member_id}')
def change_member_access(member_id: str, body: MemberAccessIn, admin: User = Depends(require_admin),
                         db: Session = Depends(get_db)):
    if body.role is None and body.is_active is None:
        raise HTTPException(422, 'Provide a role or active state')
    # Tenant-level serialization: two admins cannot disable each other using
    # requests that authenticated before either change committed.
    db.execute(update(Tenant).where(Tenant.id == admin.tenant_id).values(name=Tenant.name))
    db.refresh(admin)
    if admin.role != 'admin' or not admin.is_active:
        raise HTTPException(403, 'Administrator access changed; sign in again')
    target = db.get(User, member_id, populate_existing=True)
    if not target or target.tenant_id != admin.tenant_id:
        raise HTTPException(404, 'Member not found')
    if target.id == admin.id and (body.role not in (None, 'admin') or body.is_active is False):
        raise HTTPException(409, 'Another administrator must change your access; self-removal is refused')
    before = {'role': target.role, 'is_active': target.is_active}
    if body.role is not None:
        target.role = body.role
    if body.is_active is not None:
        target.is_active = body.is_active
    after = {'role': target.role, 'is_active': target.is_active}
    if before != after:
        for session in db.scalars(select(AuthSession).where(AuthSession.user_id == target.id,
            AuthSession.tenant_id == admin.tenant_id, AuthSession.revoked_at.is_(None))):
            revoke_local(db, session, by=admin.id, reason='member_access_changed')
        db.add(AuditLog(tenant_id=admin.tenant_id, user_id=admin.id, action='member.access_change',
                       detail=json.dumps({'member_id': target.id, 'before': before, 'after': after}, sort_keys=True)))
    db.commit()
    return {'id': target.id, **after, 'kernel_revocation': 'pending' if before != after else 'unchanged'}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, user.tenant_id)
    return {"id": user.id, "email": user.email, "display_name": user.display_name,
            "role": user.role, "tenant": {"id": tenant.id, "name": tenant.name,
                                          "key_policy": tenant.key_policy}}


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=128)


@router.post("/change-password")
def change_password(body: ChangePasswordIn, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(401, "Current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    for session in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id,
                                                       AuthSession.revoked_at.is_(None))):
        revoke_local(db, session, by=user.id, reason="password_changed")
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id,
                    action="auth.change_password", detail=""))
    db.commit()
    return {"ok": True}
