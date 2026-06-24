"""Auth: tenant signup (creates org + admin), login, refresh, member invite."""
import secrets
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditLog, Tenant, User
from ..security import (
    decode_token, get_current_user, hash_password, make_access_token,
    make_refresh_token, require_admin, verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Login brute-force protection: 5 failures per email per 15 minutes → lockout.
# In-process store; swap for Redis on multi-replica deployments.
# ---------------------------------------------------------------------------
_bf_lock = threading.Lock()
_bf_hits: dict[str, list[float]] = {}
_BF_MAX = 5
_BF_WINDOW = 900  # 15 minutes


def _check_brute_force(email: str) -> None:
    now = time.monotonic()
    with _bf_lock:
        window = [t for t in _bf_hits.get(email, []) if now - t < _BF_WINDOW]
        if len(window) >= _BF_MAX:
            raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
        _bf_hits[email] = window


def _record_failure(email: str) -> None:
    now = time.monotonic()
    with _bf_lock:
        hits = [t for t in _bf_hits.get(email, []) if now - t < _BF_WINDOW]
        hits.append(now)
        _bf_hits[email] = hits


def _clear_failures(email: str) -> None:
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


def _tokens(user: User) -> TokenOut:
    return TokenOut(access_token=make_access_token(user),
                    refresh_token=make_refresh_token(user),
                    role=user.role, display_name=user.display_name, tenant_id=user.tenant_id)


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
    return _tokens(user)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    _check_brute_force(body.email.lower())
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not verify_password(body.password, user.password_hash):
        _record_failure(body.email.lower())
        raise HTTPException(401, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(403, "Account deactivated")
    _clear_failures(body.email.lower())
    return _tokens(user)


class RefreshIn(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token, "refresh")
    user = db.get(User, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or deactivated")
    return _tokens(user)


class InviteIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    display_name: str = ""
    role: str = "consultant"


@router.post("/members", status_code=201)
def add_member(body: InviteIn, admin: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    if body.role not in ("admin", "consultant"):
        raise HTTPException(422, "role must be admin or consultant")
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


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, user.tenant_id)
    return {"id": user.id, "email": user.email, "display_name": user.display_name,
            "role": user.role, "tenant": {"id": tenant.id, "name": tenant.name,
                                          "key_policy": tenant.key_policy}}
