"""Auth: tenant signup (creates org + admin), login, refresh, member invite."""
from fastapi import APIRouter, Depends, HTTPException
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


class SignupIn(BaseModel):
    org_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    display_name: str = ""
    key_policy: str = "both"


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
    tenant = Tenant(name=body.org_name, key_policy=body.key_policy)
    db.add(tenant)
    db.flush()
    user = User(tenant_id=tenant.id, email=body.email.lower(),
                password_hash=hash_password(body.password),
                display_name=body.display_name or body.email.split("@")[0], role="admin")
    db.add(user)
    db.add(AuditLog(tenant_id=tenant.id, user_id=user.id, action="tenant.signup"))
    db.commit()
    return _tokens(user)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(403, "Account deactivated")
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
                display_name=body.display_name or body.email.split("@")[0], role=body.role)
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
