"""Password hashing (argon2id) and JWT access/refresh tokens.

Tokens carry a `pv` (password version) claim — a short fingerprint of the
user's current password hash. Changing the password changes the fingerprint,
which immediately invalidates every previously issued access AND refresh
token. A persistent session row additionally governs access, revocation and
single-use refresh rotation; a JWT signature alone is never session authority.
"""
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import AuthSession, User

_ph = PasswordHasher()

# Static hash used to equalise timing when the email does not exist —
# prevents user enumeration via the argon2-verify timing oracle.
_DUMMY_HASH = PasswordHasher().hash("timing-equalizer-not-a-real-password")


def password_fingerprint(password_hash: str) -> str:
    """Short, non-reversible fingerprint of the stored hash for the `pv` claim."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:12]


def dummy_verify() -> None:
    """Burn the same time as a real argon2 verification (constant-time login path)."""
    try:
        _ph.verify(_DUMMY_HASH, "wrong-password")
    except VerifyMismatchError:
        pass


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except VerifyMismatchError:
        return False


def _make_token(sub: str, tenant_id: str, role: str, kind: str, minutes: int,
                pv: str, session_id: str, nonce: str) -> str:
    s = get_settings()
    payload = {
        "sub": sub, "tid": tenant_id, "role": role, "kind": kind, "pv": pv,
        "sid": session_id, "jti": nonce,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm="HS256")


def make_access_token(user: User, session: AuthSession) -> str:
    return _make_token(user.id, user.tenant_id, user.role, "access",
                       get_settings().access_token_minutes,
                       pv=password_fingerprint(user.password_hash), session_id=session.id, nonce=uuid.uuid4().hex)


def make_refresh_token(user: User, session: AuthSession, nonce: str) -> str:
    return _make_token(user.id, user.tenant_id, user.role, "refresh",
                       get_settings().refresh_token_days * 24 * 60,
                       pv=password_fingerprint(user.password_hash), session_id=session.id, nonce=nonce)


def decode_token(token: str, expected_kind: str) -> dict:
    s = get_settings()
    try:
        payload = jwt.decode(token, s.jwt_secret, algorithms=["HS256"],
                             options={"require": ["sub", "tid", "sid", "pv", "kind", "jti", "iat", "exp"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    if payload.get("kind") != expected_kind:
        raise HTTPException(401, "Wrong token type")
    if any(not isinstance(payload.get(k), str) or not payload[k] for k in ("sub", "tid", "sid", "pv", "jti")):
        raise HTTPException(401, "Invalid token claims")
    return payload


def session_for(db: Session, payload: dict, user: User) -> AuthSession:
    session = db.get(AuthSession, payload["sid"])
    if (not session or session.user_id != user.id or session.tenant_id != user.tenant_id
            or payload["tid"] != user.tenant_id or session.revoked_at is not None
            or session.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)):
        raise HTTPException(401, "Session expired or revoked")
    return session


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    payload = decode_token(auth[7:], "access")
    user = db.get(User, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or deactivated")
    # Reject tokens minted before the most recent password change.
    # compare_digest: constant-time — no oracle on how many chars matched.
    if not hmac.compare_digest(str(payload.get("pv") or ""),
                               password_fingerprint(user.password_hash)):
        raise HTTPException(401, "Session expired — please sign in again")
    request.state.auth_session = session_for(db, payload, user)
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admin role required")
    return user
