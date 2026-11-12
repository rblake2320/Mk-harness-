"""Password hashing (argon2id) and the request principal.

Tokens are JWTs that name a server-side session (`sid`, app/identity.py); the
session row — not the token — decides whether the request is authenticated.
Tokens also carry `pv`, a fingerprint of the password hash, so a password change
invalidates every token even before the session revocation is observed.
"""
import hashlib

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .db import get_db
from .models import User

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
    if not hashed:
        return False
    try:
        return _ph.verify(hashed, pw)
    except VerifyMismatchError:
        return False


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """The authenticated principal (rbac.route_guard has already run for every /api
    route; this returns its cached result or authenticates directly)."""
    from .identity import authenticate
    return authenticate(request, db)


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role not in ("owner", "admin"):
        raise HTTPException(403, "Admin role required")
    return user
