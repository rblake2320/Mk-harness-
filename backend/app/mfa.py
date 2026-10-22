"""Mandatory TOTP MFA: encrypted secrets, durable replay/attempt state, backups.

The second-factor verifier has no provider calls and no runtime bypass. Used OTP
counters and recovery-code consumption commit with the authorized operation.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi import HTTPException
from sqlalchemy import case, delete, or_, update
from sqlalchemy.orm import Session

from .config import get_settings
from .crypto import decrypt_secret, encrypt_secret
from .models import AuthFactor, AuthRecoveryCode, User


def utcnow():
    return datetime.now(timezone.utc)


def aad(user: User, session_id: str | None = None) -> str:
    return f'mfa:{user.tenant_id}:{user.id}' + (f':pending:{session_id}' if session_id else '')


def seal(user: User, secret: str, session_id: str | None = None) -> str:
    return encrypt_secret(get_settings().master_key_bytes, secret, aad(user, session_id))


def unseal(user: User, encrypted: str, session_id: str | None = None) -> str:
    return decrypt_secret(get_settings().master_key_bytes, encrypted, aad(user, session_id))


def factor_for(db: Session, user: User) -> AuthFactor | None:
    row = db.get(AuthFactor, user.id)
    if row and row.tenant_id != user.tenant_id:
        raise HTTPException(401, 'Invalid factor scope')
    return row


def check_limit(db: Session, factor: AuthFactor) -> None:
    if factor.locked_until:
        if factor.locked_until.replace(tzinfo=timezone.utc) > utcnow():
            raise HTTPException(429, {'code': 'MFA_LOCKED', 'message': 'Too many failed second-factor attempts. Try again in 15 minutes.'})
        # Do not clear a concurrent lockout from an older ORM snapshot.
        # Expired locks are reset only by a conditional write below.


def reject_code(db: Session, factor: AuthFactor) -> None:
    db.execute(update(AuthFactor).where(AuthFactor.user_id == factor.user_id).values(
        failed_attempts=AuthFactor.failed_attempts + 1,
        locked_until=case((AuthFactor.failed_attempts >= 4, utcnow() + timedelta(minutes=15)),
                          else_=AuthFactor.locked_until)))
    db.commit()  # failure counters are durable even though the request is refused
    raise HTTPException(401, {'code': 'MFA_INVALID', 'message': 'Invalid or already used second-factor credential'})


def matching_counter(secret: str, code: str) -> int | None:
    current = int(utcnow().timestamp()) // 30
    otp = pyotp.TOTP(secret)
    candidates = [counter for counter in (current - 1, current, current + 1)
                  if hmac.compare_digest(otp.at(counter * 30), code)]
    return max(candidates) if candidates else None


def recovery_digest(code: str) -> str:
    return hashlib.sha256(code.strip().replace('-', '').lower().encode()).hexdigest()


def claim_factor(db: Session, factor: AuthFactor) -> None:
    """Serialize verification/replacement against the live factor, not a snapshot.

    The conditional write takes a row lock on Postgres (a write lock on SQLite)
    until the code-consumption transaction commits. Recovery attempts cannot
    clear a lockout or authenticate against a factor replaced during the check.
    """
    now = utcnow()
    changed = db.execute(update(AuthFactor).where(AuthFactor.user_id == factor.user_id,
        AuthFactor.tenant_id == factor.tenant_id, AuthFactor.secret_enc == factor.secret_enc,
        or_(AuthFactor.locked_until.is_(None), AuthFactor.locked_until <= now)).values(
            failed_attempts=case((AuthFactor.locked_until <= now, 0), else_=AuthFactor.failed_attempts),
            locked_until=None).execution_options(synchronize_session=False)).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(429, {'code': 'MFA_LOCKED', 'message': 'Second factor changed or locked. Sign in again after the lockout expires.'})
    db.refresh(factor)


def replace_recovery_codes(db: Session, user: User) -> list[str]:
    db.execute(delete(AuthRecoveryCode).where(AuthRecoveryCode.user_id == user.id, AuthRecoveryCode.tenant_id == user.tenant_id))
    codes = []
    for _ in range(8):
        raw = secrets.token_hex(16)
        code = '-'.join(raw[i:i + 8] for i in range(0, 32, 8))
        codes.append(code)
        db.add(AuthRecoveryCode(user_id=user.id, tenant_id=user.tenant_id, digest=recovery_digest(code)))
    return codes


def verify_factor(db: Session, user: User, *, code: str | None, recovery_code: str | None) -> None:
    factor = factor_for(db, user)
    if not factor or not factor.confirmed_at or not factor.secret_enc:
        raise HTTPException(403, 'Enroll a second factor first')
    check_limit(db, factor)
    claim_factor(db, factor)
    if recovery_code:
        changed = db.execute(update(AuthRecoveryCode).where(AuthRecoveryCode.user_id == user.id,
            AuthRecoveryCode.tenant_id == user.tenant_id, AuthRecoveryCode.digest == recovery_digest(recovery_code),
            AuthRecoveryCode.consumed_at.is_(None)).values(consumed_at=utcnow())).rowcount
    else:
        counter = matching_counter(unseal(user, factor.secret_enc), code or '')
        changed = 0 if counter is None else db.execute(update(AuthFactor).where(
            AuthFactor.user_id == user.id, AuthFactor.tenant_id == user.tenant_id,
            AuthFactor.last_counter < counter,
            or_(AuthFactor.locked_until.is_(None), AuthFactor.locked_until <= utcnow()))
            .values(last_counter=counter).execution_options(synchronize_session=False)).rowcount
    if changed != 1:
        reject_code(db, factor)
    db.execute(update(AuthFactor).where(AuthFactor.user_id == user.id).values(failed_attempts=0, locked_until=None))
