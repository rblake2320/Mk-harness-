"""MFA enrollment, login completion, one-use recovery and fresh step-up."""
from datetime import timedelta, timezone

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import mfa, security
from ..auth_sessions import revoke_local
from ..db import get_db
from ..models import AuditLog, AuthFactor, AuthRecoveryCode, AuthSession, User
from .auth import _tokens

router = APIRouter(prefix='/auth', tags=['mfa'])


class FactorIn(BaseModel):
    code: str | None = Field(default=None, pattern=r'^\d{6}$')
    recovery_code: str | None = Field(default=None, min_length=32, max_length=64)

    @model_validator(mode='after')
    def one_credential(self):
        if bool(self.code) == bool(self.recovery_code):
            raise ValueError('Provide exactly one authenticator or recovery code')
        return self


class StepUpIn(FactorIn):
    password: str = Field(min_length=1, max_length=128)


def no_store(response: Response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'


def enrollment_authority(session: AuthSession, factor: AuthFactor | None):
    if factor and factor.confirmed_at:
        if session.mfa_verified_at is None:
            raise HTTPException(403, {'code': 'MFA_REQUIRED', 'message': 'Verify the existing second factor before replacing it.'})
        security.enforce_step_up(session)
    elif mfa.utcnow() - session.created_at.replace(tzinfo=timezone.utc) > timedelta(minutes=10):
        raise HTTPException(401, 'Sign in again before enrolling a second factor')


@router.post('/mfa/enroll')
def begin(request: Request, response: Response, user: User = Depends(security.get_authenticated_user),
          db: Session = Depends(get_db)):
    session = request.state.auth_session
    factor = mfa.factor_for(db, user)
    enrollment_authority(session, factor)
    if not factor:
        factor = AuthFactor(user_id=user.id, tenant_id=user.tenant_id)
        db.add(factor)
    else:
        mfa.check_limit(db, factor)
    if factor.pending_session_id == session.id and factor.pending_secret_enc:
        secret = mfa.unseal(user, factor.pending_secret_enc, session.id)
    else:
        secret = pyotp.random_base32()
        factor.pending_secret_enc = mfa.seal(user, secret, session.id)
        factor.pending_session_id = session.id
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Enrollment changed in another session; retry')
    no_store(response)
    return {'secret': secret, 'provisioning_uri': pyotp.TOTP(secret).provisioning_uri(user.email, issuer_name='Consultant Studio')}


@router.post('/mfa/confirm')
def confirm(body: FactorIn, request: Request, response: Response,
            user: User = Depends(security.get_authenticated_user), db: Session = Depends(get_db)):
    session = request.state.auth_session
    factor = mfa.factor_for(db, user)
    if not factor or factor.pending_session_id != session.id or not factor.pending_secret_enc or not body.code:
        raise HTTPException(409, 'No authenticator enrollment for this session')
    enrollment_authority(session, factor)
    mfa.check_limit(db, factor)
    mfa.claim_factor(db, factor)
    if factor.pending_session_id != session.id or not factor.pending_secret_enc:
        raise HTTPException(409, 'Enrollment already completed or replaced')
    enrollment_authority(session, factor)
    pending = factor.pending_secret_enc
    secret = mfa.unseal(user, pending, session.id)
    counter = mfa.matching_counter(secret, body.code)
    if counter is None:
        mfa.reject_code(db, factor)
    now = mfa.utcnow()
    changed = db.execute(update(AuthFactor).where(AuthFactor.user_id == user.id,
        AuthFactor.pending_session_id == session.id, AuthFactor.pending_secret_enc == pending).values(
            secret_enc=mfa.seal(user, secret), confirmed_at=now, last_counter=counter,
            pending_secret_enc=None, pending_session_id=None, failed_attempts=0, locked_until=None)).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, 'Enrollment already completed or replaced')
    codes = mfa.replace_recovery_codes(db, user)
    # Never upgrade a password-only bearer in place. It might have been stolen
    # before MFA. Replacing a factor also kills every old app/kernel session.
    for previous in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))):
        revoke_local(db, previous, by=user.id, reason='mfa_enrolled')
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action='auth.mfa.enroll', detail=''))
    token = _tokens(user, db, verified=True)
    no_store(response)
    return {'tokens': token, 'recovery_codes': codes}


@router.post('/mfa/verify')
def verify(body: FactorIn, request: Request, response: Response,
           user: User = Depends(security.get_authenticated_user), db: Session = Depends(get_db)):
    session = request.state.auth_session
    if session.mfa_verified_at is not None:
        raise HTTPException(409, 'This session is already verified')
    mfa.verify_factor(db, user, code=body.code, recovery_code=body.recovery_code)
    revoke_local(db, session, by=user.id, reason='mfa_login_completed')
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action='auth.mfa.login', detail='recovery' if body.recovery_code else 'totp'))
    no_store(response)
    return {'tokens': _tokens(user, db, verified=True)}


@router.post('/step-up')
def step_up(body: StepUpIn, request: Request, response: Response,
            user: User = Depends(security.get_current_user), db: Session = Depends(get_db)):
    factor = mfa.factor_for(db, user)
    if not factor or not factor.confirmed_at:
        raise HTTPException(403, 'Enroll a second factor first')
    mfa.check_limit(db, factor)
    if not security.verify_password(body.password, user.password_hash):
        mfa.reject_code(db, factor)
    mfa.verify_factor(db, user, code=body.code, recovery_code=body.recovery_code)
    request.state.auth_session.step_up_at = mfa.utcnow()
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action='auth.step_up', detail=''))
    db.commit()
    no_store(response)
    return {'verified': True, 'valid_for_seconds': 300}


@router.get('/mfa/status')
def status(user: User = Depends(security.get_current_user), db: Session = Depends(get_db)):
    factor = mfa.factor_for(db, user)
    remaining = list(db.scalars(select(AuthRecoveryCode.id).where(AuthRecoveryCode.user_id == user.id,
                                                                AuthRecoveryCode.consumed_at.is_(None))))
    return {'enrolled': bool(factor and factor.confirmed_at), 'recovery_codes_remaining': len(remaining)}


@router.post('/mfa/recovery-codes')
def recovery_codes(request: Request, response: Response, user: User = Depends(security.get_current_user),
                   db: Session = Depends(get_db)):
    security.enforce_step_up(request.state.auth_session)
    codes = mfa.replace_recovery_codes(db, user)
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id, action='auth.mfa.recovery_rotate', detail=''))
    db.commit()
    no_store(response)
    return {'recovery_codes': codes}
