"""Post-backup access withdrawal must survive actual application restoration."""
import uuid
import asyncio
import psycopg
from psycopg import sql
from sqlalchemy import select
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import pytest
from test_app_database import database, initialized, raw  # noqa: F401
from app_security_restore_fixture import AppSecurityRecovery

PASSWORD="SyntheticRecoveryPassword123!"


def signup(client):
    email="security-"+uuid.uuid4().hex+"@example.com"
    response=client.post("/api/auth/signup",json={"org_name":"Recovery fixture","email":email,"password":PASSWORD,"key_policy":"both"})
    assert response.status_code==201,response.status_code
    return email,response.json()


def header(tokens):
    return {"Authorization":"Bearer "+tokens["access_token"]}


def login(client,email):
    response=client.post("/api/auth/login",json={"email":email,"password":PASSWORD})
    assert response.status_code==200,response.status_code
    return response.json()


@pytest.mark.parametrize("withdrawal",["logout","password","demote","disable"])
def test_application_access_withdrawal_survives_backup_restore(initialized,monkeypatch,withdrawal):
    recovery=AppSecurityRecovery(initialized,monkeypatch)
    password="SyntheticRecoveryPassword123!"
    email="restore-"+uuid.uuid4().hex+"@example.com"
    with recovery.client() as client:
        signup=client.post("/api/auth/signup",json={"org_name":"Recovery fixture","email":email,"password":password,"key_policy":"both"})
        assert signup.status_code==201, signup.status_code
        tokens=recovery.mfa(client,signup.json())
        admin_headers={"Authorization":"Bearer "+tokens["access_token"]}
        if withdrawal in {"demote","disable"}:
            email="member-"+uuid.uuid4().hex+"@example.com"
            member=client.post("/api/auth/members",headers=admin_headers,json={"email":email,"password":password,"role":"admin"})
            assert member.status_code==201,member.status_code
            login=client.post("/api/auth/login",json={"email":email,"password":password})
            assert login.status_code==200,login.status_code
            tokens=recovery.mfa(client,login.json())
        headers={"Authorization":"Bearer "+tokens["access_token"]}
        assert client.get("/api/auth/me",headers=headers).status_code==200
        snapshot=recovery.backup()
        if withdrawal=="logout":
            result=client.post("/api/auth/logout",headers=headers)
            assert result.status_code in {200,202},result.status_code
        elif withdrawal=="password":
            result=client.post("/api/auth/change-password",headers=headers,json={"current_password":password,"new_password":"ReplacementRecoveryPassword456!"})
            assert result.status_code==200,result.status_code
            assert client.post("/api/auth/login",json={"email":email,"password":password}).status_code==401
        else:
            body={"role":"auditor"} if withdrawal=="demote" else {"is_active":False}
            result=client.patch("/api/auth/members/"+member.json()["id"],headers=admin_headers,json=body)
            assert result.status_code==200,result.status_code
        assert client.get("/api/auth/me",headers=headers).status_code==401
        pin=recovery.export()
    with recovery.restored(snapshot) as target:
        replayed=recovery.replay(target,pin)
        assert replayed["applied"] is True
        with recovery.client(target) as client:
            restored_status=client.get("/api/auth/me",headers=headers).status_code
            assert restored_status==401, "restoration reauthorized a revoked application session"
            if withdrawal in {"password","disable"}:
                denied=client.post("/api/auth/login",json={"email":email,"password":password}).status_code
                assert denied == (403 if withdrawal=="disable" else 401)
            if withdrawal in {"password","demote","logout"}:
                current="ReplacementRecoveryPassword456!" if withdrawal=="password" else password
                fresh=client.post("/api/auth/login",json={"email":email,"password":current})
                assert fresh.status_code==200,fresh.status_code
                assert fresh.json()["mfa_state"]=="verification_required"
                if withdrawal=="demote":
                    from sqlalchemy.orm import Session
                    from sqlalchemy import select
                    from app import db
                    from app.models import User
                    with Session(db._engine) as session:
                        assert session.scalar(select(User.role).where(User.email==email))=="auditor"


@pytest.mark.parametrize("change",["factor_rotation","code_rotation","code_consumption","lockout","pending_enrollment","refresh_rotation"])
def test_post_backup_mfa_and_refresh_state_survive_restore(initialized,monkeypatch,change):
    recovery=AppSecurityRecovery(initialized,monkeypatch)
    with recovery.client() as client:
        email,tokens=signup(client)
        tokens,old_secret,old_codes=recovery.mfa(client,tokens,details=True)
        backup=recovery.backup()
        current_codes=old_codes
        if change=="factor_rotation":
            tokens,new_secret,current_codes=recovery.mfa(client,tokens,details=True)
        elif change=="code_rotation":
            response=client.post("/api/auth/mfa/recovery-codes",headers=header(tokens))
            assert response.status_code==200,response.status_code
            current_codes=response.json()["recovery_codes"]
        elif change=="code_consumption":
            password_only=login(client,email)
            verified=client.post("/api/auth/mfa/verify",headers=header(password_only),json={"recovery_code":old_codes[1]})
            assert verified.status_code==200,verified.status_code
        elif change=="lockout":
            password_only=login(client,email)
            for _ in range(5):
                status=client.post("/api/auth/mfa/verify",headers=header(password_only),json={"recovery_code":"0"*32}).status_code
                assert status in {401,429}
        elif change=="pending_enrollment":
            response=client.post("/api/auth/mfa/enroll",headers=header(tokens))
            assert response.status_code==200,response.status_code
        else:
            response=client.post("/api/auth/refresh",json={"refresh_token":tokens["refresh_token"]})
            assert response.status_code==200,response.status_code
            rotated=response.json()
        pin=recovery.export()
    with recovery.restored(backup) as target:
        report=recovery.replay(target,pin)
        assert report["pending_kernel_revocations"]>0 and report["security_ready"] is False
        with recovery.client(target) as client:
            denied=client.post("/api/auth/refresh",json={"refresh_token":tokens["refresh_token"]}).status_code
            assert denied==401
            if change=="refresh_rotation":
                denied=client.post("/api/auth/refresh",json={"refresh_token":rotated["refresh_token"]}).status_code
                assert denied==401
            fresh=login(client,email)
            assert fresh["mfa_state"]=="verification_required"
            if change=="lockout":
                status=client.post("/api/auth/mfa/verify",headers=header(fresh),json={"recovery_code":old_codes[2]}).status_code
                assert status==429
            else:
                if change in {"factor_rotation","code_rotation","code_consumption"}:
                    status=client.post("/api/auth/mfa/verify",headers=header(fresh),json={"recovery_code":old_codes[1]}).status_code
                    assert status==401
                if change=="factor_rotation":
                    # The exact confirmed source seed, not an older backup seed.
                    from sqlalchemy.orm import Session
                    from app import db
                    from app.models import AuthFactor,User
                    from app.mfa import unseal
                    with Session(db._engine) as session:
                        user=session.query(User).filter_by(email=email).one()
                        factor=session.get(AuthFactor,user.id)
                        assert unseal(user,factor.secret_enc)==new_secret!=old_secret
                response=client.post("/api/auth/mfa/verify",headers=header(fresh),json={"recovery_code":current_codes[2]})
                assert response.status_code==200,response.status_code
                status=client.get("/api/auth/me",headers=header(response.json()["tokens"])).status_code
                assert status==200
            if change=="pending_enrollment":
                from sqlalchemy.orm import Session
                from app import db
                from app.models import AuthFactor
                with Session(db._engine) as session:
                    factor=session.query(AuthFactor).one()
                    assert factor.pending_secret_enc is None and factor.pending_session_id is None


def test_recovered_sessions_are_delivered_to_actual_kernel_and_generation_is_bound(initialized,monkeypatch,tmp_path):
    from kernel_restore_fixture import Recovery
    from app import db
    from app.auth_sessions import drain_revocations
    from app.models import RecoveredSessionRevocation, User
    recovery=AppSecurityRecovery(initialized,monkeypatch)
    with recovery.client() as client:
        email,tokens=signup(client)
        tokens=recovery.mfa(client,tokens)
        backup=recovery.backup()
        later=login(client,email)
        pin=recovery.export()
        with Session(db._engine) as session:
            user=session.scalar(select(User).where(User.email==email))
            tid,uid=str(uuid.UUID(user.tenant_id)),str(uuid.UUID(user.id))
    name="mk_security_kernel_"+uuid.uuid4().hex
    admin=recovery.owner.set(database="mk_app_test_admin")
    with psycopg.connect(raw(admin),autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    kernel=None
    try:
        kernel=Recovery(recovery.owner.set(database=name),tmp_path)
        with recovery.restored(backup) as target, kernel.client() as service:
            report=recovery.replay(target,pin)
            expected=report["sessions_fenced"]
            assert expected>=3 and report["pending_kernel_revocations"]==expected
            # A new session created AFTER the backup is absent from restored
            # auth_sessions, yet its authority still must be revoked downstream.
            for sid in (tokens["session_id"],later["session_id"]):
                result=kernel.propose(service,tid,uid,str(uuid.uuid4()),session_id=sid)
                assert result.status_code in {202,403},result.status_code
            engine=recovery.configure(target)
            with Session(engine) as session:
                assert asyncio.run(drain_revocations(session,service))>=expected
            for sid in (tokens["session_id"],later["session_id"]):
                result=kernel.propose(service,tid,uid,str(uuid.uuid4()),session_id=sid)
                assert result.status_code==401,result.status_code
            unaffected=kernel.propose(service,tid,uid,str(uuid.uuid4()),session_id="fresh-unrelated-session")
            assert unaffected.status_code in {202,403},unaffected.status_code
            report=recovery.replay(target,pin)
            assert report["security_ready"] and report["already_applied"]
            with Session(engine) as session:
                assert all(row.attempts==1 and row.confirmed_at for row in session.scalars(select(RecoveredSessionRevocation)))
            different={**pin,"privacy_digest":"0"*64}
            with pytest.raises(ValueError,match="binding"): recovery.replay(target,different)
            # A second restore generation must obtain receiving proof again;
            # an old backup's delivery confirmations are not portable authority.
            second={**pin,"id":uuid.uuid4().hex}
            report=recovery.replay(target,second)
            assert report["pending_kernel_revocations"]==expected
            with pytest.raises(ValueError,match="generation"): recovery.replay(target,pin)
            with Session(engine) as session:
                assert asyncio.run(drain_revocations(session,service))>=expected
            assert recovery.replay(target,second)["security_ready"]
    finally:
        if kernel: kernel.close()
        assert name.startswith("mk_security_kernel_")
        with psycopg.connect(raw(admin),autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


def test_accounts_and_session_obligations_created_after_backup_are_reconstructed(initialized,monkeypatch):
    recovery=AppSecurityRecovery(initialized,monkeypatch)
    with recovery.client() as client:
        backup=recovery.backup()
        email,tokens=signup(client)
        tokens,secret,codes=recovery.mfa(client,tokens,details=True)
        pin=recovery.export()
    with recovery.restored(backup) as target:
        assert recovery.replay(target,pin)["sessions_fenced"]>=2
        with recovery.client(target) as client:
            denied=client.get("/api/auth/me",headers=header(tokens)).status_code
            assert denied==401
            fresh=login(client,email)
            assert fresh["mfa_state"]=="verification_required"
            verified=client.post("/api/auth/mfa/verify",headers=header(fresh),json={"recovery_code":codes[2]})
            assert verified.status_code==200,verified.status_code
            # Readiness is fail-closed even before the ordinary 60-second backlog
            # alarm: restored kernel revocations have not received proof yet.
            ready=client.get("/api/health/ready")
            assert ready.status_code==503,ready.status_code
            assert ready.json()["checks"]["recovery_security"]=="pending"


def test_restore_preview_sql_fences_and_mid_replay_rollback(initialized,monkeypatch):
    from sqlalchemy import event
    from app.models import AuthSession, SecurityRestoreReceipt, User
    from app.security import verify_password
    from app import db
    recovery=AppSecurityRecovery(initialized,monkeypatch)
    with recovery.client() as client:
        email,tokens=signup(client)
        tokens=recovery.mfa(client,tokens)
        backup=recovery.backup()
        response=client.post("/api/auth/change-password",headers=header(tokens),json={
            "current_password":PASSWORD,"new_password":"ReplacementRecoveryPassword456!"})
        assert response.status_code==200,response.status_code
        pin=recovery.export()
    with recovery.restored(backup) as target:
        preview=recovery.replay(target,pin,apply=False)
        assert preview["applied"] is False and preview["security_ready"] is False
        def fail_after_credentials(conn,cursor,statement,parameters,context,executemany):
            if statement.startswith("INSERT INTO recovered_session_revocations"):
                raise RuntimeError("synthetic mid-replay failure")
        event.listen(__import__("sqlalchemy").engine.Engine,"before_cursor_execute",fail_after_credentials)
        try:
            with pytest.raises(RuntimeError,match="mid-replay"): recovery.replay(target,pin)
        finally: event.remove(__import__("sqlalchemy").engine.Engine,"before_cursor_execute",fail_after_credentials)
        engine=recovery.configure(target)
        with Session(engine) as session:
            assert session.scalar(select(SecurityRestoreReceipt.id)) is None
            assert verify_password(PASSWORD,session.scalar(select(User.password_hash).where(User.email==email)))
            assert session.get(AuthSession,tokens["session_id"]).revoked_at is None
        assert recovery.replay(target,pin)["applied"]
        for statement in (
            "UPDATE mk_app.auth_sessions SET revoked_at=NULL WHERE id=%s",
            "DELETE FROM mk_app.recovered_session_revocations WHERE session_id=%s",
            "UPDATE mk_app.security_restore_receipts SET ledger_sha256=repeat('0',64) WHERE id=%s",
        ):
            with pytest.raises(psycopg.Error):
                with psycopg.connect(raw(target)) as conn:
                    conn.execute(statement,(pin["id"] if "receipts" in statement else tokens["session_id"],))
        with pytest.raises(psycopg.errors.CheckViolation):
            with psycopg.connect(raw(recovery.owner.set(database=target.database))) as conn:
                conn.execute("TRUNCATE mk_app.recovered_session_revocations")
        # A repeat must not overwrite a password changed after the recovery.
        with Session(engine) as session:
            user=session.scalar(select(User).where(User.email==email))
            from app.security import hash_password
            user.password_hash=hash_password("PostRecoveryPassword789!")
            session.commit()
        assert recovery.replay(target,pin)["already_applied"]
        with Session(engine) as session:
            assert verify_password("PostRecoveryPassword789!",session.scalar(select(User.password_hash).where(User.email==email)))


@pytest.mark.parametrize("conflict",["omission","creation_identity","mfa_key","consumed_code"])
def test_pinned_but_conflicting_source_is_rejected_without_mutation(initialized,monkeypatch,conflict):
    from app import db
    from app.models import AuthSession,SecurityRestoreReceipt
    from app.tools import security_ledger as ledger
    recovery=AppSecurityRecovery(initialized,monkeypatch)
    with recovery.client() as client:
        email,tokens=signup(client)
        tokens=recovery.mfa(client,tokens)
        backup=recovery.backup()
        pin=recovery.export()
        checked=ledger.load_encrypted(pin["security"],pin["security_digest"],pin["cutoff"],
            recovery.recovery_key.private_bytes_raw().hex(),pin["privacy_digest"])
        source=checked.value
        if conflict=="omission":
            for group in ("users","factors","recovery_codes","sessions"): source[group]=[]
        elif conflict=="creation_identity":
            source["users"][0]["created_at"]=(datetime.now(timezone.utc)-timedelta(days=2)).isoformat()
        elif conflict=="mfa_key": source["factors"][0]["secret_enc"]="invalid-sealed-factor"
        else:
            consumed=next(row for row in source["recovery_codes"] if row["consumed_at"] is not None)
            consumed["consumed_at"]=None
        with monkeypatch.context() as patch:
            patch.setattr(ledger,"snapshot",lambda session:source)
            encrypted=ledger.export_encrypted(None,recovery.recovery_key.public_key().public_bytes_raw().hex(),pin["privacy_digest"])
        conflicting={**pin,"security":encrypted,"security_digest":ledger.sha256(encrypted)}
    with recovery.restored(backup) as target:
        with pytest.raises(ValueError): recovery.replay(target,conflicting)
        engine=recovery.configure(target)
        with Session(engine) as session:
            assert session.scalar(select(SecurityRestoreReceipt.id)) is None
            assert session.get(AuthSession,tokens["session_id"]).revoked_at is None
        # Repair the supplied input, not the gate, and successfully replay.
        assert recovery.replay(target,pin)["applied"]
