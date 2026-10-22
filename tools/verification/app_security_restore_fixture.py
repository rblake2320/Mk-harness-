"""Real application HTTP and backup recovery, only on owned synthetic databases."""
import base64
import hashlib
import json
import os
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg
import pyotp
from psycopg import sql
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, text
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from test_app_database import raw, RUNTIME_PASSWORD, MIGRATION_PASSWORD
from app import db
from app.config import get_settings
from app.kernel import get_kernel_client
from app.migrate import bootstrap
from app.tools.privacy_ledger import export_ledger
from app.tools.security_ledger import export_encrypted, load_encrypted
from app.tools.security_restore import restore


class AppSecurityRecovery:
    def __init__(self, initialized, monkeypatch):
        self.owner, self.migration, self.runtime = initialized
        self.recovery_key = X25519PrivateKey.generate()
        self.patch = monkeypatch
        self.docker = os.environ.get("MK_PRIVACY_TEST_DOCKER", "docker")
        self.container = os.environ["MK_PRIVACY_TEST_POSTGRES_CONTAINER"]
        inspected = subprocess.run([self.docker,"inspect",self.container],capture_output=True,text=True,check=True,timeout=20)
        info = json.loads(inspected.stdout)[0]
        assert "POSTGRES_DB=mk_app_test_admin" in info["Config"]["Env"]
        assert any(int(port["HostPort"]) == self.owner.port for port in info["NetworkSettings"]["Ports"]["5432/tcp"])
        monkeypatch.setenv("JWT_SECRET", "synthetic-recovery-session-key-"+"a"*40)
        monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"b"*32).decode())
        monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "10000")
        for name in ("DB_HOST","DB_PASSWORD","APP_SEAL_KEYS","RUST_ACTION_KERNEL_URL","KERNEL_ASSERTION_PRIVATE_KEY",
                "ANTHROPIC_API_KEY","OPENAI_API_KEY","GEMINI_API_KEY","STRIPE_SECRET_KEY"):
            monkeypatch.delenv(name,raising=False)

    def configure(self, runtime):
        if db._engine is not None: db._engine.dispose()
        self.patch.setenv("DATABASE_URL",runtime.render_as_string(hide_password=False))
        get_settings.cache_clear(); get_kernel_client.cache_clear()
        return db.init_engine(runtime)

    @contextmanager
    def client(self, target=None):
        self.configure(target or self.runtime)
        from app.main import app
        with TestClient(app) as client: yield client

    @staticmethod
    def mfa(client, tokens, password="SyntheticRecoveryPassword123!", *, details=False):
        headers={"Authorization":"Bearer "+tokens["access_token"]}
        enrolled=client.post("/api/auth/mfa/enroll",headers=headers)
        assert enrolled.status_code==200, enrolled.status_code
        confirmed=client.post("/api/auth/mfa/confirm",headers=headers,json={"code":pyotp.TOTP(enrolled.json()["secret"]).now()})
        assert confirmed.status_code==200, confirmed.status_code
        tokens=confirmed.json()["tokens"]
        stepped=client.post("/api/auth/step-up",headers={"Authorization":"Bearer "+tokens["access_token"]},
            json={"password":password,"recovery_code":confirmed.json()["recovery_codes"][0]})
        assert stepped.status_code==200, stepped.status_code
        return (tokens,enrolled.json()["secret"],confirmed.json()["recovery_codes"]) if details else tokens

    def backup(self):
        assert self.owner.database.startswith("mk_app_acceptance_")
        result=subprocess.run([self.docker,"exec",self.container,"pg_dump","-U",self.owner.username,
            "--format=custom","--dbname",self.owner.database],capture_output=True,timeout=45)
        assert result.returncode==0 and result.stdout.startswith(b"PGDMP")
        return result.stdout

    def export(self):
        cutoff=datetime.now(timezone.utc)
        with Session(db._engine) as session:
            session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
            contents=export_ledger(session)
            digest=hashlib.sha256(contents).hexdigest()
            encrypted=export_encrypted(session,self.recovery_key.public_key().public_bytes_raw().hex(),digest)
        return {"privacy":contents,"privacy_digest":digest,"security":encrypted,
            "security_digest":hashlib.sha256(encrypted).hexdigest(),"cutoff":cutoff,"id":uuid.uuid4().hex}

    def replay(self,target,pin,*,apply=True):
        checked=load_encrypted(pin["security"],pin["security_digest"],pin["cutoff"],
            self.recovery_key.private_bytes_raw().hex(),pin["privacy_digest"])
        engine=create_engine(self.migration.set(database=target.database),hide_parameters=True)
        try:
            with Session(engine) as session:
                report=restore(session,checked,pin["privacy"],pin["cutoff"],pin["id"],apply=apply)
                if apply: session.commit()
            return report
        finally: engine.dispose()

    @contextmanager
    def restored(self, snapshot):
        name="mk_app_security_restored_"+uuid.uuid4().hex
        admin=self.owner.set(database="mk_app_test_admin")
        with psycopg.connect(raw(admin),autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        target=self.owner.set(database=name)
        try:
            result=subprocess.run([self.docker,"exec","-i",self.container,"pg_restore","-U",target.username,
                "--exit-on-error","--dbname",name],input=snapshot,capture_output=True,timeout=45)
            assert result.returncode==0
            bootstrap(target,RUNTIME_PASSWORD,MIGRATION_PASSWORD)
            yield self.runtime.set(database=name)
        finally:
            if db._engine is not None: db._engine.dispose()
            db._engine=db._SessionLocal=None
            get_settings.cache_clear(); get_kernel_client.cache_clear()
            assert name.startswith("mk_app_security_restored_")
            with psycopg.connect(raw(admin),autocommit=True) as conn:
                conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
