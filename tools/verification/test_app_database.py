"""Real PostgreSQL acceptance. Run explicitly against a disposable, labelled cluster.

MK_APP_TEST_ADMIN_URL must point at the dedicated mk_app_test_admin database on
loopback. Never point this at a shared service; the fixture creates only fresh
UUID-named databases and removes exactly those databases on exit.
"""
import os
import sys
import uuid
import base64
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from sqlalchemy.engine import make_url

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
from app import db
from app.migrate import bootstrap, migrate
from app.models import Base
from app.database_policy import migration_files

RUNTIME_PASSWORD = "acceptance-runtime-only"
MIGRATION_PASSWORD = "acceptance-migrator-only"
VERSIONS = [path.name for path in migration_files()]


def raw(url):
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


@pytest.fixture
def initialized(database):
    bootstrap(database, RUNTIME_PASSWORD, MIGRATION_PASSWORD)
    migration = database.set(username="mk_app_migrator", password=MIGRATION_PASSWORD)
    runtime = database.set(username="mk_app_login", password=RUNTIME_PASSWORD)
    assert migrate(migration) == VERSIONS
    assert migrate(migration) == VERSIONS  # idempotent, checksummed
    yield database, migration, runtime


@pytest.fixture
def database():
    url = make_url(os.environ["MK_APP_TEST_ADMIN_URL"])
    assert url.host in {"localhost", "127.0.0.1"} and url.database == "mk_app_test_admin"
    admin = url.set(drivername="postgresql").render_as_string(hide_password=False)
    name = "mk_app_acceptance_" + uuid.uuid4().hex
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    target = url.set(database=name, drivername="postgresql+psycopg")
    try:
        yield target
    finally:
        if db._engine is not None:
            db._engine.dispose()
        db._engine = db._SessionLocal = None
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


def test_owner_is_rejected_before_api_creates_any_tables(database):
    with pytest.raises(RuntimeError, match="runtime database identity"):
        db.init_engine(database.render_as_string(hide_password=False))
    with psycopg.connect(database.set(drivername="postgresql").render_as_string(hide_password=False)) as conn:
        assert conn.execute("SELECT count(*) FROM pg_tables WHERE schemaname IN ('public','mk_app')").fetchone()[0] == 0


def test_runtime_has_dml_not_ddl_audit_mutation_or_kernel_access(initialized):
    owner, migration, runtime = initialized
    with psycopg.connect(raw(owner)) as conn:
        conn.execute("CREATE SCHEMA kernel; CREATE TABLE kernel.probe(secret text)")
    engine = db.init_engine(runtime)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT session_user, current_user, current_schema()").one() == ("mk_app_login", "mk_app_login", "pg_catalog")
        assert conn.exec_driver_sql("SELECT count(*) FROM users").scalar() == 0
    denied = ["CREATE TABLE mk_app.bad(id int)", "CREATE TABLE public.bad(id int)",
              "CREATE TEMP TABLE bad(id int)", "ALTER TABLE mk_app.users ADD COLUMN bad int",
              "DROP TABLE mk_app.users CASCADE", "TRUNCATE mk_app.users CASCADE",
              "UPDATE mk_app.audit_logs SET detail='changed'", "DELETE FROM mk_app.audit_logs",
              "INSERT INTO mk_app.schema_migrations VALUES ('fake','fake',now())",
              "SELECT * FROM kernel.probe", "SET ROLE mk_app_owner", "SET ROLE mk_app_migrator"]
    for statement in denied:
        with psycopg.connect(raw(runtime)) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
    with pytest.raises(RuntimeError, match="runtime database identity"):
        db.init_engine(migration)
    with pytest.raises(RuntimeError, match="separate mk_app_migrator"):
        migrate(runtime)


def test_set_role_cannot_disguise_owner_login(initialized):
    owner, _, _ = initialized
    disguised = owner.update_query_dict({"options": "-c role=mk_app_login"})
    with pytest.raises(RuntimeError, match="runtime database identity"):
        db.init_engine(disguised)


@pytest.mark.parametrize("grant,undo", [
    ("GRANT mk_app_owner TO mk_app_login", "REVOKE mk_app_owner FROM mk_app_login"),
    ("ALTER ROLE mk_app_login BYPASSRLS", "ALTER ROLE mk_app_login NOBYPASSRLS"),
    ("GRANT UPDATE ON mk_app.audit_logs TO mk_app_login", "REVOKE UPDATE ON mk_app.audit_logs FROM mk_app_login"),
    ("GRANT CREATE ON SCHEMA public TO mk_app_login", "REVOKE CREATE ON SCHEMA public FROM mk_app_login"),
    ("GRANT INSERT ON mk_app.schema_migrations TO mk_app_login", "REVOKE INSERT ON mk_app.schema_migrations FROM mk_app_login"),
    ("GRANT UPDATE(detail) ON mk_app.audit_logs TO mk_app_login", "REVOKE UPDATE(detail) ON mk_app.audit_logs FROM mk_app_login"),
])
def test_runtime_rejects_privilege_drift(initialized, grant, undo):
    owner, _, runtime = initialized
    with psycopg.connect(raw(owner)) as conn:
        conn.execute(grant)
    try:
        with pytest.raises(RuntimeError, match="runtime database identity"):
            db.init_engine(runtime)
    finally:
        with psycopg.connect(raw(owner)) as conn:
            conn.execute(undo)


def test_schema_and_applied_migration_tampering_fail_closed(initialized):
    owner, migration, runtime = initialized
    with psycopg.connect(raw(owner)) as conn:
        conn.execute("UPDATE mk_app.schema_migrations SET sha256='tampered'")
    with pytest.raises(RuntimeError, match="ledger"):
        db.init_engine(runtime)
    with pytest.raises(RuntimeError, match="checksum"):
        migrate(migration)


def test_missing_schema_cannot_be_created_by_runtime(database):
    bootstrap(database, RUNTIME_PASSWORD, MIGRATION_PASSWORD)
    runtime = database.set(username="mk_app_login", password=RUNTIME_PASSWORD)
    with pytest.raises(RuntimeError, match="incomplete"):
        db.init_engine(runtime)
    with psycopg.connect(raw(database)) as conn:
        assert conn.execute("SELECT count(*) FROM pg_tables WHERE schemaname='mk_app'").fetchone()[0] == 0


def test_schema_drift_rolls_back_migration_ledger(initialized):
    owner, migration, runtime = initialized
    with psycopg.connect(raw(owner)) as conn:
        conn.execute("ALTER TABLE mk_app.users DROP CONSTRAINT users_tenant_id_fkey")
    with pytest.raises(RuntimeError, match="foreign key drift"):
        db.init_engine(runtime)
    with pytest.raises(RuntimeError, match="foreign key drift"):
        migrate(migration)


def test_simultaneous_first_migrations_serialize(database):
    from concurrent.futures import ThreadPoolExecutor
    bootstrap(database, RUNTIME_PASSWORD, MIGRATION_PASSWORD)
    migration = database.set(username="mk_app_migrator", password=MIGRATION_PASSWORD)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(migrate, [migration, migration]))
    assert results == [VERSIONS, VERSIONS]
    with psycopg.connect(raw(database)) as conn:
        assert conn.execute("SELECT count(*) FROM mk_app.schema_migrations").fetchone()[0] == len(VERSIONS)


def test_public_data_adoption_is_explicit_and_preserves_rows(database):
    # Match the existing application table; bootstrap does not recreate or erase it.
    from sqlalchemy import create_engine
    from app.models import Tenant
    from sqlalchemy.orm import Session
    engine = create_engine(database)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Tenant(id="retained", name="retained synthetic tenant"))
        session.commit()
    engine.dispose()
    with pytest.raises(RuntimeError, match="adopt-public"):
        bootstrap(database, RUNTIME_PASSWORD, MIGRATION_PASSWORD)
    with psycopg.connect(raw(database)) as conn:
        assert conn.execute("SELECT name FROM public.tenants WHERE id='retained'").fetchone()[0] == "retained synthetic tenant"
    bootstrap(database, RUNTIME_PASSWORD, MIGRATION_PASSWORD, adopt_public=True)
    migrate(database.set(username="mk_app_migrator", password=MIGRATION_PASSWORD))
    runtime = database.set(username="mk_app_login", password=RUNTIME_PASSWORD)
    with db.init_engine(runtime).connect() as conn:
        assert conn.exec_driver_sql("SELECT name FROM tenants WHERE id='retained'").scalar() == "retained synthetic tenant"


def test_real_api_mfa_and_customer_transaction_with_runtime_identity(initialized, monkeypatch):
    import pyotp
    from fastapi.testclient import TestClient
    from app.config import get_settings
    _, _, runtime = initialized
    monkeypatch.setenv("DATABASE_URL", runtime.render_as_string(hide_password=False))
    monkeypatch.setenv("JWT_SECRET", "acceptance-test-only-" + "a" * 32)
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"a" * 32).decode())
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "10000")
    for name in ("DB_HOST", "DB_PASSWORD", "RUST_ACTION_KERNEL_URL", "KERNEL_ASSERTION_PRIVATE_KEY",
                 "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "STRIPE_SECRET_KEY"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    db.init_engine(runtime)
    from app.main import app
    with TestClient(app) as client:
        signup = client.post("/api/auth/signup", json={"org_name": "PG only", "email": "pg@example.com", "password": "SyntheticStrongPassword123!", "key_policy": "both"})
        assert signup.status_code == 201, signup.status_code
        headers = {"Authorization": "Bearer " + signup.json()["access_token"]}
        assert client.get("/api/customers", headers=headers).status_code == 403
        enrolled = client.post("/api/auth/mfa/enroll", headers=headers)
        assert enrolled.status_code == 200
        confirmed = client.post("/api/auth/mfa/confirm", headers=headers, json={"code": pyotp.TOTP(enrolled.json()["secret"]).now()})
        assert confirmed.status_code == 200, confirmed.status_code
        headers = {"Authorization": "Bearer " + confirmed.json()["tokens"]["access_token"]}
        created = client.post("/api/customers", headers=headers, json={"name": "Synthetic PG customer"})
        assert created.status_code == 201, created.status_code
        assert client.get("/api/customers", headers=headers).status_code == 200
        assert client.get("/api/health/ready").status_code == 200
    with psycopg.connect(raw(runtime), options="-c search_path=mk_app") as conn:
        assert conn.execute("SELECT count(*) FROM customers").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM audit_logs").fetchone()[0] > 0
    get_settings.cache_clear()


def test_seal_rekey_covers_real_postgres_records_and_fences_old_writers(initialized, monkeypatch):
    from sqlalchemy.orm import Session
    from app.config import get_settings
    from app.crypto import encrypt_secret, seal_secret, unseal_secret
    from app.tools.reseal import FIELDS, activate, scan
    from backend.tests.test_seal_rotation import seed_rotation_records
    from app.models import ProviderKey
    owner, migration, runtime = initialized
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"0" * 32).decode())
    monkeypatch.delenv("APP_SEAL_KEYS", raising=False)
    get_settings.cache_clear()
    engine = db.init_engine(runtime)
    try:
        with Session(engine, expire_on_commit=False) as session:
            records = seed_rotation_records(session)
            old = records[ProviderKey].ciphertext
            before = scan(session)
            assert before.total == before.stale == 9 and not before.clean()
        monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode() + ",m0=master")
        get_settings.cache_clear()
        with pytest.raises(RuntimeError, match="separate mk_app_migrator login"):
            activate(runtime)
        assert activate(migration)["writer_kid"] == "s2"
        with psycopg.connect(raw(runtime)) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("UPDATE mk_app.application_seal_policy SET writer_kid='m0'")
        with Session(engine) as session:
            report = scan(session, apply=True, batch_size=1)
            assert report.updated == 9 and report.clean()
        # Even an old process holding MASTER_KEY cannot reintroduce legacy rows.
        for ciphertext in (old, seal_secret("old writer", "unused", keys=[("m0", b"0" * 32)])):
            with psycopg.connect(raw(runtime)) as conn:
                with pytest.raises(psycopg.errors.CheckViolation, match="SEAL_WRITER_RETIRED"):
                    conn.execute("UPDATE mk_app.provider_keys SET ciphertext=%s WHERE id='fixture'", (ciphertext,))
        monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode())
        get_settings.cache_clear()
        with Session(engine) as session:
            assert scan(session).clean()
            for item in FIELDS:
                row = session.scalars(__import__("sqlalchemy").select(item.model)).one()
                assert unseal_secret(getattr(row, item.name), item.aad(row)) == "synthetic-" + item.name
                primary = next(iter(item.model.__table__.primary_key.columns)).name
                obsolete = encrypt_secret(b"0" * 32, "late-obsolete", item.aad(row))
                with psycopg.connect(raw(runtime)) as old_writer:
                    with pytest.raises(psycopg.errors.CheckViolation, match="SEAL_WRITER_RETIRED"):
                        old_writer.execute(sql.SQL("UPDATE mk_app.{} SET {}=%s WHERE {}=%s").format(
                            sql.Identifier(item.model.__tablename__), sql.Identifier(item.name), sql.Identifier(primary)),
                            (obsolete, getattr(row, primary)))
    finally:
        get_settings.cache_clear()


def test_policy_activation_waits_for_inflight_legacy_write(initialized, monkeypatch):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from app.config import get_settings
    from app.tools.reseal import activate
    from backend.tests.test_seal_rotation import seed_rotation_records
    from sqlalchemy.orm import Session
    from app.crypto import encrypt_secret
    owner, migration, runtime = initialized
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"0" * 32).decode())
    monkeypatch.delenv("APP_SEAL_KEYS", raising=False)
    get_settings.cache_clear()
    with Session(db.init_engine(runtime)) as session:
        seed_rotation_records(session)
    monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode() + ",m0=master")
    get_settings.cache_clear()
    writer = psycopg.connect(raw(runtime))
    try:
        writer.execute("UPDATE mk_app.provider_keys SET ciphertext=%s WHERE id='fixture'",
                       (encrypt_secret(b"0" * 32, "inflight", "a" * 32 + ":fixture:fixture"),))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(activate, migration)
            try:
                with psycopg.connect(raw(owner), autocommit=True) as inspect_conn:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        blocked = inspect_conn.execute("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetchone()[0]
                        if blocked: break
                        time.sleep(.02)
                assert blocked == 1 and not pending.done()
            finally:
                writer.commit()
            assert pending.result(timeout=5)["writer_kid"] == "s2"
        with pytest.raises(psycopg.errors.CheckViolation, match="SEAL_WRITER_RETIRED"):
            writer.execute("UPDATE mk_app.provider_keys SET ciphertext=%s WHERE id='fixture'",
                           (encrypt_secret(b"0" * 32, "late", "a" * 32 + ":fixture:fixture"),))
    finally:
        writer.close(); get_settings.cache_clear()


def test_waiting_legacy_writer_observes_new_fence_after_activation(initialized, monkeypatch):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from app.config import get_settings
    from backend.tests.test_seal_rotation import seed_rotation_records
    from sqlalchemy.orm import Session
    from app.crypto import encrypt_secret
    owner, _, runtime = initialized
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"0" * 32).decode())
    monkeypatch.delenv("APP_SEAL_KEYS", raising=False)
    get_settings.cache_clear()
    with Session(db.init_engine(runtime)) as session:
        seed_rotation_records(session)
    controller = psycopg.connect(raw(owner))
    try:
        controller.execute("UPDATE mk_app.application_seal_policy SET writer_kid='s2',allow_legacy=false WHERE id=1")
        def stale_write():
            with psycopg.connect(raw(runtime)) as writer:
                writer.execute("UPDATE mk_app.provider_keys SET ciphertext=%s WHERE id='fixture'",
                               (encrypt_secret(b"0" * 32, "waiting", "a" * 32 + ":fixture:fixture"),))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(stale_write)
            try:
                with psycopg.connect(raw(owner), autocommit=True) as inspection:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        blocked = inspection.execute("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetchone()[0]
                        if blocked: break
                        time.sleep(.02)
                assert blocked == 1 and not pending.done()
            finally:
                controller.commit()
            with pytest.raises(psycopg.errors.CheckViolation, match="SEAL_WRITER_RETIRED"):
                pending.result(timeout=5)
        with psycopg.connect(raw(runtime)) as writer:
            writer.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            # Both independent fences reject stale transaction snapshots; the
            # alphabetically first BEFORE trigger determines the refusal code.
            with pytest.raises(psycopg.errors.CheckViolation, match="(SEAL|PRIVACY)_WRITE_REQUIRES_READ_COMMITTED"):
                writer.execute("UPDATE mk_app.provider_keys SET ciphertext=%s WHERE id='fixture'",
                               (encrypt_secret(b"0" * 32, "snapshot", "unused"),))
    finally:
        controller.close(); get_settings.cache_clear()


def test_killed_reseal_process_resumes_committed_batches(initialized, monkeypatch):
    import json
    import subprocess
    import time
    from app.config import get_settings
    from app.crypto import encrypt_secret
    from app.tools.reseal import activate
    from backend.tests.test_seal_rotation import seed_rotation_records
    from sqlalchemy.orm import Session
    owner, migration, runtime = initialized
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"0" * 32).decode())
    monkeypatch.delenv("APP_SEAL_KEYS", raising=False)
    get_settings.cache_clear()
    with Session(db.init_engine(runtime)) as session:
        seed_rotation_records(session)
    # Enough individually committed batches to observe and interrupt actual work.
    with psycopg.connect(raw(owner)) as conn:
        with conn.cursor() as cursor:
            cursor.executemany("""INSERT INTO mk_app.exceptions
                (id,tenant_id,customer_id,kind,source_reference,detail_enc,state,resolved_by,resolved_at,version,audit_ref,created_at)
                VALUES (%s,%s,NULL,'fixture','',%s,'open',NULL,NULL,1,'',now())""",
                [(f"kill-{index:06d}", "a" * 32, encrypt_secret(b"0" * 32, f"record-{index}", "mk-foundation:" + "a" * 32 + ":exception"))
                 for index in range(4000)])
    ring = "s2=" + base64.b64encode(b"2" * 32).decode() + ",m0=master"
    monkeypatch.setenv("APP_SEAL_KEYS", ring)
    get_settings.cache_clear()
    activate(migration)
    environment = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "backend"),
                   "DATABASE_URL": runtime.render_as_string(hide_password=False),
                   "MASTER_KEY": base64.b64encode(b"0" * 32).decode(), "APP_SEAL_KEYS": ring}
    command = [sys.executable, "-m", "app.tools.reseal", "rekey", "--batch-size", "1", "--actor", "kill-acceptance"]
    process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    observed = 0
    try:
        with psycopg.connect(raw(owner), autocommit=True) as inspection:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                observed = inspection.execute("SELECT count(*) FROM mk_app.audit_logs WHERE action='security.seal_rekey' AND user_id='kill-acceptance'").fetchone()[0]
                if observed >= 2:
                    process.kill()
                    break
                time.sleep(.02)
        stdout, stderr = process.communicate(timeout=10)
        assert observed >= 2 and process.returncode != 0, (observed, process.returncode)
        # Committed ciphertext and audit survive SIGKILL; unfinished batches retry.
        resumed = subprocess.run([sys.executable, "-m", "app.tools.reseal", "rekey", "--batch-size", "200", "--actor", "resume-acceptance"],
                                 env=environment, capture_output=True, text=True, timeout=40)
        assert resumed.returncode == 0, resumed.stdout
        report = json.loads(resumed.stdout)
        assert report["total"] == 4009 and 0 < report["updated"] < 4009
        assert report["stale"] == report["unreadable"] == report["conflicts"] == 0
        environment["APP_SEAL_KEYS"] = "s2=" + base64.b64encode(b"2" * 32).decode()
        final = subprocess.run([sys.executable, "-m", "app.tools.reseal", "status"], env=environment,
                               capture_output=True, text=True, timeout=20)
        assert final.returncode == 0 and json.loads(final.stdout)["total"] == 4009
    finally:
        if process.poll() is None:
            process.kill(); process.communicate(timeout=10)
        get_settings.cache_clear()
