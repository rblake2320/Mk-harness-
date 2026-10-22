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

RUNTIME_PASSWORD = "acceptance-runtime-only"
MIGRATION_PASSWORD = "acceptance-migrator-only"


def raw(url):
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


@pytest.fixture
def initialized(database):
    bootstrap(database, RUNTIME_PASSWORD, MIGRATION_PASSWORD)
    migration = database.set(username="mk_app_migrator", password=MIGRATION_PASSWORD)
    runtime = database.set(username="mk_app_login", password=RUNTIME_PASSWORD)
    assert migrate(migration) == ["0001_initial.sql"]
    assert migrate(migration) == ["0001_initial.sql"]  # idempotent, checksummed
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
    assert results == [["0001_initial.sql"], ["0001_initial.sql"]]
    with psycopg.connect(raw(database)) as conn:
        assert conn.execute("SELECT count(*) FROM mk_app.schema_migrations").fetchone()[0] == 1


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
