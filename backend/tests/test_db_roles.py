"""S3 — separate runtime database identity, proven against a real PostgreSQL.

Runs the shipped init script (deploy/app/initdb/10-app-roles.sh) and migrate job
against a fresh database, then proves the runtime login can do DML and nothing
else, and that the API's least-privilege gate refuses an over-privileged login.
Skipped only when no PostgreSQL admin URL is provided (CI provides one).
"""
import os
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError

ADMIN = os.environ.get("MK_TEST_PG_ADMIN_URL")
pytestmark = pytest.mark.skipif(not ADMIN, reason="MK_TEST_PG_ADMIN_URL not set")
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def pg():
    admin = make_url(ADMIN)
    db = f"mk_roles_{uuid.uuid4().hex[:8]}"
    eng = create_engine(admin, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        for r in ("mk_app", "mk_app_owner"):
            c.execute(text(f"DROP OWNED BY {r} CASCADE")) if c.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname=:r"), {"r": r}).first() else None
            c.execute(text(f"DROP ROLE IF EXISTS {r}"))
        c.execute(text(f'CREATE DATABASE "{db}"'))
    owner_pw, runtime_pw = uuid.uuid4().hex, uuid.uuid4().hex
    env = {**os.environ, "POSTGRES_USER": admin.username, "POSTGRES_DB": db,
           "PGHOST": admin.host or "127.0.0.1", "PGPORT": str(admin.port or 5432),
           "PGPASSWORD": admin.password or "",
           "APP_DB_OWNER_PASSWORD": owner_pw, "APP_DB_RUNTIME_PASSWORD": runtime_pw}
    subprocess.run(["sh", str(ROOT / "deploy/app/initdb/10-app-roles.sh")], env=env, check=True)
    base = admin.set(database=db)
    owner = base.set(username="mk_app_owner", password=owner_pw)
    runtime = base.set(username="mk_app", password=runtime_pw)
    out = subprocess.run(["python", "-m", "app.tools.migrate"], cwd=ROOT / "backend", capture_output=True,
                         text=True, env={**os.environ, "DATABASE_URL": owner.render_as_string(hide_password=False),
                                         "APP_RUNTIME_ROLE": "mk_app", "MK_ALLOW_DEV_SECRETS": "1"})
    assert out.returncode == 0, out.stderr
    yield {"owner": owner, "runtime": runtime, "admin": base, "migrate_out": out.stdout}
    with eng.connect() as c:
        c.execute(text(f'DROP DATABASE "{db}" WITH (FORCE)'))
        for r in ("mk_app", "mk_app_owner"):
            c.execute(text(f"DROP ROLE IF EXISTS {r}"))


def test_migrate_creates_schema_and_grants(pg):
    assert "DML granted to mk_app" in pg["migrate_out"]
    with create_engine(pg["runtime"]).connect() as c:
        assert c.execute(text("SELECT count(*) FROM users")).scalar() == 0


def test_runtime_login_passes_least_privilege_gate(pg):
    from app.db import privilege_problem
    assert privilege_problem(create_engine(pg["runtime"])) is None


@pytest.mark.parametrize("who,expect", [("owner", "owns"), ("admin", "superuser")])
def test_gate_refuses_owner_and_superuser(pg, who, expect):
    from app.db import privilege_problem
    assert expect in privilege_problem(create_engine(pg[who]))


def test_runtime_can_do_dml(pg):
    eng = create_engine(pg["runtime"])
    with eng.begin() as c:
        c.execute(text("INSERT INTO tenants (id, name, key_policy, brand, created_at) VALUES ('t-dml','x','central','mary_kay', now())"))
        c.execute(text("UPDATE tenants SET name='y' WHERE id='t-dml'"))
        c.execute(text("DELETE FROM tenants WHERE id='t-dml'"))


@pytest.mark.parametrize("ddl", [
    "CREATE TABLE evil (id int)",
    "DROP TABLE users",
    "ALTER TABLE users ADD COLUMN evil int",
    "TRUNCATE users",
    "CREATE ROLE evil",
    "ALTER ROLE mk_app SUPERUSER",
    "CREATE DATABASE evil",
    "CREATE SCHEMA evil",
    "CREATE FUNCTION evil() RETURNS int LANGUAGE sql AS 'select 1'",
    "SET ROLE mk_app_owner",
])
def test_runtime_cannot_change_schema_or_roles(pg, ddl):
    eng = create_engine(pg["runtime"], isolation_level="AUTOCOMMIT")
    with pytest.raises(ProgrammingError):
        with eng.connect() as c:
            c.execute(text(ddl))


def test_runtime_cannot_regrant(pg):
    """A non-owner GRANT is a silent no-op in PostgreSQL (WARNING, not ERROR) — prove
    nothing was actually granted rather than trusting the absence of an error."""
    with create_engine(pg["runtime"]).begin() as c:
        c.execute(text("GRANT ALL ON users TO PUBLIC"))
    with create_engine(pg["admin"]).connect() as c:
        leaked = c.execute(text("SELECT count(*) FROM information_schema.role_table_grants "
                                "WHERE table_name='users' AND grantee='PUBLIC'")).scalar()
    assert leaked == 0


def test_api_refuses_to_start_over_privileged(pg, monkeypatch):
    """The startup gate itself, not just the helper: get_engine raises."""
    from app import db as dbmod
    from app.config import get_settings
    monkeypatch.setenv("DATABASE_URL", pg["owner"].render_as_string(hide_password=False))
    monkeypatch.setenv("DB_CREATE_ALL", "false")
    monkeypatch.setenv("DB_REQUIRE_LEAST_PRIVILEGE", "true")
    get_settings.cache_clear()
    saved = dbmod._engine, dbmod._SessionLocal
    try:
        with pytest.raises(RuntimeError, match="over-privileged"):
            dbmod.init_engine(pg["owner"].render_as_string(hide_password=False))
        assert (dbmod._engine, dbmod._SessionLocal) == saved   # nothing half-configured
    finally:
        get_settings.cache_clear()
