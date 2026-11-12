"""One-shot schema job (contract S3): create/upgrade the application schema with
the OWNER login, then grant DML to the runtime role. The API itself runs with
DB_CREATE_ALL=false and the runtime login, and refuses to start as an owner or
superuser when DB_REQUIRE_LEAST_PRIVILEGE=true.

    DATABASE_URL=postgresql+psycopg://mk_app_owner:...@db/mkharness \\
    APP_RUNTIME_ROLE=mk_app python -m app.tools.migrate
"""
from __future__ import annotations

import os
import re
import sys
import uuid

from sqlalchemy import create_engine, inspect, text

from ..config import get_settings
from ..models import Base


def add_missing_columns(engine) -> list[tuple[str, str]]:
    """Additive schema evolution: create_all() creates missing TABLES but never adds
    columns to existing ones. Add each missing column that is nullable or has a
    scalar default; refuse (raise) anything else, so a non-additive change cannot
    be applied silently — that needs a reviewed migration."""
    insp = inspect(engine)
    added: list[tuple[str, str]] = []
    for table in Base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            default = col.default.arg if col.default is not None and col.default.is_scalar else None
            if not col.nullable and default is None:
                raise SystemExit(f"non-additive schema change: {table.name}.{col.name} is NOT NULL without a "
                                 "scalar default — write a reviewed migration")
            ddl = col.type.compile(dialect=engine.dialect)
            clause = ""
            if default is not None:
                lit = ("TRUE" if default else "FALSE") if isinstance(default, bool) else (
                    str(default) if isinstance(default, (int, float)) else "'" + str(default).replace("'", "''") + "'")
                clause = f" DEFAULT {lit}"
            null = "" if col.nullable else " NOT NULL"
            with engine.begin() as c:
                c.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl}{clause}{null}'))
            added.append((table.name, col.name))
    return added


def establish_owners(engine) -> int:
    """Data migration for tenants created before the owner role existed: their founding
    user was signed up as `admin`, owner-only permissions (billing) would be
    unreachable, and only an owner may appoint one. For each tenant without an active
    owner, promote its earliest active admin. Idempotent; returns tenants changed."""
    with engine.begin() as c:
        rows = c.execute(text(
            "SELECT u.tenant_id, (SELECT a.id FROM users a WHERE a.tenant_id = u.tenant_id AND a.role = 'admin' "
            "AND a.is_active ORDER BY a.created_at, a.id LIMIT 1) AS promote "
            "FROM users u GROUP BY u.tenant_id "
            "HAVING SUM(CASE WHEN u.role = 'owner' AND u.is_active THEN 1 ELSE 0 END) = 0")).all()
        n = 0
        for tenant_id, promote in rows:
            if promote:
                c.execute(text("UPDATE users SET role = 'owner' WHERE id = :id"), {"id": promote})
                c.execute(text("INSERT INTO audit_logs (id, tenant_id, user_id, action, detail, created_at) "
                               "VALUES (:id, :t, :u, 'role.migrated_owner', 'founding admin promoted to owner', "
                               "CURRENT_TIMESTAMP)"), {"id": uuid.uuid4().hex, "t": tenant_id, "u": promote})
                n += 1
    return n


def main() -> int:
    url = get_settings().database_url
    runtime = os.environ.get("APP_RUNTIME_ROLE", "mk_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", runtime):
        print("APP_RUNTIME_ROLE must be a plain lowercase identifier", file=sys.stderr)
        return 2
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    added = add_missing_columns(engine)
    for t, c in added:
        print(f"added column {t}.{c}")
    owners = establish_owners(engine)
    if owners:
        print(f"promoted founding admin to owner in {owners} tenant(s)")
    if engine.dialect.name != "postgresql":
        print(f"schema created ({engine.dialect.name}); no roles to grant")
        return 0
    with engine.begin() as c:
        c.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{runtime}"'))
        c.execute(text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{runtime}"'))
        tables = c.execute(text("SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")).scalar()
    print(f"schema ready: {tables} tables; DML granted to {runtime}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
