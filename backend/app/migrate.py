"""Explicit app database operator bootstrap and separate transactional migration.

No credentials on command lines or in output. The API never calls this module.
"""
import argparse
import hashlib
import os

import psycopg
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from .config import Settings
from .database_policy import MIGRATIONS, READ_ONLY_TABLES, migration_files, validate_schema
from .models import Base


def bootstrap(url, runtime_password, migration_password, *, adopt_public=False):
    if min(len(runtime_password), len(migration_password)) < 16 or runtime_password == migration_password:
        raise ValueError("Distinct app runtime and migration passwords of at least 16 characters are required")
    resolved = Settings(_env_file=None, database_url=make_url(url).render_as_string(hide_password=False),
                        db_host="", db_password="").connection_url
    target = resolved.set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(target) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(58721493621)")
        conn.execute((MIGRATIONS / "roles.sql").read_text(encoding="utf-8"))
        name = conn.execute("SELECT current_database()").fetchone()[0]
        conn.execute(sql.SQL("REVOKE CREATE, TEMP ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name)))
        conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO mk_app_runtime, mk_app_migrator").format(sql.Identifier(name)))
        for role, password in (("mk_app_login", runtime_password), ("mk_app_migrator", migration_password)):
            conn.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
        # Existing public-schema application tables are never moved implicitly.
        public = {row[0] for row in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")}
        existing = public & Base.metadata.tables.keys()
        if existing and not adopt_public:
            raise RuntimeError("Existing application tables require explicit bootstrap --adopt-public and a verified backup")
        if adopt_public:
            for table in sorted(existing):
                if conn.execute("SELECT to_regclass(%s)", (f"mk_app.{table}",)).fetchone()[0]:
                    raise RuntimeError("Both public and mk_app contain an application table; refusing ambiguous adoption")
                conn.execute(sql.SQL("ALTER TABLE public.{} SET SCHEMA mk_app").format(sql.Identifier(table)))
                conn.execute(sql.SQL("ALTER TABLE mk_app.{} OWNER TO mk_app_owner").format(sql.Identifier(table)))
        owner = conn.execute("SELECT r.rolname FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='mk_app'").fetchone()[0]
        if owner != "mk_app_owner":
            raise RuntimeError("Application schema has an unexpected owner")


def require_migration_identity(conn):
    identity = conn.execute(text("SELECT session_user, current_user")).one()
    if tuple(identity) != ("mk_app_migrator", "mk_app_migrator"):
        raise RuntimeError("Migration requires the separate mk_app_migrator login")
    elevated = conn.execute(text("""SELECT EXISTS(SELECT 1 FROM pg_roles WHERE
        (rolname=session_user OR pg_has_role(session_user,oid,'MEMBER'))
        AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
             OR rolname NOT IN ('mk_app_owner','mk_app_migrator')))""")).scalar()
    if elevated:
        raise RuntimeError("Unexpected migration identity privileges")
    conn.exec_driver_sql("SET LOCAL ROLE mk_app_owner")


def migrate(url):
    resolved = Settings(_env_file=None, database_url=make_url(url).render_as_string(hide_password=False),
                        db_host="", db_password="").connection_url
    engine = create_engine(resolved, hide_parameters=True)
    try:
        with engine.begin() as conn:
            require_migration_identity(conn)
            conn.exec_driver_sql("SET LOCAL search_path = mk_app, pg_catalog")
            conn.exec_driver_sql("SELECT pg_advisory_xact_lock(58721493621)")
            conn.exec_driver_sql("CREATE TABLE IF NOT EXISTS mk_app.schema_migrations (version text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())")
            applied = dict(conn.execute(text("SELECT version, sha256 FROM mk_app.schema_migrations")).all())
            files = migration_files()
            if set(applied) - {p.name for p in files}:
                raise RuntimeError("Database has newer/unknown migrations; refusing downgrade")
            for path in files:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if path.name in applied:
                    if applied[path.name] != digest:
                        raise RuntimeError("Applied migration checksum mismatch")
                    continue
                # Raw SQL files contain literal %ROWTYPE / LIKE patterns, not
                # driver placeholders. Execute without an empty parameter map.
                conn.connection.driver_connection.execute(path.read_text(encoding="utf-8"), prepare=False)
                conn.execute(text("INSERT INTO mk_app.schema_migrations(version,sha256) VALUES (:version,:sha256)"),
                             {"version": path.name, "sha256": digest})
            validate_schema(conn)
            for name in [*Base.metadata.tables, "schema_migrations"]:
                identifier = conn.dialect.identifier_preparer.quote(name)
                conn.exec_driver_sql(f"REVOKE ALL ON TABLE mk_app.{identifier} FROM PUBLIC, mk_app_runtime, mk_app_login")
                permissions = "SELECT" if name in READ_ONLY_TABLES else "SELECT, INSERT" if name == "audit_logs" else "SELECT, INSERT, UPDATE, DELETE"
                conn.exec_driver_sql(f"GRANT {permissions} ON TABLE mk_app.{identifier} TO mk_app_runtime")
            return [p.name for p in files]
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["bootstrap", "upgrade"])
    parser.add_argument("--adopt-public", action="store_true")
    args = parser.parse_args()
    if args.operation == "bootstrap":
        explicit = os.environ.get("MK_APP_BOOTSTRAP_URL")
        target = make_url(explicit) if explicit else Settings(db_user=os.environ["MK_APP_BOOTSTRAP_USER"], db_password=os.environ["MK_APP_BOOTSTRAP_PASSWORD"]).connection_url
        bootstrap(target, os.environ["MK_APP_RUNTIME_PASSWORD"],
                  os.environ["MK_APP_MIGRATION_PASSWORD"], adopt_public=args.adopt_public)
        print("Application roles/schema bootstrapped; run upgrade as mk_app_migrator")
    else:
        if args.adopt_public:
            raise ValueError("--adopt-public applies only to operator bootstrap")
        explicit = os.environ.get("MK_APP_MIGRATION_URL")
        target = make_url(explicit) if explicit else Settings(db_user="mk_app_migrator", db_password=os.environ["MK_APP_MIGRATION_PASSWORD"]).connection_url
        print("Application migrations applied:", ", ".join(migrate(target)))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # DB exceptions may contain full SQL with secrets; never print them.
        print(f"Application migration failed ({type(exc).__name__}); inspect database state with the operator runbook")
        raise SystemExit(1) from None
