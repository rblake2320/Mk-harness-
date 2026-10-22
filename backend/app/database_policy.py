"""Fail closed on privileged/owner PostgreSQL credentials and schema drift."""
import hashlib
from pathlib import Path

from sqlalchemy import inspect, text

from .models import Base

MIGRATIONS = Path(__file__).parent / "migrations"


def migration_files():
    return sorted(MIGRATIONS.glob("[0-9]*.sql"))


def validate_schema(connection):
    inspector = inspect(connection)
    actual = set(inspector.get_table_names(schema="mk_app"))
    required = set(Base.metadata.tables)
    if not required <= actual:
        raise RuntimeError("Application database schema is incomplete; run the separate migrator")
    for name, table in Base.metadata.tables.items():
        columns = {c["name"]: c for c in inspector.get_columns(name, schema="mk_app")}
        expected = {c.name for c in table.columns}
        if expected != columns.keys():
            raise RuntimeError(f"Application schema drift in {name}; an explicit migration is required")
        for column in table.columns:
            observed = columns[column.name]
            incompatible = observed["type"]._type_affinity is not column.type._type_affinity
            for attribute in ("length", "timezone"):
                incompatible |= getattr(observed["type"], attribute, None) != getattr(column.type, attribute, None)
            if observed["nullable"] != column.nullable or incompatible:
                raise RuntimeError(f"Application schema drift in {name}.{column.name}")
        primary = inspector.get_pk_constraint(name, schema="mk_app")["constrained_columns"]
        if set(primary) != {c.name for c in table.primary_key.columns}:
            raise RuntimeError(f"Application primary key drift in {name}")
        foreign_keys = inspector.get_foreign_keys(name, schema="mk_app")
        if any(f["referred_schema"] not in {None, "mk_app"} for f in foreign_keys):
            raise RuntimeError(f"Application foreign key schema drift in {name}")
        foreign = {(tuple(f["constrained_columns"]), f["referred_table"], tuple(f["referred_columns"]))
                   for f in foreign_keys}
        expected_fk = {(tuple(c.name for c in f.columns), next(iter(f.elements)).column.table.name,
                        tuple(e.column.name for e in f.elements)) for f in table.foreign_key_constraints}
        if foreign != expected_fk:
            raise RuntimeError(f"Application foreign key drift in {name}")
        from sqlalchemy import UniqueConstraint
        expected_unique = {tuple(c.name for c in constraint.columns) for constraint in table.constraints
                           if isinstance(constraint, UniqueConstraint)}
        observed_unique = {tuple(c["column_names"]) for c in inspector.get_unique_constraints(name, schema="mk_app")}
        if expected_unique != observed_unique:
            raise RuntimeError(f"Application unique constraint drift in {name}")


def validate_runtime(connection):
    # Check both identities: SET ROLE must never hide an owner/superuser login.
    identity = connection.execute(text("SELECT session_user, current_user")).one()
    if identity[0] != "mk_app_login" or identity[1] != "mk_app_login":
        raise RuntimeError("Unsafe runtime database identity: use the dedicated mk_app_login")
    roles = connection.execute(text("""
        SELECT rolname, rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls AS unsafe
        FROM pg_roles WHERE oid = (SELECT oid FROM pg_roles WHERE rolname=session_user)
           OR pg_has_role(session_user, oid, 'MEMBER')
    """)).all()
    if any(row.unsafe or row.rolname not in {"mk_app_login", "mk_app_runtime"} for row in roles):
        raise RuntimeError("Unsafe runtime database identity: elevated attributes or extra role memberships")
    if connection.execute(text("SELECT has_database_privilege(current_database(), 'CREATE,TEMP')")).scalar():
        raise RuntimeError("Unsafe runtime database identity: database DDL permission")
    schemas = connection.execute(text("""SELECT nspname FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema'
        AND (has_schema_privilege(oid, 'CREATE') OR pg_has_role(nspowner, 'MEMBER'))""")).all()
    if schemas:
        raise RuntimeError("Unsafe runtime database identity: schema ownership or CREATE permission")
    relations = connection.execute(text("""SELECT n.nspname, c.relname, c.relkind,
        pg_has_role(c.relowner, 'MEMBER') AS owned,
        (has_table_privilege(c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR has_any_column_privilege(c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')) AS accessible,
        (has_table_privilege(c.oid, 'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR has_any_column_privilege(c.oid, 'UPDATE,REFERENCES')) AS destructive,
        has_table_privilege(c.oid, 'TRUNCATE,REFERENCES,TRIGGER') AS ddl
        , has_any_column_privilege(c.oid, 'INSERT') AS insertable
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname NOT LIKE 'pg_%'
          AND n.nspname <> 'information_schema'""")).all()
    for row in relations:
        permitted = row.nspname == "mk_app" and row.relname in {*Base.metadata.tables, "schema_migrations"}
        immutable = row.relname in {"audit_logs", "schema_migrations"}
        if row.owned or (row.accessible and not permitted) or row.ddl or (immutable and row.destructive) or (row.relname == "schema_migrations" and row.insertable):
            raise RuntimeError("Unsafe runtime database identity: table ownership or excess grants")
    if connection.execute(text("""SELECT EXISTS(SELECT 1 FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prosecdef
        AND n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
        AND has_function_privilege(p.oid,'EXECUTE'))""")).scalar():
        raise RuntimeError("Unsafe runtime database identity: executable security-definer function")
    validate_schema(connection)
    for name in [*Base.metadata.tables, "schema_migrations"]:
        required = ["SELECT"] if name == "schema_migrations" else ["SELECT", "INSERT"] if name == "audit_logs" else ["SELECT", "INSERT", "UPDATE", "DELETE"]
        for permission in required:
            if not connection.execute(text("SELECT has_table_privilege(:table, :permission)"),
                                      {"table": f"mk_app.{name}", "permission": permission}).scalar():
                raise RuntimeError("Runtime database identity is missing required application grants")
    try:
        applied = dict(connection.execute(text("SELECT version, sha256 FROM mk_app.schema_migrations")).all())
    except Exception as exc:
        raise RuntimeError("Application migration ledger is missing") from exc
    expected = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in migration_files()}
    if not expected or applied != expected:
        raise RuntimeError("Application migration ledger does not match the shipped image")
