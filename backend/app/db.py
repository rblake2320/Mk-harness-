"""Database engine and session management."""
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .models import Base

_engine = None
_SessionLocal = None


def init_engine(url: str | None = None):
    global _engine, _SessionLocal
    if _engine is not None and url is None:
        return _engine  # already configured (tests or prior startup)
    settings = get_settings()
    target = url or settings.database_url
    kwargs = {}
    if target.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(target, pool_pre_ping=True, **kwargs)
    if settings.db_create_all:
        Base.metadata.create_all(engine)
        from .tools.migrate import establish_owners   # dev path: same data migration as the job
        establish_owners(engine)
    if settings.db_require_least_privilege:
        problem = privilege_problem(engine)
        if problem:
            engine.dispose()
            raise RuntimeError(f"refusing to start: database login is over-privileged ({problem}); "
                               "run the API as the runtime role and migrate with app.tools.migrate")
    _engine = engine
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def privilege_problem(engine) -> str | None:
    """None when the connected login is least-privilege for the application schema;
    otherwise the reason. Only meaningful on PostgreSQL."""
    from sqlalchemy import text
    if engine.dialect.name != "postgresql":
        return "not PostgreSQL (least-privilege cannot be verified)"
    with engine.connect() as c:
        row = c.execute(text(
            "SELECT r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, "
            "(SELECT count(*) FROM pg_tables t WHERE t.schemaname = 'public' AND t.tableowner = current_user) "
            "FROM pg_roles r WHERE r.rolname = current_user")).one()
    flags = [name for name, on in zip(("superuser", "bypassrls", "createrole", "createdb"), row[:4]) if on]
    if row[4]:
        flags.append(f"owns {row[4]} application tables")
    return ", ".join(flags) or None


def get_db() -> Generator[Session, None, None]:
    if _SessionLocal is None:
        init_engine()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
