"""Database engine and session management."""
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .models import Base

_engine = None
_SessionLocal = None


def init_engine(url: str | URL | None = None):
    global _engine, _SessionLocal
    if _engine is not None and url is None:
        return _engine  # already configured (tests or prior startup)
    settings = get_settings()
    target = make_url(url) if url is not None else settings.connection_url
    kwargs = {}
    if target.get_backend_name() == "sqlite":
        kwargs["connect_args"] = {"check_same_thread": False}
    candidate = create_engine(target, pool_pre_ping=True, hide_parameters=True, **kwargs)
    try:
        if candidate.dialect.name == "postgresql":
            from .database_policy import validate_runtime
            with candidate.connect() as connection:
                validate_runtime(connection)
            from sqlalchemy import event
            @event.listens_for(candidate, "connect")
            def search_path(connection, _record):
                # SET outside a transaction so pool rollback cannot reset it.
                previous = connection.autocommit
                connection.autocommit = True
                try:
                    connection.execute("SET search_path = pg_catalog, mk_app")
                finally:
                    connection.autocommit = previous
            # The validation connection preceded the hook; recycle it.
            candidate.dispose()
        elif candidate.dialect.name == "sqlite":
            Base.metadata.create_all(candidate)  # explicit local-development path
        else:
            raise RuntimeError("Only PostgreSQL and local SQLite are supported")
    except Exception:
        candidate.dispose()
        raise
    _engine = candidate
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_db() -> Generator[Session, None, None]:
    if _SessionLocal is None:
        init_engine()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
