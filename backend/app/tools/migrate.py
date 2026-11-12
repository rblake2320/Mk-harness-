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

from sqlalchemy import create_engine, text

from ..config import get_settings
from ..models import Base


def main() -> int:
    url = get_settings().database_url
    runtime = os.environ.get("APP_RUNTIME_ROLE", "mk_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", runtime):
        print("APP_RUNTIME_ROLE must be a plain lowercase identifier", file=sys.stderr)
        return 2
    engine = create_engine(url)
    Base.metadata.create_all(engine)
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
