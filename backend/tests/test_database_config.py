"""Deployment configuration must select the real database, without URL injection."""
import pytest
from sqlalchemy.engine import make_url

from app import db
from app.config import Settings


def test_ecs_database_fields_do_not_fall_back_to_sqlite(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    settings = Settings(_env_file=None, db_host="database.example.test", db_user="mk_app_login",
                        db_password="local@/?:#password", db_name="mkharness",
                        db_sslrootcert="/etc/mk/rds-global-bundle.pem")
    monkeypatch.setattr(db, "get_settings", lambda: settings)
    monkeypatch.setattr(db, "_engine", None)
    seen = []

    class Captured(Exception):
        pass

    def capture(url, **kwargs):
        seen.append(make_url(url))
        raise Captured

    monkeypatch.setattr(db, "create_engine", capture)
    with pytest.raises(Captured):
        db.init_engine()
    assert seen[0].get_backend_name() == "postgresql", "ECS DB_HOST was silently ignored"
    assert seen[0].password == "local@/?:#password"
    assert seen[0].host == "database.example.test"
    assert seen[0].query["sslmode"] == "verify-full"
    assert seen[0].query["sslrootcert"] == "/etc/mk/rds-global-bundle.pem"


@pytest.mark.parametrize("fields", [
    {"db_host": "db.example.test"},
    {"db_password": "local-only"},
    {"database_url": "sqlite://", "db_host": "db.example.test", "db_password": "local-only"},
    {"db_host": "db.example.test", "db_password": "local-only", "db_sslmode": "disable"},
])
def test_partial_ambiguous_or_insecure_database_configuration_fails(fields, monkeypatch):
    # Set explicitly so an ambient DATABASE_URL cannot turn this into another test.
    for key in ("DATABASE_URL", "DB_HOST", "DB_PASSWORD", "DB_USER", "DB_SSLMODE"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValueError):
        Settings(_env_file=None, **fields).connection_url
