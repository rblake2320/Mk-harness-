"""Shared fixtures. SQLite in-memory for speed; identical models run on
Postgres in production (compose file provisions it)."""
import base64
import os

import pytest
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JWT_SECRET"] = "test-secret-test-secret-test-secret-1234"
os.environ["MASTER_KEY"] = base64.b64encode(b"0" * 32).decode()
os.environ["RATE_LIMIT_PER_MINUTE"] = "1000"

from app.config import get_settings  # noqa: E402
get_settings.cache_clear()

from app import db as dbmod  # noqa: E402
from app.main import app  # noqa: E402

# Single shared in-memory engine across the whole test session.
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from app.models import Base  # noqa: E402

engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                       poolclass=StaticPool)
Base.metadata.create_all(engine)
dbmod._engine = engine
dbmod._SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def signup(client, org="Pink Org", email="admin@example.com", pw="superSecret123!",
           key_policy="both"):
    r = client.post("/api/auth/signup", json={
        "org_name": org, "email": email, "password": pw, "key_policy": key_policy})
    assert r.status_code == 201, r.text
    return r.json()


def auth_headers(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}
