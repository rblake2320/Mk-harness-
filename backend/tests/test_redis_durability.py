"""Redis durability: the API must survive Redis dying AFTER startup.

Uses a REAL redis-server process — spawned, killed, and revived by the test.
No fakes, no client mocks: this exercises the exact production failure mode
(connection refused mid-flight) at the HTTP boundary.

Skipped automatically where the redis-server binary is unavailable; CI
installs it so this always runs there.
"""
import shutil
import socket
import subprocess
import time
import uuid

import pytest

REDIS_PORT = 6391  # dedicated port — never collides with a system Redis

pytestmark = pytest.mark.skipif(
    shutil.which("redis-server") is None,
    reason="redis-server binary not available",
)


def _wait_port(port: int, up: bool, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.2)
            alive = s.connect_ex(("localhost", port)) == 0
        if alive == up:
            return True
        time.sleep(0.1)
    return False


@pytest.fixture()
def live_redis_client(tmp_path, monkeypatch):
    """App wired to a real Redis on a dedicated port; caller may kill/revive it."""
    proc = subprocess.Popen(
        ["redis-server", "--port", str(REDIS_PORT), "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert _wait_port(REDIS_PORT, up=True), "redis-server failed to start"

    monkeypatch.setenv("REDIS_URL", f"redis://localhost:{REDIS_PORT}/0")
    from app import cache
    from app.config import get_settings
    get_settings.cache_clear()
    cache.reset_for_tests()

    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    try:
        yield client
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        subprocess.run(["redis-cli", "-p", str(REDIS_PORT), "shutdown", "nosave"],
                       capture_output=True)
        get_settings.cache_clear()
        cache.reset_for_tests()


def _signup(client):
    email = f"dur{uuid.uuid4().hex[:10]}@t.com"
    r = client.post("/api/auth/signup", json={
        "org_name": "DurabilityOrg", "email": email,
        "password": "superSecret123!", "key_policy": "both"})
    assert r.status_code == 201
    return email, {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_api_survives_redis_death_and_recovers(live_redis_client):
    client = live_redis_client
    email, headers = _signup(client)

    from app.cache import get_redis
    assert get_redis() is not None, "test precondition: Redis path must be active"

    # Baseline with Redis alive: rate-limited endpoint and login both work.
    assert client.post("/api/chat/stream", headers=headers,
                       json={"message": "hi", "skill": "assistant"}).status_code == 200
    assert client.post("/api/auth/login", json={
        "email": email, "password": "superSecret123!"}).status_code == 200

    # Kill Redis for real.
    subprocess.run(["redis-cli", "-p", str(REDIS_PORT), "shutdown", "nosave"],
                   capture_output=True)
    assert _wait_port(REDIS_PORT, up=False), "redis did not die"

    # Login must NOT crash — in-process brute-force fallback takes over.
    assert client.post("/api/auth/login", json={
        "email": email, "password": "superSecret123!"}).status_code == 200

    # Rate-limited endpoint must NOT crash — in-process limiter takes over.
    assert client.post("/api/chat/stream", headers=headers,
                       json={"message": "hi", "skill": "assistant"}).status_code == 200

    # Brute-force lockout must still ENGAGE during the outage (security holds).
    for _ in range(5):
        client.post("/api/auth/login", json={"email": email,
                                             "password": "definitelyWrong99"})
    r = client.post("/api/auth/login", json={"email": email,
                                             "password": "definitelyWrong99"})
    assert r.status_code == 429, "lockout must survive Redis outage"

    # Revive Redis — the app must resume Redis-backed limiting on its own,
    # with no restart (connection pool reconnects per call).
    subprocess.Popen(
        ["redis-server", "--port", str(REDIS_PORT), "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert _wait_port(REDIS_PORT, up=True), "redis did not revive"

    _, headers2 = _signup(client)  # fresh user — not locked out
    assert client.post("/api/chat/stream", headers=headers2,
                       json={"message": "hi", "skill": "assistant"}).status_code == 200

    import redis as _redis
    probe = _redis.from_url(f"redis://localhost:{REDIS_PORT}/0", decode_responses=True)
    assert probe.keys("rl:*"), "rate-limit keys must be written to Redis again after revival"
