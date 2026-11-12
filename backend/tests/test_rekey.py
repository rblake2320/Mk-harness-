"""S10 — application sealing-key rotation (MASTER_KEY re-encryption).

Every sealed column moves to a new key without data loss; the app keeps working
during (both keys listed) and after (new key only) the rotation; pre-versioning
ciphertext is readable as m0; a row the tool cannot open is reported and never
overwritten; AAD scope binding survives re-sealing; re-running is a no-op.
"""
import base64
import uuid

import pytest
from sqlalchemy import select

from app import crypto, db as dbmod
from app.config import get_settings
from app.foundation import _aad, seal, unseal
from app.models import CustomerDestination, DraftVersion, MfaFactor, ProviderKey
from app.tools import rekey

from .conftest import auth_headers, signup
from .test_identity import _enroll_totp, _totp_now

K2 = base64.b64encode(bytes([42]) * 32).decode()
K3 = base64.b64encode(bytes([43]) * 32).decode()


@pytest.fixture
def keys(monkeypatch):
    def use(spec: str):
        if spec:
            monkeypatch.setenv("SEALING_KEYS", spec)
        else:
            monkeypatch.delenv("SEALING_KEYS", raising=False)
        get_settings.cache_clear()
    yield use
    # Leave the shared test database as other tests expect it: everything under m0.
    use(f"m0=master,k2={K2},k3={K3}")
    db = dbmod._SessionLocal()
    rekey.scan(db, apply=True)
    db.close()
    monkeypatch.delenv("SEALING_KEYS", raising=False)
    get_settings.cache_clear()


def _db():
    return dbmod._SessionLocal()


def _world(client):
    tag = uuid.uuid4().hex[:8]
    t = signup(client, org=f"Org {tag}", email=f"rk-{tag}@example.com")
    h = auth_headers(t)
    cid = client.post("/api/customers", json={"name": "Rae"}, headers=h).json()["id"]
    d = client.post(f"/api/customers/{cid}/destinations", json={"channel": "sms", "value": "+15555550161"}, headers=h)
    assert d.status_code == 201, d.text
    assert client.put("/api/keys/mine", json={"provider": "openai", "api_key": "sk-test-rekey-0123456789"},
                      headers=h).status_code in (200, 201)
    secret, _ = _enroll_totp(client, h)
    return h, cid, d.json()["id"], secret


def test_rotation_moves_every_sealed_column_and_the_app_keeps_working(client, keys, frozen_clock):
    frozen_clock("2026-11-12T10:00:05+00:00")
    keys("")
    h, cid, did, secret = _world(client)
    db = _db()
    # A pre-versioning row (unprefixed ciphertext) is m0's and opens.
    c = db.get(CustomerDestination, did)
    legacy = crypto.encrypt_secret(get_settings().master_key_bytes, "+15555550161", _aad(c.tenant_id, "destination"))
    c.value_enc = legacy
    db.commit()
    assert crypto.key_id_of(legacy) == "m0" and unseal(c.tenant_id, "destination", legacy) == "+15555550161"
    # Phase 1: new key first, old still listed. Status is not clean until re-keyed.
    keys(f"k2={K2},m0=master")
    st = rekey.scan(db, apply=False)
    # The shared test DB may hold other tests' deliberately fake ciphertext: compare
    # against that baseline instead of assuming zero.
    baseline = set(st["unreadable_rows"])
    assert st["current"] == "k2" and st["stale"] > 0, st
    assert not any(did in r for r in baseline)
    assert rekey.main(["status"]) == 1
    # New writes already use k2.
    assert crypto.key_id_of(seal(c.tenant_id, "draft", "x")) == "k2"
    out = rekey.scan(db, apply=True)
    assert out["resealed"] >= 3 and set(out["unreadable_rows"]) == baseline, out   # destination, provider key, TOTP
    after = rekey.scan(db, apply=False)
    assert after["stale"] == len(baseline) and set(after["unreadable_rows"]) == baseline, after
    again = rekey.scan(db, apply=True)
    assert again["resealed"] == 0                                 # idempotent / crash-resumable
    # Phase 2: old key removed. Destination, provider key and TOTP all still work.
    keys(f"k2={K2}")
    db.expire_all()
    assert all(crypto.key_id_of(x) == "k2" for x in db.scalars(select(CustomerDestination.value_enc).where(
        CustomerDestination.id == did)))
    assert all(crypto.key_id_of(x) == "k2" for x in db.scalars(select(ProviderKey.ciphertext)))
    assert all(crypto.key_id_of(x) == "k2" for x in db.scalars(select(MfaFactor.secret_enc)) if x)
    r = client.get(f"/api/customers/{cid}/destinations", headers=h)
    assert r.status_code == 200 and r.json()[0]["value_masked"].endswith("0161"), r.text
    frozen_clock("2026-11-12T10:00:40+00:00")
    s = client.post("/api/security/step-up", json={"method": "totp", "code": _totp_now(secret)}, headers=h)
    assert s.status_code == 200, s.text                          # TOTP secret re-sealed and usable
    db.close()


def test_a_row_that_cannot_be_opened_is_reported_and_never_overwritten(client, keys):
    keys("")
    h, cid, did, _ = _world(client)
    db = _db()
    c = db.get(CustomerDestination, did)
    # Sealed under a kid nobody has configured (lost key / foreign row).
    keys(f"k3={K3}")
    orphan = seal(c.tenant_id, "destination", "+15555550199")
    keys(f"k2={K2},m0=master")
    c.value_enc = orphan
    db.commit()
    out = rekey.scan(db, apply=True)
    assert out["unreadable"] >= 1 and any(did in r for r in out["unreadable_rows"]), out
    db.expire_all()
    assert db.get(CustomerDestination, did).value_enc == orphan   # untouched: no silent data loss
    assert rekey.main(["status"]) == 1
    with pytest.raises(KeyError):
        unseal(c.tenant_id, "destination", orphan)
    db.close()


def test_same_kid_with_a_different_key_does_not_decrypt(client, keys):
    keys(f"k2={K2}")
    h, cid, did, _ = _world(client)
    keys(f"k2={K3}")      # operator error: kid reused for a different key
    db = _db()
    out = rekey.scan(db, apply=True)
    assert out["unreadable"] >= 1 and out["resealed"] == 0
    db.close()


def test_aad_scope_binding_survives_resealing(client, keys):
    keys(f"k2={K2},m0=master")
    h1, _, did1, _ = _world(client)
    h2, _, did2, _ = _world(client)
    db = _db()
    rekey.scan(db, apply=True)
    a, b = db.get(CustomerDestination, did1), db.get(CustomerDestination, did2)
    with pytest.raises(Exception):
        unseal(b.tenant_id, "destination", a.value_enc)          # copied to another tenant: fails
    with pytest.raises(Exception):
        unseal(a.tenant_id, "draft", a.value_enc)                # same tenant, other kind: fails
    db.close()


def test_sealing_keys_config_is_validated(keys):
    for bad in ["k2", f"K2={K2}", f"k2={K2},k2={K2}", "k2=AAAA", "k2=not-base64!!"]:
        keys(bad)
        with pytest.raises(Exception):
            _ = get_settings().sealing_key_list
