"""Application sealing keys rotate independently of destination fingerprints."""
import base64
import uuid
from datetime import datetime, timezone

import pytest

from app import foundation, mfa
from app.config import get_settings
from app.crypto import encrypt_secret
from app.models import User


def test_every_encrypted_model_column_is_in_rotation_inventory():
    from app.models import Base
    from app.tools.reseal import FIELDS
    expected = {(table.name, c.name) for table in Base.metadata.tables.values() for c in table.columns
                if c.name.endswith("_enc") or c.name == "ciphertext"}
    actual = {(item.model.__tablename__, item.name) for item in FIELDS}
    assert actual == expected
    assert len(actual) == 9


def seed_rotation_records(db):
    """Synthetic isolated SQLite records for all nine fields, no provider calls."""
    from app.tools.reseal import FIELDS
    from app.models import AuthFactor, Customer, ImportJob, Tenant, User
    models = [Tenant, User, Customer, ImportJob, *dict.fromkeys(item.model for item in FIELDS)]
    records = {}
    for model in models:
        data = {}
        for column in model.__table__.columns:
            if column.default or column.nullable:
                continue
            kind = column.type.python_type
            data[column.name] = (datetime.now(timezone.utc) if kind is datetime else False if kind is bool
                                 else 1 if kind is int else 0.1 if kind is float else "fixture")
        data["tenant_id"] = "a" * 32
        if model is Tenant:
            data.pop("tenant_id")
            data["id"] = "a" * 32
        elif hasattr(model, "id"):
            data["id"] = "fixture"
        if model is AuthFactor:
            data["pending_session_id"] = "pending-session"
        row = model(**data)
        records[model] = row
    for item in FIELDS:
        row = records[item.model]
        setattr(row, item.name, encrypt_secret(get_settings().master_key_bytes, "synthetic-" + item.name, item.aad(row)))
    for model in (Tenant, User, Customer, ImportJob):
        db.add(records[model]); db.flush()
    db.add_all(row for model, row in records.items() if model not in (Tenant, User, Customer, ImportJob))
    db.commit()
    return records


def isolated_db(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.models import Base
    engine = create_engine("sqlite:///" + str(tmp_path / (uuid.uuid4().hex + ".db")))
    Base.metadata.create_all(engine)
    return engine, Session(engine, expire_on_commit=False)


def test_rekey_all_fields_then_remove_old_key_and_read_every_value(tmp_path, monkeypatch):
    from app.crypto import unseal_secret
    from app.models import ApplicationSealPolicy, AuditLog
    from app.tools.reseal import FIELDS, scan
    from sqlalchemy import select
    engine, db = isolated_db(tmp_path)
    try:
        records = seed_rotation_records(db)
        db.add(ApplicationSealPolicy(id=1, writer_kid="s2", allow_legacy=False)); db.commit()
        monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode() + ",m0=master")
        get_settings.cache_clear()
        before = scan(db)
        assert before.total == before.stale == 9 and not before.clean()
        after = scan(db, apply=True, batch_size=1)
        assert after.updated == 9 and after.clean()
        assert scan(db, apply=True).updated == 0
        logs = db.scalars(select(AuditLog)).all()
        assert len(logs) == 9 and all("synthetic-" not in log.detail for log in logs)
        monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode())
        get_settings.cache_clear()
        db.expire_all()
        for item in FIELDS:
            row = records[item.model]
            assert unseal_secret(getattr(row, item.name), item.aad(row)) == "synthetic-" + item.name
        assert scan(db).clean()
    finally:
        db.close(); engine.dispose(); get_settings.cache_clear()


def test_corrupt_value_blocks_retirement_without_logging_plaintext(tmp_path, monkeypatch):
    from app.models import ApplicationSealPolicy, ProviderKey
    from app.tools.reseal import scan
    engine, db = isolated_db(tmp_path)
    try:
        records = seed_rotation_records(db)
        records[ProviderKey].ciphertext = "invalid-not-a-key"
        db.add(ApplicationSealPolicy(id=1, writer_kid="s2", allow_legacy=False)); db.commit()
        monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode() + ",m0=master")
        get_settings.cache_clear()
        report = scan(db, apply=True, batch_size=1)
        assert report.updated == 8 and report.unreadable == 1 and not report.clean()
        assert "invalid-not-a-key" not in repr(report)
        assert records[ProviderKey].ciphertext == "invalid-not-a-key"
    finally:
        db.close(); engine.dispose(); get_settings.cache_clear()


def test_rekey_does_not_overwrite_concurrent_new_value(tmp_path, monkeypatch):
    from app.models import ApplicationSealPolicy, ProviderKey
    from app.tools import reseal
    from sqlalchemy.orm import Session
    from sqlalchemy import update
    engine, db = isolated_db(tmp_path)
    try:
        records = seed_rotation_records(db)
        row = records[ProviderKey]
        db.add(ApplicationSealPolicy(id=1, writer_kid="s2", allow_legacy=False)); db.commit()
        monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode() + ",m0=master")
        get_settings.cache_clear()
        original = reseal.seal_secret
        replacement = original("newer-synthetic", reseal.FIELDS[0].aad(row))
        raced = False
        def race(plaintext, aad, **kwargs):
            nonlocal raced
            if not raced:
                raced = True
                with Session(engine) as other:
                    other.execute(update(ProviderKey).where(ProviderKey.id == row.id).values(ciphertext=replacement))
                    other.commit()
            return original(plaintext, aad, **kwargs)
        monkeypatch.setattr(reseal, "seal_secret", race)
        report = reseal.scan(db, apply=True, batch_size=1)
        db.refresh(row)
        assert report.conflicts == 1 and row.ciphertext == replacement
        assert not report.clean() and reseal.scan(db).clean()
    finally:
        db.close(); engine.dispose(); get_settings.cache_clear()


@pytest.mark.parametrize("change", ["tenant", "kind", "kid", "malformed"])
def test_envelope_binding_and_malformed_values_fail(change):
    from app.crypto import seal_secret, unseal_secret
    keys = [("s2", b"2" * 32), ("alias", b"2" * 32)]
    encrypted = seal_secret("synthetic", "tenant:purpose", keys=keys)
    aad = "tenant:purpose"
    if change == "tenant": aad = "foreign:purpose"
    if change == "kind": aad = "tenant:other"
    if change == "kid": encrypted = encrypted.replace("mk1:s2:", "mk1:alias:")
    if change == "malformed": encrypted = "mk1:s2:not!base64"
    with pytest.raises(Exception):
        unseal_secret(encrypted, aad, keys=keys)


@pytest.mark.parametrize("spec", ["bad", "K2=master", "m0=master,m0=master", "s2=bad-base64", "s2=YQ==", "m0=master,"])
def test_invalid_sealing_key_configuration_fails_closed(spec, monkeypatch):
    monkeypatch.setenv("APP_SEAL_KEYS", spec)
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError):
            get_settings().seal_key_list
    finally:
        get_settings.cache_clear()


def test_application_sealing_uses_selected_key_without_changing_fingerprints(monkeypatch):
    tenant = "1" * 32
    before = foundation.fingerprint(tenant, "sms", "+12025550123")
    monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode() + ",m0=master")
    get_settings.cache_clear()
    try:
        encrypted = foundation.seal(tenant, "destination", "+12025550123")
        assert encrypted.startswith("mk1:s2:"), "sealing key rotation setting was ignored"
        assert foundation.unseal(tenant, "destination", encrypted) == "+12025550123"
        assert foundation.fingerprint(tenant, "sms", "+12025550123") == before
        user = User(id="u", tenant_id=tenant)
        assert mfa.seal(user, "SYNTHETICSEED").startswith("mk1:s2:")
    finally:
        get_settings.cache_clear()


def test_removing_legacy_seal_key_refuses_legacy_ciphertext(monkeypatch):
    legacy = encrypt_secret(get_settings().master_key_bytes, "synthetic", "mk-foundation:t:draft")
    monkeypatch.setenv("APP_SEAL_KEYS", "s2=" + base64.b64encode(b"2" * 32).decode())
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="unavailable"):
            foundation.unseal("t", "draft", legacy)
    finally:
        get_settings.cache_clear()
