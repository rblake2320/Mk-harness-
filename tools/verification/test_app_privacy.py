"""Deletion acceptance against the disposable PostgreSQL runtime identity."""
import base64
import sys
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from test_app_database import database, initialized  # noqa: F401
from app import db
from app.config import get_settings
from app.models import Customer, ProviderKey, User
from app.routes.account import DeleteAccountIn, delete_account
from app.routes.customers import delete_customer
from app.security import hash_password

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend" / "tests"))
from test_seal_rotation import seed_rotation_records


@pytest.fixture
def populated(initialized, monkeypatch):
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(b"0" * 32).decode())
    monkeypatch.setenv("JWT_SECRET", "synthetic-privacy-test-jwt-key-" + "0" * 32)
    monkeypatch.delenv("APP_SEAL_KEYS", raising=False)
    get_settings.cache_clear()
    engine = db.init_engine(initialized[2])
    with Session(engine, expire_on_commit=False) as session:
        records = seed_rotation_records(session)
        user = records[User]
        user.password_hash = hash_password("deletion-test-password")
        records[ProviderKey].user_id = user.id
        session.commit()
        yield session, records
    get_settings.cache_clear()


def test_linked_customer_deletion_works_under_foreign_keys(populated):
    session, records = populated
    cid = records[Customer].id
    result = delete_customer(cid, records[User], session)
    assert result["ok"]
    session.expire_all()
    assert session.get(Customer, cid) is None


def test_account_deletion_erases_owned_provider_credential(populated):
    session, records = populated
    # No customer graph: isolate the credential-retention defect.
    from app.models import Base
    for table in reversed(Base.metadata.sorted_tables):
        if table.name not in {"tenants", "users", "provider_keys", "schema_migrations", "application_seal_policy", "audit_logs", "erasure_requests", "retained_consents"}:
            session.execute(table.delete())
    session.commit()
    result = delete_account(DeleteAccountIn(password="deletion-test-password"), records[User], session)
    assert result["ok"]
    assert session.scalar(select(ProviderKey).where(ProviderKey.user_id == records[User].id)) is None


def seed_customer_graph(session, records):
    from datetime import datetime, timezone
    from app.models import (ActionLink, BriefItem, Commitment, ConsentEvent, ConsentRecord,
        ContactPreference, CustomerDestination, InboundApplication, SkinAnalysis, SuppressionEvent)
    for model in (ActionLink, BriefItem, Commitment, ConsentEvent, ConsentRecord,
                  ContactPreference, InboundApplication, SkinAnalysis, SuppressionEvent):
        data = {}
        for column in model.__table__.columns:
            if column.default or column.nullable:
                continue
            kind = column.type.python_type
            data[column.name] = (datetime.now(timezone.utc) if kind is datetime else False if kind is bool
                                 else 1 if kind is int else 0.1 if kind is float else "fixture")
        data["tenant_id"] = records[User].tenant_id
        if hasattr(model, "customer_id"):
            data["customer_id"] = records[Customer].id
        if model is ConsentEvent:
            data["destination_id"] = records[CustomerDestination].id
            data["evidence_ref"] = "private-person@example.invalid"
        if model is SuppressionEvent:
            data["reason"] = "private customer reason"
        row = model(**data)
        session.add(row); session.flush()
    session.commit()


def test_full_graph_erased_minimal_consent_and_suppression_retained(populated):
    from app.models import (ActionLink, BriefItem, Commitment, ConsentEvent, ConsentRecord,
        ContactPreference, CustomerDestination, DraftVersion, ExceptionRecord, ImportRow,
        InboundApplication, Outcome, RetainedConsent, SkinAnalysis, SuppressionEvent, AuditLog)
    session, records = populated
    seed_customer_graph(session, records)
    tid, cid = records[User].tenant_id, records[Customer].id
    result = delete_customer(cid, records[User], session)
    assert result["status"] == "pending_downstream" and "kernel_contact" in result["pending"]
    for model in (ActionLink, BriefItem, Commitment, ConsentEvent, ConsentRecord,
        ContactPreference, CustomerDestination, DraftVersion, ExceptionRecord, ImportRow, Outcome, SkinAnalysis):
        assert session.scalar(select(model).where(model.tenant_id == tid, model.customer_id == cid)) is None
    proofs = session.scalars(select(RetainedConsent)).all()
    assert len(proofs) == 2
    import json
    assert all("evidence_ref" not in json.loads(proof.proof_json) for proof in proofs)
    assert all("private" not in proof.proof_json for proof in proofs)
    suppression = session.scalar(select(SuppressionEvent))
    assert suppression.customer_id is None and suppression.reason == "privacy_erasure"
    assert suppression.fingerprint == "fixture"
    marker = session.scalar(select(InboundApplication))
    assert marker.customer_id is None and marker.created_json == "[]" and marker.label == "erased"
    assert session.scalar(select(AuditLog).where(AuditLog.action == "privacy.customer.active_erased"))
    # Retrying the public endpoint uses the tombstone without duplicating work.
    assert delete_customer(cid, records[User], session)["request_id"] == result["request_id"]


def test_cross_tenant_and_other_member_data_survive(populated):
    from app.models import Tenant
    from fastapi import HTTPException
    session, records = populated
    own = records[User]
    peer = User(id="peer", tenant_id=own.tenant_id, email="peer@example.invalid", password_hash="x")
    session.add(peer); session.flush()
    session.add(Tenant(id="foreign", name="foreign business")); session.flush()
    foreign = User(id="foreign", tenant_id="foreign", email="foreign@example.invalid", password_hash="x")
    session.add(foreign); session.flush()
    session.add_all([Customer(id="peer-c", tenant_id=peer.tenant_id, user_id=peer.id, name="Peer private"),
                     Customer(id="foreign-c", tenant_id=foreign.tenant_id, user_id=foreign.id, name="Foreign private"),
                     ProviderKey(tenant_id=own.tenant_id, user_id=peer.id, provider="ollama", scope="user", ciphertext=""),
                     ProviderKey(tenant_id=own.tenant_id, user_id=None, provider="ollama", scope="tenant", ciphertext="")])
    session.commit()
    for cid in ("peer-c", "foreign-c"):
        with pytest.raises(HTTPException) as caught:
            delete_customer(cid, own, session)
        assert caught.value.status_code == 404
    delete_account(DeleteAccountIn(password="deletion-test-password"), own, session)
    assert session.get(Customer, "peer-c").name == "Peer private"
    assert session.get(Customer, "foreign-c").name == "Foreign private"
    assert len(session.scalars(select(ProviderKey)).all()) == 2  # peer + shared business key
    assert session.get(Tenant, own.tenant_id).name != "Erased business"


def test_runtime_cannot_rewrite_erasure_tombstones_or_minimal_proof(populated):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError
    session, records = populated
    seed_customer_graph(session, records)
    delete_customer(records[Customer].id, records[User], session)
    for statement in ("DELETE FROM erasure_requests", "UPDATE erasure_requests SET subject_id='changed'",
                      "DELETE FROM retained_consents", "UPDATE retained_consents SET proof_json='{}'"):
        with pytest.raises(DBAPIError) as caught:
            session.execute(text(statement))
        assert caught.value.orig.sqlstate == "42501"
        session.rollback()


def test_account_erasure_serializes_with_inflight_write_and_blocks_late_write(populated):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from app.privacy import erase_account
    from sqlalchemy.exc import IntegrityError
    session, records = populated
    engine = session.bind
    uid, tid = records[User].id, records[User].tenant_id
    session.commit()
    started = Event()
    def erase():
        with Session(engine) as other:
            actor = other.get(User, uid)
            started.set()
            erase_account(other, actor)
            other.commit()
    with Session(engine) as writer, ThreadPoolExecutor(max_workers=1) as pool:
        writer.add(Customer(id="inflight", tenant_id=tid, user_id=uid, name="inflight private"))
        writer.flush()  # holds the shared user guard lock until commit
        work = pool.submit(erase)
        assert started.wait(5)
        # Inspect the database's lock wait, not a timing-only assertion.
        import time
        from sqlalchemy import text
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with engine.connect() as probe:
                waiting = probe.execute(text("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'")).scalar()
            if waiting:
                break
            time.sleep(.02)
        assert waiting and not work.done()
        writer.commit()
        work.result(timeout=10)
    session.expire_all()
    assert session.get(Customer, "inflight") is None
    with pytest.raises(IntegrityError) as caught:
        session.add(Customer(tenant_id=tid, user_id=uid, name="late private")); session.flush()
    assert "PRIVACY_SUBJECT_ERASED" in str(caught.value.orig)
    session.rollback()


def test_deleted_identity_and_shared_keys_cannot_be_resurrected(populated):
    from sqlalchemy import update
    from sqlalchemy.exc import IntegrityError
    session, records = populated
    own = records[User]
    uid, tid = own.id, own.tenant_id
    delete_account(DeleteAccountIn(password="deletion-test-password"), own, session)
    for change in ({"is_active": True}, {"display_name": "restored name"}, {"email": "old@example.invalid"}):
        with pytest.raises(IntegrityError) as caught:
            session.execute(update(User).where(User.id == uid).values(**change))
        assert "PRIVACY_SUBJECT_ERASED" in str(caught.value.orig)
        session.rollback()
    with pytest.raises(IntegrityError):
        session.add(ProviderKey(tenant_id=tid, user_id=None, provider="ollama", scope="tenant", ciphertext=""))
        session.flush()
    session.rollback()


def test_restore_ledger_rejects_corruption_staleness_and_scope_mismatch(populated):
    import hashlib
    import json
    from datetime import datetime, timedelta, timezone
    from app.tools.privacy_ledger import export_ledger, load_ledger, replay_ledger
    session, records = populated
    before = datetime.now(timezone.utc)
    delete_customer(records[Customer].id, records[User], session)
    raw = export_ledger(session)
    digest = hashlib.sha256(raw).hexdigest()
    rows = load_ledger(raw, digest, before)
    assert len(rows) == 1
    assert replay_ledger(session, rows)["applied"] is False
    with pytest.raises(ValueError, match="digest"):
        load_ledger(raw + b" ", digest, before)
    with pytest.raises(ValueError, match="stale"):
        load_ledger(raw, digest, datetime.now(timezone.utc) + timedelta(seconds=1))
    forged = [dict(rows[0], tenant_id="another-tenant")]
    with pytest.raises(ValueError, match="tenant mismatch"):
        replay_ledger(session, forged, apply=True)
    duplicate = json.loads(raw); duplicate["requests"] *= 2
    encoded = json.dumps(duplicate).encode()
    with pytest.raises(ValueError, match="Duplicate"):
        load_ledger(encoded, hashlib.sha256(encoded).hexdigest(), before)
    conflicting = [dict(rows[0], requested_by="different-requestor")]
    with pytest.raises(ValueError, match="conflicts"):
        replay_ledger(session, conflicting, apply=True)
