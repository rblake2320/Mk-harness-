"""External cleanup identity must survive restoring a pre-acceptance backup."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3

import httpx
import pytest
import respx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.billing_erasure import BillingErasureClient, deliver_billing_erasure, resolve_binding
from app.models import Base, BillingErasureBinding, BillingProvision, ErasureRequest, ErasureTask, Tenant, User
from app.privacy import erase_account
from app.tools.privacy_ledger import export_ledger, load_ledger, replay_ledger


@pytest.mark.parametrize("backup_stage", ["empty", "before_intent", "before_acceptance"])
@respx.mock
def test_post_backup_billing_identity_survives_pinned_erasure_replay(tmp_path, backup_stage):
    source_path, restored_path = tmp_path / "source.db", tmp_path / "restored.db"
    source = create_engine(f"sqlite:///{source_path}")
    Base.metadata.create_all(source)
    def backup():
        with sqlite3.connect(source_path) as before, sqlite3.connect(restored_path) as snapshot:
            before.backup(snapshot)
    if backup_stage == "empty": backup()
    with Session(source, expire_on_commit=False) as db:
        tenant = Tenant(name="Synthetic restore billing"); db.add(tenant); db.flush()
        user = User(tenant_id=tenant.id, email="synthetic-restore@example.test", password_hash="synthetic")
        db.add(user); db.commit()
        intent = None
        if backup_stage == "before_acceptance":
            intent = BillingProvision(tenant_id=tenant.id, user_id=user.id)
            db.add(intent); db.commit()
        if backup_stage != "empty": backup()
        if intent is None:
            intent = BillingProvision(tenant_id=tenant.id, user_id=user.id)
            db.add(intent); db.commit()
        intent.stripe_customer_id = "cus_AcceptedAfterBackup"; db.commit()
        request = erase_account(db, user); db.commit()
        before_export = datetime.now(timezone.utc)
        ledger = export_ledger(db)
        request_id, intent_id = request.id, intent.id
    source.dispose()
    restored = create_engine(f"sqlite:///{restored_path}")
    with Session(restored) as db:
        records = load_ledger(ledger, hashlib.sha256(ledger).hexdigest(), before_export)
        assert replay_ledger(db, records)["applied"] is False
        assert db.scalar(select(BillingErasureBinding.id)) is None
        replay_ledger(db, records, apply=True); db.commit()
        # A local erase alone loses the external obligation. The exact immutable
        # identity and known provider binding must come from the retained ledger.
        row = resolve_binding(db, db.get(ErasureRequest, request_id))
        assert row is not None, "post-backup billing intent was lost"
        assert row.stripe_customer_id == "cus_AcceptedAfterBackup", "accepted provider binding was lost"
        assert db.scalar(select(ErasureTask.id).where(ErasureTask.request_id == request_id,
            ErasureTask.kind == "billing_provision", ErasureTask.target_id == intent_id))
        if backup_stage != "before_acceptance":
            assert db.get(BillingProvision, intent_id) is None  # never recreate a business intent
        if backup_stage == "empty":
            assert db.scalar(select(User.id)) is None and db.scalar(select(Tenant.id)) is None
        replay_ledger(db, records, apply=True); db.commit()
        task = db.scalar(select(ErasureTask).where(ErasureTask.request_id == request_id,
            ErasureTask.kind == "billing_provision"))
        get = respx.get("https://api.stripe.com/v1/customers/cus_AcceptedAfterBackup").mock(
            return_value=httpx.Response(200, json={"object": "customer", "id": "cus_AcceptedAfterBackup", "deleted": True}))
        assert asyncio.run(deliver_billing_erasure(db, BillingErasureClient(), task.id))
        assert get.call_count == 1 and len(respx.calls) == 1
        fresh = datetime.now(timezone.utc)
        again = export_ledger(db)
        assert load_ledger(again, hashlib.sha256(again).hexdigest(), fresh)[0]["billing_provisions"][0]["stripe_customer_id"] == "cus_AcceptedAfterBackup"
    restored.dispose()


@pytest.mark.parametrize("fault", ["v1", "cross_tenant", "cross_user", "late_created", "bad_customer", "extra_field", "duplicate_intent", "duplicate_customer"])
def test_ledger_rejects_missing_or_crossed_external_identity(fault):
    now = datetime.now(timezone.utc)
    row = {"id": "1" * 32, "tenant_id": "2" * 32, "requested_by": "3" * 32,
        "subject_kind": "account", "subject_id": "3" * 32,
        "requested_at": now.isoformat(), "due_at": (now + timedelta(days=30)).isoformat(),
        "backup_expires_at": (now + timedelta(days=35)).isoformat(),
        "billing_provisions": [{"id": "4" * 32, "tenant_id": "2" * 32, "user_id": "3" * 32,
            "created_at": (now - timedelta(minutes=1)).isoformat(), "stripe_customer_id": "cus_RestoreFixture"}]}
    data = {"format": "mk-erasure-ledger-v2", "exported_at": now.isoformat(), "requests": [row]}
    binding = row["billing_provisions"][0]
    if fault == "v1": data["format"] = "mk-erasure-ledger-v1"; row.pop("billing_provisions")
    if fault == "cross_tenant": binding["tenant_id"] = "5" * 32
    if fault == "cross_user": binding["user_id"] = "5" * 32
    if fault == "late_created": binding["created_at"] = (now + timedelta(minutes=1)).isoformat()
    if fault == "bad_customer": binding["stripe_customer_id"] = "cus_x/../../another"
    if fault == "extra_field": binding["email"] = "private@example.test"
    if fault.startswith("duplicate_"):
        other = json.loads(json.dumps(row)); other.update(id="6" * 32, requested_by="7" * 32, subject_id="7" * 32)
        other["billing_provisions"][0]["user_id"] = "7" * 32
        if fault == "duplicate_intent": other["billing_provisions"][0]["stripe_customer_id"] = "cus_Another"
        else: other["billing_provisions"][0]["id"] = "8" * 32
        data["requests"].append(other)
    encoded = json.dumps(data).encode()
    with pytest.raises(ValueError):
        load_ledger(encoded, hashlib.sha256(encoded).hexdigest(), now - timedelta(seconds=1))
