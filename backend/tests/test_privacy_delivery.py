import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.kernel.client import KernelResponse, KernelUnavailable
from app.models import Base, ErasureRequest, ErasureTask
from app.privacy_delivery import bound_receipt, deliver_kernel_erasure, drain_kernel_erasures


@pytest.fixture
def queue(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'privacy.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        now = datetime.now(timezone.utc)
        request = ErasureRequest(tenant_id=uuid.uuid4().hex, requested_by=uuid.uuid4().hex,
            subject_kind="customer", subject_id=uuid.uuid4().hex, due_at=now+timedelta(days=30),
            backup_expires_at=now+timedelta(days=35))
        db.add(request); db.flush()
        task = ErasureTask(request_id=request.id, tenant_id=request.tenant_id,
                           kind="kernel_contact", target_id=request.subject_id)
        db.add(task); db.flush()
        expected = dict(tenant_id=request.tenant_id, request_id=request.id,
                        subject_id=request.subject_id, subject_kind="contact")
        db.commit()
        yield engine, task.id, expected
    engine.dispose()


def receipt(expected, **updates):
    return {**expected, "active_content_erased": True, "pending_provider_deletions": 0,
            "blocked_actions": 0, "pending_sender_cleanup": 0, **updates}


@pytest.mark.parametrize("updates", [
    {"tenant_id":str(uuid.uuid4())}, {"request_id":str(uuid.uuid4())},
    {"subject_id":str(uuid.uuid4())}, {"subject_kind":"account"},
    {"active_content_erased":1}, {"pending_provider_deletions":False},
    {"blocked_actions":-1}, {"pending_sender_cleanup":"0"},
])
def test_crossed_or_malformed_receipt_refused(queue, updates):
    _, _, expected = queue
    assert bound_receipt(201, receipt(expected, **updates), **expected) is None
    assert bound_receipt(200, receipt(expected), **expected) is None


def test_pending_receipt_retries_and_confirms_only_bound_zero_counts(queue):
    engine, task_id, expected = queue
    class Kernel:
        timeout = 2
        pending = 1
        calls = []
        async def call(self, method, path, **kwargs):
            self.calls.append(kwargs)
            assert method == "POST" and path == "/privacy/erase"
            assert kwargs["roles"] == ["privacy_eraser"]
            assert kwargs["json"]["request_id"] == str(uuid.UUID(expected["request_id"]))
            return KernelResponse(201, receipt(expected, pending_provider_deletions=self.pending,
                untrusted_private_content="must not persist"), "synthetic-request")
    kernel = Kernel()
    with Session(engine) as db:
        assert not asyncio.run(deliver_kernel_erasure(db, kernel, task_id))
        row = db.get(ErasureTask, task_id); db.refresh(row)
        assert row.confirmed_at is None and row.status == "pending"
        assert "untrusted_private_content" not in json.loads(row.receipt_json)
        assert "must not persist" not in row.receipt_json
        row.next_attempt_at = datetime.now(timezone.utc)-timedelta(seconds=1); db.commit()
        kernel.pending = 0
        assert asyncio.run(drain_kernel_erasures(db, kernel)) == 1
        db.refresh(row)
        assert row.confirmed_at and row.status == "confirmed" and row.attempts == 2
        assert asyncio.run(deliver_kernel_erasure(db, kernel, task_id))
        assert len(kernel.calls) == 2


def test_outbox_identity_and_non_kernel_tasks_cannot_expand_authority(queue):
    engine, task_id, _ = queue
    class Kernel:
        timeout = 2
        async def call(self, *args, **kwargs):
            raise AssertionError("unbound task must not leave the application")
    with Session(engine) as db:
        row=db.get(ErasureTask,task_id); row.target_id=uuid.uuid4().hex; db.commit()
        assert not asyncio.run(deliver_kernel_erasure(db,Kernel(),task_id))
        db.refresh(row); assert row.status == "blocked" and row.last_error == "ERASURE_IDENTITY_INVALID"
        row.kind="backup_expiry"; db.commit()
        assert not asyncio.run(deliver_kernel_erasure(db,Kernel(),task_id))
        assert row.confirmed_at is None


def test_concurrent_delivery_lease_and_restart_after_lost_response(queue):
    engine, task_id, expected = queue
    calls = []
    class Kernel:
        timeout = 2
        async def call(self, *args, **kwargs):
            calls.append(kwargs)
            with Session(engine) as competing:
                assert not await deliver_kernel_erasure(competing, self, task_id)
            if len(calls) == 1:
                raise KernelUnavailable("fixture", "response lost after kernel commit")
            return KernelResponse(201,receipt(expected),"synthetic-request")
    with Session(engine) as db:
        assert not asyncio.run(deliver_kernel_erasure(db,Kernel(),task_id))
    with Session(engine) as restarted:
        row=restarted.get(ErasureTask,task_id)
        assert row.last_error == "KERNEL_ERASURE_UNAVAILABLE" and row.confirmed_at is None
        row.next_attempt_at=datetime.now(timezone.utc)-timedelta(seconds=1); restarted.commit()
        assert asyncio.run(deliver_kernel_erasure(restarted,Kernel(),task_id))
        restarted.refresh(row); assert row.attempts == 2
    assert len(calls) == 2
    assert calls[0]["json"] == calls[1]["json"]
    assert calls[0]["session_id"] != calls[1]["session_id"]
