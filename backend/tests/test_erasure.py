"""S13 — subject erasure, the external erasure ledger, restore replay, retention.

Adversarial focus: content must be gone from EVERY table the data map lists, the
suppression must keep blocking after erasure, another tenant/book cannot erase,
the ledger detects tampering and torn writes, concurrent writers keep one chain,
a restored database is re-erased by replay, and the published retention policy is
generated from the rules the purge job enforces.
"""
import json
import multiprocessing
import os
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from sqlalchemy import select

from app import db as dbmod
from app import erasure
from app.foundation import active_suppressions, fingerprint, normalize, seal
from app.models import (
    ActionLink, AuditLog, BriefItem, Commitment, ConsentEvent, ContactPreference, Customer, CustomerDestination,
    DraftVersion, ErasureRequest, ExceptionRecord, ImportJob, ImportRow, Message, Conversation, Outcome,
    SkinAnalysis, SuppressionEvent, User,
)

from .conftest import auth_headers, signup
from .test_agent_ops import KERNEL
from .test_foundation import kernel_env  # noqa: F401 — fixture

PHONE, PHONE2 = "+15555550142", "+15555550143"


def _db():
    return dbmod._SessionLocal()


def _owner(client, tag=None):
    tag = tag or uuid.uuid4().hex[:8]
    t = signup(client, org=f"Org {tag}", email=f"e-{tag}@example.com")
    return t, auth_headers(t)


def _rich_customer(client, h):
    """A customer with content in every table the data map lists."""
    cid = client.post("/api/customers", json={"name": "Brenda Q. Private", "phone": PHONE, "email": "b@private.example",
                                              "notes": "allergic to lanolin"}, headers=h).json()["id"]
    d1 = client.post(f"/api/customers/{cid}/destinations", json={"channel": "sms", "value": PHONE}, headers=h).json()
    d2 = client.post(f"/api/customers/{cid}/destinations", json={"channel": "sms", "value": PHONE2}, headers=h).json()
    db = _db()
    c = db.get(Customer, cid)
    tid, uid = c.tenant_id, c.user_id
    db.add(SuppressionEvent(tenant_id=tid, customer_id=cid, channel="sms", fingerprint=d1["fingerprint"],
                            reason="STOP", source="sms_reply"))
    db.add(ConsentEvent(tenant_id=tid, customer_id=cid, destination_id=d2["id"], channel="sms", purposes_json='["x"]',
                        source="web_form", evidence_type="form_submission", evidence_ref="form #77 Brenda signature",
                        evidence_digest="sha256:" + "1" * 64, effective_at=datetime.now(timezone.utc),
                        expires_at=datetime.now(timezone.utc) + timedelta(days=300), created_by=uid))
    db.add(ContactPreference(tenant_id=tid, customer_id=cid, timezone="America/Chicago"))
    k = Commitment(tenant_id=tid, customer_id=cid, owner_user_id=uid, source_type="consultant_note",
                   commitment_text="Send Brenda the lanolin-free list", status="confirmed", created_by=uid)
    db.add(k)
    db.flush()
    db.add(BriefItem(tenant_id=tid, user_id=uid, customer_id=cid, brief_date="2026-11-12", rule="commitment_due",
                     rank_category=1, source_type="commitment", source_reference=k.id, dedupe_key=f"x-{cid}",
                     suggested_step="Text Brenda"))
    db.add(DraftVersion(tenant_id=tid, customer_id=cid, text_enc=seal(tid, "draft", "Hi Brenda!"),
                        text_digest="sha256:" + "2" * 64, generated_by=uid))
    db.add(ExceptionRecord(tenant_id=tid, customer_id=cid, kind="product_concern", detail_enc=seal(tid, "x", "rash")))
    db.add(Outcome(tenant_id=tid, customer_id=cid, kind="resolved", recorded_by=uid, note_enc=seal(tid, "x", "ordered")))
    db.add(SkinAnalysis(tenant_id=tid, user_id=uid, customer_id=cid, provider="p", model="m", result_json="{}"))
    job = ImportJob(tenant_id=tid, user_id=uid, idempotency_key=uuid.uuid4().hex, source_digest="sha256:" + "3" * 64,
                    mapping_json="{}")
    db.add(job)
    db.flush()
    db.add(ImportRow(tenant_id=tid, job_id=job.id, row_index=0, status="create", name="Brenda Q. Private",
                     phone_enc="x", email_enc="y", notes="n", customer_id=cid))
    db.add(ActionLink(tenant_id=tid, customer_id=cid, kernel_action_id=str(uuid.uuid4()), action_digest="sha256:" + "4" * 64))
    db.commit()
    db.close()
    return cid, d1["fingerprint"], d2["fingerprint"], tid


def test_erasure_empties_every_content_table_and_keeps_only_minimal_records(client):
    t, h = _owner(client)
    cid, fp_suppressed, fp_plain, tid = _rich_customer(client, h)
    before = len(erasure.ledger_entries())
    r = client.delete(f"/api/customers/{cid}", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["kernel_acknowledged"] is False          # no kernel configured: queued, not claimed
    db = _db()
    c = db.get(Customer, cid)
    assert (c.name, c.phone, c.email, c.notes, c.skin_profile_json) == ("Erased customer", "", "", "", "")
    assert c.erased_at is not None
    dests = db.scalars(select(CustomerDestination).where(CustomerDestination.customer_id == cid)).all()
    assert all(d.value_enc == "" and d.retired_at is not None for d in dests)
    fps = {d.fingerprint for d in dests}
    assert fp_suppressed in fps and fp_plain not in fps     # suppression keeps its key; the other is tombstoned
    assert all(f == fp_suppressed or f.startswith("erased:") for f in fps)
    assert db.scalars(select(ConsentEvent.evidence_ref).where(ConsentEvent.customer_id == cid)).all() == [""]
    assert db.scalars(select(ConsentEvent.evidence_digest).where(ConsentEvent.customer_id == cid)).all() == ["sha256:" + "1" * 64]
    assert db.scalar(select(ContactPreference).where(ContactPreference.customer_id == cid)) is None
    assert db.scalar(select(BriefItem).where(BriefItem.customer_id == cid)) is None
    assert db.scalar(select(SkinAnalysis).where(SkinAnalysis.customer_id == cid)) is None
    k = db.scalar(select(Commitment).where(Commitment.customer_id == cid))
    assert (k.commitment_text, k.status) == ("", "cancelled")
    assert db.scalars(select(DraftVersion.text_enc).where(DraftVersion.customer_id == cid)).all() == [""]
    assert db.scalars(select(ExceptionRecord.detail_enc).where(ExceptionRecord.customer_id == cid)).all() == [""]
    assert db.scalars(select(Outcome.note_enc).where(Outcome.customer_id == cid)).all() == [""]
    row = db.scalar(select(ImportRow).where(ImportRow.customer_id == cid))
    assert (row.name, row.phone_enc, row.email_enc, row.notes) == ("", "", "", "")
    assert db.scalar(select(ActionLink).where(ActionLink.customer_id == cid)) is not None   # ids + digests stay
    req = db.scalar(select(ErasureRequest).where(ErasureRequest.subject_id == cid))
    assert req.app_completed_at and req.kernel_acknowledged_at is None
    assert abs((req.due_by - req.requested_at) - timedelta(days=30)) < timedelta(seconds=1)
    assert fp_suppressed in json.loads(req.kernel_fingerprints_json) and fp_plain in json.loads(req.kernel_fingerprints_json)
    # No PII anywhere in the audit trail of this tenant.
    for a in db.scalars(select(AuditLog.detail).where(AuditLog.tenant_id == tid)).all():
        for pii in ("Brenda", "lanolin", "5555550142", "private.example"):
            assert pii not in (a or ""), a
    # Opt-out still blocks: the same number re-added later is still suppressed.
    assert active_suppressions(db, tid, fingerprint(tid, "sms", normalize("sms", PHONE)), "sms")
    db.close()
    # Gone from every read path, and a second erase is a 404 (not a second ledger entry).
    assert client.get(f"/api/customers/{cid}", headers=h).status_code == 404
    assert all(x["id"] != cid for x in client.get("/api/customers", headers=h).json())
    assert client.get("/api/customers/search", params={"q": "Erased"}, headers=h).json() == []
    assert "Erased customer" not in client.get("/api/customers/export.csv", headers=h).text
    assert client.delete(f"/api/customers/{cid}", headers=h).status_code == 404
    entries = erasure.ledger_entries()
    assert len(entries) == before + 1 and entries[-1]["body"]["subject_id"] == cid
    assert "Brenda" not in json.dumps(entries[-1])


def test_erasure_is_tenant_and_book_scoped(client):
    _, h1 = _owner(client)
    _, h2 = _owner(client)
    cid = client.post("/api/customers", json={"name": "Keep Me"}, headers=h1).json()["id"]
    assert client.delete(f"/api/customers/{cid}", headers=h2).status_code == 404
    assert client.get(f"/api/customers/{cid}", headers=h1).json()["name"] == "Keep Me"


def test_erasure_needs_step_up(client, frozen_clock):
    frozen_clock("2026-11-12T10:00:00+00:00")
    _, h = _owner(client)
    cid = client.post("/api/customers", json={"name": "Stale"}, headers=h).json()["id"]
    frozen_clock("2026-11-12T10:30:00+00:00")
    r = client.delete(f"/api/customers/{cid}", headers=h)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "STEP_UP_REQUIRED"


def test_legal_hold_records_request_but_erases_nothing(client):
    _, h = _owner(client)
    cid = client.post("/api/customers", json={"name": "Held Person"}, headers=h).json()["id"]
    db = _db()
    c = db.get(Customer, cid)
    before = len(erasure.ledger_entries())
    req = erasure.erase_customer(db, tenant_id=c.tenant_id, customer_id=cid, requested_by=c.user_id,
                                 legal_hold_reason="litigation hold LH-12")
    db.commit()
    assert req.legal_hold and req.app_completed_at is None
    assert db.get(Customer, cid).name == "Held Person"
    assert len(erasure.ledger_entries()) == before
    db.close()


# ---------------------------------------------------------------- the ledger
def test_ledger_detects_edits_reordering_forged_seals_and_torn_writes(tmp_path, monkeypatch):
    from app.config import get_settings
    monkeypatch.setenv("ERASURE_LEDGER_PATH", str(tmp_path / "l.jsonl"))
    get_settings.cache_clear()
    try:
        for i in range(3):
            erasure.ledger_append({"request": f"r{i}", "tenant_id": "t", "subject_type": "customer", "subject_id": f"c{i}",
                                   "requested_at": "2026-11-12T00:00:00+00:00"})
        p = tmp_path / "l.jsonl"
        good = p.read_text()
        assert len(erasure.ledger_entries()) == 3
        lines = good.splitlines()
        cases = {
            "edit": "\n".join([lines[0], lines[1].replace('"c1"', '"cX"'), lines[2]]),
            "reorder": "\n".join([lines[1], lines[0], lines[2]]),
            "drop": "\n".join([lines[0], lines[2]]),
            "torn": good + '{"seq":4,"prev"',
        }
        e = json.loads(lines[2]); e["body"]["subject_id"] = "cZ"
        d, _ = erasure._seal(e["prev"], {"seq": e["seq"], "body": e["body"]})
        e["digest"] = d   # recomputed digest without the key: the seal must fail
        cases["forged_seal"] = "\n".join([lines[0], lines[1], json.dumps(e)])
        for name, text in cases.items():
            p.write_text(text + "\n")
            with pytest.raises(ValueError):
                erasure.ledger_entries()
        p.write_text(good)
        # Wrong key: an attacker who can write the file cannot re-seal it.
        monkeypatch.setenv("ERASURE_LEDGER_KEY", "a-different-key")
        get_settings.cache_clear()
        with pytest.raises(ValueError, match="seal"):
            erasure.ledger_entries()
    finally:
        get_settings.cache_clear()


def _append_many(path, n, tag):
    os.environ["ERASURE_LEDGER_PATH"] = path
    from app.config import get_settings
    get_settings.cache_clear()
    from app import erasure as er
    for i in range(n):
        er.ledger_append({"request": f"{tag}-{i}", "tenant_id": "t", "subject_type": "customer",
                          "subject_id": f"{tag}-{i}", "requested_at": "2026-11-12T00:00:00+00:00"})


def test_concurrent_writers_keep_one_verifiable_chain(tmp_path, monkeypatch):
    path = str(tmp_path / "c.jsonl")
    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=_append_many, args=(path, 25, f"p{i}")) for i in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    from app.config import get_settings
    monkeypatch.setenv("ERASURE_LEDGER_PATH", path)
    get_settings.cache_clear()
    try:
        entries = erasure.ledger_entries()
        assert len(entries) == 100 and [e["seq"] for e in entries] == list(range(1, 101))
        assert len({e["body"]["request"] for e in entries}) == 100
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------- restore replay
def test_restore_then_replay_reerases_and_requeues_the_kernel(client):
    _, h = _owner(client)
    cid, fp1, _, tid = _rich_customer(client, h)
    db = _db()
    snap = {d.id: (d.value_enc, d.fingerprint) for d in db.scalars(
        select(CustomerDestination).where(CustomerDestination.customer_id == cid))}
    db.close()
    assert client.delete(f"/api/customers/{cid}", headers=h).status_code == 200
    # Simulate restoring a backup taken before the erasure: content back, request row gone.
    db = _db()
    c = db.get(Customer, cid)
    c.name, c.notes, c.erased_at = "Brenda Q. Private", "allergic to lanolin", None
    for d in db.scalars(select(CustomerDestination).where(CustomerDestination.customer_id == cid)):
        d.value_enc, d.fingerprint = snap[d.id]
        d.retired_at = None
    db.query(ErasureRequest).filter(ErasureRequest.subject_id == cid).delete()
    db.commit()
    assert client.get(f"/api/customers/{cid}", headers=h).status_code == 200    # the restore "worked"
    out = erasure.replay(db)
    assert out["reapplied"] >= 1 and out["recreated_requests"] >= 1
    db.expire_all()
    c = db.get(Customer, cid)
    assert c.name == "Erased customer" and c.erased_at is not None
    assert all(d.value_enc == "" for d in db.scalars(select(CustomerDestination).where(CustomerDestination.customer_id == cid)))
    req = db.scalar(select(ErasureRequest).where(ErasureRequest.subject_id == cid))
    assert req.kernel_acknowledged_at is None and fp1 in json.loads(req.kernel_fingerprints_json)
    # Replay twice is a no-op on content.
    erasure.replay(db)
    assert db.get(Customer, cid).name == "Erased customer"
    db.close()
    assert client.get(f"/api/customers/{cid}", headers=h).status_code == 404


def test_replay_refuses_a_broken_ledger(tmp_path, monkeypatch):
    from app.config import get_settings
    from app.tools import erasure as tool
    p = tmp_path / "b.jsonl"
    p.write_text('{"seq":1}\n')
    monkeypatch.setenv("ERASURE_LEDGER_PATH", str(p))
    get_settings.cache_clear()
    try:
        assert tool.main(["verify"]) == 1
        assert tool.main(["replay"]) == 1
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------- kernel delivery
def test_kernel_delivery_acknowledges_retries_and_reports_overdue(client, kernel_env, frozen_clock):  # noqa: F811
    frozen_clock("2026-11-12T09:00:00+00:00")
    _, h = _owner(client)
    cid, fp1, fp2, tid = _rich_customer(client, h)
    with respx.mock() as m:
        route = m.post(f"{KERNEL}/internal/v1/erasures").mock(return_value=httpx.Response(503, json={"x": 1}))
        r = client.delete(f"/api/customers/{cid}", headers=h)
        assert r.status_code == 200 and r.json()["kernel_acknowledged"] is False
        body = json.loads(route.calls[0].request.content)
        assert set(body["destination_hashes"]) == {fp1, fp2} and len(body["action_ids"]) == 1
        assert "Brenda" not in route.calls[0].request.content.decode()
    db = _db()
    req = db.scalar(select(ErasureRequest).where(ErasureRequest.subject_id == cid))
    assert req.kernel_attempts == 1 and req.kernel_last_error == "HTTP 503"
    db.close()
    frozen_clock("2026-12-13T09:00:00+00:00")       # 31 days later, still unacknowledged
    with respx.mock() as m:
        m.get(f"{KERNEL}/health/ready").mock(return_value=httpx.Response(200, json={}))
        assert int(client.get("/api/health/ready").json()["checks"]["erasures_overdue"]) >= 1
    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/erasures").mock(return_value=httpx.Response(200, json={"actions_erased": 1}))
        db = _db()
        assert erasure.deliver_to_kernel(db, tenant_id=tid) == 1
        db.close()
    db = _db()
    req = db.scalar(select(ErasureRequest).where(ErasureRequest.subject_id == cid))
    assert req.kernel_acknowledged_at is not None and json.loads(req.kernel_result_json) == {"actions_erased": 1}
    db.close()


# ---------------------------------------------------------------- account deletion
def test_account_deletion_erases_book_credentials_and_sessions(client):
    t, h = _owner(client)
    cid, *_ = _rich_customer(client, h)
    r = client.request("DELETE", "/api/account", json={"password": "wrong-password-1"}, headers=h)
    assert r.status_code == 403
    r = client.request("DELETE", "/api/account", json={"password": "superSecret123!"}, headers=h)
    assert r.status_code == 200 and r.json()["customers_erased"] == 1
    assert client.get("/api/auth/me", headers=h).status_code == 401
    db = _db()
    assert db.get(Customer, cid).erased_at is not None
    db.close()


def test_last_owner_cannot_delete_account_while_members_remain(client):
    t, h = _owner(client)
    tag = uuid.uuid4().hex[:6]
    assert client.post("/api/auth/members", json={"email": f"m-{tag}@example.com", "password": "superSecret123!",
                                                  "role": "consultant"}, headers=h).status_code == 201
    r = client.request("DELETE", "/api/account", json={"password": "superSecret123!"}, headers=h)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "LAST_OWNER"


# ---------------------------------------------------------------- retention
def test_retention_purges_only_what_is_past_its_period_and_is_idempotent(client, frozen_clock):
    from app.retention import RULES, run
    _, h = _owner(client)
    cid = client.post("/api/customers", json={"name": "R"}, headers=h).json()["id"]
    db = _db()
    c = db.get(Customer, cid)
    old = datetime(2025, 1, 1, tzinfo=timezone.utc)
    new = datetime(2026, 11, 1, tzinfo=timezone.utc)
    conv_old = Conversation(tenant_id=c.tenant_id, user_id=c.user_id, created_at=old)
    conv_new = Conversation(tenant_id=c.tenant_id, user_id=c.user_id, created_at=new)
    db.add_all([conv_old, conv_new]); db.flush()
    db.add_all([Message(conversation_id=conv_old.id, role="user", content="old secret", created_at=old),
                Message(conversation_id=conv_new.id, role="user", content="fresh", created_at=new),
                DraftVersion(tenant_id=c.tenant_id, customer_id=cid, text_enc="enc-old", text_digest="sha256:" + "5" * 64,
                             generated_by="u", created_at=old),
                DraftVersion(tenant_id=c.tenant_id, customer_id=cid, text_enc="enc-new", text_digest="sha256:" + "6" * 64,
                             generated_by="u", created_at=new),
                ExceptionRecord(tenant_id=c.tenant_id, customer_id=cid, kind="complaint", detail_enc="open-old",
                                state="open", created_at=old),
                ExceptionRecord(tenant_id=c.tenant_id, customer_id=cid, kind="complaint", detail_enc="closed-old",
                                state="resolved", resolved_at=old, created_at=old)])
    db.commit()
    ids = (conv_old.id, conv_new.id)
    frozen_clock("2026-11-12T00:00:00+00:00")
    counts = run(db)
    assert set(counts) == {r.key for r in RULES}
    db.expire_all()
    assert db.get(Conversation, ids[0]) is None and db.get(Conversation, ids[1]) is not None
    assert db.scalars(select(Message.content).where(Message.conversation_id == ids[1])).all() == ["fresh"]
    texts = set(db.scalars(select(DraftVersion.text_enc).where(DraftVersion.customer_id == cid)).all())
    assert texts == {"", "enc-new"}
    details = set(db.scalars(select(ExceptionRecord.detail_enc).where(ExceptionRecord.customer_id == cid)).all())
    assert details == {"open-old", ""}          # open issues are never purged out from under a person
    again = run(db)
    assert again["assistant_conversations"] == 0 and again["message_drafts"] == 0
    db.close()


def test_privacy_policy_is_generated_from_enforced_rules(client):
    from app.retention import RULES, STANDING
    html = client.get("/privacy").text
    for r in RULES:
        assert r.policy in html
    for t in STANDING:
        assert t in html
    assert "{RETENTION_LIST}" not in html and "auto-purged" not in html


def test_migrate_adds_nullable_columns_and_refuses_non_additive(tmp_path):
    from sqlalchemy import create_engine, inspect, text
    from app.models import Base
    from app.tools.migrate import add_missing_columns
    eng = create_engine(f"sqlite:///{tmp_path}/m.db")
    Base.metadata.create_all(eng)
    with eng.begin() as c:
        c.execute(text("ALTER TABLE customers DROP COLUMN erased_at"))
    assert ("customers", "erased_at") in add_missing_columns(eng)
    assert "erased_at" in {x["name"] for x in inspect(eng).get_columns("customers")}
    assert add_missing_columns(eng) == []
    from sqlalchemy import Column, MetaData, String, Table
    md = MetaData()
    Table("customers", md, Column("id", String(32), primary_key=True), Column("must_have", String(5), nullable=False))
    import app.tools.migrate as mig
    real = mig.Base.metadata
    try:
        mig.Base.metadata = md
        with pytest.raises(SystemExit, match="non-additive"):
            add_missing_columns(eng)
    finally:
        mig.Base.metadata = real
