"""Billing erasure fences exercised through the restricted PostgreSQL login."""
import uuid
import json
import os
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Thread

import psycopg
import pytest
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import Session

from test_app_database import database, initialized, raw, RUNTIME_PASSWORD, MIGRATION_PASSWORD  # noqa: F401
from app import db as dbmod
from app.models import Base, BillingErasureBinding, BillingProvision, ErasureTask, Subscription, Tenant, User
from app.privacy import erase_account


def seed(session):
    tenant = Tenant(name="Synthetic billing privacy fixture"); session.add(tenant); session.flush()
    user = User(tenant_id=tenant.id, email=uuid.uuid4().hex + "@example.test", password_hash="synthetic")
    other = User(tenant_id=tenant.id, email=uuid.uuid4().hex + "@example.test", password_hash="synthetic")
    session.add_all([user, other]); session.flush()
    subscription = Subscription(tenant_id=tenant.id, user_id=user.id, status="active",
        stripe_customer_id="cus_PrivacyControl", stripe_subscription_id="sub_PrivacyControl")
    session.add(subscription); session.commit()
    return user, other, subscription


def test_late_runtime_sql_cannot_revive_or_rebind_erased_billing(initialized):
    runtime = initialized[2]
    engine = dbmod.init_engine(runtime)
    with Session(engine, expire_on_commit=False) as session:
        user, other, subscription = seed(session)
        erase_account(session, user); session.commit()
        subscription_id, user_id, tenant_id = subscription.id, user.id, user.tenant_id
    mutations = [
        ("UPDATE mk_app.subscriptions SET status='active' WHERE id=%s", (subscription_id,)),
        ("UPDATE mk_app.subscriptions SET stripe_customer_id='cus_Crossed' WHERE id=%s", (subscription_id,)),
        ("UPDATE mk_app.subscriptions SET stripe_subscription_id='sub_Crossed' WHERE id=%s", (subscription_id,)),
        ("UPDATE mk_app.subscriptions SET tier='revived' WHERE id=%s", (subscription_id,)),
        ("UPDATE mk_app.subscriptions SET user_id=%s WHERE id=%s", (other.id, subscription_id)),
        ("""INSERT INTO mk_app.subscriptions(id,tenant_id,user_id,stripe_customer_id,tier,interval,status,created_at,updated_at)
            VALUES (%s,%s,%s,'cus_Recreated','','','active',now(),now())""", (uuid.uuid4().hex, tenant_id, user_id)),
    ]
    for statement, parameters in mutations:
        with psycopg.connect(raw(runtime)) as connection:
            with pytest.raises(psycopg.errors.CheckViolation, match="PRIVACY_BILLING_FROZEN"):
                connection.execute(statement, parameters)
    with psycopg.connect(raw(runtime)) as connection:
        assert connection.execute("SELECT status,stripe_customer_id FROM mk_app.subscriptions WHERE id=%s", (subscription_id,)).fetchone() == (
            "deletion_pending", "cus_PrivacyControl")


def test_erased_billing_only_allows_terminal_cleanup_not_new_business_fields(initialized):
    runtime = initialized[2]
    engine = dbmod.init_engine(runtime)
    with Session(engine, expire_on_commit=False) as session:
        user, _other, subscription = seed(session)
        request = erase_account(session, user); session.commit()
        request_id, subscription_id = request.id, subscription.id
    with psycopg.connect(raw(runtime)) as connection:
        connection.execute("UPDATE mk_app.subscriptions SET status='canceled',stripe_customer_id=NULL,stripe_subscription_id=NULL WHERE id=%s", (subscription_id,))
        # A terminal mirror update is never a provider-erasure receipt.
        assert connection.execute("SELECT count(*) FROM mk_app.erasure_tasks WHERE request_id=%s AND confirmed_at IS NULL", (request_id,)).fetchone()[0] >= 2
    with psycopg.connect(raw(runtime)) as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        with pytest.raises(psycopg.errors.CheckViolation, match="PRIVACY_WRITE_REQUIRES_READ_COMMITTED"):
            connection.execute("UPDATE mk_app.subscriptions SET status='canceled' WHERE id=%s", (subscription_id,))


def test_waiting_billing_writer_sees_committed_erasure_fence(initialized):
    runtime = initialized[2]
    engine = dbmod.init_engine(runtime)
    started = Event()
    with Session(engine, expire_on_commit=False) as session:
        user, _other, subscription = seed(session)
        subscription_id = subscription.id
        erase_account(session, user)  # hold the erasure transaction open

        def late_writer():
            with psycopg.connect(raw(runtime)) as connection:
                connection.execute("SET lock_timeout='5s'")
                started.set()
                try:
                    connection.execute("UPDATE mk_app.subscriptions SET status='active' WHERE id=%s", (subscription_id,))
                except psycopg.errors.CheckViolation as exc:
                    return "PRIVACY_BILLING_FROZEN" in str(exc)
            return False

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(late_writer)
            assert started.wait(timeout=5)
            session.commit()
            assert future.result(timeout=8)
    with psycopg.connect(raw(runtime)) as connection:
        assert connection.execute("SELECT status FROM mk_app.subscriptions WHERE id=%s", (subscription_id,)).fetchone()[0] == "deletion_pending"


def test_additive_upgrade_protects_existing_erasure_without_rewriting_old_migrations(database, monkeypatch):
    from app import migrate as migration
    from app.database_policy import migration_files

    migration.bootstrap(database, RUNTIME_PASSWORD, MIGRATION_PASSWORD)
    operator = database.set(username="mk_app_migrator", password=MIGRATION_PASSWORD)
    runtime = database.set(username="mk_app_login", password=RUNTIME_PASSWORD)
    files = migration_files()
    assert files[3].name == "0004_billing_erasure_fence.sql"
    # Model the historical 0003 schema explicitly. Do not create new tables in
    # the old database or disable validation to make an upgrade appear valid.
    historical = MetaData()
    for name, table in Base.metadata.tables.items():
        if name not in {"billing_provisions", "billing_erasure_bindings"}:
            table.to_metadata(historical)
    from app import database_policy
    with monkeypatch.context() as old_release:
        old_release.setattr(migration, "migration_files", lambda: files[:3])
        old_release.setattr(migration, "Base", SimpleNamespace(metadata=historical))
        old_release.setattr(database_policy, "Base", SimpleNamespace(metadata=historical))
        migration.migrate(operator)
    # Construct pre-upgrade state without invoking the newer image's startup
    # gate. The ordinary startup correctly refuses this older migration ledger.
    old_engine = create_engine(runtime.update_query_dict({"options": "-csearch_path=mk_app,pg_catalog"}), hide_parameters=True)
    with Session(old_engine, expire_on_commit=False) as session:
        user, _other, subscription = seed(session)
        from app.privacy import _request
        # Historical account tombstone fixture; current erase_account correctly
        # requires the new provisioning table and must not run on the old image.
        _request(session, user.tenant_id, user.id, "account", user.id)
        user.is_active = False
        user.email = f"deleted_{user.id}@deleted"
        user.display_name = user.password_hash = ""
        user.referral_code = user.referred_by = None
        subscription.status = "deletion_pending"
        session.commit()
        subscription_id = subscription.id
    old_engine.dispose()
    with pytest.raises(RuntimeError, match="schema is incomplete|migration ledger"):
        dbmod.init_engine(runtime)
    assert migration.migrate(operator) == [file.name for file in files]
    dbmod.init_engine(runtime)
    with psycopg.connect(raw(runtime)) as connection:
        with pytest.raises(psycopg.errors.CheckViolation, match="PRIVACY_BILLING_FROZEN"):
            connection.execute("UPDATE mk_app.subscriptions SET status='active' WHERE id=%s", (subscription_id,))


def test_provision_identity_and_bound_customer_are_immutable_after_erasure(initialized):
    runtime = initialized[2]
    engine = dbmod.init_engine(runtime)
    with Session(engine, expire_on_commit=False) as session:
        user, other, _subscription = seed(session)
        row = BillingProvision(tenant_id=user.tenant_id, user_id=user.id)
        session.add(row); session.commit()
        request = erase_account(session, user); session.commit()
        assert session.query(ErasureTask).filter_by(request_id=request.id,
            kind="billing_provision", target_id=row.id).count() == 1
        identity, tid, uid, other_id = row.id, row.tenant_id, row.user_id, other.id
    with psycopg.connect(raw(runtime)) as connection:
        connection.execute("UPDATE mk_app.billing_provisions SET stripe_customer_id='cus_BoundOnce' WHERE id=%s", (identity,))
    mutations = [
        ("DELETE FROM mk_app.billing_provisions WHERE id=%s", (identity,)),
        ("UPDATE mk_app.billing_provisions SET user_id=%s WHERE id=%s", (other_id, identity)),
        ("UPDATE mk_app.billing_provisions SET id=%s WHERE id=%s", (uuid.uuid4().hex, identity)),
        ("UPDATE mk_app.billing_provisions SET created_at=now() WHERE id=%s", (identity,)),
        ("UPDATE mk_app.billing_provisions SET stripe_customer_id=NULL WHERE id=%s", (identity,)),
        ("UPDATE mk_app.billing_provisions SET stripe_customer_id='cus_Other' WHERE id=%s", (identity,)),
    ]
    for statement, parameters in mutations:
        with psycopg.connect(raw(runtime)) as connection:
            with pytest.raises(psycopg.errors.CheckViolation, match="BILLING_PROVISION_IMMUTABLE"):
                connection.execute(statement, parameters)
    with psycopg.connect(raw(runtime)) as connection:
        with pytest.raises(psycopg.errors.CheckViolation, match="PRIVACY_BILLING_FROZEN"):
            connection.execute("INSERT INTO mk_app.billing_provisions(id,tenant_id,user_id,created_at) VALUES (%s,%s,%s,now())",
                (uuid.uuid4().hex, tid, uid))


def test_provision_insert_waits_for_erasure_and_refuses_commit(initialized):
    runtime = initialized[2]
    engine = dbmod.init_engine(runtime)
    started = Event()
    with Session(engine, expire_on_commit=False) as session:
        user, other, _subscription = seed(session)
        tid, uid = user.tenant_id, user.id
        erase_account(session, user)
        def insert():
            with psycopg.connect(raw(runtime)) as connection:
                connection.execute("SET lock_timeout='5s'"); started.set()
                try:
                    connection.execute("INSERT INTO mk_app.billing_provisions(id,tenant_id,user_id,created_at) VALUES (%s,%s,%s,now())",
                        (uuid.uuid4().hex, tid, uid))
                except psycopg.errors.CheckViolation as exc:
                    return "PRIVACY_BILLING_FROZEN" in str(exc)
            return False
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(insert)
            assert started.wait(timeout=5)
            session.commit()
            assert future.result(timeout=8)


def test_process_killed_after_provider_delete_recovers_without_second_delete(initialized):
    """Real HTTP + PostgreSQL + SIGKILL, at the acceptance/receipt boundary."""
    from app.billing import provision_metadata
    runtime = initialized[2]
    engine = dbmod.init_engine(runtime)
    with Session(engine, expire_on_commit=False) as session:
        user, other, _subscription = seed(session)
        row = BillingProvision(tenant_id=user.tenant_id, user_id=user.id)
        session.add(row); session.commit()
        row.stripe_customer_id = "cus_ProcessFixture"; session.commit()
        request = erase_account(session, user); session.commit()
        task_id = session.query(ErasureTask.id).filter_by(request_id=request.id, kind="billing_provision").scalar()
        metadata = provision_metadata(row.id, row.tenant_id, row.user_id)
    accepted, release = Event(), Event()
    state = {"deleted": False, "deletes": 0, "reads": 0, "creates": 0}
    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def do_GET(self):
            assert self.path == "/v1/customers/cus_ProcessFixture"
            assert self.headers["Authorization"] == "Bearer synthetic-local-fixture-only"
            state["reads"] += 1
            self.reply()
        def do_DELETE(self):
            assert self.path == "/v1/customers/cus_ProcessFixture"
            state["deletes"] += 1; state["deleted"] = True; accepted.set()
            release.wait(20)
            self.reply()
        def do_POST(self):
            state["creates"] += 1
            self.send_error(500)
        def reply(self):
            body = {"id": "cus_ProcessFixture", "object": "customer"}
            body.update({"deleted": True} if state["deleted"] else {"metadata": metadata})
            data = json.dumps(body).encode()
            try:
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    command = [sys.executable, str(Path(__file__).with_name("billing_erasure_process.py")),
        f"http://127.0.0.1:{server.server_port}/v1", task_id]
    env = {**os.environ, "MK_BILLING_FIXTURE_DB": runtime.render_as_string(hide_password=False)}
    child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        assert accepted.wait(15), "provider delete was not reached"
        child.kill(); child.communicate(timeout=5)
        assert child.returncode != 0
        with psycopg.connect(raw(runtime)) as connection:
            status, confirmed, lease = connection.execute("SELECT status,confirmed_at,lease_id FROM mk_app.erasure_tasks WHERE id=%s", (task_id,)).fetchone()
            assert status == "pending" and confirmed is None and lease is not None
            # Only this disposable task's lease is advanced to avoid a 2m test wait.
            connection.execute("UPDATE mk_app.erasure_tasks SET next_attempt_at=now()-interval '1 second' WHERE id=%s", (task_id,))
        release.set()
        retry = subprocess.run(command, env=env, capture_output=True, text=True, encoding="utf-8", timeout=20)
        assert retry.returncode == 0, retry.stderr
        assert retry.stdout.strip() == "confirmed"
        with psycopg.connect(raw(runtime)) as connection:
            assert connection.execute("SELECT status,attempts FROM mk_app.erasure_tasks WHERE id=%s", (task_id,)).fetchone() == ("confirmed", 2)
        assert state == {"deleted": True, "deletes": 1, "reads": 2, "creates": 0}
    finally:
        release.set()
        if child.poll() is None: child.kill(); child.communicate(timeout=5)
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def test_restored_cleanup_binding_is_bound_to_tombstone_and_immutable(initialized):
    from app.models import ErasureRequest
    runtime = initialized[2]
    engine = dbmod.init_engine(runtime)
    with Session(engine, expire_on_commit=False) as session:
        user, other, sub = seed(session)
        row = BillingProvision(tenant_id=user.tenant_id, user_id=user.id)
        session.add(row); session.commit()
        request = erase_account(session, user); session.commit()
        restored = BillingErasureBinding(id=row.id, request_id=request.id, tenant_id=row.tenant_id,
            user_id=row.user_id, created_at=row.created_at, stripe_customer_id="cus_RestoredBinding")
        session.add(restored); session.commit()
        identity, other_id = row.id, other.id
        from app.tools.privacy_ledger import export_ledger, load_ledger, replay_ledger
        import hashlib
        from datetime import datetime, timezone
        before = datetime.now(timezone.utc)
        raw_ledger = export_ledger(session)
        rows = load_ledger(raw_ledger, hashlib.sha256(raw_ledger).hexdigest(), before)
        replay_ledger(session, rows, apply=True); session.commit()
        assert session.query(BillingErasureBinding).count() == 1
    for statement, parameters in [
        ("UPDATE mk_app.billing_erasure_bindings SET user_id=%s WHERE id=%s", (other_id, identity)),
        ("UPDATE mk_app.billing_erasure_bindings SET stripe_customer_id=NULL WHERE id=%s", (identity,)),
        ("UPDATE mk_app.billing_erasure_bindings SET stripe_customer_id='cus_Crossed' WHERE id=%s", (identity,)),
        ("UPDATE mk_app.billing_erasure_bindings SET created_at=now() WHERE id=%s", (identity,)),
        ("DELETE FROM mk_app.billing_erasure_bindings WHERE id=%s", (identity,)),
    ]:
        with psycopg.connect(raw(runtime)) as connection:
            with pytest.raises(psycopg.errors.CheckViolation, match="BILLING_RESTORE_BINDING_IMMUTABLE"):
                connection.execute(statement, parameters)
    with psycopg.connect(raw(runtime)) as connection:
        with pytest.raises(psycopg.errors.CheckViolation, match="BILLING_RESTORE_REQUEST_MISMATCH"):
            connection.execute("INSERT INTO mk_app.billing_erasure_bindings(id,request_id,tenant_id,user_id,created_at) VALUES (%s,%s,%s,%s,now())",
                (uuid.uuid4().hex, request.id, row.tenant_id, other_id))
