"""Billing erasure fences exercised through the restricted PostgreSQL login."""
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import psycopg
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from test_app_database import database, initialized, raw, RUNTIME_PASSWORD, MIGRATION_PASSWORD  # noqa: F401
from app import db as dbmod
from app.models import Subscription, Tenant, User
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
    assert files[-1].name == "0004_billing_erasure_fence.sql"
    with monkeypatch.context() as old_release:
        old_release.setattr(migration, "migration_files", lambda: files[:-1])
        migration.migrate(operator)
    # Construct pre-upgrade state without invoking the newer image's startup
    # gate. The ordinary startup correctly refuses this older migration ledger.
    old_engine = create_engine(runtime.update_query_dict({"options": "-csearch_path=mk_app,pg_catalog"}), hide_parameters=True)
    with Session(old_engine, expire_on_commit=False) as session:
        user, _other, subscription = seed(session)
        erase_account(session, user); session.commit()
        subscription_id = subscription.id
    old_engine.dispose()
    with pytest.raises(RuntimeError, match="migration ledger"):
        dbmod.init_engine(runtime)
    assert migration.migrate(operator) == [file.name for file in files]
    dbmod.init_engine(runtime)
    with psycopg.connect(raw(runtime)) as connection:
        with pytest.raises(psycopg.errors.CheckViolation, match="PRIVACY_BILLING_FROZEN"):
            connection.execute("UPDATE mk_app.subscriptions SET status='active' WHERE id=%s", (subscription_id,))
