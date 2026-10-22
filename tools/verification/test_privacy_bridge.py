"""Real application runtime PostgreSQL -> signed HTTP -> Rust -> kernel PostgreSQL.

Requires MK_PRIVACY_KERNEL_BINARY and the explicit disposable app cluster fixture.
Each invocation owns a UUID database/login/process; no existing database is reset.
"""
import asyncio
import base64
import os
import socket
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import psycopg
import pytest
from psycopg import sql
from sqlalchemy import select
from sqlalchemy.orm import Session

from test_app_database import database, initialized, raw  # noqa: F401
from app import db
from app.config import get_settings
from app.kernel.assertions import AssertionMinter
from app.kernel.client import KernelClient
from app.models import Customer, ErasureTask, Tenant, User
from app.privacy import erase_customer
from app.privacy_delivery import drain_kernel_erasures


@pytest.mark.parametrize("spelling", ["compact", "hyphenated", "braced", "urn"])
def test_actual_privacy_delivery_across_both_databases(initialized, tmp_path, monkeypatch, spelling):
    binary = Path(os.environ["MK_PRIVACY_KERNEL_BINARY"]).resolve(strict=True)
    owner, _, runtime = initialized
    admin = owner.set(database="mk_app_test_admin")
    name = "mk_kernel_privacy_" + uuid.uuid4().hex
    login = "mk_privacy_" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    kernel_url = owner.set(database=name)
    process = None
    minter = AssertionMinter.generate("privacy-fixture")
    env = {key:value for key,value in os.environ.items() if not key.startswith(("MK_", "RUST_ACTION_"))}
    env.update(MK_DATABASE_URL=raw(kernel_url), MK_MASTER_KEY=base64.b64encode(os.urandom(32)).decode(),
        MK_ASSERTION_KEYS=f"privacy-fixture={minter.public_key_b64url()}",
        MK_APPROVAL_RP_ID="localhost",MK_APPROVAL_ORIGINS="http://localhost:8000",
        RUST_ACTION_KERNEL_ENABLED="1", RUST_LOG="warn")
    with psycopg.connect(raw(admin),autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        subprocess.run([str(binary)],env={**env,"MK_MIGRATE_ONLY":"1"},check=True,capture_output=True,timeout=30)
        with psycopg.connect(raw(kernel_url),autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(login),sql.Literal(password)))
            conn.execute(sql.SQL("GRANT mk_kernel_api TO {}").format(sql.Identifier(login)))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1",0)); port=listener.getsockname()[1]
        env.update(MK_DATABASE_URL=raw(kernel_url.set(username=login,password=password)),MK_BIND=f"127.0.0.1:{port}")
        with (tmp_path / "kernel.log").open("wb") as log:
            process=subprocess.Popen([str(binary)],env=env,stdout=log,stderr=subprocess.STDOUT)
        base=f"http://127.0.0.1:{port}"
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            if process.poll() is not None:
                pytest.fail("owned kernel process exited; inspect fixture kernel.log")
            try:
                if httpx.get(base+"/health/ready",timeout=1).status_code==200: break
            except httpx.TransportError:
                pass
            time.sleep(.1)
        else:
            pytest.fail("owned kernel readiness timed out")
        kernel=KernelClient(base,minter,2)
        monkeypatch.setenv("MASTER_KEY",base64.b64encode(b"0"*32).decode())
        monkeypatch.delenv("APP_SEAL_KEYS",raising=False)
        get_settings.cache_clear()
        engine=db.init_engine(runtime)
        with Session(engine,expire_on_commit=False) as session:
            tenant=Tenant(name="Privacy bridge fixture");session.add(tenant);session.flush()
            user=User(tenant_id=tenant.id,email=f"privacy-{uuid.uuid4().hex}@example.invalid",password_hash="no-login-fixture")
            session.add(user);session.flush()
            customer=Customer(tenant_id=tenant.id,user_id=user.id,name="Synthetic customer",notes="Synthetic private notes")
            session.add(customer);session.commit()
            now=datetime.now(timezone.utc)
            uid,tid,cid=(str(uuid.UUID(value)) for value in (user.id,tenant.id,customer.id))
            resource_id={"compact":cid.replace("-", "").upper(),"hyphenated":cid,
                "braced":"{"+cid+"}","urn":"urn:uuid:"+cid}[spelling]
            proposal={"schema_version":"mk.action.v1","tenant_id":tid,"requested_by":uid,
                "origin":{"type":"agent"},"workflow":"customer_follow_up","action_kind":"send_sms",
                "tool_id":"mobile.sms.send.v1","resource":{"type":"contact","id":resource_id},
                "arguments":{"contact_id":cid,"to":"+15555550100","rendered_text":"Synthetic private bridge content. Reply STOP to opt out."},
                "purpose":"synthetic_private_purpose","risk":"high","requested_at":now.isoformat(),
                "expires_at":(now+timedelta(minutes=10)).isoformat(),"idempotency_key":"synthetic-private-key-"+uuid.uuid4().hex,"evidence":[]}
            proposed=asyncio.run(kernel.call("POST","/actions",user_id=uid,tenant_id=tid,roles=["agent"],session_id="privacy-fixture",json=proposal))
            assert proposed.status_code in {202,403}, proposed.body
            action_id=proposed.body["result"]["action_id"]
            request=erase_customer(session,user,customer.id);session.commit()
            assert session.get(Customer,customer.id) is None
            assert asyncio.run(drain_kernel_erasures(session,kernel))==1
            task=session.scalar(select(ErasureTask).where(ErasureTask.request_id==request.id,ErasureTask.kind=="kernel_contact"))
            session.refresh(task);assert task.confirmed_at and task.status=="confirmed"
            leftovers=list(session.scalars(select(ErasureTask).where(ErasureTask.request_id==request.id,ErasureTask.confirmed_at.is_(None))))
            assert {row.kind for row in leftovers}=={"restore_ledger_anchor","backup_expiry"}
            gone=asyncio.run(kernel.call("GET",f"/actions/{action_id}",user_id=uid,tenant_id=tid,roles=["consultant"],session_id="privacy-fixture"))
            assert gone.status_code==410
            with psycopg.connect(raw(kernel_url)) as conn:
                assert conn.execute("SELECT octet_length(canonical_request),content_erased_at IS NOT NULL FROM kernel.actions WHERE tenant_id=%s AND action_id=%s",(tid,action_id)).fetchone()==(0,True)
                assert conn.execute("SELECT purpose='',idempotency_key NOT LIKE '%%synthetic-private%%' FROM kernel.actions WHERE tenant_id=%s AND action_id=%s",(tid,action_id)).fetchone()==(True,True)
                assert conn.execute("SELECT key_erased,idempotency_key NOT LIKE '%%synthetic-private%%' FROM kernel.idempotency_records WHERE tenant_id=%s AND first_action_id=%s",(tid,action_id)).fetchone()==(True,True)
            # A fresh application delivery session needs no browser token and
            # no duplicate network erasure after the durable receipt.
            with Session(engine) as restarted:
                assert asyncio.run(drain_kernel_erasures(restarted,kernel))==0
    finally:
        if process is not None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill();process.wait(timeout=5)
        with psycopg.connect(raw(admin),autocommit=True) as conn:
            assert name.startswith("mk_kernel_privacy_") and login.startswith("mk_privacy_")
            conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(login)))
        get_settings.cache_clear()
