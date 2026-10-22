"""Real process death/restart with provider acceptance and Redis unavailable.

Only the explicit disposable database fixture and loopback simulator are used.
Generated credentials and signing material remain in memory/private pytest files.
"""
import asyncio
import base64
import json
import os
import socket
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import psycopg
import pytest
from psycopg import sql

from test_app_database import database, raw  # noqa: F401
from app.kernel.assertions import AssertionMinter
from app.kernel.client import KernelClient


def test_worker_survives_redis_outage_and_recovers_killed_provider_deletion(database, tmp_path):
    api_binary = Path(os.environ["MK_PRIVACY_KERNEL_BINARY"]).resolve(strict=True)
    worker_binary = api_binary.with_name("mk-action-worker")
    assert worker_binary.is_file()
    tid, uid, request, message = (str(uuid.uuid4()) for _ in range(4))
    message = "SM" + message.replace("-", "")
    account, token = "AC" + uuid.uuid4().hex, "synthetic-provider-token"
    number = "+15555550101"
    login_api, login_worker = ("mk_privacy_" + uuid.uuid4().hex for _ in range(2))
    password = uuid.uuid4().hex
    minter = AssertionMinter.generate("privacy-process")
    present, accepted, release = threading.Event(), threading.Event(), threading.Event()
    present.set()
    state = {"deletes": 0, "auth_failures": 0, "sends": 0}
    expected_auth = "Basic " + base64.b64encode(f"{account}:{token}".encode()).decode()
    path = f"/2010-04-01/Accounts/{account}/Messages/{message}.json"

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def authorized(self):
            if self.headers.get("Authorization") != expected_auth or self.path != path:
                state["auth_failures"] += 1
                self.reply(401, {"code": 20003})
                return False
            return True
        def reply(self, status, body=None):
            encoded = json.dumps(body).encode() if body is not None else b""
            try:
                self.send_response(status); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded))); self.end_headers()
                self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError): pass
        def do_GET(self):
            if not self.authorized(): return
            if present.is_set():
                self.reply(200, {"sid": message, "account_sid": account, "status": "delivered",
                    "from": number, "to": "+15555550100", "direction": "outbound-api",
                    "body": "synthetic process-death privacy canary"})
            else: self.reply(404, {"code": 20404})
        def do_DELETE(self):
            if not self.authorized(): return
            state["deletes"] += 1
            if present.is_set():
                present.clear(); accepted.set()
                release.wait(20)  # kill the exact worker after this external effect
                self.reply(204)
            else: self.reply(404, {"code": 20404})
        def do_POST(self):
            state["sends"] += 1
            self.reply(500)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True); server_thread.start()
    env = {k:v for k,v in os.environ.items() if not k.startswith(("MK_", "RUST_ACTION_"))}
    env.update(MK_DATABASE_URL=raw(database), MK_MASTER_KEY=base64.b64encode(os.urandom(32)).decode(),
        MK_ASSERTION_KEYS=f"privacy-process={minter.public_key_b64url()}", MK_APPROVAL_RP_ID="localhost",
        MK_APPROVAL_ORIGINS="http://localhost:8000",RUST_ACTION_KERNEL_ENABLED="1",RUST_LOG="warn",
        MK_PUBLIC_WEBHOOK_BASE="https://example.invalid")
    processes, roles = [], []
    def spawn(binary, config, name):
        with (tmp_path/name).open("wb") as log:
            child = subprocess.Popen([str(binary)],env=config,stdout=log,stderr=subprocess.STDOUT)
        processes.append(child)
        return child
    def stop(child):
        if child.poll() is None:
            child.kill(); child.wait(timeout=5)
    try:
        subprocess.run([str(api_binary)],env={**env,"MK_MIGRATE_ONLY":"1"},check=True,capture_output=True,timeout=30)
        with psycopg.connect(raw(database),autocommit=True) as conn:
            for login, role in [(login_api,"mk_kernel_api"),(login_worker,"mk_kernel_worker")]:
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(login),sql.Literal(password)))
                roles.append(login)
                conn.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(role),sql.Identifier(login)))
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1",0)); port=port_socket.getsockname()[1]
        api_env={**env,"MK_DATABASE_URL":raw(database.set(username=login_api,password=password)),"MK_BIND":f"127.0.0.1:{port}"}
        api=spawn(api_binary,api_env,"api.log")
        base=f"http://127.0.0.1:{port}"
        for _ in range(100):
            assert api.poll() is None
            try:
                if httpx.get(base+"/health/ready",timeout=.3).status_code==200: break
            except httpx.TransportError: pass
            time.sleep(.1)
        else: pytest.fail("owned API readiness timeout")
        kernel=KernelClient(base,minter,2)
        def call(route,roles,body):
            actor=str(uuid.uuid5(uuid.NAMESPACE_URL,f"mk:privacy-erasure:{tid}")) if roles==["privacy_eraser"] else uid
            return asyncio.run(kernel.call("POST",route,user_id=actor,tenant_id=tid,roles=roles,session_id="privacy-process",json=body))
        sender=call("/senders",["tenant_admin"],{"owner_user_id":uid,"display_name":"Synthetic sender",
            "account_sid":account,"auth_token":token,"from_number":number})
        assert sender.status_code==201
        sender_id=sender.body["sender_identity_id"]
        erased=call("/privacy/erase",["privacy_eraser"],{"request_id":request,"subject_kind":"account","subject_id":uid})
        assert erased.status_code==201 and erased.body["pending_sender_cleanup"]==1
        with psycopg.connect(raw(database)) as conn:
            conn.execute("INSERT INTO kernel.privacy_provider_deletions(tenant_id,request_id,sender_identity_id,provider,provider_message_id) VALUES(%s,%s,%s,'twilio',%s)",(tid,request,sender_id,message))
        # Keep a non-listening port bound: deterministic connection refusal,
        # without touching the running Redis instance or any of its keys.
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1",0))
            worker_env={**env,"MK_DATABASE_URL":raw(database.set(username=login_worker,password=password)),
                "MK_REDIS_URL":f"redis://127.0.0.1:{unavailable.getsockname()[1]}","MK_METRICS_BIND":"",
                "MK_TWILIO_API_BASE":f"http://127.0.0.1:{server.server_port}",
                "MK_PUBLIC_WEBHOOK_BASE":base,
                "MK_EGRESS_AUTHORITIES":f"127.0.0.1:{server.server_port},127.0.0.1:{port}","MK_ALLOW_LOOPBACK_HTTP":"1"}
            worker=spawn(worker_binary,worker_env,"worker-before-kill.log")
            for _ in range(100):
                assert worker.poll() is None, "worker exited before privacy cleanup while Redis was unavailable"
                if accepted.wait(.1): break
            else: pytest.fail("provider deletion was not attempted with Redis unavailable")
            stop(worker); release.set()
            with psycopg.connect(raw(database)) as conn:
                assert conn.execute("SELECT attempts,confirmed_at IS NULL,lease_id IS NOT NULL FROM kernel.privacy_provider_deletions WHERE tenant_id=%s",(tid,)).fetchone()==(1,True,True)
                conn.execute("UPDATE kernel.privacy_provider_deletions SET next_attempt_at=now()-interval '1 second' WHERE tenant_id=%s",(tid,))
            restarted=spawn(worker_binary,worker_env,"worker-after-restart.log")
            for _ in range(100):
                assert restarted.poll() is None
                with psycopg.connect(raw(database)) as conn:
                    confirmed=conn.execute("SELECT confirmed_at IS NOT NULL FROM kernel.privacy_provider_deletions WHERE tenant_id=%s",(tid,)).fetchone()[0]
                if confirmed: break
                time.sleep(.1)
            else: pytest.fail("expired lease did not recover after actual process restart")
            stop(restarted)
        assert not present.is_set() and state=={"deletes":2,"auth_failures":0,"sends":0}
        after=call("/privacy/erase",["privacy_eraser"],{"request_id":request,"subject_kind":"account","subject_id":uid})
        assert after.status_code==201
        assert after.body["pending_provider_deletions"]==0 and after.body["pending_provider_retention"]==1
        with psycopg.connect(raw(database)) as conn:
            assert conn.execute("SELECT count(*) FROM kernel.audit_events WHERE tenant_id=%s AND event_type='provider_content_erased'",(tid,)).fetchone()[0]==1
    finally:
        release.set()
        for process in reversed(processes): stop(process)
        server.shutdown(); server.server_close(); server_thread.join(timeout=2)
        with psycopg.connect(raw(database.set(database="mk_app_test_admin")),autocommit=True) as conn:
            for login in roles:
                assert login.startswith("mk_privacy_")
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
