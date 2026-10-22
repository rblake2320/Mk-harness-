"""Actual recovery binaries against only fresh, fixture-owned databases."""
import asyncio
import base64
import hashlib
import json
import os
import socket
import subprocess
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import psycopg
from psycopg import sql
from test_app_database import raw
from app.kernel.assertions import AssertionMinter
from app.kernel.client import KernelClient


def utc():
    return datetime.now(timezone.utc).isoformat()


def records(result):
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


class Recovery:
    def __init__(self, database, tmp_path):
        self.database, self.tmp = database, tmp_path
        self.api = Path(os.environ["MK_PRIVACY_KERNEL_BINARY"]).resolve(strict=True)
        self.minter = AssertionMinter.generate("privacy-restore")
        self.env = {k:v for k,v in os.environ.items() if not k.startswith(("MK_", "RUST_ACTION_"))}
        self.env.update(MK_DATABASE_URL=raw(database), MK_MASTER_KEY=base64.b64encode(os.urandom(32)).decode(),
            MK_ASSERTION_KEYS="privacy-restore="+self.minter.public_key_b64url(),
            MK_APPROVAL_RP_ID="localhost", MK_APPROVAL_ORIGINS="http://localhost:8000",
            RUST_ACTION_KERNEL_ENABLED="1", RUST_LOG="warn")
        self.run(self.api, env={**self.env, "MK_MIGRATE_ONLY":"1"}, check=True)
        self.disable()
        self.login = "mk_restore_"+uuid.uuid4().hex
        self.password = uuid.uuid4().hex
        with psycopg.connect(raw(database), autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(self.login), sql.Literal(self.password)))
            conn.execute(sql.SQL("GRANT mk_kernel_api TO {}").format(sql.Identifier(self.login)))

    def close(self):
        with psycopg.connect(raw(self.database),autocommit=True) as conn:
            assert self.login.startswith("mk_restore_")
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(self.login)))

    def run(self, binary, *args, env=None, check=False):
        return subprocess.run([str(binary), *map(str,args)], env=env or self.env,
            capture_output=True, text=True, timeout=40, check=check)

    def disable(self, target=None):
        with psycopg.connect(raw(target or self.database)) as conn:
            conn.execute("UPDATE kernel.kill_switches SET dispatch_enabled=false WHERE scope='global'")

    def gate(self, target=None, pin=(), apply=False, inspection=False):
        return self.run(self.api.with_name("mk-restore-gate"), "--restored-at", utc(),
            *pin, *(["--apply"] if apply else []), *(["--inspection-only"] if inspection else []),
            env={**self.env, "MK_DATABASE_URL":raw(target or self.database)})

    def export(self, filename="ledger.json"):
        not_before = utc()
        path = self.tmp/filename
        result = self.run(self.api.with_name("mk-privacy-ledger"), "export", "--ledger", path, check=True)
        digest = "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
        assert records(result)[0]["sha256"] == digest
        if os.name != "nt": assert path.stat().st_mode & 0o777 == 0o600
        return ["--privacy-ledger", str(path), "--privacy-sha256", digest, "--privacy-not-before", not_before]

    @contextmanager
    def client(self, target=None):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0)); port = sock.getsockname()[1]
        target = target or self.database
        env = {**self.env, "MK_DATABASE_URL":raw(target.set(username=self.login,password=self.password)),
            "MK_BIND":f"127.0.0.1:{port}"}
        with (self.tmp/("api-"+uuid.uuid4().hex+".log")).open("wb") as log:
            process = subprocess.Popen([str(self.api)],env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic()+20
            while time.monotonic()<deadline:
                assert process.poll() is None, "owned API exited; inspect temporary fixture log"
                try:
                    if httpx.get(base+"/health/ready",timeout=1).status_code == 200: break
                except httpx.TransportError: pass
                time.sleep(.1)
            else: raise AssertionError("owned API readiness timeout")
            yield KernelClient(base,self.minter,3)
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)

    def call(self, client, tid, uid, route, body, roles=("agent",)):
        return asyncio.run(client.call("POST",route,user_id=uid,tenant_id=tid,
            roles=list(roles),session_id="restore-fixture",json=body))

    def propose(self, client, tid, uid, cid, phone="+15555550100", **overrides):
        now = datetime.now(timezone.utc)
        proposal = {"schema_version":"mk.action.v1", "tenant_id":tid, "requested_by":uid,
            "origin":{"type":"agent"},"workflow":"customer_follow_up","action_kind":"send_sms",
            "tool_id":"mobile.sms.send.v1","resource":{"type":"contact","id":cid},
            "arguments":{"contact_id":cid,"to":phone,"rendered_text":"RESTORE-PRIVATE-CANARY. Reply STOP to opt out."},
            "purpose":"restore_private_purpose","risk":"high","requested_at":now.isoformat(),
            "expires_at":(now+timedelta(minutes=10)).isoformat(),"idempotency_key":"private-"+uuid.uuid4().hex,"evidence":[]}
        proposal.update(overrides)
        return self.call(client,tid,uid,"/actions",proposal)

    def erase(self, client, tid, cid, request=None):
        request = request or str(uuid.uuid4())
        result = self.call(client,tid,str(uuid.uuid5(uuid.NAMESPACE_URL,f"mk:privacy-erasure:{tid}")),
            "/privacy/erase",{"request_id":request,"subject_kind":"contact","subject_id":cid},("privacy_eraser",))
        assert result.status_code == 201, result.body
        return request, result.body

    def docker(self):
        binary = os.environ.get("MK_PRIVACY_TEST_DOCKER", "docker")
        container = os.environ["MK_PRIVACY_TEST_POSTGRES_CONTAINER"]
        info = json.loads(subprocess.run([binary,"inspect",container],check=True,capture_output=True,text=True,timeout=20).stdout)[0]
        mappings = info["NetworkSettings"]["Ports"]["5432/tcp"]
        assert any(int(item["HostPort"]) == self.database.port for item in mappings), "container is not the dedicated test cluster"
        assert "POSTGRES_DB=mk_app_test_admin" in info["Config"]["Env"]
        return binary, container

    def backup(self):
        binary, container = self.docker()
        assert self.database.database.startswith("mk_app_acceptance_")
        result = subprocess.run([binary,"exec",container,"pg_dump","-U",self.database.username,
            "-d",self.database.database,"--format=custom","--no-owner"],check=True,capture_output=True,timeout=45)
        assert result.stdout.startswith(b"PGDMP")
        return result.stdout

    @contextmanager
    def restored(self, dump):
        binary, container = self.docker()
        name = "mk_kernel_restored_"+uuid.uuid4().hex
        admin = self.database.set(database="mk_app_test_admin")
        with psycopg.connect(raw(admin),autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        target = self.database.set(database=name)
        try:
            subprocess.run([binary,"exec","-i",container,"pg_restore","-U",target.username,
                "-d",name,"--no-owner","--exit-on-error"],input=dump,check=True,capture_output=True,timeout=45)
            yield target
        finally:
            with psycopg.connect(raw(admin),autocommit=True) as conn:
                assert name.startswith("mk_kernel_restored_")
                conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
