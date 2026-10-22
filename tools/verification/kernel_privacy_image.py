"""Exercise kernel privacy through the built, restricted runtime image.

Owns only recorded UUID targets on the labelled mk-87-rows disposable PG cluster.
Uses generated test keys and synthetic content; makes no provider requests.
"""
import argparse
import asyncio
import base64
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import psycopg
from psycopg import sql

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"backend"))
from app.kernel.assertions import AssertionMinter
from app.kernel.client import KernelClient


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--image",required=True)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    report={"scope":"author-run built kernel image; synthetic fixtures; no provider calls"}
    owned="mk-kernel-privacy-"+uuid.uuid4().hex
    database="mk_kernel_image_"+uuid.uuid4().hex
    login="mk_privacy_"+uuid.uuid4().hex
    container="mk-acceptance-pg-20261021"
    network_created=attached=database_created=login_created=api_created=False
    dsn=os.environ["MK_KERNEL_TEST_ADMIN_DSN"]
    conninfo=psycopg.conninfo.conninfo_to_dict(dsn)
    assert conninfo["host"] in {"localhost","127.0.0.1"} and conninfo["dbname"]=="postgres"

    def docker(*parts,env=None):
        result=subprocess.run(["docker",*parts],capture_output=True,text=True,timeout=90,
            env={**os.environ,**(env or {})})
        if result.returncode:
            raise RuntimeError(f"Docker {parts[0]} failed with exit {result.returncode}")
        return result.stdout.strip()

    info=json.loads(docker("inspect",container))[0]
    assert info["Config"]["Labels"].get("codex.task")=="mk-87-rows"
    image=json.loads(docker("image","inspect",args.image))[0]["Id"]
    report["image_id"]=image
    key=AssertionMinter.generate("privacy-image")
    env={"MK_DATABASE_URL":f"postgres://{conninfo['user']}:{conninfo['password']}@db:5432/{database}",
        "MK_MASTER_KEY":base64.b64encode(os.urandom(32)).decode(),
        "MK_ASSERTION_KEYS":f"privacy-image={key.public_key_b64url()}",
        "MK_APPROVAL_RP_ID":"localhost","MK_APPROVAL_ORIGINS":"http://localhost:8000",
        "RUST_ACTION_KERNEL_ENABLED":"1","MK_BIND":"0.0.0.0:8090","RUST_LOG":"warn"}
    try:
        with psycopg.connect(dsn,autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
            database_created=True
        docker("network","create","--label","codex.task=mk-87-rows",owned);network_created=True
        docker("network","connect","--alias","db",owned,container);attached=True
        migration={**env,"MK_MIGRATE_ONLY":"1"}
        options=["run","--rm","--network",owned,"--read-only","--cap-drop=ALL","--security-opt=no-new-privileges",
            "--label","codex.task=mk-87-rows"]
        for name in migration: options.extend(["--env",name])
        docker(*options,image,env=migration)
        password=secrets.token_hex(24)
        with psycopg.connect(dsn,autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(login),sql.Literal(password)))
            login_created=True
            conn.execute(sql.SQL("GRANT mk_kernel_api TO {}").format(sql.Identifier(login)))
        env["MK_DATABASE_URL"]=f"postgres://{login}:{password}@db:5432/{database}"
        options=["run","-d","--name",owned,"--network",owned,"--read-only","--cap-drop=ALL",
            "--security-opt=no-new-privileges","--memory","256m","--cpus","1","--pids-limit","64",
            "--label","codex.task=mk-87-rows","--publish","127.0.0.1::8090"]
        for name in env: options.extend(["--env",name])
        docker(*options,image,env=env);api_created=True
        state=json.loads(docker("inspect",owned))[0]
        assert state["Config"]["User"]=="65532:65532" and state["HostConfig"]["ReadonlyRootfs"]
        port=state["NetworkSettings"]["Ports"]["8090/tcp"][0]["HostPort"]
        base=f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                if httpx.get(base+"/health/ready",timeout=1).status_code==200: break
            except httpx.TransportError: pass
            time.sleep(.1)
        else: raise RuntimeError("kernel image readiness timeout")
        client=KernelClient(base,key,3)
        tenant,user,contact,request=(str(uuid.uuid4()) for _ in range(4))
        now=datetime.now(timezone.utc)
        proposal={"schema_version":"mk.action.v1","tenant_id":tenant,"requested_by":user,
            "origin":{"type":"agent"},"workflow":"customer_follow_up","action_kind":"send_sms",
            "tool_id":"mobile.sms.send.v1","resource":{"type":"contact","id":contact.replace("-","").upper()},
            "arguments":{"contact_id":contact,"to":"+15555550100","rendered_text":"Synthetic image privacy canary. Reply STOP to opt out."},
            "purpose":"customer_requested_follow_up","risk":"high","requested_at":now.isoformat(),
            "expires_at":(now+timedelta(minutes=10)).isoformat(),"idempotency_key":uuid.uuid4().hex,"evidence":[]}
        def call(method,path,roles,payload=None):
            return asyncio.run(client.call(method,path,user_id=user,tenant_id=tenant,roles=roles,
                session_id="privacy-image-fixture",json=payload))
        proposed=call("POST","/actions",["agent"],proposal)
        assert proposed.status_code in {202,403},proposed.body
        aid=proposed.body["result"]["action_id"]
        erased=call("POST","/privacy/erase",["privacy_eraser"],
            {"request_id":request,"subject_kind":"contact","subject_id":contact})
        assert erased.status_code==201 and erased.body["active_content_erased"] is True
        assert erased.body["pending_provider_deletions"]==0
        assert call("GET",f"/actions/{aid}",["consultant"]).status_code==410
        assert call("POST","/actions",["agent"],proposal).status_code==410
        assert call("GET","/senders",["privacy_eraser"]).status_code==403
        with psycopg.connect(psycopg.conninfo.make_conninfo(dsn,dbname=database)) as conn:
            assert conn.execute("SELECT octet_length(canonical_request),content_erased_at IS NOT NULL FROM kernel.actions WHERE tenant_id=%s AND action_id=%s",(tenant,aid)).fetchone()==(0,True)
            report["migration_count"]=conn.execute("SELECT count(*) FROM _sqlx_migrations WHERE success").fetchone()[0]
        report.update(user=state["Config"]["User"],read_only_root=True,dropped_capabilities=state["HostConfig"]["CapDrop"],
            active_content_erased=True,erased_read_status=410,reintake_status=410,service_cross_route_status=403)
    finally:
        if api_created: docker("rm","-f",owned)
        if attached: docker("network","disconnect",owned,container)
        if network_created: docker("network","rm",owned)
        with psycopg.connect(dsn,autocommit=True) as conn:
            assert database.startswith("mk_kernel_image_") and login.startswith("mk_privacy_")
            if database_created: conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
            if login_created: conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
        report["owned_targets_removed"]=True
        (output/"report.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report))


if __name__=="__main__": main()
