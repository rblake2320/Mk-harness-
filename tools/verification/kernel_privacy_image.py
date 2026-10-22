"""Exercise kernel privacy through the built, restricted runtime image.

Owns only recorded UUID targets on the labelled mk-87-rows disposable PG cluster.
Uses generated test keys and synthetic content; no external provider requests.
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
    parser.add_argument("--provider-fixture-image",help="Existing Python application image for isolated provider test equipment")
    args=parser.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    report={"scope":"author-run built kernel image; synthetic fixtures; no external provider calls"}
    owned="mk-kernel-privacy-"+uuid.uuid4().hex
    database="mk_kernel_image_"+uuid.uuid4().hex
    restored_database="mk_kernel_restored_"+uuid.uuid4().hex
    login="mk_privacy_"+uuid.uuid4().hex
    container="mk-acceptance-pg-20261021"
    network_created=attached=database_created=login_created=api_created=False
    provider_created=worker_created=worker_login_created=False
    restored_created=False
    worker_name,provider_name,worker_login=owned+"-worker",owned+"-provider",login+"_worker"
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
            "--tmpfs","/recovery:rw,noexec,nosuid,uid=65532,gid=65532,mode=0700,size=8388608",
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
            actor=str(uuid.uuid5(uuid.NAMESPACE_URL,f"mk:privacy-erasure:{tenant}")) if roles==["privacy_eraser"] else user
            return asyncio.run(client.call(method,path,user_id=actor,tenant_id=tenant,roles=roles,
                session_id="privacy-image-fixture",json=payload))
        proposed=call("POST","/actions",["agent"],proposal)
        assert proposed.status_code in {202,403},proposed.body
        aid=proposed.body["result"]["action_id"]
        # Actual pre-erasure backup. Raw bytes remain in memory, never artifacts.
        dump=subprocess.run(["docker","exec",container,"pg_dump","-U",conninfo["user"],
            "-d",database,"--format=custom","--no-owner"],check=True,capture_output=True,timeout=60).stdout
        assert dump.startswith(b"PGDMP")
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

        def recovery_command(binary,arguments,target):
            recovery_env={**os.environ,"MK_DATABASE_URL":f"postgres://{conninfo['user']}:{conninfo['password']}@db:5432/{target}"}
            return subprocess.run(["docker","exec","--env","MK_DATABASE_URL",owned,
                "/usr/local/bin/"+binary,*arguments],env=recovery_env,capture_output=True,text=True,timeout=60)

        freshness=datetime.now(timezone.utc).isoformat()
        exported=recovery_command("mk-privacy-ledger",["export","--ledger","/recovery/kernel.json"],database)
        assert exported.returncode==0, "built-image ledger export failed"
        export_receipt=json.loads(exported.stdout)
        with psycopg.connect(dsn,autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restored_database)));restored_created=True
        subprocess.run(["docker","exec","-i",container,"pg_restore","-U",conninfo["user"],
            "-d",restored_database,"--no-owner","--exit-on-error"],input=dump,check=True,capture_output=True,timeout=60)
        del dump
        restored_dsn=psycopg.conninfo.make_conninfo(dsn,dbname=restored_database)
        with psycopg.connect(restored_dsn) as conn:
            assert conn.execute("SELECT octet_length(canonical_request)>0 FROM kernel.actions WHERE action_id=%s",(aid,)).fetchone()==(True,)
            conn.execute("UPDATE kernel.kill_switches SET dispatch_enabled=false WHERE scope='global'")
        gate_args=["--restored-at",datetime.now(timezone.utc).isoformat()]
        refused=recovery_command("mk-restore-gate",gate_args,restored_database)
        assert refused.returncode!=0 and 'privacy_restore_ledger' in refused.stdout
        gate_args += ["--privacy-ledger","/recovery/kernel.json","--privacy-sha256",export_receipt["sha256"],"--privacy-not-before",freshness]
        preview=recovery_command("mk-restore-gate",gate_args,restored_database)
        assert preview.returncode!=0
        applied=recovery_command("mk-restore-gate",[*gate_args,"--apply"],restored_database)
        assert applied.returncode==0, "built-image privacy restore failed"
        gate_report=[json.loads(line) for line in applied.stdout.splitlines() if line.startswith("{")]
        assert gate_report[-1]["gate"]=="PASS"
        assert recovery_command("mk-restore-gate",gate_args,restored_database).returncode==0
        with psycopg.connect(restored_dsn) as conn:
            assert conn.execute("SELECT octet_length(canonical_request),content_erased_at IS NOT NULL FROM kernel.actions WHERE action_id=%s",(aid,)).fetchone()==(0,True)
            assert conn.execute("SELECT count(*) FROM kernel.privacy_destination_fences").fetchone()==(1,)
            assert conn.execute("SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope='global'").fetchone()==(False,)
        report["privacy_restore"]={"actual_pg_dump_restore":True,"without_external_ledger_refused":True,
            "preview_refused_unreplayed_content":True,"apply_scrubbed_content":True,"restored_fences":1,
            "dispatch_enabled":False,"repeat_report_passed":True,"runtime_user":state["Config"]["User"],
            "ledger_sha256":export_receipt["sha256"],"gate":gate_report}
        if args.provider_fixture_image:
            # Provider and worker share one isolated network namespace, so the
            # production HTTP egress rule remains strictly loopback-only.
            account,token,message="AC"+uuid.uuid4().hex,secrets.token_hex(24),"SM"+uuid.uuid4().hex
            number="+15555550101"
            sender=call("POST","/senders",["tenant_admin"],{"owner_user_id":user,"display_name":"Synthetic image sender",
                "account_sid":account,"auth_token":token,"from_number":number})
            assert sender.status_code==201
            sender_id=sender.body["sender_identity_id"]
            account_request=str(uuid.uuid4())
            body={"request_id":account_request,"subject_kind":"account","subject_id":user}
            assert call("POST","/privacy/erase",["privacy_eraser"],body).status_code==201
            worker_password=secrets.token_hex(24)
            with psycopg.connect(psycopg.conninfo.make_conninfo(dsn,dbname=database),autocommit=True) as conn:
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(worker_login),sql.Literal(worker_password)))
                worker_login_created=True
                conn.execute(sql.SQL("GRANT mk_kernel_worker TO {}").format(sql.Identifier(worker_login)))
                conn.execute("INSERT INTO kernel.privacy_provider_deletions(tenant_id,request_id,sender_identity_id,provider,provider_message_id) VALUES(%s,%s,%s,'twilio',%s)",
                    (tenant,account_request,sender_id,message))
            fixture={"FIXTURE_ACCOUNT":account,"FIXTURE_TOKEN":token,"FIXTURE_MESSAGE":message,"FIXTURE_NUMBER":number}
            mount=f"type=bind,src={Path(__file__).with_name('provider_erasure_server.py').resolve()},dst=/fixture.py,readonly"
            options=["run","-d","--name",provider_name,"--network",owned,"--read-only","--cap-drop=ALL",
                "--security-opt=no-new-privileges","--label","codex.task=mk-87-rows","--publish","127.0.0.1::8790",
                "--mount",mount,"--entrypoint","python"]
            for name in fixture: options.extend(["--env",name])
            docker(*options,args.provider_fixture_image,"/fixture.py",env=fixture);provider_created=True
            provider=json.loads(docker("inspect",provider_name))[0]
            fixture_port=provider["NetworkSettings"]["Ports"]["8790/tcp"][0]["HostPort"]
            fixture_url=f"http://127.0.0.1:{fixture_port}"
            for _ in range(100):
                try:
                    if httpx.get(fixture_url+"/fixture-state",auth=(account,token),timeout=1).status_code==200: break
                except httpx.TransportError: pass
                time.sleep(.1)
            else: raise RuntimeError("provider fixture readiness timeout")
            worker_env={**env,"MK_DATABASE_URL":f"postgres://{worker_login}:{worker_password}@db:5432/{database}",
                "MK_REDIS_URL":"redis://127.0.0.1:1","MK_METRICS_BIND":"","MK_ALLOW_LOOPBACK_HTTP":"1",
                "MK_TWILIO_API_BASE":"http://127.0.0.1:8790","MK_PUBLIC_WEBHOOK_BASE":"http://127.0.0.1:8790",
                "MK_EGRESS_AUTHORITIES":"127.0.0.1:8790"}
            options=["run","-d","--name",worker_name,"--network",f"container:{provider_name}","--read-only","--cap-drop=ALL",
                "--security-opt=no-new-privileges","--label","codex.task=mk-87-rows","--memory","256m","--cpus","1",
                "--pids-limit","64","--entrypoint","/usr/local/bin/mk-action-worker"]
            for name in worker_env: options.extend(["--env",name])
            docker(*options,image,env=worker_env);worker_created=True
            for _ in range(100):
                fixture_state=httpx.get(fixture_url+"/fixture-state",auth=(account,token),timeout=1).json()
                if not fixture_state["present"]: break
                assert json.loads(docker("inspect",worker_name))[0]["State"]["Running"],"image worker exited"
                time.sleep(.1)
            else: raise RuntimeError("image worker did not delete with Redis unavailable")
            docker("kill","--signal","KILL",worker_name)
            assert json.loads(docker("inspect",worker_name))[0]["State"]["ExitCode"]==137
            httpx.post(fixture_url+"/fixture-release",auth=(account,token),timeout=1).raise_for_status()
            with psycopg.connect(psycopg.conninfo.make_conninfo(dsn,dbname=database)) as conn:
                assert conn.execute("SELECT attempts,confirmed_at IS NULL,lease_id IS NOT NULL FROM kernel.privacy_provider_deletions WHERE tenant_id=%s",(tenant,)).fetchone()==(1,True,True)
                conn.execute("UPDATE kernel.privacy_provider_deletions SET next_attempt_at=now()-interval '1 second' WHERE tenant_id=%s",(tenant,))
            docker("start",worker_name)
            for _ in range(100):
                with psycopg.connect(psycopg.conninfo.make_conninfo(dsn,dbname=database)) as conn:
                    confirmed=conn.execute("SELECT confirmed_at IS NOT NULL FROM kernel.privacy_provider_deletions WHERE tenant_id=%s",(tenant,)).fetchone()[0]
                if confirmed: break
                time.sleep(.1)
            else: raise RuntimeError("image worker did not recover the abandoned deletion lease")
            final=call("POST","/privacy/erase",["privacy_eraser"],body)
            assert final.status_code==201 and final.body["pending_provider_deletions"]==0 and final.body["pending_provider_retention"]==1
            fixture_state=httpx.get(fixture_url+"/fixture-state",auth=(account,token),timeout=1).json()
            assert fixture_state=={"deletes":2,"sends":0,"auth_failures":0,"present":False}
            with psycopg.connect(psycopg.conninfo.make_conninfo(dsn,dbname=database)) as conn:
                receipts=conn.execute("SELECT count(*) FROM kernel.audit_events WHERE tenant_id=%s AND event_type='provider_content_erased'",(tenant,)).fetchone()[0]
                assert receipts==1
            worker_state=json.loads(docker("inspect",worker_name))[0]
            assert worker_state["Config"]["User"]=="65532:65532" and worker_state["HostConfig"]["ReadonlyRootfs"]
            assert "ALL" in worker_state["HostConfig"]["CapDrop"]
            report["provider_cleanup"]={**fixture_state,"redis_unavailable":True,"sigkill_after_external_effect":True,
                "restart_recovered_lease":True,"active_receipts":receipts,"backup_pending":True,"restricted_worker_role":True,
                "worker_user":worker_state["Config"]["User"],"worker_read_only":True,"killed_exit_code":137}
        report["outcome"]="Worked"
    except Exception as exc:
        report.update(outcome="Failed",error_type=type(exc).__name__)
        raise
    finally:
        if worker_created: docker("rm","-f",worker_name)
        if provider_created: docker("rm","-f",provider_name)
        if api_created: docker("rm","-f",owned)
        if attached: docker("network","disconnect",owned,container)
        if network_created: docker("network","rm",owned)
        with psycopg.connect(dsn,autocommit=True) as conn:
            assert database.startswith("mk_kernel_image_") and login.startswith("mk_privacy_")
            assert restored_database.startswith("mk_kernel_restored_")
            if restored_created: conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(restored_database)))
            if database_created: conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
            if login_created: conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
            if worker_login_created: conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(worker_login)))
        report["owned_targets_removed"]=True
        (output/"report.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report))


if __name__=="__main__": main()
