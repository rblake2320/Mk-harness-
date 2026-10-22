"""A restored database cannot certify its own deletion ledger's completeness."""
import base64
import json
import os
import subprocess
import psycopg
import hashlib
import uuid
import pytest
from psycopg import sql
from datetime import timedelta
from datetime import datetime, timezone
from pathlib import Path

from test_app_database import database, raw  # noqa: F401
from app.kernel.assertions import AssertionMinter
from kernel_restore_fixture import Recovery, records
from restore_inspection import validate as validate_inspection


@pytest.fixture
def recovery(database, tmp_path):
    fixture = Recovery(database,tmp_path)
    try: yield fixture
    finally: fixture.close()


def test_empty_pinned_ledger_and_inspection_never_authorizes_restore(recovery):
    inspected = recovery.gate(inspection=True)
    assert inspected.returncode == 0, inspected.stderr
    assert records(inspected)[-1]["gate"] == "INSPECTION_ONLY"
    assert validate_inspection(inspected.stdout) == 9
    assert recovery.gate(apply=True,inspection=True).returncode != 0
    pin = recovery.export()
    assert recovery.gate(pin=pin).returncode == 0
    assert recovery.gate(pin=pin,apply=True).returncode == 0
    before = Path(pin[1]).read_bytes()
    assert recovery.run(recovery.api.with_name("mk-privacy-ledger"),"export","--ledger",pin[1]).returncode != 0
    assert Path(pin[1]).read_bytes() == before
    with psycopg.connect(raw(recovery.database)) as conn:
        assert conn.execute("SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope='global'").fetchone() == (False,)


@pytest.mark.parametrize("new_tenant", [False, True])
@pytest.mark.parametrize("restriction", ["suppression", "channel", "tenant", "session_revocation", "user_revocation"])
def test_post_backup_contact_and_principal_restrictions_survive_recovery(recovery, restriction, new_tenant):
    tid, uid, cid, admin = (str(uuid.uuid4()) for _ in range(4))
    is_suppression = restriction in {"suppression", "channel", "tenant"}
    dump = recovery.backup() if new_tenant else None
    with recovery.client() as client:
        proposed = recovery.propose(client, tid, uid, cid)
        assert proposed.status_code in {202, 403}, proposed.body
        if dump is None: dump = recovery.backup()
        if is_suppression:
            body = {"reason": "POST-BACKUP-PRIVATE-REASON", "permanent": True, "source": "operator"}
            if restriction != "tenant": body["channel"] = "sms"
            if restriction == "suppression": body["destination"] = "+15555550100"
            restricted = recovery.call(client, tid, admin, "/suppressions", body, ("tenant_admin",))
        else:
            body = {"user_id": uid, "reason": "POST-BACKUP-PRIVATE-REASON"}
            if restriction == "session_revocation": body["session_id"] = "restore-fixture"
            restricted = recovery.call(client, tid, admin, "/revocations", body, ("tenant_admin",))
        assert restricted.status_code == 201, restricted.body
        if not is_suppression:
            assert recovery.propose(client, tid, uid, cid).status_code == 401
    pin = recovery.export()
    exported = Path(pin[1]).read_bytes()
    assert all(value not in exported for value in (b"POST-BACKUP-PRIVATE-REASON", b"+15555550100", b"restore-fixture"))
    with recovery.restored(dump) as target:
        assert recovery.gate(target, pin=pin).returncode != 0
        with psycopg.connect(raw(target)) as connection:
            assert connection.execute("SELECT count(*) FROM kernel.suppressions").fetchone() == (0,)
            assert connection.execute("SELECT count(*) FROM kernel.revocations").fetchone() == (0,)
        result = recovery.gate(target, pin=pin, apply=True)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert recovery.gate(target, pin=pin, apply=True).returncode == 0
        assert recovery.gate(target, pin=pin).returncode == 0
        replayed_pin = recovery.export("reexport.json", target)
        assert json.loads(Path(replayed_pin[1]).read_bytes())["restrictions"] == json.loads(exported)["restrictions"]
        with psycopg.connect(raw(target)) as connection:
            if is_suppression:
                count = connection.execute("SELECT count(*) FROM kernel.suppressions WHERE tenant_id=%s AND permanent AND lifted_at IS NULL", (tid,)).fetchone()[0]
            else:
                kind = "session" if restriction == "session_revocation" else "user"
                count = connection.execute("SELECT count(*) FROM kernel.revocations WHERE tenant_id=%s AND user_id=%s AND kind=%s", (tid, uid, kind)).fetchone()[0]
            assert count == 1, "post-backup restriction disappeared even though restore gate passed"
            assert connection.execute("SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope='global'").fetchone() == (False,)
        if not is_suppression:
            with recovery.client(target) as client:
                assert recovery.propose(client, tid, uid, cid).status_code == 401
                other = recovery.propose(client, tid, uid, cid, session_id="unrevoked-session")
                assert other.status_code == (401 if restriction == "user_revocation" else 403), other.body
                assert recovery.propose(client, tid, admin, cid).status_code == 403
                assert recovery.propose(client, str(uuid.uuid4()), uid, cid).status_code == 403
        else:
            # Enable only the disposable, API-only fixture; no worker, relay or
            # provider is configured. Exercise the real proposal policy boundary.
            assert target.database.startswith("mk_kernel_restored_")
            with psycopg.connect(raw(target)) as connection:
                connection.execute("UPDATE kernel.kill_switches SET dispatch_enabled=true WHERE scope='global'")
            with recovery.client(target) as client:
                denied = recovery.propose(client, tid, uid, cid)
                assert denied.status_code == 403, denied.body
                assert denied.body["decision"]["code"] == "suppressed", denied.body
            recovery.disable(target)


@pytest.mark.parametrize("switch", ["enabled", "missing"])
def test_replay_refuses_non_disabled_global_dispatch(recovery, switch):
    pin = recovery.export()
    with psycopg.connect(raw(recovery.database)) as conn:
        if switch == "enabled": conn.execute("UPDATE kernel.kill_switches SET dispatch_enabled=true WHERE scope='global'")
        else: conn.execute("DELETE FROM kernel.kill_switches WHERE scope='global'")
    assert recovery.gate(pin=pin,apply=True).returncode != 0


def test_restriction_conflicts_omissions_and_mid_replay_failure_are_atomic(recovery):
    tid, uid, cid = (str(uuid.uuid4()) for _ in range(3))
    dump = recovery.backup()
    with recovery.client() as client:
        assert recovery.call(client, tid, uid, "/suppressions", {
            "channel":"sms", "destination":"+15555550100", "reason":"test", "permanent":True,
            "source":"operator"}, ("tenant_admin",)).status_code == 201
        assert recovery.call(client, tid, uid, "/revocations", {
            "user_id":str(uuid.uuid4()), "session_id":"PRIVATE-SESSION-CANARY", "reason":"test"},
            ("tenant_admin",)).status_code == 201
    pin = recovery.export()
    value = json.loads(Path(pin[1]).read_text())
    for collection, field, replacement in (("suppressions","permanent",False),
            ("revocations","user_id",str(uuid.uuid4()))):
        for mutation in ("conflict", "omission"):
            altered = json.loads(json.dumps(value))
            if mutation == "omission": altered["restrictions"][collection] = []
            else: altered["restrictions"][collection][0][field] = replacement
            path = recovery.tmp/(collection+mutation+".json")
            path.write_text(json.dumps(altered))
            bad = [*pin]; bad[1] = str(path); bad[3] = "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
            with psycopg.connect(raw(recovery.database)) as conn:
                baseline = conn.execute("SELECT count(*) FROM kernel.audit_events").fetchone()
            assert recovery.gate(pin=bad, apply=True).returncode != 0
            with psycopg.connect(raw(recovery.database)) as conn:
                assert conn.execute("SELECT count(*) FROM kernel.audit_events").fetchone() == baseline
                assert conn.execute("SELECT count(*) FROM kernel.suppressions WHERE permanent").fetchone() == (1,)
                assert conn.execute("SELECT count(*) FROM kernel.revocations").fetchone() == (1,)
    with recovery.restored(dump) as target:
        # Revocations follow suppressions: fail after opt-out and audit writes.
        with psycopg.connect(raw(target)) as conn:
            conn.execute("""CREATE FUNCTION kernel.restriction_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'synthetic restriction recovery fault'; END $$""")
            conn.execute("CREATE TRIGGER restriction_test_fault BEFORE INSERT ON kernel.revocations FOR EACH ROW EXECUTE FUNCTION kernel.restriction_test_fault()")
        assert recovery.gate(target, pin=pin, apply=True).returncode != 0
        with psycopg.connect(raw(target)) as conn:
            for table in ("suppressions", "revocations", "audit_events", "tenant_directory"):
                assert conn.execute(sql.SQL("SELECT count(*) FROM kernel.{}").format(sql.Identifier(table))).fetchone() == (0,)
            conn.execute("DROP TRIGGER restriction_test_fault ON kernel.revocations")
        result = recovery.gate(target, pin=pin, apply=True)
        assert result.returncode == 0, (result.stdout, result.stderr)


def test_recovered_session_shape_and_runtime_immutability(recovery):
    tid, uid, rid = (str(uuid.uuid4()) for _ in range(3))
    statement = """INSERT INTO kernel.revocations(tenant_id,revocation_id,user_id,kind,session_id,session_digest,revoked_by,reason)
        VALUES(%s,%s,%s,'session',%s,%s,%s,'test')"""
    for session, digest in ((None,None), (None,"not-a-digest"), ("raw","sha256:"+"a"*64)):
        with psycopg.connect(raw(recovery.database), autocommit=True) as conn:
            with pytest.raises(psycopg.errors.CheckViolation):
                conn.execute(statement, (tid,rid,uid,session,digest,uid))
    with psycopg.connect(raw(recovery.database)) as conn:
        conn.execute(statement, (tid,rid,uid,None,"sha256:"+"a"*64,uid))
    with psycopg.connect(raw(recovery.database.set(username=recovery.login,password=recovery.password)), autocommit=True) as conn:
        for statement in ("UPDATE kernel.revocations SET session_digest=NULL", "DELETE FROM kernel.revocations", "TRUNCATE kernel.revocations"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute(statement)


@pytest.mark.parametrize("new_objects", [False, True])
@pytest.mark.parametrize("authority", ["permission", "approval_credential", "adapter", "adapter_rotation"])
def test_post_backup_authority_withdrawal_survives_recovery(recovery, authority, new_objects):
    tid, uid, cid, entity = (str(uuid.uuid4()) for _ in range(4))
    dump = recovery.backup() if new_objects else None
    with recovery.client() as client:
        assert recovery.propose(client,tid,uid,cid).status_code == 403
        if authority == "permission":
            now = datetime.now(timezone.utc)
            created = recovery.call(client,tid,uid,f"/contacts/{cid}/permissions",{
                "channel":"sms","destination":"+15555550100","scope":["customer_follow_up"],
                "source":"synthetic recovery fixture","proof_digest":"sha256:"+"a"*64,
                "granted_at":now.isoformat(),"expires_at":(now+timedelta(days=1)).isoformat()},("tenant_admin",))
            assert created.status_code == 201, created.body
            entity = created.body["id"]
            route, body, status = f"/contacts/{cid}/permissions/{entity}/revoke", None, 200
            query = "SELECT status='revoked' AND revoked_at IS NOT NULL FROM kernel.contact_permissions WHERE permission_id=%s"
        elif authority == "approval_credential":
            # Owned fixture seeds a pre-existing registry row; this test covers
            # recovery and live credential eligibility, not passkey enrollment.
            with psycopg.connect(raw(recovery.database)) as conn:
                conn.execute("""INSERT INTO kernel.approval_credentials(tenant_id,credential_row_id,user_id,credential_id,alg,public_key,aaguid,attestation_fmt)
                    VALUES(%s,%s,%s,%s,'EdDSA',%s,%s,'none')""",(tid,entity,uid,os.urandom(32),os.urandom(32),bytes(16)))
            route, body, status = f"/approval-credentials/{entity}/revoke", None, 200
            query = "SELECT revoked_at IS NOT NULL FROM kernel.approval_credentials WHERE credential_row_id=%s"
        else:
            created = recovery.call(client,tid,uid,"/adapters",{"agent_id":"recovery-"+uuid.uuid4().hex,
                "name":"synthetic recovery fixture","platform":"android","version":"1","capabilities":[],
                "allowed_actions":["send_sms"],"callback_authority":"127.0.0.1:8787"},("tenant_admin",))
            assert created.status_code == 201, created.body
            entity = created.body["adapter"]["adapter_id"]
            if authority == "adapter":
                route, body, status = f"/adapters/{entity}/revoke", None, 204
                query = "SELECT revoked_at IS NOT NULL FROM kernel.adapter_registrations WHERE adapter_id=%s"
            else:
                route, body, status = f"/adapters/{entity}/rotate", {"overlap_secs":0}, 200
                with psycopg.connect(raw(recovery.database)) as conn:
                    entity = str(conn.execute("SELECT credential_id FROM kernel.adapter_credentials WHERE adapter_id=%s",(entity,)).fetchone()[0])
                query = "SELECT not_after IS NOT NULL AND not_after<=clock_timestamp() FROM kernel.adapter_credentials WHERE credential_id=%s"
        table, primary, reopen = {
            "permission":("contact_permissions","permission_id","status='granted',revoked_at=NULL"),
            "approval_credential":("approval_credentials","credential_row_id","revoked_at=NULL"),
            "adapter":("adapter_registrations","adapter_id","revoked_at=NULL"),
            "adapter_rotation":("adapter_credentials","credential_id","not_after=NULL,revoked_at=NULL"),
        }[authority]
        with psycopg.connect(raw(recovery.database)) as conn:
            original = conn.execute(sql.SQL("SELECT to_jsonb(r) FROM kernel.{} r WHERE {}=%s").format(sql.Identifier(table),sql.Identifier(primary)),(entity,)).fetchone()[0]
        if dump is None: dump = recovery.backup()
        changed = recovery.call(client,tid,uid,route,body,("tenant_admin",))
        assert changed.status_code == status, changed.body
        with psycopg.connect(raw(recovery.database)) as conn:
            assert conn.execute(query,(entity,)).fetchone() == (True,)
        if authority == "approval_credential":
            assert recovery.call(client,tid,uid,"/kill-switch/global/challenge",None,("platform_operator",)).status_code == 412
    pin = recovery.export()
    authority_value = json.loads(Path(pin[1]).read_bytes())
    for mutation in ("omitted", "conflicting"):
        altered = json.loads(json.dumps(authority_value))
        if mutation == "omitted": altered["restrictions"]["authorities"] = []
        else: altered["restrictions"]["authorities"][0]["identity_digest"] = "sha256:"+"0"*64
        altered_path = recovery.tmp/(mutation+"-authority.json")
        altered_path.write_text(json.dumps(altered))
        bad_pin = [*pin]; bad_pin[1] = str(altered_path); bad_pin[3] = "sha256:"+hashlib.sha256(altered_path.read_bytes()).hexdigest()
        assert recovery.gate(pin=bad_pin,apply=True).returncode != 0
        with psycopg.connect(raw(recovery.database)) as conn:
            assert conn.execute("SELECT count(*) FROM kernel.recovery_authority_fences").fetchone() == (0,)
    with recovery.restored(dump) as target:
        if authority == "permission" and not new_objects:
            with psycopg.connect(raw(target),autocommit=True) as conn:
                conn.execute(sql.SQL("ALTER DATABASE {} SET timezone='Pacific/Honolulu'").format(sql.Identifier(target.database)))
        result = recovery.gate(target,pin=pin,apply=True)
        assert result.returncode == 0, (result.stdout,result.stderr)
        assert recovery.gate(target,pin=pin,apply=True).returncode == 0
        exported = recovery.export("authority-reexport.json", target)
        assert json.loads(Path(exported[1]).read_bytes())["restrictions"]["authorities"] == json.loads(Path(pin[1]).read_bytes())["restrictions"]["authorities"]
        if authority == "approval_credential":
            with recovery.client(target) as client:
                challenge = recovery.call(client,tid,uid,"/kill-switch/global/challenge",None,("platform_operator",))
                assert challenge.status_code == 412, "restored revoked credential can request operator step-up"
        with psycopg.connect(raw(target)) as conn:
            assert conn.execute(query,(entity,)).fetchone() == (None if new_objects else (True,)), "restore gate passed but withdrawn authority was restored"
            assert conn.execute("SELECT count(*) FROM kernel.recovery_authority_fences WHERE entity_id=%s",(entity,)).fetchone() == (1,)
        with psycopg.connect(raw(target),autocommit=True) as conn:
            if new_objects:
                with pytest.raises(psycopg.errors.RaiseException,match="withdrawn recovery identity"):
                    conn.execute(sql.SQL("INSERT INTO kernel.{} SELECT * FROM jsonb_populate_record(NULL::kernel.{},%s::jsonb)").format(sql.Identifier(table),sql.Identifier(table)),(json.dumps(original),))
            else:
                with pytest.raises(psycopg.errors.RaiseException,match="cannot be reopened"):
                    conn.execute(sql.SQL("UPDATE kernel.{} SET ").format(sql.Identifier(table))+sql.SQL(reopen)+sql.SQL(" WHERE {}=%s").format(sql.Identifier(primary)),(entity,))


def test_post_backup_draft_withdrawal_cancels_restored_queue(recovery):
    tid,uid,cid,draft = (str(uuid.uuid4()) for _ in range(4))
    evidence = [{"type":"document","id":"draft:"+draft,"digest":"sha256:"+"d"*64}]
    with recovery.client() as client:
        proposal = recovery.propose(client,tid,uid,cid,evidence=evidence)
        assert proposal.status_code == 403
        action = proposal.body["result"]["action_id"]
        # Owned crash-point fixture models an action waiting in the outbound queue.
        with psycopg.connect(raw(recovery.database)) as conn:
            conn.execute("UPDATE kernel.actions SET state='queued' WHERE action_id=%s",(action,))
        dump = recovery.backup()
        withdrawn = recovery.call(client,tid,uid,f"/drafts/{draft}/invalidate",None,("tenant_admin",))
        assert withdrawn.status_code == 200 and withdrawn.body["cancelled_actions"] == 1
        assert recovery.propose(client,tid,uid,cid,evidence=evidence).status_code == 409
    pin = recovery.export()
    with recovery.restored(dump) as target:
        result = recovery.gate(target,pin=pin,apply=True)
        assert result.returncode == 0,(result.stdout,result.stderr)
        with psycopg.connect(raw(target)) as conn:
            assert conn.execute("SELECT state FROM kernel.actions WHERE action_id=%s",(action,)).fetchone() == ("cancelled",)
        with recovery.client(target) as client:
            assert recovery.propose(client,tid,uid,cid,evidence=evidence).status_code == 409


def test_authority_replay_is_atomic_and_fences_are_tenant_scoped_immutable(recovery):
    tid,uid = (str(uuid.uuid4()) for _ in range(2))
    permissions=[]
    with recovery.client() as client:
        now=datetime.now(timezone.utc)
        for _ in range(2):
            contact=str(uuid.uuid4())
            granted=recovery.call(client,tid,uid,f"/contacts/{contact}/permissions",{
                "channel":"sms","destination":"+15555550100","scope":["customer_follow_up"],
                "source":"atomic fixture","proof_digest":"sha256:"+"c"*64,
                "granted_at":now.isoformat(),"expires_at":(now+timedelta(days=1)).isoformat()},("tenant_admin",))
            assert granted.status_code==201
            permissions.append((contact,granted.body["id"]))
        dump=recovery.backup()
        for contact,permission in permissions:
            assert recovery.call(client,tid,uid,f"/contacts/{contact}/permissions/{permission}/revoke",None,("tenant_admin",)).status_code==200
    pin=recovery.export()
    fault_id=json.loads(Path(pin[1]).read_bytes())["restrictions"]["authorities"][-1]["entity_id"]
    with recovery.restored(dump) as target:
        with psycopg.connect(raw(target)) as conn:
            baseline=conn.execute("SELECT count(*) FROM kernel.audit_events").fetchone()
            conn.execute(sql.SQL("""CREATE FUNCTION kernel.authority_replay_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.permission_id={}::uuid AND NEW.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'synthetic authority fault';
                END IF; RETURN NEW; END $$""").format(sql.Literal(fault_id)))
            conn.execute("CREATE TRIGGER authority_replay_test_fault BEFORE UPDATE ON kernel.contact_permissions FOR EACH ROW EXECUTE FUNCTION kernel.authority_replay_test_fault()")
        assert recovery.gate(target,pin=pin,apply=True).returncode != 0
        with psycopg.connect(raw(target)) as conn:
            assert conn.execute("SELECT count(*) FROM kernel.contact_permissions WHERE status='granted' AND revoked_at IS NULL").fetchone()==(2,)
            assert conn.execute("SELECT count(*) FROM kernel.recovery_authority_fences").fetchone()==(0,)
            assert conn.execute("SELECT count(*) FROM kernel.audit_events").fetchone()==baseline
            conn.execute("DROP TRIGGER authority_replay_test_fault ON kernel.contact_permissions")
        applied=recovery.gate(target,pin=pin,apply=True)
        assert applied.returncode==0,(applied.stdout,applied.stderr)
        with psycopg.connect(raw(target),autocommit=True) as conn:
            for mutation in ("DELETE FROM kernel.recovery_authority_fences","TRUNCATE kernel.recovery_authority_fences",
                    "UPDATE kernel.recovery_authority_fences SET not_after=not_after+interval '1 second'",
                    "UPDATE kernel.recovery_authority_fences SET identity_digest='sha256:'||repeat('0',64)"):
                with pytest.raises(psycopg.errors.RaiseException): conn.execute(mutation)
        with psycopg.connect(raw(target.set(username=recovery.login,password=recovery.password)),autocommit=True) as conn:
            assert conn.execute("SELECT count(*) FROM kernel.recovery_authority_fences").fetchone()==(0,)
            conn.execute("SELECT set_config('kernel.tenant_id',%s,false)",(tid,))
            assert conn.execute("SELECT count(*) FROM kernel.recovery_authority_fences").fetchone()==(2,)
            conn.execute("SELECT set_config('kernel.tenant_id',%s,false)",(str(uuid.uuid4()),))
            assert conn.execute("SELECT count(*) FROM kernel.recovery_authority_fences").fetchone()==(0,)
            for mutation in ("DELETE FROM kernel.recovery_authority_fences", "UPDATE kernel.recovery_authority_fences SET not_after=now()"):
                with pytest.raises(psycopg.errors.InsufficientPrivilege): conn.execute(mutation)


def test_standalone_replay_and_strict_cli_options(recovery):
    pin = recovery.export()
    binary = recovery.api.with_name("mk-privacy-ledger")
    args = ["replay","--ledger",pin[1],"--sha256",pin[3],"--not-before",pin[5]]
    for suffix in ([],["--apply"]):
        result = recovery.run(binary,*args,*suffix)
        assert result.returncode == 0, result.stderr
        assert records(result)[0]["enforced"] is True
    for suffix in (["--wat"],["--ledger",pin[1]],["--not-before"]):
        assert recovery.run(binary,*args,*suffix).returncode != 0
    assert recovery.run(binary,"export","--ledger",recovery.tmp/"bad.json","--apply").returncode != 0


@pytest.mark.parametrize("mutation", ["digest","stale","future","unknown_field","duplicate","bad_fence","nil"])
def test_bad_ledger_never_mutates_database(recovery, mutation):
    pin = recovery.export()
    value = json.loads(Path(pin[1]).read_text())
    req = {"tenant_id":str(uuid.uuid4()),"request_id":str(uuid.uuid4()),"subject_kind":"contact",
        "subject_id":str(uuid.uuid4()),"requested_at":value["exported_at"]}
    if mutation == "stale": pin[-1] = (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    elif mutation == "future": value["exported_at"] = (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    elif mutation == "unknown_field": value["authorized"] = True
    elif mutation == "duplicate": value["requests"] = [req,req]
    elif mutation == "nil": req["tenant_id"] = str(uuid.UUID(int=0)); value["requests"] = [req]
    elif mutation == "bad_fence":
        value["requests"] = [req]
        value["fences"] = [{"tenant_id":req["tenant_id"],"request_id":req["request_id"],
            "channel":"sms","destination_hash":"not-a-hash","destination_fingerprints":[]}]
    Path(pin[1]).write_text(json.dumps(value))
    pin[3] = "sha256:"+("0"*64 if mutation == "digest" else hashlib.sha256(Path(pin[1]).read_bytes()).hexdigest())
    result = recovery.gate(pin=pin,apply=True)
    assert result.returncode != 0
    assert records(result)[-1]["gate"] == "FAIL"
    with psycopg.connect(raw(recovery.database)) as conn:
        assert conn.execute("SELECT count(*) FROM kernel.privacy_erasure_requests").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM kernel.audit_events").fetchone() == (0,)


def test_actual_backup_replays_post_backup_deletions_and_new_contact_fences(recovery):
    tid,uid,old,new = (str(uuid.uuid4()) for _ in range(4))
    with recovery.client() as client:
        proposed = recovery.propose(client,tid,uid,old)
        assert proposed.status_code in {202,403}, proposed.body
        action = proposed.body["result"]["action_id"]
        dump = recovery.backup()
        later = recovery.propose(client,tid,uid,new,"+15555550101")
        assert later.status_code in {202,403}, later.body
        assert recovery.erase(client,tid,old)[1]["active_content_erased"]
        assert recovery.erase(client,tid,new)[1]["active_content_erased"]
    pin = recovery.export()
    ledger_bytes = Path(pin[1]).read_bytes()
    assert all(canary not in ledger_bytes for canary in (b"RESTORE-PRIVATE", b"+15555550100",b"+15555550101"))
    assert len(json.loads(ledger_bytes)["fences"]) == 2
    with recovery.restored(dump) as target:
        with psycopg.connect(raw(target)) as conn:
            assert conn.execute("SELECT octet_length(canonical_request)>0 FROM kernel.actions WHERE action_id=%s",(action,)).fetchone() == (True,)
            assert conn.execute("SELECT count(*) FROM kernel.privacy_erasure_requests").fetchone() == (0,)
        assert recovery.gate(target).returncode != 0
        assert recovery.gate(target,pin=pin).returncode != 0
        applied = recovery.gate(target,pin=pin,apply=True)
        assert applied.returncode == 0, (applied.stdout,applied.stderr)
        assert records(applied)[-1]["gate"] == "PASS"
        assert recovery.gate(target,pin=pin).returncode == 0
        assert recovery.gate(target,pin=pin,apply=True).returncode == 0
        with psycopg.connect(raw(target)) as conn:
            assert conn.execute("SELECT octet_length(canonical_request),purpose,content_erased_at IS NOT NULL FROM kernel.actions WHERE action_id=%s",(action,)).fetchone() == (0,"",True)
            assert conn.execute("SELECT count(*) FROM kernel.privacy_erasure_requests WHERE content_erased_at IS NOT NULL").fetchone() == (2,)
            assert conn.execute("SELECT count(*) FROM kernel.privacy_destination_fences").fetchone() == (2,)
            assert conn.execute("SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope='global'").fetchone() == (False,)
        with recovery.client(target) as client:
            for contact,phone in ((old,"+15555550100"),(new,"+15555550101")):
                assert recovery.propose(client,tid,uid,contact,phone).status_code == 410
            result = recovery.propose(client,tid,uid,str(uuid.uuid4()),"+15555550101")
            assert result.status_code == 410, result.body
            assert "erased" in json.dumps(result.body).lower(), result.body


def test_uncertain_restored_action_is_quarantined_not_falsely_erased(recovery):
    tid,uid,cid = (str(uuid.uuid4()) for _ in range(3))
    with recovery.client() as client:
        proposed = recovery.propose(client,tid,uid,cid)
        action = proposed.body["result"]["action_id"]
        # Controlled crash-point fixture: provider commit boundary was crossed.
        with psycopg.connect(raw(recovery.database)) as conn:
            conn.execute("UPDATE kernel.actions SET state='dispatching' WHERE action_id=%s",(action,))
        assert recovery.erase(client,tid,cid)[1]["blocked_actions"] == 1
    pin = recovery.export()
    result = recovery.gate(pin=pin,apply=True)
    assert result.returncode != 0
    privacy = next(row for row in records(result) if row.get("check")=="privacy_restore_ledger")
    assert not privacy["ok"] and privacy["detail"]["pending_content"] == 1
    with psycopg.connect(raw(recovery.database)) as conn:
        assert conn.execute("SELECT state,octet_length(canonical_request)>0 FROM kernel.actions WHERE action_id=%s",(action,)).fetchone() == ("reconciliation_required",True)
        assert conn.execute("SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope='global'").fetchone() == (False,)


@pytest.mark.parametrize("cross_tenant",[False,True])
def test_conflicting_or_omitted_identity_and_late_sql_failure_roll_back(recovery,cross_tenant):
    tid,uid,first,second = (str(uuid.uuid4()) for _ in range(4))
    subjects = [(tid,first),(str(uuid.uuid4()) if cross_tenant else tid,second)]
    with recovery.client() as client:
        for tenant,cid in subjects: assert recovery.propose(client,tenant,uid,cid).status_code in {202,403}
        dump = recovery.backup()
        for tenant,cid in subjects: recovery.erase(client,tenant,cid)
    pin = recovery.export()
    value = json.loads(Path(pin[1]).read_text())
    for mutation in ("conflict","omission"):
        altered = json.loads(json.dumps(value))
        if mutation == "conflict": altered["requests"][0]["subject_id"] = str(uuid.uuid4())
        else: altered["requests"] = []; altered["fences"] = []
        path = recovery.tmp/(mutation+".json"); path.write_text(json.dumps(altered))
        bad = [*pin]; bad[1] = str(path); bad[3] = "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
        assert recovery.gate(pin=bad,apply=True).returncode != 0
    with recovery.restored(dump) as target:
        # Fail AFTER the first subject has been scrubbed, inside the same TX.
        fail_subject = value["requests"][-1]["subject_id"]
        with psycopg.connect(raw(target)) as conn:
            baseline = conn.execute("SELECT count(*) FROM kernel.audit_events").fetchone()
            conn.execute(sql.SQL("""CREATE FUNCTION kernel.restore_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.subject_id={}::uuid AND NEW.content_erased_at IS NOT NULL THEN
                RAISE EXCEPTION 'synthetic restore fault'; END IF; RETURN NEW; END $$""").format(sql.Literal(fail_subject)))
            conn.execute("CREATE TRIGGER restore_test_fault BEFORE UPDATE ON kernel.privacy_erasure_requests FOR EACH ROW EXECUTE FUNCTION kernel.restore_test_fault()")
        failed = recovery.gate(target,pin=pin,apply=True)
        assert failed.returncode != 0
        with psycopg.connect(raw(target)) as conn:
            assert conn.execute("SELECT count(*) FROM kernel.actions WHERE octet_length(canonical_request)>0").fetchone() == (2,)
            assert conn.execute("SELECT count(*) FROM kernel.privacy_erasure_requests").fetchone() == (0,)
            assert conn.execute("SELECT count(*) FROM kernel.privacy_destination_fences").fetchone() == (0,)
            assert conn.execute("SELECT count(*) FROM kernel.audit_events").fetchone() == baseline
            conn.execute("DROP TRIGGER restore_test_fault ON kernel.privacy_erasure_requests")
        passed = recovery.gate(target,pin=pin,apply=True)
        assert passed.returncode == 0, (passed.stdout,passed.stderr)


def test_account_erasure_replay_restores_revocation_without_blocking_other_user(recovery):
    tid,uid,cid,other = (str(uuid.uuid4()) for _ in range(4))
    with recovery.client() as client:
        assert recovery.propose(client,tid,uid,cid).status_code in {202,403}
        dump = recovery.backup()
        service = str(uuid.uuid5(uuid.NAMESPACE_URL,f"mk:privacy-erasure:{tid}"))
        erased = recovery.call(client,tid,service,"/privacy/erase",{
            "request_id":str(uuid.uuid4()),"subject_kind":"account","subject_id":uid},("privacy_eraser",))
        assert erased.status_code == 201 and erased.body["active_content_erased"]
    pin = recovery.export()
    with recovery.restored(dump) as target:
        applied = recovery.gate(target,pin=pin,apply=True)
        assert applied.returncode == 0, (applied.stdout,applied.stderr)
        with psycopg.connect(raw(target)) as conn:
            assert conn.execute("SELECT count(*) FROM kernel.revocations WHERE tenant_id=%s AND kind='user' AND user_id=%s",(tid,uid)).fetchone() == (1,)
        with recovery.client(target) as client:
            denied = recovery.propose(client,tid,uid,cid)
            assert denied.status_code == 401 and denied.body["code"] == "PRINCIPAL_REVOKED"
            allowed = recovery.propose(client,tid,other,str(uuid.uuid4()),"+15555550109")
            assert allowed.status_code in {202,403} and "result" in allowed.body


def test_restore_gate_requires_independently_retained_erasure_ledger(database):
    api = Path(os.environ["MK_PRIVACY_KERNEL_BINARY"]).resolve(strict=True)
    gate = api.with_name("mk-restore-gate")
    assert gate.is_file()
    env={k:v for k,v in os.environ.items() if not k.startswith(("MK_","RUST_ACTION_"))}
    env.update(MK_DATABASE_URL=raw(database),MK_MASTER_KEY=base64.b64encode(os.urandom(32)).decode(),
        MK_ASSERTION_KEYS="privacy-restore="+AssertionMinter.generate("privacy-restore").public_key_b64url(),
        MK_APPROVAL_RP_ID="localhost",MK_APPROVAL_ORIGINS="http://localhost:8000",
        RUST_ACTION_KERNEL_ENABLED="1",RUST_LOG="warn")
    subprocess.run([str(api)],env={**env,"MK_MIGRATE_ONLY":"1"},check=True,capture_output=True,timeout=30)
    with psycopg.connect(raw(database)) as conn:
        conn.execute("UPDATE kernel.kill_switches SET dispatch_enabled=false WHERE scope='global'")
    result=subprocess.run([str(gate),"--restored-at",datetime.now(timezone.utc).isoformat()],
        env=env,capture_output=True,text=True,timeout=30)
    records=[json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert records, "restore gate produced no structured checks"
    assert result.returncode != 0, f"restore gate passed without the external post-backup erasure ledger: {records}"
    assert any(row.get("check")=="privacy_restore_ledger" and row.get("ok") is False for row in records)
