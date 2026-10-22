"""Synthetic canaries through the real signed HTTP kernel entrypoints."""
import json
import asyncio
import uuid
import base64
import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone

import httpx
import psycopg
import pytest
from psycopg import sql
from test_app_database import database, raw  # noqa: F401
from test_kernel_privacy_restore import recovery  # noqa: F401


@pytest.mark.parametrize("surface",["suppression_reason","permission_scope"])
def test_business_text_never_enters_kernel_audit(recovery,surface):
    tid,uid,cid=(str(uuid.uuid4()) for _ in range(3))
    canary="SYNTHETIC-PRIVATE-PERSON-"+uuid.uuid4().hex
    with recovery.client() as client:
        if surface=="suppression_reason":
            result=recovery.call(client,tid,uid,"/suppressions",{
                "channel":"sms","destination":"+15555550100","reason":canary,"source":"test","permanent":True},("consultant",))
        else:
            now=datetime.now(timezone.utc)
            result=recovery.call(client,tid,uid,f"/contacts/{cid}/permissions",{
                "channel":"sms","destination":"+15555550100","scope":[canary],"source":"test",
                "proof_digest":"sha256:"+"a"*64,"granted_at":now.isoformat(),
                "expires_at":(now+timedelta(days=1)).isoformat()},("consultant",))
        assert result.status_code==201,result.body
    with psycopg.connect(raw(recovery.database)) as conn:
        rows=conn.execute("SELECT payload_redacted FROM kernel.audit_events WHERE tenant_id=%s",(tid,)).fetchall()
        assert rows
        assert canary not in json.dumps(rows)


def test_caller_correlation_text_is_not_permanent_audit_metadata(recovery):
    tid,uid=(str(uuid.uuid4()) for _ in range(2))
    canary="SYNTHETIC-PRIVATE-TRACE-"+uuid.uuid4().hex
    with recovery.client() as client:
        result=asyncio.run(client.call("POST","/suppressions",user_id=uid,tenant_id=tid,
            roles=["consultant"],session_id="audit-test",request_id=canary,
            json={"channel":None,"destination":None,"reason":"test","source":"test","permanent":True}))
        assert result.status_code==201,result.body
    with psycopg.connect(raw(recovery.database)) as conn:
        rows=conn.execute("SELECT trace_id,payload_redacted FROM kernel.audit_events WHERE tenant_id=%s",(tid,)).fetchall()
        assert rows and canary not in json.dumps(rows)


def test_uuid_correlation_survives_audit_redaction(recovery):
    tid,uid,trace=(str(uuid.uuid4()) for _ in range(3))
    with recovery.client() as client:
        result=asyncio.run(client.call("POST","/suppressions",user_id=uid,tenant_id=tid,
            roles=["consultant"],session_id="audit-test",request_id=trace,
            json={"channel":None,"destination":None,"reason":"test","source":"test","permanent":True}))
        assert result.status_code==201,result.body
    with psycopg.connect(raw(recovery.database)) as conn:
        assert conn.execute("SELECT trace_id FROM kernel.audit_events WHERE tenant_id=%s",(tid,)).fetchall()==[(trace,)]


@pytest.mark.parametrize("surface",["unmatched","matched","erased"])
def test_signed_provider_callback_canaries_do_not_enter_audit(recovery,surface):
    tid,uid,cid=(str(uuid.uuid4()) for _ in range(3))
    canary="SYNTHETIC-PRIVATE-PROVIDER-"+uuid.uuid4().hex
    token=uuid.uuid4().hex
    account,message="AC"+uuid.uuid4().hex,"SM"+uuid.uuid4().hex
    recovery.env["MK_PUBLIC_WEBHOOK_BASE"]="https://example.invalid"
    with recovery.client() as client:
        sender=recovery.call(client,tid,uid,"/senders",{"owner_user_id":uid,
            "display_name":"Synthetic audit test","account_sid":account,"auth_token":token,
            "from_number":"+15555550101"},("tenant_admin",))
        assert sender.status_code==201,sender.body
        sid=sender.body["sender_identity_id"]
        if surface!="unmatched":
            proposed=recovery.propose(client,tid,uid,cid)
            assert proposed.status_code in (202,403),proposed.body
            aid=proposed.body["result"]["action_id"]
            with psycopg.connect(raw(recovery.database)) as conn:
                conn.execute("""INSERT INTO kernel.message_deliveries(tenant_id,action_id,attempt,
                    sender_identity_id,provider,provider_message_id,state,submission_started_at)
                    VALUES(%s,%s,1,%s,'twilio',%s,'delivered',now())""",(tid,aid,sid,message))
            if surface=="erased":
                assert recovery.erase(client,tid,cid)[1]["active_content_erased"]
        path=f"/webhooks/twilio/status/{sid}"
        form={"AccountSid":account,"MessageSid":message,"MessageStatus":canary,"ErrorCode":canary}
        signed="https://example.invalid"+path+"".join(k+v for k,v in sorted(form.items()))
        signature=base64.b64encode(hmac.new(token.encode(),signed.encode(),hashlib.sha1).digest()).decode()
        result=httpx.post(client.base_url+path,data=form,headers={"X-Twilio-Signature":signature})
        assert result.status_code==200,result.text
    with psycopg.connect(raw(recovery.database)) as conn:
        rows=conn.execute("SELECT payload_redacted FROM kernel.audit_events WHERE tenant_id=%s",(tid,)).fetchall()
        assert rows and canary not in json.dumps(rows)
    assert canary not in "\n".join(path.read_text() for path in recovery.tmp.glob("api-*.log"))


def test_adapter_descriptions_and_credentials_stay_out_of_audit(recovery):
    tid,uid=(str(uuid.uuid4()) for _ in range(2))
    canary="SYNTHETIC-PRIVATE-ADAPTER-"+uuid.uuid4().hex
    with recovery.client() as client:
        result=recovery.call(client,tid,uid,"/adapters",{"agent_id":canary,"name":canary,
            "platform":canary,"version":"1","capabilities":[canary],"allowed_actions":["send_sms"],
            "callback_authority":"127.0.0.1:8787"},("tenant_admin",))
        assert result.status_code==201,result.body
    with psycopg.connect(raw(recovery.database)) as conn:
        rows=conn.execute("SELECT payload_redacted FROM kernel.audit_events WHERE tenant_id=%s",(tid,)).fetchall()
        assert rows and canary not in json.dumps(rows)
        assert result.body["enrollment_secret"] not in json.dumps(rows)


def test_rejected_tool_identifier_never_enters_audit(recovery):
    tid,uid,cid=(str(uuid.uuid4()) for _ in range(3))
    canary="synthetic_private_person_"+uuid.uuid4().hex+".v1"
    with recovery.client() as client:
        result=recovery.propose(client,tid,uid,cid,tool_id=canary)
        assert result.status_code==403,result.body
    with psycopg.connect(raw(recovery.database)) as conn:
        rows=conn.execute("SELECT actor_id,payload_redacted FROM kernel.audit_events WHERE tenant_id=%s",(tid,)).fetchall()
        assert rows and canary not in json.dumps(rows)


def test_device_callback_actor_and_error_are_not_freeform_audit_text(recovery):
    tid,uid,cid=(str(uuid.uuid4()) for _ in range(3))
    canary="synthetic_private_person_"+uuid.uuid4().hex
    with recovery.client() as client:
        adapter=recovery.call(client,tid,uid,"/adapters",{"agent_id":canary,"name":"Synthetic test",
            "platform":"test","version":"1","capabilities":[],"allowed_actions":["send_sms"],
            "callback_authority":"127.0.0.1:8787"},("tenant_admin",))
        assert adapter.status_code==201,adapter.body
        proposed=recovery.propose(client,tid,uid,cid,arguments={"contact_id":cid,"to":"+15555550100",
            "rendered_text":"Synthetic fixture. Reply STOP to opt out.","agent_id":canary})
        assert proposed.status_code==403,proposed.body
        aid=proposed.body["result"]["action_id"]
        # Synthetic dispatch state for receipt acceptance; no device was sent work.
        with psycopg.connect(raw(recovery.database)) as conn:
            conn.execute("UPDATE kernel.actions SET state='dispatching',attempt=1 WHERE action_id=%s",(aid,))
        body=json.dumps({"schema":"consultant-studio.mobile-execution-failure.v1","status":"failed",
            "result":{},"error_code":canary},separators=(",",":"))
        path=f"/adapter/v1/work-orders/{uuid.UUID(aid).hex}/callbacks"
        timestamp,nonce=str(int(time.time())),uuid.uuid4().hex
        signed="\n".join(["POST",path,timestamp,nonce,hashlib.sha256(body.encode()).hexdigest()])
        signature=hmac.new(adapter.body["enrollment_secret"].encode(),signed.encode(),hashlib.sha256).hexdigest()
        result=httpx.post(client.base_url+path,content=body,headers={"Content-Type":"application/json",
            "x-mobile-agent":canary,"x-mobile-tenant":tid,"x-mobile-timestamp":timestamp,
            "x-mobile-nonce":nonce,"x-mobile-signature":signature})
        assert result.status_code==200,result.text
        assert result.json()=={"applied":True,"state":"failed_final"}
    with psycopg.connect(raw(recovery.database)) as conn:
        rows=conn.execute("SELECT actor_id,payload_redacted FROM kernel.audit_events WHERE tenant_id=%s",(tid,)).fetchall()
        assert rows and canary not in json.dumps(rows)
    assert canary not in "\n".join(path.read_text() for path in recovery.tmp.glob("api-*.log"))


def test_database_failure_does_not_expose_driver_detail_in_logs_or_response(recovery):
    tid,uid,cid=(str(uuid.uuid4()) for _ in range(3))
    canary="SYNTHETIC-PRIVATE-DB-"+uuid.uuid4().hex
    with psycopg.connect(raw(recovery.database)) as conn:
        conn.execute(sql.SQL("""CREATE FUNCTION kernel.audit_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION '%',{}; END $$""").format(sql.Literal(canary)))
        conn.execute("CREATE TRIGGER audit_test_fault BEFORE INSERT ON kernel.actions FOR EACH ROW EXECUTE FUNCTION kernel.audit_test_fault()")
    with recovery.client() as client:
        result=recovery.propose(client,tid,uid,cid)
        assert result.status_code==500,result.body
        assert canary not in json.dumps(result.body)
    logs="\n".join(path.read_text() for path in recovery.tmp.glob("api-*.log"))
    assert "store error" in logs
    assert canary not in logs
