"""S12: caller-controlled business text must not enter permanent audit records."""
import uuid
import pytest

from sqlalchemy import select
from .conftest import signup, auth_headers
from .test_foundation import _customer, kernel_env, kernel_ok, CONSENT  # noqa: F401


def audit_details(tenant):
    from app import db as dbmod
    from app.models import AuditLog
    with dbmod._SessionLocal() as db:
        return "\n".join(db.scalars(select(AuditLog.detail).where(AuditLog.tenant_id==tenant)))


def test_member_email_is_not_audit_metadata(client):
    token=signup(client,email=f"admin-{uuid.uuid4().hex}@example.com")
    canary=f"audit-person-{uuid.uuid4().hex}@example.com"
    result=client.post("/api/auth/members",headers=auth_headers(token),json={"email":canary,"password":"synthetic-password-123"})
    assert result.status_code==201
    assert canary not in audit_details(token["tenant_id"])


def test_source_provenance_stays_in_business_record_not_audit(client):
    token=signup(client,email=f"admin-{uuid.uuid4().hex}@example.com")
    canary="PRIVATE-SOURCE-"+uuid.uuid4().hex
    result=client.post("/api/knowledge/sources",headers=auth_headers(token),json={
        "title":"Synthetic evidence","source_reference":"https://example.invalid/?customer="+canary,
        "source_version":canary,"content_sha256":"a"*64})
    assert result.status_code==201,result.text
    assert canary not in audit_details(token["tenant_id"])


@pytest.mark.parametrize("key",["email","EMAIL","access_token","reason","source_reference","claims_used"])
def test_nested_raw_personal_data_is_rejected_by_audit_boundary(client,key):
    from app import db as dbmod
    from app.foundation import audit
    token=signup(client,email=f"admin-{uuid.uuid4().hex}@example.com")
    user_id=client.get("/api/auth/me",headers=auth_headers(token)).json()["id"]
    with dbmod._SessionLocal() as db:
        with pytest.raises((ValueError,RuntimeError)):
            audit(db,token["tenant_id"],user_id,"synthetic.nested",{"metadata":[{key:"private@example.invalid"}]})


def test_claim_identifiers_and_content_stay_in_business_records(client):
    token=signup(client,email=f"admin-{uuid.uuid4().hex}@example.com")
    h=auth_headers(token)
    canary="PRIVATE-CLAIM-"+uuid.uuid4().hex
    source=client.post("/api/knowledge/sources",headers=h,json={"title":"Synthetic evidence",
        "source_reference":"test","source_version":"test","content_sha256":"a"*64})
    assert source.status_code==201,source.text
    result=client.post("/api/knowledge/claims",headers=h,json={"source_id":source.json()["id"],
        "claim_id":canary,"product_id":canary,"approved_text":canary})
    assert result.status_code==201,result.text
    assert canary not in audit_details(token["tenant_id"])


def test_revocation_and_suppression_reasons_stay_in_business_records(client,kernel_env):
    token=signup(client,email=f"admin-{uuid.uuid4().hex}@example.com")
    h=auth_headers(token)
    canary="PRIVATE-PREFERENCE-"+uuid.uuid4().hex
    cid,did,_=_customer(client,h)
    with kernel_ok():
        consent=client.post(f"/api/customers/{cid}/consent",headers=h,json={**CONSENT,"destination_id":did})
        assert consent.status_code==201,consent.text
        revoked=client.post(f"/api/customers/{cid}/consent/{consent.json()['id']}/revoke",headers=h,json={"reason":canary})
        assert revoked.status_code==200,revoked.text
        suppressed=client.post("/api/suppressions",headers=h,json={"destination_id":did,"reason":canary,"source":"consultant"})
        assert suppressed.status_code==201,suppressed.text
    assert canary not in audit_details(token["tenant_id"])


def test_commitment_provenance_stays_in_business_record(client):
    token=signup(client,email=f"admin-{uuid.uuid4().hex}@example.com")
    h=auth_headers(token)
    cid,_,_=_customer(client,h)
    canary="PRIVATE-COMMITMENT-"+uuid.uuid4().hex
    result=client.post("/api/commitments",headers=h,json={"customer_id":cid,"text":"Call back",
        "evidence_text":"Please call me back","source_reference":canary})
    assert result.status_code==201,result.text
    assert canary not in audit_details(token["tenant_id"])
