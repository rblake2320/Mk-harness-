"""P2: reviewed fact conflicts block drafting without asking the model to choose."""
import uuid
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import respx
from jsonschema import Draft202012Validator
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from app.drafting import live_claims
from app import db as dbmod
from app.models import ApprovedClaim, Base, ClaimFact, KnowledgeSource, Tenant

from .test_commitments_brief import _user_with_key
from .test_drafting import _model
from .test_foundation import _customer, kernel_env  # noqa: F401


def reviewed_claim(client, headers, fact_value, *, product="cream", market="US", facts=True):
    tag = uuid.uuid4().hex[:10]
    source = client.post("/api/knowledge/sources", headers=headers, json={
        "title": "Controlled product fixture", "source_reference": f"fixture-{tag}",
        "source_version": tag, "content_sha256": "a" * 64, "market": market}).json()
    assert client.post(f"/api/knowledge/sources/{source['id']}/review", headers=headers,
                       json={"decision": "approved", "reviewer": "reviewer-fixture"}).status_code == 200
    claim = client.post("/api/knowledge/claims", headers=headers, json={
        "claim_id": f"cream.fragrance.{tag}", "product_id": product, "source_id": source["id"],
        "market": market, "approved_text": f"This cream {'contains fragrance' if fact_value == 'present' else 'is fragrance-free'}."}).json()
    review = {"decision": "approved", "reviewer": "reviewer-fixture"}
    if facts:
        review["facts"] = {"composition.fragrance": fact_value}
    response = client.post(f"/api/knowledge/v2/claims/{claim['id']}/review", headers=headers, json=review)
    return claim, response


@respx.mock
def test_two_approved_contradictory_claims_block_before_model(client):
    h = _user_with_key(client)
    a, ar = reviewed_claim(client, h, "present")
    b, br = reviewed_claim(client, h, "absent")
    assert ar.status_code == br.status_code == 200
    cid, _, _ = _customer(client, h, phone="+15555559011")
    # The old implementation called the model and accepted either approved claim.
    model = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=_model("Hi Angela! {claim:" + a["claim_id"] + "} Reply STOP to opt out.", [a["claim_id"]]))
    response = client.post("/api/drafts", headers=h, json={"customer_id": cid, "product_ids": ["cream"]})
    assert response.status_code == 201
    body = response.json()
    assert body["draft"] is None and "conflict" in body["limitation"].lower()
    assert body["review_task_id"] and body["neutral_text"].endswith("Reply STOP to opt out.")
    assert not model.called
    assert client.get("/api/knowledge/claims?product_id=cream", headers=h).json() == []
    # Withdrawing the conflicting claim restores the remaining reviewed fact.
    assert client.post(f"/api/knowledge/claims/{b['id']}/review", headers=h,
                       json={"decision": "withdrawn", "reviewer": "reviewer-fixture"}).status_code == 200
    assert [x["claim_id"] for x in client.get("/api/knowledge/claims?product_id=cream", headers=h).json()] == [a["claim_id"]]


def test_conflict_scope_is_product_market_and_visible_tenant(client):
    h, other = _user_with_key(client), _user_with_key(client)
    a, response = reviewed_claim(client, h, "present")
    assert response.status_code == 200
    reviewed_claim(client, h, "absent", product="other")
    reviewed_claim(client, h, "absent", market="CA")
    reviewed_claim(client, other, "absent")
    same, response = reviewed_claim(client, h, "present")
    assert response.status_code == 200
    assert {x["claim_id"] for x in client.get("/api/knowledge/claims?product_id=cream", headers=h).json()} == {a["claim_id"], same["claim_id"]}


def test_unannotated_claim_cannot_be_approved(client):
    h = _user_with_key(client)
    _, response = reviewed_claim(client, h, "present", facts=False)
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "CLAIM_FACTS_REQUIRED"


def test_v1_review_is_compatible_but_cannot_inherit_v2_eligibility(client):
    h = _user_with_key(client)
    claim, response = reviewed_claim(client, h, "present")
    assert response.status_code == 200
    legacy = client.post(f"/api/knowledge/claims/{claim['id']}/review", headers=h,
                         json={"decision": "approved", "reviewer": "legacy-reviewer"})
    assert legacy.status_code == 200 and legacy.json()["review_status"] == "approved"
    assert legacy.json()["facts_review_required"] is True
    assert client.get("/api/knowledge/claims?product_id=cream", headers=h).json() == []


@pytest.mark.parametrize("facts", [{}, {"Composition.Fragrance": "present"}, {"composition.fragrance": " "},
                                  {"composition.fragrance": "x" * 121}, {f"fact{i}": "v" for i in range(17)}])
def test_v2_review_rejects_unbounded_or_noncanonical_facts(client, facts):
    h = _user_with_key(client)
    claim, _ = reviewed_claim(client, h, "present")
    response = client.post(f"/api/knowledge/v2/claims/{claim['id']}/review", headers=h,
                           json={"decision": "approved", "reviewer": "reviewer", "facts": facts})
    assert response.status_code == 422


def test_additive_legacy_database_migration_preserves_but_withholds_old_claim(tmp_path):
    engine = create_engine("sqlite:///" + (tmp_path / "legacy.db").as_posix())
    Base.metadata.create_all(engine, tables=[t for t in Base.metadata.sorted_tables if t.name != "claim_facts"])
    assert "claim_facts" not in inspect(engine).get_table_names()
    with Session(engine) as db:
        tenant = Tenant(name="Migration fixture")
        db.add(tenant); db.flush()
        source = KnowledgeSource(tenant_id=tenant.id, title="Legacy source", source_reference="source",
                                 source_version="v1", content_digest="sha256:" + "a" * 64,
                                 effective_at=datetime(2020, 1, 1, tzinfo=timezone.utc), review_status="approved")
        db.add(source); db.flush()
        claim = ApprovedClaim(tenant_id=tenant.id, claim_id="legacy.v1", product_id="cream",
                              approved_text="This cream contains fragrance.", source_id=source.id,
                              source_reference="source", source_version="v1", market="US",
                              effective_at=datetime(2020, 1, 1, tzinfo=timezone.utc), review_status="approved")
        db.add(claim); db.flush()
        tid, cid = tenant.id, claim.id
        db.commit()
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        claim = db.get(ApprovedClaim, cid)
        assert claim.approved_text == "This cream contains fragrance." and claim.review_status == "approved"
        assert live_claims(db, tid, ["cream"]) == []
        db.add(ClaimFact(claim_row_id=cid, name="composition.fragrance", value="present"))
        db.commit()
        assert [c.claim_id for c in live_claims(db, tid, ["cream"])] == ["legacy.v1"]
    engine.dispose()


def test_v2_review_contract_has_positive_and_negative_controls():
    schema = json.loads((Path(__file__).resolve().parents[2] / "contracts/knowledge/v2/claim-review.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.validate({"decision": "approved", "reviewer": "reviewer", "facts": {"composition.fragrance": "present"}})
    validator.validate({"decision": "withdrawn", "reviewer": "reviewer"})
    assert list(validator.iter_errors({"decision": "approved", "reviewer": "reviewer"}))
    assert list(validator.iter_errors({"decision": "approved", "reviewer": "reviewer", "facts": {}}))


@respx.mock
def test_one_available_product_does_not_hide_a_missing_requested_product(client):
    h = _user_with_key(client)
    reviewed_claim(client, h, "present")
    cid, _, _ = _customer(client, h, phone="+15555559013")
    response = client.post("/api/drafts", headers=h,
                           json={"customer_id": cid, "product_ids": ["cream", "missing"]})
    assert response.status_code == 201 and response.json()["draft"] is None
    assert response.json()["review_task_id"]
    assert len(respx.calls) == 0


@respx.mock
def test_conflict_appearing_during_model_call_is_rechecked(client):
    h = _user_with_key(client)
    a, _ = reviewed_claim(client, h, "present")
    b, _ = reviewed_claim(client, h, "absent")
    client.post(f"/api/knowledge/claims/{b['id']}/review", headers=h,
                json={"decision": "withdrawn", "reviewer": "reviewer"})
    cid, _, _ = _customer(client, h, phone="+15555559014")
    def concurrent_review(request):
        with dbmod._SessionLocal() as db:
            db.get(ApprovedClaim, b["id"]).review_status = "approved"
            db.commit()
        return _model("Hi Angela! {claim:" + a["claim_id"] + "} Reply STOP to opt out.", [a["claim_id"]])
    respx.post("https://api.anthropic.com/v1/messages").mock(side_effect=concurrent_review)
    response = client.post("/api/drafts", headers=h, json={"customer_id": cid, "product_ids": ["cream"]})
    assert response.status_code == 201
    assert response.json()["draft"] is None and "conflict" in response.json()["limitation"].lower()


@respx.mock
def test_existing_draft_is_rechecked_before_proposal_and_edit(client, kernel_env):
    h = _user_with_key(client)
    a, response = reviewed_claim(client, h, "present")
    assert response.status_code == 200
    cid, _, _ = _customer(client, h, phone="+15555559012")
    client.put(f"/api/customers/{cid}/preferences", headers=h, json={"timezone": "America/Chicago"})
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=_model("Hi Angela! {claim:" + a["claim_id"] + "} Reply STOP to opt out.", [a["claim_id"]]))
    draft = client.post("/api/drafts", headers=h, json={"customer_id": cid, "product_ids": ["cream"]}).json()["draft"]
    assert draft
    reviewed_claim(client, h, "absent")
    before = len(respx.calls)
    proposed = client.post(f"/api/drafts/{draft['id']}/propose", headers=h, json={})
    assert proposed.status_code == 409 and proposed.json()["detail"]["code"] == "DRAFT_CLAIMS_CHANGED"
    assert len(respx.calls) == before  # no kernel request made
    edited = client.post(f"/api/drafts/{draft['id']}/edit", headers=h, json={"text": draft["text"]})
    assert edited.status_code == 422 and edited.json()["detail"]["code"] == "CLAIM_CONFLICT"
