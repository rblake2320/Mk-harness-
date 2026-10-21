"""WP03 — customer & permission foundation (matrix rows F1–F9).

Proves:
  F2/F8  an imported number is not permission; import mapping cannot set consent;
         consent needs evidence and is attributed; revoked consent is not restored by import
  F3     editing a profile / adding a destination cannot erase suppression;
         suppressed destination refuses new consent
  F4     permission view is labelled historical; execution re-checks kernel (consent write
         fails closed when the kernel is down — nothing recorded locally)
  F5     import preview/commit/rollback, duplicates (in-file and vs existing), row errors,
         provenance, idempotency, formula-escaped export, rollback keeps referenced records
  F7     cross-tenant isolation on every new route (404), incl. import jobs and destinations
  F9     unknown timezone blocks send_sms proposals before the kernel; known tz passes
  fingerprint parity with the kernel's destination hash
"""
import base64
import hashlib
import hmac
import json
import uuid

import httpx
import pytest
import respx

from app.config import get_settings
from app.foundation import fingerprint, normalize
from app.kernel import get_kernel_client
from app.kernel.assertions import AssertionMinter

from .conftest import auth_headers, signup
from .test_agent_ops import KERNEL, MINTER, sms_request, verify_assertion


@pytest.fixture
def kernel_env(monkeypatch):
    monkeypatch.setenv("RUST_ACTION_KERNEL_URL", KERNEL)
    monkeypatch.setenv("KERNEL_ASSERTION_PRIVATE_KEY",
                       base64.urlsafe_b64encode(MINTER._key.private_bytes_raw()).rstrip(b"=").decode())
    monkeypatch.setenv("KERNEL_ASSERTION_KID", "k-test")
    get_settings.cache_clear(); get_kernel_client.cache_clear()
    yield
    get_settings.cache_clear(); get_kernel_client.cache_clear()


def _user(client, tag=None):
    tag = tag or uuid.uuid4().hex[:6]
    tok = signup(client, org=f"Org {tag}", email=f"u-{tag}@example.com")
    return auth_headers(tok)


def _customer(client, h, name="Angela", phone="+15555550100"):
    r = client.post("/api/customers", json={"name": name, "phone": phone}, headers=h)
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    d = client.post(f"/api/customers/{cid}/destinations", json={"channel": "sms", "value": phone}, headers=h)
    assert d.status_code == 201, d.text
    return cid, d.json()["id"], d.json()["fingerprint"]


def kernel_ok():
    m = respx.mock(assert_all_called=False)
    m.post(url__regex=rf"{KERNEL}/internal/v1/contacts/.*/permissions$").mock(
        side_effect=lambda req: (verify_assertion(req), httpx.Response(201, json={"id": str(uuid.uuid4())}))[1])
    m.post(url__regex=rf"{KERNEL}/internal/v1/contacts/.*/permissions/.*/revoke$").mock(
        return_value=httpx.Response(200, json={"id": "x", "revoked": True}))
    m.post(f"{KERNEL}/internal/v1/suppressions").mock(
        return_value=httpx.Response(201, json={"id": str(uuid.uuid4())}))
    m.post(f"{KERNEL}/internal/v1/actions").mock(return_value=httpx.Response(202, json={"ok": True}))
    return m


CONSENT = {"purposes": ["customer_requested_follow_up"], "source": "web_form",
           "evidence_type": "form_submission", "evidence_text": "I agree to texts about my orders."}


# --------------------------------------------------------------------------- #
# Fingerprint parity with the kernel
# --------------------------------------------------------------------------- #
def test_fingerprint_matches_kernel_destination_hash(kernel_env):
    s = get_settings()
    tenant = uuid.uuid4().hex
    norm = normalize("sms", "(555) 555-0100")
    assert norm == "+15555550100"
    expected = hmac.new(s.master_key_bytes, f"{uuid.UUID(tenant)}|sms|{norm}".encode(), hashlib.sha256).hexdigest()
    assert fingerprint(tenant, "sms", norm) == expected
    assert normalize("email", "  Angela@Example.COM ") == "angela@example.com"
    with pytest.raises(Exception):
        normalize("sms", "555-0100")


# --------------------------------------------------------------------------- #
# F2 / F8 — permission needs evidence; import never grants it
# --------------------------------------------------------------------------- #
def test_imported_number_is_not_permission(client, kernel_env):
    h = _user(client)
    with kernel_ok():
        job = client.post("/api/customers/import/preview", json={
            "idempotency_key": "imp-" + uuid.uuid4().hex, "mapping": {"name": "Name", "phone": "Phone"},
            "csv_text": "Name,Phone\nAngela,555-555-0100\n"}, headers=h).json()
        client.post(f"/api/customers/import/{job['job_id']}/commit", headers=h)
        cid = client.get(f"/api/customers/import/{job['job_id']}", headers=h).json()["rows"][0]["customer_id"]
        view = client.get(f"/api/customers/{cid}/permissions", headers=h).json()
    assert view["consent_events"] == []
    assert "historical" in view["note"]
    assert job["consent_note"].startswith("Imported contacts have NO outreach permission")


@pytest.mark.parametrize("target", ["consent", "consented", "opt_in", "permission", "suppressed"])
def test_import_mapping_cannot_set_consent_or_suppression(client, kernel_env, target):
    h = _user(client)
    r = client.post("/api/customers/import/preview", json={
        "idempotency_key": "imp-" + uuid.uuid4().hex, "mapping": {"name": "Name", target: "C"},
        "csv_text": "Name,C\nA,yes\n"}, headers=h)
    assert r.status_code == 422 and "evidence" in r.text


def test_consent_requires_evidence_and_is_attributed(client, kernel_env):
    h = _user(client)
    cid, did, fp = _customer(client, h)
    seen = {}
    with kernel_ok() as m:
        m.post(url__regex=rf"{KERNEL}/internal/v1/contacts/.*/permissions$").mock(
            side_effect=lambda req: (seen.update(c=verify_assertion(req), b=json.loads(req.content)),
                                     httpx.Response(201, json={"id": str(uuid.uuid4())}))[1])
        r = client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=h)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["evidence_digest"] == "sha256:" + hashlib.sha256(CONSENT["evidence_text"].encode()).hexdigest()
    assert seen["b"]["proof_digest"] == body["evidence_digest"]
    assert seen["b"]["scope"] == ["customer_requested_follow_up"]
    # missing evidence text → 422; import as source → 422; unknown purpose → 422
    bad = dict(CONSENT, destination_id=did); bad.pop("evidence_text")
    assert client.post(f"/api/customers/{cid}/consent", json=bad, headers=h).status_code == 422
    assert client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did, "source": "import"},
                       headers=h).status_code == 422
    assert client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did,
                                                               "purposes": ["marketing_blast"]}, headers=h).status_code == 422


def test_consent_fails_closed_when_kernel_down_and_records_nothing(client, kernel_env):
    h = _user(client)
    cid, did, fp = _customer(client, h)
    with respx.mock() as m:
        m.post(url__regex=rf"{KERNEL}/internal/v1/contacts/.*/permissions$").mock(side_effect=httpx.ConnectError("down"))
        r = client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=h)
    assert r.status_code == 503
    assert client.get(f"/api/customers/{cid}/permissions", headers=h).json()["consent_events"] == []


def test_kernel_denial_passes_through_and_records_nothing(client, kernel_env):
    h = _user(client)
    cid, did, fp = _customer(client, h)
    with respx.mock() as m:
        m.post(url__regex=rf"{KERNEL}/internal/v1/contacts/.*/permissions$").mock(
            return_value=httpx.Response(403, json={"code": "ROLE_REQUIRED"}))
        r = client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=h)
    assert r.status_code == 403 and r.json()["code"] == "ROLE_REQUIRED"
    assert client.get(f"/api/customers/{cid}/permissions", headers=h).json()["consent_events"] == []


def test_revoked_consent_is_not_restored_by_reimport(client, kernel_env):
    h = _user(client)
    cid, did, fp = _customer(client, h, phone="+15555550111")
    with kernel_ok():
        ev = client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=h).json()
        rv = client.post(f"/api/customers/{cid}/consent/{ev['id']}/revoke", json={"reason": "customer asked"}, headers=h)
        assert rv.status_code == 200 and rv.json()["status"] == "revoked"
        # Re-import the same number: duplicate, no new customer, no consent.
        job = client.post("/api/customers/import/preview", json={
            "idempotency_key": "imp-" + uuid.uuid4().hex, "mapping": {"name": "Name", "phone": "Phone"},
            "csv_text": "Name,Phone\nAngela,+15555550111\n"}, headers=h).json()
        assert job["duplicates"] == 1 and job["will_create"] == 0
        client.post(f"/api/customers/import/{job['job_id']}/commit", headers=h)
        view = client.get(f"/api/customers/{cid}/permissions", headers=h).json()
    assert [e["status"] for e in view["consent_events"]] == ["revoked"]


# --------------------------------------------------------------------------- #
# F3 — suppression survives profile edits; blocks new consent
# --------------------------------------------------------------------------- #
def test_suppression_survives_profile_edit_and_blocks_consent(client, kernel_env):
    h = _user(client)
    cid, did, fp = _customer(client, h, phone="+15555550122")
    with kernel_ok():
        s = client.post("/api/suppressions", json={"destination_id": did, "reason": "STOP", "source": "sms_reply"}, headers=h)
        assert s.status_code == 201 and s.json()["fingerprint"] == fp
        # Profile edit (name/phone/notes) cannot touch suppression.
        r = client.put(f"/api/customers/{cid}", json={"name": "Angela B", "phone": "+15555550122", "notes": "x"}, headers=h)
        assert r.status_code == 200
        dests = client.get(f"/api/customers/{cid}/destinations", headers=h).json()
        assert dests[0]["suppressed"] is True
        # New consent on the suppressed destination is refused.
        c = client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=h)
        assert c.status_code == 409 and c.json()["detail"]["code"] == "SUPPRESSED"
        # Re-adding the same number as a "new" destination returns the same suppressed destination.
        again = client.post(f"/api/customers/{cid}/destinations", json={"channel": "sms", "value": "555-555-0122"}, headers=h)
        assert again.json()["id"] == did


def test_suppression_revokes_active_consent_locally(client, kernel_env):
    h = _user(client)
    cid, did, fp = _customer(client, h, phone="+15555550133")
    with kernel_ok():
        client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=h)
        client.post("/api/suppressions", json={"destination_id": did, "reason": "complaint", "source": "complaint"}, headers=h)
        view = client.get(f"/api/customers/{cid}/permissions", headers=h).json()
    assert view["consent_events"][0]["status"] == "revoked"
    assert len(view["suppressions"]) == 1


# --------------------------------------------------------------------------- #
# F5 — import lifecycle
# --------------------------------------------------------------------------- #
CSV = "Name,Phone,Email,Notes\nAngela,555-555-0100,a@example.com,likes samples\nBea,+15555550101,,\nAngela Dup,5555550100,,\n,+15555550102,,\nNoContact,,,\nCara,bad-phone,,\n"


def test_import_preview_commit_rollback(client, kernel_env):
    h = _user(client)
    key = "imp-" + uuid.uuid4().hex
    body = {"idempotency_key": key, "filename": "book.csv", "csv_text": CSV,
            "mapping": {"name": "Name", "phone": "Phone", "email": "Email", "notes": "Notes"}}
    pv = client.post("/api/customers/import/preview", json=body, headers=h)
    assert pv.status_code == 201, pv.text
    j = pv.json()
    assert j["status"] == "preview" and j["row_count"] == 6
    assert j["will_create"] == 2 and j["duplicates"] == 1 and j["errors"] == 3
    statuses = {r["row"]: r["status"] for r in j["rows"]}
    assert statuses == {0: "create", 1: "create", 2: "duplicate", 3: "error", 4: "error", 5: "error"}
    assert j["source_digest"] == "sha256:" + hashlib.sha256(CSV.encode()).hexdigest()
    # idempotent preview
    assert client.post("/api/customers/import/preview", json=body, headers=h).json()["job_id"] == j["job_id"]
    # commit twice → same result
    c1 = client.post(f"/api/customers/import/{j['job_id']}/commit", headers=h).json()
    c2 = client.post(f"/api/customers/import/{j['job_id']}/commit", headers=h).json()
    assert c1["created_count"] == 2 == c2["created_count"]
    assert len(client.get("/api/customers", headers=h).json()) == 2
    # a second import of the same file creates nothing
    j2 = client.post("/api/customers/import/preview", json={**body, "idempotency_key": key + "-2"}, headers=h).json()
    assert j2["will_create"] == 0 and j2["duplicates"] == 3  # Angela, Bea, and the in-file dup
    # rollback removes the unreferenced two
    rb = client.post(f"/api/customers/import/{j['job_id']}/rollback", headers=h).json()
    assert rb["removed"] == 2 and rb["kept_referenced"] == []
    assert client.get("/api/customers", headers=h).json() == []
    assert client.post(f"/api/customers/import/{j['job_id']}/rollback", headers=h).status_code == 409


def test_rollback_keeps_customers_that_gained_consent(client, kernel_env):
    h = _user(client)
    body = {"idempotency_key": "imp-" + uuid.uuid4().hex, "csv_text": "Name,Phone\nAngela,+15555550144\nBea,+15555550145\n",
            "mapping": {"name": "Name", "phone": "Phone"}}
    with kernel_ok():
        j = client.post("/api/customers/import/preview", json=body, headers=h).json()
        rows = client.post(f"/api/customers/import/{j['job_id']}/commit", headers=h).json()["rows"]
        cid = rows[0]["customer_id"]
        did = client.get(f"/api/customers/{cid}/destinations", headers=h).json()[0]["id"]
        assert client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=h).status_code == 201
        rb = client.post(f"/api/customers/import/{j['job_id']}/rollback", headers=h).json()
    assert rb["removed"] == 1 and rb["kept_referenced"] == [cid]


def test_export_is_formula_escaped_and_masked(client, kernel_env):
    h = _user(client)
    _customer(client, h, name="=HYPERLINK(\"http://evil\")", phone="+15555550155")
    client.post("/api/customers", json={"name": "+cmd", "phone": "", "notes": "@SUM(1)"}, headers=h)
    r = client.get("/api/customers/export.csv", headers=h)
    assert r.status_code == 200
    text = r.text
    assert "'=HYPERLINK" in text and "'+cmd" in text and "'@SUM" in text
    assert "+15555550155" not in text and "0155" in text


# --------------------------------------------------------------------------- #
# F7 — cross-tenant isolation on every new route
# --------------------------------------------------------------------------- #
def test_cross_tenant_isolation(client, kernel_env):
    a, b = _user(client, "a" + uuid.uuid4().hex[:5]), _user(client, "b" + uuid.uuid4().hex[:5])
    cid, did, fp = _customer(client, a)
    with kernel_ok():
        job = client.post("/api/customers/import/preview", json={
            "idempotency_key": "imp-" + uuid.uuid4().hex, "mapping": {"name": "Name", "phone": "Phone"},
            "csv_text": "Name,Phone\nX,+15555550166\n"}, headers=a).json()
        ev = client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=a).json()
        for method, path, body in [
            ("GET", f"/api/customers/{cid}/destinations", None),
            ("POST", f"/api/customers/{cid}/destinations", {"channel": "sms", "value": "+15555550177"}),
            ("PUT", f"/api/customers/{cid}/preferences", {"timezone": "America/Chicago"}),
            ("POST", f"/api/customers/{cid}/consent", {**CONSENT, "destination_id": did}),
            ("POST", f"/api/customers/{cid}/consent/{ev['id']}/revoke", {"reason": "x"}),
            ("GET", f"/api/customers/{cid}/permissions", None),
            ("POST", "/api/suppressions", {"destination_id": did, "reason": "x", "source": "consultant"}),
            ("GET", f"/api/customers/import/{job['job_id']}", None),
            ("POST", f"/api/customers/import/{job['job_id']}/commit", None),
            ("POST", f"/api/customers/import/{job['job_id']}/rollback", None),
        ]:
            r = client.request(method, path, json=body, headers=b)
            assert r.status_code == 404, f"{method} {path} → {r.status_code}"
            r = client.request(method, path, json=body)
            assert r.status_code == 401, f"{method} {path} unauth → {r.status_code}"
    # Tenant B importing the same number is NOT a duplicate of A's (fingerprints are tenant-keyed).
    jb = client.post("/api/customers/import/preview", json={
        "idempotency_key": "imp-" + uuid.uuid4().hex, "mapping": {"name": "Name", "phone": "Phone"},
        "csv_text": "Name,Phone\nX,+15555550100\n"}, headers=b).json()
    assert jb["will_create"] == 1


# --------------------------------------------------------------------------- #
# F9 — unknown timezone blocks automated outreach before the kernel
# --------------------------------------------------------------------------- #
def test_unknown_timezone_blocks_send_until_set(client, kernel_env):
    h = _user(client)
    cid, did, fp = _customer(client, h, phone="+15555550188")
    req = sms_request(cid)
    req["arguments"]["agent_id"] = "moto-1"
    with kernel_ok() as m:
        r = client.post("/api/agent-ops/actions", json={"origin": "agent", "request": req}, headers=h)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "TIMEZONE_UNKNOWN"
        assert not m.routes[3].called  # nothing reached the kernel
        assert client.put(f"/api/customers/{cid}/preferences", json={"timezone": "Mars/Olympus"}, headers=h).status_code == 422
        p = client.put(f"/api/customers/{cid}/preferences", json={"timezone": "America/Chicago"}, headers=h)
        assert p.status_code == 200 and p.json()["dispatch_blocked_reason"] is None
        r = client.post("/api/agent-ops/actions", json={"origin": "agent", "request": req}, headers=h)
        assert r.status_code == 202
        # non-outreach kinds are not blocked by timezone
        up = dict(req, action_kind="update_contact", tool_id="crm.contact.update.v1", risk="low")
        up["arguments"] = {"contact_id": req["arguments"]["contact_id"], "fields": {"notes": "x"}}
        cid2, _, _ = _customer(client, h, name="NoTZ", phone="+15555550199")
        up["arguments"]["contact_id"] = str(uuid.UUID(cid2)); up["resource"]["id"] = str(uuid.UUID(cid2))
        assert client.post("/api/agent-ops/actions", json={"origin": "agent", "request": up}, headers=h).status_code == 202


def test_timezone_gate_covers_every_outreach_kind_and_trusts_only_resource_id(client, kernel_env):
    """Codex findings on WP03: the gate applied only to send_sms/send_dm and preferred
    arguments.contact_id over resource.id. Every outreach kind the kernel classifies as
    outreach is gated, the authoritative id is resource.id, and a proposal naming two
    different customers is refused instead of being checked against the convenient one."""
    h = _user(client)
    no_tz, _, _ = _customer(client, h, name="NoTZ", phone="+15555550177")
    with_tz, _, _ = _customer(client, h, name="HasTZ", phone="+15555550166")
    assert client.put(f"/api/customers/{with_tz}/preferences", json={"timezone": "America/Chicago"}, headers=h).status_code == 200
    with kernel_ok() as m:
        for kind, tool in (("send_email", "email.send.v1"), ("send_dm", "social.dm.send.v1"), ("mobile_work_order", "mobile.sms.send.v1")):
            req = sms_request(no_tz)
            req["action_kind"] = kind; req["tool_id"] = tool
            r = client.post("/api/agent-ops/actions", json={"origin": "agent", "request": req}, headers=h)
            assert r.status_code == 422 and r.json()["detail"]["code"] == "TIMEZONE_UNKNOWN", (kind, r.text)
        # resource.id is the customer without a timezone; arguments.contact_id names one with a timezone.
        req = sms_request(no_tz)
        req["arguments"]["contact_id"] = str(uuid.UUID(with_tz))
        r = client.post("/api/agent-ops/actions", json={"origin": "agent", "request": req}, headers=h)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "contact_mismatch", r.text
        # A customer this tenant does not have cannot have a known timezone: refused, not skipped.
        req = sms_request(uuid.uuid4().hex)
        r = client.post("/api/agent-ops/actions", json={"origin": "agent", "request": req}, headers=h)
        assert r.status_code == 404 and r.json()["detail"]["code"] == "customer_not_found", r.text
        # Outreach must name a contact resource at all.
        req = sms_request(with_tz); req["resource"] = {"type": "campaign", "id": str(uuid.uuid4())}
        r = client.post("/api/agent-ops/actions", json={"origin": "agent", "request": req}, headers=h)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "outreach_resource_required", r.text
        assert not m.routes[3].called


def test_suppression_channel_must_match_the_destination(client, kernel_env):
    """Codex finding: channel=email on an SMS destination filed the phone fingerprint under
    email (locally and in the kernel) and left the number contactable. Refused now."""
    h = _user(client)
    cid, did, fp = _customer(client, h, phone="+15555550144")
    with kernel_ok() as m:
        r = client.post("/api/suppressions", json={"destination_id": did, "channel": "email", "reason": "STOP", "source": "sms_reply"}, headers=h)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "channel_mismatch", r.text
        assert not m.routes[2].called, "nothing reached the kernel"
        r = client.post("/api/suppressions", json={"destination_id": did, "channel": "sms", "reason": "STOP", "source": "sms_reply"}, headers=h)
        assert r.status_code == 201 and r.json()["channel"] == "sms" and r.json()["fingerprint"] == fp


def test_import_keeps_notes_and_dedupes_email_only_rows(client, kernel_env):
    """Codex findings: mapped notes were discarded at commit; email-only rows were never
    deduplicated (in-file or against existing customers)."""
    h = _user(client)
    # An existing email-only customer.
    r = client.post("/api/customers", json={"name": "Existing", "phone": ""}, headers=h)
    assert r.status_code == 201, r.text
    assert client.post(f"/api/customers/{r.json()['id']}/destinations", json={"channel": "email", "value": "Existing@Example.com"}, headers=h).status_code == 201
    csv_text = "Name,Email,Notes\nA,a@example.com,likes matte\nA again,A@EXAMPLE.COM,dup in file\nE,existing@example.com,already a customer\nB,b@example.com,\n"
    j = client.post("/api/customers/import/preview", json={"idempotency_key": "imp-" + uuid.uuid4().hex,
                    "mapping": {"name": "Name", "email": "Email", "notes": "Notes"}, "csv_text": csv_text}, headers=h)
    assert j.status_code == 201, j.text
    j = j.json()
    assert j["will_create"] == 2 and j["duplicates"] == 2, j
    c = client.post(f"/api/customers/import/{j['job_id']}/commit", headers=h)
    assert c.status_code == 200, c.text
    customers = {x["name"]: x for x in client.get("/api/customers", headers=h).json()}
    assert customers["A"]["notes"] == "likes matte"
    assert "A again" not in customers and "E" not in customers
    assert set(customers) == {"Existing", "A", "B"}
