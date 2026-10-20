"""Cross-language contract conformance (Python side).

Runs without pytest so CI can invoke it with `python -I`; also importable by
the FastAPI test suite. Proves:
  1. every checked-in schema compiles under Draft 2020-12;
  2. every HMAC vector in contracts/mobile/v1/hmac-vectors.json signs
     identically with the Python reference implementation (the same
     algorithm the legacy backend/app/agent_ops/security.py uses);
  3. the canonical Rust fixture digest for mk.action.v1 is reproducible from
     Python, so approvals bound in Rust can be displayed/verified by FastAPI.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def _load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def _jcs(value) -> bytes:
    """RFC 8785 for the value shapes used by the kernel (strings, ints, bools,
    null, arrays, objects). Floats are intentionally unsupported here: the
    action envelope never carries them."""
    def enc(v):
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            raise TypeError("floats are not permitted in canonical action documents")
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        if isinstance(v, list):
            return "[" + ",".join(enc(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(f"{enc(k)}:{enc(v[k])}" for k in keys) + "}"
        raise TypeError(type(v))
    return enc(value).encode("utf-8")


def test_schemas_compile():
    for p in sorted(ROOT.glob("**/*.schema.json")):
        Draft202012Validator.check_schema(json.loads(p.read_text(encoding="utf-8")))


def test_hmac_vectors():
    data = _load("mobile/v1/hmac-vectors.json")
    assert data["algorithm"] == "hmac-sha256-v1"
    assert len(data["vectors"]) >= 6
    for v in data["vectors"]:
        body = v["body_utf8"].encode("utf-8")
        assert hashlib.sha256(body).hexdigest() == v["body_sha256"], v["name"]
        payload = "\n".join([v["method"].upper(), v["path"], v["timestamp"], v["nonce"], v["body_sha256"]]).encode()
        sig = hmac.new(v["secret"].encode(), payload, hashlib.sha256).hexdigest()
        assert sig == v["signature_hex"], v["name"]


def test_action_fixture_digest_matches_rust():
    """Pinned in rust/crates/mk-contracts/src/action.rs (PINNED_FIXTURE_DIGEST)."""
    fixture = {
        "schema_version": "mk.action.v1",
        "action_id": "0191f6f0-e2b4-7a2b-9c5c-3d1e2f3a4b5e",
        "tenant_id": "0191f6f0-e2b4-7a2b-9c5c-3d1e2f3a4b5c",
        "requested_by": "0191f6f0-e2b4-7a2b-9c5c-3d1e2f3a4b5d",
        "origin": {"type": "agent", "session_id": "sess-1", "model_call_id": "call-1"},
        "workflow": "customer_follow_up",
        "action_kind": "send_sms",
        "tool_id": "mobile.sms.send.v1",
        "resource": {"type": "contact", "id": "c-1"},
        "arguments": {
            "contact_id": "c-1",
            "template_id": "reorder_followup.v1",
            "rendered_text": "Hi! Your order shipped. Reply STOP to opt out.",
        },
        "purpose": "customer_requested_follow_up",
        "risk": "high",
        "requested_at": "2026-10-19T15:50:00Z",
        "expires_at": "2026-10-19T16:20:00Z",
        "idempotency_key": "follow-up:c-1:2026-10-19",
        "evidence": [{"type": "conversation", "id": "conv-1", "digest": "sha256:" + "0" * 64}],
    }
    Draft202012Validator(_load("action/v1/action-request.schema.json")).validate(fixture)
    digest = hashlib.sha256(_jcs(fixture)).hexdigest()
    assert digest == "32137d2014708b28f72eab14fc52c58ef4d4b93ea83048c952aa5b3521ae5dc3", digest


def test_work_order_fixture_validates():
    order = {
        "schema": "consultant-studio.mobile-work-order.v1",
        "adapter": "mobile-adapter-v1",
        "upstream_contract": "phoneclaw@c59995b",
        "verified_on_device": False,
        "workflow": "follow_up",
        "steps": [{"action": "open", "target": "sms"}, {"action": "input", "field": "recipient", "value": "+15555550100"}],
        "clawscript_source": "open sms",
        "adapter_actions_required": ["open", "input"],
        "result_fields": ["sent"],
        "task_id": "0191f6f0e2b47a2b9c5c3d1e2f3a4b5c",
        "agent_id": "simulator-1",
        "callback_url": "https://kernel.internal/adapter/v1/work-orders/0191f6f0e2b47a2b9c5c3d1e2f3a4b5c/callbacks",
        "callback_auth": "hmac-sha256-v1",
    }
    Draft202012Validator(_load("mobile/v1/mobile-work-order.schema.json")).validate(order)
    order["verified_on_device"] = True
    errors = list(Draft202012Validator(_load("mobile/v1/mobile-work-order.schema.json")).iter_errors(order))
    assert errors, "verified_on_device=true must be rejected by the contract"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: {exc!r}")
    sys.exit(1 if failures else 0)


def test_commitment_and_outcome_schemas_compile_and_separate_transport_from_business():
    import jsonschema
    base = ROOT
    c = json.loads((base / "commitments/v1/commitment.schema.json").read_text())
    o = json.loads((base / "outcomes/v1/outcome.schema.json").read_text())
    Draft202012Validator.check_schema(c)
    Draft202012Validator.check_schema(o)
    v = Draft202012Validator(c, format_checker=jsonschema.FormatChecker())
    draft = {"id": "a" * 32, "customer_id": "b" * 32, "kind": "promise", "text": "Check sample",
             "status": "draft", "due_at": None, "due_window": ["2026-11-01T00:00:00+00:00", "2026-11-30T23:59:59+00:00"],
             "timezone": "America/Chicago", "source_type": "conversation", "source_reference": "",
             "evidence_digest": "sha256:" + "0" * 64, "created_by": "ai", "confirmed_by": None, "version": 1}
    v.validate(draft)
    # An AI-created record that is not confirmed cannot be anything but a draft.
    bad = dict(draft, status="confirmed")
    assert list(v.iter_errors(bad)), "ai-created unconfirmed record must not be 'confirmed'"
    # Confirmed needs a date or a full window
    nodate = dict(draft, status="confirmed", confirmed_by="u", due_window=[None, None])
    assert list(v.iter_errors(nodate))
    ov = Draft202012Validator(o)
    ov.validate({"id": "a" * 32, "kind": "consultant_confirmed_order", "customer_id": "b" * 32, "commitment_id": None})
    assert list(ov.iter_errors({"id": "a" * 32, "kind": "delivered", "customer_id": "b" * 32, "commitment_id": None}))
