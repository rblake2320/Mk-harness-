"""Adversarial suite for mk-mobile-agent-adb. Stdlib only: `python -m unittest -v`
(or pytest). No device: executors are faked; the kernel is a capturing callback
sink that verifies every signature the way the kernel does.

Proves:
  contract     signing matches the published cross-language HMAC vectors
  intake auth  missing header / wrong agent / wrong tenant / bad sig / stale ts → 401
  replay       same nonce twice → 401; survives agent restart (persisted ledger)
  idempotency  same task_id + same body → 200, executed exactly once;
               same task_id + different body → 409, not executed
  schema       verified_on_device:true, unknown keys, bad task_id, callback path
               mismatch, non-https callback → 422, nothing executed
  callbacks    executing → complete|failed, signed, bodies match the schemas,
               result carries digests only (no phone number / text leakage)
  evidence     bundle written atomically; hash chain verifies; tamper detected
  adb          executor parses sent rows, finds Send button, refuses empty boot id
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import agent as A  # noqa: E402

VECTORS = Path(__file__).resolve().parents[2] / "contracts" / "mobile" / "v1" / "hmac-vectors.json"
TENANT = "00000000-0000-4000-8000-000000000001"
SECRET = "enrollment-secret-for-tests-0123456789"
TASK = "0123456789abcdef0123456789abcdef"
TO, TEXT = "+15555550100", "Hi! Your order shipped. Reply STOP to opt out."


def order(task=TASK, **over):
    o = {
        "schema": A.SCHEMA_WORK_ORDER, "adapter": A.ADAPTER, "upstream_contract": "phoneclaw@abc",
        "verified_on_device": False, "workflow": "follow_up",
        "steps": [{"action": "open", "target": "sms"},
                  {"action": "input", "field": "recipient", "value": TO},
                  {"action": "input", "field": "message", "value": TEXT},
                  {"action": "click", "description": "Tap send"},
                  {"action": "scrape", "description": "Delivery status", "return_as": "sent"}],
        "clawscript_source": "# generated\n", "adapter_actions_required": ["open", "input"],
        "result_fields": ["sent"], "task_id": task, "agent_id": "moto-1",
        "callback_url": f"https://kernel.internal/adapter/v1/work-orders/{task}/callbacks",
        "callback_auth": A.CALLBACK_AUTH,
    }
    o.update(over)
    return o


class FakeExecutor(A.Executor):
    def __init__(self, sent=True, code=""):
        self.sent, self.code, self.calls = sent, code, 0

    def run(self, order, evidence_dir):
        self.calls += 1
        return A.ExecResult(self.sent, {"device": {"boot_id_digest": "x"}}, self.code)


class Sink:
    """Captures callbacks and verifies them exactly like the kernel."""

    def __init__(self, secret):
        self.secret, self.calls, self.nonces = secret, [], set()

    def __call__(self, url, headers, body):
        path = A.urlsplit(url).path
        assert headers["X-Mobile-Agent"] == "moto-1"
        assert headers["X-Mobile-Tenant"] == TENANT
        exp = A.sign(self.secret, "POST", path, headers["X-Mobile-Timestamp"],
                     headers["X-Mobile-Nonce"], body)
        assert exp == headers["X-Mobile-Signature"], "callback signature"
        assert headers["X-Mobile-Nonce"] not in self.nonces, "callback nonce reuse"
        self.nonces.add(headers["X-Mobile-Nonce"])
        self.calls.append((url, json.loads(body)))
        return 200


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.now = 1_800_000_000
        self.sink = Sink(SECRET)
        self.exec = FakeExecutor()
        self.agent = self.make_agent()

    def make_agent(self, executor=None, sink=None):
        cfg = A.Config("moto-1", TENANT, SECRET, evidence_dir=self.dir,
                       callback_base="http://127.0.0.1:8090")
        return A.Agent(cfg, executor or self.exec, http_post=sink or self.sink,
                       clock=lambda: self.now)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def post(self, o=None, body=None, ts=None, nonce=None, sig=None, agent_id="moto-1",
             tenant=TENANT, drop=()):
        body = body if body is not None else json.dumps(o or order(), separators=(",", ":")).encode()
        ts = str(self.now if ts is None else ts)
        nonce = nonce or os.urandom(8).hex()
        path = "/work-orders"
        h = {"X-Mobile-Agent": agent_id, "X-Mobile-Tenant": tenant, "X-Mobile-Timestamp": ts,
             "X-Mobile-Nonce": nonce,
             "X-Mobile-Signature": sig or A.sign(SECRET, "POST", path, ts, nonce, body)}
        for d in drop:
            h.pop(d)
        st, out = self.agent.handle_intake("POST", path, h, body)
        self.agent.wait_idle()
        return st, out


class ContractVectors(unittest.TestCase):
    def test_signing_matches_published_vectors(self):
        v = json.loads(VECTORS.read_text())
        for vec in v["vectors"]:
            body = vec["body_utf8"].encode()
            self.assertEqual(hashlib.sha256(body).hexdigest(), vec["body_sha256"])
            self.assertEqual(A.sign(vec["secret"], vec["method"], vec["path"], vec["timestamp"],
                                    vec["nonce"], body), vec["signature_hex"], vec["name"])
        # Negative vectors are described as mutations of a base vector; the
        # altered-body case is the one a signer can reproduce directly.
        base = {x["name"]: x for x in v["vectors"]}
        for neg in v.get("negative_vectors", []):
            b = base[neg["base"]]
            self.assertTrue(neg["expect"].startswith("reject"))
            if neg["name"] == "altered-body":
                self.assertNotEqual(A.sign(b["secret"], b["method"], b["path"], b["timestamp"],
                                           b["nonce"], b'{"status":"complete"}'),
                                    b["signature_hex"])


class IntakeAuth(Base):
    def test_happy_path_202_and_two_callbacks(self):
        st, out = self.post()
        self.assertEqual(st, 202, out)
        self.assertEqual(self.exec.calls, 1)
        kinds = [b["status"] for _, b in self.sink.calls]
        self.assertEqual(kinds, ["executing", "complete"])
        url, done = self.sink.calls[1]
        self.assertEqual(url, f"http://127.0.0.1:8090/adapter/v1/work-orders/{TASK}/callbacks")
        self.assertEqual(done["schema"], A.SCHEMA_COMPLETE)
        self.assertEqual(done["error_code"], "")
        self.assertTrue(done["result"]["sent"])
        self.assertTrue(re.match(r"^[0-9a-f]{64}$", done["result"]["evidence_digest"]))

    def test_missing_header_401(self):
        for h in ("X-Mobile-Signature", "X-Mobile-Nonce", "X-Mobile-Timestamp"):
            st, _ = self.post(drop=(h,))
            self.assertEqual(st, 401)
        self.assertEqual(self.exec.calls, 0)

    def test_wrong_agent_or_tenant_401(self):
        self.assertEqual(self.post(agent_id="moto-2")[0], 401)
        self.assertEqual(self.post(tenant="00000000-0000-4000-8000-000000000002")[0], 401)
        self.assertEqual(self.exec.calls, 0)

    def test_bad_signature_401(self):
        st, out = self.post(sig="0" * 64)
        self.assertEqual((st, out["error"]), (401, "bad_signature"))
        # Signature over a different body (tampered in flight) fails too.
        body = json.dumps(order(), separators=(",", ":")).encode()
        ts, nonce = str(self.now), "n-tamper"
        good = A.sign(SECRET, "POST", "/work-orders", ts, nonce, body)
        st, _ = self.post(body=body + b" ", ts=ts, nonce=nonce, sig=good)
        self.assertEqual(st, 401)
        self.assertEqual(self.exec.calls, 0)

    def test_timestamp_tolerance_is_120s(self):
        self.assertEqual(self.post(ts=self.now - 120)[0], 202)
        self.assertEqual(self.post(o=order("1" * 32), ts=self.now + 120)[0], 202)
        self.assertEqual(self.post(o=order("2" * 32), ts=self.now - 121)[0], 401)
        self.assertEqual(self.post(o=order("3" * 32), ts=self.now + 121)[0], 401)
        self.assertEqual(self.post(o=order("4" * 32), ts="not-a-number")[0], 401)

    def test_nonce_replay_401_even_with_valid_signature(self):
        self.assertEqual(self.post(nonce="n1")[0], 202)
        st, out = self.post(o=order("5" * 32), nonce="n1")
        self.assertEqual((st, out["error"]), (401, "nonce_replayed"))
        self.assertEqual(self.exec.calls, 1)

    def test_nonce_ledger_survives_restart(self):
        self.assertEqual(self.post(nonce="n-restart")[0], 202)
        self.agent = self.make_agent()  # fresh process, same evidence dir
        st, out = self.post(o=order("6" * 32), nonce="n-restart")
        self.assertEqual(out["error"], "nonce_replayed")

    def test_nonce_window_expires_after_retention(self):
        self.assertEqual(self.post(nonce="n-old")[0], 202)
        self.now += 2 * 120 + 61
        self.assertEqual(self.post(o=order("7" * 32), nonce="n-old")[0], 202)


class Idempotency(Base):
    def test_duplicate_delivery_is_200_and_not_re_executed(self):
        self.assertEqual(self.post()[0], 202)
        st, out = self.post()
        self.assertEqual((st, out.get("duplicate")), (200, True))
        self.assertEqual(self.exec.calls, 1)
        self.assertEqual(len(self.sink.calls), 2)

    def test_duplicate_after_restart_is_not_re_executed(self):
        self.assertEqual(self.post()[0], 202)
        ex2 = FakeExecutor()
        self.agent = self.make_agent(executor=ex2)
        self.assertEqual(self.post()[0], 200)
        self.assertEqual(ex2.calls, 0)

    def test_same_task_id_different_content_409(self):
        self.assertEqual(self.post()[0], 202)
        o = order(); o["steps"][2]["value"] = "DIFFERENT TEXT"
        st, out = self.post(o=o)
        self.assertEqual((st, out["error"]), (409, "task_id_content_conflict"))
        self.assertEqual(self.exec.calls, 1)


class Schema(Base):
    def _422(self, o, detail=None):
        st, out = self.post(o=o)
        self.assertEqual(st, 422, out)
        if detail:
            self.assertIn(detail, out["detail"])
        self.assertEqual(self.exec.calls, 0)
        self.assertEqual(self.sink.calls, [])

    def test_verified_on_device_true_is_rejected(self):
        self._422(order(verified_on_device=True), "verified_on_device")

    def test_unknown_key_rejected(self):
        self._422(order(extra="x"), "extra")

    def test_missing_key_rejected(self):
        o = order(); del o["steps"]
        self._422(o, "missing")

    def test_bad_task_id(self):
        self._422(order("ZZ"), "task_id")

    def test_callback_task_mismatch(self):
        self._422(order(callback_url=f"https://kernel.internal/adapter/v1/work-orders/{'9'*32}/callbacks"),
                  "callback_task_mismatch")

    def test_callback_must_be_https(self):
        self._422(order(callback_url=f"http://kernel.internal/adapter/v1/work-orders/{TASK}/callbacks"),
                  "callback_url")

    def test_open_url_must_be_https(self):
        o = order(); o["steps"].insert(1, {"action": "open_url", "url": "http://evil"})
        self._422(o, "open_url_scheme")

    def test_step_with_extra_field_rejected(self):
        o = order(); o["steps"][0]["shell"] = "rm -rf /"
        self._422(o, "step_open")

    def test_agent_id_mismatch(self):
        self._422(order(agent_id="other-agent"), "")

    def test_not_json(self):
        st, _ = self.post(body=b"\xff\xfe")
        self.assertEqual(st, 422)


class Callbacks(Base):
    def test_failure_posts_failed_schema_with_error_code(self):
        self.exec = FakeExecutor(sent=False, code="send_button_not_found")
        self.agent = self.make_agent()
        self.assertEqual(self.post()[0], 202)
        _, failed = self.sink.calls[1]
        self.assertEqual(failed["schema"], A.SCHEMA_FAILED)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["error_code"], "send_button_not_found")
        self.assertFalse(failed["result"]["sent"])

    def test_no_pii_in_callbacks_or_chain(self):
        self.post()
        blob = json.dumps(self.sink.calls) + (self.dir / "evidence-ledger.jsonl").read_text()
        self.assertNotIn(TO, blob)
        self.assertNotIn(TEXT, blob)
        self.assertNotIn("5555550100", blob)

    def test_callback_result_within_schema_limits(self):
        self.post()
        for _, b in self.sink.calls:
            self.assertEqual(set(b), {"schema", "status", "result", "error_code"})
            self.assertLessEqual(len(b["result"]), 100)

    def test_callback_failure_status_recorded_not_retried_blindly(self):
        sink_calls = []

        def down(url, headers, body):
            sink_calls.append(body); return 0  # kernel unreachable
        self.agent = self.make_agent(sink=down)
        self.assertEqual(self.post()[0], 202)
        self.assertEqual(len(sink_calls), 2)
        ledger = json.loads((self.dir / "ledger.json").read_text())
        self.assertEqual(ledger["tasks"][TASK]["state"], "reported")
        self.assertEqual(ledger["tasks"][TASK]["callback_status"], 0)


class Evidence(Base):
    def test_bundle_and_chain(self):
        self.post(); self.post(o=order("a" * 32))
        b = json.loads((self.dir / f"{TASK}.json").read_text())
        self.assertIs(b["verified_on_device"], False)
        self.assertEqual(b["order_digest"], hashlib.sha256(
            json.dumps(order(), sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        ok, n = A.EvidenceChain.verify(self.dir / "evidence-ledger.jsonl")
        self.assertTrue(ok); self.assertEqual(n, 2)
        # Chain head equals the digest reported to the kernel.
        self.assertEqual(self.sink.calls[-1][1]["result"]["evidence_digest"],
                         json.loads((self.dir / "evidence-ledger.jsonl").read_text()
                                    .splitlines()[-1])["entry_hash"])

    def test_tamper_detected(self):
        self.post(); self.post(o=order("b" * 32))
        p = self.dir / "evidence-ledger.jsonl"
        lines = p.read_text().splitlines()
        lines[0] = lines[0].replace('"sent":true', '"sent":false')
        p.write_text("\n".join(lines) + "\n")
        ok, n = A.EvidenceChain.verify(p)
        self.assertFalse(ok); self.assertEqual(n, 0)

    def test_atomic_write_leaves_no_temp_on_failure(self):
        class Boom:
            pass
        with self.assertRaises(TypeError):
            A.atomic_write_json(self.dir / "x.json", Boom())
        self.assertEqual([p.name for p in self.dir.iterdir() if p.suffix == ".tmp"], [])
        self.assertFalse((self.dir / "x.json").exists())


class AdbExecutorTests(unittest.TestCase):
    """Drives AdbExecutor with a scripted adb. Proves parsing and the identity gate."""

    def make(self, script):
        calls = []

        def runner(argv):
            calls.append(argv)
            key = " ".join(argv[2:])
            for pat, (rc, out) in script:
                if re.search(pat, key):
                    return subprocess.CompletedProcess(argv, rc, out, b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return A.AdbExecutor("adb", "ZX1G", runner=runner), calls

    ROWS_BEFORE = b"Row: 0 _id=10, address=+15555550199, body=old, date=1\n"
    ROWS_AFTER = ROWS_BEFORE + (
        b"Row: 1 _id=11, address=+1 555-555-0100, body=" + TEXT.encode() + b", date=1700000000\n")
    UI = (b'<node text="Send" bounds="[900,1800][1000,1900]" />')

    def test_sms_send_success_with_evidence(self):
        state = {"n": 0}

        def rows(argv):
            state["n"] += 1
            return (0, self.ROWS_BEFORE if state["n"] == 1 else self.ROWS_AFTER)
        ex, calls = self.make([
            (r"getprop ro.serialno", (0, b"ZX1G\n")),
            (r"getprop ro.build.fingerprint", (0, b"motorola/x\n")),
            (r"boot_id", (0, b"8f3c-boot\n")),
            (r"cat /sdcard/mk_ui.xml", (0, self.UI)),
            (r"^screencap", (0, b"\x89PNG...")),
        ])
        # patch dynamic row script
        orig = ex.runner

        def runner(argv):
            if "content" in argv and "query" in argv:
                rc, out = rows(argv); return subprocess.CompletedProcess(argv, rc, out, b"")
            return orig(argv)
        ex.runner = runner
        A.time.sleep = lambda *_: None
        d = Path(tempfile.mkdtemp())
        try:
            r = ex.run(order(), d)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertTrue(r.sent, r)
        self.assertEqual(r.evidence["sent_rows_before"], 1)
        self.assertEqual(r.evidence["sent_rows_after"], 2)
        self.assertEqual(r.evidence["sms_row_id_digest"], hashlib.sha256(b"11").hexdigest())
        self.assertEqual(r.evidence["device"]["boot_id_digest"],
                         hashlib.sha256(b"8f3c-boot").hexdigest())
        self.assertNotIn("ZX1G", json.dumps(r.evidence))  # serial only as digest
        tap = [c for c in calls if "tap" in c][0]
        self.assertEqual(tap[-2:], ["950", "1850"])
        self.assertTrue(any("android.intent.action.SENDTO" in c for c in calls))

    def test_empty_boot_identity_is_refused(self):
        ex, _ = self.make([(r"getprop ro.serialno", (0, b"ZX1G\n")), (r"boot_id", (0, b"\n"))])
        r = ex.run(order(), Path(tempfile.mkdtemp()))
        self.assertFalse(r.sent)
        self.assertEqual(r.error_code, "device_identity_empty")

    def test_send_button_missing_without_fallback_fails_closed(self):
        ex, calls = self.make([
            (r"getprop ro.serialno", (0, b"S\n")), (r"boot_id", (0, b"B\n")),
            (r"cat /sdcard/mk_ui.xml", (0, b"<node text='Nope'/>")),
        ])
        A.time.sleep = lambda *_: None
        r = ex.run(order(), Path(tempfile.mkdtemp()))
        self.assertEqual(r.error_code, "send_button_not_found")
        self.assertFalse(any("tap" in c for c in calls))

    def test_invalid_destination_never_touches_device(self):
        ex, calls = self.make([])
        o = order(); o["steps"][1]["value"] = "555-0100"
        r = ex.run(o, Path(tempfile.mkdtemp()))
        self.assertEqual(r.error_code, "invalid_order_arguments")
        self.assertEqual(calls, [])

    def test_non_sms_order_unsupported(self):
        ex, calls = self.make([])
        o = order(); o["steps"][0] = {"action": "open", "target": "instagram"}
        self.assertEqual(ex.run(o, Path(tempfile.mkdtemp())).error_code, "unsupported_workflow")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
