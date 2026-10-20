#!/usr/bin/env python3
"""mk-mobile-agent-adb — reference *real-device* mobile adapter for the MK action kernel.

Runs on a controller host (Windows/macOS/Linux) with an Android phone attached
over ADB (USB or `adb connect`). It is the counterpart of the courier pattern
already used with the Moto phones: receive a signed work order, execute it on
the device, report a signed result. Standard library only — no pip installs on
the controller.

    kernel worker ──HMAC──▶ POST /work-orders   (this agent, intake)
                            │  verify sig/ts/nonce, schema, task_id idempotency
                            │  202 Accepted
                            ├─▶ callback: executing
                            ├─▶ adb: open SMS composer, type, tap Send, read sent row
                            └─▶ callback: complete {sent, evidence digests}  |  failed {error_code}

Security model (the kernel is the authority; this agent only obeys it):
* Every intake request must carry a valid HMAC-SHA256 over
  METHOD\\nPATH\\nTIMESTAMP\\nNONCE\\nSHA256(body) under the enrollment secret.
* Timestamp skew ≤ MK_TOLERANCE_SECS (default 120, same as the kernel).
* Nonce replay refused for 2×tolerance+60 s; the nonce + task ledgers are
  persisted (crash-safe atomic writes) so a restart does not reopen the window.
* `task_id` is the idempotency key: same body → 200 (not re-executed);
  different body → 409. Each task executes at most once per ledger lifetime.
* `verified_on_device` in the order must be `false` (schema const). This agent
  never claims it; the evidence bundle it writes is what a human reviews.
* Nothing from the order (phone number, message text) is written to logs or
  callbacks. Evidence carries digests only; the raw bundle stays on the
  controller under MK_EVIDENCE_DIR for the reviewer.

Environment:
  MK_AGENT_ID            agent_id registered with the kernel (required)
  MK_TENANT_ID           tenant uuid (required)
  MK_AGENT_SECRET        enrollment secret from POST /adapters (required)
  MK_AGENT_BIND          host:port to listen on (default 127.0.0.1:8787)
  MK_CALLBACK_BASE       scheme+authority override for callbacks, e.g.
                         http://127.0.0.1:8090 for a local kernel (default:
                         https://<callback_authority from the order>)
  MK_EXECUTOR            adb | dry-run   (default adb)
  MK_ADB                 adb binary (default "adb")
  MK_ADB_SERIAL          device serial for -s (optional)
  MK_TOLERANCE_SECS      HMAC timestamp tolerance (default 120)
  MK_EVIDENCE_DIR        evidence bundles + ledgers (default ./evidence)
  MK_SMS_SEND_TAP        "x,y" fallback tap if the Send button is not found

Run:  python agent.py             (Windows: py -3 agent.py)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

SCHEMA_WORK_ORDER = "consultant-studio.mobile-work-order.v1"
SCHEMA_STATE = "consultant-studio.mobile-execution-state.v1"
SCHEMA_COMPLETE = "consultant-studio.mobile-execution-completion.v1"
SCHEMA_FAILED = "consultant-studio.mobile-execution-failure.v1"
ADAPTER = "mobile-adapter-v1"
CALLBACK_AUTH = "hmac-sha256-v1"
TASK_ID_RE = re.compile(r"^[0-9a-f]{32}$")
E164_RE = re.compile(r"^\+[1-9][0-9]{6,14}$")
MAX_BODY = 256 * 1024


# --------------------------------------------------------------------------- #
# Crypto (matches contracts/mobile/v1 + rust/crates/mk-crypto/src/hmac_sig.rs)
# --------------------------------------------------------------------------- #
def canonical(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    body_hex = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{ts}\n{nonce}\n{body_hex}".encode("utf-8")


def sign(secret: str, method: str, path: str, ts: str, nonce: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), canonical(method, path, ts, nonce, body),
                    hashlib.sha256).hexdigest()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------- #
# Crash-safe ledgers (atomic replace; hash-chained evidence log)
# --------------------------------------------------------------------------- #
def atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # atomic on POSIX and NTFS
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Ledger:
    """Nonce window + task registry, persisted after every mutation."""

    def __init__(self, path: Path, retain_secs: int):
        self.path = path
        self.retain = retain_secs
        self.lock = threading.Lock()
        self.nonces: dict[str, int] = {}
        self.tasks: dict[str, dict[str, Any]] = {}
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self.nonces = {str(k): int(v) for k, v in data.get("nonces", {}).items()}
            self.tasks = dict(data.get("tasks", {}))

    def _persist(self) -> None:
        atomic_write_json(self.path, {"nonces": self.nonces, "tasks": self.tasks})

    def check_nonce(self, nonce: str, ts: int, now: int) -> bool:
        with self.lock:
            cutoff = now - self.retain
            self.nonces = {n: t for n, t in self.nonces.items() if t >= cutoff}
            if nonce in self.nonces:
                return False
            self.nonces[nonce] = ts
            self._persist()
            return True

    def register_task(self, task_id: str, body_digest: str) -> str:
        """'new' | 'duplicate' | 'conflict'"""
        with self.lock:
            cur = self.tasks.get(task_id)
            if cur is None:
                self.tasks[task_id] = {"digest": body_digest, "state": "accepted",
                                       "accepted_at": int(time.time())}
                self._persist()
                return "new"
            return "duplicate" if cur["digest"] == body_digest else "conflict"

    def set_state(self, task_id: str, state: str, **extra: Any) -> None:
        with self.lock:
            self.tasks[task_id].update({"state": state, **extra})
            self._persist()


class EvidenceChain:
    """Append-only, hash-chained JSONL: each line commits to the previous line."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.head = "0" * 64
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.head = json.loads(line)["entry_hash"]

    def append(self, entry: dict[str, Any]) -> str:
        with self.lock:
            body = dict(entry, prev_hash=self.head)
            canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            body["entry_hash"] = sha256_hex(canon)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.head = body["entry_hash"]
            return self.head

    @staticmethod
    def verify(path: Path) -> tuple[bool, int]:
        prev = "0" * 64
        n = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            h = e.pop("entry_hash")
            if e.get("prev_hash") != prev:
                return False, n
            if sha256_hex(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()) != h:
                return False, n
            prev = h
            n += 1
        return True, n


# --------------------------------------------------------------------------- #
# Work-order validation (structural mirror of mobile-work-order.schema.json)
# --------------------------------------------------------------------------- #
class OrderError(ValueError):
    pass


def validate_order(o: Any) -> dict[str, Any]:
    if not isinstance(o, dict):
        raise OrderError("not_an_object")
    required = ["schema", "adapter", "upstream_contract", "verified_on_device", "workflow",
                "steps", "clawscript_source", "adapter_actions_required", "result_fields",
                "task_id", "agent_id", "callback_url", "callback_auth"]
    missing = [k for k in required if k not in o]
    extra = [k for k in o if k not in required]
    if missing or extra:
        raise OrderError(f"schema_keys missing={missing} extra={extra}")
    if o["schema"] != SCHEMA_WORK_ORDER or o["adapter"] != ADAPTER:
        raise OrderError("schema_or_adapter")
    if o["verified_on_device"] is not False:
        raise OrderError("verified_on_device_must_be_false")
    if o["callback_auth"] != CALLBACK_AUTH:
        raise OrderError("callback_auth")
    if not TASK_ID_RE.match(str(o["task_id"])):
        raise OrderError("task_id")
    if o["workflow"] not in ("follow_up", "appointment", "order_status",
                             "recruit_outreach", "social_post"):
        raise OrderError("workflow")
    steps = o["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 20:
        raise OrderError("steps")
    for s in steps:
        if not isinstance(s, dict) or "action" not in s:
            raise OrderError("step")
        a = s["action"]
        keys = set(s) - {"action"}
        ok = {"open": {"target"}, "open_url": {"url"}, "click": {"description"},
              "input": {"field", "value"}, "scrape": {"description", "return_as"}}
        if a not in ok or keys != ok[a]:
            raise OrderError(f"step_{a}")
        if a == "open" and s["target"] not in ("sms", "instagram", "facebook", "tiktok", "x"):
            raise OrderError("open_target")
        if a == "open_url" and not str(s["url"]).startswith("https://"):
            raise OrderError("open_url_scheme")
    u = urlsplit(str(o["callback_url"]))
    if u.scheme != "https" or not u.netloc:
        raise OrderError("callback_url")
    if not re.match(r"^/adapter/v1/work-orders/[0-9a-f]{32}/callbacks$", u.path):
        raise OrderError("callback_path")
    if u.path.split("/")[4] != o["task_id"]:
        raise OrderError("callback_task_mismatch")
    return o


# --------------------------------------------------------------------------- #
# Executors
# --------------------------------------------------------------------------- #
@dataclass
class ExecResult:
    sent: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    error_code: str = ""


class Executor:
    def run(self, order: dict[str, Any], evidence_dir: Path) -> ExecResult:  # pragma: no cover
        raise NotImplementedError


class DryRunExecutor(Executor):
    """Executes nothing. Produces a bundle that says so, for contract runs."""

    def run(self, order: dict[str, Any], evidence_dir: Path) -> ExecResult:
        return ExecResult(sent=False, error_code="dry_run_no_device")


class AdbExecutor(Executor):
    """Drives the stock Messages composer on an Android device via ADB.

    Steps are taken from the order: open sms → input recipient/message →
    click send → scrape delivery status. Confirmation = a new row in
    content://sms/sent whose address and body match. Evidence = device
    identity, boot id, before/after sent-row counts, matched row id (digest),
    screenshot digest. No message text or phone number leaves the bundle.
    """

    def __init__(self, adb: str = "adb", serial: str | None = None,
                 fallback_tap: tuple[int, int] | None = None,
                 runner: Callable[[list[str]], subprocess.CompletedProcess] | None = None):
        self.base = [adb] + (["-s", serial] if serial else [])
        self.fallback_tap = fallback_tap
        self.runner = runner or (lambda argv: subprocess.run(
            argv, capture_output=True, timeout=60, check=False))

    def _sh(self, *args: str) -> str:
        cp = self.runner(self.base + ["shell", *args])
        if cp.returncode != 0:
            raise RuntimeError(f"adb_shell_failed:{args[0]}")
        return cp.stdout.decode("utf-8", "replace")

    def _exec_out(self, *args: str) -> bytes:
        cp = self.runner(self.base + ["exec-out", *args])
        if cp.returncode != 0:
            raise RuntimeError(f"adb_exec_out_failed:{args[0]}")
        return cp.stdout

    def _identity(self) -> dict[str, str]:
        serial = self._sh("getprop", "ro.serialno").strip()
        fp = self._sh("getprop", "ro.build.fingerprint").strip()
        boot = self._sh("cat", "/proc/sys/kernel/random/boot_id").strip()
        if not serial or not boot:
            # The Moto courier lesson: an empty boot identity is not a device.
            raise RuntimeError("device_identity_empty")
        return {"serial_digest": sha256_hex(serial.encode()), "fingerprint": fp,
                "boot_id_digest": sha256_hex(boot.encode())}

    # `content query` prints `Row: N k=v, k=v, ...`. The body is free text and
    # may itself contain ", ", "=", or newlines, so it is projected LAST and
    # parsed as "everything after `body=`" up to the next `Row:` anchor; the
    # fixed-shape fields before it (`_id`, `address`, `date`) are matched
    # structurally, never by splitting on commas.
    _ROW_RE = re.compile(
        r"^Row: \d+ _id=(?P<_id>\d+), address=(?P<address>[^,\n]*), date=(?P<date>\d*), body=(?P<body>.*?)"
        r"(?=^Row: \d+ |\Z)",
        re.MULTILINE | re.DOTALL,
    )

    @classmethod
    def parse_rows(cls, out: str) -> list[dict[str, str]]:
        rows = []
        for m in cls._ROW_RE.finditer(out):
            d = m.groupdict()
            d["body"] = d["body"].rstrip("\n")
            rows.append(d)
        return rows

    def _sent_rows(self) -> list[dict[str, str]]:
        out = self._sh("content", "query", "--uri", "content://sms/sent",
                       "--projection", "_id:address:date:body")
        return self.parse_rows(out)

    def _find_send_button(self) -> tuple[int, int] | None:
        self._sh("uiautomator", "dump", "/sdcard/mk_ui.xml")
        xml = self._sh("cat", "/sdcard/mk_ui.xml")
        for m in re.finditer(r'<node[^>]*?(?:content-desc|text)="(Send(?: message| SMS)?)"[^>]*?'
                             r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
            x1, y1, x2, y2 = map(int, m.groups()[1:])
            return (x1 + x2) // 2, (y1 + y2) // 2
        return None

    def run(self, order: dict[str, Any], evidence_dir: Path) -> ExecResult:
        steps = order["steps"]
        if not steps or steps[0].get("action") != "open" or steps[0].get("target") != "sms":
            return ExecResult(False, error_code="unsupported_workflow")
        inputs = {s["field"]: s["value"] for s in steps if s.get("action") == "input"}
        to, text = inputs.get("recipient", ""), inputs.get("message", "")
        if not E164_RE.match(to) or not text:
            return ExecResult(False, error_code="invalid_order_arguments")
        try:
            ident = self._identity()
            before = self._sent_rows()
            # Open the composer pre-filled; this does not send by itself.
            self._sh("am", "start", "-a", "android.intent.action.SENDTO",
                     "-d", shlex.quote(f"sms:{to}"), "--es", "sms_body", shlex.quote(text))
            time.sleep(1.5)
            tap = self._find_send_button() or self.fallback_tap
            if tap is None:
                return ExecResult(False, error_code="send_button_not_found",
                                  evidence={"device": ident})
            self._sh("input", "tap", str(tap[0]), str(tap[1]))
            # Poll the sent box for the matching row (≤ 20 s).
            match = None
            for _ in range(20):
                time.sleep(1.0)
                after = self._sent_rows()
                if len(after) > len(before):
                    cand = [r for r in after if r.get("body") == text and
                            re.sub(r"\D", "", r.get("address", "")) == re.sub(r"\D", "", to)]
                    if cand:
                        match = cand[-1]
                        break
            shot = self._exec_out("screencap", "-p")
            shot_path = evidence_dir / f"{order['task_id']}.png"
            shot_path.write_bytes(shot)
            ev = {
                "device": ident,
                "sent_rows_before": len(before),
                "sent_rows_after": len(after),
                "sms_row_id_digest": sha256_hex(match["_id"].encode()) if match else "",
                "sms_row_date": match.get("date", "") if match else "",
                "screenshot_sha256": sha256_hex(shot),
            }
            if not match:
                return ExecResult(False, evidence=ev, error_code="sent_row_not_found")
            return ExecResult(True, evidence=ev)
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as e:
            code = str(e).split(":")[0] if isinstance(e, RuntimeError) else "adb_error"
            return ExecResult(False, error_code=re.sub(r"[^a-z0-9_.-]", "_", code.lower())[:80])


# --------------------------------------------------------------------------- #
# Agent
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    agent_id: str
    tenant_id: str
    secret: str
    bind: str = "127.0.0.1:8787"
    callback_base: str | None = None
    tolerance: int = 120
    evidence_dir: Path = Path("./evidence")

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ
        for k in ("MK_AGENT_ID", "MK_TENANT_ID", "MK_AGENT_SECRET"):
            if not env.get(k):
                sys.exit(f"{k} is required")
        return cls(agent_id=env["MK_AGENT_ID"], tenant_id=env["MK_TENANT_ID"],
                   secret=env["MK_AGENT_SECRET"], bind=env.get("MK_AGENT_BIND", "127.0.0.1:8787"),
                   callback_base=env.get("MK_CALLBACK_BASE") or None,
                   tolerance=int(env.get("MK_TOLERANCE_SECS", "120")),
                   evidence_dir=Path(env.get("MK_EVIDENCE_DIR", "./evidence")))


class Agent:
    def __init__(self, cfg: Config, executor: Executor,
                 http_post: Callable[[str, dict[str, str], bytes], int] | None = None,
                 clock: Callable[[], int] = lambda: int(time.time())):
        self.cfg = cfg
        self.executor = executor
        self.clock = clock
        self.http_post = http_post or _urllib_post
        self.ledger = Ledger(cfg.evidence_dir / "ledger.json", 2 * cfg.tolerance + 60)
        self.chain = EvidenceChain(cfg.evidence_dir / "evidence-ledger.jsonl")
        self.executions = 0
        self._threads: list[threading.Thread] = []

    # -- intake --------------------------------------------------------------
    def handle_intake(self, method: str, path: str, headers: dict[str, str],
                      body: bytes) -> tuple[int, dict[str, Any]]:
        h = {k.lower(): v for k, v in headers.items()}
        for k in ("x-mobile-agent", "x-mobile-tenant", "x-mobile-timestamp",
                  "x-mobile-nonce", "x-mobile-signature"):
            if k not in h:
                return 401, {"error": "missing_auth_header"}
        if h["x-mobile-agent"] != self.cfg.agent_id or h["x-mobile-tenant"] != self.cfg.tenant_id:
            return 401, {"error": "unknown_agent_or_tenant"}
        try:
            ts = int(h["x-mobile-timestamp"])
        except ValueError:
            return 401, {"error": "bad_timestamp"}
        now = self.clock()
        if abs(now - ts) > self.cfg.tolerance:
            return 401, {"error": "timestamp_out_of_tolerance"}
        expected = sign(self.cfg.secret, method, path, h["x-mobile-timestamp"],
                        h["x-mobile-nonce"], body)
        if not hmac.compare_digest(expected, h["x-mobile-signature"].lower()):
            return 401, {"error": "bad_signature"}
        if not self.ledger.check_nonce(h["x-mobile-nonce"], ts, now):
            return 401, {"error": "nonce_replayed"}
        try:
            order = validate_order(json.loads(body.decode("utf-8")))
        except (ValueError, OrderError) as e:
            return 422, {"error": "work_order_invalid", "detail": str(e)[:200]}
        if order["agent_id"] != self.cfg.agent_id:
            return 422, {"error": "agent_id_mismatch"}
        state = self.ledger.register_task(order["task_id"], sha256_hex(body))
        if state == "conflict":
            return 409, {"error": "task_id_content_conflict"}
        if state == "duplicate":
            return 200, {"accepted": True, "task_id": order["task_id"], "duplicate": True}
        t = threading.Thread(target=self._execute, args=(order,), daemon=True)
        self._threads.append(t)
        t.start()
        return 202, {"accepted": True, "task_id": order["task_id"]}

    def wait_idle(self, timeout: float = 30) -> None:
        for t in self._threads:
            t.join(timeout)

    # -- execution + callbacks ---------------------------------------------
    def _callback(self, order: dict[str, Any], body: dict[str, Any]) -> int:
        u = urlsplit(order["callback_url"])
        base = (self.cfg.callback_base or f"{u.scheme}://{u.netloc}").rstrip("/")
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ts = str(self.clock())
        nonce = secrets.token_hex(16)
        headers = {
            "Content-Type": "application/json",
            "X-Mobile-Agent": self.cfg.agent_id,
            "X-Mobile-Tenant": self.cfg.tenant_id,
            "X-Mobile-Timestamp": ts,
            "X-Mobile-Nonce": nonce,
            "X-Mobile-Signature": sign(self.cfg.secret, "POST", u.path, ts, nonce, raw),
        }
        return self.http_post(base + u.path, headers, raw)

    def _execute(self, order: dict[str, Any]) -> None:
        task = order["task_id"]
        self.ledger.set_state(task, "executing")
        self._callback(order, {"schema": SCHEMA_STATE, "status": "executing",
                               "result": {}, "error_code": ""})
        self.executions += 1
        res = self.executor.run(order, self.cfg.evidence_dir)
        bundle = {
            "task_id": task, "agent_id": self.cfg.agent_id, "tenant_id": self.cfg.tenant_id,
            "order_digest": sha256_hex(json.dumps(order, sort_keys=True,
                                                  separators=(",", ":")).encode()),
            "verified_on_device": False,          # a human flips this in review, never code
            "sent": res.sent, "error_code": res.error_code, "evidence": res.evidence,
            "completed_at": self.clock(),
        }
        atomic_write_json(self.cfg.evidence_dir / f"{task}.json", bundle)
        head = self.chain.append(bundle)
        result = {"sent": res.sent, "evidence_digest": head}
        if res.sent:
            body = {"schema": SCHEMA_COMPLETE, "status": "complete", "result": result,
                    "error_code": ""}
        else:
            body = {"schema": SCHEMA_FAILED, "status": "failed", "result": result,
                    "error_code": res.error_code or "execution_failed"}
        status = self._callback(order, body)
        self.ledger.set_state(task, "reported", callback_status=status, evidence_head=head)


def _urllib_post(url: str, headers: dict[str, str], body: bytes) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return 0


def make_server(agent: Agent) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:  # no request logging: PII discipline
            pass

        def do_POST(self) -> None:
            n = int(self.headers.get("Content-Length", "0"))
            if n > MAX_BODY:
                self._reply(413, {"error": "body_too_large"}); return
            body = self.rfile.read(n)
            status, out = agent.handle_intake("POST", urlsplit(self.path).path,
                                              dict(self.headers.items()), body)
            self._reply(status, out)

        def do_GET(self) -> None:
            if urlsplit(self.path).path == "/health":
                self._reply(200, {"ok": True, "agent_id": agent.cfg.agent_id})
            else:
                self._reply(404, {"error": "not_found"})

        def _reply(self, status: int, obj: dict[str, Any]) -> None:
            raw = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    host, port = agent.cfg.bind.rsplit(":", 1)
    return ThreadingHTTPServer((host, int(port)), Handler)


def main() -> None:
    cfg = Config.from_env()
    mode = os.environ.get("MK_EXECUTOR", "adb")
    if mode == "dry-run":
        executor: Executor = DryRunExecutor()
    else:
        tap = os.environ.get("MK_SMS_SEND_TAP")
        executor = AdbExecutor(os.environ.get("MK_ADB", "adb"), os.environ.get("MK_ADB_SERIAL"),
                               tuple(int(v) for v in tap.split(",")) if tap else None)
    agent = Agent(cfg, executor)
    srv = make_server(agent)
    print(f"mk-mobile-agent-adb listening on {cfg.bind} executor={mode} "
          f"evidence={cfg.evidence_dir}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
