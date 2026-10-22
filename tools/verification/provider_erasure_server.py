"""Loopback-only test equipment; deliberately stops a DELETE after its effect."""
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

account, token, sid, number = (os.environ[k] for k in
    ("FIXTURE_ACCOUNT", "FIXTURE_TOKEN", "FIXTURE_MESSAGE", "FIXTURE_NUMBER"))
auth = "Basic " + base64.b64encode(f"{account}:{token}".encode()).decode()
resource = f"/2010-04-01/Accounts/{account}/Messages/{sid}.json"
present, release = threading.Event(), threading.Event()
present.set()
state = {"deletes": 0, "sends": 0, "auth_failures": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, status, body=None):
        payload = json.dumps(body).encode() if body is not None else b""
        try:
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError): pass
    def allowed(self):
        if self.headers.get("Authorization") == auth: return True
        state["auth_failures"] += 1; self.reply(401, {"code":20003}); return False
    def do_GET(self):
        if not self.allowed(): return
        if self.path == "/fixture-state":
            self.reply(200, {**state, "present":present.is_set()}); return
        if self.path != resource: self.reply(404); return
        if present.is_set():
            self.reply(200,{"sid":sid,"account_sid":account,"status":"delivered",
                "from":number,"to":"+15555550100","direction":"outbound-api",
                "body":"Synthetic built-image provider privacy canary"})
        else: self.reply(404,{"code":20404})
    def do_DELETE(self):
        if not self.allowed(): return
        if self.path != resource: self.reply(404); return
        state["deletes"] += 1
        if present.is_set():
            present.clear(); release.wait(60); self.reply(204)
        else: self.reply(404,{"code":20404})
    def do_POST(self):
        if not self.allowed(): return
        if self.path == "/fixture-release": release.set(); self.reply(204)
        else: state["sends"] += 1; self.reply(500)


ThreadingHTTPServer(("0.0.0.0",8790),Handler).serve_forever()
