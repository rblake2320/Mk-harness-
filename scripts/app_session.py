#!/usr/bin/env python3
"""Obtain an app access token the way a real consultant does (MFA included).

    app_session.py APP_URL EMAIL PASSWORD SECRET_FILE   -> prints access token

- MFA required, no factor yet: enrolls TOTP, stores the base32 secret in
  SECRET_FILE (mode 600), confirms with a computed code.
- Factor present: logs in and answers the TOTP challenge from SECRET_FILE.
- MFA off (dev/test only): returns the password-only token.
Used by kernel-live-smoke.sh and kernel-preflight.sh. Stdlib only.
"""
import base64, hashlib, hmac, json, os, struct, sys, time, urllib.error, urllib.request


def call(url, path, body, token=None):
    h = {"content-type": "application/json"}
    if token:
        h["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url + path, json.dumps(body).encode(), h)
    try:
        return json.load(urllib.request.urlopen(req, timeout=15))
    except urllib.error.HTTPError as e:
        sys.exit(f"{path}: HTTP {e.code} {e.read()[:300]!r}")


def code_for(secret, step):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def fresh_step(state):
    """A step never used before for this factor (the server refuses TOTP replay)."""
    while (step := int(time.time()) // 30) <= state.get("last_step", -1):
        time.sleep(1)
    state["last_step"] = step
    return step


def main(url, email, password, secret_file):
    state = json.load(open(secret_file)) if os.path.exists(secret_file) else {}
    r = call(url, "/api/auth/login", {"email": email, "password": password})
    if r.get("mfa_required"):
        code = code_for(state["secret"], fresh_step(state))
        r = call(url, "/api/auth/mfa/verify", {"mfa_token": r["mfa_token"], "method": "totp", "code": code})
    elif r.get("mfa_enrollment_required"):
        b = call(url, "/api/security/mfa/totp/begin", {}, r["access_token"])
        state["secret"] = b["secret"]
        call(url, "/api/security/mfa/totp/confirm",
             {"factor_id": b["factor_id"], "code": code_for(b["secret"], fresh_step(state))}, r["access_token"])
    fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)
    print(r["access_token"])


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
