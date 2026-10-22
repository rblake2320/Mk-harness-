"""Seal a production plan for review, then open that exact plan after approval.

Public artifacts contain only encrypted plan bytes and bounded resource/action
counts. The release owner reviews the decrypted plan privately before approving
the protected production environment. This tool never runs an apply.
"""
import argparse
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from .image_provenance import valid_inputs
except ImportError:  # direct script entrypoint
    from image_provenance import valid_inputs

MAX_PLAN = 64 * 1024 * 1024
TOFU_VERSION = "1.10.6"
LIFETIME = timedelta(hours=2)
DOMAIN = b"mk-production-plan-v1"
ACTIONS = {("no-op",), ("read",), ("create",), ("update",), ("delete",),
    ("delete", "create"), ("create", "delete"), ("forget",), ("create", "forget")}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def bounded_read(path, maximum):
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if not value or len(value) > maximum:
        raise ValueError("Missing or oversized plan data")
    return value


def context(repo, sha, run_id, attempt, kernel_image, app_image, lock_digest):
    if (not valid_inputs(repo, sha, kernel_image, app_image)
        or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id)
        or not re.fullmatch(r"[1-9][0-9]{0,5}", attempt)
        or not re.fullmatch(r"[0-9a-f]{64}", lock_digest)):
        raise ValueError("Invalid plan execution context")
    return {"repository": repo, "source_sha": sha, "run_id": run_id, "run_attempt": attempt,
        "kernel_image": kernel_image, "app_image": app_image, "environment": "production",
        "provider_lock_sha256": lock_digest, "tofu_version": TOFU_VERSION}


def public_review(plan):
    if (not re.fullmatch(r"1\.[0-9]+", plan.get("format_version", ""))
        or plan.get("terraform_version") != TOFU_VERSION or plan.get("errored") is not False):
        raise ValueError("Invalid, errored or incompatible OpenTofu plan")
    counts = Counter()
    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list):
        raise ValueError("Invalid resource change list")
    for resource in changes:
        kind = resource.get("type", "")
        actions = tuple(resource.get("change", {}).get("actions", []))
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", kind) or actions not in ACTIONS:
            raise ValueError("Unsupported resource type or change action")
        counts[(kind, actions)] += 1
    # No addresses, for_each keys, names, before/after values, outputs,
    # variables, provider configuration or exception text enter this report.
    return {"tofu_version": TOFU_VERSION, "private_plan_review_required": True,
        "resource_changes": [{"type": kind, "actions": list(actions), "count": count}
            for (kind, actions), count in sorted(counts.items())]}


def derive(private, public):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=DOMAIN).derive(private.exchange(public))


def key_bytes(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Expected a 32-byte lowercase hex plan key")
    return bytes.fromhex(value)


def seal(plan, plan_json, expected, recipient_hex, output, now):
    if not plan or len(plan) > MAX_PLAN:
        raise ValueError("Missing or oversized binary plan")
    review = public_review(plan_json)
    recipient = X25519PublicKey.from_public_bytes(key_bytes(recipient_hex))
    ephemeral = X25519PrivateKey.generate()
    metadata = {**expected, "created_at": now.isoformat(), "expires_at": (now + LIFETIME).isoformat(),
        "plan_sha256": sha256(plan), "review_sha256": sha256(canonical(review)),
        "recipient_sha256": sha256(recipient.public_bytes_raw())}
    header = {"version": 1, "metadata": metadata,
        "ephemeral_public_key": ephemeral.public_key().public_bytes_raw().hex(),
        "nonce": os.urandom(12).hex()}
    cipher = AESGCM(derive(ephemeral, recipient)).encrypt(bytes.fromhex(header["nonce"]), plan, canonical(header))
    envelope = canonical({**header, "ciphertext": base64.b64encode(cipher).decode("ascii")})
    output.mkdir(parents=True, exist_ok=False)
    (output / "plan.enc.json").write_bytes(envelope)
    (output / "review.json").write_bytes(canonical(review))
    return {"verdict": "SEALED", "envelope_sha256": sha256(envelope), "metadata": metadata, "review": review}


def open_plan(package, expected, private_hex, envelope_digest, output, now):
    raw = bounded_read(package / "plan.enc.json", MAX_PLAN * 2)
    if not re.fullmatch(r"[0-9a-f]{64}", envelope_digest) or sha256(raw) != envelope_digest:
        raise ValueError("Plan artifact differs from producer job output")
    envelope = json.loads(raw)
    if set(envelope) != {"version", "metadata", "ephemeral_public_key", "nonce", "ciphertext"} or envelope["version"] != 1:
        raise ValueError("Invalid sealed plan envelope")
    metadata = envelope["metadata"]
    if set(metadata) != set(expected) | {"created_at", "expires_at", "plan_sha256", "review_sha256", "recipient_sha256"}:
        raise ValueError("Invalid plan metadata")
    if any(metadata[key] != value for key, value in expected.items()):
        raise ValueError("Plan execution context changed")
    created = datetime.fromisoformat(metadata["created_at"])
    expires = datetime.fromisoformat(metadata["expires_at"])
    if created.tzinfo is None or expires.tzinfo is None or not created <= now <= expires or expires - created != LIFETIME:
        raise ValueError("Plan approval window expired or invalid")
    review = bounded_read(package / "review.json", 1024 * 1024)
    if sha256(review) != metadata["review_sha256"]:
        raise ValueError("Published review summary changed")
    private = X25519PrivateKey.from_private_bytes(key_bytes(private_hex))
    if sha256(private.public_key().public_bytes_raw()) != metadata["recipient_sha256"]:
        raise ValueError("Wrong production plan recipient")
    ephemeral = X25519PublicKey.from_public_bytes(key_bytes(envelope["ephemeral_public_key"]))
    if not re.fullmatch(r"[0-9a-f]{24}", envelope["nonce"]):
        raise ValueError("Invalid plan nonce")
    cipher = base64.b64decode(envelope.pop("ciphertext"), validate=True)
    if not 16 < len(cipher) <= MAX_PLAN + 16:
        raise ValueError("Invalid encrypted plan size")
    plan = AESGCM(derive(private, ephemeral)).decrypt(bytes.fromhex(envelope["nonce"]), cipher, canonical(envelope))
    if sha256(plan) != metadata["plan_sha256"]:
        raise ValueError("Decrypted plan bytes changed")
    output.mkdir(parents=True, exist_ok=False)
    with os.fdopen(os.open(output / "plan.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(plan)
    return {"verdict": "OPENED", "metadata": metadata, "plan_sha256": sha256(plan)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("seal", "open"))
    for argument in ("repo", "sha", "run-id", "attempt", "kernel-image", "app-image"):
        parser.add_argument("--" + argument, required=True)
    parser.add_argument("--lock-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--package", type=Path)
    args = parser.parse_args()
    try:
        expected = context(args.repo, args.sha, args.run_id, args.attempt, args.kernel_image,
            args.app_image, sha256(bounded_read(args.lock_file, 1024 * 1024)))
        now = datetime.now(timezone.utc)
        if args.operation == "seal":
            binary = bounded_read(args.plan, MAX_PLAN)
            # Render the exact binary ourselves. A caller-authored JSON summary
            # must not be substituted for the plan the reviewer will approve.
            rendered = subprocess.run(["tofu", "show", "-json", str(args.plan.resolve())],
                capture_output=True, text=True, encoding="utf-8", timeout=120)
            if rendered.returncode or len(rendered.stdout.encode("utf-8")) > MAX_PLAN * 2:
                raise ValueError("Cannot render bounded binary plan")
            if bounded_read(args.plan, MAX_PLAN) != binary:
                raise ValueError("Binary plan changed while being rendered")
            report = seal(binary,
                json.loads(rendered.stdout), expected,
                os.environ["PLAN_PUBLIC_KEY"], args.output, now)
            if "GITHUB_OUTPUT" in os.environ:
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                    stream.write("envelope_sha256=" + report["envelope_sha256"] + "\n")
        else:
            report = open_plan(args.package, expected, os.environ["PLAN_PRIVATE_KEY"],
                os.environ["PLAN_ENVELOPE_SHA256"], args.output, now)
        print(json.dumps(report))
        return 0
    except Exception as exc:
        # Neither decrypted values nor supplied key material enter an error log.
        print(json.dumps({"verdict": "REFUSED", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
