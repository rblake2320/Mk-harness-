"""Offline account-security recovery. This is not an authorization to open ingress.

The operator supplies independently retained input digests and a new recovery ID.
All local changes commit together; recovered kernel authorities must subsequently
be revoked by the durable worker before this security gate reports ready.
"""
import json
from datetime import datetime, timezone

from sqlalchemy import delete, select, text

from ..crypto import unseal_secret
from ..database_policy import validate_schema, migration_files
from ..models import (Tenant, User, AuthFactor, AuthRecoveryCode, AuthSession,
                      AuthRevocation, RecoveredSessionRevocation, SecurityRestoreReceipt)
from . import security_ledger as ledger
from .privacy_ledger import load_ledger, replay_ledger


def target_binding(db):
    url = db.bind.url
    oid = db.scalar(text("SELECT oid FROM pg_database WHERE datname=current_database()"))
    return ledger.sha256(ledger.canonical([url.host, url.port, url.database, oid]))


def operator_context(db):
    if db.bind.dialect.name != "postgresql":
        raise ValueError("Security recovery requires the controlled PostgreSQL operator")
    db.execute(text("SET LOCAL ROLE mk_app_owner"))
    db.execute(text("SET LOCAL search_path = pg_catalog, mk_app"))
    db.execute(text("SELECT pg_advisory_xact_lock(58721493621)"))
    validate_schema(db.connection())
    applied = dict(db.execute(text("SELECT version, sha256 FROM mk_app.schema_migrations")).all())
    expected = {path.name: ledger.sha256(path.read_bytes()) for path in migration_files()}
    if applied != expected:
        raise ValueError("Recovery migration ledger does not match the shipped image")
    # Source intake and all target writers must already be stopped. Locks also
    # make concurrent target operations wait instead of observing a partial cut.
    db.execute(text("LOCK TABLE mk_app.tenants, mk_app.users, mk_app.auth_sessions, "
        "mk_app.auth_factors, mk_app.auth_recovery_codes, mk_app.auth_revocations, "
        "mk_app.security_restore_receipts, mk_app.recovered_session_revocations "
        "IN ACCESS EXCLUSIVE MODE"))
    return target_binding(db)


def decoded(model, row):
    return {name: ledger.stamp(value) if value is not None and
        model.__table__.columns[name].type.python_type is datetime else value
        for name, value in row.items()}


def identities(db, source):
    result = {row["id"]: row for row in source["sessions"]}
    for model in (AuthSession, AuthRevocation, RecoveredSessionRevocation):
        for row in db.scalars(select(model)):
            sid = row.id if model is AuthSession else row.session_id
            binding = {"id": sid, "tenant_id": row.tenant_id, "user_id": row.user_id}
            if sid in result and result[sid] != binding:
                raise ValueError("Conflicting restored session identity")
            result[sid] = binding
    return [result[key] for key in sorted(result)]


def validate_target(db, source):
    for group in ("tenants", "users"):
        model, _ = ledger.GROUPS[group]
        incoming = {row["id"]: row for row in source[group]}
        for old in db.scalars(select(model)):
            row = incoming.get(old.id)
            if row is None:
                raise ValueError("Security snapshot omitted a retained identity")
            if ledger.stamp(old.created_at) != ledger.stamp(row["created_at"]) or (
                    group == "users" and old.tenant_id != row["tenant_id"]):
                raise ValueError("Security snapshot identity collision")
    for group in ("factors", "recovery_codes"):
        model, _ = ledger.GROUPS[group]
        for row in source[group]:
            key = row["user_id"] if group == "factors" else row["id"]
            old = db.get(model, key)
            if old and (old.tenant_id != row["tenant_id"] or old.user_id != row["user_id"]):
                raise ValueError("Security credential ownership collision")
            if group == "factors":
                if (row["secret_enc"] is None) != (row["confirmed_at"] is None):
                    raise ValueError("Incomplete confirmed MFA factor")
                if row["secret_enc"] is not None:
                    import base64
                    try:
                        seed = unseal_secret(row["secret_enc"], f'mfa:{row["tenant_id"]}:{row["user_id"]}')
                        if not 16 <= len(base64.b32decode(seed, casefold=False)) <= 64:
                            raise ValueError("Invalid MFA seed")
                    except Exception:
                        raise ValueError("MFA recovery key or factor is invalid") from None
            elif old and (old.digest != row["digest"] or (
                    old.consumed_at is not None and row["consumed_at"] is None)):
                raise ValueError("Recovery code identity or consumption rollback")
    identities(db, source)


def gate(db, recovery_id, *, security_sha256, privacy_sha256, target_binding):
    receipt = db.get(SecurityRestoreReceipt, recovery_id)
    if receipt is None or (receipt.ledger_sha256, receipt.privacy_sha256, receipt.target_binding) != (
            security_sha256, privacy_sha256, target_binding):
        raise ValueError("Missing or conflicting security recovery receipt")
    expected = json.loads(receipt.sessions_json, object_pairs_hook=ledger.strict_object)
    pending = 0
    for identity in expected:
        row = db.get(RecoveredSessionRevocation, identity["id"])
        if row is None or (row.tenant_id, row.user_id, row.restore_id) != (
                identity["tenant_id"], identity["user_id"], recovery_id):
            raise ValueError("Recovered session fence is missing or belongs to another generation")
        old = db.get(AuthSession, identity["id"])
        if old and (old.tenant_id != row.tenant_id or old.user_id != row.user_id or old.revoked_at is None):
            raise ValueError("Restored session authority was reopened")
        pending += row.confirmed_at is None
    return {"applied": True, "recovery_id": recovery_id, "sessions_fenced": len(expected),
            "pending_kernel_revocations": pending, "security_ready": pending == 0,
            "status": "READY_SECURITY_ONLY" if pending == 0 else "PENDING_KERNEL_REVOCATIONS"}


def restore(db, checked, privacy_raw, not_before, recovery_id, *, apply=False):
    if not isinstance(checked, ledger.AuthenticatedSnapshot) or checked.authentication is not ledger._AUTHENTICATED:
        raise ValueError("Authenticated encrypted security snapshot required")
    if not ledger.hex_value(recovery_id, 32):
        raise ValueError("A separately retained recovery generation ID is required")
    source = ledger.validate_snapshot(checked.value)
    records = load_ledger(privacy_raw, checked.privacy_digest, not_before)
    target = operator_context(db)
    previous = db.get(SecurityRestoreReceipt, recovery_id)
    if previous is not None:
        # Never reapply credentials over changes made AFTER a successful restore.
        return {**gate(db, recovery_id, security_sha256=checked.digest,
            privacy_sha256=checked.privacy_digest, target_binding=target), "already_applied": True}
    latest = db.scalar(select(SecurityRestoreReceipt.source_exported_at)
        .order_by(SecurityRestoreReceipt.source_exported_at.desc()).limit(1))
    if latest and ledger.stamp(source["exported_at"]) < ledger.stamp(latest):
        raise ValueError("Security recovery cannot roll back a newer recovery generation")
    validate_target(db, source)
    replay_ledger(db, records, apply=False)
    sessions = identities(db, source)
    if not apply:
        return {"applied": False, "status": "VALIDATED_ONLY", "sessions_to_fence": len(sessions),
                "accounts": len(source["users"]), "security_ready": False}
    # Erase old business content before synchronizing the CURRENT security state.
    # SQL erasure fences remain enabled and reject any incompatible reactivation.
    privacy = replay_ledger(db, records, apply=True)
    for group in ("tenants", "users"):
        model, _ = ledger.GROUPS[group]
        for raw in source[group]:
            values = decoded(model, raw)
            if group == "users": values["referred_by"] = None
            row = db.get(model, raw["id"])
            if row is None: db.add(model(**values))
            else:
                for key, value in values.items(): setattr(row, key, value)
        db.flush()
    for raw in source["users"]:
        db.get(User, raw["id"]).referred_by = raw["referred_by"]
    db.flush()
    # The pinned source is authoritative for rotation and recovery-code use.
    # Pending enrollments never cross a restore or authorize an old session.
    for group in ("factors", "recovery_codes"):
        model, _ = ledger.GROUPS[group]
        db.execute(delete(model))
        for raw in source[group]: db.add(model(**decoded(model, raw)))
        db.flush()
    now = datetime.now(timezone.utc)
    db.add(SecurityRestoreReceipt(id=recovery_id, ledger_sha256=checked.digest,
        privacy_sha256=checked.privacy_digest, target_binding=target,
        source_exported_at=ledger.stamp(source["exported_at"]),
        sessions_json=ledger.canonical(sessions).decode(), applied_at=now))
    db.flush()
    for identity in sessions:
        row = db.get(AuthSession, identity["id"])
        if row:
            row.revoked_at = row.revoked_at or now
            row.mfa_verified_at = row.step_up_at = None
    db.flush()
    for identity in sessions:
        row = db.get(RecoveredSessionRevocation, identity["id"])
        if row is None:
            db.add(RecoveredSessionRevocation(session_id=identity["id"], tenant_id=identity["tenant_id"],
                user_id=identity["user_id"], restore_id=recovery_id, created_at=now, next_attempt_at=now))
        else:
            row.restore_id = recovery_id
            row.confirmed_at = row.lease_id = None
            row.attempts = 0
            row.last_error = ""
            row.next_attempt_at = now
    db.flush()
    return {**gate(db, recovery_id, security_sha256=checked.digest,
        privacy_sha256=checked.privacy_digest, target_binding=target), "privacy": privacy}


def main():
    import argparse
    import os
    from pathlib import Path
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import Session
    from ..config import Settings, get_settings
    from ..db import init_engine
    from .privacy_ledger import export_ledger

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["export", "replay", "check", "deliver"])
    parser.add_argument("--privacy-ledger", type=Path)
    parser.add_argument("--security-ledger", type=Path)
    parser.add_argument("--privacy-sha256")
    parser.add_argument("--security-sha256")
    parser.add_argument("--not-before")
    parser.add_argument("--recovery-id")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--quiesced", action="store_true",
        help="Acknowledge source intake and security/billing writers stopped; target ingress/dispatch remain disabled")
    args = parser.parse_args()
    if args.apply and args.operation != "replay": parser.error("--apply is only valid for replay")
    if (args.operation == "export" or args.apply) and not args.quiesced:
        parser.error("Export/apply requires an explicit --quiesced acknowledgment")
    if args.operation == "deliver":
        import asyncio
        from ..auth_sessions import drain_revocations
        from ..kernel import get_kernel_client
        if not ledger.hex_value(args.security_sha256) or not ledger.hex_value(args.privacy_sha256) or not ledger.hex_value(args.recovery_id, 32):
            parser.error("Delivery requires the recovery ID and both independently retained digests")
        # Only the ordinary runtime role/signing capability: no archive private
        # key, plaintext credential snapshot, migration role or public ingress.
        engine = init_engine(get_settings().connection_url)
        try:
            with Session(engine) as db:
                binding = target_binding(db)
                context = dict(security_sha256=args.security_sha256, privacy_sha256=args.privacy_sha256,
                    target_binding=binding)
                gate(db, args.recovery_id, **context)
                db.commit()
                delivered = asyncio.run(drain_revocations(db, get_kernel_client()))
                db.expire_all()
                report = {**gate(db, args.recovery_id, **context), "deliveries_recorded": delivered}
            print(json.dumps(report, sort_keys=True))
            if not report["security_ready"]: raise SystemExit(2)
        finally: engine.dispose()
        return
    if not args.privacy_ledger or not args.security_ledger:
        parser.error("Export/replay/check requires both ledger paths")
    if args.privacy_ledger.resolve() == args.security_ledger.resolve():
        parser.error("The public ledger and encrypted security archive require different paths")
    if args.operation == "export":
        if args.privacy_ledger.exists() or args.security_ledger.exists():
            raise ValueError("Recovery files already exist; no overwrite is allowed")
        engine = init_engine(get_settings().connection_url)
        try:
            with Session(engine) as db:
                db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
                privacy = export_ledger(db)
                digest = ledger.sha256(privacy)
                security = ledger.export_encrypted(db, os.environ["MK_SECURITY_RECOVERY_PUBLIC_KEY"], digest)
            for path, data in ((args.privacy_ledger, privacy), (args.security_ledger, security)):
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
            print(json.dumps({"privacy_sha256": digest, "security_sha256": ledger.sha256(security),
                "status": "EXPORTED_PIN_BOTH_DIGESTS_IN_INDEPENDENT_CUSTODY"}, sort_keys=True))
        finally: engine.dispose()
        return
    if not all((args.privacy_sha256, args.security_sha256, args.not_before, args.recovery_id)):
        parser.error("Replay/check requires both independent digests, --not-before and --recovery-id")
    cutoff = ledger.stamp(args.not_before)
    checked = ledger.load_encrypted(args.security_ledger.read_bytes(), args.security_sha256,
        cutoff, os.environ["MK_SECURITY_RECOVERY_PRIVATE_KEY"], args.privacy_sha256)
    url = make_url(os.environ["MK_SECURITY_RESTORE_DATABASE_URL"])
    resolved = Settings(_env_file=None, database_url=url.render_as_string(hide_password=False),
                        db_host="", db_password="").connection_url
    engine = create_engine(resolved, hide_parameters=True)
    try:
        with Session(engine) as db:
            report = restore(db, checked, args.privacy_ledger.read_bytes(), cutoff,
                args.recovery_id, apply=args.apply)
            if args.operation == "check" and not report.get("already_applied"):
                raise ValueError("No security recovery receipt for this generation")
            if args.apply: db.commit()
        print(json.dumps(report, sort_keys=True))
        if args.operation == "check" and not report["security_ready"]: raise SystemExit(2)
    finally: engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never expose profiles, password verifiers, seal keys or SQL parameters.
        print(json.dumps({"error": type(exc).__name__, "status": "refused"}))
        raise SystemExit(1) from None
