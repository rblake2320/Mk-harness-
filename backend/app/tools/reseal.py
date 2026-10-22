"""Application sealing-key lifecycle: status, activate write fence, rekey.

Secrets come from APP_SEAL_KEYS, never CLI arguments. status/rekey use the normal
restricted app DB login; activate uses only MK_APP_MIGRATION_URL. No provider
calls, fingerprint changes, approval changes or dispatch enable operations.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from dataclasses import asdict, dataclass, field

from sqlalchemy import create_engine, select, text, update
from sqlalchemy.orm import Session

from ..config import get_settings
from ..crypto import ciphertext_kid, key_aad, seal_secret, unseal_secret
from ..models import (ApplicationSealPolicy, AuditLog, AuthFactor, CustomerDestination,
                      DraftVersion, ExceptionRecord, ImportRow, Outcome, ProviderKey)


@dataclass(frozen=True)
class Field:
    model: type
    name: str
    kind: str

    def aad(self, row):
        if self.model is ProviderKey:
            return key_aad(row.tenant_id, row.user_id, row.provider)
        if self.model is AuthFactor:
            base = f"mfa:{row.tenant_id}:{row.user_id}"
            if self.name == "pending_secret_enc":
                if not row.pending_session_id:
                    raise ValueError("Pending MFA binding is missing")
                base += f":pending:{row.pending_session_id}"
            return base
        return f"mk-foundation:{row.tenant_id}:{self.kind}"

    def bindings(self, row):
        values = {"tenant_id": row.tenant_id}
        if self.model is ProviderKey:
            values.update(user_id=row.user_id, provider=row.provider)
        if self.model is AuthFactor:
            values["user_id"] = row.user_id
            if self.name == "pending_secret_enc":
                values["pending_session_id"] = row.pending_session_id
        return values


FIELDS = (
    Field(ProviderKey, "ciphertext", "provider"),
    Field(CustomerDestination, "value_enc", "destination"),
    Field(ImportRow, "phone_enc", "destination"), Field(ImportRow, "email_enc", "destination"),
    Field(DraftVersion, "text_enc", "draft"), Field(ExceptionRecord, "detail_enc", "exception"),
    Field(Outcome, "note_enc", "outcome"), Field(AuthFactor, "secret_enc", "mfa"),
    Field(AuthFactor, "pending_secret_enc", "mfa"),
)


@dataclass
class Report:
    total: int = 0
    stale: int = 0
    unreadable: int = 0
    updated: int = 0
    conflicts: int = 0
    key_counts: dict[str, int] = field(default_factory=dict)
    database_writer_kid: str | None = None
    legacy_writes_allowed: bool | None = None

    def clean(self):
        current = get_settings().seal_key_list[0][0]
        return (not (self.stale or self.unreadable or self.conflicts)
                and self.database_writer_kid == current and self.legacy_writes_allowed is False)


def scan(db: Session, *, apply=False, batch_size=200, actor="operator") -> Report:
    if not 1 <= batch_size <= 1000:
        raise ValueError("batch_size must be between 1 and 1000")
    if not actor or len(actor) > 32:
        raise ValueError("actor must be a nonempty operator identifier of at most 32 characters")
    keys = get_settings().seal_key_list
    current = keys[0][0]
    policy = db.get(ApplicationSealPolicy, 1, populate_existing=True)
    rep = Report(database_writer_kid=policy.writer_kid if policy else None,
                 legacy_writes_allowed=policy.allow_legacy if policy else None)
    if apply and db.bind.dialect.name == "postgresql" and (not policy or policy.writer_kid != current or policy.allow_legacy):
        raise RuntimeError("Activate the current sealing-key write fence before rekey")
    counts = Counter()
    for item in FIELDS:
        primary = next(iter(item.model.__table__.primary_key.columns))
        column = getattr(item.model, item.name)
        after = None
        while True:
            query = select(item.model).where(column.is_not(None), column != "").order_by(primary).limit(batch_size)
            if after is not None:
                query = query.where(primary > after)
            rows = list(db.scalars(query.execution_options(populate_existing=True)))
            if not rows:
                break
            audit_counts = Counter()
            for row in rows:
                after = getattr(row, primary.name)
                old = getattr(row, item.name)
                rep.total += 1
                try:
                    kid = ciphertext_kid(old)
                    binding = item.aad(row)
                    plaintext = unseal_secret(old, binding, keys=keys)
                except Exception:
                    rep.unreadable += 1
                    counts["unreadable"] += 1
                    continue
                counts[kid] += 1
                if kid == current:
                    continue
                rep.stale += 1
                if not apply:
                    continue
                replacement = seal_secret(plaintext, binding, keys=keys)
                conditions = [primary == after, column == old]
                conditions.extend(getattr(item.model, key) == value for key, value in item.bindings(row).items())
                changed = db.execute(update(item.model).where(*conditions).values({item.name: replacement})
                                     .execution_options(synchronize_session=False)).rowcount
                if changed == 1:
                    rep.updated += 1
                    audit_counts[row.tenant_id] += 1
                else:
                    rep.conflicts += 1
            if apply:
                for tenant, count in audit_counts.items():
                    db.add(AuditLog(tenant_id=tenant, user_id=actor, action="security.seal_rekey",
                                    detail=json.dumps({"field": f"{item.model.__tablename__}.{item.name}",
                                                       "writer_kid": current, "updated": count}, sort_keys=True)))
                db.commit()  # changed ciphertext and audit commit together, one bounded batch
    rep.key_counts = dict(counts)
    if apply:
        after_report = scan(db, batch_size=batch_size, actor=actor)
        after_report.updated, after_report.conflicts = rep.updated, rep.conflicts
        return after_report
    return rep


def activate(url, *, actor="operator"):
    """Only the separate migration login can change the database write policy."""
    current = get_settings().seal_key_list[0][0]
    from ..migrate import require_migration_identity
    from ..config import Settings
    from sqlalchemy.engine import make_url
    if not actor or len(actor) > 32:
        raise ValueError("actor must identify the operator with at most 32 characters")
    resolved = Settings(_env_file=None, database_url=make_url(url).render_as_string(hide_password=False),
                        db_host="", db_password="").connection_url
    engine = create_engine(resolved, hide_parameters=True)
    try:
        with engine.begin() as conn:
            require_migration_identity(conn)
            conn.exec_driver_sql("SELECT pg_advisory_xact_lock(58721493622)")
            # The policy's statement trigger takes the exclusive lock before any
            # change and waits for all outstanding shared-lock ciphertext writes.
            previous = conn.execute(text("SELECT writer_kid FROM mk_app.application_seal_policy WHERE id=1")).scalar_one()
            result = conn.execute(text("UPDATE mk_app.application_seal_policy SET writer_kid=:kid, allow_legacy=false WHERE id=1"), {"kid": current})
            if result.rowcount != 1:
                raise RuntimeError("Application sealing policy is missing")
            import uuid
            conn.execute(text("INSERT INTO mk_app.audit_logs(id,tenant_id,user_id,action,detail,created_at) VALUES (:id,'platform',:actor,'security.seal_activate',:detail,now())"),
                         {"id": uuid.uuid4().hex, "actor": actor, "detail": json.dumps({"from": previous, "to": current})})
            return {"from": previous, "writer_kid": current, "allow_legacy": False}
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["status", "activate", "rekey"])
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--actor", default="operator")
    args = parser.parse_args()
    if args.command == "activate":
        print(json.dumps(activate(os.environ["MK_APP_MIGRATION_URL"], actor=args.actor)))
        return 0
    from ..db import get_db
    generator = get_db()
    db = next(generator)
    try:
        report = scan(db, apply=args.command == "rekey", batch_size=args.batch_size, actor=args.actor)
    finally:
        generator.close()
    print(json.dumps(asdict(report), sort_keys=True))
    return 0 if report.clean() else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "outcome": "Failed"}))
        raise SystemExit(2) from None
