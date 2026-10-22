"""Export content-free erasure tombstones; replay a trusted ledger after restore.

The expected SHA256 and minimum freshness time MUST come from the separately
retained ledger/incident record, never from the restored database. This tool
does not enable traffic, confirm provider deletion, or certify backup expiry.
"""
import argparse
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import init_engine
from ..models import BillingErasureBinding, BillingProvision, ErasureRequest, User, Customer
from ..privacy import _task, erase_account, erase_customer

FIELDS = ("id", "tenant_id", "requested_by", "subject_kind", "subject_id", "requested_at", "due_at", "backup_expires_at")
DATES = {"requested_at", "due_at", "backup_expires_at"}
BILLING_FIELDS = ("id", "tenant_id", "user_id", "created_at", "stripe_customer_id")


def billing_identity(raw, request):
    if not isinstance(raw, dict) or set(raw) != set(BILLING_FIELDS):
        raise ValueError("Invalid billing ledger fields")
    row = dict(raw)
    if not all(isinstance(row[key], str) and re.fullmatch(r"[0-9a-f]{32}", row[key]) for key in ("id", "tenant_id", "user_id")):
        raise ValueError("Invalid billing ledger identity")
    if row["stripe_customer_id"] is not None and (not isinstance(row["stripe_customer_id"], str) or not re.fullmatch(r"cus_[A-Za-z0-9]{1,60}", row["stripe_customer_id"])):
        raise ValueError("Invalid billing provider identity")
    if isinstance(row["created_at"], str):
        row["created_at"] = timestamp(row["created_at"])
    if not isinstance(row["created_at"], datetime) or row["created_at"].tzinfo is None:
        raise ValueError("Invalid billing creation time")
    if request["subject_kind"] != "account" or request["tenant_id"] != row["tenant_id"] or request["subject_id"] != row["user_id"] or request["requested_by"] != row["user_id"] or row["created_at"] > request["requested_at"]:
        raise ValueError("Billing ledger request mismatch")
    return row


def binding_conflicts(existing, candidate):
    return any(normalized(getattr(existing, key), "requested_at" if key == "created_at" else key) != candidate[key]
        for key in BILLING_FIELDS if key != "stripe_customer_id") or bool(existing.stripe_customer_id
        and candidate["stripe_customer_id"] and existing.stripe_customer_id != candidate["stripe_customer_id"])


def timestamp(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Ledger timestamps require a time zone")
    return stamp.astimezone(timezone.utc)


def normalized(value, key):
    if key in DATES:
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return value


def export_ledger(db: Session) -> bytes:
    # The transaction snapshot comes BEFORE exported_at. A timestamp is a
    # freshness bound, not proof that another replica has stopped accepting work.
    # Operators must quiesce intake, billing creation and cleanup workers before
    # taking the final cut, so no accepted external effect occurs after export.
    records = []
    for row in db.scalars(select(ErasureRequest).order_by(ErasureRequest.requested_at, ErasureRequest.id)):
        record = {name: (normalized(getattr(row, name), name).isoformat() if name in DATES else getattr(row, name)) for name in FIELDS}
        record["billing_provisions"] = []
        if row.subject_kind == "account":
            from ..billing_erasure import resolve_binding
            binding = resolve_binding(db, row)
            original = db.scalar(select(BillingProvision.id).where(BillingProvision.user_id == row.subject_id))
            restored = db.scalar(select(BillingErasureBinding.id).where(BillingErasureBinding.request_id == row.id))
            if binding is None and (original or restored):
                raise ValueError("Conflicting billing ledger identities")
            if binding:
                record["billing_provisions"].append({name: (normalized(binding.created_at, "requested_at").isoformat()
                    if name == "created_at" else getattr(binding, name)) for name in BILLING_FIELDS})
        records.append(record)
    result = {"format": "mk-erasure-ledger-v2", "exported_at": datetime.now(timezone.utc).isoformat(), "requests": records}
    return (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()


def load_ledger(raw: bytes, expected_sha256: str, not_before: datetime):
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError("Erasure ledger exceeds size limit")
    if len(expected_sha256) != 64 or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256.lower()):
        raise ValueError("Erasure ledger digest mismatch")
    if not_before.tzinfo is None:
        raise ValueError("Minimum ledger time requires a time zone")
    data = json.loads(raw)
    if set(data) != {"format", "exported_at", "requests"} or data["format"] != "mk-erasure-ledger-v2":
        raise ValueError("Erasure ledger v2 required; refresh external cleanup identities")
    exported = timestamp(data["exported_at"])
    if not not_before <= exported <= datetime.now(timezone.utc):
        raise ValueError("Erasure ledger is stale or future-dated")
    if not isinstance(data["requests"], list):
        raise ValueError("Invalid erasure request list")
    records, seen, subjects, billing_ids, customer_ids = [], set(), set(), set(), set()
    for raw_row in data["requests"]:
        expected = set(FIELDS) | {"billing_provisions"}
        if not isinstance(raw_row, dict) or set(raw_row) != expected:
            raise ValueError("Invalid erasure record fields")
        row = dict(raw_row)
        for key in DATES:
            row[key] = timestamp(row[key])
        for key in set(FIELDS) - DATES:
            if not isinstance(row[key], str) or not 1 <= len(row[key]) <= 32:
                raise ValueError("Invalid erasure identifier")
        if row["subject_kind"] not in {"account", "customer"}:
            raise ValueError("Invalid erasure subject")
        if not row["requested_at"] <= exported or not row["requested_at"] < row["due_at"] <= row["backup_expires_at"]:
            raise ValueError("Invalid erasure dates")
        subject = (row["tenant_id"], row["subject_kind"], row["subject_id"])
        if row["id"] in seen or subject in subjects:
            raise ValueError("Duplicate erasure ledger record")
        bindings = row.get("billing_provisions", [])
        if not isinstance(bindings, list) or len(bindings) > 1:
            raise ValueError("Invalid billing obligation list")
        row["billing_provisions"] = [billing_identity(binding, row) for binding in bindings]
        for binding in row["billing_provisions"]:
            customer_id = binding["stripe_customer_id"]
            if binding["id"] in billing_ids or (customer_id is not None and customer_id in customer_ids):
                raise ValueError("Duplicate billing ledger identity")
            billing_ids.add(binding["id"])
            if customer_id is not None:
                customer_ids.add(customer_id)
        seen.add(row["id"]); subjects.add(subject); records.append(row)
    return records


def replay_ledger(db: Session, records: list[dict], *, apply=False) -> dict:
    # Validate the COMPLETE input against the restored identities before any
    # destructive write; never silently skip a tenant or ownership mismatch.
    for row in records:
        actor = db.get(User, row["requested_by"])
        if actor and actor.tenant_id != row["tenant_id"]:
            raise ValueError("Erasure ledger tenant mismatch")
        if row["subject_kind"] == "account" and row["subject_id"] != row["requested_by"]:
            raise ValueError("Account erasure subject mismatch")
        customer = db.get(Customer, row["subject_id"]) if row["subject_kind"] == "customer" else None
        if customer and (not actor or customer.tenant_id != row["tenant_id"] or customer.user_id != actor.id):
            raise ValueError("Erasure ledger customer ownership mismatch")
        existing = db.scalar(select(ErasureRequest).where(ErasureRequest.tenant_id == row["tenant_id"],
            ErasureRequest.subject_kind == row["subject_kind"], ErasureRequest.subject_id == row["subject_id"]))
        by_id = db.get(ErasureRequest, row["id"])
        if by_id and (not existing or by_id.id != existing.id):
            raise ValueError("Erasure ledger request ID collision")
        if existing and any(normalized(getattr(existing, key), key) != row[key]
                            for key in FIELDS):
            raise ValueError("Erasure ledger conflicts with retained tombstone")
        bindings = row.get("billing_provisions", [])
        if not isinstance(bindings, list) or len(bindings) > 1:
            raise ValueError("Invalid billing obligation list")
        for raw in bindings:
            candidate = billing_identity(raw, row)
            for model in (BillingProvision, BillingErasureBinding):
                existing_bindings = db.scalars(select(model).where((model.id == candidate["id"]) |
                    (model.user_id == candidate["user_id"]))).all()
                if any(binding_conflicts(binding, candidate) for binding in existing_bindings):
                    raise ValueError("Billing ledger conflicts with retained identity")
                if model is BillingErasureBinding and any(binding.request_id != row["id"] for binding in existing_bindings):
                    raise ValueError("Billing ledger request collision")
    if not apply:
        return {"applied": False, "requests": len(records), "active_store_replayed": 0}
    for row in records:
        if db.get(ErasureRequest, row["id"]) is None:
            db.add(ErasureRequest(**{key: row[key] for key in FIELDS}))
    db.flush()
    for row in records:
        for raw in row.get("billing_provisions", []):
            candidate = billing_identity(raw, row)
            binding = db.get(BillingErasureBinding, candidate["id"])
            if binding is None:
                db.add(BillingErasureBinding(request_id=row["id"], **candidate))
            elif binding.stripe_customer_id is None:
                binding.stripe_customer_id = candidate["stripe_customer_id"]
            _task(db, db.get(ErasureRequest, row["id"]), "billing_provision", candidate["id"])
    db.flush()
    count = 0
    # Customer requests precede accounts so original request IDs survive when an
    # account erasure sweeps the graph. One transaction, no partial restore gate.
    for row in sorted(records, key=lambda r: r["subject_kind"] == "account"):
        actor = db.get(User, row["requested_by"])
        if not actor:
            continue  # object never existed at this backup point; tombstone retained
        if row["subject_kind"] == "customer":
            if db.get(Customer, row["subject_id"]) is not None:
                erase_customer(db, actor, row["subject_id"], replay=True); count += 1
        else:
            erase_account(db, actor); count += 1
    db.flush()
    return {"applied": True, "requests": len(records), "active_store_replayed": count,
            "downstream_receipts_required": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["export", "replay"])
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--sha256")
    parser.add_argument("--not-before")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    engine = init_engine(get_settings().connection_url)
    with Session(engine) as db:
        if args.operation == "export":
            raw = export_ledger(db)
            # Never silently replace a previously retained ledger.
            with args.ledger.open("xb") as output:
                output.write(raw)
            print(json.dumps({"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}))
        else:
            if not args.sha256 or not args.not_before:
                parser.error("replay requires externally retained --sha256 and --not-before")
            records = load_ledger(args.ledger.read_bytes(), args.sha256, timestamp(args.not_before))
            report = replay_ledger(db, records, apply=args.apply)
            if args.apply:
                db.commit()
            print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "status": "refused"}))
        raise SystemExit(1) from None
