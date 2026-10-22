"""Application-side destination-fingerprint rotation (contract S6/S10).

    python -m app.tools.refingerprint status        # rows not under the current key; exit 1 if any
    python -m app.tools.refingerprint rekey         # rewrite every row under the current key

Rotation order (mirrors the kernel's `mk-keyctl fingerprint-*`; the two key lists
must stay identical so inbound tags match):

  1. FINGERPRINT_KEYS=m0=master,k2=<new>   (new key listed, not current) — deploy
  2. FINGERPRINT_KEYS=k2=<new>,m0=master   (new key current)            — deploy
  3. rekey — every CustomerDestination is re-fingerprinted from its sealed value,
     and every SuppressionEvent / ImportRow carrying one of that destination's
     fingerprints is moved with it, in one transaction per tenant
  4. status must exit 0 (no destination lacking the current fingerprint, no
     suppression unmapped) before m0 is removed from the list.

A SuppressionEvent whose fingerprint maps to no destination (its destination row
was deleted) is reported as `unmapped` and blocks step 4: lookups under the old key
still find it while the old key is listed, and removing the key would orphan it.
Never deletes or lifts a suppression.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..foundation import destination_value, fingerprints_all
from ..models import CustomerDestination, ImportRow, SuppressionEvent


@dataclass
class Report:
    destinations_total: int = 0
    destinations_stale: int = 0
    destinations_unreadable: int = 0
    suppressions_total: int = 0
    suppressions_stale: int = 0
    suppressions_unmapped: int = 0
    updated: int = 0
    notes: list[str] = field(default_factory=list)

    def clean(self) -> bool:
        return not (self.destinations_stale or self.destinations_unreadable
                    or self.suppressions_stale or self.suppressions_unmapped)


def _scan(db: Session, apply: bool) -> Report:
    rep = Report()
    # old fingerprint (any configured key) → current fingerprint, per tenant
    moves: dict[tuple[str, str], str] = {}
    current_fps: set[tuple[str, str]] = set()
    for d in db.scalars(select(CustomerDestination)):
        rep.destinations_total += 1
        try:
            fps = fingerprints_all(d.tenant_id, d.channel, destination_value(d))
        except Exception:  # noqa: BLE001 — sealed under a key we do not hold
            rep.destinations_unreadable += 1
            rep.notes.append(f"destination {d.id}: sealed value unreadable")
            continue
        current = fps[0]
        current_fps.add((d.tenant_id, current))
        if d.fingerprint not in fps:
            # Stored fingerprint reproduces under no configured key: an old key was
            # removed too early. Map it anyway (the sealed value is authoritative).
            rep.notes.append(f"destination {d.id}: stored fingerprint matches no configured key")
        for fp in set(fps) | {d.fingerprint}:
            if fp != current:
                moves[(d.tenant_id, fp)] = current
        if d.fingerprint != current:
            rep.destinations_stale += 1
            if apply:
                d.fingerprint = current
                rep.updated += 1
    for s in db.scalars(select(SuppressionEvent)):
        rep.suppressions_total += 1
        key = (s.tenant_id, s.fingerprint)
        if key in current_fps:
            continue
        if key in moves:
            rep.suppressions_stale += 1
            if apply:
                s.fingerprint = moves[key]
                rep.updated += 1
        else:
            rep.suppressions_unmapped += 1
            rep.notes.append(f"suppression {s.id}: fingerprint maps to no destination (keep the old key listed)")
    if apply:
        for r in db.scalars(select(ImportRow)):
            for attr in ("phone_fingerprint", "email_fingerprint"):
                v = getattr(r, attr, None)
                if v and (r.tenant_id, v) in moves:
                    setattr(r, attr, moves[(r.tenant_id, v)])
        db.flush()
        # Re-scan so the report states what is left, not what was found.
        after = _scan(db, apply=False)
        after.updated = rep.updated
        return after
    return rep


def status(db: Session) -> Report:
    return _scan(db, apply=False)


def rekey(db: Session) -> Report:
    rep = _scan(db, apply=True)
    db.commit()
    return rep


def main(argv: list[str] | None = None) -> int:
    from ..db import get_db
    args = argv if argv is not None else sys.argv[1:]
    if args[:1] not in (["status"], ["rekey"]):
        print(__doc__)
        return 2
    gen = get_db()
    db = next(gen)
    try:
        rep = rekey(db) if args[0] == "rekey" else status(db)
    finally:
        gen.close()
    print(f"destinations={rep.destinations_total} stale={rep.destinations_stale} unreadable={rep.destinations_unreadable} "
          f"suppressions={rep.suppressions_total} stale={rep.suppressions_stale} unmapped={rep.suppressions_unmapped} "
          f"updated={rep.updated}")
    for n in rep.notes[:50]:
        print("  -", n)
    if not rep.clean():
        print("NOT SAFE to remove an old fingerprint key from FINGERPRINT_KEYS")
        return 1
    print("every row is under the current fingerprint key")
    return 0


if __name__ == "__main__":
    sys.exit(main())
