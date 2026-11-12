"""Application sealing-key rotation (contract S10).

    python -m app.tools.rekey status   # counts per key id; exit 1 if any row is not
                                       # under the current key or cannot be opened
    python -m app.tools.rekey rekey    # re-seal every row under the current key

Covers every column the application seals: destinations and import contacts,
drafts, exception details, outcome notes, TOTP secrets and provider API keys.
Each row is opened with the key its ciphertext names and re-sealed under the
current key with the SAME associated data, in batches committed as they go
(idempotent: a crash resumes where it stopped). Rotation:
  1. SEALING_KEYS="new=<b64>,m0=master"  (new first; old still listed) → restart
  2. rekey  → status must show every row under `new` and 0 unreadable
  3. SEALING_KEYS="new=<b64>"            → restart; old key can be destroyed
"""
from __future__ import annotations

import json
import sys
from collections import Counter

from sqlalchemy import select

from ..crypto import key_aad, key_id_of, open_value, seal_value
from ..config import get_settings
from ..foundation import _aad
from ..models import (CustomerDestination, DraftVersion, ExceptionRecord, ImportRow, MfaFactor, Outcome,
                      ProviderKey)

BATCH = 500


def _columns():
    """(model, column, aad(row)) for every sealed column."""
    return [
        (CustomerDestination, "value_enc", lambda r: _aad(r.tenant_id, "destination")),
        (ImportRow, "phone_enc", lambda r: _aad(r.tenant_id, "destination")),
        (ImportRow, "email_enc", lambda r: _aad(r.tenant_id, "destination")),
        (DraftVersion, "text_enc", lambda r: _aad(r.tenant_id, "draft")),
        (ExceptionRecord, "detail_enc", lambda r: _aad(r.tenant_id, "exception")),
        (Outcome, "note_enc", lambda r: _aad(r.tenant_id, "outcome")),
        (MfaFactor, "secret_enc", lambda r: _aad(r.tenant_id, f"totp:{r.user_id}:{r.id}")),
        (ProviderKey, "ciphertext", lambda r: key_aad(r.tenant_id, r.user_id, r.provider)),
    ]


def scan(db, apply: bool) -> dict:
    current = get_settings().sealing_key_list[0][0]
    by_kid: Counter = Counter()
    unreadable: list[str] = []
    resealed = 0
    for model, col, aad in _columns():
        last = ""
        while True:
            rows = db.scalars(select(model).where(model.id > last).order_by(model.id).limit(BATCH)).all()
            if not rows:
                break
            for r in rows:
                ct = getattr(r, col) or ""
                if not ct:
                    continue
                kid = key_id_of(ct)
                by_kid[kid] += 1
                try:
                    pt = open_value(ct, aad(r))
                except Exception:  # noqa: BLE001 — wrong/missing key or corrupted: reported, never re-sealed
                    unreadable.append(f"{model.__tablename__}.{col}:{r.id}")
                    continue
                if apply and kid != current:
                    setattr(r, col, seal_value(pt, aad(r)))
                    resealed += 1
            last = rows[-1].id
            if apply:
                db.commit()
    stale = sum(n for k, n in by_kid.items() if k != current)
    return {"current": current, "by_key": dict(by_kid), "stale": stale if not apply else stale - resealed,
            "resealed": resealed, "unreadable": len(unreadable), "unreadable_rows": unreadable[:50]}


def main(argv=None) -> int:
    from ..db import get_db
    argv = sys.argv[1:] if argv is None else argv
    if argv not in (["status"], ["rekey"]):
        print(__doc__)
        return 2
    db = next(get_db())
    try:
        out = scan(db, apply=argv == ["rekey"])
    finally:
        db.close()
    print(json.dumps(out, sort_keys=True))
    return 0 if (out["stale"] == 0 and out["unreadable"] == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
