"""Disposable-fixture child process; deliberately refuses non-loopback resources."""
import asyncio
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
from app import billing, db
from app.billing_erasure import BillingErasureClient, deliver_billing_erasure


def main():
    endpoint, task_id = sys.argv[1:]
    origin = urlsplit(endpoint)
    target = make_url(os.environ["MK_BILLING_FIXTURE_DB"])
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.path != "/v1" or origin.query or origin.fragment or origin.username:
        raise RuntimeError("Fixture requires loopback provider")
    if target.host != "127.0.0.1" or not target.database.startswith("mk_app_acceptance_"):
        raise RuntimeError("Fixture requires disposable acceptance database")
    os.environ["STRIPE_SECRET_KEY"] = "synthetic-local-fixture-only"
    from app.config import get_settings
    get_settings.cache_clear()
    billing._API = endpoint  # test-only endpoint; production has no URL override
    db.init_engine(target)
    with db._SessionLocal() as session:
        confirmed = asyncio.run(deliver_billing_erasure(session, BillingErasureClient(), task_id))
    print("confirmed" if confirmed else "pending")
    return 0 if confirmed else 1


if __name__ == "__main__":
    raise SystemExit(main())
