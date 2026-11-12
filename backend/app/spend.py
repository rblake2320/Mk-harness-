"""Tenant spending limits (M4) and message-charge disclosure.

* AI spend: company-paid (central-key) model calls are capped per business per
  calendar month (UTC). The check runs where every model call resolves its key
  (`providers.router.resolve`), so chat, drafting, extraction and vision are all
  covered; a business at its cap gets 402 SPEND_LIMIT_REACHED and nothing is sent
  to a provider. Personal (BYO) keys bill the consultant directly and are not capped.
* SMS charges: the approval screen states the segment count and, when a price is
  configured, the estimated charge BEFORE the consultant approves.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .foundation import utcnow
from .models import Tenant, UsageRecord

GSM7 = set("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§"
           "¿abcdefghijklmnopqrstuvwxyzäöñüà")
GSM7_EXT = set("^{}\\[~]|€")


def month_start(now: datetime | None = None) -> datetime:
    n = now or utcnow()
    return datetime(n.year, n.month, 1, tzinfo=timezone.utc)


def budget_cents(db: Session, tenant_id: str) -> int:
    t = db.get(Tenant, tenant_id)
    if t is not None and t.monthly_ai_budget_cents is not None:
        return t.monthly_ai_budget_cents
    return get_settings().tenant_ai_budget_cents_default


def spent_cents(db: Session, tenant_id: str) -> int:
    usd = db.scalar(select(func.coalesce(func.sum(UsageRecord.cost_usd), 0.0)).where(
        UsageRecord.tenant_id == tenant_id, UsageRecord.key_scope == "central",
        UsageRecord.created_at >= month_start())) or 0.0
    return int(round(float(usd) * 100))


class SpendLimitReached(Exception):
    """Raised where a model key is resolved; mapped to 402 by the app's exception
    handler (and to an SSE error event by the streaming chat route)."""
    code = "SPEND_LIMIT_REACHED"
    detail = ("your business reached its monthly AI spending limit; the owner can raise it "
              "in Settings, or a consultant can use their own key")


def require_ai_budget(db: Session, tenant_id: str) -> None:
    cap = budget_cents(db, tenant_id)
    if cap > 0 and spent_cents(db, tenant_id) >= cap:
        raise SpendLimitReached()


def sms_segments(text: str) -> tuple[int, str]:
    """(segments, encoding) per GSM 03.38: GSM-7 160/153 septets, otherwise UCS-2 70/67
    code units (characters outside the BMP count twice)."""
    if all(ch in GSM7 or ch in GSM7_EXT for ch in text):
        units = sum(2 if ch in GSM7_EXT else 1 for ch in text)
        return (1 if units <= 160 else -(-units // 153)), "GSM-7"
    units = sum(2 if ord(ch) > 0xFFFF else 1 for ch in text)
    return (1 if units <= 70 else -(-units // 67)), "UCS-2"


def charge_disclosure(text: str | None) -> dict:
    segs, enc = sms_segments(text or "")
    price = get_settings().sms_price_per_segment_millicents
    est = segs * price if price > 0 else None
    return {"segments": segs, "encoding": enc,
            "price_per_segment_millicents": price or None,
            "estimated_millicents": est,
            "note": (f"{segs} SMS segment(s); estimated provider charge shown before you approve."
                     if est is not None else
                     f"{segs} SMS segment(s); the per-message price is not configured for this business, "
                     "so the charge cannot be estimated.")}
