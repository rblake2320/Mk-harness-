"""Subscription entitlement gate.

`require_active_subscription` is a drop-in FastAPI dependency. It is a no-op while
settings.billing_enforced is False (the default), so existing flows and the 90-day trial
period are unaffected. Flip BILLING_ENFORCED=1 at launch to require an active/trialing
subscription for gated AI features; unsubscribed users then get HTTP 402.
"""
from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Subscription, User
from .security import get_current_user

_ENTITLED = ("trialing", "active")


def require_active_subscription(user: User = Depends(get_current_user),
                                db: Session = Depends(get_db)) -> User:
    if not get_settings().billing_enforced:
        return user
    sub = db.scalar(select(Subscription).where(Subscription.user_id == user.id))
    if not sub or sub.status not in _ENTITLED:
        raise HTTPException(402, {
            "code": "subscription_required",
            "message": "An active subscription is required. Start your free trial.",
        })
    return user
