"""Workflow-specific prompt and device action plans."""

from .appointment import build as appointment
from .follow_up import build as follow_up
from .order_status import build as order_status
from .recruit_outreach import build as recruit_outreach
from .social_post import build as social_post

BUILDERS = {
    "follow_up": follow_up,
    "appointment": appointment,
    "order_status": order_status,
    "recruit_outreach": recruit_outreach,
    "social_post": social_post,
}
