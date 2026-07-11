from __future__ import annotations


def build(payload: dict, response: str) -> list[dict]:
    return [
        {"action": "open_url", "url": payload["booking_url"]},
        {"action": "click", "description": "requested available time slot"},
        {"action": "click", "description": "confirm booking"},
        {
            "action": "scrape",
            "description": "booking confirmation number",
            "return_as": "confirmation_number",
        },
    ]
