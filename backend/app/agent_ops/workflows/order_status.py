from __future__ import annotations


def build(payload: dict, response: str) -> list[dict]:
    return [
        {"action": "open_url", "url": payload["portal_url"]},
        {"action": "click", "description": "order history"},
        {
            "action": "scrape",
            "description": f"status for order {payload['order_id']}",
            "return_as": "status",
        },
    ]
