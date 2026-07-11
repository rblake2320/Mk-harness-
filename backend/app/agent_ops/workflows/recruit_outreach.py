from __future__ import annotations


def build(payload: dict, response: str) -> list[dict]:
    message = f"{response.strip()}\n\nIndependent Beauty Consultant"
    return [
        {"action": "open", "target": payload.get("platform", "instagram")},
        {"action": "click", "description": "new direct message"},
        {"action": "input", "field": "recipient", "value": payload["handle"]},
        {"action": "input", "field": "message", "value": message},
        {"action": "click", "description": "send direct message"},
    ]
