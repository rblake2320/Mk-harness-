from __future__ import annotations


def build(payload: dict, response: str) -> list[dict]:
    caption = f"{response.strip()}\n\nIndependent Beauty Consultant"
    return [
        {"action": "open", "target": payload.get("platform", "instagram")},
        {"action": "click", "description": "create a new post"},
        {"action": "input", "field": "caption", "value": caption},
        {"action": "click", "description": "share post"},
    ]
