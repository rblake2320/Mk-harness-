from __future__ import annotations


def build(payload: dict, response: str) -> list[dict]:
    message = f"{response.strip()}\n\nIndependent Beauty Consultant"
    return [
        {"action": "open", "target": "sms"},
        {"action": "click", "description": "start a new message"},
        {"action": "input", "field": "recipient", "value": payload["phone"]},
        {"action": "input", "field": "message", "value": message},
        {"action": "click", "description": "send message"},
    ]
