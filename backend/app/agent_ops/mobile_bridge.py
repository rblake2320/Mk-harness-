"""Translate governed workflow output into a versioned mobile-adapter envelope.

The upstream PhoneClaw project documents JavaScript ClawScript helpers but no remote
webhook protocol. This module therefore targets an operator-controlled adapter, not
the APK directly. ``verified_on_device`` remains false until a real-device receipt is
recorded for the exact adapter version.
"""

from __future__ import annotations

import json
from typing import Any

from . import WORK_ORDER_SCHEMA
from .workflows import BUILDERS

_DIRECT_OPEN = {
    "instagram": "launchInstagram",
    "x": "launchTwitter",
    "tiktok": "launchTikTok",
}


def _js(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)


def _compile_clawscript(steps: list[dict]) -> tuple[str, list[str]]:
    lines = ['speakText("Starting governed mobile work order");']
    adapter_actions: list[str] = []
    scrape_index = 0
    for step in steps:
        action = step["action"]
        if action == "click":
            lines.append(f"magicClicker({_js(step['description'])});")
            lines.append("delay(1200);")
        elif action == "scrape":
            scrape_index += 1
            lines.append(
                f"var scrapeResult{scrape_index} = magicScraper({_js(step['description'])});"
            )
        elif action == "open" and step.get("target") in _DIRECT_OPEN:
            lines.append(f"{_DIRECT_OPEN[step['target']]}();")
            lines.append("delay(2000);")
        else:
            adapter_actions.append(action)
            lines.append(f"// Adapter action required: {_js(step)}")
    lines.append('speakText("ClawScript-supported steps completed");')
    return "\n".join(lines) + "\n", sorted(set(adapter_actions))


def build(workflow: str, response: str, payload_json: str) -> dict:
    if workflow not in BUILDERS:
        raise ValueError(f"unsupported workflow: {workflow}")
    payload = json.loads(payload_json)
    steps = BUILDERS[workflow](payload, response)
    source, adapter_actions = _compile_clawscript(steps)
    return {
        "schema": WORK_ORDER_SCHEMA,
        "adapter": "mobile-adapter-v1",
        "upstream_contract": (
            "PhoneClaw ClawScript helper surface at commit "
            "c59995b726a127da16275d2d8e0760408b988542"
        ),
        "verified_on_device": False,
        "workflow": workflow,
        "steps": steps,
        "clawscript_source": source,
        "adapter_actions_required": adapter_actions,
        "result_fields": [step["return_as"] for step in steps if step.get("return_as")],
    }
