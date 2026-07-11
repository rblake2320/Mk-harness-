"""Load and validate the published Agent Operations wire contracts."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

CONTRACT_DIR = Path(__file__).resolve().parents[2] / "contracts" / "agent_ops" / "v1"

CONTRACT_FILES = {
    "work_order": "mobile-work-order.schema.json",
    "ping": "mobile-agent-ping.schema.json",
    "executing": "mobile-execution-state.schema.json",
    "complete": "mobile-execution-completion.schema.json",
    "failed": "mobile-execution-failure.schema.json",
}


class ContractValidationError(ValueError):
    """Raised when a wire payload does not match its published schema."""


@lru_cache(maxsize=len(CONTRACT_FILES))
def validator(name: str) -> Draft202012Validator:
    try:
        path = CONTRACT_DIR / CONTRACT_FILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown Agent Operations contract: {name}") from exc
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_contract(name: str, value: Any) -> None:
    try:
        validator(name).validate(value)
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "payload"
        raise ContractValidationError(f"{location}: {exc.message}") from exc
