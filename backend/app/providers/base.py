"""Provider-agnostic LLM interface.

Every provider (Anthropic, OpenAI, Gemini, Ollama/local, or anything added
later) implements ProviderAdapter. The rest of the application only ever
speaks these types — swapping or adding models requires zero changes
outside this package.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field


@dataclass
class ImagePart:
    media_type: str  # image/jpeg, image/png, image/webp
    data_b64: str


@dataclass
class ChatMessage:
    role: str  # "user" | "assistant"
    content: str
    images: list[ImagePart] = field(default_factory=list)


@dataclass
class ChatRequest:
    messages: list[ChatMessage]
    system: str = ""
    model: str = ""
    max_tokens: int = 1024
    temperature: float = 0.7
    json_mode: bool = False  # instruct the model to emit a single JSON object


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class ChatResult:
    text: str
    usage: Usage
    model: str
    provider: str


@dataclass
class StreamChunk:
    delta: str = ""
    done: bool = False
    usage: Usage | None = None


class ProviderError(Exception):
    """Normalized provider failure. retryable=True triggers failover."""

    def __init__(self, message: str, status: int = 0, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class ProviderAdapter(ABC):
    name: str = "base"

    def __init__(self, api_key: str = "", base_url: str = ""):
        self.api_key = api_key
        self.base_url = base_url

    @abstractmethod
    async def complete(self, req: ChatRequest) -> ChatResult: ...

    @abstractmethod
    def stream(self, req: ChatRequest) -> AsyncIterator[StreamChunk]: ...

    @abstractmethod
    def default_model(self, vision: bool = False) -> str: ...


# ---------------------------------------------------------------------------
# Model catalog: cost per million tokens (USD) for metering. Prices change;
# update here or override via admin API without touching adapter code.
# Unknown models meter at 0 cost but still record token counts.
# ---------------------------------------------------------------------------
MODEL_CATALOG: dict[str, dict] = {
    # provider: anthropic
    "claude-sonnet-4-6":          {"provider": "anthropic", "in": 3.00,  "out": 15.00, "vision": True},
    "claude-haiku-4-5-20251001":  {"provider": "anthropic", "in": 1.00,  "out": 5.00,  "vision": True},
    # provider: openai
    "gpt-4o":                     {"provider": "openai",    "in": 2.50,  "out": 10.00, "vision": True},
    "gpt-4o-mini":                {"provider": "openai",    "in": 0.15,  "out": 0.60,  "vision": True},
    # provider: gemini
    "gemini-2.0-flash":           {"provider": "gemini",    "in": 0.10,  "out": 0.40,  "vision": True},
    "gemini-1.5-pro":             {"provider": "gemini",    "in": 1.25,  "out": 5.00,  "vision": True},
    # provider: ollama (local — no per-token cost)
    "llama3.2-vision":            {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": True},
    "llama3.1":                   {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": False},
    # MK-trained local models (DGX Spark GB10)
    "mk-copilot-nano:latest":     {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": False},
    "mk-copilot-v2:latest":       {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": False},
    "mk-copilot-trained:latest":  {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": False},
    "student-mk-trained:latest":  {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": False},
    "aiarmy-mk-copilot:latest":   {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": False},
    "qwen3-vl:latest":            {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": True},
    "llama3.2-vision:latest":     {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": True},
    "qwen2.5:7b":                 {"provider": "ollama",    "in": 0.0,   "out": 0.0,   "vision": False},
}


def cost_usd(model: str, usage: Usage) -> float:
    entry = MODEL_CATALOG.get(model)
    if not entry:
        return 0.0
    return round(
        usage.input_tokens / 1_000_000 * entry["in"]
        + usage.output_tokens / 1_000_000 * entry["out"], 6,
    )
