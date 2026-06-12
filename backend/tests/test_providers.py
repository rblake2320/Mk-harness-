"""Provider adapter contract tests.

These use respx to simulate each provider's documented wire format —
mocking exists ONLY in the test suite (per project rule); product code
always speaks to real endpoints. Each test asserts our adapters produce
byte-correct request payloads and parse real response/stream formats.
"""
import json

import httpx
import pytest
import respx

from app.providers.anthropic_openai import AnthropicAdapter, OpenAIAdapter
from app.providers.base import (
    ChatMessage, ChatRequest, ImagePart, ProviderError, Usage, cost_usd,
)
from app.providers.gemini_ollama import GeminiAdapter, OllamaAdapter

REQ = ChatRequest(messages=[ChatMessage(role="user", content="hello")],
                  system="be brief", model="", max_tokens=100)


@pytest.mark.asyncio
@respx.mock
async def test_anthropic_complete_payload_and_parse():
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={
            "model": "claude-sonnet-4-6",
            "content": [{"type": "text", "text": "hi there"}],
            "usage": {"input_tokens": 12, "output_tokens": 4},
        }))
    a = AnthropicAdapter(api_key="sk-ant-x")
    res = await a.complete(REQ)
    sent = json.loads(route.calls[0].request.content)
    assert sent["system"] == "be brief"
    assert sent["messages"] == [{"role": "user", "content": "hello"}]
    assert route.calls[0].request.headers["x-api-key"] == "sk-ant-x"
    assert res.text == "hi there" and res.usage.input_tokens == 12


@pytest.mark.asyncio
@respx.mock
async def test_anthropic_stream_parses_sse():
    sse = (
        'data: {"type":"message_start","message":{"usage":{"input_tokens":9}}}\n\n'
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hel"}}\n\n'
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"lo"}}\n\n'
        'data: {"type":"message_delta","usage":{"output_tokens":2}}\n\n'
        'data: {"type":"message_stop"}\n\n'
    )
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, content=sse.encode(),
                                    headers={"content-type": "text/event-stream"}))
    chunks, final = "", None
    async for c in AnthropicAdapter(api_key="k").stream(REQ):
        chunks += c.delta
        if c.done:
            final = c.usage
    assert chunks == "Hello"
    assert final.input_tokens == 9 and final.output_tokens == 2


@pytest.mark.asyncio
@respx.mock
async def test_openai_vision_payload_and_json_mode():
    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={
            "model": "gpt-4o", "choices": [{"message": {"content": '{"a":1}'}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 6},
        }))
    req = ChatRequest(
        messages=[ChatMessage(role="user", content="look",
                              images=[ImagePart("image/jpeg", "QUJD")])],
        system="sys", model="gpt-4o", json_mode=True)
    res = await OpenAIAdapter(api_key="sk-x").complete(req)
    sent = json.loads(route.calls[0].request.content)
    assert sent["response_format"] == {"type": "json_object"}
    image_parts = [p for p in sent["messages"][1]["content"] if p["type"] == "image_url"]
    assert image_parts[0]["image_url"]["url"].startswith("data:image/jpeg;base64,")
    assert res.usage.output_tokens == 6


@pytest.mark.asyncio
@respx.mock
async def test_gemini_complete():
    route = respx.post(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    ).mock(return_value=httpx.Response(200, json={
        "candidates": [{"content": {"parts": [{"text": "bonjour"}]}}],
        "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3},
    }))
    res = await GeminiAdapter(api_key="g-key").complete(REQ)
    assert route.calls[0].request.headers["x-goog-api-key"] == "g-key"
    assert res.text == "bonjour" and res.usage.output_tokens == 3


@pytest.mark.asyncio
@respx.mock
async def test_ollama_complete_local_no_key():
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(200, json={
            "model": "llama3.1", "message": {"role": "assistant", "content": "local hi"},
            "prompt_eval_count": 5, "eval_count": 2, "done": True,
        }))
    res = await OllamaAdapter().complete(REQ)
    assert res.text == "local hi" and res.provider == "ollama"


@pytest.mark.asyncio
@respx.mock
async def test_provider_error_normalization_retryable():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(529, json={"error": {"message": "overloaded"}}))
    with pytest.raises(ProviderError) as exc:
        await AnthropicAdapter(api_key="k").complete(REQ)
    assert exc.value.retryable is True and exc.value.status == 529


@pytest.mark.asyncio
@respx.mock
async def test_provider_error_auth_not_retryable():
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(401, json={"error": {"message": "bad key"}}))
    with pytest.raises(ProviderError) as exc:
        await OpenAIAdapter(api_key="bad").complete(REQ)
    assert exc.value.retryable is False


def test_cost_calculation():
    u = Usage(input_tokens=1_000_000, output_tokens=1_000_000)
    assert cost_usd("claude-sonnet-4-6", u) == 18.0
    assert cost_usd("llama3.1", u) == 0.0          # local = free
    assert cost_usd("unknown-model", u) == 0.0     # unknown still meters tokens, no cost
