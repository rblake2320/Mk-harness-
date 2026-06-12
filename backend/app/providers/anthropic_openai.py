"""Anthropic and OpenAI(-compatible) adapters.

The OpenAI adapter doubles as the path for any OpenAI-compatible endpoint
(Azure OpenAI, vLLM, LM Studio) via base_url override.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx

from .base import (
    ChatRequest, ChatResult, ProviderAdapter, ProviderError, StreamChunk, Usage,
)

_TIMEOUT = httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=10.0)
_RETRYABLE = {408, 429, 500, 502, 503, 504, 529}


def _raise_for(resp: httpx.Response, provider: str) -> None:
    if resp.status_code >= 400:
        retryable = resp.status_code in _RETRYABLE
        try:
            detail = resp.json().get("error", {}).get("message", resp.text[:300])
        except Exception:
            detail = resp.text[:300]
        raise ProviderError(f"{provider}: {detail}", resp.status_code, retryable)


class AnthropicAdapter(ProviderAdapter):
    name = "anthropic"
    DEFAULT = "claude-sonnet-4-6"

    def default_model(self, vision: bool = False) -> str:
        return self.DEFAULT

    def _payload(self, req: ChatRequest) -> dict:
        messages = []
        for m in req.messages:
            if m.images:
                content: list[dict] = [
                    {"type": "image",
                     "source": {"type": "base64", "media_type": i.media_type, "data": i.data_b64}}
                    for i in m.images
                ]
                content.append({"type": "text", "text": m.content})
                messages.append({"role": m.role, "content": content})
            else:
                messages.append({"role": m.role, "content": m.content})
        system = req.system
        if req.json_mode:
            system += "\nRespond with a single valid JSON object only. No markdown fences, no prose."
        body = {
            "model": req.model or self.DEFAULT,
            "max_tokens": req.max_tokens,
            "temperature": req.temperature,
            "messages": messages,
        }
        if system:
            body["system"] = system
        return body

    def _headers(self) -> dict:
        return {"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                "content-type": "application/json"}

    def _url(self) -> str:
        return (self.base_url or "https://api.anthropic.com") + "/v1/messages"

    async def complete(self, req: ChatRequest) -> ChatResult:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(self._url(), headers=self._headers(), json=self._payload(req))
        _raise_for(resp, self.name)
        data = resp.json()
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        u = data.get("usage", {})
        return ChatResult(text=text,
                          usage=Usage(u.get("input_tokens", 0), u.get("output_tokens", 0)),
                          model=data.get("model", req.model), provider=self.name)

    async def stream(self, req: ChatRequest) -> AsyncIterator[StreamChunk]:
        body = self._payload(req) | {"stream": True}
        usage = Usage()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            async with client.stream("POST", self._url(), headers=self._headers(), json=body) as resp:
                if resp.status_code >= 400:
                    await resp.aread()
                    _raise_for(resp, self.name)
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    try:
                        ev = json.loads(line[5:].strip())
                    except json.JSONDecodeError:
                        continue
                    t = ev.get("type")
                    if t == "message_start":
                        usage.input_tokens = ev.get("message", {}).get("usage", {}).get("input_tokens", 0)
                    elif t == "content_block_delta":
                        delta = ev.get("delta", {}).get("text", "")
                        if delta:
                            yield StreamChunk(delta=delta)
                    elif t == "message_delta":
                        usage.output_tokens = ev.get("usage", {}).get("output_tokens", 0)
                    elif t == "message_stop":
                        yield StreamChunk(done=True, usage=usage)
                        return
        yield StreamChunk(done=True, usage=usage)


class OpenAIAdapter(ProviderAdapter):
    name = "openai"
    DEFAULT = "gpt-4o-mini"

    def default_model(self, vision: bool = False) -> str:
        return "gpt-4o" if vision else self.DEFAULT

    def _payload(self, req: ChatRequest, stream: bool) -> dict:
        messages: list[dict] = []
        system = req.system
        if req.json_mode:
            system += "\nRespond with a single valid JSON object only."
        if system:
            messages.append({"role": "system", "content": system})
        for m in req.messages:
            if m.images:
                content: list[dict] = [{"type": "text", "text": m.content}]
                content += [
                    {"type": "image_url",
                     "image_url": {"url": f"data:{i.media_type};base64,{i.data_b64}"}}
                    for i in m.images
                ]
                messages.append({"role": m.role, "content": content})
            else:
                messages.append({"role": m.role, "content": m.content})
        body = {
            "model": req.model or self.DEFAULT,
            "max_tokens": req.max_tokens,
            "temperature": req.temperature,
            "messages": messages,
            "stream": stream,
        }
        if stream:
            body["stream_options"] = {"include_usage": True}
        if req.json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "content-type": "application/json"}

    def _url(self) -> str:
        return (self.base_url or "https://api.openai.com") + "/v1/chat/completions"

    async def complete(self, req: ChatRequest) -> ChatResult:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(self._url(), headers=self._headers(),
                                     json=self._payload(req, stream=False))
        _raise_for(resp, self.name)
        data = resp.json()
        text = data["choices"][0]["message"].get("content") or ""
        u = data.get("usage", {})
        return ChatResult(text=text,
                          usage=Usage(u.get("prompt_tokens", 0), u.get("completion_tokens", 0)),
                          model=data.get("model", req.model), provider=self.name)

    async def stream(self, req: ChatRequest) -> AsyncIterator[StreamChunk]:
        usage = Usage()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            async with client.stream("POST", self._url(), headers=self._headers(),
                                     json=self._payload(req, stream=True)) as resp:
                if resp.status_code >= 400:
                    await resp.aread()
                    _raise_for(resp, self.name)
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    chunk = line[5:].strip()
                    if chunk == "[DONE]":
                        break
                    try:
                        ev = json.loads(chunk)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("usage"):
                        usage = Usage(ev["usage"].get("prompt_tokens", 0),
                                      ev["usage"].get("completion_tokens", 0))
                    choices = ev.get("choices") or []
                    if choices:
                        delta = choices[0].get("delta", {}).get("content")
                        if delta:
                            yield StreamChunk(delta=delta)
        yield StreamChunk(done=True, usage=usage)
