"""Google Gemini and Ollama (local/self-hosted) adapters."""
from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx

from .anthropic_openai import _RETRYABLE, _TIMEOUT, _raise_for
from .base import ChatRequest, ChatResult, ProviderAdapter, ProviderError, StreamChunk, Usage


class GeminiAdapter(ProviderAdapter):
    name = "gemini"
    DEFAULT = "gemini-2.0-flash"

    def default_model(self, vision: bool = False) -> str:
        return self.DEFAULT

    def _payload(self, req: ChatRequest) -> dict:
        contents = []
        for m in req.messages:
            parts: list[dict] = []
            if m.images:
                parts += [{"inline_data": {"mime_type": i.media_type, "data": i.data_b64}}
                          for i in m.images]
            parts.append({"text": m.content})
            contents.append({"role": "user" if m.role == "user" else "model", "parts": parts})
        body: dict = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": req.max_tokens, "temperature": req.temperature},
        }
        system = req.system
        if req.json_mode:
            body["generationConfig"]["responseMimeType"] = "application/json"
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        return body

    def _url(self, model: str, stream: bool) -> str:
        base = self.base_url or "https://generativelanguage.googleapis.com"
        verb = "streamGenerateContent?alt=sse" if stream else "generateContent"
        return f"{base}/v1beta/models/{model}:{verb}"

    def _headers(self) -> dict:
        return {"x-goog-api-key": self.api_key, "content-type": "application/json"}

    @staticmethod
    def _extract(data: dict) -> tuple[str, Usage]:
        text = ""
        for cand in data.get("candidates", []):
            for part in cand.get("content", {}).get("parts", []):
                text += part.get("text", "")
        meta = data.get("usageMetadata", {})
        return text, Usage(meta.get("promptTokenCount", 0), meta.get("candidatesTokenCount", 0))

    async def complete(self, req: ChatRequest) -> ChatResult:
        model = req.model or self.DEFAULT
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(self._url(model, False), headers=self._headers(),
                                     json=self._payload(req))
        _raise_for(resp, self.name)
        text, usage = self._extract(resp.json())
        return ChatResult(text=text, usage=usage, model=model, provider=self.name)

    async def stream(self, req: ChatRequest) -> AsyncIterator[StreamChunk]:
        model = req.model or self.DEFAULT
        usage = Usage()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            async with client.stream("POST", self._url(model, True), headers=self._headers(),
                                     json=self._payload(req)) as resp:
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
                    text, u = self._extract(ev)
                    if u.input_tokens or u.output_tokens:
                        usage = u
                    if text:
                        yield StreamChunk(delta=text)
        yield StreamChunk(done=True, usage=usage)


class OllamaAdapter(ProviderAdapter):
    """Local or self-hosted models. No API key required; base_url points at
    the Ollama server (default http://localhost:11434)."""
    name = "ollama"
    DEFAULT = "student-mk-trained:latest"

    def default_model(self, vision: bool = False) -> str:
        return "qwen3-vl:latest" if vision else self.DEFAULT

    def _payload(self, req: ChatRequest, stream: bool) -> dict:
        messages: list[dict] = []
        system = req.system
        if req.json_mode:
            system += "\nRespond with a single valid JSON object only."
        if system:
            messages.append({"role": "system", "content": system})
        for m in req.messages:
            entry: dict = {"role": m.role, "content": m.content}
            if m.images:
                entry["images"] = [i.data_b64 for i in m.images]
            messages.append(entry)
        body = {
            "model": req.model or self.DEFAULT,
            "messages": messages,
            "stream": stream,
            "options": {"num_predict": req.max_tokens, "temperature": req.temperature},
        }
        if req.json_mode:
            body["format"] = "json"
        return body

    def _url(self) -> str:
        return (self.base_url or "http://localhost:11434") + "/api/chat"

    async def complete(self, req: ChatRequest) -> ChatResult:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(self._url(), json=self._payload(req, stream=False))
        except httpx.ConnectError as e:
            raise ProviderError(f"ollama: cannot reach {self._url()} ({e})", 0, retryable=True)
        _raise_for(resp, self.name)
        data = resp.json()
        return ChatResult(
            text=data.get("message", {}).get("content", ""),
            usage=Usage(data.get("prompt_eval_count", 0), data.get("eval_count", 0)),
            model=data.get("model", req.model), provider=self.name,
        )

    async def stream(self, req: ChatRequest) -> AsyncIterator[StreamChunk]:
        usage = Usage()
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                async with client.stream("POST", self._url(),
                                         json=self._payload(req, stream=True)) as resp:
                    if resp.status_code >= 400:
                        await resp.aread()
                        _raise_for(resp, self.name)
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if ev.get("done"):
                            usage = Usage(ev.get("prompt_eval_count", 0), ev.get("eval_count", 0))
                            break
                        delta = ev.get("message", {}).get("content", "")
                        if delta:
                            yield StreamChunk(delta=delta)
        except httpx.ConnectError as e:
            raise ProviderError(f"ollama: cannot reach {self._url()} ({e})", 0, retryable=True)
        yield StreamChunk(done=True, usage=usage)
