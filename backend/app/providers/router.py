"""Model router: resolves which provider + key to use for a request,
executes with failover, and records usage.

Key resolution order (per tenant key_policy):
  policy=central -> tenant key, else env key
  policy=byo     -> user's own key only
  policy=both    -> user key -> tenant key -> env key

Failover: if the chosen provider raises a retryable ProviderError, the router
walks the tenant's fallback chain (admin-configurable order) until one works.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..crypto import decrypt_secret, key_aad
from ..models import ProviderKey, Tenant, UsageRecord, User
from .anthropic_openai import AnthropicAdapter, OpenAIAdapter
from .base import ChatRequest, ChatResult, ProviderAdapter, ProviderError, Usage, cost_usd
from .gemini_ollama import GeminiAdapter, OllamaAdapter

ADAPTERS: dict[str, type[ProviderAdapter]] = {
    "anthropic": AnthropicAdapter,
    "openai": OpenAIAdapter,
    "gemini": GeminiAdapter,
    "ollama": OllamaAdapter,
}

# Default failover order; admins can re-order per request via `provider` param.
DEFAULT_CHAIN = ["anthropic", "openai", "gemini", "ollama"]


@dataclass
class ResolvedProvider:
    adapter: ProviderAdapter
    provider: str
    key_scope: str  # byo | central


class NoKeyAvailable(Exception):
    pass


def _env_key(provider: str) -> str:
    s = get_settings()
    return {"anthropic": s.anthropic_api_key, "openai": s.openai_api_key,
            "gemini": s.gemini_api_key, "ollama": "local"}.get(provider, "")


def resolve(db: Session, user: User, provider: str) -> ResolvedProvider:
    """Resolve adapter + key for one provider under the tenant's key policy."""
    tenant = db.get(Tenant, user.tenant_id)
    policy = tenant.key_policy if tenant else "both"
    s = get_settings()
    cls = ADAPTERS.get(provider)
    if cls is None:
        raise NoKeyAvailable(f"Unknown provider '{provider}'")

    def from_row(row: ProviderKey, scope: str) -> ResolvedProvider:
        plaintext = decrypt_secret(s.master_key_bytes, row.ciphertext,
                                   key_aad(row.tenant_id, row.user_id, row.provider))
        return ResolvedProvider(cls(api_key=plaintext, base_url=row.base_url), provider, scope)

    if policy in ("byo", "both"):
        row = db.scalar(select(ProviderKey).where(
            ProviderKey.tenant_id == user.tenant_id, ProviderKey.user_id == user.id,
            ProviderKey.provider == provider))
        if row:
            return from_row(row, "byo")
        if policy == "byo" and provider != "ollama":
            raise NoKeyAvailable(
                f"Your team requires a personal {provider} API key. Add one in Settings.")

    if policy in ("central", "both"):
        row = db.scalar(select(ProviderKey).where(
            ProviderKey.tenant_id == user.tenant_id, ProviderKey.user_id.is_(None),
            ProviderKey.provider == provider))
        if row:
            return from_row(row, "central")
        env = _env_key(provider)
        if env:
            base = s.ollama_base_url if provider == "ollama" else ""
            return ResolvedProvider(cls(api_key="" if provider == "ollama" else env,
                                        base_url=base), provider, "central")

    if provider == "ollama":
        # Ollama needs no key — usable whenever a base_url is configured.
        return ResolvedProvider(cls(base_url=s.ollama_base_url), provider, "central")

    raise NoKeyAvailable(f"No API key available for {provider} under policy '{policy}'.")


def record_usage(db: Session, user: User, result_model: str, provider: str,
                 key_scope: str, usage: Usage, kind: str = "chat") -> None:
    db.add(UsageRecord(
        tenant_id=user.tenant_id, user_id=user.id, provider=provider, model=result_model,
        key_scope=key_scope, input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
        cost_usd=cost_usd(result_model, usage), kind=kind,
    ))
    db.commit()


async def complete_with_failover(
    db: Session, user: User, req: ChatRequest,
    provider: str | None = None, kind: str = "chat",
) -> ChatResult:
    """Non-streaming completion with automatic failover on retryable errors."""
    chain = [provider] if provider else DEFAULT_CHAIN
    errors: list[str] = []
    for name in chain:
        try:
            resolved = resolve(db, user, name)
        except NoKeyAvailable as e:
            errors.append(str(e))
            continue
        sub_req = ChatRequest(**{**req.__dict__})
        if not sub_req.model or _provider_of_model(sub_req.model) != name:
            vision = any(m.images for m in req.messages)
            sub_req.model = resolved.adapter.default_model(vision=vision)
        try:
            result = await resolved.adapter.complete(sub_req)
            record_usage(db, user, result.model, name, resolved.key_scope, result.usage, kind)
            return result
        except ProviderError as e:
            errors.append(str(e))
            if not e.retryable or provider is not None:
                raise
    raise ProviderError("All providers failed: " + " | ".join(errors), 503, retryable=False)


def _provider_of_model(model: str) -> str | None:
    from .base import MODEL_CATALOG
    entry = MODEL_CATALOG.get(model)
    return entry["provider"] if entry else None
