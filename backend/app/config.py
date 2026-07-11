"""Application configuration. All secrets come from environment — never hardcoded."""

import base64
import os
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./mkharness.db"
    jwt_secret: str = ""
    master_key: str = ""  # base64-encoded 32 bytes for AES-256-GCM envelope encryption
    cors_origins: str = "http://localhost:5173"

    anthropic_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"

    redis_url: str = ""  # e.g. redis://localhost:6379/0; empty = in-process fallback
    rate_limit_per_minute: int = 30
    max_upload_mb: int = 8
    access_token_minutes: int = 30
    refresh_token_days: int = 14

    # Local PanDerm skin analysis API (port 8101). Empty = use cloud vision model.
    skin_analysis_url: str = ""
    # Default brand for new tenants.
    default_brand: str = "mary_kay"

    # Stripe billing (REST API via httpx — no SDK dependency). All from env.
    stripe_secret_key: str = ""  # sk_live_... / sk_test_...
    stripe_webhook_secret: str = ""  # whsec_... — verifies inbound webhook signatures
    billing_trial_days: int = 90
    billing_enforced: bool = (
        False  # when True, AI features require an active/trialing sub
    )
    billing_success_url: str = "http://localhost:5173/billing/success"
    billing_cancel_url: str = "http://localhost:5173/billing/cancel"
    billing_portal_return_url: str = "http://localhost:5173/billing"
    referral_credit_cents: int = 500  # $5 credit per referred conversion
    # Price IDs created in the Stripe dashboard, supplied as JSON: {"tier:interval": "price_..."}
    # e.g. {"solo:month":"price_a","solo:year":"price_b","director:year":"price_c"}
    stripe_prices: str = ""

    # Governed Agent Operations. Disabled unless deployment opts in explicitly.
    agent_operations_enabled: bool = False
    agent_operations_webhook_hosts: str = ""
    agent_operations_target_hosts: str = ""
    agent_operations_public_base_url: str = ""
    agent_operations_dispatch_timeout_seconds: float = 10.0

    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def stripe_price_map(self) -> dict[str, str]:
        import json

        if not self.stripe_prices:
            return {}
        try:
            data = json.loads(self.stripe_prices)
            return {str(k): str(v) for k, v in data.items()}
        except (ValueError, AttributeError):
            return {}

    @property
    def master_key_bytes(self) -> bytes:
        if not self.master_key:
            raise RuntimeError(
                "MASTER_KEY is not set. Generate 32 random bytes (base64)."
            )
        try:
            raw = base64.b64decode(self.master_key, validate=True)
        except Exception:
            raise RuntimeError("MASTER_KEY is not valid base64.")
        if len(raw) != 32:
            raise RuntimeError("MASTER_KEY must decode to exactly 32 bytes.")
        return raw

    @property
    def agent_operations_webhook_host_set(self) -> set[str]:
        return {
            host.strip().lower().rstrip(".")
            for host in self.agent_operations_webhook_hosts.split(",")
            if host.strip()
        }

    @property
    def agent_operations_target_host_set(self) -> set[str]:
        return {
            host.strip().lower().rstrip(".")
            for host in self.agent_operations_target_hosts.split(",")
            if host.strip()
        }

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


def require_secret(settings: Settings) -> None:
    """Fail fast at startup if production-critical secrets are missing."""
    if not settings.jwt_secret or len(settings.jwt_secret) < 32:
        if os.environ.get("MK_ALLOW_DEV_SECRETS") != "1":
            raise RuntimeError(
                "JWT_SECRET must be set (>=32 chars). "
                "Set MK_ALLOW_DEV_SECRETS=1 only for local development."
            )
