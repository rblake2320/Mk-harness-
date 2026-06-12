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

    rate_limit_per_minute: int = 30
    max_upload_mb: int = 8
    access_token_minutes: int = 30
    refresh_token_days: int = 14

    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def master_key_bytes(self) -> bytes:
        if not self.master_key:
            raise RuntimeError("MASTER_KEY is not set. Generate 32 random bytes (base64).")
        raw = base64.b64decode(self.master_key)
        if len(raw) != 32:
            raise RuntimeError("MASTER_KEY must decode to exactly 32 bytes.")
        return raw

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
