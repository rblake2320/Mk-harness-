"""Application configuration. All secrets come from environment — never hardcoded."""
import base64
import os
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./mkharness.db"
    db_host: str = ""
    db_port: int = 5432
    db_name: str = "mkharness"
    db_user: str = "mk_app_login"
    db_password: str = ""
    db_sslmode: str = "verify-full"
    db_sslrootcert: str = ""
    jwt_secret: str = ""
    master_key: str = ""  # base64-encoded 32 bytes for AES-256-GCM envelope encryption
    # Destination-fingerprint keys, `kid=base64(32 bytes)[,kid=...]`, FIRST = current.
    # Must equal the kernel's MK_FINGERPRINT_KEYS so inbound tags match. Empty = the
    # master key as `m0` (pre-rotation behaviour). `m0=master` names the master key.
    fingerprint_keys: str = ""
    cors_origins: str = "http://localhost:5173"

    anthropic_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"

    redis_url: str = ""            # e.g. redis://localhost:6379/0; empty = in-process fallback
    rate_limit_per_minute: int = 30
    max_upload_mb: int = 8
    access_token_minutes: int = 30
    refresh_token_days: int = 14

    # Local PanDerm skin analysis API (port 8101). Empty = use cloud vision model.
    skin_analysis_url: str = ""
    # Default brand for new tenants.
    default_brand: str = "mary_kay"

    # Stripe billing (REST API via httpx — no SDK dependency). All from env.
    stripe_secret_key: str = ""       # sk_live_... / sk_test_...
    stripe_webhook_secret: str = ""   # whsec_... — verifies inbound webhook signatures
    billing_trial_days: int = 90
    billing_enforced: bool = False    # when True, AI features require an active/trialing sub
    billing_success_url: str = "http://localhost:5173/billing/success"
    billing_cancel_url: str = "http://localhost:5173/billing/cancel"
    billing_portal_return_url: str = "http://localhost:5173/billing"
    referral_credit_cents: int = 500  # $5 credit per referred conversion
    # Price IDs created in the Stripe dashboard, supplied as JSON: {"tier:interval": "price_..."}
    # e.g. {"solo:month":"price_a","solo:year":"price_b","director:year":"price_c"}
    stripe_prices: str = ""

    # Rust action kernel (sole authority for governed actions). Empty URL or key
    # => every /api/agent-ops route answers 503. There is no Python fallback.
    rust_action_kernel_url: str = ""            # e.g. http://kernel-api:8090 (private net)
    kernel_assertion_private_key: str = ""      # base64url 32-byte Ed25519 seed
    kernel_assertion_kid: str = "k1"            # must match a kid in MK_ASSERTION_KEYS
    kernel_timeout_seconds: float = 10.0
    # Only operators may flip the global kill switch; comma-separated user ids.
    kernel_platform_operators: str = ""

    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def connection_url(self):
        """Compose the ECS secret without parsing password characters as a URL."""
        from sqlalchemy.engine import URL, make_url
        if self.db_host or self.db_password:
            if not all((self.db_host, self.db_password, self.db_user, self.db_name)):
                raise ValueError("DB_HOST, DB_PASSWORD, DB_USER and DB_NAME are required together")
            if "database_url" in self.model_fields_set:
                raise ValueError("Configure DATABASE_URL or DB_HOST fields, not both")
            query = {"sslmode": self.db_sslmode}
            if self.db_sslrootcert:
                query["sslrootcert"] = self.db_sslrootcert
            result = URL.create("postgresql+psycopg", username=self.db_user,
                                password=self.db_password, host=self.db_host,
                                port=self.db_port, database=self.db_name, query=query)
        else:
            result = make_url(self.database_url)
        if result.get_backend_name() == "postgresql":
            if result.drivername == "postgresql":
                result = result.set(drivername="postgresql+psycopg")
            # Explicit insecure transport is for loopback/Compose development only.
            local = result.host in {"localhost", "127.0.0.1", "::1", "db"}
            if not local and result.query.get("sslmode") != "verify-full":
                raise ValueError("Remote PostgreSQL requires sslmode=verify-full")
            if not local and not result.query.get("sslrootcert"):
                raise ValueError("Remote PostgreSQL requires an explicit sslrootcert")
        return result

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
    def fingerprint_key_list(self) -> list[tuple[str, bytes]]:
        import re
        spec = self.fingerprint_keys.strip()
        if not spec:
            return [("m0", self.master_key_bytes)]
        out: list[tuple[str, bytes]] = []
        for part in (p.strip() for p in spec.split(",") if p.strip()):
            kid, sep, val = part.partition("=")
            kid = kid.strip()
            if not sep or not re.fullmatch(r"[a-z0-9_-]{1,16}", kid) or any(k == kid for k, _ in out):
                raise RuntimeError("FINGERPRINT_KEYS entries must be unique kid=base64 with kid [a-z0-9_-]{1,16}")
            raw = self.master_key_bytes if val.strip() == "master" else base64.b64decode(val.strip(), validate=True)
            if len(raw) != 32:
                raise RuntimeError("FINGERPRINT_KEYS keys must decode to exactly 32 bytes")
            out.append((kid, raw))
        return out

    @property
    def master_key_bytes(self) -> bytes:
        if not self.master_key:
            raise RuntimeError("MASTER_KEY is not set. Generate 32 random bytes (base64).")
        try:
            raw = base64.b64decode(self.master_key, validate=True)
        except Exception:
            raise RuntimeError("MASTER_KEY is not valid base64.")
        if len(raw) != 32:
            raise RuntimeError("MASTER_KEY must decode to exactly 32 bytes.")
        return raw

    @property
    def platform_operator_ids(self) -> frozenset[str]:
        return frozenset(x.strip() for x in self.kernel_platform_operators.split(",") if x.strip())

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
