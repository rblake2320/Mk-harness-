"""SQLAlchemy 2.0 models. Multi-tenant: every row hangs off a tenant_id.

Portable types (String UUIDs, JSON-as-text) so the same models run on
Postgres in production and SQLite in the test suite.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def uid() -> str:
    return uuid.uuid4().hex


def now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    # Key policy: "central" (company keys only), "byo" (consultant keys only), "both"
    key_policy: Mapped[str] = mapped_column(String(10), default="both")
    # Brand config identifier — drives system prompts and product catalog.
    brand: Mapped[str] = mapped_column(String(40), default="mary_kay")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    users: Mapped[list["User"]] = relationship(back_populates="tenant")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(120), default="")
    role: Mapped[str] = mapped_column(String(20), default="consultant")  # admin | consultant
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


class ProviderKey(Base):
    """Encrypted API keys. scope='tenant' (central, admin-managed) or scope='user' (BYO)."""
    __tablename__ = "provider_keys"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", "provider", name="uq_key_scope"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(20))  # anthropic | openai | gemini | ollama
    scope: Mapped[str] = mapped_column(String(10))     # tenant | user
    ciphertext: Mapped[str] = mapped_column(Text)       # base64(nonce + AES-GCM ciphertext)
    base_url: Mapped[str] = mapped_column(String(255), default="")  # for ollama/self-hosted
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Conversation(Base):
    __tablename__ = "conversations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(200), default="New conversation")
    skill: Mapped[str] = mapped_column(String(40), default="assistant")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    messages: Mapped[list["Message"]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan", order_by="Message.created_at"
    )


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id"), index=True)
    role: Mapped[str] = mapped_column(String(12))  # user | assistant
    content: Mapped[str] = mapped_column(Text)
    provider: Mapped[str] = mapped_column(String(20), default="")
    model: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    conversation: Mapped[Conversation] = relationship(back_populates="messages")


class Customer(Base):
    """CRM-lite: a consultant's customer book."""
    __tablename__ = "customers"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    phone: Mapped[str] = mapped_column(String(40), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")        # preferences, shade matches, history
    last_contact: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Skin profile — populated by skin analysis, powers personalized recommendations.
    skin_undertone: Mapped[str] = mapped_column(String(20), default="")  # warm | cool | neutral
    fitzpatrick_type: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 1-6
    skin_profile_json: Mapped[str] = mapped_column(Text, default="")  # latest 7-dim scores
    skin_profile_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SkinAnalysis(Base):
    __tablename__ = "skin_analyses"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    customer_id: Mapped[str | None] = mapped_column(ForeignKey("customers.id"), nullable=True)
    result_json: Mapped[str] = mapped_column(Text)  # structured cosmetic observations
    provider: Mapped[str] = mapped_column(String(20), default="")
    model: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class UsageRecord(Base):
    """Per-call metering: tokens + computed cost. Powers the admin usage dashboard."""
    __tablename__ = "usage_records"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(20))
    model: Mapped[str] = mapped_column(String(80))
    key_scope: Mapped[str] = mapped_column(String(10), default="central")  # central | byo
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    kind: Mapped[str] = mapped_column(String(20), default="chat")  # chat | vision
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ConsultantProfile(Base):
    """Per-consultant behavioral analytics and business context.

    Created lazily on first meaningful interaction. Drives personalized system
    prompts and cross-brand network effects — aggregate data trains better agents.
    """
    __tablename__ = "consultant_profiles"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    # Skill usage counts (JSON: {"sales_coach": 42, "social": 18, ...})
    skill_usage_json: Mapped[str] = mapped_column(Text, default="{}")
    # Engagement metrics
    total_conversations: Mapped[int] = mapped_column(Integer, default=0)
    total_skin_analyses: Mapped[int] = mapped_column(Integer, default=0)
    compliance_flags: Mapped[int] = mapped_column(Integer, default=0)
    # Business context (consultant-provided or inferred)
    tenure_months: Mapped[int | None] = mapped_column(Integer, nullable=True)
    team_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    star_wholesale_qtd: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Timestamps
    last_active: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    user_id: Mapped[str] = mapped_column(String(32), index=True, default="")
    action: Mapped[str] = mapped_column(String(60))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
