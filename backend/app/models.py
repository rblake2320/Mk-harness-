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
    # Referral program: every user gets a shareable code; referred_by points at the referrer.
    referral_code: Mapped[str | None] = mapped_column(String(16), unique=True, nullable=True, index=True)
    referred_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
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


class Subscription(Base):
    """One subscription per consultant. Mirrors Stripe state, driven by webhooks.

    status: none (never subscribed) | trialing | active | past_due | canceled | incomplete.
    Tier/interval are the chosen plan (e.g. solo/year). stripe_subscription_id is null
    until checkout completes.
    """
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), unique=True, index=True)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    tier: Mapped[str] = mapped_column(String(20), default="")        # solo | director | leader | studio
    interval: Mapped[str] = mapped_column(String(10), default="")    # month | year
    status: Mapped[str] = mapped_column(String(20), default="none")
    trial_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ReferralCredit(Base):
    """Ledger of referral rewards. One row per referred conversion.

    status: pending (earned, not yet pushed to Stripe) | applied (credited to Stripe
    customer balance) | void. amount_cents is the reward to the referrer.
    """
    __tablename__ = "referral_credits"
    __table_args__ = (UniqueConstraint("referred_user_id", name="uq_referral_per_referred"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)  # referrer (earns)
    referred_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    amount_cents: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(10), default="pending")
    stripe_txn_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ConsentRecord(Base):
    """Records consent for sensitive-data processing (skin analysis).

    Two subjects:
      - subject="operator": the consultant accepts the data-processing terms.
        One active record gates the whole skin-analysis feature. customer_id is null.
      - subject="customer": a specific customer consented to a skin analysis.
        customer_id is set; required before analyzing that customer.

    We keep every grant/revocation as an immutable audit trail (never hard-deleted),
    storing the SHA-256 of the exact consent text shown so we can prove WHAT was agreed
    to. This is the Washington My Health My Data Act / BIPA consent record — derived skin
    attributes (undertone, Fitzpatrick) are "consumer health data" with a private right
    of action, so the consent record is the liability shield.
    """
    __tablename__ = "consent_records"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    subject: Mapped[str] = mapped_column(String(20))  # operator | customer
    customer_id: Mapped[str | None] = mapped_column(ForeignKey("customers.id"), nullable=True, index=True)
    scope: Mapped[str] = mapped_column(String(40), default="skin")  # data scope this consent covers
    consent_version: Mapped[str] = mapped_column(String(40))        # version of the text shown
    text_sha256: Mapped[str] = mapped_column(String(64))           # integrity hash of exact text
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    user_id: Mapped[str] = mapped_column(String(32), index=True, default="")
    action: Mapped[str] = mapped_column(String(60))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ClawAgent(Base):
    """Tenant-scoped device adapter registration.

    PhoneClaw itself does not currently publish a webhook protocol. ``webhook_url``
    therefore points at a separately deployed adapter that accepts the versioned,
    signed work-order envelope produced by this service.
    """

    __tablename__ = "claw_agents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "agent_id", name="uq_claw_agent_tenant_label"),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(80), index=True)
    webhook_url: Mapped[str] = mapped_column(String(2048))
    secret_ciphertext: Mapped[str] = mapped_column(Text)
    platform_specialty: Mapped[str] = mapped_column(String(40), default="multi")
    capabilities_json: Mapped[str] = mapped_column(Text, default="{}")
    adapter_version: Mapped[str] = mapped_column(
        String(80), default="phoneclaw-clawscript-adapter-v1"
    )
    status: Mapped[str] = mapped_column(String(20), default="offline")
    last_ping: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CallCenterTask(Base):
    __tablename__ = "cc_tasks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(80), index=True)
    workflow: Mapped[str] = mapped_column(String(40), index=True)
    payload_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    claw_script_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    compliance_checked: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approved_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    audit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class CallCenterContactPermission(Base):
    """Operator-attested permission record; not a legal sufficiency determination."""

    __tablename__ = "cc_contact_permissions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    channel: Mapped[str] = mapped_column(String(40), index=True)
    destination_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    purpose: Mapped[str] = mapped_column(String(40), index=True)
    asserted_basis: Mapped[str] = mapped_column(String(60))
    source_reference: Mapped[str] = mapped_column(String(500))
    evidence_digest: Mapped[str] = mapped_column(String(64))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CallCenterAuditHead(Base):
    __tablename__ = "cc_audit_heads"
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id"), primary_key=True
    )
    last_hash: Mapped[str] = mapped_column(String(64), default="genesis")
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CallCenterAuditEntry(Base):
    __tablename__ = "cc_audit_entries"
    __table_args__ = (
        UniqueConstraint("tenant_id", "sequence", name="uq_cc_audit_tenant_sequence"),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("cc_tasks.id"), nullable=True, index=True
    )
    agent_id: Mapped[str] = mapped_column(String(80), default="", index=True)
    workflow: Mapped[str] = mapped_column(String(40), default="")
    event: Mapped[str] = mapped_column(String(60), index=True)
    detail_digest: Mapped[str] = mapped_column(String(64))
    sequence: Mapped[int] = mapped_column(Integer)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ClawCallbackNonce(Base):
    __tablename__ = "claw_callback_nonces"
    __table_args__ = (
        UniqueConstraint("tenant_id", "agent_id", "nonce", name="uq_claw_callback_nonce"),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(80), index=True)
    nonce: Mapped[str] = mapped_column(String(80))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
