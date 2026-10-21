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


# --------------------------------------------------------------------------- #
# Customer & permission foundation (WP03) and downstream records (WP04/05)
# Every row: tenant_id, version, created_at, audit reference. Destinations are
# stored encrypted plus an HMAC fingerprint that matches the kernel's
# destination hash so suppression lines up across the boundary.
# --------------------------------------------------------------------------- #
class CustomerDestination(Base):
    """A normalized contact destination (E.164 phone or lowercase email)."""
    __tablename__ = "customer_destinations"
    __table_args__ = (UniqueConstraint("tenant_id", "channel", "fingerprint", "customer_id",
                                       name="uq_destination_scope"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    channel: Mapped[str] = mapped_column(String(12))             # sms | email
    value_enc: Mapped[str] = mapped_column(Text)                 # AES-GCM, AAD bound to tenant
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # HMAC(master, tenant|channel|normalized)
    label: Mapped[str] = mapped_column(String(40), default="")
    is_primary: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(24), default="manual")  # manual | import | inbound
    source_ref: Mapped[str] = mapped_column(String(64), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ContactPreference(Base):
    """Per-customer contact preferences. timezone None blocks automated dispatch (F9)."""
    __tablename__ = "contact_preferences"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), unique=True, index=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)   # IANA
    preferred_channel: Mapped[str] = mapped_column(String(12), default="sms")
    window_start_hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_end_hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    language: Mapped[str] = mapped_column(String(8), default="en")
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ConsentEvent(Base):
    """Permission evidence for OUTREACH, scoped per the contract: customer, destination,
    consultant business (tenant), channel, purpose, evidence source, effective time,
    revocation. Immutable; revocation sets revoked_at. The kernel's contact_permissions
    row (kernel_permission_id) is the execution-time authority; this is the evidence.
    Imports can never create one (F8)."""
    __tablename__ = "consent_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    destination_id: Mapped[str] = mapped_column(ForeignKey("customer_destinations.id"), index=True)
    channel: Mapped[str] = mapped_column(String(12))
    purposes_json: Mapped[str] = mapped_column(Text)              # JSON list of purpose strings
    source: Mapped[str] = mapped_column(String(32))               # web_form | verbal_confirmed | inbound_message | paper_form
    evidence_type: Mapped[str] = mapped_column(String(32))        # form_submission | message | signed_document | consultant_attestation
    evidence_ref: Mapped[str] = mapped_column(String(256), default="")
    evidence_digest: Mapped[str] = mapped_column(String(71))      # sha256:<hex>
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(12), default="active")  # active | revoked | expired
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str] = mapped_column(String(120), default="")
    kernel_permission_id: Mapped[str] = mapped_column(String(36), default="")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SuppressionEvent(Base):
    """A never-contact record. Keyed by destination fingerprint so it survives profile
    edits and re-imports (F3, F8). Lifted only by an explicit workflow with evidence."""
    __tablename__ = "suppression_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str | None] = mapped_column(ForeignKey("customers.id"), nullable=True, index=True)
    channel: Mapped[str | None] = mapped_column(String(12), nullable=True)   # None = all channels
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(String(32))               # sms_reply | consultant | provider | complaint
    permanent: Mapped[bool] = mapped_column(Boolean, default=True)
    kernel_suppression_id: Mapped[str] = mapped_column(String(36), default="")
    created_by: Mapped[str] = mapped_column(String(32), default="")  # user id or "system"
    lifted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lifted_by: Mapped[str] = mapped_column(String(32), default="")
    lift_evidence_digest: Mapped[str] = mapped_column(String(71), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SenderIdentity(Base):
    """A registered business sending number for one consultant business (D1)."""
    __tablename__ = "sender_identities"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(24))             # twilio
    provider_resource_ref: Mapped[str] = mapped_column(String(64), default="")
    number_e164: Mapped[str] = mapped_column(String(20))
    registration_status: Mapped[str] = mapped_column(String(24), default="pending")  # pending | registered | suspended
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ImportJob(Base):
    """CSV import with preview → commit → optional rollback (F5)."""
    __tablename__ = "import_jobs"
    __table_args__ = (UniqueConstraint("tenant_id", "idempotency_key", name="uq_import_idem"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(80))
    source_filename: Mapped[str] = mapped_column(String(200), default="")
    source_digest: Mapped[str] = mapped_column(String(71))
    mapping_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(12), default="preview")  # preview | committed | rolled_back
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    created_count: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ImportRow(Base):
    __tablename__ = "import_rows"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("import_jobs.id"), index=True)
    row_index: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(12))   # create | duplicate | error
    error: Mapped[str] = mapped_column(String(200), default="")
    name: Mapped[str] = mapped_column(String(120), default="")
    phone_enc: Mapped[str] = mapped_column(Text, default="")
    phone_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    email_enc: Mapped[str] = mapped_column(Text, default="")
    email_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    customer_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Commitment(Base):
    """A promise to a customer (W1). AI creates drafts only; a consultant confirms."""
    __tablename__ = "commitments"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    source_type: Mapped[str] = mapped_column(String(24))          # conversation | inbound_message | consultant_note
    source_reference: Mapped[str] = mapped_column(String(64), default="")
    source_version: Mapped[str] = mapped_column(String(64), default="")
    source_evidence_reference: Mapped[str] = mapped_column(String(71), default="")  # sha256 digest
    # kind: promise (consultant promised) | customer_request (explicit ask) |
    #       unanswered_question | customer_date (customer supplied a follow-up date)
    kind: Mapped[str] = mapped_column(String(24), default="promise")
    commitment_text: Mapped[str] = mapped_column(Text)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    due_window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    due_window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(12), default="draft")  # draft | confirmed | deferred | resolved | cancelled
    created_by: Mapped[str] = mapped_column(String(32))            # user id or "ai"
    confirmed_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_reference: Mapped[str] = mapped_column(String(64), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class BriefItem(Base):
    __tablename__ = "brief_items"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    brief_date: Mapped[str] = mapped_column(String(10), index=True)  # YYYY-MM-DD in consultant tz
    rule: Mapped[str] = mapped_column(String(40))                 # commitment_due | explicit_request | unanswered_question | customer_date | exception
    rank_category: Mapped[int] = mapped_column(Integer)
    source_type: Mapped[str] = mapped_column(String(24))
    source_reference: Mapped[str] = mapped_column(String(64))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="open")  # open | approved | deferred | resolved | skipped | suppressed
    permission_state: Mapped[str] = mapped_column(String(16), default="unknown")
    permission_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suggested_step: Mapped[str] = mapped_column(String(200), default="")
    draft_version_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(120), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (UniqueConstraint("tenant_id", "dedupe_key", name="uq_brief_dedupe"),)


class DraftVersion(Base):
    __tablename__ = "draft_versions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    brief_item_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    commitment_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    text_enc: Mapped[str] = mapped_column(Text)
    text_digest: Mapped[str] = mapped_column(String(71))
    relationship_spans_json: Mapped[str] = mapped_column(Text, default="[]")
    claim_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    source_versions_json: Mapped[str] = mapped_column(Text, default="{}")
    generated_by: Mapped[str] = mapped_column(String(120))          # ai:<provider>:<model> | user id
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ActionLink(Base):
    """Links an application record to a kernel action id and its digest."""
    __tablename__ = "action_links"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    kernel_action_id: Mapped[str] = mapped_column(String(36), index=True)
    action_digest: Mapped[str] = mapped_column(String(71))
    brief_item_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    commitment_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    draft_version_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_known_state: Mapped[str] = mapped_column(String(32), default="proposed")
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ExceptionRecord(Base):
    __tablename__ = "exceptions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str | None] = mapped_column(ForeignKey("customers.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(32))  # product_concern | complaint | wrong_number | identity_ambiguity | delivery_uncertain | missing_permission | ambiguous_reply | ambiguous_opt_out
    source_reference: Mapped[str] = mapped_column(String(64), default="")
    detail_enc: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[str] = mapped_column(String(12), default="open")  # open | resolved | dismissed
    resolved_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Outcome(Base):
    """Business outcome, separate from transport state (X1)."""
    __tablename__ = "outcomes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    commitment_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    action_link_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kind: Mapped[str] = mapped_column(String(32))  # resolved | deferred | opted_out | no_response | customer_reported_order | consultant_confirmed_order | exception_open | cancelled
    recorded_by: Mapped[str] = mapped_column(String(32))
    note_enc: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class KnowledgeSource(Base):
    """Authorized, versioned, reviewed product source material (P1)."""
    __tablename__ = "knowledge_sources"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)  # None = platform-wide
    title: Mapped[str] = mapped_column(String(200))
    source_reference: Mapped[str] = mapped_column(String(256))
    source_version: Mapped[str] = mapped_column(String(64))
    content_digest: Mapped[str] = mapped_column(String(71))
    market: Mapped[str] = mapped_column(String(8), default="US")
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewer: Mapped[str] = mapped_column(String(120), default="")
    review_status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | approved | withdrawn
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ApprovedClaim(Base):
    """Approved-claims registry (P1). The model may SELECT a claim id; it never writes
    claim text. Claims are versioned, market-scoped, time-bounded and reviewed."""
    __tablename__ = "approved_claims"
    __table_args__ = (UniqueConstraint("tenant_id", "claim_id", "source_version", name="uq_claim_version"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)  # None = platform-wide
    claim_id: Mapped[str] = mapped_column(String(64), index=True)
    product_id: Mapped[str] = mapped_column(String(64), index=True)
    approved_text: Mapped[str] = mapped_column(Text)
    source_id: Mapped[str] = mapped_column(ForeignKey("knowledge_sources.id"), index=True)
    source_reference: Mapped[str] = mapped_column(String(256))
    source_version: Mapped[str] = mapped_column(String(64))
    market: Mapped[str] = mapped_column(String(8), default="US")
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewer: Mapped[str] = mapped_column(String(120), default="")
    review_status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | approved | withdrawn
    version: Mapped[int] = mapped_column(Integer, default=1)
    audit_ref: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
