-- Frozen application baseline. Never edit after application; append a new migration.
CREATE TABLE IF NOT EXISTS audit_logs (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	action VARCHAR(60) NOT NULL,
	detail TEXT NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;
CREATE INDEX IF NOT EXISTS ix_audit_logs_tenant_id ON audit_logs (tenant_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs (user_id);

CREATE TABLE IF NOT EXISTS tenants (
	id VARCHAR(32) NOT NULL,
	name VARCHAR(120) NOT NULL,
	key_policy VARCHAR(10) NOT NULL,
	brand VARCHAR(40) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id)
)

;


CREATE TABLE IF NOT EXISTS inbound_applications (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	source_reference VARCHAR(80) NOT NULL,
	kernel_event_id VARCHAR(64) NOT NULL,
	label VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32),
	created_json TEXT NOT NULL,
	hold_status INTEGER,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_inbound_application UNIQUE (tenant_id, source_reference),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id)
)

;
CREATE INDEX IF NOT EXISTS ix_inbound_applications_tenant_id ON inbound_applications (tenant_id);

CREATE TABLE IF NOT EXISTS knowledge_sources (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32),
	title VARCHAR(200) NOT NULL,
	source_reference VARCHAR(256) NOT NULL,
	source_version VARCHAR(64) NOT NULL,
	content_digest VARCHAR(71) NOT NULL,
	market VARCHAR(8) NOT NULL,
	effective_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE,
	reviewer VARCHAR(120) NOT NULL,
	review_status VARCHAR(16) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id)
)

;
CREATE INDEX IF NOT EXISTS ix_knowledge_sources_tenant_id ON knowledge_sources (tenant_id);

CREATE TABLE IF NOT EXISTS users (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	email VARCHAR(255) NOT NULL,
	password_hash VARCHAR(255) NOT NULL,
	display_name VARCHAR(120) NOT NULL,
	role VARCHAR(20) NOT NULL,
	is_active BOOLEAN NOT NULL,
	referral_code VARCHAR(16),
	referred_by VARCHAR(32),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (email),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(referred_by) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_users_email ON users (email);
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_referral_code ON users (referral_code);
CREATE INDEX IF NOT EXISTS ix_users_referred_by ON users (referred_by);
CREATE INDEX IF NOT EXISTS ix_users_tenant_id ON users (tenant_id);

CREATE TABLE IF NOT EXISTS approved_claims (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32),
	claim_id VARCHAR(64) NOT NULL,
	product_id VARCHAR(64) NOT NULL,
	approved_text TEXT NOT NULL,
	source_id VARCHAR(32) NOT NULL,
	source_reference VARCHAR(256) NOT NULL,
	source_version VARCHAR(64) NOT NULL,
	market VARCHAR(8) NOT NULL,
	effective_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE,
	reviewer VARCHAR(120) NOT NULL,
	review_status VARCHAR(16) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_claim_version UNIQUE (tenant_id, claim_id, source_version),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(source_id) REFERENCES knowledge_sources (id)
)

;
CREATE INDEX IF NOT EXISTS ix_approved_claims_claim_id ON approved_claims (claim_id);
CREATE INDEX IF NOT EXISTS ix_approved_claims_product_id ON approved_claims (product_id);
CREATE INDEX IF NOT EXISTS ix_approved_claims_source_id ON approved_claims (source_id);
CREATE INDEX IF NOT EXISTS ix_approved_claims_tenant_id ON approved_claims (tenant_id);

CREATE TABLE IF NOT EXISTS auth_factors (
	user_id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	secret_enc TEXT,
	confirmed_at TIMESTAMP WITH TIME ZONE,
	last_counter INTEGER NOT NULL,
	pending_secret_enc TEXT,
	pending_session_id VARCHAR(32),
	failed_attempts INTEGER NOT NULL,
	locked_until TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (user_id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id)
)

;
CREATE INDEX IF NOT EXISTS ix_auth_factors_tenant_id ON auth_factors (tenant_id);

CREATE TABLE IF NOT EXISTS auth_recovery_codes (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	digest VARCHAR(64) NOT NULL,
	consumed_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	UNIQUE (digest)
)

;
CREATE INDEX IF NOT EXISTS ix_auth_recovery_codes_tenant_id ON auth_recovery_codes (tenant_id);
CREATE INDEX IF NOT EXISTS ix_auth_recovery_codes_user_id ON auth_recovery_codes (user_id);

CREATE TABLE IF NOT EXISTS auth_sessions (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	refresh_digest VARCHAR(64) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	revoked_at TIMESTAMP WITH TIME ZONE,
	mfa_verified_at TIMESTAMP WITH TIME ZONE,
	step_up_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_auth_sessions_tenant_id ON auth_sessions (tenant_id);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id ON auth_sessions (user_id);

CREATE TABLE IF NOT EXISTS consultant_profiles (
	id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	skill_usage_json TEXT NOT NULL,
	total_conversations INTEGER NOT NULL,
	total_skin_analyses INTEGER NOT NULL,
	compliance_flags INTEGER NOT NULL,
	tenure_months INTEGER,
	team_size INTEGER,
	star_wholesale_qtd FLOAT,
	last_active TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id)
)

;
CREATE INDEX IF NOT EXISTS ix_consultant_profiles_tenant_id ON consultant_profiles (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_consultant_profiles_user_id ON consultant_profiles (user_id);

CREATE TABLE IF NOT EXISTS conversations (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	title VARCHAR(200) NOT NULL,
	skill VARCHAR(40) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_conversations_tenant_id ON conversations (tenant_id);
CREATE INDEX IF NOT EXISTS ix_conversations_user_id ON conversations (user_id);

CREATE TABLE IF NOT EXISTS customers (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	name VARCHAR(120) NOT NULL,
	phone VARCHAR(40) NOT NULL,
	email VARCHAR(255) NOT NULL,
	notes TEXT NOT NULL,
	last_contact TIMESTAMP WITH TIME ZONE,
	skin_undertone VARCHAR(20) NOT NULL,
	fitzpatrick_type INTEGER,
	skin_profile_json TEXT NOT NULL,
	skin_profile_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_customers_tenant_id ON customers (tenant_id);
CREATE INDEX IF NOT EXISTS ix_customers_user_id ON customers (user_id);

CREATE TABLE IF NOT EXISTS import_jobs (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	idempotency_key VARCHAR(80) NOT NULL,
	source_filename VARCHAR(200) NOT NULL,
	source_digest VARCHAR(71) NOT NULL,
	mapping_json TEXT NOT NULL,
	status VARCHAR(12) NOT NULL,
	row_count INTEGER NOT NULL,
	created_count INTEGER NOT NULL,
	duplicate_count INTEGER NOT NULL,
	error_count INTEGER NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	committed_at TIMESTAMP WITH TIME ZONE,
	rolled_back_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_import_idem UNIQUE (tenant_id, idempotency_key),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_import_jobs_tenant_id ON import_jobs (tenant_id);
CREATE INDEX IF NOT EXISTS ix_import_jobs_user_id ON import_jobs (user_id);

CREATE TABLE IF NOT EXISTS provider_keys (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32),
	provider VARCHAR(20) NOT NULL,
	scope VARCHAR(10) NOT NULL,
	ciphertext TEXT NOT NULL,
	base_url VARCHAR(255) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_key_scope UNIQUE (tenant_id, user_id, provider),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_provider_keys_tenant_id ON provider_keys (tenant_id);
CREATE INDEX IF NOT EXISTS ix_provider_keys_user_id ON provider_keys (user_id);

CREATE TABLE IF NOT EXISTS referral_credits (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	referred_user_id VARCHAR(32) NOT NULL,
	amount_cents INTEGER NOT NULL,
	status VARCHAR(10) NOT NULL,
	stripe_txn_id VARCHAR(64),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	applied_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_referral_per_referred UNIQUE (referred_user_id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(referred_user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_referral_credits_referred_user_id ON referral_credits (referred_user_id);
CREATE INDEX IF NOT EXISTS ix_referral_credits_tenant_id ON referral_credits (tenant_id);
CREATE INDEX IF NOT EXISTS ix_referral_credits_user_id ON referral_credits (user_id);

CREATE TABLE IF NOT EXISTS sender_identities (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	provider VARCHAR(24) NOT NULL,
	provider_resource_ref VARCHAR(64) NOT NULL,
	number_e164 VARCHAR(20) NOT NULL,
	registration_status VARCHAR(24) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_sender_identities_tenant_id ON sender_identities (tenant_id);
CREATE INDEX IF NOT EXISTS ix_sender_identities_user_id ON sender_identities (user_id);

CREATE TABLE IF NOT EXISTS subscriptions (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	stripe_customer_id VARCHAR(64),
	stripe_subscription_id VARCHAR(64),
	tier VARCHAR(20) NOT NULL,
	interval VARCHAR(10) NOT NULL,
	status VARCHAR(20) NOT NULL,
	trial_end TIMESTAMP WITH TIME ZONE,
	current_period_end TIMESTAMP WITH TIME ZONE,
	first_paid_at TIMESTAMP WITH TIME ZONE,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_subscriptions_stripe_customer_id ON subscriptions (stripe_customer_id);
CREATE INDEX IF NOT EXISTS ix_subscriptions_stripe_subscription_id ON subscriptions (stripe_subscription_id);
CREATE INDEX IF NOT EXISTS ix_subscriptions_tenant_id ON subscriptions (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_subscriptions_user_id ON subscriptions (user_id);

CREATE TABLE IF NOT EXISTS usage_records (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	provider VARCHAR(20) NOT NULL,
	model VARCHAR(80) NOT NULL,
	key_scope VARCHAR(10) NOT NULL,
	input_tokens INTEGER NOT NULL,
	output_tokens INTEGER NOT NULL,
	cost_usd FLOAT NOT NULL,
	kind VARCHAR(20) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_usage_records_tenant_id ON usage_records (tenant_id);
CREATE INDEX IF NOT EXISTS ix_usage_records_user_id ON usage_records (user_id);

CREATE TABLE IF NOT EXISTS action_links (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32) NOT NULL,
	kernel_action_id VARCHAR(36) NOT NULL,
	action_digest VARCHAR(71) NOT NULL,
	brief_item_id VARCHAR(32),
	commitment_id VARCHAR(32),
	draft_version_id VARCHAR(32),
	last_known_state VARCHAR(32) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_action_links_customer_id ON action_links (customer_id);
CREATE INDEX IF NOT EXISTS ix_action_links_kernel_action_id ON action_links (kernel_action_id);
CREATE INDEX IF NOT EXISTS ix_action_links_tenant_id ON action_links (tenant_id);

CREATE TABLE IF NOT EXISTS auth_revocations (
	session_id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	confirmed_at TIMESTAMP WITH TIME ZONE,
	attempts INTEGER NOT NULL,
	last_error VARCHAR(80) NOT NULL,
	next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL,
	lease_id VARCHAR(32),
	PRIMARY KEY (session_id),
	FOREIGN KEY(session_id) REFERENCES auth_sessions (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_auth_revocations_confirmed_at ON auth_revocations (confirmed_at);
CREATE INDEX IF NOT EXISTS ix_auth_revocations_next_attempt_at ON auth_revocations (next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_auth_revocations_tenant_id ON auth_revocations (tenant_id);
CREATE INDEX IF NOT EXISTS ix_auth_revocations_user_id ON auth_revocations (user_id);

CREATE TABLE IF NOT EXISTS brief_items (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32) NOT NULL,
	brief_date VARCHAR(10) NOT NULL,
	rule VARCHAR(40) NOT NULL,
	rank_category INTEGER NOT NULL,
	source_type VARCHAR(24) NOT NULL,
	source_reference VARCHAR(64) NOT NULL,
	due_at TIMESTAMP WITH TIME ZONE,
	state VARCHAR(16) NOT NULL,
	permission_state VARCHAR(16) NOT NULL,
	permission_checked_at TIMESTAMP WITH TIME ZONE,
	suggested_step VARCHAR(200) NOT NULL,
	draft_version_id VARCHAR(32),
	action_id VARCHAR(36),
	dedupe_key VARCHAR(120) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_brief_dedupe UNIQUE (tenant_id, dedupe_key),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_brief_items_brief_date ON brief_items (brief_date);
CREATE INDEX IF NOT EXISTS ix_brief_items_customer_id ON brief_items (customer_id);
CREATE INDEX IF NOT EXISTS ix_brief_items_dedupe_key ON brief_items (dedupe_key);
CREATE INDEX IF NOT EXISTS ix_brief_items_tenant_id ON brief_items (tenant_id);
CREATE INDEX IF NOT EXISTS ix_brief_items_user_id ON brief_items (user_id);

CREATE TABLE IF NOT EXISTS claim_facts (
	claim_row_id VARCHAR(32) NOT NULL,
	name VARCHAR(100) NOT NULL,
	value VARCHAR(120) NOT NULL,
	PRIMARY KEY (claim_row_id, name),
	FOREIGN KEY(claim_row_id) REFERENCES approved_claims (id) ON DELETE CASCADE
)

;


CREATE TABLE IF NOT EXISTS commitments (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32) NOT NULL,
	owner_user_id VARCHAR(32) NOT NULL,
	source_type VARCHAR(24) NOT NULL,
	source_reference VARCHAR(64) NOT NULL,
	source_version VARCHAR(64) NOT NULL,
	source_evidence_reference VARCHAR(71) NOT NULL,
	kind VARCHAR(24) NOT NULL,
	commitment_text TEXT NOT NULL,
	due_at TIMESTAMP WITH TIME ZONE,
	due_window_start TIMESTAMP WITH TIME ZONE,
	due_window_end TIMESTAMP WITH TIME ZONE,
	timezone VARCHAR(64),
	status VARCHAR(12) NOT NULL,
	created_by VARCHAR(32) NOT NULL,
	confirmed_by VARCHAR(32),
	confirmed_at TIMESTAMP WITH TIME ZONE,
	resolution_reference VARCHAR(64) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id),
	FOREIGN KEY(owner_user_id) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_commitments_customer_id ON commitments (customer_id);
CREATE INDEX IF NOT EXISTS ix_commitments_owner_user_id ON commitments (owner_user_id);
CREATE INDEX IF NOT EXISTS ix_commitments_tenant_id ON commitments (tenant_id);

CREATE TABLE IF NOT EXISTS consent_records (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	subject VARCHAR(20) NOT NULL,
	customer_id VARCHAR(32),
	scope VARCHAR(40) NOT NULL,
	consent_version VARCHAR(40) NOT NULL,
	text_sha256 VARCHAR(64) NOT NULL,
	granted_at TIMESTAMP WITH TIME ZONE NOT NULL,
	revoked_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_consent_records_customer_id ON consent_records (customer_id);
CREATE INDEX IF NOT EXISTS ix_consent_records_tenant_id ON consent_records (tenant_id);
CREATE INDEX IF NOT EXISTS ix_consent_records_user_id ON consent_records (user_id);

CREATE TABLE IF NOT EXISTS contact_preferences (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32) NOT NULL,
	timezone VARCHAR(64),
	preferred_channel VARCHAR(12) NOT NULL,
	window_start_hour INTEGER,
	window_end_hour INTEGER,
	language VARCHAR(8) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE UNIQUE INDEX IF NOT EXISTS ix_contact_preferences_customer_id ON contact_preferences (customer_id);
CREATE INDEX IF NOT EXISTS ix_contact_preferences_tenant_id ON contact_preferences (tenant_id);

CREATE TABLE IF NOT EXISTS customer_destinations (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32) NOT NULL,
	channel VARCHAR(12) NOT NULL,
	value_enc TEXT NOT NULL,
	fingerprint VARCHAR(64) NOT NULL,
	label VARCHAR(40) NOT NULL,
	is_primary BOOLEAN NOT NULL,
	source VARCHAR(24) NOT NULL,
	source_ref VARCHAR(64) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	retired_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_destination_scope UNIQUE (tenant_id, channel, fingerprint, customer_id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_customer_destinations_customer_id ON customer_destinations (customer_id);
CREATE INDEX IF NOT EXISTS ix_customer_destinations_fingerprint ON customer_destinations (fingerprint);
CREATE INDEX IF NOT EXISTS ix_customer_destinations_tenant_id ON customer_destinations (tenant_id);

CREATE TABLE IF NOT EXISTS draft_versions (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32) NOT NULL,
	brief_item_id VARCHAR(32),
	commitment_id VARCHAR(32),
	text_enc TEXT NOT NULL,
	text_digest VARCHAR(71) NOT NULL,
	relationship_spans_json TEXT NOT NULL,
	claim_ids_json TEXT NOT NULL,
	source_versions_json TEXT NOT NULL,
	generated_by VARCHAR(120) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_draft_versions_brief_item_id ON draft_versions (brief_item_id);
CREATE INDEX IF NOT EXISTS ix_draft_versions_commitment_id ON draft_versions (commitment_id);
CREATE INDEX IF NOT EXISTS ix_draft_versions_customer_id ON draft_versions (customer_id);
CREATE INDEX IF NOT EXISTS ix_draft_versions_tenant_id ON draft_versions (tenant_id);

CREATE TABLE IF NOT EXISTS exceptions (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32),
	kind VARCHAR(32) NOT NULL,
	source_reference VARCHAR(64) NOT NULL,
	detail_enc TEXT NOT NULL,
	state VARCHAR(12) NOT NULL,
	resolved_by VARCHAR(32),
	resolved_at TIMESTAMP WITH TIME ZONE,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_exceptions_customer_id ON exceptions (customer_id);
CREATE INDEX IF NOT EXISTS ix_exceptions_tenant_id ON exceptions (tenant_id);

CREATE TABLE IF NOT EXISTS import_rows (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	job_id VARCHAR(32) NOT NULL,
	row_index INTEGER NOT NULL,
	status VARCHAR(12) NOT NULL,
	error VARCHAR(200) NOT NULL,
	name VARCHAR(120) NOT NULL,
	phone_enc TEXT NOT NULL,
	phone_fingerprint VARCHAR(64) NOT NULL,
	email_enc TEXT NOT NULL,
	email_fingerprint VARCHAR(64) NOT NULL,
	notes TEXT NOT NULL,
	customer_id VARCHAR(32),
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(job_id) REFERENCES import_jobs (id)
)

;
CREATE INDEX IF NOT EXISTS ix_import_rows_job_id ON import_rows (job_id);
CREATE INDEX IF NOT EXISTS ix_import_rows_tenant_id ON import_rows (tenant_id);

CREATE TABLE IF NOT EXISTS messages (
	id VARCHAR(32) NOT NULL,
	conversation_id VARCHAR(32) NOT NULL,
	role VARCHAR(12) NOT NULL,
	content TEXT NOT NULL,
	provider VARCHAR(20) NOT NULL,
	model VARCHAR(80) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(conversation_id) REFERENCES conversations (id)
)

;
CREATE INDEX IF NOT EXISTS ix_messages_conversation_id ON messages (conversation_id);

CREATE TABLE IF NOT EXISTS outcomes (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32) NOT NULL,
	commitment_id VARCHAR(32),
	action_link_id VARCHAR(32),
	kind VARCHAR(32) NOT NULL,
	recorded_by VARCHAR(32) NOT NULL,
	note_enc TEXT NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_outcomes_commitment_id ON outcomes (commitment_id);
CREATE INDEX IF NOT EXISTS ix_outcomes_customer_id ON outcomes (customer_id);
CREATE INDEX IF NOT EXISTS ix_outcomes_tenant_id ON outcomes (tenant_id);

CREATE TABLE IF NOT EXISTS skin_analyses (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	user_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32),
	result_json TEXT NOT NULL,
	provider VARCHAR(20) NOT NULL,
	model VARCHAR(80) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(user_id) REFERENCES users (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_skin_analyses_tenant_id ON skin_analyses (tenant_id);
CREATE INDEX IF NOT EXISTS ix_skin_analyses_user_id ON skin_analyses (user_id);

CREATE TABLE IF NOT EXISTS suppression_events (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32),
	channel VARCHAR(12),
	fingerprint VARCHAR(64) NOT NULL,
	reason VARCHAR(120) NOT NULL,
	source VARCHAR(32) NOT NULL,
	permanent BOOLEAN NOT NULL,
	kernel_suppression_id VARCHAR(36) NOT NULL,
	created_by VARCHAR(32) NOT NULL,
	lifted_at TIMESTAMP WITH TIME ZONE,
	lifted_by VARCHAR(32) NOT NULL,
	lift_evidence_digest VARCHAR(71) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id)
)

;
CREATE INDEX IF NOT EXISTS ix_suppression_events_customer_id ON suppression_events (customer_id);
CREATE INDEX IF NOT EXISTS ix_suppression_events_fingerprint ON suppression_events (fingerprint);
CREATE INDEX IF NOT EXISTS ix_suppression_events_tenant_id ON suppression_events (tenant_id);

CREATE TABLE IF NOT EXISTS consent_events (
	id VARCHAR(32) NOT NULL,
	tenant_id VARCHAR(32) NOT NULL,
	customer_id VARCHAR(32) NOT NULL,
	destination_id VARCHAR(32) NOT NULL,
	channel VARCHAR(12) NOT NULL,
	purposes_json TEXT NOT NULL,
	source VARCHAR(32) NOT NULL,
	evidence_type VARCHAR(32) NOT NULL,
	evidence_ref VARCHAR(256) NOT NULL,
	evidence_digest VARCHAR(71) NOT NULL,
	effective_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	status VARCHAR(12) NOT NULL,
	revoked_at TIMESTAMP WITH TIME ZONE,
	revoked_reason VARCHAR(120) NOT NULL,
	kernel_permission_id VARCHAR(36) NOT NULL,
	created_by VARCHAR(32) NOT NULL,
	version INTEGER NOT NULL,
	audit_ref VARCHAR(32) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id),
	FOREIGN KEY(customer_id) REFERENCES customers (id),
	FOREIGN KEY(destination_id) REFERENCES customer_destinations (id),
	FOREIGN KEY(created_by) REFERENCES users (id)
)

;
CREATE INDEX IF NOT EXISTS ix_consent_events_created_by ON consent_events (created_by);
CREATE INDEX IF NOT EXISTS ix_consent_events_customer_id ON consent_events (customer_id);
CREATE INDEX IF NOT EXISTS ix_consent_events_destination_id ON consent_events (destination_id);
CREATE INDEX IF NOT EXISTS ix_consent_events_tenant_id ON consent_events (tenant_id);
