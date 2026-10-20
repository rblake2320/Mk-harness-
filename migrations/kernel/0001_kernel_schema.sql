-- MK action kernel: schema `kernel`. Owned exclusively by Rust migrations.
-- Python/Alembic must never touch this schema; this migration never touches
-- Python-owned tables.
--
-- Roles (created idempotently; passwords are set out-of-band by deployment):
--   mk_kernel_migrator  owns the schema, runs migrations
--   mk_kernel_api       API process: read/write actions, approvals, consent
--   mk_kernel_worker    worker: leases, attempts, idempotency, dispatch
--   mk_kernel_relay     outbox relay: claim/publish outbox rows
--   mk_kernel_readonly  support/analytics
-- No runtime role may UPDATE or DELETE audit_events.

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mk_kernel_api') THEN CREATE ROLE mk_kernel_api NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mk_kernel_worker') THEN CREATE ROLE mk_kernel_worker NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mk_kernel_relay') THEN CREATE ROLE mk_kernel_relay NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mk_kernel_readonly') THEN CREATE ROLE mk_kernel_readonly NOLOGIN; END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS kernel;

-- Tenant context for RLS. Every runtime connection sets
--   SET LOCAL kernel.tenant_id = '<uuid>'   (per transaction)
-- or runs as a role with BYPASSRLS for cross-tenant maintenance (verifier).
CREATE OR REPLACE FUNCTION kernel.current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('kernel.tenant_id', true), '')::uuid
$$;

-- ---------------------------------------------------------------------------
CREATE TABLE kernel.policy_versions (
  tenant_id                 uuid        NOT NULL,
  version                   text        NOT NULL,
  dispatch_enabled          boolean     NOT NULL DEFAULT true,
  agent_operations_entitled boolean     NOT NULL DEFAULT true,
  allow_self_approval       boolean     NOT NULL DEFAULT false,
  contact_hours_start       smallint    NOT NULL DEFAULT 8  CHECK (contact_hours_start BETWEEN 0 AND 24),
  contact_hours_end         smallint    NOT NULL DEFAULT 21 CHECK (contact_hours_end BETWEEN 0 AND 24),
  contact_tz                text        NOT NULL DEFAULT 'America/Chicago',
  contact_tz_offset_minutes integer     NOT NULL DEFAULT -300,
  max_per_contact_per_day   integer     NOT NULL DEFAULT 2 CHECK (max_per_contact_per_day >= 0),
  approval_ttl_secs         integer     NOT NULL DEFAULT 900 CHECK (approval_ttl_secs BETWEEN 60 AND 86400),
  required_opt_out_phrase   text        NOT NULL DEFAULT 'reply stop',
  roles_allowed_to_propose  text[]      NOT NULL DEFAULT ARRAY['agent','consultant','manager','tenant_admin'],
  created_at                timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE kernel.kill_switches (
  scope        text        NOT NULL,              -- 'global' or 'tenant'
  tenant_id    uuid,                              -- NULL for global
  dispatch_enabled boolean NOT NULL DEFAULT true,
  changed_by   text        NOT NULL,
  changed_at   timestamptz NOT NULL DEFAULT now(),
  CHECK ((scope = 'global' AND tenant_id IS NULL) OR (scope = 'tenant' AND tenant_id IS NOT NULL))
);
CREATE UNIQUE INDEX kill_switches_global_uq ON kernel.kill_switches ((scope)) WHERE scope = 'global';
CREATE UNIQUE INDEX kill_switches_tenant_uq ON kernel.kill_switches (tenant_id) WHERE scope = 'tenant';
INSERT INTO kernel.kill_switches (scope, tenant_id, dispatch_enabled, changed_by) VALUES ('global', NULL, true, 'migration');

-- ---------------------------------------------------------------------------
CREATE TABLE kernel.actions (
  action_id          uuid        NOT NULL,
  tenant_id          uuid        NOT NULL,
  requested_by       uuid        NOT NULL,
  origin_type        text        NOT NULL,
  workflow           text        NOT NULL,
  action_kind        text        NOT NULL,
  tool_id            text        NOT NULL,
  resource_type      text        NOT NULL,
  resource_id        text        NOT NULL,
  channel            text,
  purpose            text        NOT NULL,
  risk               text        NOT NULL CHECK (risk IN ('low','medium','high')),
  state              text        NOT NULL,
  -- Exact canonical bytes (RFC 8785) of the bound request; approvals commit to their digest.
  canonical_request  bytea       NOT NULL,
  action_digest      text        NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  destination_hash   text,
  idempotency_key    text        NOT NULL,
  requested_at       timestamptz NOT NULL,
  expires_at         timestamptz NOT NULL,
  attempt            integer     NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  error_code         text,
  replay_of          uuid,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, action_id),
  UNIQUE (action_id),
  CHECK (expires_at > requested_at)
);
CREATE INDEX actions_state_idx ON kernel.actions (tenant_id, state, updated_at);
CREATE INDEX actions_contact_idx ON kernel.actions (tenant_id, resource_id, channel, created_at)
  WHERE action_kind IN ('send_sms','send_email','send_dm','mobile_work_order');
CREATE INDEX actions_expiry_idx ON kernel.actions (expires_at) WHERE state IN ('policy_pending','approval_required','approved','queued','failed_retryable');

CREATE TABLE kernel.action_attempts (
  tenant_id     uuid        NOT NULL,
  action_id     uuid        NOT NULL,
  attempt       integer     NOT NULL,
  worker_id     text        NOT NULL,
  started_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  outcome       text        NOT NULL DEFAULT 'started' CHECK (outcome IN ('started','completed','failed_retryable','failed_final','reconciliation_required')),
  error_code    text,
  adapter_id    uuid,
  external_ref  text,
  result_digest text,
  PRIMARY KEY (tenant_id, action_id, attempt),
  FOREIGN KEY (tenant_id, action_id) REFERENCES kernel.actions (tenant_id, action_id)
);

CREATE TABLE kernel.approvals (
  approval_id     uuid        NOT NULL,
  tenant_id       uuid        NOT NULL,
  action_id       uuid        NOT NULL,
  action_digest   text        NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  approver_id     uuid        NOT NULL,
  approver_roles  text[]      NOT NULL DEFAULT '{}',
  decision        text        NOT NULL CHECK (decision IN ('approved','rejected')),
  reason          text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz,
  consumed_by     text,
  revoked_at      timestamptz,
  revoked_by      uuid,
  request_ip_hash text,
  session_id      text,
  PRIMARY KEY (tenant_id, approval_id),
  UNIQUE (approval_id),
  FOREIGN KEY (tenant_id, action_id) REFERENCES kernel.actions (tenant_id, action_id),
  CHECK (expires_at > created_at)
);
-- At most one *live* approved decision per action.
CREATE UNIQUE INDEX approvals_one_live_per_action ON kernel.approvals (tenant_id, action_id)
  WHERE decision = 'approved' AND consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX approvals_pending_idx ON kernel.approvals (tenant_id, created_at) WHERE consumed_at IS NULL AND revoked_at IS NULL;

-- ---------------------------------------------------------------------------
CREATE TABLE kernel.contact_permissions (
  permission_id uuid        NOT NULL,
  tenant_id     uuid        NOT NULL,
  contact_id    uuid        NOT NULL,
  channel       text        NOT NULL,
  status        text        NOT NULL CHECK (status IN ('granted','revoked','expired')),
  scope         text[]      NOT NULL,
  source        text        NOT NULL,
  proof_digest  text        NOT NULL CHECK (proof_digest ~ '^sha256:[0-9a-f]{64}$'),
  granted_at    timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz,
  recorded_by   uuid        NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, permission_id),
  UNIQUE (permission_id),
  CHECK (expires_at > granted_at)
);
CREATE INDEX contact_permissions_lookup ON kernel.contact_permissions (tenant_id, contact_id, channel);

CREATE TABLE kernel.suppressions (
  suppression_id              uuid        NOT NULL,
  tenant_id                   uuid        NOT NULL,
  normalized_destination_hash text,                 -- NULL = tenant-wide
  channel                     text,                 -- NULL = all channels
  scope                       text        NOT NULL,
  reason                      text        NOT NULL,
  permanent                   boolean     NOT NULL DEFAULT false,
  created_at                  timestamptz NOT NULL DEFAULT now(),
  lifted_at                   timestamptz,
  lifted_by                   uuid,
  source                      text        NOT NULL,
  PRIMARY KEY (tenant_id, suppression_id),
  UNIQUE (suppression_id)
);
CREATE INDEX suppressions_lookup ON kernel.suppressions (tenant_id, channel, normalized_destination_hash) WHERE lifted_at IS NULL;

-- ---------------------------------------------------------------------------
CREATE TABLE kernel.adapter_registrations (
  adapter_id          uuid        NOT NULL,
  tenant_id           uuid        NOT NULL,
  agent_id            text        NOT NULL CHECK (agent_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$'),
  name                text        NOT NULL,
  adapter_kind        text        NOT NULL DEFAULT 'mobile-adapter-v1',
  platform            text        NOT NULL,
  version             text        NOT NULL,
  capabilities        text[]      NOT NULL DEFAULT '{}',
  allowed_actions     text[]      NOT NULL DEFAULT '{}',
  callback_authority  text        NOT NULL,   -- allowlisted host[:port]; never user-supplied
  verified_on_device  boolean     NOT NULL DEFAULT false,
  revoked_at          timestamptz,
  last_used_at        timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, adapter_id),
  UNIQUE (adapter_id),
  UNIQUE (tenant_id, agent_id)
);

CREATE TABLE kernel.adapter_credentials (
  credential_id   uuid        NOT NULL,
  tenant_id       uuid        NOT NULL,
  adapter_id      uuid        NOT NULL,
  -- AES-256-GCM ciphertext of the HMAC secret, AAD = tenant:adapter:credential.
  secret_ciphertext bytea     NOT NULL,
  secret_fingerprint text     NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  -- Rotation: old credential gets not_after = now + overlap.
  not_after       timestamptz,
  revoked_at      timestamptz,
  PRIMARY KEY (tenant_id, credential_id),
  UNIQUE (credential_id),
  FOREIGN KEY (tenant_id, adapter_id) REFERENCES kernel.adapter_registrations (tenant_id, adapter_id)
);
CREATE INDEX adapter_credentials_live ON kernel.adapter_credentials (tenant_id, adapter_id) WHERE revoked_at IS NULL;

CREATE TABLE kernel.adapter_nonces (
  tenant_id   uuid        NOT NULL,
  adapter_id  uuid        NOT NULL,
  nonce       text        NOT NULL CHECK (length(nonce) BETWEEN 1 AND 80),
  seen_at     timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, adapter_id, nonce)
);
CREATE INDEX adapter_nonces_expiry ON kernel.adapter_nonces (expires_at);

CREATE TABLE kernel.adapter_callbacks (
  callback_id   uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id     uuid        NOT NULL,
  adapter_id    uuid        NOT NULL,
  action_id     uuid        NOT NULL,
  kind          text        NOT NULL CHECK (kind IN ('executing','complete','failed')),
  body_digest   text        NOT NULL,
  nonce         text        NOT NULL,
  received_at   timestamptz NOT NULL DEFAULT now(),
  applied       boolean     NOT NULL,
  PRIMARY KEY (tenant_id, callback_id),
  FOREIGN KEY (tenant_id, action_id) REFERENCES kernel.actions (tenant_id, action_id)
);
CREATE INDEX adapter_callbacks_action ON kernel.adapter_callbacks (tenant_id, action_id, received_at);

-- ---------------------------------------------------------------------------
CREATE TABLE kernel.execution_leases (
  tenant_id   uuid        NOT NULL,
  action_id   uuid        NOT NULL,
  worker_id   text        NOT NULL,
  lease_token uuid        NOT NULL,
  acquired_at timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, action_id),
  FOREIGN KEY (tenant_id, action_id) REFERENCES kernel.actions (tenant_id, action_id)
);
CREATE INDEX execution_leases_expiry ON kernel.execution_leases (expires_at);

CREATE TABLE kernel.idempotency_records (
  tenant_id       uuid        NOT NULL,
  action_kind     text        NOT NULL,
  idempotency_key text        NOT NULL,
  request_digest  text        NOT NULL,
  first_action_id uuid        NOT NULL,
  status          text        NOT NULL DEFAULT 'accepted',
  response_digest text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, action_kind, idempotency_key)
);

CREATE TABLE kernel.outbox_events (
  outbox_id     bigserial   PRIMARY KEY,
  tenant_id     uuid        NOT NULL,
  action_id     uuid        NOT NULL,
  event_kind    text        NOT NULL,  -- 'dispatch' | 'retry'
  payload       jsonb       NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  available_at  timestamptz NOT NULL DEFAULT now(),
  leased_until  timestamptz,
  leased_by     text,
  published_at  timestamptz,
  attempts      integer     NOT NULL DEFAULT 0
);
CREATE INDEX outbox_pending ON kernel.outbox_events (available_at, outbox_id) WHERE published_at IS NULL;

CREATE TABLE kernel.dead_letters (
  tenant_id       uuid        NOT NULL,
  action_id       uuid        NOT NULL,
  final_state     text        NOT NULL,
  attempts        integer     NOT NULL,
  error_code      text,
  diagnostics     jsonb       NOT NULL,   -- redacted
  dead_lettered_at timestamptz NOT NULL DEFAULT now(),
  replayed_as     uuid,
  PRIMARY KEY (tenant_id, action_id),
  FOREIGN KEY (tenant_id, action_id) REFERENCES kernel.actions (tenant_id, action_id)
);

-- ---------------------------------------------------------------------------
CREATE TABLE kernel.audit_heads (
  tenant_id  uuid        PRIMARY KEY,
  last_hash  text        NOT NULL DEFAULT 'genesis',
  count      bigint      NOT NULL DEFAULT 0 CHECK (count >= 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE kernel.audit_events (
  event_id            uuid        NOT NULL,
  tenant_id           uuid        NOT NULL,
  tenant_sequence     bigint      NOT NULL CHECK (tenant_sequence >= 1),
  occurred_at         timestamptz NOT NULL,
  actor_type          text        NOT NULL,
  actor_id            text        NOT NULL,
  action_id           uuid,
  event_type          text        NOT NULL,
  payload_redacted    jsonb       NOT NULL,
  payload_digest      text        NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
  previous_event_hash text        NOT NULL,
  event_hash          text        NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  trace_id            text,
  policy_version      text        NOT NULL,
  PRIMARY KEY (tenant_id, tenant_sequence),
  UNIQUE (event_id),
  UNIQUE (event_hash)
);
CREATE INDEX audit_events_action ON kernel.audit_events (tenant_id, action_id, tenant_sequence);

-- Defense in depth: even the owner cannot UPDATE/DELETE audit rows through a
-- normal statement. Only a migration that drops this trigger can.
CREATE OR REPLACE FUNCTION kernel.audit_events_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'kernel.audit_events is append-only' USING ERRCODE = 'integrity_constraint_violation';
END $$;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON kernel.audit_events
  FOR EACH ROW EXECUTE FUNCTION kernel.audit_events_immutable();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON kernel.audit_events
  FOR EACH ROW EXECUTE FUNCTION kernel.audit_events_immutable();

-- ---------------------------------------------------------------------------
-- Row-level security on every tenant-scoped table.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'policy_versions','actions','action_attempts','approvals','contact_permissions','suppressions',
    'adapter_registrations','adapter_credentials','adapter_nonces','adapter_callbacks',
    'execution_leases','idempotency_records','outbox_events','dead_letters','audit_heads','audit_events'
  ] LOOP
    EXECUTE format('ALTER TABLE kernel.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE kernel.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON kernel.%I USING (tenant_id = kernel.current_tenant()) WITH CHECK (tenant_id = kernel.current_tenant())', t);
  END LOOP;
END $$;
-- Relay and worker claim across tenants (they do not read payload-bearing
-- tenant data without setting the tenant context afterwards).
CREATE POLICY relay_claim ON kernel.outbox_events TO mk_kernel_relay USING (true) WITH CHECK (true);
CREATE POLICY worker_lease_sweep ON kernel.execution_leases TO mk_kernel_worker USING (true) WITH CHECK (tenant_id = kernel.current_tenant());
CREATE POLICY readonly_all ON kernel.audit_events TO mk_kernel_readonly USING (true);
CREATE POLICY readonly_heads ON kernel.audit_heads TO mk_kernel_readonly USING (true);

-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA kernel TO mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;

GRANT SELECT, INSERT, UPDATE ON kernel.actions, kernel.approvals, kernel.contact_permissions, kernel.suppressions,
  kernel.adapter_registrations, kernel.adapter_credentials, kernel.idempotency_records, kernel.outbox_events,
  kernel.policy_versions, kernel.kill_switches, kernel.audit_heads TO mk_kernel_api;
GRANT SELECT, INSERT ON kernel.audit_events, kernel.adapter_nonces, kernel.adapter_callbacks TO mk_kernel_api;
GRANT SELECT ON kernel.action_attempts, kernel.execution_leases, kernel.dead_letters TO mk_kernel_api;

GRANT SELECT, INSERT, UPDATE ON kernel.actions, kernel.action_attempts, kernel.approvals, kernel.execution_leases,
  kernel.idempotency_records, kernel.dead_letters, kernel.audit_heads, kernel.outbox_events TO mk_kernel_worker;
GRANT SELECT, INSERT ON kernel.audit_events, kernel.adapter_nonces, kernel.adapter_callbacks TO mk_kernel_worker;
GRANT DELETE ON kernel.execution_leases, kernel.adapter_nonces TO mk_kernel_worker;
GRANT SELECT ON kernel.contact_permissions, kernel.suppressions, kernel.adapter_registrations,
  kernel.adapter_credentials, kernel.policy_versions, kernel.kill_switches TO mk_kernel_worker;

GRANT SELECT, UPDATE ON kernel.outbox_events TO mk_kernel_relay;
GRANT USAGE ON SEQUENCE kernel.outbox_events_outbox_id_seq TO mk_kernel_api, mk_kernel_worker;

GRANT SELECT ON ALL TABLES IN SCHEMA kernel TO mk_kernel_readonly;

-- Explicitly: no runtime role gets UPDATE/DELETE on audit_events.
REVOKE UPDATE, DELETE, TRUNCATE ON kernel.audit_events FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
