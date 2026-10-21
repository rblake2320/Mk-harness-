-- 0004: production messaging through a provider adapter (contract WP07, rows
-- C1–C8): per-business sender identities with sealed provider credentials,
-- message delivery records with monotonic provider-evidence states, inbound
-- event records (body sealed), inbound health, and the serialized
-- customer/channel control path (advisory locks; see mk-store::control_path).

-- One registered sender per consultant business. Credentials are sealed with
-- the kernel master key (AES-256-GCM, AAD = tenant:sender) — the API process
-- never reads them; only the worker (to submit) and the webhook verifier.
CREATE TABLE kernel.sender_identities (
  sender_identity_id   uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id            uuid        NOT NULL,
  owner_user_id        uuid        NOT NULL,            -- the consultant business
  provider             text        NOT NULL CHECK (provider IN ('twilio')),
  display_name         text        NOT NULL,
  account_sid          text        NOT NULL CHECK (account_sid ~ '^AC[0-9a-fA-F]{32}$'),
  auth_token_sealed    bytea       NOT NULL,
  from_number          text        CHECK (from_number IS NULL OR from_number ~ '^\+[1-9][0-9]{7,14}$'),
  messaging_service_sid text       CHECK (messaging_service_sid IS NULL OR messaging_service_sid ~ '^MG[0-9a-fA-F]{32}$'),
  -- registration evidence (10DLC brand/campaign or toll-free verification), recorded not asserted
  registration_status  text        NOT NULL DEFAULT 'unverified' CHECK (registration_status IN ('unverified','pending','registered','rejected')),
  registration_ref     text        NOT NULL DEFAULT '',
  status               text        NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  version              integer     NOT NULL DEFAULT 1,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, sender_identity_id),
  UNIQUE (sender_identity_id),
  -- a number is one business's; never shared across tenants
  UNIQUE (from_number),
  CHECK ((from_number IS NULL) <> (messaging_service_sid IS NULL))
);
CREATE INDEX sender_identities_owner ON kernel.sender_identities (tenant_id, owner_user_id) WHERE status = 'active';

-- Delivery record: one per action attempt that reached the provider boundary.
-- `state` is derived monotonically from provider events (mk-adapters::twilio::DeliveryState).
CREATE TABLE kernel.message_deliveries (
  delivery_id          uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id            uuid        NOT NULL,
  action_id            uuid        NOT NULL,
  attempt              integer     NOT NULL,
  sender_identity_id   uuid        NOT NULL,
  provider             text        NOT NULL,
  provider_message_id  text,
  state                text        NOT NULL CHECK (state IN ('submission_started','provider_accepted','sent','delivered','failed','delivery_unknown','submission_unknown')),
  provider_error_code  text,
  -- read status is separate and unknown unless a supported source supplies it
  read_status          text        NOT NULL DEFAULT 'unknown' CHECK (read_status IN ('unknown','read')),
  submission_started_at timestamptz NOT NULL,
  last_event_at        timestamptz,
  reconciled_at        timestamptz,
  reconciliation_note  text,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, delivery_id),
  UNIQUE (delivery_id),
  UNIQUE (tenant_id, action_id, attempt),
  FOREIGN KEY (tenant_id, action_id) REFERENCES kernel.actions (tenant_id, action_id)
);
CREATE INDEX message_deliveries_pmid ON kernel.message_deliveries (provider, provider_message_id) WHERE provider_message_id IS NOT NULL;

-- Every provider callback is preserved as received (deduped on provider event
-- identity); state derivation never deletes or rewrites them.
CREATE TABLE kernel.delivery_events (
  event_id             uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id            uuid        NOT NULL,
  delivery_id          uuid        NOT NULL,
  provider             text        NOT NULL,
  provider_event_id    text        NOT NULL,          -- MessageSid + ':' + MessageStatus
  provider_status      text        NOT NULL,
  provider_error_code  text,
  received_at          timestamptz NOT NULL DEFAULT now(),
  authentication_result text       NOT NULL CHECK (authentication_result IN ('verified')),
  raw_event_digest     text        NOT NULL CHECK (raw_event_digest ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (provider, provider_event_id)
);

-- Inbound customer messages: contract-mandated fields. Body sealed; never in
-- logs or audit metadata.
CREATE TABLE kernel.inbound_events (
  event_id             uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id            uuid        NOT NULL,
  provider             text        NOT NULL,
  provider_event_id    text        NOT NULL,          -- MessageSid
  sender_identity_id   uuid        NOT NULL,
  source_destination_hash text     NOT NULL,          -- HMAC fingerprint of the customer's number
  received_at          timestamptz NOT NULL DEFAULT now(),
  provider_timestamp   timestamptz,
  content_sealed       bytea       NOT NULL,          -- the body, AES-256-GCM
  content_reference    text        NOT NULL,          -- 'sealed:' || event_id
  authentication_result text       NOT NULL CHECK (authentication_result IN ('verified')),
  raw_event_digest     text        NOT NULL CHECK (raw_event_digest ~ '^sha256:[0-9a-f]{64}$'),
  opt_out_signal       text        NOT NULL CHECK (opt_out_signal IN ('explicit','possible','none')),
  disposition          text        NOT NULL CHECK (disposition IN ('suppressed','held','queued_for_meaning')),
  acknowledged_at      timestamptz,
  processed_at         timestamptz,                   -- async meaning processing done
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (event_id),
  UNIQUE (provider, provider_event_id)                -- durable dedupe before any task is created
);
CREATE INDEX inbound_events_pending ON kernel.inbound_events (tenant_id, received_at) WHERE processed_at IS NULL;

-- Inbound-path health per tenant (row C8). The worker refuses dispatch when
-- the most recent successful check is older than the pause threshold.
CREATE TABLE kernel.inbound_health (
  tenant_id            uuid        NOT NULL PRIMARY KEY,
  last_ok_at           timestamptz,
  last_failure_at      timestamptz,
  last_failure_reason  text        NOT NULL DEFAULT '',
  paused_since         timestamptz,
  resumed_at           timestamptz,
  pending_events_at_resume integer,
  updated_at           timestamptz NOT NULL DEFAULT now()
);

-- Outbox event kinds the inbound path emits for async meaning processing.
-- (outbox_events is generic; nothing to alter.)

-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['sender_identities','message_deliveries','delivery_events','inbound_events','inbound_health'] LOOP
    EXECUTE format('ALTER TABLE kernel.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE kernel.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON kernel.%I USING (tenant_id = kernel.current_tenant()) WITH CHECK (tenant_id = kernel.current_tenant())', t);
  END LOOP;
END $$;

-- Webhooks arrive before any tenant context: the API resolves the sender
-- identity (and thus the tenant) from the URL path with a cross-tenant read on
-- the identity table only, then opens a tenant transaction.
CREATE POLICY api_sender_lookup ON kernel.sender_identities FOR SELECT TO mk_kernel_api USING (true);
-- Worker needs cross-tenant discovery of paused/stale tenants for health sweeps.
CREATE POLICY worker_inbound_health ON kernel.inbound_health FOR SELECT TO mk_kernel_worker USING (true);

GRANT SELECT, INSERT, UPDATE ON kernel.sender_identities TO mk_kernel_api;
GRANT SELECT ON kernel.sender_identities TO mk_kernel_worker, mk_kernel_readonly;
GRANT SELECT, INSERT, UPDATE ON kernel.message_deliveries TO mk_kernel_api, mk_kernel_worker;
GRANT SELECT, INSERT ON kernel.delivery_events TO mk_kernel_api;
GRANT SELECT, INSERT, UPDATE ON kernel.inbound_events TO mk_kernel_api;
GRANT SELECT, UPDATE ON kernel.inbound_events TO mk_kernel_worker;
GRANT SELECT, INSERT, UPDATE ON kernel.inbound_health TO mk_kernel_api, mk_kernel_worker;
GRANT SELECT ON kernel.message_deliveries, kernel.delivery_events, kernel.inbound_events, kernel.inbound_health TO mk_kernel_readonly;
-- Events and inbound records are evidence.
REVOKE UPDATE, DELETE, TRUNCATE ON kernel.delivery_events FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
REVOKE DELETE, TRUNCATE ON kernel.inbound_events, kernel.message_deliveries, kernel.sender_identities FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
