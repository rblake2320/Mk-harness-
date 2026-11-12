-- 0010: subject erasure (contract S13).
--
-- The application erases its own copies and then asks the kernel to erase the
-- kernel's: the message content inside terminal actions' canonical request
-- (arguments + evidence), and inbound message bodies from the subject's
-- destinations. Destination hashes, digests, states and the audit chain stay:
-- they are content-free and the chain must still verify after erasure. Copies
-- held by the SMS provider are queued in provider_erasures and deleted by the
-- worker through the provider's supported API.
ALTER TABLE kernel.actions ADD COLUMN erased_at timestamptz;
ALTER TABLE kernel.inbound_events ADD COLUMN erased_at timestamptz;

CREATE TABLE kernel.subject_erasures (
  erasure_id          uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id           uuid        NOT NULL,
  request_ref         text        NOT NULL CHECK (length(request_ref) BETWEEN 1 AND 64),
  requested_by        uuid        NOT NULL,
  destination_hashes  integer     NOT NULL CHECK (destination_hashes >= 0),
  actions_erased      integer     NOT NULL CHECK (actions_erased >= 0),
  actions_cancelled   integer     NOT NULL CHECK (actions_cancelled >= 0),
  inbound_erased      integer     NOT NULL CHECK (inbound_erased >= 0),
  provider_copies     integer     NOT NULL CHECK (provider_copies >= 0),
  created_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, erasure_id),
  UNIQUE (tenant_id, request_ref)
);

CREATE TABLE kernel.provider_erasures (
  provider_erasure_id uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id           uuid        NOT NULL,
  erasure_id          uuid        NOT NULL,
  sender_identity_id  uuid        NOT NULL,
  provider            text        NOT NULL,
  provider_message_id text        NOT NULL,
  direction           text        NOT NULL CHECK (direction IN ('outbound','inbound')),
  state               text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','deleted','not_found','failed')),
  attempts            integer     NOT NULL DEFAULT 0,
  last_error          text,
  next_attempt_at     timestamptz NOT NULL DEFAULT now(),
  completed_at        timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, provider_erasure_id),
  UNIQUE (tenant_id, provider, provider_message_id),
  FOREIGN KEY (tenant_id, erasure_id) REFERENCES kernel.subject_erasures (tenant_id, erasure_id)
);
CREATE INDEX provider_erasures_due ON kernel.provider_erasures (next_attempt_at) WHERE state = 'pending';

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['subject_erasures','provider_erasures'] LOOP
    EXECUTE format('ALTER TABLE kernel.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE kernel.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON kernel.%I USING (tenant_id = kernel.current_tenant()) WITH CHECK (tenant_id = kernel.current_tenant())', t);
  END LOOP;
END $$;
-- The worker discovers due provider deletions across tenants (ids only), then
-- does each one inside that tenant's context.
CREATE POLICY worker_provider_erasure_sweep ON kernel.provider_erasures FOR SELECT TO mk_kernel_worker USING (true);

GRANT SELECT, INSERT ON kernel.subject_erasures TO mk_kernel_api;
GRANT SELECT, INSERT ON kernel.provider_erasures TO mk_kernel_api;
GRANT SELECT, UPDATE ON kernel.provider_erasures TO mk_kernel_worker;
GRANT SELECT ON kernel.subject_erasures, kernel.provider_erasures TO mk_kernel_readonly;
GRANT SELECT ON kernel.message_deliveries TO mk_kernel_api;
