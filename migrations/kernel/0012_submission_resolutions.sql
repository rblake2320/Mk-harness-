-- C4: an immutable human decision over a specific provider observation.
-- A resolution never authorizes a send or rewrites the original action.
CREATE TABLE kernel.submission_resolutions (
  tenant_id uuid NOT NULL,
  action_id uuid NOT NULL,
  delivery_id uuid NOT NULL,
  operation_digest text NOT NULL CHECK (operation_digest ~ '^sha256:[0-9a-f]{64}$'),
  provider_message_id text NOT NULL CHECK (provider_message_id ~ '^(SM|MM)[0-9a-fA-F]{32}$'),
  observed_state text NOT NULL,
  decision text NOT NULL,
  resolved_by uuid NOT NULL,
  credential_row_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, action_id),
  FOREIGN KEY (tenant_id, action_id) REFERENCES kernel.actions (tenant_id, action_id),
  FOREIGN KEY (tenant_id, delivery_id) REFERENCES kernel.message_deliveries (tenant_id, delivery_id),
  CHECK ((decision = 'closed_no_replacement' AND observed_state IN ('provider_accepted','sent','delivered'))
      OR (decision = 'replacement_permitted' AND observed_state = 'failed'))
);
ALTER TABLE kernel.submission_resolutions ENABLE ROW LEVEL SECURITY;
ALTER TABLE kernel.submission_resolutions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON kernel.submission_resolutions
  USING (tenant_id = kernel.current_tenant()) WITH CHECK (tenant_id = kernel.current_tenant());
GRANT SELECT, INSERT ON kernel.submission_resolutions TO mk_kernel_api;
GRANT SELECT ON kernel.submission_resolutions TO mk_kernel_worker, mk_kernel_readonly;
REVOKE UPDATE, DELETE, TRUNCATE ON kernel.submission_resolutions
  FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
CREATE FUNCTION kernel.reject_resolution_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'submission resolutions are append-only'; END $$;
CREATE TRIGGER immutable_resolution BEFORE UPDATE OR DELETE OR TRUNCATE
  ON kernel.submission_resolutions FOR EACH STATEMENT EXECUTE FUNCTION kernel.reject_resolution_mutation();
