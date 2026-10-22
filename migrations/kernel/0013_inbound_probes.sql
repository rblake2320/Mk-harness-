-- One bounded, short-lived probe generation per sender. An HTTP acknowledgement
-- is not health evidence until the issuing worker reads its committed receipt.
CREATE TABLE kernel.inbound_probes (
  tenant_id uuid NOT NULL,
  sender_identity_id uuid NOT NULL,
  probe_id uuid,
  issued_at timestamptz,
  expires_at timestamptz,
  body_digest text,
  received_at timestamptz,
  confirmed_at timestamptz,
  last_ok_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, sender_identity_id),
  FOREIGN KEY (tenant_id, sender_identity_id) REFERENCES kernel.sender_identities (tenant_id, sender_identity_id),
  CHECK (body_digest IS NULL OR body_digest ~ '^sha256:[0-9a-f]{64}$')
);
ALTER TABLE kernel.inbound_probes ENABLE ROW LEVEL SECURITY;
ALTER TABLE kernel.inbound_probes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON kernel.inbound_probes
  USING (tenant_id = kernel.current_tenant()) WITH CHECK (tenant_id = kernel.current_tenant());
GRANT SELECT ON kernel.inbound_probes TO mk_kernel_api, mk_kernel_worker, mk_kernel_readonly;
GRANT INSERT, UPDATE ON kernel.inbound_probes TO mk_kernel_worker;
GRANT UPDATE (received_at) ON kernel.inbound_probes TO mk_kernel_api;
REVOKE DELETE, TRUNCATE ON kernel.inbound_probes FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
ALTER TABLE kernel.inbound_health ADD COLUMN recovery_required boolean NOT NULL DEFAULT false;
