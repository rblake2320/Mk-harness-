-- A retry watermark is not successful reconciliation evidence. Claim work in
-- a short transaction, release connections before the provider GET, and allow
-- recovery after a worker crash. Existing tenant RLS/role grants are unchanged.
ALTER TABLE kernel.message_deliveries
    ADD COLUMN reconciliation_checked_at timestamptz;
CREATE INDEX message_deliveries_reconciliation_due
    ON kernel.message_deliveries (tenant_id, reconciliation_checked_at, submission_started_at)
    WHERE provider_message_id IS NOT NULL
      AND state NOT IN ('delivered', 'failed');
