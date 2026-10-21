-- 0007: a contact permission is bound to the destination the consent evidence
-- covers. Policy v1 matched permissions by (contact, channel) only, so consent
-- recorded for one number permitted outreach to any number supplied in the
-- action's `arguments.to`. New grants carry the destination fingerprint (same
-- HMAC the suppression ledger uses); the consent check requires it to equal
-- the action's destination. Rows without one (pre-0007) no longer authorize
-- outreach to a destination — fail closed; re-record consent with its evidence.
ALTER TABLE kernel.contact_permissions ADD COLUMN destination_hash text;
CREATE INDEX contact_permissions_destination ON kernel.contact_permissions (tenant_id, contact_id, channel, destination_hash);
