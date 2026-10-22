-- 0008: versioned destination fingerprints (contract S6 — key rotation must
-- not orphan opt-outs or consent). Each destination-bearing row carries
-- `kid:hex` fingerprints under every configured key; lookups match on array
-- overlap. Pre-0008 hashes were keyed by the master key and are tagged `m0`.
-- Suppressions, permissions and inbound events also keep the raw destination
-- sealed under the keyring, so `mk-keyctl fingerprint-rekey` can add a new
-- key's tag without any outside input. Actions re-derive it from their
-- canonical arguments.
ALTER TABLE kernel.suppressions
  ADD COLUMN destination_fingerprints text[] NOT NULL DEFAULT '{}',
  ADD COLUMN destination_sealed bytea;
ALTER TABLE kernel.contact_permissions
  ADD COLUMN destination_fingerprints text[] NOT NULL DEFAULT '{}',
  ADD COLUMN destination_sealed bytea;
ALTER TABLE kernel.actions
  ADD COLUMN destination_fingerprints text[] NOT NULL DEFAULT '{}';
ALTER TABLE kernel.inbound_events
  ADD COLUMN destination_fingerprints text[] NOT NULL DEFAULT '{}',
  ADD COLUMN destination_sealed bytea;

UPDATE kernel.suppressions SET destination_fingerprints = ARRAY['m0:' || normalized_destination_hash]
  WHERE normalized_destination_hash IS NOT NULL;
UPDATE kernel.contact_permissions SET destination_fingerprints = ARRAY['m0:' || destination_hash]
  WHERE destination_hash IS NOT NULL;
UPDATE kernel.actions SET destination_fingerprints = ARRAY['m0:' || destination_hash]
  WHERE destination_hash IS NOT NULL AND channel IS NOT NULL;
UPDATE kernel.inbound_events SET destination_fingerprints = ARRAY['m0:' || source_destination_hash]
  WHERE source_destination_hash IS NOT NULL;

CREATE INDEX suppressions_fingerprints ON kernel.suppressions USING gin (destination_fingerprints);
CREATE INDEX contact_permissions_fingerprints ON kernel.contact_permissions USING gin (destination_fingerprints);
CREATE INDEX actions_fingerprints ON kernel.actions USING gin (destination_fingerprints);
CREATE INDEX inbound_events_fingerprints ON kernel.inbound_events USING gin (destination_fingerprints);
