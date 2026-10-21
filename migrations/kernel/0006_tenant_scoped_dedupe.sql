-- 0006: provider event dedupe is scoped to the tenant.
--
-- Twilio SIDs are globally unique in practice, but the dedupe key must never
-- let one tenant's row make another tenant's inbound STOP (or delivery
-- callback) look like a redelivery: under RLS the conflicting row is invisible
-- to the inserting tenant, so a global UNIQUE would silently drop the event
-- and acknowledge it. Scoping the constraint to (tenant_id, provider,
-- provider_event_id) keeps durable per-tenant dedupe and removes the
-- cross-tenant suppression path.
ALTER TABLE kernel.delivery_events
  DROP CONSTRAINT delivery_events_provider_provider_event_id_key,
  ADD CONSTRAINT delivery_events_tenant_provider_event_key UNIQUE (tenant_id, provider, provider_event_id);

ALTER TABLE kernel.inbound_events
  DROP CONSTRAINT inbound_events_provider_provider_event_id_key,
  ADD CONSTRAINT inbound_events_tenant_provider_event_key UNIQUE (tenant_id, provider, provider_event_id);
