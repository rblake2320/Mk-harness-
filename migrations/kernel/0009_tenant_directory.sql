-- 0009: tenant directory for cross-tenant operator work under row-level security.
--
-- Operator tools (mk-keyctl reencrypt/retire/fingerprint-*, pre-flight) must
-- touch every tenant's rows. Every kernel table forces RLS, and production
-- logins (including the managed database's master user) are NOBYPASSRLS, so a
-- cross-tenant query outside a tenant context silently returns nothing — a
-- vacuous "0 stale / 0 orphaned" (found in review). Tools now enumerate
-- tenants here and do the work inside one tenant transaction per tenant.
--
-- The directory holds tenant UUIDs only (no tenant data) and is not under RLS.
-- Rows are added by SECURITY DEFINER triggers on the tables a tenant cannot
-- exist without; the backfill below sees every tenant when run by a superuser
-- or BYPASSRLS migrator and is otherwise filled forward by the triggers.
CREATE TABLE kernel.tenant_directory (
  tenant_id  uuid PRIMARY KEY,
  first_seen timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION kernel.register_tenant() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = kernel, pg_temp AS $$
BEGIN
  INSERT INTO kernel.tenant_directory (tenant_id) VALUES (NEW.tenant_id) ON CONFLICT DO NOTHING;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION kernel.register_tenant() FROM PUBLIC;

DO $$
DECLARE t text;
BEGIN
  -- Triggers only on low-volume tables: every destination-bearing write
  -- (action, suppression, permission, inbound event) appends an audit event in
  -- the same transaction, which creates the tenant's audit head first.
  FOREACH t IN ARRAY ARRAY['audit_heads','policy_versions','sender_identities','adapter_registrations'] LOOP
    EXECUTE format('CREATE TRIGGER %I AFTER INSERT ON kernel.%I FOR EACH ROW EXECUTE FUNCTION kernel.register_tenant()',
                   t || '_register_tenant', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['audit_heads','policy_versions','sender_identities','adapter_registrations',
                           'suppressions','contact_permissions','actions','inbound_events'] LOOP
    EXECUTE format('INSERT INTO kernel.tenant_directory (tenant_id) SELECT DISTINCT tenant_id FROM kernel.%I WHERE tenant_id IS NOT NULL ON CONFLICT DO NOTHING', t);
  END LOOP;
END $$;

GRANT SELECT ON kernel.tenant_directory TO mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;

-- Rolling deploys: a pre-0008 binary still running after this migration inserts
-- destination rows with the hash column set and no fingerprint tags; such an
-- opt-out would be invisible to tag-overlap lookups. Pre-0008 binaries only
-- ever fingerprint with the master key, so default empty tags to `m0:<hash>`.
CREATE FUNCTION kernel.default_fingerprint_tags() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE h text;
BEGIN
  IF coalesce(array_length(NEW.destination_fingerprints, 1), 0) = 0 THEN
    -- to_jsonb: one function for four row types (field names differ per table).
    h := to_jsonb(NEW) ->> (CASE TG_TABLE_NAME
           WHEN 'suppressions' THEN 'normalized_destination_hash'
           WHEN 'inbound_events' THEN 'source_destination_hash'
           ELSE 'destination_hash' END);
    IF h IS NOT NULL AND (TG_TABLE_NAME <> 'actions' OR to_jsonb(NEW) ->> 'channel' IS NOT NULL) THEN
      NEW.destination_fingerprints := ARRAY['m0:' || h];
    END IF;
  END IF;
  RETURN NEW;
END $$;
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['suppressions','contact_permissions','actions','inbound_events'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON kernel.%I FOR EACH ROW EXECUTE FUNCTION kernel.default_fingerprint_tags()',
                   t || '_default_fingerprints', t);
  END LOOP;
END $$;
