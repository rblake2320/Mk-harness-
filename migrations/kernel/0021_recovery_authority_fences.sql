-- Recovery-only tombstones, including withdrawals of objects absent from backup.
-- Runtime roles can read them, never create, remove, or relax them.
CREATE TABLE kernel.recovery_authority_fences (
  tenant_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('permission','approval_credential','adapter','adapter_credential','draft')),
  entity_id uuid NOT NULL,
  identity_digest text NOT NULL CHECK (identity_digest ~ '^sha256:[0-9a-f]{64}$'),
  not_after timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,kind,entity_id),
  UNIQUE (kind,entity_id)
);
ALTER TABLE kernel.recovery_authority_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE kernel.recovery_authority_fences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON kernel.recovery_authority_fences
  USING (tenant_id=kernel.current_tenant()) WITH CHECK (tenant_id=kernel.current_tenant());
GRANT SELECT ON kernel.recovery_authority_fences TO mk_kernel_api,mk_kernel_worker,mk_kernel_readonly;
CREATE FUNCTION kernel.recovery_authority_tighten_only() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
BEGIN
  IF (to_jsonb(NEW)-'not_after') IS DISTINCT FROM (to_jsonb(OLD)-'not_after')
      OR NEW.not_after > OLD.not_after THEN
    RAISE EXCEPTION 'recovery authority fence cannot be reassigned or relaxed';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER recovery_authority_tighten_only BEFORE UPDATE ON kernel.recovery_authority_fences
  FOR EACH ROW EXECUTE FUNCTION kernel.recovery_authority_tighten_only();
CREATE TRIGGER recovery_authority_no_remove BEFORE DELETE OR TRUNCATE ON kernel.recovery_authority_fences
  FOR EACH STATEMENT EXECUTE FUNCTION kernel.reject_resolution_mutation();

CREATE FUNCTION kernel.recovery_authority_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
DECLARE cutoff timestamptz; identity uuid; withdrawn boolean; target_kind text;
BEGIN
  CASE TG_TABLE_NAME
    WHEN 'contact_permissions' THEN target_kind:='permission'; identity:=NEW.permission_id;
    WHEN 'approval_credentials' THEN target_kind:='approval_credential'; identity:=NEW.credential_row_id;
    WHEN 'adapter_registrations' THEN target_kind:='adapter'; identity:=NEW.adapter_id;
    WHEN 'adapter_credentials' THEN target_kind:='adapter_credential'; identity:=NEW.credential_id;
    ELSE RAISE EXCEPTION 'unknown recovery authority target';
  END CASE;
  SELECT not_after INTO cutoff FROM kernel.recovery_authority_fences
    WHERE tenant_id=NEW.tenant_id AND kind=target_kind AND entity_id=identity;
  IF cutoff IS NULL THEN RETURN NEW; END IF;
  IF TG_OP='INSERT' THEN RAISE EXCEPTION 'withdrawn recovery identity cannot be reused'; END IF;
  CASE target_kind
    WHEN 'permission' THEN withdrawn:=NEW.status='revoked' AND NEW.revoked_at<=cutoff;
    WHEN 'approval_credential' THEN withdrawn:=NEW.revoked_at<=cutoff;
    WHEN 'adapter' THEN withdrawn:=NEW.revoked_at<=cutoff;
    WHEN 'adapter_credential' THEN withdrawn:=LEAST(NEW.revoked_at,NEW.not_after)<=cutoff;
  END CASE;
  IF withdrawn IS DISTINCT FROM true THEN RAISE EXCEPTION 'withdrawn recovery authority cannot be reopened'; END IF;
  RETURN NEW;
END $$;
DO $$ DECLARE target text; BEGIN
  FOREACH target IN ARRAY ARRAY['contact_permissions','approval_credentials','adapter_registrations','adapter_credentials'] LOOP
    EXECUTE format('CREATE TRIGGER recovery_authority_guard BEFORE INSERT OR UPDATE ON kernel.%I FOR EACH ROW EXECUTE FUNCTION kernel.recovery_authority_guard()',target);
  END LOOP;
END $$;
