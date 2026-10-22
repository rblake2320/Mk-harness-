-- Preserve creation intent across erasure, crashes and ambiguous HTTP outcomes.
CREATE TABLE IF NOT EXISTS mk_app.billing_provisions (
    id varchar(32) PRIMARY KEY,
    tenant_id varchar(32) NOT NULL REFERENCES mk_app.tenants(id),
    user_id varchar(32) NOT NULL REFERENCES mk_app.users(id),
    created_at timestamptz NOT NULL,
    stripe_customer_id varchar(64) UNIQUE
);
-- Add checks even for an explicitly adopted pre-migration ORM table.
ALTER TABLE mk_app.billing_provisions ADD CONSTRAINT billing_provision_id_shape CHECK (id ~ '^[0-9a-f]{32}$');
ALTER TABLE mk_app.billing_provisions ADD CONSTRAINT billing_provision_customer_shape
    CHECK (stripe_customer_id IS NULL OR stripe_customer_id ~ '^cus_[A-Za-z0-9]{1,60}$');
CREATE INDEX IF NOT EXISTS ix_billing_provisions_tenant_id ON mk_app.billing_provisions(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_billing_provisions_user_id ON mk_app.billing_provisions(user_id);
CREATE FUNCTION mk_app.guard_billing_provision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mk_app AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'BILLING_PROVISION_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' THEN
        IF (to_jsonb(NEW) - 'stripe_customer_id') <> (to_jsonb(OLD) - 'stripe_customer_id')
           OR (OLD.stripe_customer_id IS NOT NULL AND NEW.stripe_customer_id IS DISTINCT FROM OLD.stripe_customer_id) THEN
            RAISE EXCEPTION 'BILLING_PROVISION_IMMUTABLE' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'PRIVACY_WRITE_REQUIRES_READ_COMMITTED' USING ERRCODE='23514';
    END IF;
    PERFORM id FROM mk_app.users WHERE id=NEW.user_id AND tenant_id=NEW.tenant_id AND is_active FOR SHARE;
    IF NOT FOUND OR EXISTS (SELECT 1 FROM mk_app.erasure_requests
        WHERE tenant_id=NEW.tenant_id AND subject_kind='account' AND subject_id=NEW.user_id) THEN
        RAISE EXCEPTION 'PRIVACY_BILLING_FROZEN' USING ERRCODE='23514';
    END IF;
    -- New intents cannot claim an external outcome before any provider call.
    IF NEW.stripe_customer_id IS NOT NULL THEN
        RAISE EXCEPTION 'BILLING_PROVISION_UNBOUND_INSERT' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION mk_app.guard_billing_provision() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mk_app.guard_billing_provision() TO mk_app_runtime;
CREATE TRIGGER billing_provision_guard BEFORE INSERT OR UPDATE OR DELETE ON mk_app.billing_provisions
FOR EACH ROW EXECUTE FUNCTION mk_app.guard_billing_provision();
