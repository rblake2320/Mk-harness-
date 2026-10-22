-- Restore only an external cleanup obligation, never a business/account row.
CREATE TABLE IF NOT EXISTS mk_app.billing_erasure_bindings (
    id varchar(32) PRIMARY KEY,
    request_id varchar(32) NOT NULL UNIQUE REFERENCES mk_app.erasure_requests(id),
    tenant_id varchar(32) NOT NULL,
    user_id varchar(32) NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    stripe_customer_id varchar(64) UNIQUE
);
CREATE INDEX IF NOT EXISTS ix_billing_erasure_bindings_tenant_id ON mk_app.billing_erasure_bindings(tenant_id);
ALTER TABLE mk_app.billing_erasure_bindings ADD CONSTRAINT billing_restore_identity_shape
    CHECK (id ~ '^[0-9a-f]{32}$' AND user_id ~ '^[0-9a-f]{32}$' AND tenant_id ~ '^[0-9a-f]{32}$');
ALTER TABLE mk_app.billing_erasure_bindings ADD CONSTRAINT billing_restore_customer_shape
    CHECK (stripe_customer_id IS NULL OR stripe_customer_id ~ '^cus_[A-Za-z0-9]{1,60}$');
CREATE FUNCTION mk_app.guard_billing_restore_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mk_app AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'BILLING_RESTORE_BINDING_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' AND ((to_jsonb(NEW) - 'stripe_customer_id') <> (to_jsonb(OLD) - 'stripe_customer_id')
        OR (OLD.stripe_customer_id IS NOT NULL AND NEW.stripe_customer_id IS DISTINCT FROM OLD.stripe_customer_id)) THEN
        RAISE EXCEPTION 'BILLING_RESTORE_BINDING_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mk_app.erasure_requests WHERE id=NEW.request_id
        AND tenant_id=NEW.tenant_id AND subject_kind='account' AND subject_id=NEW.user_id
        AND requested_by=NEW.user_id AND NEW.created_at <= requested_at) THEN
        RAISE EXCEPTION 'BILLING_RESTORE_REQUEST_MISMATCH' USING ERRCODE='23514';
    END IF;
    IF EXISTS (SELECT 1 FROM mk_app.billing_provisions WHERE (id=NEW.id OR user_id=NEW.user_id)
        AND (id<>NEW.id OR user_id<>NEW.user_id OR tenant_id<>NEW.tenant_id OR created_at<>NEW.created_at
          OR (stripe_customer_id IS NOT NULL AND NEW.stripe_customer_id IS NOT NULL AND stripe_customer_id<>NEW.stripe_customer_id))) THEN
        RAISE EXCEPTION 'BILLING_RESTORE_PROVISION_MISMATCH' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION mk_app.guard_billing_restore_binding() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mk_app.guard_billing_restore_binding() TO mk_app_runtime;
CREATE TRIGGER billing_restore_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON mk_app.billing_erasure_bindings
FOR EACH ROW EXECUTE FUNCTION mk_app.guard_billing_restore_binding();
