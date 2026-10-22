-- A late provider event must not revive or rebind billing after account erasure.
-- Keep terminal cleanup possible, without treating a local mirror as a provider
-- receipt. Erasure tasks remain independently pending until their executor has
-- verified the required external outcome.
CREATE FUNCTION mk_app.guard_erased_billing() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mk_app AS $$
DECLARE
    erased boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'PRIVACY_WRITE_REQUIRES_READ_COMMITTED' USING ERRCODE='23514';
    END IF;
    -- Serialize the check with the erasure transaction's user row lock.
    PERFORM id FROM mk_app.users WHERE id=NEW.user_id AND tenant_id=NEW.tenant_id FOR SHARE;
    erased := EXISTS (SELECT 1 FROM mk_app.erasure_requests
        WHERE tenant_id=NEW.tenant_id AND subject_kind='account' AND subject_id=NEW.user_id);
    IF TG_OP='UPDATE' THEN
        erased := erased OR EXISTS (SELECT 1 FROM mk_app.erasure_requests
            WHERE tenant_id=OLD.tenant_id AND subject_kind='account' AND subject_id=OLD.user_id);
    END IF;
    IF NOT erased THEN
        RETURN NEW;
    END IF;
    IF TG_OP='UPDATE'
       AND NEW.status IN ('deletion_pending','canceled')
       AND (NEW.stripe_customer_id IS NULL OR NEW.stripe_customer_id IS NOT DISTINCT FROM OLD.stripe_customer_id)
       AND (NEW.stripe_subscription_id IS NULL OR NEW.stripe_subscription_id IS NOT DISTINCT FROM OLD.stripe_subscription_id)
       AND (to_jsonb(NEW) - ARRAY['status','updated_at','stripe_customer_id','stripe_subscription_id'])
         = (to_jsonb(OLD) - ARRAY['status','updated_at','stripe_customer_id','stripe_subscription_id']) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'PRIVACY_BILLING_FROZEN' USING ERRCODE='23514';
END;
$$;
REVOKE ALL ON FUNCTION mk_app.guard_erased_billing() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mk_app.guard_erased_billing() TO mk_app_runtime;
CREATE TRIGGER privacy_billing_guard BEFORE INSERT OR UPDATE ON mk_app.subscriptions
FOR EACH ROW EXECUTE FUNCTION mk_app.guard_erased_billing();
