CREATE TABLE IF NOT EXISTS mk_app.erasure_requests (
    id varchar(32) PRIMARY KEY,
    tenant_id varchar(32) NOT NULL,
    requested_by varchar(32) NOT NULL,
    subject_kind varchar(16) NOT NULL CHECK (subject_kind IN ('account','customer')),
    subject_id varchar(32) NOT NULL,
    requested_at timestamptz NOT NULL,
    due_at timestamptz NOT NULL,
    backup_expires_at timestamptz NOT NULL,
    CONSTRAINT uq_erasure_subject UNIQUE (tenant_id, subject_kind, subject_id)
);
CREATE INDEX IF NOT EXISTS erasure_requests_tenant_id ON mk_app.erasure_requests(tenant_id);
CREATE TABLE IF NOT EXISTS mk_app.erasure_tasks (
    id varchar(32) PRIMARY KEY,
    request_id varchar(32) NOT NULL REFERENCES mk_app.erasure_requests(id),
    tenant_id varchar(32) NOT NULL,
    kind varchar(32) NOT NULL,
    target_id varchar(80) NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('pending','confirmed','blocked')),
    receipt_json text NOT NULL,
    attempts integer NOT NULL,
    last_error varchar(80) NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    lease_id varchar(32),
    confirmed_at timestamptz,
    CONSTRAINT uq_erasure_task UNIQUE (request_id, kind, target_id)
);
CREATE INDEX IF NOT EXISTS erasure_tasks_request_id ON mk_app.erasure_tasks(request_id);
CREATE INDEX IF NOT EXISTS erasure_tasks_tenant_id ON mk_app.erasure_tasks(tenant_id);
CREATE TABLE IF NOT EXISTS mk_app.retained_consents (
    id varchar(32) PRIMARY KEY,
    tenant_id varchar(32) NOT NULL,
    request_id varchar(32) NOT NULL REFERENCES mk_app.erasure_requests(id),
    source_kind varchar(20) NOT NULL,
    source_id varchar(32) NOT NULL,
    proof_json text NOT NULL,
    retain_until timestamptz NOT NULL,
    CONSTRAINT uq_retained_consent UNIQUE (tenant_id, source_kind, source_id)
);
CREATE INDEX IF NOT EXISTS retained_consents_tenant_id ON mk_app.retained_consents(tenant_id);
CREATE INDEX IF NOT EXISTS retained_consents_request_id ON mk_app.retained_consents(request_id);

-- Account erasure and in-flight personal-data writes serialize on the user.
-- Durable revocation delivery and append-only evidence deliberately remain writable.
CREATE FUNCTION mk_app.guard_erased_account() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mk_app AS $$
DECLARE
    actor_id varchar(32);
    tenant varchar(32);
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'PRIVACY_WRITE_REQUIRES_READ_COMMITTED' USING ERRCODE='23514';
    END IF;
    IF TG_TABLE_NAME = 'messages' THEN
        SELECT user_id, tenant_id INTO actor_id, tenant FROM mk_app.conversations WHERE id=NEW.conversation_id;
    ELSIF TG_TABLE_NAME = 'import_rows' THEN
        SELECT user_id, tenant_id INTO actor_id, tenant FROM mk_app.import_jobs WHERE id=NEW.job_id;
    ELSE
        actor_id := NEW.user_id;
        tenant := NEW.tenant_id;
    END IF;
    IF actor_id IS NULL THEN
        IF TG_TABLE_NAME = 'provider_keys' THEN
            PERFORM id FROM mk_app.tenants WHERE id=tenant FOR SHARE;
            IF NOT EXISTS (SELECT 1 FROM mk_app.users WHERE tenant_id=tenant AND is_active) THEN
                RAISE EXCEPTION 'PRIVACY_SUBJECT_ERASED' USING ERRCODE='23514';
            END IF;
        END IF;
        RETURN NEW;
    END IF;
    PERFORM id FROM mk_app.users WHERE id=actor_id AND tenant_id=tenant FOR SHARE;
    IF EXISTS (SELECT 1 FROM mk_app.erasure_requests
               WHERE tenant_id=tenant AND subject_kind='account' AND subject_id=actor_id) THEN
        -- A revoked session's delivery metadata must remain available.
        IF TG_TABLE_NAME = 'auth_sessions' AND TG_OP = 'UPDATE'
           AND to_jsonb(NEW)->>'revoked_at' IS NOT NULL THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'PRIVACY_SUBJECT_ERASED' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE FUNCTION mk_app.guard_erased_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mk_app AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM mk_app.erasure_requests
               WHERE tenant_id=NEW.tenant_id AND subject_kind='account' AND subject_id=NEW.id)
       AND (NEW.is_active OR NEW.email <> 'deleted_' || NEW.id || '@deleted'
            OR NEW.password_hash <> '' OR NEW.display_name <> '' OR NEW.referral_code IS NOT NULL
            OR NEW.referred_by IS NOT NULL) THEN
        RAISE EXCEPTION 'PRIVACY_SUBJECT_ERASED' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION mk_app.guard_erased_identity() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mk_app.guard_erased_identity() TO mk_app_runtime;
CREATE TRIGGER privacy_identity_guard BEFORE INSERT OR UPDATE ON mk_app.users
FOR EACH ROW EXECUTE FUNCTION mk_app.guard_erased_identity();
REVOKE ALL ON FUNCTION mk_app.guard_erased_account() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mk_app.guard_erased_account() TO mk_app_runtime;
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['provider_keys','auth_factors','auth_recovery_codes',
        'auth_sessions','conversations','messages','customers','skin_analyses',
        'consultant_profiles','import_jobs','import_rows','sender_identities']
    LOOP
        EXECUTE format('CREATE TRIGGER privacy_account_guard BEFORE INSERT OR UPDATE ON mk_app.%I FOR EACH ROW EXECUTE FUNCTION mk_app.guard_erased_account()', table_name);
    END LOOP;
END;
$$;
