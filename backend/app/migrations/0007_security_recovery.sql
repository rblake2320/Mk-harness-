-- Only the controlled operator can attest a new security-recovery generation.
CREATE TABLE IF NOT EXISTS mk_app.security_restore_receipts (
    id varchar(32) PRIMARY KEY,
    ledger_sha256 varchar(64) NOT NULL,
    privacy_sha256 varchar(64) NOT NULL,
    target_binding varchar(64) NOT NULL,
    source_exported_at timestamptz NOT NULL,
    sessions_json text NOT NULL,
    applied_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS mk_app.recovered_session_revocations (
    session_id varchar(32) PRIMARY KEY,
    tenant_id varchar(32) NOT NULL,
    user_id varchar(32) NOT NULL,
    restore_id varchar(32) NOT NULL REFERENCES mk_app.security_restore_receipts(id),
    created_at timestamptz NOT NULL,
    confirmed_at timestamptz,
    attempts integer NOT NULL,
    last_error varchar(80) NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    lease_id varchar(32)
);
CREATE INDEX IF NOT EXISTS ix_recovered_session_revocations_tenant_id ON mk_app.recovered_session_revocations(tenant_id);
CREATE INDEX IF NOT EXISTS ix_recovered_session_revocations_user_id ON mk_app.recovered_session_revocations(user_id);
CREATE INDEX IF NOT EXISTS ix_recovered_session_revocations_confirmed_at ON mk_app.recovered_session_revocations(confirmed_at);
CREATE INDEX IF NOT EXISTS ix_recovered_session_revocations_next_attempt_at ON mk_app.recovered_session_revocations(next_attempt_at);
ALTER TABLE mk_app.security_restore_receipts ADD CONSTRAINT security_restore_identity_shape CHECK (
    id ~ '^[0-9a-f]{32}$' AND ledger_sha256 ~ '^[0-9a-f]{64}$'
    AND privacy_sha256 ~ '^[0-9a-f]{64}$' AND target_binding ~ '^[0-9a-f]{64}$');
ALTER TABLE mk_app.recovered_session_revocations ADD CONSTRAINT recovered_session_identity_shape CHECK (
    session_id ~ '^[0-9a-f]{32}$' AND tenant_id ~ '^[0-9a-f]{32}$' AND user_id ~ '^[0-9a-f]{32}$');
CREATE FUNCTION mk_app.guard_recovered_session_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,mk_app AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'RECOVERY_SESSION_IMMUTABLE' USING ERRCODE='23514'; END IF;
    IF TG_OP='UPDATE' AND (NEW.session_id<>OLD.session_id OR NEW.tenant_id<>OLD.tenant_id
        OR NEW.user_id<>OLD.user_id OR NEW.created_at<>OLD.created_at
        OR (NEW.restore_id<>OLD.restore_id AND NEW.confirmed_at IS NOT NULL)) THEN
        RAISE EXCEPTION 'RECOVERY_SESSION_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    IF EXISTS (SELECT 1 FROM mk_app.auth_sessions WHERE id=NEW.session_id
        AND (tenant_id<>NEW.tenant_id OR user_id<>NEW.user_id)) THEN
        RAISE EXCEPTION 'RECOVERY_SESSION_IDENTITY_CONFLICT' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER recovered_session_identity BEFORE INSERT OR UPDATE OR DELETE ON mk_app.recovered_session_revocations
    FOR EACH ROW EXECUTE FUNCTION mk_app.guard_recovered_session_identity();
CREATE FUNCTION mk_app.guard_restored_session_authority() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,mk_app AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM mk_app.recovered_session_revocations WHERE session_id=NEW.id
        AND (tenant_id<>NEW.tenant_id OR user_id<>NEW.user_id OR NEW.revoked_at IS NULL)) THEN
        RAISE EXCEPTION 'RECOVERY_SESSION_REVOKED' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER restored_session_authority BEFORE INSERT OR UPDATE ON mk_app.auth_sessions
    FOR EACH ROW EXECUTE FUNCTION mk_app.guard_restored_session_authority();
REVOKE ALL ON FUNCTION mk_app.guard_recovered_session_identity(),mk_app.guard_restored_session_authority() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mk_app.guard_recovered_session_identity(),mk_app.guard_restored_session_authority() TO mk_app_runtime;
CREATE FUNCTION mk_app.reject_security_recovery_removal() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,mk_app AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY_RECOVERY_IMMUTABLE' USING ERRCODE='23514';
END $$;
CREATE TRIGGER security_restore_immutable BEFORE UPDATE OR DELETE ON mk_app.security_restore_receipts
    FOR EACH ROW EXECUTE FUNCTION mk_app.reject_security_recovery_removal();
CREATE TRIGGER security_restore_no_truncate BEFORE TRUNCATE ON mk_app.security_restore_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION mk_app.reject_security_recovery_removal();
CREATE TRIGGER recovered_session_no_truncate BEFORE TRUNCATE ON mk_app.recovered_session_revocations
    FOR EACH STATEMENT EXECUTE FUNCTION mk_app.reject_security_recovery_removal();
REVOKE ALL ON FUNCTION mk_app.reject_security_recovery_removal() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mk_app.reject_security_recovery_removal() TO mk_app_runtime;
