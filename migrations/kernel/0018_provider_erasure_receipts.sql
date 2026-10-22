-- A provider DELETE/readback proves active absence, not backup expiration.
ALTER TABLE kernel.privacy_provider_deletions
  ADD COLUMN backup_not_before timestamptz,
  ADD COLUMN backup_confirmed_at timestamptz,
  ADD COLUMN backup_receipt_digest text,
  ADD CONSTRAINT privacy_provider_active_receipt CHECK (
    (confirmed_at IS NULL AND receipt_digest IS NULL AND backup_not_before IS NULL)
    OR (confirmed_at IS NOT NULL AND receipt_digest IS NOT NULL AND backup_not_before IS NOT NULL AND receipt_digest ~ '^sha256:[a-f0-9]{64}$'
        AND backup_not_before >= confirmed_at + interval '30 days')),
  ADD CONSTRAINT privacy_provider_backup_receipt CHECK (
    (backup_confirmed_at IS NULL AND backup_receipt_digest IS NULL)
    OR (backup_confirmed_at IS NOT NULL AND confirmed_at IS NOT NULL AND backup_not_before IS NOT NULL
        AND backup_receipt_digest IS NOT NULL AND backup_confirmed_at >= backup_not_before
        AND backup_receipt_digest ~ '^sha256:[a-f0-9]{64}$'));

CREATE FUNCTION kernel.privacy_provider_receipt_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'privacy provider obligation is immutable' USING ERRCODE='23514';
  END IF;
  IF (NEW.tenant_id,NEW.deletion_id,NEW.request_id,NEW.sender_identity_id,NEW.provider,
      NEW.provider_message_id,NEW.created_at) IS DISTINCT FROM
     (OLD.tenant_id,OLD.deletion_id,OLD.request_id,OLD.sender_identity_id,OLD.provider,
      OLD.provider_message_id,OLD.created_at)
    OR NEW.attempts < OLD.attempts
    OR (OLD.confirmed_at IS NOT NULL AND
       (NEW.confirmed_at,NEW.receipt_digest,NEW.backup_not_before) IS DISTINCT FROM
       (OLD.confirmed_at,OLD.receipt_digest,OLD.backup_not_before))
    OR (OLD.backup_confirmed_at IS NOT NULL AND
       (NEW.backup_confirmed_at,NEW.backup_receipt_digest) IS DISTINCT FROM
       (OLD.backup_confirmed_at,OLD.backup_receipt_digest)) THEN
    RAISE EXCEPTION 'privacy provider identity or receipt regression' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER privacy_provider_receipt_guard BEFORE UPDATE OR DELETE
ON kernel.privacy_provider_deletions FOR EACH ROW EXECUTE FUNCTION kernel.privacy_provider_receipt_guard();
REVOKE ALL ON FUNCTION kernel.privacy_provider_receipt_guard() FROM PUBLIC;

-- Intake may append obligations, never assert a cleanup outcome. Workers cannot
-- rewrite targets or certify backups; that requires separately retained proof.
REVOKE UPDATE ON kernel.privacy_provider_deletions FROM mk_kernel_api,mk_kernel_worker;
GRANT UPDATE (attempts,next_attempt_at,lease_id,last_error,confirmed_at,receipt_digest,backup_not_before)
ON kernel.privacy_provider_deletions TO mk_kernel_worker;
CREATE INDEX privacy_provider_due ON kernel.privacy_provider_deletions(tenant_id,next_attempt_at,deletion_id)
WHERE confirmed_at IS NULL;
