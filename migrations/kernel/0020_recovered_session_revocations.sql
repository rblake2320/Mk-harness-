-- Recovery ledgers carry a tenant/user-bound digest, not free-form session IDs.
-- Existing live revocation rows remain valid and immutable.
ALTER TABLE kernel.revocations ADD COLUMN session_digest text;
ALTER TABLE kernel.revocations DROP CONSTRAINT revocations_check;
ALTER TABLE kernel.revocations ADD CONSTRAINT revocations_target_shape CHECK (
    user_id IS NOT NULL AND (
        (kind='user' AND session_id IS NULL AND session_digest IS NULL) OR
        (kind='session' AND (
            (session_id IS NOT NULL AND session_digest IS NULL) OR
            (session_id IS NULL AND session_digest IS NOT NULL AND session_digest ~ '^sha256:[0-9a-f]{64}$')
        ))
    )
);
CREATE INDEX revocations_session_digest ON kernel.revocations(tenant_id,user_id,session_digest)
    WHERE kind='session' AND session_digest IS NOT NULL;
