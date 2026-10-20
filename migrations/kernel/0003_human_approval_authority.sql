-- 0003: separated human-approval authority (contract WP06, rows H6, H9).
--
-- The proposal service (FastAPI) holds the actor-assertion key and can present
-- any principal. From this migration on, an *approval* additionally requires a
-- WebAuthn assertion that the kernel verifies against a credential the human
-- registered through the kernel, over a challenge the kernel derived from the
-- exact action digest. FastAPI relays bytes; it cannot produce them.

-- Registered passkeys / security keys per human user.
CREATE TABLE kernel.approval_credentials (
  credential_row_id uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id         uuid        NOT NULL,
  user_id           uuid        NOT NULL,
  credential_id     bytea       NOT NULL,
  alg               text        NOT NULL CHECK (alg IN ('ES256','EdDSA','RS256')),
  public_key        bytea       NOT NULL,
  sign_count        bigint      NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  aaguid            bytea       NOT NULL,
  attestation_fmt   text        NOT NULL,
  label             text        NOT NULL DEFAULT '',
  created_at        timestamptz NOT NULL DEFAULT now(),
  last_used_at      timestamptz,
  revoked_at        timestamptz,
  revoked_by        uuid,
  PRIMARY KEY (tenant_id, credential_row_id),
  UNIQUE (credential_row_id),
  -- A credential id is globally unique by construction; refusing a duplicate
  -- across tenants also refuses a cloned registration.
  UNIQUE (credential_id)
);
CREATE INDEX approval_credentials_user ON kernel.approval_credentials (tenant_id, user_id) WHERE revoked_at IS NULL;

-- Kernel-issued challenges: registration (no action) or approval (bound to an
-- action id and digest). Single-use; short-lived.
CREATE TABLE kernel.approval_challenges (
  challenge_id   uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id      uuid        NOT NULL,
  user_id        uuid        NOT NULL,
  -- register: new credential; approve: bound to an action; operator: bound to an
  -- operator operation digest (e.g. re-enabling the global kill switch).
  kind           text        NOT NULL CHECK (kind IN ('register','approve','operator')),
  action_id      uuid,
  action_digest  text        CHECK (action_digest IS NULL OR action_digest ~ '^sha256:[0-9a-f]{64}$'),
  nonce          bytea       NOT NULL,
  challenge      bytea       NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz,
  PRIMARY KEY (tenant_id, challenge_id),
  UNIQUE (challenge_id),
  UNIQUE (challenge),
  CHECK ((kind = 'approve') = (action_id IS NOT NULL AND action_digest IS NOT NULL)),
  CHECK ((kind = 'operator') = (action_id IS NULL AND action_digest IS NOT NULL)),
  CHECK (expires_at > created_at)
);
CREATE INDEX approval_challenges_expiry ON kernel.approval_challenges (expires_at);

-- Revocations (row H9): a revoked session or user can neither approve nor have
-- a prior approval dispatched. Checked at assertion time and at dispatch.
CREATE TABLE kernel.revocations (
  revocation_id uuid        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id     uuid        NOT NULL,
  kind          text        NOT NULL CHECK (kind IN ('session','user')),
  session_id    text,
  user_id       uuid,
  reason        text        NOT NULL DEFAULT '',
  revoked_by    uuid        NOT NULL,
  revoked_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, revocation_id),
  UNIQUE (revocation_id),
  -- A session belongs to exactly one user; session revocations carry both so a
  -- session id can never be matched across users.
  CHECK (user_id IS NOT NULL AND ((kind = 'session' AND session_id IS NOT NULL) OR (kind = 'user' AND session_id IS NULL)))
);
CREATE INDEX revocations_session ON kernel.revocations (tenant_id, user_id, session_id) WHERE kind = 'session';
CREATE INDEX revocations_user ON kernel.revocations (tenant_id, user_id) WHERE kind = 'user';

-- An approval records which human credential proved it. NULL only when the
-- kernel runs with MK_ALLOW_UNBOUND_APPROVAL=1 (development/test), and the
-- approval row says so explicitly.
ALTER TABLE kernel.approvals
  ADD COLUMN approval_credential_row_id uuid,
  ADD COLUMN human_binding text NOT NULL DEFAULT 'unbound' CHECK (human_binding IN ('webauthn','unbound'));

-- ---------------------------------------------------------------------------
-- RLS on the new tenant-scoped tables (same shape as 0001).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['approval_credentials','approval_challenges','revocations'] LOOP
    EXECUTE format('ALTER TABLE kernel.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE kernel.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON kernel.%I USING (tenant_id = kernel.current_tenant()) WITH CHECK (tenant_id = kernel.current_tenant())', t);
  END LOOP;
END $$;

-- Revocation is checked while authenticating the request, before any tenant
-- context exists: the API gets cross-tenant read on revocations only.
CREATE POLICY api_revocation_check ON kernel.revocations FOR SELECT TO mk_kernel_api USING (true);
CREATE POLICY worker_revocation_check ON kernel.revocations FOR SELECT TO mk_kernel_worker USING (true);

GRANT SELECT, INSERT, UPDATE ON kernel.approval_credentials TO mk_kernel_api;
GRANT SELECT, INSERT, UPDATE ON kernel.approval_challenges TO mk_kernel_api;
GRANT SELECT, INSERT ON kernel.revocations TO mk_kernel_api;
GRANT SELECT ON kernel.approval_credentials, kernel.revocations TO mk_kernel_worker;
GRANT SELECT, DELETE ON kernel.approval_challenges TO mk_kernel_worker;   -- expiry purge
GRANT SELECT ON kernel.approval_credentials, kernel.approval_challenges, kernel.revocations TO mk_kernel_readonly;
-- Revocations and credentials are evidence: no deletes by anyone but an operator migration.
REVOKE DELETE, TRUNCATE ON kernel.approval_credentials, kernel.revocations FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
REVOKE UPDATE ON kernel.revocations FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
CREATE POLICY worker_challenge_purge_select ON kernel.approval_challenges
  FOR SELECT TO mk_kernel_worker USING (expires_at < now());
CREATE POLICY worker_challenge_purge ON kernel.approval_challenges
  FOR DELETE TO mk_kernel_worker USING (expires_at < now());
