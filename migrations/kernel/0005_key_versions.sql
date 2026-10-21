-- 0005: versioned envelope encryption (contract row S6).
--
-- Data encryption keys (DEKs) are stored WRAPPED by a key-encryption key that
-- never enters the database (environment / secrets manager / KMS). Processes
-- load every non-retired version at start and seal with the current one.
-- Rotation = add version → re-encrypt rows → retire old version. Version 0
-- is the legacy single master key and never has a row here.
CREATE TABLE kernel.key_versions (
  version      integer     PRIMARY KEY CHECK (version > 0),
  kek_id       text        NOT NULL,
  wrapped_dek  bytea       NOT NULL,
  status       text        NOT NULL CHECK (status IN ('active','retiring','retired')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  created_by   text        NOT NULL,
  retired_at   timestamptz,
  note         text        NOT NULL DEFAULT ''
);
-- Exactly one active version at a time.
CREATE UNIQUE INDEX key_versions_one_active ON kernel.key_versions ((status)) WHERE status = 'active';

-- Not tenant data: readable by every runtime identity (they must unwrap to
-- operate), writable only by the operator tooling identity (migrations/keyctl
-- run as the owner). Runtime processes can never mint or retire keys.
GRANT SELECT ON kernel.key_versions TO mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON kernel.key_versions FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
