-- 0002: shared single-use registry for actor-assertion `jti`s.
--
-- Replaces the process-local ReplayGuard in mk-api for every non-GET request.
-- With several API replicas, a jti consumed by replica A must be refused by
-- replica B; only durable, shared state gives that. Rows are keyed by jti
-- alone (not tenant) so a token can never be replayed across tenants either.
--
-- Not tenant-scoped and therefore NOT under RLS: the check runs before any
-- tenant context exists (it is part of authenticating the request).

CREATE TABLE kernel.assertion_jtis (
  jti         uuid        PRIMARY KEY,
  tenant_id   uuid        NOT NULL,
  subject     uuid        NOT NULL,
  seen_at     timestamptz NOT NULL DEFAULT now(),
  -- exp + clock skew; rows past this are garbage for any verifier.
  expires_at  timestamptz NOT NULL
);
CREATE INDEX assertion_jtis_expiry ON kernel.assertion_jtis (expires_at);

-- API records every write's jti; worker housekeeping purges expired rows.
GRANT SELECT, INSERT ON kernel.assertion_jtis TO mk_kernel_api;
GRANT SELECT, DELETE ON kernel.assertion_jtis TO mk_kernel_worker;
GRANT SELECT ON kernel.assertion_jtis TO mk_kernel_readonly;
-- A jti row is evidence of use: never editable, never deletable by the API.
REVOKE UPDATE, DELETE, TRUNCATE ON kernel.assertion_jtis FROM mk_kernel_api, mk_kernel_relay, mk_kernel_readonly;
REVOKE UPDATE, TRUNCATE ON kernel.assertion_jtis FROM mk_kernel_worker;

-- Least-privilege tightening found by the live smoke with per-process
-- logins: only the relay claims/publishes outbox rows. The API and worker
-- enqueue (INSERT) and never update.
REVOKE UPDATE ON kernel.outbox_events FROM mk_kernel_api, mk_kernel_worker;
