-- Per-process LOGIN identities for the kernel. Run once per database, after
-- migrations (which create the NOLOGIN privilege roles and all grants), as a
-- user allowed to CREATE ROLE. Idempotent.
--
--   psql "$ADMIN_URL" -v api_pw="$MK_DB_API_PASSWORD" -v worker_pw="$MK_DB_WORKER_PASSWORD" \
--        -v relay_pw="$MK_DB_RELAY_PASSWORD" -v readonly_pw="$MK_DB_READONLY_PASSWORD" \
--        -f deploy/kernel/roles.sql
--
-- Each process then connects as its own login, e.g.
--   MK_DATABASE_URL=postgres://mk_api_login:<pw>@db/mkharness   (kernel-api)
-- A login inherits exactly one privilege role and owns nothing, so RLS is
-- enforced (never bypassed) and the API process cannot claim outbox rows,
-- the relay cannot read approvals, and the verifier can only read.
CREATE OR REPLACE FUNCTION pg_temp.mk_ensure_login(login text, privilege text, pw text)
RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE extra text;
BEGIN
  IF pw IS NULL OR length(pw) < 16 THEN
    RAISE EXCEPTION 'password for % must be at least 16 characters', login;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = login) THEN
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS', login, pw);
  ELSE
    EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS', login, pw);
  END IF;
  EXECUTE format('GRANT %I TO %I', privilege, login);
  -- A login must hold exactly one privilege role.
  SELECT string_agg(r.rolname, ',') INTO extra
    FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
   WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = login) AND r.rolname <> privilege;
  IF extra IS NOT NULL THEN
    RAISE EXCEPTION '% holds unexpected roles: %', login, extra;
  END IF;
END $fn$;

SELECT pg_temp.mk_ensure_login('mk_api_login',      'mk_kernel_api',      :'api_pw');
SELECT pg_temp.mk_ensure_login('mk_worker_login',   'mk_kernel_worker',   :'worker_pw');
SELECT pg_temp.mk_ensure_login('mk_relay_login',    'mk_kernel_relay',    :'relay_pw');
SELECT pg_temp.mk_ensure_login('mk_readonly_login', 'mk_kernel_readonly', :'readonly_pw');
