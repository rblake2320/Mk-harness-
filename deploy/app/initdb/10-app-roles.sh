#!/bin/sh
# Application database identities (contract S3: separate runtime DB identities;
# no application owner/superuser connection at runtime). Runs once, on first
# start of the `db` volume, as the bootstrap superuser (docker-entrypoint-initdb.d).
#
#   $APP_DB_OWNER_ROLE   (mk_app_owner) owns the schema; used ONLY by the one-shot
#                        `api-migrate` job (python -m app.tools.migrate)
#   $APP_DB_RUNTIME_ROLE (mk_app)       the API's runtime login: DML on application
#                        tables, nothing else (no DDL, no roles, no RLS bypass)
set -eu
: "${APP_DB_OWNER_PASSWORD:?set APP_DB_OWNER_PASSWORD}"
: "${APP_DB_RUNTIME_PASSWORD:?set APP_DB_RUNTIME_PASSWORD}"
OWNER="${APP_DB_OWNER_ROLE:-mk_app_owner}"
RUNTIME="${APP_DB_RUNTIME_ROLE:-mk_app}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner="$OWNER" -v runtime="$RUNTIME" -v db="$POSTGRES_DB" \
  -v owner_pw="$APP_DB_OWNER_PASSWORD" -v runtime_pw="$APP_DB_RUNTIME_PASSWORD" <<'SQL'
CREATE ROLE :"owner" LOGIN PASSWORD :'owner_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE :"runtime" LOGIN PASSWORD :'runtime_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 100;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON DATABASE :"db" FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO :"owner";
GRANT USAGE ON SCHEMA public TO :"runtime";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"runtime";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO :"runtime";
SQL
