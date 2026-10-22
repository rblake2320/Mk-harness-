# Application database ownership and migration

The API uses `mk_app_login` -> `mk_app_runtime`, never the database owner. A
separate `mk_app_migrator` login can explicitly assume the NOLOGIN
`mk_app_owner` role. Tables live in `mk_app`; the API gets table-specific DML,
append-only audit access, and read-only migration history. It has no kernel
table privileges. PostgreSQL startup checks both the session and current role,
reachable role memberships/attributes, DDL/ownership and excess grants, schema
constraints, and the exact shipped migration checksums. It never creates tables.
SQLite auto-creation remains a local-development/test path only.

## First deployment or existing-volume upgrade

1. Keep dispatch disabled and stop app writers. Take and restore-test a backup.
   Record database identity, existing public application tables and row counts.
   Use the approved image digest, not a moving tag.
2. Provision distinct random passwords (at least 16 characters) for runtime and
   migration in their separate secret stores. Do not pass passwords in command
   arguments or enable shell tracing. Do not give bootstrap/owner or migration
   credentials to the API task.
3. In a one-shot operator process, set `MK_APP_BOOTSTRAP_URL` to the owner DSN,
   `MK_APP_RUNTIME_PASSWORD` and `MK_APP_MIGRATION_PASSWORD`, then run
   `python -m app.migrate bootstrap`. Alternatively use `DB_HOST`, `DB_NAME`,
   `DB_SSLMODE`, `DB_SSLROOTCERT`, `MK_APP_BOOTSTRAP_USER` and
   `MK_APP_BOOTSTRAP_PASSWORD` so special password characters are not URL-parsed.
   Existing application tables in `public` cause a refusal. After verifying
   backup and counts, explicitly add `--adopt-public`: only exact known
   application tables move, with data preserved. Duplicates in both schemas or
   unsafe existing roles fail closed. No unrelated/kernel table is adopted.
4. Discard operator credentials from the execution environment. Set the separate
   `MK_APP_MIGRATION_URL` and run `python -m app.migrate upgrade`, or supply
   `DB_HOST`, `DB_NAME`, TLS settings and `MK_APP_MIGRATION_PASSWORD`. This login
   must actually be `mk_app_migrator`; an owner disguised with SET ROLE is refused.
   Migrations and checksum history commit together under a transaction/advisory
   lock. An incompatible existing schema fails, requiring an explicit migration;
   do not edit an applied SQL file or bypass the checksum check.
5. Start the API with only `DB_HOST`, `DB_USER=mk_app_login`, `DB_PASSWORD`,
   `DB_NAME=mkharness`, `DB_SSLMODE=verify-full` and
   `DB_SSLROOTCERT=/etc/mk/rds-global-bundle.pem`. `DATABASE_URL` is an alternative,
   not an additional setting. Partial/ambiguous fields fail instead of falling
   back to SQLite. Remote connections require verified TLS and an explicit CA.
6. Verify `/api/health/ready`, actual `session_user`/`current_user`, the denial
   tests, retained row counts, MFA and a scoped customer transaction. Preserve
   logs and image digest. Then use the normal preflight/enable gate.

Bootstrap revokes PUBLIC database CREATE/TEMP and public-schema CREATE within
the target database; review other applications before using a shared database.
It does not reset data, enable dispatch, or provision any cloud resources.
Audit deletion and retention are separate governed processes, not API grants.
After restoring into a fresh database, reapply bootstrap and validate privileges
before starting runtime: `pg_dump`/`pg_restore` without database creation does not
copy the source database's PUBLIC TEMP/CREATE revocations. The app's startup gate
rejects that drift; do not weaken it to make a restore start.

## Compose / ECS

Set `POSTGRES_PASSWORD`, distinct `APP_DATABASE_PASSWORD` and
`APP_MIGRATION_PASSWORD`, and reviewed `RDS_CA_BUNDLE_SHA256` alongside ordinary
app secrets. Run `docker compose up -d db`, then
`docker compose --profile operator run --rm app-bootstrap` (explicit
`python -m app.migrate bootstrap --adopt-public` override for an existing volume).
Ordinary `docker compose up --build` runs the migration service before the API.
The API never receives the owner or migration password. Compose uses an isolated
development network without TLS; deployed RDS uses verify-full.

The app image now includes the checksum-pinned official RDS CA, runs as numeric
UID 65532, and includes its actual Python health probe. Deployment image builds
require the reviewed `RDS_CA_BUNDLE_SHA256` repository variable for both images;
CI records the fetched bundle digest separately. The ECS module declares an
explicit `app_migrator` one-shot task with only the migration credential. Run
and verify that task before app rollout. The existing deployment pipeline's
remote smoke/deployment gates still require their separate O8 implementation
and authorized staging configuration; defining a task does not run it.

## Verification

`python -m pytest tools/verification/test_app_database.py` requires
`MK_APP_TEST_ADMIN_URL` for a dedicated disposable loopback PostgreSQL cluster
with database `mk_app_test_admin`. It creates and removes exact UUID databases.
It tests actual SQL denials, privilege/ledger/schema drift, explicit data-preserving
adoption, and real MFA/customer transactions. CI runs this as a mandatory job.

`tools/verification/app_database_image.py` runs the built image as non-root with
a read-only filesystem and dropped capabilities, separate bootstrap/migration
processes, real HTTP MFA/export checks and restart persistence. It accepts only
the task-labelled disposable test container and removes its own resources.
Neither script constitutes independent staging qualification.

Application recovery must also use the separately encrypted, independently
pinned account-security archive and generation-bound kernel revocation receipts
in [application security recovery](application-security-recovery.md). A successful
pg_restore or deletion-only replay cannot authorize reopening ingress.

Reference: PostgreSQL [session and privilege inspection](https://www.postgresql.org/docs/16/functions-info.html)
and SQLAlchemy [structured connection URLs](https://docs.sqlalchemy.org/en/20/core/engines.html#creating-urls-programmatically).
