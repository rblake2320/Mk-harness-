# Application database privilege boundary — S3 engineering batch

Source `c88e1c0415610820d2ff7d09ae4a52ecd155d51d`, PR37, 2026-10-22.
Author-run development/container verification. No independent staging release
qualification or row closure is claimed.

## Observed failures and repairs

- Deployment `DB_HOST`/`DB_PASSWORD` were silently ignored and selected SQLite
  (`appdb-initial-red.xml`). The API also accepted a real PostgreSQL owner and
  created tables on startup (`appdb-owner-red.xml`). Configuration now resolves
  structured credentials safely, refuses partial/ambiguous settings, and requires
  verified TLS with an explicit CA for remote PostgreSQL.
- Runtime `mk_app_login` has DML-only access to `mk_app`, append-only audit writes
  and read-only migration history. Startup checks session/current identities,
  reachable memberships/attributes, DDL/ownership, table/column grants,
  security-definer escape paths, required DML, schema and migration checksums.
  Owner credentials cannot be hidden behind SET ROLE. API startup performs no
  PostgreSQL DDL.
- Separate operator bootstrap and `mk_app_migrator` one-shot upgrade support
  explicit, data-preserving adoption of known old public tables. Transactions and
  advisory locks serialize first migration; replay validates checksums. Existing
  drift fails rather than silently changing application contracts. Applied SQL
  has fixed LF bytes; later changes require a new migration.
- Compose and ECS now wire the actual runtime login and separate migration
  secret. The app image contains the checksum-pinned RDS CA and a real Python
  health probe; the old ECS probe named a kernel binary absent from the app image.
  Deployment build settings now supply the required reviewed CA pin for both
  images. No AWS resources were created or modified.

## Source-pin results

- **323 Python regression tests passed**, no skips
  (`appdb-python-c88e1c0.xml`).
- **15 real PostgreSQL acceptance scenarios passed**, no skips
  (`appdb-postgres-c88e1c0.xml`): runtime cannot create/alter/drop/truncate, modify
  audit rows, forge migration history, read kernel data or assume owner/migrator;
  table and column grant drift, role escalation, missing schema, missing FK and
  tampered ledger are refused; explicit adoption retains rows; concurrent first
  migrations produce one history row; real MFA/customer transactions work.
- Shipped image
  `sha256:e28d25760ef32efd31118f7338dbb2c6d2155b5c2fe1ae431f0ecfa866f117a3`
  (`appdb-image-c88e1c0/report.json`): UID 65532, read-only root, all capabilities
  dropped; separate bootstrap/upgrade/idempotent rerun; owner runtime refused;
  password-only customer access 403; verified customer creation 201; export
  before fresh authentication 403 and after 200; shipped health probe exit 0;
  after restart the authenticated customer read returns 200. Database readback
  confirms `mk_app_login`, one retained customer and five audit records. Owned
  image-run containers/network/database were removed, not shared services.
- OpenTofu 1.10.6 module validation and recursive format check passed; Compose
  config validation passed with synthetic local values. These are configuration
  checks, not a cloud deployment (`appdb-infra-validate-v1.log`).
- The preceding MFA/preflight source `93a2842` passed all nine CI checks; live
  run metadata is retained in `appdb-predecessor-*-ci.json`. Current source CI is
  tracked separately and is not independent release qualification.

Intermediate reports are retained as produced. The first migration test caught
an incorrect DDL search path (pg_catalog first), corrected to mk_app first for
the migrator only. One fixture email used a reserved `.test` domain and was
rejected before the intended scenario; the corrected synthetic example.com
fixture passes. The first image build correctly refused a wrong checksum caused
by hashing PowerShell-converted content instead of raw response bytes. Raw-byte
hashing matches the build-verified CA digest
`90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b`.
The first restart probe used Docker's old dynamically published port; the probe
now rediscovers it, and source-pin output confirms the port actually changed.
No failed intermediate run is relabelled as a source-pin success.

See `docs/runbooks/application-database.md` for operator separation, tested
upgrade and repeatable commands. `appdb-security-manifest.json` binds artifacts.
