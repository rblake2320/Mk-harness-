-- Run only through `python -m app.migrate bootstrap` with operator credentials.
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mk_app_owner') THEN
    CREATE ROLE mk_app_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mk_app_runtime') THEN
    CREATE ROLE mk_app_runtime NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mk_app_login') THEN
    CREATE ROLE mk_app_login LOGIN INHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mk_app_migrator') THEN
    CREATE ROLE mk_app_migrator LOGIN NOINHERIT;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN
    ('mk_app_owner','mk_app_runtime','mk_app_login','mk_app_migrator')
    AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION 'Unsafe existing application role attributes';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
    JOIN pg_roles parent ON parent.oid=m.roleid
    WHERE member.rolname IN ('mk_app_owner','mk_app_runtime','mk_app_login','mk_app_migrator')
    AND NOT ((member.rolname='mk_app_login' AND parent.rolname='mk_app_runtime')
         OR (member.rolname='mk_app_migrator' AND parent.rolname='mk_app_owner'))) THEN
    RAISE EXCEPTION 'Unexpected application role membership';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE
    (rolname IN ('mk_app_owner','mk_app_runtime') AND rolcanlogin) OR
    (rolname IN ('mk_app_login','mk_app_migrator') AND NOT rolcanlogin)) THEN
    RAISE EXCEPTION 'Unsafe application role login attributes';
  END IF;
END
$roles$;
GRANT mk_app_runtime TO mk_app_login;
GRANT mk_app_owner TO mk_app_migrator;
CREATE SCHEMA IF NOT EXISTS mk_app AUTHORIZATION mk_app_owner;
REVOKE ALL ON SCHEMA mk_app FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA mk_app TO mk_app_runtime;
