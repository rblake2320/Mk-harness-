-- Fence obsolete application writers before retiring a sealing key.
CREATE TABLE IF NOT EXISTS application_seal_policy (
  id integer PRIMARY KEY CHECK (id = 1),
  writer_kid varchar(16) NOT NULL CHECK (writer_kid ~ '^[a-z0-9_-]{1,16}$'),
  allow_legacy boolean NOT NULL CHECK (NOT allow_legacy OR writer_kid = 'm0')
);
INSERT INTO application_seal_policy VALUES (1, 'm0', true) ON CONFLICT (id) DO NOTHING;

CREATE FUNCTION mk_app.seal_policy_lock() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  PERFORM pg_advisory_xact_lock(58721493622);
  RETURN NULL; -- statement trigger return value is ignored
END
$fn$;
CREATE TRIGGER seal_policy_lock BEFORE INSERT OR UPDATE OR DELETE ON application_seal_policy
FOR EACH STATEMENT EXECUTE FUNCTION mk_app.seal_policy_lock();

CREATE FUNCTION mk_app.check_seal_write() RETURNS trigger LANGUAGE plpgsql VOLATILE AS $fn$
DECLARE
  field_name text;
  ciphertext text;
  previous text;
  policy mk_app.application_seal_policy%ROWTYPE;
BEGIN
  FOREACH field_name IN ARRAY TG_ARGV LOOP
    ciphertext := to_jsonb(NEW)->>field_name;
    previous := CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD)->>field_name ELSE NULL END;
    IF ciphertext IS NULL OR ciphertext = '' OR ciphertext IS NOT DISTINCT FROM previous THEN
      CONTINUE;
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
      RAISE EXCEPTION 'SEAL_WRITE_REQUIRES_READ_COMMITTED' USING ERRCODE = '23514';
    END IF;
    -- Held through commit. A policy change cannot complete while an old write
    -- is in flight; a waiting writer reads the policy after acquiring the lock.
    PERFORM pg_advisory_xact_lock_shared(58721493622);
    SELECT * INTO STRICT policy FROM mk_app.application_seal_policy WHERE id = 1;
    IF ciphertext LIKE 'mk1:%' THEN
      IF split_part(ciphertext, ':', 2) = policy.writer_kid
         AND ciphertext ~ '^mk1:[a-z0-9_-]{1,16}:[A-Za-z0-9+/]+={0,2}$' THEN
        CONTINUE;
      END IF;
    ELSIF policy.allow_legacy AND ciphertext ~ '^[A-Za-z0-9+/]+={0,2}$' THEN
      CONTINUE;
    END IF;
    RAISE EXCEPTION 'SEAL_WRITER_RETIRED' USING ERRCODE = '23514';
  END LOOP;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION mk_app.seal_policy_lock(), mk_app.check_seal_write() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mk_app.check_seal_write() TO mk_app_runtime;

CREATE TRIGGER seal_write BEFORE INSERT OR UPDATE ON provider_keys
FOR EACH ROW EXECUTE FUNCTION mk_app.check_seal_write('ciphertext');
CREATE TRIGGER seal_write BEFORE INSERT OR UPDATE ON customer_destinations
FOR EACH ROW EXECUTE FUNCTION mk_app.check_seal_write('value_enc');
CREATE TRIGGER seal_write BEFORE INSERT OR UPDATE ON import_rows
FOR EACH ROW EXECUTE FUNCTION mk_app.check_seal_write('phone_enc', 'email_enc');
CREATE TRIGGER seal_write BEFORE INSERT OR UPDATE ON draft_versions
FOR EACH ROW EXECUTE FUNCTION mk_app.check_seal_write('text_enc');
CREATE TRIGGER seal_write BEFORE INSERT OR UPDATE ON exceptions
FOR EACH ROW EXECUTE FUNCTION mk_app.check_seal_write('detail_enc');
CREATE TRIGGER seal_write BEFORE INSERT OR UPDATE ON outcomes
FOR EACH ROW EXECUTE FUNCTION mk_app.check_seal_write('note_enc');
CREATE TRIGGER seal_write BEFORE INSERT OR UPDATE ON auth_factors
FOR EACH ROW EXECUTE FUNCTION mk_app.check_seal_write('secret_enc', 'pending_secret_enc');
