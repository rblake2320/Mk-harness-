-- Durable subject fences survive application deletion and deployment rollback.
CREATE TABLE kernel.privacy_erasure_requests (
  tenant_id uuid NOT NULL,
  request_id uuid NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('contact','account')),
  subject_id uuid NOT NULL,
  requested_at timestamptz NOT NULL,
  content_erased_at timestamptz,
  PRIMARY KEY (tenant_id,request_id),
  UNIQUE (tenant_id,subject_kind,subject_id)
);
CREATE TABLE kernel.privacy_provider_deletions (
  tenant_id uuid NOT NULL,
  deletion_id uuid NOT NULL DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL,
  sender_identity_id uuid NOT NULL,
  provider text NOT NULL,
  provider_message_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  confirmed_at timestamptz,
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_id uuid,
  last_error text,
  receipt_digest text,
  PRIMARY KEY (tenant_id,deletion_id),
  UNIQUE (tenant_id,request_id,provider,provider_message_id),
  FOREIGN KEY (tenant_id,request_id) REFERENCES kernel.privacy_erasure_requests(tenant_id,request_id)
);
ALTER TABLE kernel.actions ADD COLUMN content_erased_at timestamptz;
ALTER TABLE kernel.inbound_events ADD COLUMN content_erased_at timestamptz;
ALTER TABLE kernel.idempotency_records ADD COLUMN key_erased boolean NOT NULL DEFAULT false;
ALTER TABLE kernel.idempotency_records DROP CONSTRAINT idempotency_records_pkey;
ALTER TABLE kernel.idempotency_records ADD PRIMARY KEY (tenant_id,action_kind,idempotency_key,key_erased);
CREATE TABLE kernel.privacy_destination_fences (
  tenant_id uuid NOT NULL,
  request_id uuid NOT NULL,
  channel text NOT NULL,
  destination_hash text NOT NULL,
  destination_fingerprints text[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id,request_id,channel,destination_hash),
  FOREIGN KEY (tenant_id,request_id) REFERENCES kernel.privacy_erasure_requests(tenant_id,request_id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['privacy_erasure_requests','privacy_provider_deletions','privacy_destination_fences'] LOOP
    EXECUTE format('ALTER TABLE kernel.%I ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE kernel.%I FORCE ROW LEVEL SECURITY',t);
    EXECUTE format('CREATE POLICY tenant_isolation ON kernel.%I USING (tenant_id=kernel.current_tenant()) WITH CHECK (tenant_id=kernel.current_tenant())',t);
  END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE ON kernel.privacy_erasure_requests, kernel.privacy_provider_deletions TO mk_kernel_api;
GRANT SELECT,UPDATE ON kernel.privacy_provider_deletions TO mk_kernel_worker;
GRANT SELECT ON kernel.privacy_erasure_requests TO mk_kernel_worker;
GRANT SELECT ON kernel.privacy_erasure_requests,kernel.privacy_provider_deletions TO mk_kernel_readonly;
GRANT SELECT,INSERT ON kernel.privacy_destination_fences TO mk_kernel_api;
GRANT SELECT ON kernel.privacy_destination_fences TO mk_kernel_worker,mk_kernel_readonly;

CREATE FUNCTION kernel.privacy_tenant_lock(tenant uuid, exclusive boolean)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
BEGIN
  IF exclusive THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('privacy-tenant:'||tenant::text,0));
  ELSE
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('privacy-tenant:'||tenant::text,0));
  END IF;
END $$;

CREATE FUNCTION kernel.privacy_subject_lock(tenant uuid, kind text, subject uuid, exclusive boolean)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'privacy requires read committed' USING ERRCODE='23514';
  END IF;
  IF exclusive THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('privacy:'||tenant::text||':'||kind||':'||subject::text,0));
  ELSE
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('privacy:'||tenant::text||':'||kind||':'||subject::text,0));
  END IF;
END $$;

-- Application IDs are compact UUIDs; old callers also used uppercase, braces
-- or URNs. Resolve identity, not textual spelling, without rejecting opaque
-- non-customer resources that the historical action contract also permits.
CREATE FUNCTION kernel.privacy_resource_uuid(resource text) RETURNS uuid
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,kernel AS $$
BEGIN
  RETURN regexp_replace(resource,'^urn:uuid:','','i')::uuid;
EXCEPTION WHEN invalid_text_representation THEN RETURN NULL;
END $$;
CREATE INDEX actions_privacy_contact ON kernel.actions(tenant_id,kernel.privacy_resource_uuid(resource_id))
WHERE resource_type='contact';

CREATE FUNCTION kernel.check_privacy_intake() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
DECLARE contact uuid;
BEGIN
  PERFORM kernel.privacy_tenant_lock(NEW.tenant_id,false);
  -- Same global order as the new binary: account, contact, then draft/control
  -- locks and the action row. Legacy writers cannot bypass a committed fence.
  PERFORM kernel.privacy_subject_lock(NEW.tenant_id,'account',NEW.requested_by,false);
  IF NEW.resource_type='contact' THEN
    -- Older contracts permit opaque resource identifiers; only UUID subjects
    -- can name an application customer, but account/destination guards still apply.
    contact := kernel.privacy_resource_uuid(NEW.resource_id);
    IF contact IS NOT NULL THEN
      PERFORM kernel.privacy_subject_lock(NEW.tenant_id,'contact',contact,false);
    END IF;
  END IF;
  IF EXISTS (SELECT 1 FROM kernel.privacy_erasure_requests WHERE tenant_id=NEW.tenant_id
    AND ((subject_kind='account' AND subject_id=NEW.requested_by)
      OR (subject_kind='contact' AND subject_id=contact)))
    OR EXISTS (SELECT 1 FROM kernel.privacy_destination_fences WHERE tenant_id=NEW.tenant_id
      AND channel=NEW.channel AND (destination_hash=NEW.destination_hash
        OR destination_fingerprints && NEW.destination_fingerprints)) THEN
    RAISE EXCEPTION 'privacy subject erased' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
-- BEFORE triggers run alphabetically: privacy precedes the existing draft fence.
CREATE TRIGGER a_privacy_intake BEFORE INSERT ON kernel.actions
FOR EACH ROW EXECUTE FUNCTION kernel.check_privacy_intake();

CREATE FUNCTION kernel.privacy_tombstone_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'privacy tombstone is permanent' USING ERRCODE='23514';
  END IF;
  IF ROW(NEW.tenant_id,NEW.request_id,NEW.subject_kind,NEW.subject_id,NEW.requested_at)
     IS DISTINCT FROM ROW(OLD.tenant_id,OLD.request_id,OLD.subject_kind,OLD.subject_id,OLD.requested_at)
     OR (OLD.content_erased_at IS NOT NULL AND NEW.content_erased_at IS DISTINCT FROM OLD.content_erased_at) THEN
    RAISE EXCEPTION 'privacy tombstone is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER privacy_tombstone_no_rewrite BEFORE UPDATE OR DELETE ON kernel.privacy_erasure_requests
FOR EACH ROW EXECUTE FUNCTION kernel.privacy_tombstone_immutable();

-- Content removal is one-way, including when an older binary is rolled back.
CREATE FUNCTION kernel.privacy_action_no_restore() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
BEGIN
  IF OLD.content_erased_at IS NOT NULL AND
    (NEW.content_erased_at IS DISTINCT FROM OLD.content_erased_at OR octet_length(NEW.canonical_request)<>0
     OR NEW.purpose<>'' OR NEW.action_digest<>OLD.action_digest OR NEW.state<>OLD.state
     OR NEW.idempotency_key<>OLD.idempotency_key) THEN
    RAISE EXCEPTION 'erased action cannot be restored' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER privacy_action_no_restore BEFORE UPDATE ON kernel.actions
FOR EACH ROW EXECUTE FUNCTION kernel.privacy_action_no_restore();

CREATE FUNCTION kernel.privacy_permission_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
BEGIN
  PERFORM kernel.privacy_tenant_lock(NEW.tenant_id,false);
  IF EXISTS(SELECT 1 FROM kernel.privacy_erasure_requests WHERE tenant_id=NEW.tenant_id
      AND subject_kind='contact' AND subject_id=NEW.contact_id)
    AND (TG_OP='INSERT' OR NEW.status<>'revoked' OR NEW.destination_sealed IS NOT NULL OR NEW.source<>'privacy-erased') THEN
    RAISE EXCEPTION 'erased permission cannot be restored' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER privacy_permission_guard BEFORE INSERT OR UPDATE ON kernel.contact_permissions
FOR EACH ROW EXECUTE FUNCTION kernel.privacy_permission_guard();

CREATE FUNCTION kernel.privacy_inbound_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
DECLARE rid uuid;
BEGIN
  PERFORM kernel.privacy_tenant_lock(NEW.tenant_id,false);
  IF TG_OP='UPDATE' AND OLD.content_erased_at IS NOT NULL THEN
    IF NEW.content_erased_at IS DISTINCT FROM OLD.content_erased_at OR octet_length(NEW.content_sealed)<>0
      OR NEW.destination_sealed IS NOT NULL OR NEW.content_reference<>'privacy-erased' OR NEW.processed_at IS NULL THEN
      RAISE EXCEPTION 'erased inbound cannot be restored' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='INSERT' THEN
    SELECT request_id INTO rid FROM kernel.privacy_destination_fences WHERE tenant_id=NEW.tenant_id AND channel='sms'
      AND (destination_hash=NEW.source_destination_hash OR destination_fingerprints && NEW.destination_fingerprints)
      ORDER BY request_id LIMIT 1;
    IF rid IS NULL THEN
      SELECT r.request_id INTO rid FROM kernel.privacy_erasure_requests r JOIN kernel.sender_identities s
        ON s.tenant_id=r.tenant_id AND s.owner_user_id=r.subject_id
        WHERE r.tenant_id=NEW.tenant_id AND r.subject_kind='account' AND s.sender_identity_id=NEW.sender_identity_id;
    END IF;
    IF rid IS NOT NULL THEN
      NEW.content_sealed := ''::bytea;
      NEW.destination_sealed := NULL;
      NEW.content_reference := 'privacy-erased';
      NEW.content_erased_at := now();
      NEW.processed_at := now();
      INSERT INTO kernel.privacy_provider_deletions(tenant_id,request_id,sender_identity_id,provider,provider_message_id)
        VALUES(NEW.tenant_id,rid,NEW.sender_identity_id,NEW.provider,NEW.provider_event_id) ON CONFLICT DO NOTHING;
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER privacy_inbound_guard BEFORE INSERT OR UPDATE ON kernel.inbound_events
FOR EACH ROW EXECUTE FUNCTION kernel.privacy_inbound_guard();

CREATE FUNCTION kernel.privacy_sender_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,kernel AS $$
BEGIN
  PERFORM kernel.privacy_tenant_lock(NEW.tenant_id,false);
  IF EXISTS(SELECT 1 FROM kernel.privacy_erasure_requests WHERE tenant_id=NEW.tenant_id
      AND subject_kind='account' AND subject_id=NEW.owner_user_id)
      AND (TG_OP='INSERT' OR NEW.status='active') THEN
    RAISE EXCEPTION 'erased sender owner cannot be restored' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER privacy_sender_guard BEFORE INSERT OR UPDATE ON kernel.sender_identities
FOR EACH ROW EXECUTE FUNCTION kernel.privacy_sender_guard();

REVOKE ALL ON FUNCTION kernel.privacy_subject_lock(uuid,text,uuid,boolean),
  kernel.privacy_tenant_lock(uuid,boolean),
  kernel.privacy_resource_uuid(text),
  kernel.check_privacy_intake(),kernel.privacy_tombstone_immutable(),kernel.privacy_action_no_restore(),
  kernel.privacy_permission_guard(),kernel.privacy_inbound_guard(),kernel.privacy_sender_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION kernel.privacy_subject_lock(uuid,text,uuid,boolean),
  kernel.privacy_tenant_lock(uuid,boolean),
  kernel.privacy_resource_uuid(text),
  kernel.check_privacy_intake(),kernel.privacy_tombstone_immutable(),kernel.privacy_action_no_restore(),
  kernel.privacy_permission_guard(),kernel.privacy_inbound_guard(),kernel.privacy_sender_guard() TO mk_kernel_api,mk_kernel_worker;
GRANT EXECUTE ON FUNCTION kernel.privacy_tenant_lock(uuid,boolean) TO mk_kernel_relay,mk_kernel_readonly;
GRANT EXECUTE ON FUNCTION kernel.privacy_resource_uuid(text) TO mk_kernel_readonly;
