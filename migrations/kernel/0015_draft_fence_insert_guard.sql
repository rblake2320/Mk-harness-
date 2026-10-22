-- Keep H2 fail-closed when an old intake binary remains during rollout.
-- Invoker-security functions preserve the caller's tenant RLS and privileges.
CREATE FUNCTION kernel.action_draft_ids(canonical bytea) RETURNS SETOF uuid
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT DISTINCT substring(e->>'id' from 7)::uuid
  FROM jsonb_array_elements(convert_from(canonical, 'UTF8')::jsonb->'evidence') e
  WHERE e->>'type' = 'document' AND left(e->>'id', 6) = 'draft:'
$$;

CREATE FUNCTION kernel.check_draft_fence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE draft uuid;
BEGIN
  FOR draft IN SELECT * FROM kernel.action_draft_ids(NEW.canonical_request) ORDER BY 1 LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended('draft:' || NEW.tenant_id::text || ':' || draft::text, 0));
    IF EXISTS (SELECT 1 FROM kernel.invalidated_drafts WHERE tenant_id=NEW.tenant_id AND draft_id=draft) THEN
      RAISE EXCEPTION 'draft version was invalidated' USING ERRCODE='23514';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;
CREATE TRIGGER enforce_draft_fence BEFORE INSERT ON kernel.actions
  FOR EACH ROW EXECUTE FUNCTION kernel.check_draft_fence();

CREATE FUNCTION kernel.index_action_drafts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO kernel.draft_action_refs (tenant_id,draft_id,action_id)
    SELECT NEW.tenant_id,draft,NEW.action_id FROM kernel.action_draft_ids(NEW.canonical_request) draft;
  RETURN NEW;
END $$;
CREATE TRIGGER index_action_drafts AFTER INSERT ON kernel.actions
  FOR EACH ROW EXECUTE FUNCTION kernel.index_action_drafts();
