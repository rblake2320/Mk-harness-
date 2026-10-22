-- H2: durable version fences, including proposals accepted before an app
-- ActionLink could commit. These records are never reopened or reassigned.
CREATE TABLE kernel.draft_action_refs (
  tenant_id uuid NOT NULL,
  draft_id uuid NOT NULL,
  action_id uuid NOT NULL,
  PRIMARY KEY (tenant_id, draft_id, action_id),
  FOREIGN KEY (tenant_id, action_id) REFERENCES kernel.actions (tenant_id, action_id)
);
CREATE TABLE kernel.invalidated_drafts (
  tenant_id uuid NOT NULL,
  draft_id uuid NOT NULL,
  invalidated_by uuid NOT NULL,
  invalidated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, draft_id)
);
-- Existing canonical requests are immutable UTF-8 JSON. Only the application's
-- UUID-shaped draft references are indexed; other document evidence is untouched.
INSERT INTO kernel.draft_action_refs (tenant_id, draft_id, action_id)
SELECT DISTINCT a.tenant_id, substring(e->>'id' from 7)::uuid, a.action_id
FROM kernel.actions a,
LATERAL jsonb_array_elements(convert_from(a.canonical_request, 'UTF8')::jsonb->'evidence') e
WHERE e->>'type' = 'document'
  AND e->>'id' ~ '^draft:([0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$';

ALTER TABLE kernel.draft_action_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE kernel.draft_action_refs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON kernel.draft_action_refs
  USING (tenant_id = kernel.current_tenant()) WITH CHECK (tenant_id = kernel.current_tenant());
ALTER TABLE kernel.invalidated_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE kernel.invalidated_drafts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON kernel.invalidated_drafts
  USING (tenant_id = kernel.current_tenant()) WITH CHECK (tenant_id = kernel.current_tenant());
GRANT SELECT, INSERT ON kernel.draft_action_refs, kernel.invalidated_drafts TO mk_kernel_api;
GRANT SELECT ON kernel.draft_action_refs, kernel.invalidated_drafts TO mk_kernel_worker, mk_kernel_readonly;
REVOKE UPDATE, DELETE, TRUNCATE ON kernel.draft_action_refs, kernel.invalidated_drafts
  FROM mk_kernel_api, mk_kernel_worker, mk_kernel_relay, mk_kernel_readonly;
CREATE TRIGGER immutable_draft_refs BEFORE UPDATE OR DELETE OR TRUNCATE
  ON kernel.draft_action_refs FOR EACH STATEMENT EXECUTE FUNCTION kernel.reject_resolution_mutation();
CREATE TRIGGER immutable_draft_fences BEFORE UPDATE OR DELETE OR TRUNCATE
  ON kernel.invalidated_drafts FOR EACH STATEMENT EXECUTE FUNCTION kernel.reject_resolution_mutation();
