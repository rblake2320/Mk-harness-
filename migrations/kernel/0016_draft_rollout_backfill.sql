-- An old intake process may have committed between migrations 14 and 15.
-- The insert trigger now indexes all future rows; recover that rollout gap.
INSERT INTO kernel.draft_action_refs (tenant_id,draft_id,action_id)
SELECT a.tenant_id,draft,a.action_id
FROM kernel.actions a, LATERAL kernel.action_draft_ids(a.canonical_request) draft
ON CONFLICT DO NOTHING;
