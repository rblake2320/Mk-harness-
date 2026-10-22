# Product fact review (P2)

The model does not decide which contradictory source is true. Before a product
claim is eligible for drafting, a reviewer records its factual assertions via
`POST /api/knowledge/v2/claims/{row-id}/review` using the v2 contract.
The authenticated administrator and review decision are retained in the audit.

Example: `{"decision":"approved","reviewer":"named reviewer","facts":{"composition.fragrance":"absent"}}`.
Use the same canonical attribute for the same proposition across source versions.
For composition attributes, use `composition.<ingredient>` with `present` or
`absent`; use an exact normalized value for numeric attributes, such as
`sun_protection.spf: "30"`. Do not encode source-specific identifiers in fact
names or substitute a generic "reviewed" flag. Facts must faithfully represent
every factual assertion in the text. This annotation is a human review
responsibility, not a claim of general natural-language contradiction detection.

Selection is scoped to the tenant (plus approved platform sources), product,
market and effective period. Two simultaneously effective approved assertions
with different values for the same product attribute block all recommendations
for that product. Multiple live versions of one claim identity also block;
there is no silent tenant/version override. Missing annotation blocks as well.
Compatible facts for separate products/markets/tenants do not conflict.

The consultant receives a limitation, a neutral acknowledgment and a review task.
No model request is made for a blocked recommendation. Existing drafts are
rechecked before proposal, and conflicting text cannot be retained through an
edit. Withdraw incorrect/obsolete claims, then review and regenerate; do not
silently pick one source. Already-dispatched content cannot be recalled by this
application check.

## Migration and compatibility

The migration is additive: startup's existing schema creation adds
`claim_facts`; no existing claim/source rows or old columns are rewritten.
The v1 review URL and payload remain readable and callable. A v1 approval now
returns `facts_review_required: true` and remains ineligible for drafting until
explicit v2 re-review. A legacy re-review clears previous fact annotation rather
than inheriting it accidentally. V2 approval refuses empty facts with
`CLAIM_FACTS_REQUIRED`. Both versions can withdraw a claim.

Back up before deployment, run the additive schema operation under the migration
identity, and re-review all retained approved claims using authoritative sources.
Do not grant runtime schema-owner privileges to perform the migration.
The migration test creates an old-schema database, preserves a legacy approved
claim through the table addition and verifies it is withheld until annotated.
The app's existing runtime create_all/bootstrap separation remains an operations
deployment gate; this migration does not authorize runtime DDL in production.
