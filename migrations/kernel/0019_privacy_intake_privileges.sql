-- A table-wide INSERT grant also allowed intake to forge a completed receipt.
-- Only the immutable target fields belong to the API; all outcome columns use
-- database defaults until the separate worker records a verified result.
REVOKE INSERT ON kernel.privacy_provider_deletions FROM mk_kernel_api;
GRANT INSERT (tenant_id,request_id,sender_identity_id,provider,provider_message_id)
ON kernel.privacy_provider_deletions TO mk_kernel_api;
