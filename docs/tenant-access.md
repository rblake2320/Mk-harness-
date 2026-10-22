# Tenant access and role changes

Application roles are explicit; an unrecognized role is denied at login,
authenticated access and kernel-assertion mapping. There is no default-to-
consultant mapping and no role specified by the caller in an authenticated
request. The live user record, not a stale JWT role claim, controls access.

| Role | Scope |
|---|---|
| Consultant | Own customer book and workflows; human approval only through the kernel passkey ceremony and current tenant policy |
| Manager | Consultant scope plus same-tenant pending-approval context, action review and usage; no member administration, team credentials or sender administration |
| Auditor | Same-tenant application audit export; own session/MFA/password/account privacy controls only; no customer, model or kernel action access |
| Admin | Tenant member, sender, credential and policy administration plus consultant/team-review capabilities |

All roles require mandatory MFA. Sensitive changes and exports require the same
fresh five-minute check. Auditor access is an exact matched-route allowlist,
denying new routes by default. Tests enumerate the actual authenticated route
graph, not only a handful of example requests. Auditors never receive a kernel
assertion, including through agent-origin mapping. Manager assertions carry the
kernel's manager role, not tenant-admin authority. No application role grants
platform-operator access or support impersonation.

Admins add members and choose roles in Settings. Team access controls change
another member's role or enabled state after a fresh identity check. Every
material change records actor, target and before/after access, revokes all target
app sessions, and durably queues kernel revocation. The response/UI explicitly
reports kernel delivery as pending; it does not claim a provider cancellation.
Role changes require a new sign-in, including MFA. Disabling an account blocks
sign-in; reenabling does not resurrect its old sessions.

Self-demotion and self-disable are refused. Tenant-level serialization plus a
fresh actor read prevents two administrators from disabling each other with
already-authenticated concurrent requests. Cross-tenant targets return 404.
Admins cannot assign the kernel's agent, session-revoker or platform-operator
roles through the member API.

Web auditors see account security and audit export, not unusable customer or
action screens. Native auditors get a read-only audit view using the shared
step-up client. Native device parity is a separate X2 verification queue.

Application runtime and migration credentials are now separated, with actual
PostgreSQL denial/upgrade/MFA acceptance tests and a startup privilege gate; see
`runbooks/application-database.md`. Independent staging qualification and
main-branch evidence are still required for S3 closure.
