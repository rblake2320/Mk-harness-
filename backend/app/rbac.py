"""Tenant-scoped role-based access control (S3) and route policy (S2 step-up).

One table decides, for every /api route, which permission it needs and whether
it needs a fresh second factor (step-up). `route_guard` enforces it for every
router before any handler code runs; `tests/test_rbac.py` fails if a route has
no entry, so a new route cannot ship unguarded (default deny).

Roles (per tenant):

  owner       the consultant business owner: everything, incl. billing and tenant deletion
  admin       everything except billing and tenant deletion
  consultant  their own customer book end to end, incl. human approval (passkey)
  assistant   works inside ONE consultant's book (users.works_for): prepares customers,
              drafts and proposals; may record opt-outs/stops; may NOT approve, grant
              consent, export, or change security settings
  viewer      read-only inside one consultant's book

Kernel mapping (vocabulary fixed by CLAUDE.md): owner/admin → consultant+tenant_admin,
consultant → consultant, assistant/viewer → agent (a non-approving principal: the
kernel refuses its approvals and consent changes even if the app check were bypassed).

Break-glass (S9): platform support reaches a tenant only through an approved,
unexpired grant, read-only, on the BREAKGLASS_READ routes below, and every request
is audited in the target tenant.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .db import get_db

ROLES = ("owner", "admin", "consultant", "assistant", "viewer")
DELEGATED_ROLES = ("assistant", "viewer")   # act inside users.works_for's book

_CONSULTANT = frozenset({
    "customers.read", "customers.write", "customers.delete", "customers.import",
    "consent.write", "consent.revoke", "suppression.add",
    "drafts.write", "actions.propose", "actions.approve", "actions.cancel",
    "brief.read", "brief.write", "commitments.write", "outcomes.write",
    "inbound.process", "exceptions.resolve", "knowledge.read",
    "chat.use", "skin.use", "skin.consent", "keys.own",
    "exports.customers", "exports.account", "approval.credentials", "stop.dispatch",
})
_ADMIN_ONLY = frozenset({
    "members.manage", "settings.security", "senders.manage", "knowledge.manage",
    "suppression.lift", "killswitch.tenant", "breakglass.approve", "exports.audit",
    "actions.replay",
})
_OWNER_ONLY = frozenset({"billing.manage", "tenant.delete"})

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "owner": _CONSULTANT | _ADMIN_ONLY | _OWNER_ONLY,
    "admin": _CONSULTANT | _ADMIN_ONLY,
    "consultant": _CONSULTANT,
    "assistant": frozenset({
        "customers.read", "customers.write", "customers.import",
        "consent.revoke", "suppression.add",           # recording a stop is always allowed
        "drafts.write", "actions.propose", "actions.cancel",
        "brief.read", "brief.write", "commitments.write", "outcomes.write",
        "inbound.process", "knowledge.read", "chat.use", "skin.use", "keys.own", "stop.dispatch",
    }),
    "viewer": frozenset({"customers.read", "brief.read", "knowledge.read"}),
}
ALL_PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())


def has_perm(role: str, perm: str) -> bool:
    return perm in ROLE_PERMISSIONS.get(role, frozenset())


def kernel_roles(role: str) -> list[str]:
    if role in ("owner", "admin"):
        return ["consultant", "tenant_admin"]
    if role == "consultant":
        return ["consultant"]
    return ["agent"]   # assistant, viewer, support: never an approver


def book_of(user) -> str:
    """The user id whose customer book this principal works in (data scoping);
    `user.id` stays the actor for attribution."""
    if getattr(user, "role", "") in DELEGATED_ROLES or getattr(user, "role", "") == "support":
        owner = getattr(user, "works_for", None)
        if not owner:
            raise HTTPException(403, {"code": "NO_BOOK", "detail": "this account is not assigned to a consultant"})
        return owner
    return user.id


def sees_whole_tenant(user) -> bool:
    """Owners and admins may see every consultant's approvals in their business."""
    return getattr(user, "role", "") in ("owner", "admin")


@dataclass(frozen=True)
class Policy:
    perm: str | None = None        # None = any authenticated user
    step_up: bool = False          # fresh second factor within STEP_UP_WINDOW
    public: bool = False           # no authentication at all
    enrollment: bool = False       # reachable before MFA enrollment completes
    support: bool = False          # platform support staff only (break-glass requests)


P = Policy
PUBLIC = Policy(public=True)

# (METHOD, route path as registered) → policy. Every /api route must be listed.
ROUTE_POLICY: dict[tuple[str, str], Policy] = {
    # --- auth / sessions ---
    ("POST", "/api/auth/signup"): PUBLIC,
    ("POST", "/api/auth/login"): PUBLIC,
    ("POST", "/api/auth/refresh"): PUBLIC,
    ("POST", "/api/auth/mfa/verify"): PUBLIC,                 # carries the short-lived mfa_token
    ("POST", "/api/auth/mfa/passkey/options"): PUBLIC,        # carries the short-lived mfa_token
    ("POST", "/api/auth/logout"): P(enrollment=True),
    ("GET", "/api/auth/me"): P(enrollment=True),
    ("POST", "/api/auth/members"): P("members.manage", step_up=True),
    ("POST", "/api/auth/change-password"): P(step_up=True),
    ("GET", "/api/auth/sessions"): P(enrollment=True),
    ("POST", "/api/auth/sessions/{sid}/revoke"): P(enrollment=True),         # stopping: no step-up
    ("POST", "/api/auth/sessions/revoke-others"): P(enrollment=True),
    # --- second factors and step-up ---
    ("GET", "/api/security/mfa"): P(enrollment=True),
    ("POST", "/api/security/mfa/totp/begin"): P(enrollment=True),        # handler: step-up if a factor exists
    ("POST", "/api/security/mfa/totp/confirm"): P(enrollment=True),
    ("POST", "/api/security/mfa/passkey/begin"): P(enrollment=True),
    ("POST", "/api/security/mfa/passkey/finish"): P(enrollment=True),
    ("POST", "/api/security/mfa/{fid}/revoke"): P(step_up=True),
    ("POST", "/api/security/mfa/recovery-codes"): P(step_up=True),
    ("POST", "/api/security/step-up"): P(),
    ("POST", "/api/security/step-up/passkey/options"): P(),
    # --- members ---
    ("GET", "/api/security/members"): P("members.manage"),
    ("POST", "/api/security/members/{uid}/role"): P("members.manage", step_up=True),
    ("POST", "/api/security/members/{uid}/deactivate"): P("members.manage", step_up=True),
    ("POST", "/api/security/members/{uid}/sessions/revoke"): P("members.manage"),
    ("GET", "/api/security/revocations"): P("members.manage"),
    # --- break-glass ---
    ("GET", "/api/security/break-glass"): P("breakglass.approve"),
    ("POST", "/api/security/break-glass/{gid}/approve"): P("breakglass.approve", step_up=True),
    ("POST", "/api/security/break-glass/{gid}/deny"): P("breakglass.approve"),
    ("POST", "/api/security/break-glass/{gid}/revoke"): P("breakglass.approve"),
    ("POST", "/api/support/break-glass"): P(support=True),
    ("GET", "/api/support/break-glass"): P(support=True),
    ("POST", "/api/support/break-glass/{gid}/session"): P(support=True, step_up=True),
    # --- chat / skin ---
    ("GET", "/api/chat/skills"): P("chat.use"),
    ("GET", "/api/chat/models"): P("chat.use"),
    ("GET", "/api/chat/conversations"): P("chat.use"),
    ("GET", "/api/chat/conversations/{cid}"): P("chat.use"),
    ("DELETE", "/api/chat/conversations/{cid}"): P("chat.use"),
    ("POST", "/api/chat/stream"): P("chat.use"),
    ("POST", "/api/skin/analyze"): P("skin.use"),
    ("GET", "/api/skin/history"): P("skin.use"),
    ("GET", "/api/consent/skin"): P("skin.use"),
    ("GET", "/api/consent/skin/customer/{customer_id}"): P("skin.use"),
    ("POST", "/api/consent/skin"): P("skin.consent", step_up=True),
    ("DELETE", "/api/consent/skin"): P("skin.use"),                        # withdrawing consent: no step-up
    ("GET", "/api/me/skin-data/export"): P("exports.account", step_up=True),
    ("DELETE", "/api/me/skin-data"): P("skin.use", step_up=True),
    # --- customers / foundation ---
    ("GET", "/api/customers"): P("customers.read"),
    ("GET", "/api/customers/search"): P("customers.read"),
    ("GET", "/api/customers/suggestions"): P("customers.read"),
    ("GET", "/api/customers/{cid}"): P("customers.read"),
    ("POST", "/api/customers"): P("customers.write"),
    ("PUT", "/api/customers/{cid}"): P("customers.write"),
    ("DELETE", "/api/customers/{cid}"): P("customers.delete", step_up=True),
    ("POST", "/api/customers/{cid}/touch"): P("customers.write"),
    ("POST", "/api/customers/{cid}/follow-up"): P("customers.write"),
    ("POST", "/api/customers/{cid}/destinations"): P("customers.write"),
    ("GET", "/api/customers/{cid}/destinations"): P("customers.read"),
    ("PUT", "/api/customers/{cid}/preferences"): P("customers.write"),
    ("POST", "/api/customers/{cid}/consent"): P("consent.write", step_up=True),
    ("POST", "/api/customers/{cid}/consent/{eid}/revoke"): P("consent.revoke"),
    ("GET", "/api/customers/{cid}/permissions"): P("customers.read"),
    ("POST", "/api/suppressions"): P("suppression.add"),
    ("POST", "/api/customers/import/preview"): P("customers.import"),
    ("GET", "/api/customers/import/{job_id}"): P("customers.import"),
    ("POST", "/api/customers/import/{job_id}/commit"): P("customers.import"),
    ("POST", "/api/customers/import/{job_id}/rollback"): P("customers.import"),
    ("GET", "/api/customers/export.csv"): P("exports.customers", step_up=True),
    ("GET", "/api/customers/{cid}/timeline"): P("customers.read"),
    # --- commitments / brief / outcomes ---
    ("POST", "/api/commitments"): P("commitments.write"),
    ("POST", "/api/commitments/extract"): P("commitments.write"),
    ("POST", "/api/commitments/{cid}/confirm"): P("commitments.write"),
    ("POST", "/api/commitments/{cid}/defer"): P("commitments.write"),
    ("POST", "/api/commitments/{cid}/cancel"): P("commitments.write"),
    ("GET", "/api/commitments"): P("customers.read"),
    ("GET", "/api/brief"): P("brief.read"),
    ("POST", "/api/brief/items/{iid}/skip"): P("brief.write"),
    ("POST", "/api/brief/items/{iid}/defer"): P("brief.write"),
    ("POST", "/api/brief/items/{iid}/resolve"): P("brief.write"),
    ("POST", "/api/outcomes"): P("outcomes.write"),
    # --- drafting / knowledge ---
    ("POST", "/api/knowledge/sources"): P("knowledge.manage"),
    ("POST", "/api/knowledge/sources/{sid}/review"): P("knowledge.manage"),
    ("POST", "/api/knowledge/claims"): P("knowledge.manage"),
    ("POST", "/api/knowledge/claims/{rid}/review"): P("knowledge.manage"),
    ("GET", "/api/knowledge/claims"): P("knowledge.read"),
    ("POST", "/api/drafts"): P("drafts.write"),
    ("POST", "/api/drafts/{did}/edit"): P("drafts.write"),
    ("GET", "/api/drafts/{did}"): P("customers.read"),
    # --- inbound / exceptions ---
    ("POST", "/api/inbound/process"): P("inbound.process"),
    ("GET", "/api/exceptions"): P("customers.read"),
    ("POST", "/api/exceptions/{eid}/resolve"): P("exceptions.resolve"),
    # --- outreach (proposal + approval read views) ---
    ("POST", "/api/drafts/{did}/propose"): P("actions.propose"),
    ("GET", "/api/approvals/pending"): P("customers.read"),
    ("GET", "/api/actions/{action_id}"): P("customers.read"),
    ("GET", "/api/audit/export.jsonl"): P("exports.audit", step_up=True),
    # --- keys / usage / profile / billing / account ---
    ("PUT", "/api/keys/mine"): P("keys.own", step_up=True),
    ("PUT", "/api/keys/tenant"): P("settings.security", step_up=True),
    ("GET", "/api/keys/status"): P(),
    ("DELETE", "/api/keys/mine/{provider}"): P("keys.own"),
    ("GET", "/api/usage/me"): P(),
    ("GET", "/api/usage/tenant"): P("members.manage"),
    ("GET", "/api/profile/me"): P(),
    ("PATCH", "/api/profile/me"): P(),
    ("GET", "/api/billing/plans"): PUBLIC,
    ("POST", "/api/billing/webhook"): PUBLIC,                  # Stripe signature-verified in the handler
    ("GET", "/api/billing/me"): P(),
    ("POST", "/api/billing/checkout"): P("billing.manage"),
    ("POST", "/api/billing/portal"): P("billing.manage"),
    ("GET", "/api/account/export"): P("exports.account", step_up=True),
    ("DELETE", "/api/account"): P(step_up=True),
    # --- agent-ops (kernel relay) ---
    ("GET", "/api/agent-ops/health"): P(),
    ("POST", "/api/agent-ops/actions"): P("actions.propose"),
    ("GET", "/api/agent-ops/actions/{action_id}"): P("customers.read"),
    ("POST", "/api/agent-ops/actions/{action_id}/cancel"): P("actions.cancel"),
    ("POST", "/api/agent-ops/actions/{action_id}/replay"): P("actions.replay", step_up=True),
    ("POST", "/api/agent-ops/actions/{action_id}/approve"): P("actions.approve"),
    ("POST", "/api/agent-ops/actions/{action_id}/reject"): P("actions.approve"),
    ("GET", "/api/agent-ops/approvals/pending"): P("customers.read"),
    ("POST", "/api/agent-ops/actions/{action_id}/approval-challenge"): P("actions.approve"),
    ("POST", "/api/agent-ops/approval-credentials/register/begin"): P("approval.credentials", step_up=True),
    ("POST", "/api/agent-ops/approval-credentials/register/finish"): P("approval.credentials", step_up=True),
    ("GET", "/api/agent-ops/approval-credentials"): P(),
    ("POST", "/api/agent-ops/approval-credentials/{row_id}/revoke"): P(),       # stopping
    ("POST", "/api/agent-ops/revocations"): P(),                                # stopping
    ("POST", "/api/agent-ops/approvals/{approval_id}/revoke"): P("actions.cancel"),
    ("POST", "/api/agent-ops/senders"): P("senders.manage", step_up=True),
    ("GET", "/api/agent-ops/senders"): P(),
    ("POST", "/api/agent-ops/senders/{sender_id}/registration"): P("senders.manage", step_up=True),
    ("GET", "/api/agent-ops/inbound/health"): P(),
    ("POST", "/api/agent-ops/inbound/health"): P("settings.security", step_up=True),
    ("POST", "/api/agent-ops/inbound/pause"): P("stop.dispatch"),               # stopping
    ("POST", "/api/agent-ops/inbound/resume"): P("killswitch.tenant", step_up=True),
    ("POST", "/api/agent-ops/contacts/{contact_id}/permissions"): P("consent.write", step_up=True),
    ("POST", "/api/agent-ops/contacts/{contact_id}/permissions/{permission_id}/revoke"): P("consent.revoke"),
    ("POST", "/api/agent-ops/suppressions"): P("suppression.add"),
    ("DELETE", "/api/agent-ops/suppressions/{suppression_id}"): P("suppression.lift", step_up=True),
    ("POST", "/api/agent-ops/adapters"): P("settings.security", step_up=True),
    ("GET", "/api/agent-ops/adapters/{adapter_id}"): P("settings.security"),
    ("POST", "/api/agent-ops/adapters/{adapter_id}/rotate"): P("settings.security", step_up=True),
    ("POST", "/api/agent-ops/adapters/{adapter_id}/revoke"): P("settings.security"),   # stopping
    # Disabling is always allowed; ENABLING requires step-up (checked in the handler).
    ("POST", "/api/agent-ops/kill-switch/tenant"): P("killswitch.tenant"),
    # Platform operators only (checked in the handler) + kernel WebAuthn step-up to enable.
    ("POST", "/api/agent-ops/kill-switch/global"): P(),
    ("POST", "/api/agent-ops/kill-switch/global/challenge"): P(),
}

# Read-only routes platform support may use under an approved break-glass grant.
# Deliberately excludes exports, kernel relays (agent-ops), and any route that
# writes — including GET /api/brief, which materializes brief items.
BREAKGLASS_READ: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/api/auth/me"),
    ("GET", "/api/customers"),
    ("GET", "/api/customers/search"),
    ("GET", "/api/customers/{cid}"),
    ("GET", "/api/customers/{cid}/destinations"),
    ("GET", "/api/customers/{cid}/permissions"),
    ("GET", "/api/customers/{cid}/timeline"),
    ("GET", "/api/commitments"),
    ("GET", "/api/exceptions"),
    ("GET", "/api/drafts/{did}"),
    ("GET", "/api/customers/import/{job_id}"),
})


def route_key(request: Request) -> tuple[str, str]:
    route = request.scope.get("route")
    return request.method, getattr(route, "path", request.url.path)


def route_guard(request: Request, db: Session = Depends(get_db)) -> None:
    """Runs before every /api handler: authentication, MFA state, permission,
    step-up, break-glass scope. Unknown routes are denied."""
    from . import identity  # local import: identity imports models/security

    key = route_key(request)
    policy = ROUTE_POLICY.get(key)
    if policy is None:
        raise HTTPException(403, {"code": "ROUTE_NOT_AUTHORIZED", "detail": f"no policy for {key[0]} {key[1]}"})
    if policy.public:
        return
    principal = identity.authenticate(request, db)   # 401 on any session problem
    session = request.state.auth_session
    if request.state.breakglass is not None:
        if key not in BREAKGLASS_READ:
            identity.audit_breakglass(db, request, allowed=False)
            raise HTTPException(403, {"code": "BREAKGLASS_READ_ONLY",
                                      "detail": "break-glass access is read-only and limited to support views"})
        identity.audit_breakglass(db, request, allowed=True)
        return
    if identity.mfa_blocks(db, principal, session) and not policy.enrollment:
        raise HTTPException(403, {"code": "MFA_ENROLLMENT_REQUIRED",
                                  "detail": "set up a second sign-in factor to continue"})
    if policy.support:
        from .config import get_settings
        if principal.id not in get_settings().platform_support_ids:
            raise HTTPException(403, {"code": "SUPPORT_ONLY", "detail": "platform support staff only"})
    elif policy.perm and not has_perm(principal.role, policy.perm):
        raise HTTPException(403, {"code": "PERMISSION_DENIED",
                                  "detail": f"your role ({principal.role}) cannot do this ({policy.perm})"})
    if policy.step_up:
        identity.require_step_up(db, principal, session)
