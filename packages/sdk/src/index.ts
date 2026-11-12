/**
 * MK Harness SDK — single client for web (fetch/ReadableStream) and
 * React Native (fetch + XHR streaming fallback). Every API call either platform makes
 * goes through `MKClient`; shared interface logic (message-state vocabulary, error
 * explanations, approval display, the mobile→web passkey hand-off) is exported from the
 * modules re-exported at the bottom of this file.
 */
import type { MessageState, ReadStatus } from './vocabulary';
import { ApiError, apiErrorFrom } from './errors';

export interface Tokens {
  access_token: string; refresh_token: string;
  role: string; display_name: string; tenant_id: string;
  session_id?: string;
  /** MFA is required and this account has no second factor yet: only enrollment works. */
  mfa_enrollment_required?: boolean;
}
/** Password accepted; a second factor is required before any tokens are issued. */
export interface MfaChallenge { mfa_required: true; mfa_token: string; methods: string[]; expires_in: number }
export type LoginResult = Tokens | MfaChallenge;
export function isMfaChallenge(r: LoginResult): r is MfaChallenge { return (r as MfaChallenge).mfa_required === true }
export interface MfaFactor { id: string; kind: 'totp' | 'webauthn'; label: string; created_at: string; last_used_at: string | null }
export interface MfaStatus { factors: MfaFactor[]; methods: string[]; mfa_required: boolean; passkeys_available: boolean }
export interface AuthSessionInfo {
  id: string; client: string; created_at: string; last_seen_at: string; second_factor: boolean;
  current: boolean; revoked: boolean; revoked_reason: string | null;
}
export interface Member {
  id: string; email: string; display_name: string; role: string; works_for: string | null;
  active: boolean; second_factor: boolean;
}
export interface BreakGlassGrant {
  id: string; subject_user_id: string; requested_by: string; reason: string; ticket_ref: string;
  scope: string; duration_minutes: number; status: string; requested_at: string; decided_by: string | null;
  expires_at: string | null; access_count: number;
}
/** A WebAuthn credential serialized for JSON (base64url fields), as the API expects. */
export type PublicKeyCredentialJSON = Record<string, any>;
export interface SkinObservation { category: string; level: string; note: string }
export interface SkinResult {
  observations: SkinObservation[]; care_focus: string[];
  routine_suggestion: { am: string[]; pm: string[] };
  consultant_talking_points: string[]; see_professional: boolean; disclaimer: string;
  ai_disclosure?: string;
}
export interface Customer {
  id: string; name: string; phone: string; email: string;
  notes: string; last_contact: string | null;
}
export interface ConsentStatus {
  version: string; operator_consent: boolean; operator_granted_at: string | null;
  operator_text: string; customer_text: string; ai_disclosure: string;
}
export interface Plan { tier: string; interval: string }
export interface BillingStatus {
  status: string; tier: string; interval: string;
  trial_end: string | null; current_period_end: string | null; active: boolean;
  referral_code: string | null;
  referral_credits_earned_cents: number; referral_count: number;
}


// ---- WP03–WP08 types (shapes of the real routes; message-state words come only from ./vocabulary) ----
export interface Commitment {
  id: string; customer_id: string; kind: string; text: string; status: string;
  due_at: string | null; due_window: [string | null, string | null]; timezone: string;
  source_type: string; source_reference: string; evidence_digest: string; created_by: string;
  confirmed_by: string | null; version: number;
}
export interface BriefItem {
  id: string; customer: { id: string; name: string } | null; rule: string; rank_category: number;
  source_type: string; source_reference: string; source: Commitment | null; due_at: string | null;
  state: string; permission_state: string; permission_checked_at: string | null; permission_note: string;
  suggested_step: string; draft_version_id: string | null; controls: string[];
}
export interface Draft {
  id: string; customer_id: string; brief_item_id: string | null; text: string; text_digest: string;
  claims_used: string[]; source_versions: Record<string, string>; generated_by: string; version: number; note: string;
}
export interface DraftResponse { draft: Draft | null; limitation: string | null; review_task_id?: string; neutral_text?: string }
export interface PendingApproval {
  action_id: string; action_digest: string; state: string; message_state: MessageState | null;
  exact_text: string; destination_masked: string; channel: string; purpose: string; workflow: string; risk: string;
  customer: { id: string; name: string } | null;
  sending_business: { sender_identity_id: string; display_name: string; from_number: string; registration_status: string } | null;
  supporting: { commitment: { id: string; text: string; status: string; evidence_digest: string } | null; draft_version_id: string | null; evidence_count: number };
  permission: { state: string; checked_at: string | null; note: string } | null;
  scheduled_for: string | null; approval_expires_at: string; approval_lifetime_minutes: number; human_steps: string[];
}
export interface ExceptionItem {
  id: string; customer_id: string | null; kind: string; state: string; source_reference: string; detail: string;
  created_at: string; resolved_at: string | null;
}
export interface WebAuthnAssertion { credential_id: string; client_data_json: string; authenticator_data: string; signature: string }

/** Kernel action result (contracts/action/v1/action-result.schema.json). `state` is the
 *  kernel's internal state and is never shown as a message state; screens use
 *  `message_state` through `describeMessageState`. */
export interface ActionResult {
  schema_version: string; action_id: string; tenant_id: string; state: string; action_digest: string;
  attempt: number; error_code?: string; updated_at: string; replay_of?: string;
  receipt?: { adapter_id?: string; external_ref?: string; result_digest?: string };
  message_state?: MessageState; read_status?: ReadStatus; provider_message_id?: string;
}
export interface ApprovalRecord {
  approval_id: string; action_id: string; action_digest: string; approver_id: string; approver_roles?: string[];
  decision: 'approved' | 'rejected'; reason?: string; created_at: string; expires_at: string; consumed_at?: string | null;
  [k: string]: unknown;
}
export interface DecisionResponse { approval: ApprovalRecord; result: ActionResult }
export interface ActionStatus {
  action: ActionResult;
  link: { customer_id: string; commitment_id: string | null; draft_version_id: string | null; brief_item_id: string | null } | null;
  message_state_definitions: Record<MessageState, string>;
}
export interface ProposeResult {
  action_id: string; state: string | null; message_state: MessageState | null; action_digest: string;
  decision: { code?: string; [k: string]: unknown } | null; human_steps: string[];
}
export interface ApprovalChallenge {
  challenge: string; rp_id: string; action_digest: string; expires_at: string; allow_credentials: string[]; user_verification: string;
}
export interface CustomerDestination {
  id: string; channel: 'sms' | 'email'; value_masked: string; fingerprint: string; is_primary: boolean; source: string; suppressed: boolean;
}
export interface ConsentEventView {
  id: string; channel: string; purposes: string[]; status: string; source: string;
  effective_at: string; expires_at: string; revoked_at: string | null;
}
export interface SuppressionView { id: string; channel: string; reason: string; source: string; created_at: string }
export interface PermissionView { observed_at: string; note: string; consent_events: ConsentEventView[]; suppressions: SuppressionView[] }
export type TimelineEvent =
  | { at: string; type: 'commitment'; data: Commitment }
  | { at: string; type: 'outcome'; data: { id: string; kind: string; commitment_id: string | null; note: string } };
export interface ExtractResult { drafts: (Commitment & { evidence_quote: string })[]; note: string }
export interface OutcomeResult { id: string; kind: string; customer_id: string; commitment_id: string | null; note: string }
export interface InboundHealth {
  health: { last_ok_at: string | null; last_failure_at: string | null; last_failure_reason: string; paused_since: string | null; resumed_at: string | null } | null;
  dispatch_blocked: string | null; pending_events: number; stale_after_secs: number;
}
export interface InboundProcessResult {
  processed: number;
  events: { event_id: string; class: string; customer_id: string | null; matches: number; created: string[]; hold: number | null; marked_processed?: number | null; retry?: boolean }[];
}
export interface SenderIdentity {
  sender_identity_id: string; owner_user_id: string; provider?: string; display_name: string; account_sid_redacted?: string;
  from_number: string | null; messaging_service_sid: string | null; registration_status: string; status: string; created_at?: string;
}
export interface PasskeyInfo {
  credential_row_id: string; label: string; alg: string; created_at: string; last_used_at: string | null; revoked_at: string | null;
}
/** Read-only governance status assembled from `/api/agent-ops/health` (never throws for 503). */
export interface GovernanceStatus {
  /** connected: kernel ready; not_ready: reachable but failing readiness (e.g. database);
   *  unreachable: no answer; not_configured: this environment has no kernel connection. */
  kernel: 'connected' | 'not_ready' | 'unreachable' | 'not_configured';
  code: string | null;
  /** The platform-wide kill switch: false = sending stopped for everyone. Null when unknown. */
  global_dispatch_enabled: boolean | null;
  /** Whether the kernel queues approved actions for execution in this environment. */
  kernel_execution_enabled: boolean | null;
  /** `webauthn` when approvals require a kernel-verified passkey. */
  approval_binding: string | null;
  /** The team (tenant) switch is not exposed by any read route: always null (unknown). */
  team_dispatch_enabled: null;
}

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = ''; for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(pad); const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export type StreamEvent =
  | { type: 'meta'; conversation_id: string }
  | { type: 'delta'; text: string }
  | { type: 'done'; provider: string; model: string }
  | { type: 'error'; message: string };

export class MKClient {
  baseUrl: string;
  tokens: Tokens | null = null;
  onAuthExpired: (() => void) | null = null;
  /** Called on 403 STEP_UP_REQUIRED with the methods the account can use; resolve
   *  true after a successful `stepUp(...)` to have the request retried. */
  onStepUpRequired: ((methods: string[]) => Promise<boolean>) | null = null;

  constructor(baseUrl: string) { this.baseUrl = baseUrl.replace(/\/$/, ''); }

  private headers(json = true): Record<string, string> {
    const h: Record<string, string> = {};
    if (json) h['Content-Type'] = 'application/json';
    if (this.tokens) h['Authorization'] = `Bearer ${this.tokens.access_token}`;
    return h;
  }

  /** fetch with auth headers and one refresh-and-retry on 401. Never throws for HTTP status. */
  private async send(path: string, init: RequestInit = {}, retry = true): Promise<Response> {
    const r = await fetch(this.baseUrl + path, { ...init, headers: { ...this.headers(!(init.body instanceof FormData)), ...(init.headers ?? {}) } });
    if (r.status === 401 && retry && this.tokens?.refresh_token) {
      const ok = await this.refresh();
      if (ok) return this.send(path, init, false);
      this.onAuthExpired?.();
    }
    return r;
  }

  private static async body(r: Response): Promise<unknown> {
    try { return await r.json(); } catch { return undefined; }
  }

  /** Non-2xx → ApiError. A 403 STEP_UP_REQUIRED (sensitive change, factor not fresh)
   *  asks the app to run step-up and retries the original request exactly once. */
  private async fail(path: string, r: Response, again: () => Promise<any>, retry: boolean): Promise<any> {
    const err = apiErrorFrom(r.status, await MKClient.body(r), r.headers.get('Retry-After'));
    if (r.status === 403 && retry && err.code === 'STEP_UP_REQUIRED' && this.onStepUpRequired) {
      if (await this.onStepUpRequired((err.detail as any)?.methods ?? [])) return again();
    }
    throw err;
  }

  private async request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
    const r = await this.send(path, init, retry);
    if (!r.ok) return this.fail(path, r, () => this.request<T>(path, init, false), retry);
    return r.json() as Promise<T>;
  }

  private async text(path: string, retry = true): Promise<string> {
    // No init.headers: they would be captured before a token refresh and override the new token.
    const r = await this.send(path, {}, retry);
    if (!r.ok) return this.fail(path, r, () => this.text(path, false), retry);
    return r.text();
  }

  // ---- auth ----
  async signup(org_name: string, email: string, password: string,
               opts: { key_policy?: string; ref?: string } = {}) {
    this.tokens = await this.request<Tokens>('/api/auth/signup', {
      method: 'POST', body: JSON.stringify({
        org_name, email, password, key_policy: opts.key_policy ?? 'both', ref: opts.ref }) });
    return this.tokens;
  }
  /** Password step. Returns tokens, or an MFA challenge to answer with `verifyMfa`. */
  async login(email: string, password: string): Promise<LoginResult> {
    this.tokens = null;
    const r = await this.request<LoginResult>('/api/auth/login', {
      method: 'POST', body: JSON.stringify({ email, password }) }, false);
    if (!isMfaChallenge(r)) this.tokens = r;
    return r;
  }
  async verifyMfa(mfa_token: string, method: 'totp' | 'recovery' | 'webauthn',
                  answer: { code?: string; credential?: PublicKeyCredentialJSON }) {
    this.tokens = await this.request<Tokens>('/api/auth/mfa/verify', {
      method: 'POST', body: JSON.stringify({ mfa_token, method, ...answer }) }, false);
    return this.tokens;
  }
  loginPasskeyOptions(mfa_token: string) {
    return this.request<any>('/api/auth/mfa/passkey/options', { method: 'POST', body: JSON.stringify({ mfa_token }) }, false);
  }
  async logout() {
    try { if (this.tokens) await this.request('/api/auth/logout', { method: 'POST' }, false); }
    finally { this.tokens = null; }
  }
  changePassword(current_password: string, new_password: string) {
    return this.request<Tokens>('/api/auth/change-password', {
      method: 'POST', body: JSON.stringify({ current_password, new_password }) })
      .then(t => { if ((t as any)?.access_token) this.tokens = t; return t; });
  }
  // ---- MFA factors (S2) ----
  mfaStatus() { return this.request<MfaStatus>('/api/security/mfa'); }
  totpBegin() {
    return this.request<{ factor_id: string; secret: string; otpauth_uri: string; human_steps: string[] }>(
      '/api/security/mfa/totp/begin', { method: 'POST' });
  }
  totpConfirm(factor_id: string, code: string, label = 'Authenticator app') {
    return this.request<{ factor: MfaFactor; recovery_codes: string[] | null }>('/api/security/mfa/totp/confirm', {
      method: 'POST', body: JSON.stringify({ factor_id, code, label }) });
  }
  passkeyBegin() { return this.request<any>('/api/security/mfa/passkey/begin', { method: 'POST' }); }
  passkeyFinish(credential: PublicKeyCredentialJSON, label = 'Passkey') {
    return this.request<{ factor: MfaFactor; recovery_codes: string[] | null }>('/api/security/mfa/passkey/finish', {
      method: 'POST', body: JSON.stringify({ credential, label }) });
  }
  revokeFactor(id: string) { return this.request(`/api/security/mfa/${id}/revoke`, { method: 'POST' }); }
  regenerateRecoveryCodes() {
    return this.request<{ recovery_codes: string[] }>('/api/security/mfa/recovery-codes', { method: 'POST' });
  }
  // ---- step-up ----
  stepUp(method: 'totp' | 'webauthn' | 'password', answer: { code?: string; credential?: PublicKeyCredentialJSON; password?: string }) {
    return this.request<{ ok: boolean }>('/api/security/step-up', {
      method: 'POST', body: JSON.stringify({ method, ...answer }) }, false);
  }
  stepUpPasskeyOptions() { return this.request<any>('/api/security/step-up/passkey/options', { method: 'POST' }); }
  // ---- sessions ----
  sessions() { return this.request<AuthSessionInfo[]>('/api/auth/sessions'); }
  revokeSession(id: string) { return this.request(`/api/auth/sessions/${id}/revoke`, { method: 'POST' }); }
  revokeOtherSessions() { return this.request<{ revoked: number }>('/api/auth/sessions/revoke-others', { method: 'POST' }); }
  // ---- members, roles (S3) ----
  members() { return this.request<Member[]>('/api/security/members'); }
  setMemberRole(uid: string, role: string, works_for?: string | null) {
    return this.request(`/api/security/members/${uid}/role`, { method: 'POST', body: JSON.stringify({ role, works_for: works_for ?? null }) });
  }
  deactivateMember(uid: string) { return this.request(`/api/security/members/${uid}/deactivate`, { method: 'POST' }); }
  revokeMemberSessions(uid: string) { return this.request(`/api/security/members/${uid}/sessions/revoke`, { method: 'POST' }); }
  // ---- break-glass, tenant side (S9) ----
  breakGlassGrants() { return this.request<BreakGlassGrant[]>('/api/security/break-glass'); }
  breakGlassDecide(id: string, decision: 'approve' | 'deny' | 'revoke') {
    return this.request(`/api/security/break-glass/${id}/${decision}`, { method: 'POST' });
  }
  async refresh(): Promise<boolean> {
    try {
      const r = await fetch(this.baseUrl + '/api/auth/refresh', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: this.tokens?.refresh_token }) });
      if (!r.ok) return false;
      this.tokens = await r.json();
      return true;
    } catch { return false; }
  }
  me() { return this.request<any>('/api/auth/me'); }
  addMember(email: string, password: string, role = 'consultant', works_for?: string | null) {
    return this.request('/api/auth/members', {
      method: 'POST', body: JSON.stringify({ email, password, role, works_for: works_for ?? null }) });
  }

  // ---- chat (SSE over fetch) ----
  async chatStream(
    body: { message: string; conversation_id?: string; skill?: string; provider?: string; model?: string },
    onEvent: (ev: StreamEvent) => void, signal?: AbortSignal,
  ): Promise<void> {
    const r = await fetch(this.baseUrl + '/api/chat/stream', {
      method: 'POST', headers: this.headers(), body: JSON.stringify(body), signal });
    if (!r.ok || !r.body) {
      let detail = `HTTP ${r.status}`;
      try { detail = (await r.json()).detail ?? detail; } catch { /* noop */ }
      onEvent({ type: 'error', message: String(detail) });
      return;
    }
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        try { onEvent(JSON.parse(line.slice(5).trim())); } catch { /* partial */ }
      }
    }
  }
  listConversations() { return this.request<any[]>('/api/chat/conversations'); }
  getConversation(id: string) { return this.request<any>(`/api/chat/conversations/${id}`); }
  deleteConversation(id: string) { return this.request(`/api/chat/conversations/${id}`, { method: 'DELETE' }); }
  listSkills() { return this.request<Record<string, { label: string }>>('/api/chat/skills'); }
  listModels() { return this.request<Record<string, { provider: string; vision: boolean }>>('/api/chat/models'); }

  // ---- skin ----
  async analyzeSkin(file: Blob | { uri: string; name: string; type: string },
                    opts: { customer_id?: string; provider?: string; model?: string } = {}) {
    const fd = new FormData();
    fd.append('file', file as any);
    if (opts.customer_id) fd.append('customer_id', opts.customer_id);
    if (opts.provider) fd.append('provider', opts.provider);
    if (opts.model) fd.append('model', opts.model);
    return this.request<{ id: string; provider: string; model: string; result: SkinResult }>(
      '/api/skin/analyze', { method: 'POST', body: fd });
  }
  skinHistory() { return this.request<any[]>('/api/skin/history'); }

  // ---- consent (skin sensitive-data gate) ----
  getSkinConsent() { return this.request<ConsentStatus>('/api/consent/skin'); }
  getCustomerConsent(customer_id: string) {
    return this.request<{ customer_id: string; version: string; customer_consent: boolean; granted_at: string | null }>(
      `/api/consent/skin/customer/${customer_id}`);
  }
  grantSkinConsent(subject: 'operator' | 'customer', customer_id?: string) {
    return this.request<{ ok: boolean; id: string; granted_at: string; version: string }>(
      '/api/consent/skin', { method: 'POST', body: JSON.stringify({ subject, customer_id, accepted: true }) });
  }
  revokeSkinConsent() { return this.request<{ ok: boolean; revoked: number }>('/api/consent/skin', { method: 'DELETE' }); }

  // ---- subject rights (skin data export / deletion) ----
  exportSkinData() { return this.request<any>('/api/me/skin-data/export'); }
  deleteSkinData(customer_id?: string) {
    const q = customer_id ? `?customer_id=${encodeURIComponent(customer_id)}` : '';
    return this.request<any>(`/api/me/skin-data${q}`, { method: 'DELETE' });
  }

  // ---- billing ----
  getBilling() { return this.request<BillingStatus>('/api/billing/me'); }
  getPlans() { return this.request<{ configured: boolean; trial_days: number; plans: Plan[] }>('/api/billing/plans'); }
  checkout(tier: string, interval = 'year') {
    return this.request<{ url: string; session_id: string }>(
      '/api/billing/checkout', { method: 'POST', body: JSON.stringify({ tier, interval }) });
  }
  billingPortal() { return this.request<{ url: string }>('/api/billing/portal', { method: 'POST' }); }

  // ---- customers ----
  listCustomers() { return this.request<Customer[]>('/api/customers'); }
  createCustomer(c: Partial<Customer>) { return this.request<{ id: string }>('/api/customers', { method: 'POST', body: JSON.stringify(c) }); }
  updateCustomer(id: string, c: Partial<Customer>) { return this.request(`/api/customers/${id}`, { method: 'PUT', body: JSON.stringify(c) }); }
  deleteCustomer(id: string) { return this.request(`/api/customers/${id}`, { method: 'DELETE' }); }

  // ---- keys & usage ----
  keyStatus() { return this.request<any>('/api/keys/status'); }
  setMyKey(provider: string, api_key: string, base_url = '') {
    return this.request('/api/keys/mine', { method: 'PUT', body: JSON.stringify({ provider, api_key, base_url }) });
  }
  setTenantKey(provider: string, api_key: string, base_url = '') {
    return this.request('/api/keys/tenant', { method: 'PUT', body: JSON.stringify({ provider, api_key, base_url }) });
  }
  deleteMyKey(provider: string) { return this.request(`/api/keys/mine/${provider}`, { method: 'DELETE' }); }
  myUsage() { return this.request<any[]>('/api/usage/me'); }
  tenantUsage() { return this.request<any[]>('/api/usage/tenant'); }

  // ---- customer foundation (WP03) ----
  customerTimeline(id: string) { return this.request<TimelineEvent[]>(`/api/customers/${id}/timeline`); }
  customerPermissions(id: string) { return this.request<PermissionView>(`/api/customers/${id}/permissions`); }
  customerDestinations(id: string) { return this.request<CustomerDestination[]>(`/api/customers/${id}/destinations`); }
  addDestination(id: string, channel: string, value: string) {
    return this.request<{ id: string; channel: string; value_masked: string; fingerprint: string; is_primary: boolean }>(
      `/api/customers/${id}/destinations`, { method: 'POST', body: JSON.stringify({ channel, value }) });
  }
  setPreferences(id: string, prefs: { timezone?: string; preferred_channel?: 'sms' | 'email'; window_start_hour?: number; window_end_hour?: number; language?: string }) {
    return this.request<{ customer_id: string; timezone: string | null; preferred_channel: string; dispatch_blocked_reason: string | null; version: number }>(
      `/api/customers/${id}/preferences`, { method: 'PUT', body: JSON.stringify(prefs) });
  }
  /** Consent is recorded for ONE destination (the route requires `destination_id`). */
  recordConsent(id: string, body: { destination_id: string; purposes: string[]; source: string; evidence_type: string; evidence_text: string; evidence_ref?: string; expires_in_days?: number }) {
    return this.request<{ id: string; status: string; channel: string; purposes: string[]; effective_at: string; expires_at: string; evidence_digest: string; kernel_permission_id: string }>(
      `/api/customers/${id}/consent`, { method: 'POST', body: JSON.stringify(body) });
  }
  /** `reason` is required by the route (1–120 characters). */
  revokeConsent(id: string, eid: string, reason: string) {
    return this.request<{ id: string; status: string; revoked_at: string }>(`/api/customers/${id}/consent/${eid}/revoke`, { method: 'POST', body: JSON.stringify({ reason }) });
  }
  /** Suppression is filed against a destination on file (the route requires `destination_id`). */
  suppress(body: { destination_id: string; reason: string; source: 'consultant' | 'sms_reply' | 'provider' | 'complaint'; permanent?: boolean }) {
    return this.request<{ id: string; fingerprint: string; channel: string; kernel_suppression_id: string }>('/api/suppressions', { method: 'POST', body: JSON.stringify(body) });
  }

  // ---- commitments & brief (WP04) ----
  brief(date?: string) { return this.request<{ date: string; items: BriefItem[]; generated_at?: string }>(`/api/brief${date ? `?date=${date}` : ''}`); }
  briefItemAction(id: string, action: 'defer' | 'resolve' | 'skip', body: Record<string, unknown> = {}) {
    return this.request<any>(`/api/brief/items/${id}/${action}`, { method: 'POST', body: JSON.stringify(body) });
  }
  listCommitments(customer_id?: string, status?: string) {
    const q = new URLSearchParams(); if (customer_id) q.set('customer_id', customer_id); if (status) q.set('status', status);
    return this.request<Commitment[]>(`/api/commitments${q.toString() ? `?${q}` : ''}`);
  }
  createCommitment(body: Record<string, unknown>) { return this.request<Commitment>('/api/commitments', { method: 'POST', body: JSON.stringify(body) }); }
  confirmCommitment(id: string, body: { absolute_date?: string; relative_window?: string }) {
    return this.request<Commitment>(`/api/commitments/${id}/confirm`, { method: 'POST', body: JSON.stringify(body) });
  }
  deferCommitment(id: string, body: { absolute_date?: string; relative_window?: string; reason?: string }) {
    return this.request<Commitment>(`/api/commitments/${id}/defer`, { method: 'POST', body: JSON.stringify(body) });
  }
  cancelCommitment(id: string, reason = '') { return this.request<Commitment>(`/api/commitments/${id}/cancel`, { method: 'POST', body: JSON.stringify({ reason }) }); }
  extractCommitments(customer_id: string, text: string, provider?: string) {
    return this.request<ExtractResult>('/api/commitments/extract', { method: 'POST', body: JSON.stringify({ customer_id, conversation_text: text, provider }) });
  }
  recordOutcome(body: { customer_id: string; kind: string; commitment_id?: string; note?: string }) {
    return this.request<OutcomeResult>('/api/outcomes', { method: 'POST', body: JSON.stringify(body) });
  }

  // ---- drafting (WP05) ----
  generateDraft(body: { customer_id: string; brief_item_id?: string; commitment_id?: string; product_ids?: string[]; extra_context?: string; provider?: string }) {
    return this.request<DraftResponse>('/api/drafts', { method: 'POST', body: JSON.stringify(body) });
  }
  getDraft(id: string) { return this.request<Draft>(`/api/drafts/${id}`); }
  editDraft(id: string, text: string) { return this.request<Draft>(`/api/drafts/${id}/edit`, { method: 'POST', body: JSON.stringify({ text }) }); }
  liveClaims(product_id?: string) { return this.request<any[]>(`/api/knowledge/claims${product_id ? `?product_id=${product_id}` : ''}`); }

  // ---- outreach, approvals, passkeys (WP06–WP08) ----
  /** Proposes the exact draft version. Scheduling is deliberately not exposed: the
   *  approval list does not yet echo a proposal's schedule (see report), so offering it
   *  would show approvers the wrong "When". */
  proposeDraft(id: string) {
    return this.request<ProposeResult>(`/api/drafts/${id}/propose`, { method: 'POST', body: '{}' });
  }
  pendingApprovals() { return this.request<PendingApproval[]>('/api/approvals/pending'); }
  actionStatus(id: string) { return this.request<ActionStatus>(`/api/actions/${encodeURIComponent(id)}`); }
  approvalChallenge(action_id: string) {
    return this.request<ApprovalChallenge>(`/api/agent-ops/actions/${encodeURIComponent(action_id)}/approval-challenge`, { method: 'POST', body: '{}' });
  }
  approve(action_id: string, action_digest: string, webauthn: WebAuthnAssertion, reason?: string) {
    return this.request<DecisionResponse>(`/api/agent-ops/actions/${encodeURIComponent(action_id)}/approve`, { method: 'POST', body: JSON.stringify({ action_digest, webauthn, reason }) });
  }
  reject(action_id: string, action_digest: string, reason?: string) {
    return this.request<DecisionResponse>(`/api/agent-ops/actions/${encodeURIComponent(action_id)}/reject`, { method: 'POST', body: JSON.stringify({ action_digest, reason }) });
  }
  /** Withdraw a proposal before it is submitted (the kernel decides whether it still can). */
  cancelAction(action_id: string) {
    return this.request<ActionResult>(`/api/agent-ops/actions/${encodeURIComponent(action_id)}/cancel`, { method: 'POST', body: '{}' });
  }
  passkeyRegisterBegin() { return this.request<any>('/api/agent-ops/approval-credentials/register/begin', { method: 'POST', body: '{}' }); }
  passkeyRegisterFinish(body: { client_data_json: string; attestation_object: string; label: string }) {
    return this.request<any>('/api/agent-ops/approval-credentials/register/finish', { method: 'POST', body: JSON.stringify(body) });
  }
  passkeys() { return this.request<PasskeyInfo[]>('/api/agent-ops/approval-credentials'); }
  revokePasskey(row_id: string) { return this.request<any>(`/api/agent-ops/approval-credentials/${row_id}/revoke`, { method: 'POST', body: '{}' }); }
  revokeMySession(reason = '') { return this.request<any>('/api/agent-ops/revocations', { method: 'POST', body: JSON.stringify({ reason }) }); }

  /** Sign-in passkeys (S2), separate from the kernel's approval passkeys: the app
   *  server issues and verifies these challenges (py_webauthn JSON options). */
  async addSignInPasskey(label = 'Passkey') {
    const o = await this.passkeyBegin();
    const cred = await navigator.credentials.create({ publicKey: {
      ...o, challenge: b64urlDecode(o.challenge), user: { ...o.user, id: b64urlDecode(o.user.id) },
      excludeCredentials: (o.excludeCredentials ?? []).map((c: any) => ({ ...c, id: b64urlDecode(c.id) })),
    } }) as PublicKeyCredential | null;
    if (!cred) throw new Error('No passkey was created.');
    const att = cred.response as AuthenticatorAttestationResponse;
    return this.passkeyFinish({ id: cred.id, rawId: b64url(cred.rawId), type: cred.type,
      response: { clientDataJSON: b64url(att.clientDataJSON), attestationObject: b64url(att.attestationObject) } }, label);
  }
  private async getAssertion(o: any): Promise<PublicKeyCredentialJSON> {
    const cred = await navigator.credentials.get({ publicKey: {
      ...o, challenge: b64urlDecode(o.challenge),
      allowCredentials: (o.allowCredentials ?? []).map((c: any) => ({ ...c, id: b64urlDecode(c.id) })),
    } }) as PublicKeyCredential | null;
    if (!cred) throw new Error('The passkey prompt was cancelled.');
    const a = cred.response as AuthenticatorAssertionResponse;
    return { id: cred.id, rawId: b64url(cred.rawId), type: cred.type,
      response: { clientDataJSON: b64url(a.clientDataJSON), authenticatorData: b64url(a.authenticatorData),
                  signature: b64url(a.signature), userHandle: a.userHandle ? b64url(a.userHandle) : null } };
  }
  async signInWithPasskey(mfa_token: string) {
    return this.verifyMfa(mfa_token, 'webauthn', { credential: await this.getAssertion(await this.loginPasskeyOptions(mfa_token)) });
  }
  async stepUpWithPasskey() {
    return this.stepUp('webauthn', { credential: await this.getAssertion(await this.stepUpPasskeyOptions()) });
  }

  /** Full passkey registration ceremony in the browser. The kernel issued the challenge and verifies the result. */
  async registerPasskey(label: string) {
    const b = await this.passkeyRegisterBegin();
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: b64urlDecode(b.challenge), rp: { id: b.rp_id, name: 'Consultant Studio approvals' },
      user: { id: b64urlDecode(b64url(new TextEncoder().encode(b.user_id))), name: label, displayName: label },
      pubKeyCredParams: b.pub_key_cred_params, authenticatorSelection: b.authenticator_selection, attestation: 'none',
      excludeCredentials: (b.exclude_credentials as string[]).map(id => ({ type: 'public-key', id: b64urlDecode(id) })),
    } }) as PublicKeyCredential | null;
    if (!cred) throw new Error('No passkey was created.');
    const att = cred.response as AuthenticatorAttestationResponse;
    return this.passkeyRegisterFinish({ client_data_json: b64url(att.clientDataJSON), attestation_object: b64url(att.attestationObject), label });
  }

  /** One explicit approval gesture: fetch the digest-bound challenge, sign it with the passkey, submit.
   *  If the kernel's challenge is for a different digest than the one displayed, no passkey
   *  prompt is shown and nothing is submitted: the caller gets the same APPROVAL_DIGEST_MISMATCH
   *  the kernel would return, so web and mobile handle both paths identically. */
  async approveWithPasskey(action_id: string, action_digest: string, reason?: string) {
    const ch = await this.approvalChallenge(action_id);
    if (ch.action_digest !== action_digest) {
      throw new ApiError(409, { code: 'APPROVAL_DIGEST_MISMATCH', message: 'This message changed since it was displayed.', detected: 'client' });
    }
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: b64urlDecode(ch.challenge), rpId: ch.rp_id, userVerification: ch.user_verification as UserVerificationRequirement,
      allowCredentials: ch.allow_credentials.map(id => ({ type: 'public-key', id: b64urlDecode(id) })),
    } }) as PublicKeyCredential | null;
    if (!cred) throw new Error('Approval was cancelled.');
    const a = cred.response as AuthenticatorAssertionResponse;
    return this.approve(action_id, action_digest, {
      credential_id: b64url(cred.rawId), client_data_json: b64url(a.clientDataJSON),
      authenticator_data: b64url(a.authenticatorData), signature: b64url(a.signature),
    }, reason);
  }

  // ---- inbound, exceptions (WP07) ----
  processInbound(limit = 50) { return this.request<InboundProcessResult>('/api/inbound/process', { method: 'POST', body: JSON.stringify({ limit }) }); }
  listExceptions(state: 'open' | 'resolved' | 'dismissed' | 'all' = 'open') { return this.request<ExceptionItem[]>(`/api/exceptions?state=${state}`); }
  resolveException(id: string, resolution: 'resolved' | 'dismissed', note = '') {
    return this.request<ExceptionItem>(`/api/exceptions/${id}/resolve`, { method: 'POST', body: JSON.stringify({ resolution, note }) });
  }
  inboundHealth() { return this.request<InboundHealth>('/api/agent-ops/inbound/health'); }
  senders() { return this.request<SenderIdentity[]>('/api/agent-ops/senders'); }
  registerSender(body: { owner_user_id: string; display_name: string; account_sid: string; auth_token: string; from_number?: string; messaging_service_sid?: string }) {
    return this.request<any>('/api/agent-ops/senders', { method: 'POST', body: JSON.stringify(body) });
  }
  kernelHealth() { return this.request<any>('/api/agent-ops/health'); }

  /**
   * Read-only governance status: is the kernel reachable and ready, is the platform kill
   * switch on, does the kernel queue approved actions here. A 503 is a status to show,
   * not an exception; 401 and other failures still throw ApiError.
   */
  async governanceStatus(): Promise<GovernanceStatus> {
    const r = await this.send('/api/agent-ops/health');
    const body = await MKClient.body(r);
    return governanceStatusFrom(r.status, body);
  }

  // ---- exports & deletion (account) ----
  exportAccount() { return this.request<any>('/api/account/export'); }
  exportAudit() { return this.text('/api/audit/export.jsonl'); }
  exportCustomersCsv() { return this.text('/api/customers/export.csv'); }
  deleteAccount(body: { password: string }) { return this.request<any>('/api/account', { method: 'DELETE', body: JSON.stringify(body) }); }
}

/** Pure mapping of `/api/agent-ops/health` responses (exported for tests). */
export function governanceStatusFrom(status: number, body: unknown): GovernanceStatus {
  const unknownStatus = (kernel: GovernanceStatus['kernel'], code: string | null): GovernanceStatus =>
    ({ kernel, code, global_dispatch_enabled: null, kernel_execution_enabled: null, approval_binding: null, team_dispatch_enabled: null });
  const rec = (v: unknown): Record<string, unknown> | null => (typeof v === 'object' && v !== null && !Array.isArray(v) ? v as Record<string, unknown> : null);
  const b = rec(body);
  const k = rec(b?.kernel);
  const bool = (v: unknown) => (typeof v === 'boolean' ? v : null);
  if ((status === 200 || status === 503) && k) {
    const configured = b?.configured !== false;
    const ready = status === 200 && k.database === true;
    return {
      kernel: !configured ? 'not_configured' : ready ? 'connected' : 'not_ready', code: null,
      global_dispatch_enabled: bool(k.dispatch_enabled), kernel_execution_enabled: bool(k.rust_kernel_enabled),
      approval_binding: typeof rec(k.effective)?.approval_binding === 'string' ? rec(k.effective)!.approval_binding as string : null,
      team_dispatch_enabled: null,
    };
  }
  if (status === 401) throw apiErrorFrom(status, body);
  const err = apiErrorFrom(status, body);
  if (status === 503) return unknownStatus(err.code === 'KERNEL_NOT_CONFIGURED' ? 'not_configured' : 'unreachable', err.code ?? null);
  throw err;
}

export * from './vocabulary';
export * from './labels';
export * from './errors';
export * from './handoff';
export * from './approval';
export * from './governance';
export * from './days';
