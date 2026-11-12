/**
 * MK Harness SDK — single client for web (fetch/ReadableStream) and
 * React Native (fetch + XHR streaming fallback).
 */
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


// ---- WP03–WP08 types (contract vocabulary; definitions come from the API, never paraphrased) ----
export type MessageState =
  | 'proposed' | 'awaiting_approval' | 'approved' | 'queued' | 'dispatch_authorized' | 'submission_started'
  | 'provider_accepted' | 'sent' | 'delivered' | 'failed' | 'delivery_unknown' | 'submission_unknown'
  | 'cancelled' | 'denied' | 'expired';
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

/** Structured API error: `status` is the HTTP code, `detail` is the parsed body's
 *  `detail` field — a string, or an object like { code, message } for gated routes. */
export class ApiError extends Error {
  status: number; detail: any;
  constructor(status: number, detail: any) {
    super(typeof detail === 'string' ? detail : (detail?.message ?? `HTTP ${status}`));
    this.status = status; this.detail = detail; this.name = 'ApiError';
  }
  get code(): string | undefined {
    return this.detail && typeof this.detail === 'object' ? this.detail.code : undefined;
  }
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

  private async request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
    const r = await fetch(this.baseUrl + path, { ...init, headers: { ...this.headers(!(init.body instanceof FormData)), ...(init.headers ?? {}) } });
    if (r.status === 401 && retry && this.tokens?.refresh_token) {
      const ok = await this.refresh();
      if (ok) return this.request<T>(path, init, false);
      this.onAuthExpired?.();
    }
    if (!r.ok) {
      let detail: any = `HTTP ${r.status}`;
      try { detail = (await r.json()).detail ?? detail; } catch { /* keep status */ }
      // Sensitive change on a session whose factor is not fresh: ask the app to run
      // step-up (403 STEP_UP_REQUIRED), then retry the original request once.
      if (r.status === 403 && retry && detail?.code === 'STEP_UP_REQUIRED' && this.onStepUpRequired) {
        if (await this.onStepUpRequired(detail.methods ?? [])) return this.request<T>(path, init, false);
      }
      throw new ApiError(r.status, detail);
    }
    return r.json() as Promise<T>;
  }

  private async requestText(path: string, retry = true): Promise<string> {
    const r = await fetch(this.baseUrl + path, { headers: this.headers(false) });
    if (r.status === 401 && retry && this.tokens?.refresh_token) {
      if (await this.refresh()) return this.requestText(path, false);
      this.onAuthExpired?.();
    }
    if (!r.ok) {
      let detail: any = `HTTP ${r.status}`;
      try { detail = (await r.json()).detail ?? detail; } catch { /* keep status */ }
      if (r.status === 403 && retry && detail?.code === 'STEP_UP_REQUIRED' && this.onStepUpRequired) {
        if (await this.onStepUpRequired(detail.methods ?? [])) return this.requestText(path, false);
      }
      throw new ApiError(r.status, detail);
    }
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
  customerTimeline(id: string) { return this.request<any[]>(`/api/customers/${id}/timeline`); }
  customerPermissions(id: string) { return this.request<any>(`/api/customers/${id}/permissions`); }
  customerDestinations(id: string) { return this.request<any[]>(`/api/customers/${id}/destinations`); }
  addDestination(id: string, channel: string, value: string) {
    return this.request<any>(`/api/customers/${id}/destinations`, { method: 'POST', body: JSON.stringify({ channel, value }) });
  }
  setPreferences(id: string, prefs: { timezone?: string; preferred_channel?: string; do_not_contact?: boolean }) {
    return this.request(`/api/customers/${id}/preferences`, { method: 'PUT', body: JSON.stringify(prefs) });
  }
  recordConsent(id: string, body: { purposes: string[]; source: string; evidence_type: string; evidence_text: string }) {
    return this.request<any>(`/api/customers/${id}/consent`, { method: 'POST', body: JSON.stringify(body) });
  }
  revokeConsent(id: string, eid: string, reason = '') {
    return this.request(`/api/customers/${id}/consent/${eid}/revoke`, { method: 'POST', body: JSON.stringify({ reason }) });
  }
  suppress(body: { channel: string; destination?: string; destination_hash?: string; reason: string; permanent: boolean; source: string }) {
    return this.request<any>('/api/suppressions', { method: 'POST', body: JSON.stringify(body) });
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
    return this.request<any>('/api/commitments/extract', { method: 'POST', body: JSON.stringify({ customer_id, conversation_text: text, provider }) });
  }
  recordOutcome(body: { customer_id: string; kind: string; commitment_id?: string; note?: string }) {
    return this.request<any>('/api/outcomes', { method: 'POST', body: JSON.stringify(body) });
  }

  // ---- drafting (WP05) ----
  generateDraft(body: { customer_id: string; brief_item_id?: string; commitment_id?: string; product_ids?: string[]; extra_context?: string; provider?: string }) {
    return this.request<DraftResponse>('/api/drafts', { method: 'POST', body: JSON.stringify(body) });
  }
  getDraft(id: string) { return this.request<Draft>(`/api/drafts/${id}`); }
  editDraft(id: string, text: string) { return this.request<Draft>(`/api/drafts/${id}/edit`, { method: 'POST', body: JSON.stringify({ text }) }); }
  liveClaims(product_id?: string) { return this.request<any[]>(`/api/knowledge/claims${product_id ? `?product_id=${product_id}` : ''}`); }

  // ---- outreach, approvals, passkeys (WP06–WP08) ----
  proposeDraft(id: string, body: { scheduled_for?: string } = {}) {
    return this.request<any>(`/api/drafts/${id}/propose`, { method: 'POST', body: JSON.stringify(body) });
  }
  pendingApprovals() { return this.request<PendingApproval[]>('/api/approvals/pending'); }
  actionStatus(id: string) { return this.request<{ action: any; link: any; message_state_definitions: Record<MessageState, string> }>(`/api/actions/${id}`); }
  approvalChallenge(action_id: string) {
    return this.request<{ challenge: string; rp_id: string; action_digest: string; expires_at: string; allow_credentials: string[]; user_verification: string }>(
      `/api/agent-ops/actions/${action_id}/approval-challenge`, { method: 'POST', body: '{}' });
  }
  approve(action_id: string, action_digest: string, webauthn: WebAuthnAssertion, reason?: string) {
    return this.request<any>(`/api/agent-ops/actions/${action_id}/approve`, { method: 'POST', body: JSON.stringify({ action_digest, webauthn, reason }) });
  }
  reject(action_id: string, action_digest: string, reason?: string) {
    return this.request<any>(`/api/agent-ops/actions/${action_id}/reject`, { method: 'POST', body: JSON.stringify({ action_digest, reason }) });
  }
  passkeyRegisterBegin() { return this.request<any>('/api/agent-ops/approval-credentials/register/begin', { method: 'POST', body: '{}' }); }
  passkeyRegisterFinish(body: { client_data_json: string; attestation_object: string; label: string }) {
    return this.request<any>('/api/agent-ops/approval-credentials/register/finish', { method: 'POST', body: JSON.stringify(body) });
  }
  passkeys() { return this.request<any[]>('/api/agent-ops/approval-credentials'); }
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

  /** One explicit approval gesture: fetch the digest-bound challenge, sign it with the passkey, submit. */
  async approveWithPasskey(action_id: string, action_digest: string, reason?: string) {
    const ch = await this.approvalChallenge(action_id);
    if (ch.action_digest !== action_digest) throw new Error('This message changed since it was displayed. Review it again before approving.');
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
  processInbound(limit = 50) { return this.request<any>('/api/inbound/process', { method: 'POST', body: JSON.stringify({ limit }) }); }
  listExceptions(state: 'open' | 'resolved' | 'dismissed' | 'all' = 'open') { return this.request<ExceptionItem[]>(`/api/exceptions?state=${state}`); }
  resolveException(id: string, resolution: 'resolved' | 'dismissed', note = '') {
    return this.request<ExceptionItem>(`/api/exceptions/${id}/resolve`, { method: 'POST', body: JSON.stringify({ resolution, note }) });
  }
  inboundHealth() { return this.request<any>('/api/agent-ops/inbound/health'); }
  senders() { return this.request<any[]>('/api/agent-ops/senders'); }
  registerSender(body: { owner_user_id: string; display_name: string; account_sid: string; auth_token: string; from_number?: string; messaging_service_sid?: string }) {
    return this.request<any>('/api/agent-ops/senders', { method: 'POST', body: JSON.stringify(body) });
  }
  kernelHealth() { return this.request<any>('/api/agent-ops/health'); }

  // ---- exports & deletion (account) ----
  exportAccount() { return this.request<any>('/api/account/export'); }
  // Exports need step-up: they go through the same refresh/step-up/error path as JSON
  // calls (a raw fetch returned the error body as if it were the export).
  exportAudit() { return this.requestText('/api/audit/export.jsonl'); }
  exportCustomersCsv() { return this.requestText('/api/customers/export.csv'); }
  deleteAccount(body: { password: string }) { return this.request<any>('/api/account', { method: 'DELETE', body: JSON.stringify(body) }); }
}
