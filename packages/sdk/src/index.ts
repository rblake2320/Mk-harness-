/**
 * MK Harness SDK — single client for web (fetch/ReadableStream) and
 * React Native (fetch + XHR streaming fallback).
 */
export interface Tokens {
  access_token: string; refresh_token: string;
  role: string; display_name: string; tenant_id: string;
}
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
      throw new ApiError(r.status, detail);
    }
    return r.json() as Promise<T>;
  }

  // ---- auth ----
  async signup(org_name: string, email: string, password: string,
               opts: { key_policy?: string; ref?: string } = {}) {
    this.tokens = await this.request<Tokens>('/api/auth/signup', {
      method: 'POST', body: JSON.stringify({
        org_name, email, password, key_policy: opts.key_policy ?? 'both', ref: opts.ref }) });
    return this.tokens;
  }
  async login(email: string, password: string) {
    this.tokens = await this.request<Tokens>('/api/auth/login', {
      method: 'POST', body: JSON.stringify({ email, password }) });
    return this.tokens;
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
  addMember(email: string, password: string, role = 'consultant') {
    return this.request('/api/auth/members', {
      method: 'POST', body: JSON.stringify({ email, password, role }) });
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
  searchCustomers(query: string, offset = 0) {
    return this.request<{ items: Customer[]; next_offset: number | null }>('/api/customers/search', {
      method: 'POST', body: JSON.stringify({ query, offset, limit: 50 }),
    });
  }
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
  exportAudit() { return fetch(this.baseUrl + '/api/audit/export.jsonl', { headers: this.headers(false) }).then(r => r.text()); }
  exportCustomersCsv() { return fetch(this.baseUrl + '/api/customers/export.csv', { headers: this.headers(false) }).then(r => r.text()); }
  deleteAccount(body: { password: string }) { return this.request<any>('/api/account', { method: 'DELETE', body: JSON.stringify(body) }); }
}
