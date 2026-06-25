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
export interface Suggestion extends Customer {
  days_since_contact: number | null; urgency: string;
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
  suggestions() { return this.request<Suggestion[]>('/api/customers/suggestions'); }
  listCustomers() { return this.request<Customer[]>('/api/customers'); }
  createCustomer(c: Partial<Customer>) { return this.request<{ id: string }>('/api/customers', { method: 'POST', body: JSON.stringify(c) }); }
  updateCustomer(id: string, c: Partial<Customer>) { return this.request(`/api/customers/${id}`, { method: 'PUT', body: JSON.stringify(c) }); }
  deleteCustomer(id: string) { return this.request(`/api/customers/${id}`, { method: 'DELETE' }); }
  followUp(id: string, goal: string, provider?: string) {
    return this.request<{ drafts: string; provider: string; model: string }>(
      `/api/customers/${id}/follow-up`, { method: 'POST', body: JSON.stringify({ goal, provider }) });
  }

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
}
