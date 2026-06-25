import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import type { BillingStatus, Plan } from '../../../packages/sdk/src/index.ts';

const TIER_LABEL: Record<string, string> = {
  solo: 'Solo', director: 'Director', leader: 'Leader', studio: 'Studio',
};
const STATUS_LABEL: Record<string, string> = {
  none: 'No subscription yet', trialing: 'Free trial', active: 'Active',
  past_due: 'Payment past due', canceled: 'Canceled', incomplete: 'Incomplete',
};

export default function BillingView() {
  const [bill, setBill] = useState<BillingStatus | null>(null);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [trialDays, setTrialDays] = useState(90);
  const [configured, setConfigured] = useState(true);
  const [busy, setBusy] = useState('');
  const [err, setErr] = useState('');

  useEffect(() => {
    client.getBilling().then(setBill).catch(e => setErr(e.message));
    client.getPlans().then(p => { setPlans(p.plans); setTrialDays(p.trial_days); setConfigured(p.configured); })
      .catch(() => {});
  }, []);

  async function startCheckout(tier: string, interval: string) {
    setBusy(`${tier}:${interval}`); setErr('');
    try {
      const { url } = await client.checkout(tier, interval);
      window.location.href = url;            // hand off to Stripe Checkout
    } catch (e: any) { setErr(e.message); setBusy(''); }
  }

  async function openPortal() {
    setBusy('portal'); setErr('');
    try { const { url } = await client.billingPortal(); window.location.href = url; }
    catch (e: any) { setErr(e.message); setBusy(''); }
  }

  const referralLink = bill?.referral_code
    ? `${window.location.origin}/?ref=${bill.referral_code}` : '';
  const active = bill?.active;

  // Group plans by tier so annual shows first (annual-first).
  const tiers = Array.from(new Set(plans.map(p => p.tier)));
  const intervalsFor = (t: string) =>
    plans.filter(p => p.tier === t).map(p => p.interval).sort((a) => (a === 'year' ? -1 : 1));

  return (
    <div>
      <h1>Plan &amp; billing</h1>

      {bill && (
        <div className="card" style={{ maxWidth: 720, marginBottom: 20 }}>
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <div>
              <div className="level">Current plan</div>
              <div style={{ fontSize: 20 }}>
                {STATUS_LABEL[bill.status] ?? bill.status}
                {bill.tier && <> · {TIER_LABEL[bill.tier] ?? bill.tier}</>}
                {bill.interval && <span className="muted"> / {bill.interval}</span>}
              </div>
              {bill.trial_end && bill.status === 'trialing' && (
                <div className="muted" style={{ fontSize: 13 }}>
                  Trial ends {new Date(bill.trial_end).toLocaleDateString()}
                </div>
              )}
            </div>
            {active && (
              <button className="btn ghost" disabled={busy === 'portal'} onClick={openPortal}>
                {busy === 'portal' ? 'Opening…' : 'Manage / cancel'}
              </button>
            )}
          </div>
        </div>
      )}

      {!configured && (
        <div className="card" style={{ maxWidth: 720, marginBottom: 20 }}>
          <p className="muted" style={{ margin: 0 }}>
            Billing isn't switched on for this server yet. (Set your Stripe keys and prices to enable checkout.)
          </p>
        </div>
      )}

      {err && <div className="error" role="alert" style={{ marginBottom: 14 }}>{err}</div>}

      {!active && configured && (
        <>
          <p className="muted" style={{ maxWidth: 640 }}>
            Start with a {trialDays}-day free trial. Annual is the best value — cancel anytime.
          </p>
          <div className="plan-grid">
            {tiers.map(t => (
              <div className="card plan" key={t}>
                <h3 style={{ marginTop: 0 }}>{TIER_LABEL[t] ?? t}</h3>
                <div className="row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
                  {intervalsFor(t).map(interval => (
                    <button key={interval} className={interval === 'year' ? 'btn' : 'btn ghost'}
                            disabled={busy === `${t}:${interval}`}
                            onClick={() => startCheckout(t, interval)}>
                      {busy === `${t}:${interval}` ? 'Redirecting…'
                        : interval === 'year' ? 'Start yearly (best value)' : 'Start monthly'}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {bill?.referral_code && (
        <div className="card" style={{ maxWidth: 720, marginTop: 24 }}>
          <h3 style={{ marginTop: 0 }}>Refer a fellow consultant</h3>
          <p className="muted" style={{ marginTop: 0 }}>
            Share your link. When someone you refer subscribes, you get account credit.
            {bill.referral_count > 0 && (
              <> You've earned <strong>${(bill.referral_credits_earned_cents / 100).toFixed(2)}</strong>{' '}
                from {bill.referral_count} referral{bill.referral_count > 1 ? 's' : ''}.</>
            )}
          </p>
          <div className="row">
            <input readOnly value={referralLink} style={{ flex: 1 }}
                   onFocus={e => e.currentTarget.select()} />
            <button className="btn ghost" onClick={() => navigator.clipboard.writeText(referralLink)}>
              Copy link
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
