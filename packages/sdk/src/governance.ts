/**
 * Read-only "can anything be sent right now, and if not, why" summary for the
 * governance/status view on web and mobile. It reports only what the API reports;
 * where the API is silent (the team's own kill switch has no read route) it says
 * "not reported" instead of assuming a value.
 */
import type { GovernanceStatus, InboundHealth } from './index';
import { inboundBlockLabel } from './labels';

export interface StatusLine {
  key: 'kernel' | 'global_switch' | 'kernel_execution' | 'team_switch' | 'reply_path' | 'approval_binding';
  label: string;
  value: string;
  /** ok: nothing blocking; blocked: sending cannot happen; unknown: the API does not say. */
  level: 'ok' | 'blocked' | 'unknown';
}

export interface DispatchSummary {
  /** One sentence for the top of the screen. */
  headline: string;
  /** True only when every reported gate is open. Even then each message still needs
   *  its own approval and passes the kernel's checks at send time. */
  allowed: boolean;
  lines: StatusLine[];
}

const KERNEL_TEXT: Record<GovernanceStatus['kernel'], string> = {
  connected: 'Connected',
  not_ready: 'Reachable but not ready — approvals and sending are unavailable',
  unreachable: 'Unreachable — approvals and sending are unavailable',
  not_configured: 'Not configured in this environment — approvals and sending are unavailable',
};

export function dispatchSummary(status: GovernanceStatus, inbound: InboundHealth | null): DispatchSummary {
  const lines: StatusLine[] = [];
  lines.push({ key: 'kernel', label: 'Action kernel', value: KERNEL_TEXT[status.kernel] ?? 'Not reported', level: status.kernel === 'connected' ? 'ok' : 'blocked' });

  const g = status.global_dispatch_enabled;
  lines.push({ key: 'global_switch', label: 'Platform kill switch',
    value: g === true ? 'Off — the platform allows sending' : g === false ? 'On — sending is stopped for every team' : 'Not reported',
    level: g === true ? 'ok' : g === false ? 'blocked' : 'unknown' });

  const x = status.kernel_execution_enabled;
  lines.push({ key: 'kernel_execution', label: 'Kernel execution',
    value: x === true ? 'Enabled — approved messages are queued for sending' : x === false ? 'Disabled in this environment — approved messages are not queued' : 'Not reported',
    level: x === true ? 'ok' : x === false ? 'blocked' : 'unknown' });

  lines.push({ key: 'team_switch', label: 'Your team’s kill switch', value: 'Not reported by the API — ask your admin', level: 'unknown' });

  if (inbound) {
    const block = inboundBlockLabel(inbound.dispatch_blocked);
    lines.push({ key: 'reply_path', label: 'Reply path', value: block ? `Paused — ${block}` : `Healthy · ${inbound.pending_events} unprocessed repl${inbound.pending_events === 1 ? 'y' : 'ies'}`, level: block ? 'blocked' : 'ok' });
  } else {
    lines.push({ key: 'reply_path', label: 'Reply path', value: 'Not reported', level: 'unknown' });
  }

  const b = status.approval_binding;
  lines.push({ key: 'approval_binding', label: 'Approval method',
    value: b === 'webauthn' ? 'Passkey verified by the kernel' : b ? `Not passkey-bound (${b}) — development only` : 'Not reported',
    level: b === 'webauthn' ? 'ok' : b ? 'blocked' : 'unknown' });

  const blocked = lines.filter(l => l.level === 'blocked');
  const allowed = blocked.length === 0 && lines.filter(l => l.key !== 'team_switch').every(l => l.level === 'ok');
  const headline = blocked.length > 0
    ? `Sending is not possible right now: ${blocked.map(l => l.label.toLowerCase()).join(', ')}.`
    : allowed
      ? 'Sending is allowed by every gate the API reports. Each message still needs its own approval and passes the kernel’s checks when it is sent.'
      : 'Some gates are not reported, so whether sending is possible is unknown.';
  return { headline, allowed, lines };
}
