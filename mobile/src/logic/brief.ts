/**
 * Daily brief presentation (W2/W3). The server's ranking is authoritative: items arrive
 * ordered by category, due time, age and id. Grouping never reorders within a category,
 * never drops an item, and puts categories the app does not know at the end, labelled.
 */
import { BRIEF_SECTIONS, briefRuleLabel, permissionLabel } from '../../../packages/sdk/src/index';
import type { BriefItem } from '../../../packages/sdk/src/index';

export interface BriefSection { rank: number | null; title: string; description: string; items: BriefItem[] }

export function groupBrief(items: readonly BriefItem[]): BriefSection[] {
  const seen = new Set<string>();
  const byRank = new Map<number | null, BriefItem[]>();
  for (const it of items) {
    if (!it || typeof it.id !== 'string' || seen.has(it.id)) continue; // a repeated id is shown once
    seen.add(it.id);
    const known = BRIEF_SECTIONS.some(s => s.rank === it.rank_category);
    const key = known ? it.rank_category : null;
    const list = byRank.get(key) ?? [];
    list.push(it);
    byRank.set(key, list);
  }
  const out: BriefSection[] = [];
  for (const s of BRIEF_SECTIONS) {
    const list = byRank.get(s.rank);
    if (list?.length) out.push({ rank: s.rank, title: s.title, description: s.description, items: list });
  }
  const other = byRank.get(null);
  if (other?.length) out.push({ rank: null, title: 'Other', description: 'Items in a category this app does not recognise. Review them on the web app.', items: other });
  return out;
}

export function briefItemTag(it: BriefItem): string {
  return briefRuleLabel(it.rule);
}

/** Drafting is offered only when the last observation says permission is active and a
 *  customer is attached; the kernel still re-checks at send time. */
export function canDraft(it: BriefItem): boolean {
  return !!it.customer && it.permission_state === 'active';
}

export function permissionLine(it: BriefItem, formatWhen: (iso: string) => string): string {
  const when = it.permission_checked_at ? formatWhen(it.permission_checked_at) : 'time not reported';
  return `${permissionLabel(it.permission_state)} (checked ${when}) — ${it.permission_note}`;
}
