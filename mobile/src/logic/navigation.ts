/**
 * App navigation as plain state: five tabs, each with its own stack of pushed screens.
 * Pure (no React Native imports) so it is unit-tested; App.tsx holds it in useReducer
 * and maps the Android back button to `back`.
 */
export type Tab = 'brief' | 'approvals' | 'inbox' | 'customers' | 'more';
export const TABS: readonly { id: Tab; label: string }[] = [
  { id: 'brief', label: 'Brief' }, { id: 'approvals', label: 'Approvals' }, { id: 'inbox', label: 'Inbox' },
  { id: 'customers', label: 'Customers' }, { id: 'more', label: 'More' },
];

export type Route =
  | { name: 'customer'; customerId: string; customerName: string }
  | { name: 'draft'; customerId: string; customerName: string; briefItemId?: string; commitmentId?: string }
  | { name: 'status' }
  | { name: 'chat' }
  | { name: 'skin' };

export interface NavState {
  tab: Tab;
  stacks: Record<Tab, Route[]>;
  /** An action the approvals screen should bring into view and re-read (from a return link). */
  focusActionId: string | null;
}

export type NavAction =
  | { type: 'tab'; tab: Tab }
  | { type: 'push'; route: Route }
  | { type: 'back' }
  | { type: 'focusApproval'; actionId: string }
  | { type: 'clearFocus' };

export const MAX_STACK = 8;

export function initialNav(): NavState {
  return { tab: 'brief', stacks: { brief: [], approvals: [], inbox: [], customers: [], more: [] }, focusActionId: null };
}

export function navReducer(s: NavState, a: NavAction): NavState {
  switch (a.type) {
    case 'tab':
      // Re-selecting the current tab returns to its root, like platform tab bars.
      if (a.tab === s.tab) return s.stacks[s.tab].length ? { ...s, stacks: { ...s.stacks, [s.tab]: [] } } : s;
      return { ...s, tab: a.tab };
    case 'push': {
      const stack = s.stacks[s.tab];
      const top = stack[stack.length - 1];
      if (top && JSON.stringify(top) === JSON.stringify(a.route)) return s; // double tap
      const next = [...stack, a.route].slice(-MAX_STACK);
      return { ...s, stacks: { ...s.stacks, [s.tab]: next } };
    }
    case 'back': {
      const stack = s.stacks[s.tab];
      if (stack.length === 0) return s;
      return { ...s, stacks: { ...s.stacks, [s.tab]: stack.slice(0, -1) } };
    }
    case 'focusApproval':
      return { ...s, tab: 'approvals', stacks: { ...s.stacks, approvals: [] }, focusActionId: a.actionId };
    case 'clearFocus':
      return s.focusActionId === null ? s : { ...s, focusActionId: null };
    default:
      return s;
  }
}

/** True when `back` would change something; Android's back button exits the app otherwise. */
export function canGoBack(s: NavState): boolean {
  return s.stacks[s.tab].length > 0;
}

export function currentRoute(s: NavState): Route | null {
  const stack = s.stacks[s.tab];
  return stack.length ? stack[stack.length - 1] : null;
}
