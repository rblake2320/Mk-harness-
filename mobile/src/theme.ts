/**
 * Visual tokens shared by every mobile screen. No React Native imports, so the
 * accessibility test can read MIN_TOUCH directly.
 */
export const C = {
  bg: '#161216', surface: '#221b21', edge: '#2f262e', edgeHi: '#4a3a45',
  rose: '#e8a8b8', brass: '#d9b08c', text: '#f2e9ee', muted: '#b9a4b1', danger: '#f08a8a', ok: '#9fd0a8',
  onRose: '#2a1620', warnBg: '#3a2f1f', errBg: '#3a1f24', okBg: '#1f3326',
} as const;

/** WCAG 2.2 target size (and Apple HIG): every interactive control is at least 44×44 pt. */
export const MIN_TOUCH = 44;
/** Side padding that keeps content usable at 360 dp width. */
export const GUTTER = 16;

export const TONE_COLOR: Record<'pending' | 'progress' | 'evidence' | 'problem' | 'stopped', string> = {
  pending: C.rose, progress: C.brass, evidence: C.ok, problem: C.danger, stopped: C.muted,
};
