/** Human date-time for display. Invalid or missing input says so; it never invents a time. */
export function fmtWhen(iso: string | null | undefined): string {
  if (!iso) return 'not reported';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return 'unknown time';
  try { return new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch { return new Date(t).toISOString(); }
}
