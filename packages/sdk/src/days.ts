/**
 * Calendar days as `YYYY-MM-DD` for the daily brief, which is generated per LOCAL day
 * (`commitments.py::generate_brief`). Using `toISOString()` for "today" picks the UTC day,
 * which in US evenings is already tomorrow.
 */
const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** UTC midnight of y-m-d. setUTCFullYear, because Date.UTC maps years 0–99 to 1900–1999. */
function utc(y: number, m: number, d: number): Date {
  const t = new Date(0);
  t.setUTCFullYear(y, m - 1, d);
  return t;
}

export function isDay(s: unknown): s is string {
  const m = typeof s === 'string' ? DAY_RE.exec(s) : null;
  if (!m) return false;
  const d = utc(+m[1], +m[2], +m[3]);
  return d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3];
}

/** `day` moved by `delta` days (calendar arithmetic in UTC, so no DST drift). */
export function shiftDay(day: string, delta: number): string {
  if (!isDay(day) || !Number.isInteger(delta)) throw new RangeError(`not a day: ${String(day)}`);
  const [y, m, d] = day.split('-').map(Number);
  return utc(y, m, d + delta).toISOString().slice(0, 10);
}

/** The device's local calendar day. */
export function localDay(now: Date = new Date()): string {
  const y = now.getFullYear(), m = now.getMonth() + 1, d = now.getDate();
  return `${String(y).padStart(4, '0')}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}
