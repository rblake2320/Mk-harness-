/** The brief is per LOCAL day; day arithmetic must not drift across DST or month ends. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isDay, localDay, shiftDay } from '../src/index';

test('isDay accepts real calendar days only', () => {
  for (const d of ['2026-10-21', '2024-02-29', '2026-12-31', '0001-01-01']) assert.equal(isDay(d), true, d);
  for (const d of ['2026-02-29', '2026-13-01', '2026-00-10', '2026-10-32', '2026-1-1', ' 2026-10-21', '2026-10-21T00:00:00Z', '', null, 20261021]) {
    assert.equal(isDay(d), false, String(d));
  }
});

test('shiftDay crosses month, year, leap-day and DST boundaries exactly', () => {
  assert.equal(shiftDay('2026-10-31', 1), '2026-11-01');
  assert.equal(shiftDay('2026-12-31', 1), '2027-01-01');
  assert.equal(shiftDay('2024-02-28', 1), '2024-02-29');
  assert.equal(shiftDay('2026-03-08', 1), '2026-03-09', 'US DST start');
  assert.equal(shiftDay('2026-11-01', -1), '2026-10-31', 'US DST end');
  assert.equal(shiftDay('2026-10-21', 0), '2026-10-21');
  assert.throws(() => shiftDay('2026-02-30', 1), RangeError);
  assert.throws(() => shiftDay('2026-10-21', 1.5), RangeError);
});

test('localDay is the device-local calendar day, not the UTC day', () => {
  // 20:00 local on Oct 21 — in US time zones that is already Oct 22 in UTC.
  const evening = new Date(2026, 9, 21, 20, 0, 0);
  assert.equal(localDay(evening), '2026-10-21');
  assert.equal(localDay(new Date(2026, 0, 1, 0, 0, 0)), '2026-01-01');
});
