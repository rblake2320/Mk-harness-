import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import c10_tally  # noqa: E402

T0 = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)


def row(i, *, day=0, expected="delivered", scenario="normal", device_delay=60, provider_delay=5, provider_state="delivered", **kw):
    a = T0 + timedelta(days=day, minutes=i % 300)
    r = {
        "action_id": f"a{i}", "approved_at": a.isoformat(), "approval_credential_id": "cred1",
        "provider_message_id": f"SM{i}", "provider_state": provider_state, "provider_state_at": (a + timedelta(seconds=provider_delay)).isoformat(),
        "device_number": f"+1555000{i % 6:04d}", "device_seen_at": (a + timedelta(seconds=device_delay)).isoformat() if device_delay is not None else "",
        "scenario": scenario, "expected": expected, "duplicate_of": "", "ambiguous_resolution": "", "incident_id": "",
    }
    r.update(kw)
    return r


def good_run():
    rows = []
    for i in range(1000):
        day = i // 34
        sc = ["normal"] * 14 + ["opt_out", "wrong_number", "failure", "failure", "recovery", "recovery"]
        s = sc[i % len(sc)]
        if s == "failure":
            rows.append(row(i, day=day, expected="failed", scenario=s, provider_state="failed", device_delay=None))
        elif s == "opt_out":
            rows.append(row(i, day=day, expected="suppressed", scenario=s, provider_state="suppressed", device_delay=None))
        elif s == "wrong_number":
            rows.append(row(i, day=day, expected="held", scenario=s, provider_state="delivered"))
        else:
            rows.append(row(i, day=day, scenario=s))
    return rows


class Tally(unittest.TestCase):
    def test_good_run_passes(self):
        r = c10_tally.tally(good_run(), None)
        self.assertTrue(r["pass"], r)
        self.assertGreaterEqual(r["totals"]["days"], 30)

    def test_one_unapproved_message_fails_everything(self):
        rows = good_run()
        rows[10]["approval_credential_id"] = ""
        r = c10_tally.tally(rows, None)
        self.assertFalse(r["pass"])
        self.assertEqual(r["failures"]["unapproved"], ["a10"])

    def test_one_duplicate_fails(self):
        rows = good_run()
        rows[11]["duplicate_of"] = "a5"
        self.assertFalse(c10_tally.tally(rows, None)["pass"])

    def test_corroboration_rate_threshold(self):
        rows = good_run()
        eligible = [x for x in rows if x["expected"] == "delivered"]
        # 2% not corroborated → below 99%
        for x in eligible[: int(len(eligible) * 0.02) + 1]:
            x["device_seen_at"] = ""
        r = c10_tally.tally(rows, None)
        self.assertFalse(r["checks"]["device_corroboration_ge_99pct_within_5min"])

    def test_late_device_corroboration_does_not_count(self):
        rows = good_run()
        eligible = [x for x in rows if x["expected"] == "delivered"]
        for x in eligible[:20]:
            x["device_seen_at"] = (datetime.fromisoformat(x["approved_at"]) + timedelta(minutes=6)).isoformat()
        r = c10_tally.tally(rows, None)
        self.assertFalse(r["checks"]["device_corroboration_ge_99pct_within_5min"])

    def test_ambiguous_must_be_resolved_or_explicitly_unknown(self):
        rows = good_run()
        rows[3]["provider_state"] = "submission_unknown"
        self.assertFalse(c10_tally.tally(rows, None)["pass"])
        rows[3]["ambiguous_resolution"] = "left_unknown"
        r = c10_tally.tally(rows, None)
        self.assertTrue(r["checks"]["every_ambiguous_resolved_or_explicitly_unknown"])

    def test_expected_failure_that_delivered_is_a_mismatch_not_a_success(self):
        rows = good_run()
        f = next(x for x in rows if x["expected"] == "failed")
        f["provider_state"] = "delivered"
        r = c10_tally.tally(rows, None)
        self.assertFalse(r["checks"]["no_expected_failure_counted_as_success"])

    def test_incident_blocks(self):
        rows = good_run()
        rows[0]["incident_id"] = "INC-7"
        self.assertFalse(c10_tally.tally(rows, None)["pass"])

    def test_window_filters_and_short_window_fails(self):
        rows = good_run()
        w = (T0, T0 + timedelta(days=10))
        r = c10_tally.tally(rows, w)
        self.assertFalse(r["checks"]["days_at_least_30_consecutive"])
        self.assertFalse(r["checks"]["messages_at_least_1000"])


if __name__ == "__main__":
    unittest.main()
