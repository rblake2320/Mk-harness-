import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import k1_analysis  # noqa: E402

SCEN = sorted(k1_analysis.REQUIRED_SCENARIOS) * 2  # 20 scenarios


def sessions(mk_time=60.0, alt_time=100.0, mk_correct=1, mk_viol=0):
    rows = []
    for p in range(12):
        for i, sc in enumerate(SCEN):
            for arm in ("mk", "official", "alt1", "alt2"):
                t = mk_time if arm == "mk" else (alt_time if arm == "alt1" else alt_time * 1.3)
                rows.append({"participant": f"P{p}", "arm": arm, "scenario": sc, "order": i,
                             "handling_time_s": t + (p % 3), "correct": mk_correct if arm == "mk" else 1,
                             "violations": mk_viol if arm == "mk" else 0})
    return rows


def prefs(mk=11):
    return [{"participant": f"P{p}", "preferred_arm": "mk" if p < mk else "alt1", "reason": ""} for p in range(12)]


class K1(unittest.TestCase):
    def test_passing_study_yields_bounded_claim(self):
        r = k1_analysis.analyze(sessions(), prefs())
        self.assertTrue(r["pass"], r["checks"])
        self.assertEqual(r["best_alternative"], "alt1")
        self.assertIn("supports only the tested claim", r["supported_claim"])
        self.assertNotIn("best", r["supported_claim"].split("best tested")[0].lower())

    def test_29pct_reduction_fails_and_emits_no_claim(self):
        r = k1_analysis.analyze(sessions(mk_time=71.0, alt_time=100.0), prefs())
        self.assertFalse(r["checks"]["median_time_reduction_ge_30pct_vs_best_alternative"])
        self.assertIsNone(r["supported_claim"])

    def test_completion_below_95_fails(self):
        rows = sessions()
        # mark 6% of mk sessions incorrect
        mk = [x for x in rows if x["arm"] == "mk"]
        for x in mk[: int(len(mk) * 0.06) + 1]:
            x["correct"] = 0
        self.assertFalse(k1_analysis.analyze(rows, prefs())["pass"])

    def test_preference_9_of_12_fails(self):
        self.assertFalse(k1_analysis.analyze(sessions(), prefs(mk=9))["pass"])

    def test_any_privacy_violation_more_than_alternatives_fails(self):
        self.assertFalse(k1_analysis.analyze(sessions(mk_viol=1), prefs())["pass"])

    def test_missing_scenario_fails(self):
        rows = [x for x in sessions() if x["scenario"] != "opt_out"]
        self.assertFalse(k1_analysis.analyze(rows, prefs())["checks"]["all_required_scenarios_present"])

    def test_randomization_is_deterministic_and_balanced(self):
        a = k1_analysis.latin_square(["mk", "o", "a1", "a2"], 12, 7)
        b = k1_analysis.latin_square(["mk", "o", "a1", "a2"], 12, 7)
        self.assertEqual(a, b)
        firsts = [row[0] for row in a]
        self.assertEqual({firsts.count(x) for x in set(firsts)}, {3})


if __name__ == "__main__":
    unittest.main()
