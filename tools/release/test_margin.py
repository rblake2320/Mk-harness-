import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import margin  # noqa: E402


def doc(price=49.0, tenants=25, **over):
    lines = [
        {"name": "provider", "amount": 310.0, "measured": True},
        {"name": "hosting", "amount": 100.0, "measured": True},
        {"name": "model", "amount": 50.0, "measured": True},
        {"name": "observability", "amount": 20.0, "measured": True},
        {"name": "storage", "amount": 10.0, "measured": True},
        {"name": "support_labour", "amount": 100.0, "measured": True},
    ]
    d = {"price_per_tenant_month": price, "tenants_measured": tenants, "window": "2026-12", "lines": lines, "excluded_product_development": 1.0}
    d.update(over)
    return d


class Margin(unittest.TestCase):
    def test_passes_at_70_or_more(self):
        r = margin.evaluate(doc())  # cost 590 / revenue 1225 → 51.8% → fail
        self.assertFalse(r["pass"])
        r = margin.evaluate(doc(price=80.0))  # revenue 2000 → 70.5%
        self.assertTrue(r["pass"], r)

    def test_estimate_lines_fail_even_with_good_margin(self):
        d = doc(price=200.0)
        d["lines"][0]["measured"] = False
        r = margin.evaluate(d)
        self.assertFalse(r["pass"])
        self.assertEqual(r["unmeasured_lines"], ["provider"])

    def test_missing_support_labour_fails(self):
        d = doc(price=200.0)
        d["lines"] = [l for l in d["lines"] if l["name"] != "support_labour"]
        self.assertFalse(margin.evaluate(d)["pass"])

    def test_zero_tenants_or_price_fails(self):
        self.assertFalse(margin.evaluate(doc(tenants=0))["pass"])
        self.assertFalse(margin.evaluate(doc(price=0))["pass"])

    def test_product_development_is_never_netted(self):
        a = margin.evaluate(doc(price=80.0))
        b = margin.evaluate(doc(price=80.0, excluded_product_development=1e9))
        self.assertEqual(a["gross_margin_pct"], b["gross_margin_pct"])


if __name__ == "__main__":
    unittest.main()
