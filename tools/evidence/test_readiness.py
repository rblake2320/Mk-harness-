# Unit tests for the release-verdict tool. Run: python -m unittest -v tools/evidence/test_readiness.py
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import readiness  # noqa: E402

MATRIX = """
| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| F1 | thing one | tests | Release | **Implemented** |
| F2 | thing two | tests | Release | Kernel **Independently verified**; UI **Implemented** |
| F3 | thing three | review | Release | **Independently verified** |
| O4 | load | load report | Release (proven) | **Independently verified** |
| S9 | mfa | — | Release | **Not demonstrated** |
| S11 | isolation | isolation suite | Release | see F7 |
| Z1 | odd | — | Release | something else entirely |
"""


class LevelOfCell(unittest.TestCase):
    def test_lowest_child_state_wins(self):
        self.assertEqual(readiness.level_of_cell("Kernel **Independently verified**; UI **Not demonstrated**"), "not_demonstrated")
        self.assertEqual(readiness.level_of_cell("Kernel **Independently verified**; UI **Implemented**"), "implemented")
        self.assertEqual(readiness.level_of_cell("**Independently verified**"), "independently_verified")
        self.assertEqual(readiness.level_of_cell("**Production-proven** 2026-11"), "production_proven")
        self.assertEqual(readiness.level_of_cell("green CI, looks fine"), "unknown")


class Verdict(unittest.TestCase):
    def rows(self):
        return readiness.parse_matrix(MATRIX)

    def test_matrix_claims_never_close_rows(self):
        r = readiness.evaluate(self.rows(), {})
        self.assertEqual(r["verdict"], "NOT READY")
        self.assertEqual(r["rows_closed"], 0)
        ids = {f["id"] for f in r["failing"]}
        self.assertEqual(ids, {"F1", "F2", "F3", "O4", "S9", "S11", "Z1"})
        # A matrix cell claiming more than the records back is reported, not trusted.
        self.assertIn({"id": "F3", "matrix_claim": "independently_verified", "record": "none"}, r["matrix_claims_without_record"])

    def test_vocabulary_violation_blocks(self):
        r = readiness.evaluate(self.rows(), {})
        z = next(f for f in r["failing"] if f["id"] == "Z1")
        self.assertIn("vocabulary", z["why"])

    def test_records_close_rows_only_at_required_level(self):
        recs = {
            "F1": {"status": "independently_verified", "problems": [], "path": "x"},
            "F2": {"status": "implemented", "problems": [], "path": "x"},            # too low for Release
            "F3": {"status": "independently_verified", "problems": [], "path": "x"},
            "O4": {"status": "independently_verified", "problems": [], "path": "x"},  # Release (proven) needs production_proven
            "S9": {"status": "invalid", "problems": ["checksum mismatch"], "path": "x"},
            "S11": {"status": "independently_verified", "problems": [], "path": "x"},
        }
        r = readiness.evaluate(self.rows(), recs)
        self.assertEqual(r["verdict"], "NOT READY")
        self.assertEqual({f["id"] for f in r["failing"]}, {"F2", "O4", "S9", "Z1"})
        o4 = next(f for f in r["failing"] if f["id"] == "O4")
        self.assertEqual(o4["required"], "production_proven")
        s9 = next(f for f in r["failing"] if f["id"] == "S9")
        self.assertEqual(s9["record"], "invalid record")

    def test_ready_only_when_everything_closed(self):
        rows = readiness.parse_matrix("\n".join(l for l in MATRIX.splitlines() if not l.startswith(("| Z1", "| S9"))))
        recs = {rid: {"status": "production_proven" if rid == "O4" else "independently_verified", "problems": [], "path": "x"} for rid in rows}
        r = readiness.evaluate(rows, recs)
        self.assertTrue(r["verdict"].startswith("READY"))
        self.assertTrue(all(c["answer"] == "yes" for c in r["checklist"]))

    def test_checklist_question_names_blocking_rows(self):
        r = readiness.evaluate(self.rows(), {})
        q = next(c for c in r["checklist"] if c["question"].startswith("Is the full advertised"))
        self.assertEqual(q["answer"], "no")
        self.assertIn("F1", q["blocking"])

    def test_support_and_economics_use_their_contract_rows(self):
        checklist = dict(readiness.CHECKLIST)
        self.assertIn("M3", checklist["Are monitoring, support, and incident responsibilities staffed?"])
        self.assertEqual(checklist["Are economics viable at the approved price?"], ["M4"])

    def test_real_matrix_has_87_rows_and_three_production_gates(self):
        rows = readiness.parse_matrix(readiness.MATRIX.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), 87)
        self.assertEqual({rid for rid, row in rows.items() if row["required"] == "production_proven"},
                         {"O2", "O3", "O4"})

    def test_cli_reports_all_blockers_on_windows_console_encoding(self):
        result = subprocess.run(
            [sys.executable, "-I", "-c", "import runpy,sys; sys.stdout.reconfigure(encoding='cp1252'); "
             "runpy.run_path('tools/evidence/readiness.py',run_name='__main__')"],
            cwd=readiness.ROOT, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)  # NOT READY is the expected exit code.
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertIn(b"rows: 87, closed by evidence: 0, failing: 87", result.stdout)
        self.assertIn(b"Is every acceptance result linked", result.stdout)

    def test_direct_contract_entrypoint_runs_every_contract_test(self):
        result = subprocess.run([sys.executable, "-I", "contracts/tests/test_contracts.py"],
                                cwd=readiness.ROOT, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"ok   test_inbound_event_schema_matches_contract_fields_and_message_state_vocabulary", result.stdout)
        self.assertIn(b"ok   test_commitment_and_outcome_schemas_compile_and_separate_transport_from_business", result.stdout)


if __name__ == "__main__":
    unittest.main()
