import importlib.util
import json
import re
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("restore_inspection",Path(__file__).resolve().parents[2]/"tools/verification/restore_inspection.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def report(enabled=False):
    rows = [{"check":name,"ok":True,"detail":{}} for name in sorted(module.REQUIRED)]
    for row in rows:
        if row["check"] == "global_dispatch_disabled":
            row.update(ok=not enabled,detail={"dispatch_enabled":enabled})
        if row["check"] == "privacy_restore_ledger":
            row["detail"] = {"inspection_only":True,"restore_authorized":False}
    rows.append({"gate":"FAIL" if enabled else "INSPECTION_ONLY","apply":False})
    return rows


def encoded(rows):
    return "\n".join(json.dumps(row,sort_keys=True,separators=(",",":")) for row in rows)


@pytest.mark.parametrize("enabled",[False,True])
def test_only_global_dispatch_is_ignorable_for_live_inspection(enabled):
    assert module.validate(encoded(report(enabled))) == 9


@pytest.mark.parametrize("name",sorted(module.REQUIRED-{"global_dispatch_disabled"}))
def test_reproduced_field_order_regex_bug_now_rejected(name):
    rows = report(True)
    next(row for row in rows if row.get("check") == name)["ok"] = False
    text = encoded(rows)
    # Exact old shell pattern silently missed failures: detail lies between keys.
    assert not re.search(r'"check":"[a-z_]*","ok":false',text)
    with pytest.raises(ValueError): module.validate(text)


@pytest.mark.parametrize("mutation",["missing","duplicate","wrong_summary","missing_summary","string_bool","restore_pass","untyped"])
def test_incomplete_or_contradictory_report_fails_closed(mutation):
    rows = report()
    if mutation == "missing": rows.pop(0)
    elif mutation == "duplicate": rows.insert(0,rows[0])
    elif mutation == "wrong_summary": rows[-1]["gate"] = "FAIL"
    elif mutation == "missing_summary": rows.pop()
    elif mutation == "string_bool": rows[0]["ok"] = "true"
    elif mutation == "restore_pass": rows[-1]["gate"] = "PASS"
    else: rows.insert(0,{"check":"unknown","ok":True})
    with pytest.raises(ValueError): module.validate(encoded(rows))
