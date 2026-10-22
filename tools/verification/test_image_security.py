from copy import deepcopy

import pytest

from tools.verification.image_security import summarize

REPORT = {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"DiffIDs": ["layer"]},
    "Results": [{"Target": "image (debian)", "Type": "debian"}]}


def test_no_findings_is_valid_only_with_inventory_and_matching_layers():
    assert sum(summarize(REPORT, ["layer"]).values()) == 0


@pytest.mark.parametrize("change", [
    {"SchemaVersion": 1}, {"ArtifactType": "filesystem"}, {"Results": []},
    {"Results": [{}]}, {"Metadata": {"DiffIDs": ["different"]}},
    {"Results": [{"Target": "image", "Type": "debian", "Vulnerabilities": [{}]}]},
])
def test_incomplete_or_substituted_report_is_refused(change):
    with pytest.raises(ValueError):
        summarize({**deepcopy(REPORT), **change}, ["layer"])


def test_unfixed_high_and_unknown_findings_are_not_suppressed():
    report = deepcopy(REPORT)
    report["Results"][0]["Vulnerabilities"] = [
        {"VulnerabilityID": "TEST-1", "PkgName": "synthetic", "Severity": "HIGH"},
        {"VulnerabilityID": "TEST-2", "PkgName": "synthetic", "Severity": "UNKNOWN"},
    ]
    counts = summarize(report, ["layer"])
    assert counts["HIGH"] == counts["UNKNOWN"] == 1
