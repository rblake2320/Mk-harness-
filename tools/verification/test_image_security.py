from copy import deepcopy

import pytest

from tools.verification.image_security import summarize
from tools.verification import image_security

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


def test_linux_scanner_writes_as_runner_without_root_capabilities(monkeypatch):
    monkeypatch.setattr(image_security.os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(image_security.os, "getgid", lambda: 121, raising=False)
    command = image_security.scanner_command("/archive", "/host-cache", "/evidence")
    assert command[command.index("--user") + 1] == "1001:121"
    assert "--cap-drop=ALL" in command and "--read-only" in command
    assert command[-2:] == ["--cache-dir", "/cache"]
    assert "type=bind,src=/host-cache,dst=/cache" in command
    assert "type=bind,src=/archive,dst=/input,readonly" in command
    assert all("docker.sock" not in arg for arg in command)
