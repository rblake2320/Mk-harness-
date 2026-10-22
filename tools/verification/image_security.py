"""Scan one local image archive without exposing the Docker daemon to a scanner.

Retain every severity, the complete CycloneDX inventory, scanner logs and image
identity. HIGH/CRITICAL findings block even when no fix is available. Nothing is
suppressed. A missing/malformed/mismatched scan is a failure, not a clean result.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

SCANNER = "aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def summarize(report, layers):
    if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
        raise ValueError("Unsupported or missing container vulnerability report")
    if not layers or report.get("Metadata", {}).get("DiffIDs") != layers:
        raise ValueError("Scanned filesystem layers do not match the inspected image")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Scanner did not identify any package inventory")
    counts = Counter()
    for result in results:
        if not result.get("Target") or not result.get("Type"):
            raise ValueError("Unidentified scan target")
        for finding in result.get("Vulnerabilities") or []:
            severity = finding.get("Severity")
            if severity not in SEVERITIES or not finding.get("VulnerabilityID") or not finding.get("PkgName"):
                raise ValueError("Incomplete vulnerability record")
            counts[severity] += 1
    return {key: counts[key] for key in sorted(SEVERITIES)}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(parts, log=None):
    result = subprocess.run(parts, capture_output=True, text=True, encoding="utf-8", timeout=720)
    if log:
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"{parts[0]} operation failed with exit {result.returncode}; see retained log")
    return result.stdout


def scanner_command(temporary, cache, output):
    command = ["docker", "run", "--rm", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--memory=2g", "--cpus=2", "--tmpfs=/tmp"]
    # With CAP_DAC_OVERRIDE dropped, root cannot write a Linux runner-owned
    # bind directory. Run as its actual owner and avoid root's private home.
    if hasattr(os, "getuid"):
        command += ["--user", f"{os.getuid()}:{os.getgid()}"]
    return command + ["--mount", f"type=bind,src={temporary},dst=/input,readonly",
        "--mount", f"type=bind,src={cache},dst=/cache",
        "--mount", f"type=bind,src={output},dst=/output", SCANNER, "--cache-dir", "/cache"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    output, cache = args.output.resolve(), args.cache.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cache.mkdir(parents=True, exist_ok=True)
    summary = {"scope": "author/CI-run local image scan; not independent release qualification", "scanner": SCANNER}
    try:
        info = json.loads(run(["docker", "image", "inspect", args.image]))[0]
        image_id, layers = info["Id"], info["RootFS"]["Layers"]
        summary.update(image_id=image_id, architecture=info["Architecture"], os=info["Os"])
        with tempfile.TemporaryDirectory(prefix="mk-image-security-") as temporary:
            archive = Path(temporary) / "image.tar"
            run(["docker", "save", "--output", str(archive), image_id])
            summary["archive_sha256"] = digest(archive)
            container = scanner_command(temporary, cache, output)
            for format_, filename in (("json", "vulnerabilities.json"), ("cyclonedx", "sbom.cdx.json")):
                run(container + ["image", "--input", "/input/image.tar", "--scanners", "vuln",
                    "--format", format_, "--output", f"/output/{filename}", "--no-progress", "--timeout", "10m"],
                    output / f"scanner-{format_}.log")
        report = json.loads((output / "vulnerabilities.json").read_text(encoding="utf-8"))
        counts = summarize(report, layers)
        sbom = json.loads((output / "sbom.cdx.json").read_text(encoding="utf-8"))
        if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("components"):
            raise ValueError("Missing CycloneDX package inventory")
        summary.update(counts=counts, components=len(sbom["components"]),
            scan_image_config_digest=report["Metadata"]["ImageID"], filesystem_layers=layers,
            vulnerability_report_sha256=digest(output / "vulnerabilities.json"),
            sbom_sha256=digest(output / "sbom.cdx.json"),
            outcome="Failed" if counts["HIGH"] or counts["CRITICAL"] else "Worked")
    except Exception as exc:
        summary.update(outcome="Failed", error=str(exc))
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items() if key != "filesystem_layers"}))
    return 0 if summary["outcome"] == "Worked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
