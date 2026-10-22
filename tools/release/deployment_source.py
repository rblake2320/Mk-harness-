"""Read-only O8 gate: reviewed main ancestry and fresh exact-commit CI.

No cloud token, deployment, repository mutation, merge or CI rerun is performed.
The CLI reads GitHub itself; it cannot accept caller-authored approval snapshots.
"""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess

WORKFLOWS = {
    "ci.yml": {"backend-tests (3.12)", "backend-tests (3.13)", "web-build", "docker-build", "app-postgres-boundary"},
    "kernel-ci.yml": {"kernel", "contracts", "observability", "secret-scan", "kernel-image", "live-smoke"},
}
REQUIRED_CHECKS = set().union(*WORKFLOWS.values())
ACTIONS_APP_ID = 15368


def valid_repository(repo):
    return (isinstance(repo, str)
        and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+", repo))
        and repo.split("/")[1] not in {".", ".."})


def valid_inputs(repo, sha, target, workflow_ref, workflow_sha):
    return (valid_repository(repo)
        and bool(re.fullmatch(r"[0-9a-f]{40}", sha))
        and target in {"staging", "production"} and workflow_ref == "refs/heads/main"
        and sha == workflow_sha)


def approved_review(pr):
    if not pr.get("merged_at") or pr.get("base") != "main":
        return False
    latest = {}
    for review in sorted(pr.get("reviews", []), key=lambda item: item["id"]):
        if review.get("state") in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[review["user_id"]] = review
    if any(review["state"] == "CHANGES_REQUESTED" for review in latest.values()):
        return False
    return any(review["state"] == "APPROVED" and review.get("user_type") == "User"
        and review.get("user_id") != pr.get("author_id")
        and review.get("commit_id") == pr.get("head_sha") for review in latest.values())


def assess(snapshot, repo, sha, target, workflow_ref, workflow_sha, now):
    checks = []

    def check(name, ok):
        checks.append({"check": name, "ok": bool(ok)})

    # GitHub provenance binds the workflow execution commit, not an arbitrary
    # checkout ref. Never attest a different checkout under that identity.
    check("bounded_main_workflow_inputs", valid_inputs(repo, sha, target, workflow_ref, workflow_sha))
    branch, comparison = snapshot.get("branch", {}), snapshot.get("comparison", {})
    check("main_is_protected", branch.get("name") == "main" and branch.get("protected") is True)
    check("source_is_on_main", comparison.get("status") in {"ahead", "identical"}
        and comparison.get("merge_base_sha") == sha)
    rules = snapshot.get("rules", [])
    reviews = [rule.get("parameters", {}) for rule in rules if rule.get("type") == "pull_request"]
    check("main_requires_fresh_human_review", any(
        rule.get("required_approving_review_count", 0) >= 1
        and rule.get("dismiss_stale_reviews_on_push") is True
        and rule.get("require_last_push_approval") is True for rule in reviews))
    required = [rule.get("parameters", {}) for rule in rules if rule.get("type") == "required_status_checks"]
    contexts = {item.get("context") for rule in required if rule.get("strict_required_status_checks_policy") is True
        for item in rule.get("required_status_checks", []) if item.get("integration_id") == ACTIONS_APP_ID}
    check("main_requires_trusted_ci_checks", REQUIRED_CHECKS <= contexts)
    check("main_disallows_delete_and_force_push", {"deletion", "non_fast_forward"} <= {r.get("type") for r in rules})
    prs = [pr for pr in snapshot.get("pull_requests", []) if pr.get("merge_commit_sha") == sha]
    check("exact_source_has_independent_merged_pr_approval", any(approved_review(pr) for pr in prs))
    names = ("staging", "production-plan", "production") if target == "production" else ("staging",)
    for name in names:
        environment = snapshot.get("environments", {}).get(name, {})
        policy = environment.get("deployment_branch_policy") or {}
        branches = environment.get("branch_policies", [])
        check(name + ":existing_main_only_environment", environment.get("name") == name
            and policy.get("protected_branches") is False and policy.get("custom_branch_policies") is True
            and len(branches) == 1 and branches[0].get("name") == "main" and branches[0].get("type") == "branch")
        if name == "production":
            reviews = [rule for rule in environment.get("protection_rules", []) if rule.get("type") == "required_reviewers"]
            check("production:independent_environment_approval", any(rule.get("prevent_self_review") is True
                and any(reviewer.get("type") in {"User", "Team"} and reviewer.get("id")
                    for reviewer in rule.get("reviewers", [])) for rule in reviews))
    for filename, expected_jobs in WORKFLOWS.items():
        record = snapshot.get("workflows", {}).get(filename, {})
        definition = record.get("definition", {})
        runs = record.get("runs", [])
        check(filename + ":active_definition", definition.get("state") == "active"
            and definition.get("path") == ".github/workflows/" + filename)
        # Never search backwards for an older successful run after a failed or
        # incomplete newer one. The collector does not filter by conclusion.
        selected = max(runs, key=lambda run: (run["id"], run.get("run_attempt", 0)), default={})
        check(filename + ":exact_main_push", selected.get("head_sha") == sha
            and selected.get("head_branch") == "main" and selected.get("event") == "push"
            and selected.get("repository") == repo and selected.get("workflow_id") == definition.get("id"))
        check(filename + ":successful_run", selected.get("status") == "completed" and selected.get("conclusion") == "success")
        try:
            updated = datetime.fromisoformat(selected["updated_at"].replace("Z", "+00:00"))
            fresh = timedelta(0) <= now - updated <= timedelta(hours=24)
        except (KeyError, TypeError, ValueError):
            fresh = False
        check(filename + ":fresh_run", fresh)
        jobs = record.get("jobs", [])
        names = Counter(job.get("name") for job in jobs)
        check(filename + ":all_required_jobs", all(names[name] == 1 for name in expected_jobs)
            and all(job.get("status") == "completed" and job.get("conclusion") == "success"
                and job.get("run_id") == selected.get("id")
                and job.get("run_attempt") == selected.get("run_attempt") for job in jobs))
    return {"scope": "read-only source preflight; not deployment or independent release qualification",
        "source_sha": sha, "repository": repo, "target": target,
        "verdict": "PASS" if all(item["ok"] for item in checks) else "REFUSED", "checks": checks}


def api(path):
    result = subprocess.run(["gh", "api", "--hostname", "github.com", "-H",
        "X-GitHub-Api-Version: 2022-11-28", path], capture_output=True, text=True, encoding="utf-8", timeout=30)
    if result.returncode:
        raise RuntimeError(f"GitHub read failed for {path} (exit {result.returncode})")
    return json.loads(result.stdout)


def listed(path):
    result = []
    separator = "&" if "?" in path else "?"
    for page in range(1, 11):
        rows = api(f"{path}{separator}per_page=100&page={page}")
        if not isinstance(rows, list):
            raise ValueError("Unexpected GitHub list response")
        result.extend(rows)
        if len(rows) < 100:
            return result
    raise ValueError("GitHub list exceeded bounded pagination")


def collect(repo, sha, target):
    base = f"repos/{repo}"
    branch = api(base + "/branches/main")
    comparison = api(base + f"/compare/{sha}...main")
    snapshot = {"branch": {k: branch[k] for k in ("name", "protected")},
        "comparison": {"status": comparison["status"], "merge_base_sha": comparison["merge_base_commit"]["sha"]},
        "rules": listed(base + "/rules/branches/main"), "pull_requests": [], "workflows": {}, "environments": {}}
    environments = api(base + "/environments?per_page=100")
    if environments["total_count"] > 100:
        raise ValueError("Environment count exceeds bounded query")
    names = {"staging", "production-plan", "production"} if target == "production" else {"staging"}
    for environment in environments["environments"]:
        name = environment["name"]
        if name not in names:
            continue
        policies = api(base + f"/environments/{name}/deployment-branch-policies?per_page=100")
        if policies["total_count"] > 100:
            raise ValueError("Environment branch policy count exceeds bounded query")
        snapshot["environments"][name] = {"name": name,
            "deployment_branch_policy": environment.get("deployment_branch_policy"),
            "branch_policies": [{"name": policy["name"], "type": policy.get("type")} for policy in policies["branch_policies"]],
            "protection_rules": [{"type": rule["type"], "prevent_self_review": rule.get("prevent_self_review"),
                "reviewers": [{"type": reviewer["type"], "id": reviewer["reviewer"]["id"]}
                    for reviewer in rule.get("reviewers", [])]} for rule in environment.get("protection_rules", [])]}
    for row in listed(base + f"/commits/{sha}/pulls"):
        if row.get("merge_commit_sha") != sha or not row.get("merged_at"):
            continue
        pr = api(base + f"/pulls/{row['number']}")
        reviews = listed(base + f"/pulls/{row['number']}/reviews")
        snapshot["pull_requests"].append({"number": pr["number"], "merged_at": pr["merged_at"],
            "base": pr["base"]["ref"], "merge_commit_sha": pr["merge_commit_sha"],
            "head_sha": pr["head"]["sha"], "author_id": pr["user"]["id"], "reviews": [
                {"id": r["id"], "state": r["state"], "commit_id": r["commit_id"],
                    "user_id": r["user"]["id"], "user_type": r["user"]["type"]} for r in reviews]})
    for filename in WORKFLOWS:
        definition = api(base + f"/actions/workflows/{filename}")
        raw = api(base + f"/actions/workflows/{definition['id']}/runs?head_sha={sha}&event=push&branch=main&per_page=100")
        if raw["total_count"] > 100:
            raise ValueError("Workflow run count exceeds bounded query")
        runs = [{**{k: r[k] for k in ("id", "run_attempt", "workflow_id", "head_sha", "head_branch", "event",
            "status", "conclusion", "updated_at")}, "repository": r["head_repository"]["full_name"]} for r in raw["workflow_runs"]]
        record = {"definition": {k: definition[k] for k in ("id", "path", "state")}, "runs": runs, "jobs": []}
        if runs:
            selected = max(runs, key=lambda r: (r["id"], r["run_attempt"]))
            jobs = api(base + f"/actions/runs/{selected['id']}/attempts/{selected['run_attempt']}/jobs?per_page=100")
            if jobs["total_count"] > 100:
                raise ValueError("Workflow job count exceeds bounded query")
            record["jobs"] = [{k: job[k] for k in ("name", "status", "conclusion", "run_id", "run_attempt")} for job in jobs["jobs"]]
        snapshot["workflows"][filename] = record
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"verdict": "REFUSED", "source_sha": args.sha}
    try:
        if not valid_inputs(args.repo, args.sha, args.target, args.workflow_ref, args.workflow_sha):
            raise ValueError("Expected repository, full lowercase SHA matching workflow commit, closed target and main workflow")
        snapshot = collect(args.repo, args.sha, args.target)
        report = assess(snapshot, args.repo, args.sha, args.target, args.workflow_ref, args.workflow_sha, datetime.now(timezone.utc))
        report["evidence"] = snapshot
    except (RuntimeError, ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as exc:
        report["error"] = str(exc)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "evidence"}))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
