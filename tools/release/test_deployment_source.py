from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from tools.release.deployment_source import ACTIONS_APP_ID, REQUIRED_CHECKS, WORKFLOWS, assess, valid_inputs
from tools.release import deployment_source

SHA, HEAD, REPO = "a" * 40, "b" * 40, "example/project"
NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


def evidence():
    snapshot = {"branch": {"name": "main", "protected": True},
        "comparison": {"status": "ahead", "merge_base_sha": SHA},
        "rules": [
            {"type": "deletion"}, {"type": "non_fast_forward"},
            {"type": "pull_request", "parameters": {"required_approving_review_count": 1,
                "dismiss_stale_reviews_on_push": True, "require_last_push_approval": True}},
            {"type": "required_status_checks", "parameters": {"strict_required_status_checks_policy": True,
                "required_status_checks": [{"context": name, "integration_id": ACTIONS_APP_ID} for name in REQUIRED_CHECKS]}},
        ], "pull_requests": [{"number": 1, "merged_at": NOW.isoformat(), "base": "main",
            "merge_commit_sha": SHA, "head_sha": HEAD, "author_id": 1,
            "reviews": [{"id": 10, "state": "APPROVED", "commit_id": HEAD, "user_id": 2, "user_type": "User"}]}],
        "workflows": {}, "environments": {name: {"name": name,
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
            "branch_policies": [{"name": "main", "type": "branch"}],
            "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True,
                "reviewers": [{"type": "User", "id": 3}]}]}
            for name in ("staging", "production-plan", "production")}}
    for identifier, (filename, names) in enumerate(WORKFLOWS.items(), start=1):
        snapshot["workflows"][filename] = {
            "definition": {"id": identifier, "path": ".github/workflows/" + filename, "state": "active"},
            "runs": [{"id": identifier, "run_attempt": 2, "workflow_id": identifier,
                "head_sha": SHA, "head_branch": "main", "event": "push", "repository": REPO,
                "status": "completed", "conclusion": "success", "updated_at": NOW.isoformat()}],
            "jobs": [{"name": name, "status": "completed", "conclusion": "success",
                "run_id": identifier, "run_attempt": 2} for name in names]}
    return snapshot


def verdict(snapshot):
    return assess(snapshot, REPO, SHA, "staging", "refs/heads/main", SHA, NOW)["verdict"]


def test_reviewed_protected_exact_commit_with_all_current_checks_passes():
    assert verdict(evidence()) == "PASS"


@pytest.mark.parametrize("repo,sha,target,ref", [
    (REPO, "main", "staging", "refs/heads/main"),
    (REPO, "$(touch /tmp/no)", "staging", "refs/heads/main"),
    ("../../other", SHA, "staging", "refs/heads/main"),
    ("example/..", SHA, "staging", "refs/heads/main"),
    ("example/.", SHA, "staging", "refs/heads/main"),
    (REPO, SHA, "arbitrary", "refs/heads/main"),
    (REPO, SHA, "production", "refs/heads/unreviewed"),
])
def test_inputs_cannot_select_unreviewed_workflow_or_escape_api_paths(repo, sha, target, ref):
    assert not valid_inputs(repo, sha, target, ref, sha)


def test_checkout_must_match_oidc_workflow_commit_for_truthful_provenance():
    assert assess(evidence(), REPO, SHA, "staging", "refs/heads/main", HEAD, NOW)["verdict"] == "REFUSED"


def test_production_requires_existing_main_only_reviewed_environments():
    assert assess(evidence(), REPO, SHA, "production", "refs/heads/main", SHA, NOW)["verdict"] == "PASS"


@pytest.mark.parametrize("name", ["staging", "production-plan", "production"])
@pytest.mark.parametrize("fault", ["absent", "all_branches", "wildcard", "tag", "extra_branch"])
def test_environment_cannot_be_autocreated_unprotected_or_allow_unreviewed_branch(name, fault):
    snapshot = evidence(); environment = snapshot["environments"][name]
    if fault == "absent": del snapshot["environments"][name]
    if fault == "all_branches": environment["deployment_branch_policy"] = None
    if fault == "wildcard": environment["branch_policies"][0]["name"] = "*"
    if fault == "tag": environment["branch_policies"][0]["type"] = "tag"
    if fault == "extra_branch": environment["branch_policies"].append({"name": "feature", "type": "branch"})
    assert assess(snapshot, REPO, SHA, "production", "refs/heads/main", SHA, NOW)["verdict"] == "REFUSED"


@pytest.mark.parametrize("fault", ["no_rule", "no_reviewers", "self_review", "unknown_reviewer"])
def test_production_approval_cannot_be_omitted_or_self_approved(fault):
    snapshot = evidence(); environment = snapshot["environments"]["production"]
    if fault == "no_rule": environment["protection_rules"] = []
    if fault == "no_reviewers": environment["protection_rules"][0]["reviewers"] = []
    if fault == "self_review": environment["protection_rules"][0]["prevent_self_review"] = False
    if fault == "unknown_reviewer": environment["protection_rules"][0]["reviewers"][0]["type"] = "Bot"
    assert assess(snapshot, REPO, SHA, "production", "refs/heads/main", SHA, NOW)["verdict"] == "REFUSED"


@pytest.mark.parametrize("field,value", [("name", "other"), ("protected", False)])
def test_main_protection_is_mandatory(field, value):
    data = evidence(); data["branch"][field] = value
    assert verdict(data) == "REFUSED"


@pytest.mark.parametrize("field,value", [("status", "diverged"), ("status", "behind"), ("merge_base_sha", HEAD)])
def test_only_actual_main_ancestry_is_accepted(field, value):
    data = evidence(); data["comparison"][field] = value
    assert verdict(data) == "REFUSED"


@pytest.mark.parametrize("rule", ["deletion", "non_fast_forward", "pull_request", "required_status_checks"])
def test_missing_active_branch_rule_blocks(rule):
    data = evidence(); data["rules"] = [r for r in data["rules"] if r["type"] != rule]
    assert verdict(data) == "REFUSED"


@pytest.mark.parametrize("change", ["author", "bot", "stale", "dismissed", "changes", "unmerged", "wrong_merge"])
def test_review_must_be_independent_current_and_approved(change):
    data = evidence(); pr = data["pull_requests"][0]; review = pr["reviews"][0]
    if change == "author": review["user_id"] = pr["author_id"]
    if change == "bot": review["user_type"] = "Bot"
    if change == "stale": review["commit_id"] = "c" * 40
    if change == "dismissed": review["state"] = "DISMISSED"
    if change == "changes": pr["reviews"].append({**review, "id": 11, "state": "CHANGES_REQUESTED"})
    if change == "unmerged": pr["merged_at"] = None
    if change == "wrong_merge": pr["merge_commit_sha"] = HEAD
    assert verdict(data) == "REFUSED"


@pytest.mark.parametrize("field,value", [("head_sha", HEAD), ("head_branch", "feature"),
    ("event", "pull_request"), ("repository", "other/project"), ("workflow_id", 999),
    ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "skipped"),
    ("updated_at", (NOW - timedelta(hours=25)).isoformat()),
    ("updated_at", (NOW + timedelta(seconds=1)).isoformat()), ("updated_at", "invalid")])
def test_ci_identity_completion_and_freshness_cannot_be_substituted(field, value):
    data = evidence(); data["workflows"]["ci.yml"]["runs"][0][field] = value
    assert verdict(data) == "REFUSED"


def test_newer_failed_run_cannot_be_hidden_behind_older_success():
    data = evidence(); record = data["workflows"]["ci.yml"]
    record["runs"].append({**record["runs"][0], "id": 999, "conclusion": "failure"})
    assert verdict(data) == "REFUSED"


@pytest.mark.parametrize("change", ["missing", "duplicate", "failed", "skipped", "old_attempt", "different_run"])
def test_every_job_must_be_unique_successful_and_from_selected_attempt(change):
    data = evidence(); jobs = data["workflows"]["kernel-ci.yml"]["jobs"]
    if change == "missing": jobs.pop()
    if change == "duplicate": jobs.append(deepcopy(jobs[0]))
    if change == "failed": jobs[0]["conclusion"] = "failure"
    if change == "skipped": jobs[0]["conclusion"] = "skipped"
    if change == "old_attempt": jobs[0]["run_attempt"] = 1
    if change == "different_run": jobs[0]["run_id"] = 999
    assert verdict(data) == "REFUSED"


def test_untrusted_status_provider_and_weak_review_settings_do_not_qualify():
    data = evidence()
    for rule in data["rules"]:
        if rule["type"] == "required_status_checks":
            for check in rule["parameters"]["required_status_checks"]: check["integration_id"] = 999
        if rule["type"] == "pull_request": rule["parameters"]["require_last_push_approval"] = False
    assert verdict(data) == "REFUSED"


def test_github_json_uses_utf8_independent_of_host_codepage(monkeypatch):
    from types import SimpleNamespace

    def execute(command, **options):
        assert options["encoding"] == "utf-8"
        assert command[:4] == ["gh", "api", "--hostname", "github.com"]
        return SimpleNamespace(returncode=0, stdout='{"title":"Unicode review: \\u263a"}')

    monkeypatch.setattr(deployment_source.subprocess, "run", execute)
    assert deployment_source.api("repos/example/project") == {"title": "Unicode review: \u263a"}
