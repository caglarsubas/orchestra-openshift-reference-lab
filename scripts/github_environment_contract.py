#!/usr/bin/env python3
"""Verify the private GitHub environment gate without retaining API payloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn


API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
GithubGetter = Callable[[str, str], Any]
ENVIRONMENT_CONTRACTS = (
    "foundation-plan",
    "foundation-apply",
    "dependency-risk-preflight",
    "dependency-risk-collection",
    "dependency-risk-custody-verification",
)


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def payload_digest(value: Any) -> str:
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def read_restricted_token(path: Path) -> str:
    try:
        if path.is_symlink():
            fail("github_environment_token_symlink_forbidden")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            fail("github_environment_token_regular_file_required")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            fail("github_environment_token_permissions_invalid")
        raw = path.read_bytes()
        token = raw.decode("ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError("github_environment_token_read_failed") from error
    if (
        not (20 <= len(token) <= 4096)
        or any(character.isspace() for character in token)
        or len(raw) > 4098
    ):
        fail("github_environment_token_invalid")
    return token


def github_get_json(path: str, token: str) -> Any:
    request = urllib.request.Request(
        f"{API_ROOT}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "orchestra-reference-lab-environment-verifier/1",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200:
                fail("github_environment_api_status_invalid")
            value = json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError(f"github_environment_api_http_{error.code}") from error
    except (
        OSError,
        TimeoutError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("github_environment_api_read_failed") from error
    return value


def _positive_id(value: Any, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(code)
    return value


def validate_environment_payloads(
    repository: dict[str, Any],
    environment: dict[str, Any],
    branch_policies: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    repository_id = _positive_id(
        repository.get("id"), "github_environment_repository_invalid"
    )
    owner = repository.get("owner")
    owner_id = (
        _positive_id(owner.get("id"), "github_environment_repository_invalid")
        if isinstance(owner, dict)
        else fail("github_environment_repository_invalid")
    )
    if (
        repository.get("full_name") != expected["repository"]
        or str(repository_id) != expected["repositoryId"]
        or str(owner_id) != expected["repositoryOwnerId"]
        or repository.get("private") is not True
        or repository.get("visibility") != expected["repositoryVisibility"]
        or repository.get("default_branch") != expected["deploymentBranch"]
        or repository.get("archived") is not False
    ):
        fail("github_environment_repository_invalid")

    environment_id = _positive_id(
        environment.get("id"), "github_environment_identity_invalid"
    )
    if environment.get("name") != expected["environment"]:
        fail("github_environment_identity_invalid")
    deployment = environment.get("deployment_branch_policy")
    if deployment != {
        "protected_branches": False,
        "custom_branch_policies": True,
    }:
        fail("github_environment_deployment_policy_invalid")
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        fail("github_environment_protection_rules_invalid")
    required_reviewer_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    branch_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "branch_policy"
    ]
    if len(required_reviewer_rules) != 1 or len(branch_rules) != 1:
        fail("github_environment_protection_rules_invalid")
    reviewer_rule = required_reviewer_rules[0]
    if reviewer_rule.get("prevent_self_review") is not expected["preventSelfReview"]:
        fail("github_environment_self_review_invalid")
    reviewers = reviewer_rule.get("reviewers")
    if not isinstance(reviewers, list) or not (
        expected["minimumIndependentReviewers"] <= len(reviewers) <= 6
    ):
        fail("github_environment_reviewers_invalid")
    reviewer_ids: list[int] = []
    for reviewer_entry in reviewers:
        if (
            not isinstance(reviewer_entry, dict)
            or reviewer_entry.get("type") != expected["reviewerType"]
            or not isinstance(reviewer_entry.get("reviewer"), dict)
        ):
            fail("github_environment_reviewers_invalid")
        reviewer_id = _positive_id(
            reviewer_entry["reviewer"].get("id"),
            "github_environment_reviewers_invalid",
        )
        if reviewer_id == owner_id:
            fail("github_environment_owner_reviewer_forbidden")
        reviewer_ids.append(reviewer_id)
    if len(reviewer_ids) != len(set(reviewer_ids)):
        fail("github_environment_reviewers_invalid")

    policies = branch_policies.get("branch_policies")
    total_count = branch_policies.get("total_count")
    if (
        not isinstance(policies, list)
        or total_count != len(policies)
        or len(policies) != 1
        or not isinstance(policies[0], dict)
        or policies[0].get("name") != expected["deploymentBranch"]
    ):
        fail("github_environment_branch_policy_invalid")

    return {
        "repositoryIdentityDigest": payload_digest(
            {
                "id": repository_id,
                "ownerId": owner_id,
                "fullName": expected["repository"],
                "visibility": expected["repositoryVisibility"],
            }
        ),
        "environmentIdentityDigest": payload_digest(
            {"id": environment_id, "name": expected["environment"]}
        ),
        "reviewerIdentityDigests": sorted(
            payload_digest({"type": expected["reviewerType"], "id": reviewer_id})
            for reviewer_id in reviewer_ids
        ),
        "reviewerCount": len(reviewer_ids),
        "preventSelfReview": True,
        "deploymentBranchPolicyDigest": payload_digest(
            {
                "protectedBranches": False,
                "customBranchPolicies": True,
                "branches": [expected["deploymentBranch"]],
            }
        ),
    }


def validate_workflow_approvals(
    approvals: Any,
    environment: dict[str, Any],
    expected: dict[str, Any],
    *,
    workflow_run_id: int,
    workflow_run_attempt: int,
    workflow_actor_id: int,
) -> dict[str, Any]:
    workflow_run_id = _positive_id(
        workflow_run_id, "github_environment_workflow_run_invalid"
    )
    workflow_actor_id = _positive_id(
        workflow_actor_id, "github_environment_workflow_actor_invalid"
    )
    workflow_run_attempt = _positive_id(
        workflow_run_attempt, "github_environment_workflow_attempt_invalid"
    )
    if workflow_run_attempt != 1:
        fail("github_environment_workflow_rerun_forbidden")
    environment_id = _positive_id(
        environment.get("id"), "github_environment_identity_invalid"
    )
    owner_id = _positive_id(
        int(expected["repositoryOwnerId"]),
        "github_environment_repository_invalid",
    )
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        fail("github_environment_protection_rules_invalid")
    reviewer_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        fail("github_environment_protection_rules_invalid")
    reviewers = reviewer_rules[0].get("reviewers")
    if not isinstance(reviewers, list):
        fail("github_environment_reviewers_invalid")
    configured_reviewer_ids = {
        _positive_id(
            reviewer["reviewer"].get("id"),
            "github_environment_reviewers_invalid",
        )
        for reviewer in reviewers
        if isinstance(reviewer, dict)
        and reviewer.get("type") == expected["reviewerType"]
        and isinstance(reviewer.get("reviewer"), dict)
    }
    if len(configured_reviewer_ids) != len(reviewers):
        fail("github_environment_reviewers_invalid")
    if not isinstance(approvals, list):
        fail("github_environment_workflow_approvals_invalid")

    approved_reviewer_ids: list[int] = []
    rejected = False
    for review in approvals:
        if not isinstance(review, dict):
            fail("github_environment_workflow_approvals_invalid")
        reviewed_environments = review.get("environments")
        if not isinstance(reviewed_environments, list):
            fail("github_environment_workflow_approvals_invalid")
        applies = any(
            isinstance(candidate, dict)
            and candidate.get("id") == environment_id
            and candidate.get("name") == expected["environment"]
            for candidate in reviewed_environments
        )
        if not applies:
            continue
        state = review.get("state")
        user = review.get("user")
        if not isinstance(user, dict):
            fail("github_environment_workflow_approvals_invalid")
        reviewer_id = _positive_id(
            user.get("id"), "github_environment_workflow_approvals_invalid"
        )
        if state == "rejected":
            rejected = True
            continue
        if (
            state != "approved"
            or user.get("type") != expected["reviewerType"]
            or reviewer_id not in configured_reviewer_ids
            or reviewer_id in {owner_id, workflow_actor_id}
        ):
            fail("github_environment_workflow_approval_not_independent")
        approved_reviewer_ids.append(reviewer_id)

    if rejected:
        fail("github_environment_workflow_approval_rejected")
    if len(approved_reviewer_ids) != 1:
        fail("github_environment_workflow_approval_missing_or_ambiguous")
    reviewer_id = approved_reviewer_ids[0]
    return {
        "workflowRunIdentityDigest": payload_digest(
            {
                "repositoryId": expected["repositoryId"],
                "runId": workflow_run_id,
                "runAttempt": workflow_run_attempt,
            }
        ),
        "approvalIdentityDigest": payload_digest(
            {
                "environmentId": environment_id,
                "reviewerId": reviewer_id,
                "reviewerType": expected["reviewerType"],
                "state": "approved",
            }
        ),
        "independentApproval": True,
    }


def fetch_environment_evidence(
    token_path: Path,
    expected: dict[str, Any],
    *,
    get_json: GithubGetter | None = None,
    workflow_run_id: int | None = None,
    workflow_run_attempt: int | None = None,
    workflow_actor_id: int | None = None,
) -> dict[str, Any]:
    token = read_restricted_token(token_path)
    get = get_json or github_get_json
    repository = expected["repository"]
    environment = urllib.parse.quote(expected["environment"], safe="")
    repository_payload = get(f"/repos/{repository}", token)
    environment_payload = get(f"/repos/{repository}/environments/{environment}", token)
    branch_payload = get(
        f"/repos/{repository}/environments/{environment}/deployment-branch-policies"
        "?per_page=100",
        token,
    )
    if not all(
        isinstance(payload, dict)
        for payload in (repository_payload, environment_payload, branch_payload)
    ):
        fail("github_environment_api_object_required")
    evidence = validate_environment_payloads(
        repository_payload,
        environment_payload,
        branch_payload,
        expected,
    )
    workflow_identity = (
        workflow_run_id,
        workflow_run_attempt,
        workflow_actor_id,
    )
    if any(value is None for value in workflow_identity) and not all(
        value is None for value in workflow_identity
    ):
        fail("github_environment_workflow_identity_incomplete")
    if all(value is not None for value in workflow_identity):
        approvals = get(
            f"/repos/{repository}/actions/runs/{workflow_run_id}/approvals",
            token,
        )
        evidence["workflowApproval"] = validate_workflow_approvals(
            approvals,
            environment_payload,
            expected,
            workflow_run_id=workflow_run_id,
            workflow_run_attempt=workflow_run_attempt,
            workflow_actor_id=workflow_actor_id,
        )
    return evidence


def load_expected_environment(contract: str) -> dict[str, Any]:
    if contract == "foundation-plan":
        try:
            from scripts.prerequisite_observation import load_contract, validate_policy
        except ModuleNotFoundError:
            from prerequisite_observation import load_contract, validate_policy

        policy, release_set = load_contract()
        validate_policy(policy, release_set)
        return policy["gcp"]["wif"]
    if contract == "foundation-apply":
        try:
            from scripts.foundation_apply_execution import (
                load_contract,
                validate_authority,
            )
        except ModuleNotFoundError:
            from foundation_apply_execution import load_contract, validate_authority

        authority, release_set, policy = load_contract()
        validate_authority(authority, release_set, policy)
        return authority["applyFederation"]
    if contract == "dependency-risk-preflight":
        try:
            from scripts.dependency_risk_execution import (
                load_contract,
                validate_authority,
            )
        except ModuleNotFoundError:
            from dependency_risk_execution import load_contract, validate_authority

        authority, release_set, risk_policy = load_contract()
        validate_authority(authority, release_set, risk_policy)
        return authority["federation"]
    if contract == "dependency-risk-collection":
        try:
            from scripts.dependency_risk_collection_execution import (
                load_contract,
                validate_authority,
            )
        except ModuleNotFoundError:
            from dependency_risk_collection_execution import (
                load_contract,
                validate_authority,
            )

        authority, release_set, risk_policy = load_contract()
        validate_authority(authority, release_set, risk_policy)
        return authority["federation"]
    if contract == "dependency-risk-custody-verification":
        try:
            from scripts.dependency_risk_custody_verification import (
                load_contract,
                validate_authority,
            )
        except ModuleNotFoundError:
            from dependency_risk_custody_verification import (
                load_contract,
                validate_authority,
            )

        authority, release_set, risk_policy = load_contract()
        validate_authority(authority, release_set, risk_policy)
        return authority["federation"]
    fail("github_environment_contract_invalid")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("verify", choices=("verify",))
    parser.add_argument(
        "--contract", choices=ENVIRONMENT_CONTRACTS, default="foundation-plan"
    )
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--workflow-run-id", type=int, required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    parser.add_argument("--workflow-actor-id", type=int, required=True)
    args = parser.parse_args(argv)
    expected = load_expected_environment(args.contract)
    evidence = fetch_environment_evidence(
        args.token_file,
        expected,
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
        workflow_actor_id=args.workflow_actor_id,
    )
    print(
        "github_environment_protection_valid "
        f"contract={args.contract} digest={payload_digest(evidence)} "
        f"reviewers={evidence['reviewerCount']} "
        "preventSelfReview=true deploymentBranch=main currentRunApproval=true"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error)
        raise SystemExit(1)
