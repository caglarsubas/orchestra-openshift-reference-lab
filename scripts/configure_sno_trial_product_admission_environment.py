#!/usr/bin/env python3
"""Plan, apply, and verify supported GitHub environment contracts."""

from __future__ import annotations

import argparse
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.github_environment_contract import (
        API_ROOT,
        API_VERSION,
        ENVIRONMENT_CONTRACTS,
        fetch_environment_evidence,
        load_expected_environment,
        payload_digest,
        read_restricted_token,
    )
    from scripts.operator_control_plane_readiness import (
        load_policy as load_operator_control_plane_policy,
    )
    from scripts.sno_trial_product_artifact_admission import (
        POLICY_PATH,
        validate_policy,
    )
    from scripts.sno_trial_product_artifacts import (
        CANDIDATE_PATH,
        LOCK_PATH,
        load_json,
    )
except ModuleNotFoundError:
    from github_environment_contract import (
        API_ROOT,
        API_VERSION,
        ENVIRONMENT_CONTRACTS,
        fetch_environment_evidence,
        load_expected_environment,
        payload_digest,
        read_restricted_token,
    )
    from operator_control_plane_readiness import (
        load_policy as load_operator_control_plane_policy,
    )
    from sno_trial_product_artifact_admission import POLICY_PATH, validate_policy
    from sno_trial_product_artifacts import CANDIDATE_PATH, LOCK_PATH, load_json


PLAN_KIND = "orchestra.openshift.sno-trial-product-admission-environment-plan.v1"
REFERENCE_LAB_PLAN_KIND = (
    "orchestra.openshift.reference-lab-github-environment-plan.v1"
)
DEFAULT_CONTRACT = "sno-trial-product-admission"
SUPPORTED_CONTRACTS = (DEFAULT_CONTRACT, *ENVIRONMENT_CONTRACTS)
REFERENCE_LAB_ENVIRONMENT_SECRETS = {
    "foundation-plan": {"LAB_FOUNDATION_PREREQUISITES_JSON"},
    "foundation-apply": set(),
    "foundation-observation": set(),
    "dependency-risk-preflight": {
        "DEPENDENCY_RISK_GITHUB_APP_ID",
        "DEPENDENCY_RISK_GITHUB_APP_INSTALLATION_ID",
        "DEPENDENCY_RISK_GITHUB_APP_PRIVATE_KEY",
    },
    "dependency-risk-collection": {
        "DEPENDENCY_RISK_GITHUB_APP_ID",
        "DEPENDENCY_RISK_GITHUB_APP_INSTALLATION_ID",
        "DEPENDENCY_RISK_GITHUB_APP_PRIVATE_KEY",
    },
    "dependency-risk-custody-verification": {
        "DEPENDENCY_RISK_GITHUB_APP_ID",
        "DEPENDENCY_RISK_GITHUB_APP_INSTALLATION_ID",
        "DEPENDENCY_RISK_GITHUB_APP_PRIVATE_KEY",
    },
}
PLAN_CONTROLS = {
    "cloudMutationAuthorized": False,
    "deploymentAuthorized": False,
    "environmentSecretsManaged": False,
    "githubEnvironmentMutationAuthorized": True,
    "repositoryMutationAuthorized": False,
}
REPOSITORY_PERMISSIONS = {
    "read",
    "write",
    "admin",
    "pull",
    "triage",
    "push",
    "maintain",
}
GithubRequest = Callable[[str, str, str, dict[str, Any] | None], Any]


class GithubApiError(ValueError):
    """GitHub response failure with a status suitable for fail-closed routing."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"github_environment_api_http_{status}")


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def github_request_json(
    method: str,
    path: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    encoded = (
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
        if body is not None
        else None
    )
    request = urllib.request.Request(
        f"{API_ROOT}{path}",
        data=encoded,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "orchestra-reference-lab-environment-bootstrap/1",
            "X-GitHub-Api-Version": API_VERSION,
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status == 204:
                return None
            if response.status not in {200, 201}:
                raise GithubApiError(response.status)
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise GithubApiError(error.code) from error
    except GithubApiError:
        raise
    except (
        OSError,
        TimeoutError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("github_environment_api_read_failed") from error


def load_contract(
    contract: str = DEFAULT_CONTRACT,
) -> tuple[dict[str, Any], str]:
    if contract not in SUPPORTED_CONTRACTS:
        fail("github_environment_contract_invalid")
    if contract != DEFAULT_CONTRACT:
        policy, policy_digest = load_operator_control_plane_policy()
        if contract not in policy["environmentContracts"]:
            fail("github_environment_contract_invalid")
        expected = load_expected_environment(contract)
        return expected, payload_digest(
            {
                "kind": (
                    "orchestra.openshift."
                    "reference-lab-github-environment-contract.v1"
                ),
                "operatorControlPlanePolicyDigest": policy_digest,
                "contract": contract,
                "environmentContractDigest": payload_digest(expected),
                "allowedEnvironmentSecretNames": sorted(
                    allowed_environment_secret_names(contract)
                ),
            }
        )
    policy = load_json(POLICY_PATH)
    lock = load_json(LOCK_PATH)
    candidate = load_json(CANDIDATE_PATH)
    validate_policy(policy, lock, candidate)
    return policy["github"], policy["policyDigest"]


def plan_kind(contract: str) -> str:
    return PLAN_KIND if contract == DEFAULT_CONTRACT else REFERENCE_LAB_PLAN_KIND


def allowed_environment_secret_names(contract: str) -> set[str]:
    if contract == DEFAULT_CONTRACT:
        return set()
    try:
        return set(REFERENCE_LAB_ENVIRONMENT_SECRETS[contract])
    except KeyError:
        fail("github_environment_contract_invalid")


def _positive_id(value: Any, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(code)
    return value


def validate_repository(repository: Any, expected: dict[str, Any]) -> tuple[int, int]:
    value = exact_keys_subset(
        repository,
        {
            "id",
            "full_name",
            "private",
            "visibility",
            "default_branch",
            "archived",
            "owner",
        },
        "github_environment_repository_invalid",
    )
    owner = value["owner"]
    if not isinstance(owner, dict):
        fail("github_environment_repository_invalid")
    repository_id = _positive_id(value["id"], "github_environment_repository_invalid")
    owner_id = _positive_id(owner.get("id"), "github_environment_repository_invalid")
    if (
        value["full_name"] != expected["repository"]
        or str(repository_id) != expected["repositoryId"]
        or str(owner_id) != expected["repositoryOwnerId"]
        or value["private"] is not True
        or value["visibility"] != expected["repositoryVisibility"]
        or value["default_branch"] != expected["deploymentBranch"]
        or value["archived"] is not False
    ):
        fail("github_environment_repository_invalid")
    return repository_id, owner_id


def exact_keys_subset(value: Any, required: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value):
        fail(code)
    return value


def validate_reviewer(
    reviewer: Any,
    permission: Any,
    expected: dict[str, Any],
    reviewer_login: str,
    owner_id: int,
) -> tuple[int, str]:
    reviewer_value = exact_keys_subset(
        reviewer, {"id", "login", "type"}, "github_environment_reviewer_invalid"
    )
    reviewer_id = _positive_id(
        reviewer_value["id"], "github_environment_reviewer_invalid"
    )
    if (
        reviewer_value["type"] != expected["reviewerType"]
        or not isinstance(reviewer_value["login"], str)
        or reviewer_value["login"].casefold() != reviewer_login.casefold()
    ):
        fail("github_environment_reviewer_invalid")
    if reviewer_id == owner_id:
        fail("github_environment_owner_reviewer_forbidden")

    permission_value = exact_keys_subset(
        permission,
        {"permission", "user"},
        "github_environment_reviewer_permission_invalid",
    )
    permission_user = permission_value["user"]
    if (
        permission_value["permission"] not in REPOSITORY_PERMISSIONS
        or not isinstance(permission_user, dict)
        or permission_user.get("id") != reviewer_id
        or permission_user.get("type") != expected["reviewerType"]
    ):
        fail("github_environment_reviewer_repository_access_required")
    return reviewer_id, permission_value["permission"]


def desired_environment(reviewer_id: int) -> dict[str, Any]:
    return {
        "wait_timer": 0,
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "id": reviewer_id}],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def _environment_path(expected: dict[str, Any]) -> str:
    environment = urllib.parse.quote(expected["environment"], safe="")
    return f"/repos/{expected['repository']}/environments/{environment}"


def _get_optional_environment(
    request: GithubRequest,
    path: str,
    token: str,
) -> dict[str, Any] | None:
    try:
        value = request("GET", path, token, None)
    except GithubApiError as error:
        if error.status == 404:
            return None
        raise
    if not isinstance(value, dict):
        fail("github_environment_api_object_required")
    return value


def _read_branch_policies(
    request: GithubRequest,
    environment_path: str,
    token: str,
) -> dict[str, Any]:
    value = request(
        "GET",
        f"{environment_path}/deployment-branch-policies?per_page=100",
        token,
        None,
    )
    if not isinstance(value, dict):
        fail("github_environment_api_object_required")
    return value


def _read_environment_secret_names(
    request: GithubRequest,
    environment_path: str,
    token: str,
    allowed_names: set[str],
) -> list[str]:
    value = request(
        "GET",
        f"{environment_path}/secrets?per_page=100",
        token,
        None,
    )
    if not isinstance(value, dict) or not isinstance(value.get("secrets"), list):
        fail("github_environment_secrets_invalid")
    names: list[str] = []
    for secret in value["secrets"]:
        if (
            not isinstance(secret, dict)
            or not isinstance(secret.get("name"), str)
            or not secret["name"]
        ):
            fail("github_environment_secrets_invalid")
        names.append(secret["name"])
    if (
        value.get("total_count") != len(names)
        or len(names) != len(set(names))
        or not set(names).issubset(allowed_names)
    ):
        fail("github_environment_secrets_forbidden")
    return sorted(names)


def _current_state_digest(
    repository_id: int,
    owner_id: int,
    reviewer_id: int,
    permission: str,
    environment: dict[str, Any] | None,
    branches: dict[str, Any] | None,
    secret_names: list[str],
) -> str:
    return payload_digest(
        {
            "repositoryId": repository_id,
            "ownerId": owner_id,
            "reviewerId": reviewer_id,
            "reviewerPermission": permission,
            "environment": environment,
            "branchPolicies": branches,
            "environmentSecretNamesDigest": payload_digest(secret_names),
        }
    )


def _configuration_status(
    repository: dict[str, Any],
    environment: dict[str, Any] | None,
    branches: dict[str, Any] | None,
    expected: dict[str, Any],
) -> str:
    if environment is None:
        return "MISSING"
    if branches is None:
        fail("github_environment_branch_policy_invalid")
    try:
        from scripts.github_environment_contract import validate_environment_payloads
    except ModuleNotFoundError:
        from github_environment_contract import validate_environment_payloads

    try:
        validate_environment_payloads(repository, environment, branches, expected)
    except ValueError:
        return "DRIFTED"
    return "READY"


def build_plan(
    token_path: Path,
    reviewer_login: str,
    *,
    contract: str = DEFAULT_CONTRACT,
    request: GithubRequest | None = None,
) -> dict[str, Any]:
    if not reviewer_login or any(character.isspace() for character in reviewer_login):
        fail("github_environment_reviewer_login_invalid")
    token = read_restricted_token(token_path)
    call = request or github_request_json
    expected, policy_digest = load_contract(contract)
    repository_path = f"/repos/{expected['repository']}"
    repository = call("GET", repository_path, token, None)
    if not isinstance(repository, dict):
        fail("github_environment_api_object_required")
    repository_id, owner_id = validate_repository(repository, expected)

    encoded_login = urllib.parse.quote(reviewer_login, safe="")
    try:
        reviewer = call("GET", f"/users/{encoded_login}", token, None)
        permission = call(
            "GET",
            f"{repository_path}/collaborators/{encoded_login}/permission",
            token,
            None,
        )
    except GithubApiError as error:
        if error.status == 404:
            fail("github_environment_reviewer_repository_access_required")
        raise
    reviewer_id, repository_permission = validate_reviewer(
        reviewer, permission, expected, reviewer_login, owner_id
    )

    environment_path = _environment_path(expected)
    environment = _get_optional_environment(call, environment_path, token)
    branches = (
        _read_branch_policies(call, environment_path, token)
        if environment is not None
        else None
    )
    secret_names = (
        _read_environment_secret_names(
            call,
            environment_path,
            token,
            allowed_environment_secret_names(contract),
        )
        if environment is not None
        else []
    )
    status = _configuration_status(repository, environment, branches, expected)
    operations = {
        "MISSING": [
            "upsert-protected-environment",
            "create-main-branch-policy",
            "verify-exact-contract",
        ],
        "DRIFTED": [
            "upsert-protected-environment",
            "replace-branch-policies-with-main",
            "verify-exact-contract",
        ],
        "READY": [],
    }[status]
    plan = {
        "schemaVersion": 1,
        "kind": plan_kind(contract),
        "policyDigest": policy_digest,
        "repositoryIdentityDigest": payload_digest(
            {
                "id": repository_id,
                "ownerId": owner_id,
                "fullName": expected["repository"],
                "visibility": expected["repositoryVisibility"],
            }
        ),
        "reviewerIdentityDigest": payload_digest(
            {"type": expected["reviewerType"], "id": reviewer_id}
        ),
        "reviewerPermission": repository_permission,
        "environment": expected["environment"],
        "status": status,
        "currentStateDigest": _current_state_digest(
            repository_id,
            owner_id,
            reviewer_id,
            repository_permission,
            environment,
            branches,
            secret_names,
        ),
        "desiredStateDigest": payload_digest(
            {
                "environment": desired_environment(reviewer_id),
                "branchPolicies": [
                    {"name": expected["deploymentBranch"], "type": "branch"}
                ],
            }
        ),
        "operations": operations,
        "controls": PLAN_CONTROLS,
    }
    plan["planDigest"] = payload_digest(plan)
    validate_plan(plan, contract=contract)
    return plan


def validate_plan(
    plan: Any,
    *,
    contract: str = DEFAULT_CONTRACT,
) -> dict[str, Any]:
    value = exact_keys(
        plan,
        {
            "schemaVersion",
            "kind",
            "policyDigest",
            "repositoryIdentityDigest",
            "reviewerIdentityDigest",
            "reviewerPermission",
            "environment",
            "status",
            "currentStateDigest",
            "desiredStateDigest",
            "operations",
            "controls",
            "planDigest",
        },
        "github_environment_plan_keys_invalid",
    )
    expected, policy_digest = load_contract(contract)
    if (
        value["schemaVersion"] != 1
        or value["kind"] != plan_kind(contract)
        or value["policyDigest"] != policy_digest
        or value["environment"] != expected["environment"]
        or value["status"] not in {"MISSING", "DRIFTED", "READY"}
        or value["reviewerPermission"] not in REPOSITORY_PERMISSIONS
        or value["controls"] != PLAN_CONTROLS
        or not isinstance(value["operations"], list)
        or not all(isinstance(item, str) for item in value["operations"])
    ):
        fail("github_environment_plan_invalid")
    for field in (
        "policyDigest",
        "repositoryIdentityDigest",
        "reviewerIdentityDigest",
        "currentStateDigest",
        "desiredStateDigest",
        "planDigest",
    ):
        digest = value[field]
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or len(digest) != 71
        ):
            fail("github_environment_plan_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("planDigest")
    if value["planDigest"] != payload_digest(unsigned):
        fail("github_environment_plan_digest_mismatch")
    expected_operations = {
        "MISSING": [
            "upsert-protected-environment",
            "create-main-branch-policy",
            "verify-exact-contract",
        ],
        "DRIFTED": [
            "upsert-protected-environment",
            "replace-branch-policies-with-main",
            "verify-exact-contract",
        ],
        "READY": [],
    }
    if value["operations"] != expected_operations[value["status"]]:
        fail("github_environment_plan_operations_invalid")
    return value


def read_plan(
    path: Path,
    *,
    contract: str = DEFAULT_CONTRACT,
) -> dict[str, Any]:
    try:
        if path.is_symlink():
            fail("github_environment_plan_symlink_forbidden")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            fail("github_environment_plan_regular_file_required")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            fail("github_environment_plan_permissions_invalid")
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("github_environment_plan_read_failed") from error
    return validate_plan(value, contract=contract)


def write_plan(path: Path, plan: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(plan, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("ascii")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fail("github_environment_plan_output_exists")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def verify_environment(
    token_path: Path,
    *,
    contract: str = DEFAULT_CONTRACT,
    request: GithubRequest | None = None,
) -> dict[str, Any]:
    expected, _ = load_contract(contract)
    if request is None:
        evidence = fetch_environment_evidence(token_path, expected)
        token = read_restricted_token(token_path)
        secret_names = _read_environment_secret_names(
            github_request_json,
            _environment_path(expected),
            token,
            allowed_environment_secret_names(contract),
        )
        evidence["environmentSecretCount"] = len(secret_names)
        evidence["environmentSecretNamesDigest"] = payload_digest(secret_names)
        return evidence
    token = read_restricted_token(token_path)

    def get(path: str, supplied_token: str) -> Any:
        if supplied_token != token:
            fail("github_environment_token_mismatch")
        return request("GET", path, supplied_token, None)

    evidence = fetch_environment_evidence(token_path, expected, get_json=get)
    secret_names = _read_environment_secret_names(
        request,
        _environment_path(expected),
        token,
        allowed_environment_secret_names(contract),
    )
    evidence["environmentSecretCount"] = len(secret_names)
    evidence["environmentSecretNamesDigest"] = payload_digest(secret_names)
    return evidence


def apply_plan(
    token_path: Path,
    plan_path: Path,
    reviewer_login: str,
    expected_plan_digest: str,
    *,
    contract: str = DEFAULT_CONTRACT,
    request: GithubRequest | None = None,
) -> dict[str, Any]:
    stored = read_plan(plan_path, contract=contract)
    if stored["planDigest"] != expected_plan_digest:
        fail("github_environment_expected_plan_digest_mismatch")
    call = request or github_request_json
    current = build_plan(
        token_path,
        reviewer_login,
        contract=contract,
        request=call,
    )
    if current != stored:
        fail("github_environment_plan_stale")
    if current["status"] == "READY":
        return verify_environment(token_path, contract=contract, request=call)

    token = read_restricted_token(token_path)
    expected, _ = load_contract(contract)
    reviewer_id_digest = current["reviewerIdentityDigest"]
    encoded_login = urllib.parse.quote(reviewer_login, safe="")
    reviewer = call("GET", f"/users/{encoded_login}", token, None)
    if not isinstance(reviewer, dict):
        fail("github_environment_api_object_required")
    reviewer_id = _positive_id(
        reviewer.get("id"), "github_environment_reviewer_invalid"
    )
    if payload_digest({"type": expected["reviewerType"], "id": reviewer_id}) != (
        reviewer_id_digest
    ):
        fail("github_environment_reviewer_identity_changed")

    environment_path = _environment_path(expected)
    try:
        call(
            "PUT",
            environment_path,
            token,
            desired_environment(reviewer_id),
        )
    except GithubApiError as error:
        if error.status == 422:
            fail("github_environment_required_reviewers_unavailable")
        raise

    branches = _read_branch_policies(call, environment_path, token)
    policies = branches.get("branch_policies")
    if not isinstance(policies, list):
        fail("github_environment_branch_policy_invalid")
    main_seen = False
    for policy in policies:
        if not isinstance(policy, dict):
            fail("github_environment_branch_policy_invalid")
        policy_id = _positive_id(
            policy.get("id"), "github_environment_branch_policy_invalid"
        )
        if policy.get("name") == expected["deploymentBranch"] and not main_seen:
            main_seen = True
            continue
        call(
            "DELETE",
            f"{environment_path}/deployment-branch-policies/{policy_id}",
            token,
            None,
        )
    if not main_seen:
        call(
            "POST",
            f"{environment_path}/deployment-branch-policies",
            token,
            {"name": expected["deploymentBranch"], "type": "branch"},
        )
    return verify_environment(token_path, contract=contract, request=call)


def main(
    argv: list[str] | None = None,
    *,
    contract_choices: tuple[str, ...] = (DEFAULT_CONTRACT,),
    contract_required: bool = False,
) -> int:
    if (
        not contract_choices
        or len(contract_choices) != len(set(contract_choices))
        or not set(contract_choices).issubset(SUPPORTED_CONTRACTS)
    ):
        fail("github_environment_contract_choices_invalid")
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    contract_argument: dict[str, Any] = {"choices": contract_choices}
    if contract_required:
        contract_argument["required"] = True
    else:
        contract_argument["default"] = contract_choices[0]

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--token-file", type=Path, required=True)
    plan_parser.add_argument("--reviewer-login", required=True)
    plan_parser.add_argument("--output", type=Path, required=True)
    plan_parser.add_argument("--contract", **contract_argument)

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--token-file", type=Path, required=True)
    apply_parser.add_argument("--reviewer-login", required=True)
    apply_parser.add_argument("--plan", type=Path, required=True)
    apply_parser.add_argument("--expected-plan-digest", required=True)
    apply_parser.add_argument("--contract", **contract_argument)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--token-file", type=Path, required=True)
    verify_parser.add_argument("--contract", **contract_argument)

    args = parser.parse_args(argv)
    if args.command == "plan":
        value = build_plan(
            args.token_file,
            args.reviewer_login,
            contract=args.contract,
        )
        write_plan(args.output.resolve(), value)
        print(
            "github_environment_plan_created "
            f"contract={args.contract} status={value['status']} "
            f"digest={value['planDigest']} "
            f"operations={len(value['operations'])}"
        )
        return 0
    if args.command == "apply":
        evidence = apply_plan(
            args.token_file,
            args.plan,
            args.reviewer_login,
            args.expected_plan_digest,
            contract=args.contract,
        )
        print(
            "github_environment_configuration_valid "
            f"contract={args.contract} digest={payload_digest(evidence)} "
            f"reviewers={evidence['reviewerCount']} "
            "preventSelfReview=true deploymentBranch=main"
        )
        return 0
    evidence = verify_environment(args.token_file, contract=args.contract)
    print(
        "github_environment_configuration_valid "
        f"contract={args.contract} digest={payload_digest(evidence)} "
        f"reviewers={evidence['reviewerCount']} "
        "preventSelfReview=true deploymentBranch=main"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error)
        raise SystemExit(1)
