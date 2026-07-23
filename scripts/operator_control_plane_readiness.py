#!/usr/bin/env python3
"""Observe the lab's GitHub control plane without retaining identities or secrets."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.github_environment_contract import (
        ENVIRONMENT_CONTRACTS,
        GithubGetter,
        fetch_environment_evidence,
        load_expected_environment,
        payload_digest,
    )
    from scripts.validate_repository import ROOT, canonical_digest
except ModuleNotFoundError:
    from github_environment_contract import (
        ENVIRONMENT_CONTRACTS,
        GithubGetter,
        fetch_environment_evidence,
        load_expected_environment,
        payload_digest,
    )
    from validate_repository import ROOT, canonical_digest


POLICY_PATH = ROOT / "config" / "operator-control-plane-readiness.lock.json"
SCHEMA_PATH = ROOT / "schemas" / "operator-control-plane-readiness-v1.schema.json"
EXPECTED_POLICY_DIGEST = (
    "sha256:c344bba86571ab5cf347c8c70e0745c6c22afd7cc9fd930f91f7cf5b15db0ec4"
)
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
REPORT_KIND = "orchestra.reference-lab.operator-control-plane-readiness.v1"
API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
OBSERVATION_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
GithubRequest = Callable[[str, str, str, dict[str, Any] | None], Any]
Signer = Callable[[bytes, Path], bytes]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def parse_json_bytes(raw: bytes, code: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                fail(f"{code}_duplicate_key")
            value[key] = child
        return value

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{code}_json_invalid") from error
    if not isinstance(value, dict):
        fail(f"{code}_object_required")
    return value


def read_json(path: Path, code: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"{code}_read_failed") from error
    return raw, parse_json_bytes(raw, code)


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(code) from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(code)
    return parsed.astimezone(timezone.utc)


def format_time(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def validate_schema(schema: dict[str, Any]) -> None:
    def require_strict_objects(value: Any, path: str = "$") -> None:
        if isinstance(value, list):
            for index, child in enumerate(value):
                require_strict_objects(child, f"{path}/{index}")
            return
        if not isinstance(value, dict):
            return
        if (
            value.get("type") == "object"
            and value.get("additionalProperties") is not False
        ):
            fail(f"operator_control_plane_schema_not_strict:{path}")
        for key, child in value.items():
            require_strict_objects(child, f"{path}/{key}")

    strict_keys(
        schema,
        {
            "$schema",
            "$id",
            "additionalProperties",
            "properties",
            "required",
            "type",
        },
        "operator_control_plane_schema_keys_invalid",
    )
    if (
        schema["type"] != "object"
        or schema["additionalProperties"] is not False
        or schema["properties"].get("kind", {}).get("const") != REPORT_KIND
        or schema["properties"].get("profileId", {}).get("const") != PROFILE_ID
    ):
        fail("operator_control_plane_schema_identity_invalid")
    require_strict_objects(schema)


def expected_policy(schema_digest: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": "orchestra.reference-lab.operator-control-plane-readiness-policy.v1",
        "profileId": PROFILE_ID,
        "environmentContracts": list(ENVIRONMENT_CONTRACTS),
        "githubApp": {
            "purpose": "platform-release-and-package-read-only",
            "slug": "orchestra-reference-lab-release-reader",
            "owner": {"id": 37515097, "type": "User"},
            "repositorySelection": "selected",
            "installationCount": 1,
            "repository": {
                "id": 1214962908,
                "fullName": "caglarsubas/agent-hook-v2",
                "ownerId": 37515097,
                "private": True,
                "visibility": "private",
                "archived": False,
            },
            "requiredPermissions": {"contents": "read", "packages": "read"},
            "optionalPermissions": {"metadata": "read"},
            "events": [],
        },
        "observation": {
            "maxAgeMinutes": 60,
            "fullInstallationTokenRequired": True,
            "tokenRevocationRequired": True,
            "reportSchema": "schemas/operator-control-plane-readiness-v1.schema.json",
            "reportSchemaDigest": schema_digest,
        },
        "claim": {
            "independentReviewRequired": True,
            "provisioningReady": False,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
            "customerCertified": False,
            "redHatCertified": False,
            "contractualSla": False,
        },
    }


def load_policy() -> tuple[dict[str, Any], str]:
    _, schema = read_json(SCHEMA_PATH, "operator_control_plane_schema")
    validate_schema(schema)
    schema_digest = canonical_digest(schema)
    _, policy = read_json(POLICY_PATH, "operator_control_plane_policy")
    if policy != expected_policy(schema_digest):
        fail("operator_control_plane_policy_semantics_invalid")
    policy_digest = canonical_digest(policy)
    if policy_digest != EXPECTED_POLICY_DIGEST:
        fail("operator_control_plane_policy_digest_invalid")
    for contract in policy["environmentContracts"]:
        expected = load_expected_environment(contract)
        if (
            expected.get("repository")
            != "caglarsubas/orchestra-openshift-reference-lab"
            or expected.get("repositoryId") != "1307302690"
            or expected.get("repositoryOwnerId") != "37515097"
            or expected.get("repositoryVisibility") != "private"
            or expected.get("deploymentBranch") != "main"
        ):
            fail(f"operator_control_plane_environment_contract_invalid:{contract}")
    return policy, policy_digest


def read_private_key(path: Path) -> None:
    try:
        if path.is_symlink():
            fail("operator_control_plane_app_key_symlink_forbidden")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            fail("operator_control_plane_app_key_regular_file_required")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            fail("operator_control_plane_app_key_permissions_invalid")
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError("operator_control_plane_app_key_read_failed") from error
    if not 256 <= len(raw) <= 32768:
        fail("operator_control_plane_app_key_size_invalid")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("operator_control_plane_app_key_encoding_invalid") from error
    private_key_begin = "-----BEGIN " + "PRIVATE KEY-----"
    private_key_end = "-----END " + "PRIVATE KEY-----"
    rsa_key_begin = "-----BEGIN RSA " + "PRIVATE KEY-----"
    rsa_key_end = "-----END RSA " + "PRIVATE KEY-----"
    if not (
        (private_key_begin in text and private_key_end in text)
        or (rsa_key_begin in text and rsa_key_end in text)
    ):
        fail("operator_control_plane_app_key_pem_invalid")


def openssl_sign(message: bytes, private_key_path: Path) -> bytes:
    result = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(private_key_path),
        ],
        input=message,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or not 64 <= len(result.stdout) <= 1024:
        fail("operator_control_plane_app_jwt_sign_failed")
    return result.stdout


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_app_jwt(
    app_id: int,
    private_key_path: Path,
    observed_at: datetime,
    *,
    sign: Signer = openssl_sign,
) -> str:
    if not isinstance(app_id, int) or isinstance(app_id, bool) or app_id <= 0:
        fail("operator_control_plane_app_id_invalid")
    if observed_at.tzinfo is None or observed_at.utcoffset() != timedelta(0):
        fail("operator_control_plane_observed_at_invalid")
    observed_at = observed_at.astimezone(timezone.utc)
    read_private_key(private_key_path)
    issued_at = int(observed_at.timestamp()) - 60
    expires_at = issued_at + 600
    header = base64url(
        json.dumps(
            {"alg": "RS256", "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    payload = base64url(
        json.dumps(
            {"exp": expires_at, "iat": issued_at, "iss": str(app_id)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = sign(signing_input, private_key_path)
    if not isinstance(signature, bytes) or not signature:
        fail("operator_control_plane_app_jwt_sign_failed")
    return f"{header}.{payload}.{base64url(signature)}"


def github_request_json(
    method: str,
    path: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    if method not in {"GET", "POST", "DELETE"} or not path.startswith("/"):
        fail("operator_control_plane_github_request_invalid")
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "orchestra-reference-lab-control-plane-verifier/1",
        "X-GitHub-Api-Version": API_VERSION,
    }
    if body is not None:
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{API_ROOT}{path}",
        headers=headers,
        data=data,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if method == "DELETE":
                if response.status != 204:
                    fail("operator_control_plane_github_delete_status_invalid")
                return None
            if response.status not in {200, 201}:
                fail("operator_control_plane_github_status_invalid")
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError(f"operator_control_plane_github_http_{error.code}") from error
    except (
        OSError,
        TimeoutError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("operator_control_plane_github_request_failed") from error


def validate_permissions(
    value: Any, policy: dict[str, Any], code: str
) -> dict[str, str]:
    if not isinstance(value, dict):
        fail(code)
    required = policy["requiredPermissions"]
    optional = policy["optionalPermissions"]
    allowed = set(required) | set(optional)
    if set(value) - allowed:
        fail(code)
    if any(value.get(key) != access for key, access in required.items()):
        fail(code)
    if any(key in value and value[key] != access for key, access in optional.items()):
        fail(code)
    if any(access != "read" for access in value.values()):
        fail(code)
    return {key: value[key] for key in sorted(value)}


def validate_repository_payload(value: Any, expected: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("operator_control_plane_app_repository_invalid")
    owner = value.get("owner")
    if (
        value.get("id") != expected["id"]
        or value.get("full_name") != expected["fullName"]
        or value.get("private") is not expected["private"]
        or value.get("visibility") != expected["visibility"]
        or value.get("archived") is not expected["archived"]
        or not isinstance(owner, dict)
        or owner.get("id") != expected["ownerId"]
    ):
        fail("operator_control_plane_app_repository_invalid")
    return {
        "id": value["id"],
        "fullName": value["full_name"],
        "ownerId": owner["id"],
        "private": value["private"],
        "visibility": value["visibility"],
        "archived": value["archived"],
    }


def observe_github_app(
    policy: dict[str, Any],
    private_key_path: Path,
    app_id: int,
    installation_id: int,
    observed_at: datetime,
    *,
    request_json: GithubRequest = github_request_json,
    sign: Signer = openssl_sign,
) -> dict[str, Any]:
    if (
        not isinstance(installation_id, int)
        or isinstance(installation_id, bool)
        or installation_id <= 0
    ):
        fail("operator_control_plane_installation_id_invalid")
    app_policy = policy["githubApp"]
    jwt = create_app_jwt(
        app_id,
        private_key_path,
        observed_at,
        sign=sign,
    )
    app = request_json("GET", "/app", jwt, None)
    installations = request_json("GET", "/app/installations?per_page=100", jwt, None)
    if not isinstance(app, dict):
        fail("operator_control_plane_app_api_object_required")
    if (
        not isinstance(installations, list)
        or len(installations) != app_policy["installationCount"]
        or not isinstance(installations[0], dict)
    ):
        fail("operator_control_plane_app_installation_set_invalid")
    installation = installations[0]
    owner = app.get("owner")
    if (
        app.get("id") != app_id
        or app.get("slug") != app_policy["slug"]
        or not isinstance(owner, dict)
        or owner.get("id") != app_policy["owner"]["id"]
        or owner.get("type") != app_policy["owner"]["type"]
        or app.get("events") != app_policy["events"]
    ):
        fail("operator_control_plane_app_identity_invalid")
    app_permissions = validate_permissions(
        app.get("permissions"),
        app_policy,
        "operator_control_plane_app_permissions_invalid",
    )
    account = installation.get("account")
    if (
        installation.get("id") != installation_id
        or installation.get("app_id") != app_id
        or installation.get("app_slug") != app_policy["slug"]
        or installation.get("target_type") != app_policy["owner"]["type"]
        or not isinstance(account, dict)
        or account.get("id") != app_policy["owner"]["id"]
        or account.get("type") != app_policy["owner"]["type"]
        or installation.get("repository_selection") != app_policy["repositorySelection"]
        or installation.get("events") != app_policy["events"]
        or installation.get("suspended_at") is not None
    ):
        fail("operator_control_plane_installation_identity_invalid")
    installation_permissions = validate_permissions(
        installation.get("permissions"),
        app_policy,
        "operator_control_plane_installation_permissions_invalid",
    )
    if installation_permissions != app_permissions:
        fail("operator_control_plane_app_permission_drift")
    installation_identity = {
        "id": installation_id,
        "appId": app_id,
        "accountId": account["id"],
        "targetType": installation["target_type"],
    }

    token_response = request_json(
        "POST",
        f"/app/installations/{installation_id}/access_tokens",
        jwt,
        {},
    )
    if not isinstance(token_response, dict):
        fail("operator_control_plane_installation_token_invalid")
    token = token_response.get("token")
    if (
        not isinstance(token, str)
        or not 20 <= len(token) <= 4096
        or any(character.isspace() for character in token)
    ):
        fail("operator_control_plane_installation_token_invalid")

    try:
        expires_at = parse_time(
            token_response.get("expires_at"),
            "operator_control_plane_installation_token_expiry_invalid",
        )
        token_permissions = validate_permissions(
            token_response.get("permissions"),
            app_policy,
            "operator_control_plane_installation_token_permissions_invalid",
        )
        if (
            expires_at <= observed_at
            or expires_at > observed_at + timedelta(minutes=65)
            or token_response.get("repository_selection")
            != app_policy["repositorySelection"]
            or token_permissions != installation_permissions
        ):
            fail("operator_control_plane_installation_token_invalid")
        repositories = request_json(
            "GET", "/installation/repositories?per_page=100", token, None
        )
        if not isinstance(repositories, dict):
            fail("operator_control_plane_app_repositories_invalid")
        values = repositories.get("repositories")
        if (
            repositories.get("total_count") != 1
            or not isinstance(values, list)
            or len(values) != 1
        ):
            fail("operator_control_plane_app_repository_scope_invalid")
        repository = validate_repository_payload(values[0], app_policy["repository"])
    finally:
        request_json("DELETE", "/installation/token", token, None)

    installation_identity_digest = payload_digest(installation_identity)
    return {
        "applicationIdentityDigest": payload_digest(
            {"id": app_id, "slug": app_policy["slug"], "ownerId": owner["id"]}
        ),
        "installationIdentityDigest": installation_identity_digest,
        "applicationInstallationSetDigest": payload_digest(
            [installation_identity_digest]
        ),
        "applicationInstallationCount": 1,
        "repositoryIdentityDigest": payload_digest(repository),
        "repositorySetDigest": payload_digest([repository]),
        "permissionDigest": payload_digest(installation_permissions),
        "eventsDigest": payload_digest(app_policy["events"]),
        "repositorySelection": "selected",
        "repositoryCount": 1,
        "installationSuspended": False,
        "tokenRevoked": True,
    }


def collect_environment_observations(
    policy: dict[str, Any],
    token_path: Path,
    *,
    get_json: GithubGetter | None = None,
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    repository_digests: set[str] = set()
    environment_digests: set[str] = set()
    for contract in policy["environmentContracts"]:
        expected = load_expected_environment(contract)
        evidence = fetch_environment_evidence(
            token_path,
            expected,
            get_json=get_json,
        )
        observation = {
            "contract": contract,
            "contractDigest": payload_digest(expected),
            "repositoryIdentityDigest": evidence["repositoryIdentityDigest"],
            "environmentIdentityDigest": evidence["environmentIdentityDigest"],
            "reviewerIdentityDigests": evidence["reviewerIdentityDigests"],
            "reviewerCount": evidence["reviewerCount"],
            "preventSelfReview": evidence["preventSelfReview"],
            "deploymentBranchPolicyDigest": evidence["deploymentBranchPolicyDigest"],
        }
        observations.append(observation)
        repository_digests.add(observation["repositoryIdentityDigest"])
        environment_digests.add(observation["environmentIdentityDigest"])
    if (
        len(observations) != len(ENVIRONMENT_CONTRACTS)
        or len(repository_digests) != 1
        or len(environment_digests) != len(ENVIRONMENT_CONTRACTS)
    ):
        fail("operator_control_plane_environment_set_invalid")
    return observations


def report_claims() -> dict[str, bool]:
    return {
        "operatorControlPlaneObserved": True,
        "independentReviewRequired": True,
        "githubAppCredentialsRetained": False,
        "provisioningReady": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }


def collect_readiness(
    *,
    observation_id: str,
    repository_revision: str,
    observed_at: datetime,
    environment_token_path: Path,
    app_private_key_path: Path,
    app_id: int,
    installation_id: int,
    environment_get_json: GithubGetter | None = None,
    app_request_json: GithubRequest = github_request_json,
    sign: Signer = openssl_sign,
) -> dict[str, Any]:
    policy, policy_digest = load_policy()
    if not OBSERVATION_ID.fullmatch(observation_id):
        fail("operator_control_plane_observation_id_invalid")
    if not REVISION.fullmatch(repository_revision):
        fail("operator_control_plane_repository_revision_invalid")
    if observed_at.tzinfo is None or observed_at.utcoffset() != timedelta(0):
        fail("operator_control_plane_observed_at_invalid")
    observed_at = observed_at.astimezone(timezone.utc)
    report = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "observationId": observation_id,
        "profileId": PROFILE_ID,
        "policyDigest": policy_digest,
        "repositoryRevision": repository_revision,
        "observedAt": format_time(observed_at),
        "validUntil": format_time(
            observed_at + timedelta(minutes=policy["observation"]["maxAgeMinutes"])
        ),
        "environmentObservations": collect_environment_observations(
            policy,
            environment_token_path,
            get_json=environment_get_json,
        ),
        "githubAppObservation": observe_github_app(
            policy,
            app_private_key_path,
            app_id,
            installation_id,
            observed_at,
            request_json=app_request_json,
            sign=sign,
        ),
        "claims": report_claims(),
    }
    validate_report(report)
    return report


def _require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(code)
    return value


def validate_report(
    report: dict[str, Any],
    *,
    assessed_at: datetime | None = None,
) -> None:
    policy, policy_digest = load_policy()
    strict_keys(
        report,
        {
            "schemaVersion",
            "kind",
            "observationId",
            "profileId",
            "policyDigest",
            "repositoryRevision",
            "observedAt",
            "validUntil",
            "environmentObservations",
            "githubAppObservation",
            "claims",
        },
        "operator_control_plane_report_keys_invalid",
    )
    claims = strict_keys(
        report["claims"],
        set(report_claims()),
        "operator_control_plane_report_claims_invalid",
    )
    if (
        type(report["schemaVersion"]) is not int
        or report["schemaVersion"] != 1
        or report["kind"] != REPORT_KIND
        or report["profileId"] != PROFILE_ID
        or report["policyDigest"] != policy_digest
        or not isinstance(report["observationId"], str)
        or not OBSERVATION_ID.fullmatch(report["observationId"])
        or not isinstance(report["repositoryRevision"], str)
        or not REVISION.fullmatch(report["repositoryRevision"])
        or any(type(value) is not bool for value in claims.values())
        or claims != report_claims()
    ):
        fail("operator_control_plane_report_identity_invalid")
    observed_at = parse_time(
        report["observedAt"], "operator_control_plane_report_time_invalid"
    )
    valid_until = parse_time(
        report["validUntil"], "operator_control_plane_report_time_invalid"
    )
    if valid_until - observed_at != timedelta(
        minutes=policy["observation"]["maxAgeMinutes"]
    ):
        fail("operator_control_plane_report_window_invalid")
    if assessed_at is not None:
        if assessed_at.tzinfo is None or assessed_at.utcoffset() != timedelta(0):
            fail("operator_control_plane_assessed_at_invalid")
        assessed_at = assessed_at.astimezone(timezone.utc)
        if assessed_at < observed_at or assessed_at > valid_until:
            fail("operator_control_plane_report_stale")

    environment_observations = report["environmentObservations"]
    if not isinstance(environment_observations, list) or len(
        environment_observations
    ) != len(ENVIRONMENT_CONTRACTS):
        fail("operator_control_plane_report_environment_set_invalid")
    repository_digests: set[str] = set()
    environment_digests: set[str] = set()
    expected_environment_repository_digest = payload_digest(
        {
            "id": 1307302690,
            "ownerId": 37515097,
            "fullName": "caglarsubas/orchestra-openshift-reference-lab",
            "visibility": "private",
        }
    )
    expected_branch_policy_digest = payload_digest(
        {
            "protectedBranches": False,
            "customBranchPolicies": True,
            "branches": ["main"],
        }
    )
    for index, contract in enumerate(ENVIRONMENT_CONTRACTS):
        observation = strict_keys(
            environment_observations[index],
            {
                "contract",
                "contractDigest",
                "repositoryIdentityDigest",
                "environmentIdentityDigest",
                "reviewerIdentityDigests",
                "reviewerCount",
                "preventSelfReview",
                "deploymentBranchPolicyDigest",
            },
            "operator_control_plane_report_environment_invalid",
        )
        expected = load_expected_environment(contract)
        reviewers = observation["reviewerIdentityDigests"]
        if (
            observation["contract"] != contract
            or observation["contractDigest"] != payload_digest(expected)
            or observation["repositoryIdentityDigest"]
            != expected_environment_repository_digest
            or observation["deploymentBranchPolicyDigest"]
            != expected_branch_policy_digest
            or observation["preventSelfReview"] is not True
            or not isinstance(observation["reviewerCount"], int)
            or isinstance(observation["reviewerCount"], bool)
            or not 1 <= observation["reviewerCount"] <= 6
            or not isinstance(reviewers, list)
            or len(reviewers) != observation["reviewerCount"]
            or len(set(reviewers)) != len(reviewers)
        ):
            fail("operator_control_plane_report_environment_invalid")
        for key in (
            "contractDigest",
            "repositoryIdentityDigest",
            "environmentIdentityDigest",
            "deploymentBranchPolicyDigest",
        ):
            _require_digest(
                observation[key],
                "operator_control_plane_report_environment_digest_invalid",
            )
        for reviewer in reviewers:
            _require_digest(
                reviewer,
                "operator_control_plane_report_reviewer_digest_invalid",
            )
        repository_digests.add(observation["repositoryIdentityDigest"])
        environment_digests.add(observation["environmentIdentityDigest"])
    if len(repository_digests) != 1 or len(environment_digests) != len(
        ENVIRONMENT_CONTRACTS
    ):
        fail("operator_control_plane_report_environment_set_invalid")

    app = strict_keys(
        report["githubAppObservation"],
        {
            "applicationIdentityDigest",
            "installationIdentityDigest",
            "applicationInstallationSetDigest",
            "applicationInstallationCount",
            "repositoryIdentityDigest",
            "repositorySetDigest",
            "permissionDigest",
            "eventsDigest",
            "repositorySelection",
            "repositoryCount",
            "installationSuspended",
            "tokenRevoked",
        },
        "operator_control_plane_report_app_invalid",
    )
    for key in (
        "applicationIdentityDigest",
        "installationIdentityDigest",
        "applicationInstallationSetDigest",
        "repositoryIdentityDigest",
        "repositorySetDigest",
        "permissionDigest",
        "eventsDigest",
    ):
        _require_digest(app[key], "operator_control_plane_report_app_digest_invalid")
    expected_app_repository = {
        "id": policy["githubApp"]["repository"]["id"],
        "fullName": policy["githubApp"]["repository"]["fullName"],
        "ownerId": policy["githubApp"]["repository"]["ownerId"],
        "private": policy["githubApp"]["repository"]["private"],
        "visibility": policy["githubApp"]["repository"]["visibility"],
        "archived": policy["githubApp"]["repository"]["archived"],
    }
    allowed_permission_digests = {
        payload_digest(policy["githubApp"]["requiredPermissions"]),
        payload_digest(
            {
                **policy["githubApp"]["requiredPermissions"],
                **policy["githubApp"]["optionalPermissions"],
            }
        ),
    }
    if (
        app["repositorySelection"] != "selected"
        or type(app["applicationInstallationCount"]) is not int
        or app["applicationInstallationCount"]
        != policy["githubApp"]["installationCount"]
        or app["applicationInstallationSetDigest"]
        != payload_digest([app["installationIdentityDigest"]])
        or type(app["repositoryCount"]) is not int
        or app["repositoryCount"] != 1
        or app["installationSuspended"] is not False
        or app["tokenRevoked"] is not True
        or app["repositoryIdentityDigest"] != payload_digest(expected_app_repository)
        or app["repositorySetDigest"] != payload_digest([expected_app_repository])
        or app["permissionDigest"] not in allowed_permission_digests
        or app["eventsDigest"] != payload_digest(policy["githubApp"]["events"])
    ):
        fail("operator_control_plane_report_app_invalid")

    encoded = canonical_bytes(report).decode("ascii")
    for forbidden in (
        '"token"',
        '"privateKey"',
        '"login"',
        '"email"',
        "-----BEGIN",
        "ghs_",
    ):
        if forbidden in encoded:
            fail("operator_control_plane_report_sensitive_material_forbidden")


def write_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ValueError("operator_control_plane_report_create_failed") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value))
    except OSError as error:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ValueError("operator_control_plane_report_write_failed") from error


def add_app_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--app-private-key-file", type=Path, required=True)
    parser.add_argument("--app-id", type=int, required=True)
    parser.add_argument("--installation-id", type=int, required=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-policy")

    app = commands.add_parser("verify-app")
    add_app_arguments(app)

    collect = commands.add_parser("collect")
    collect.add_argument("--observation-id", required=True)
    collect.add_argument("--repository-revision", required=True)
    collect.add_argument("--environment-token-file", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)
    add_app_arguments(collect)

    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    verify.add_argument("--at", required=True)

    args = parser.parse_args(argv)
    if args.command == "validate-policy":
        _, digest = load_policy()
        print(f"operator_control_plane_readiness_policy_valid digest={digest}")
        return 0
    if args.command == "verify-app":
        policy, _ = load_policy()
        observation = observe_github_app(
            policy,
            args.app_private_key_file,
            args.app_id,
            args.installation_id,
            datetime.now(timezone.utc),
        )
        print(
            "github_app_installation_valid "
            f"digest={payload_digest(observation)} installationCount=1 "
            "repositoryCount=1 "
            "permissions=read-only tokenRevoked=true campaignEvidence=false"
        )
        return 0
    if args.command == "collect":
        report = collect_readiness(
            observation_id=args.observation_id,
            repository_revision=args.repository_revision,
            observed_at=datetime.now(timezone.utc),
            environment_token_path=args.environment_token_file,
            app_private_key_path=args.app_private_key_file,
            app_id=args.app_id,
            installation_id=args.installation_id,
        )
        write_create_only(args.output, report)
        print(
            "operator_control_plane_readiness_observed "
            f"observationId={report['observationId']} "
            f"digest={canonical_digest(report)} environments=6 repositoryCount=1 "
            "independentReviewRequired=true provisioningReady=false "
            "campaignEvidence=false referenceProfileVerified=false"
        )
        return 0
    if args.command == "verify":
        _, report = read_json(args.report, "operator_control_plane_report")
        validate_report(
            report,
            assessed_at=parse_time(
                args.at, "operator_control_plane_assessed_at_invalid"
            ),
        )
        print(
            "operator_control_plane_readiness_report_valid "
            f"observationId={report['observationId']} "
            f"digest={canonical_digest(report)} provisioningReady=false "
            "campaignEvidence=false referenceProfileVerified=false"
        )
        return 0
    fail("operator_control_plane_command_invalid")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
