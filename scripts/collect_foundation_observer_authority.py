#!/usr/bin/env python3
"""Collect payload-free proof of the live foundation-observer boundary."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.foundation_observation import (
        expected_federation,
        load_contract,
        validate_authority,
    )
    from scripts.prerequisite_observation import payload_digest
except ModuleNotFoundError:
    from foundation_observation import (
        expected_federation,
        load_contract,
        validate_authority,
    )
    from prerequisite_observation import payload_digest


KIND = "orchestra.reference-lab.foundation-observer-authority-observation.v1"
RunJson = Callable[[list[str]], Any]
TARGET_ROLES = {
    "roles/browser",
    "roles/compute.viewer",
    "roles/dns.reader",
    "roles/iam.securityReviewer",
    "roles/iam.serviceAccountViewer",
    "roles/serviceusage.serviceUsageConsumer",
}
SERVICES_ROLES = {
    "roles/artifactregistry.reader",
    "roles/browser",
    "roles/cloudkms.viewer",
    "roles/compute.viewer",
    "roles/container.clusterViewer",
    "roles/dns.reader",
    "roles/iam.securityReviewer",
    "roles/iam.serviceAccountViewer",
    "roles/serviceusage.serviceUsageConsumer",
}
CUSTOM_ROLE_ID = "orchestraFoundationStorageMetadataObserver"
CUSTOM_ROLE_PERMISSIONS = {
    "storage.buckets.get",
    "storage.buckets.getIamPolicy",
    "storage.managedFolders.get",
    "storage.managedFolders.getIamPolicy",
    "storage.managedFolders.list",
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def gcloud_json(arguments: list[str]) -> Any:
    try:
        result = subprocess.run(
            ["gcloud", *arguments, "--format=json"],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"},
        )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        fail("foundation_observer_authority_command_timeout")
    except (
        OSError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
    ) as error:
        detail = (
            error.stderr.strip()
            if isinstance(error, subprocess.CalledProcessError)
            else str(error)
        )
        fail(f"foundation_observer_authority_command_failed:{detail}")


def _bindings(policy: Any, code: str) -> list[dict[str, Any]]:
    if not isinstance(policy, dict):
        fail(code)
    bindings = policy.get("bindings", [])
    if not isinstance(bindings, list):
        fail(code)
    for binding in bindings:
        if (
            not isinstance(binding, dict)
            or not isinstance(binding.get("role"), str)
            or not isinstance(binding.get("members"), list)
            or not all(
                isinstance(member, str) for member in binding["members"]
            )
        ):
            fail(code)
    return bindings


def member_roles(policy: Any, member: str, code: str) -> set[str]:
    return {
        binding["role"]
        for binding in _bindings(policy, code)
        if member in binding["members"]
    }


def _verify_provider(
    provider: Any, federation: dict[str, Any]
) -> tuple[str, str]:
    expected_mapping = {
        "google.subject": (
            "'foundation-observation:' + assertion.repository_id + ':' + "
            "assertion.environment"
        ),
        "attribute.actor_id": "assertion.actor_id",
        "attribute.environment": "assertion.environment",
        "attribute.event_name": "assertion.event_name",
        "attribute.ref": "assertion.ref",
        "attribute.repository": "assertion.repository",
        "attribute.repository_id": "assertion.repository_id",
        "attribute.repository_owner_id": "assertion.repository_owner_id",
        "attribute.repository_visibility": "assertion.repository_visibility",
        "attribute.workflow_ref": "assertion.workflow_ref",
    }
    if (
        not isinstance(provider, dict)
        or not isinstance(provider.get("name"), str)
        or not provider["name"].endswith(
            "/locations/global/workloadIdentityPools/orchestra-lab-github/"
            "providers/foundation-observation"
        )
        or provider.get("state") != "ACTIVE"
        or provider.get("attributeMapping") != expected_mapping
        or provider.get("attributeCondition") != federation["attributeCondition"]
        or provider.get("oidc")
        != {"issuerUri": "https://token.actions.githubusercontent.com"}
    ):
        fail("foundation_observer_provider_invalid")
    pool_resource = provider["name"].rsplit("/providers/", maxsplit=1)[0]
    expected_member = (
        f"principal://iam.googleapis.com/{pool_resource}/subject/"
        f"{federation['subject']}"
    )
    return provider["name"], expected_member


def _verify_service_account(
    service_account: Any,
    service_account_policy: Any,
    user_keys: Any,
    *,
    expected_email: str,
    expected_member: str,
) -> None:
    if (
        not isinstance(service_account, dict)
        or service_account.get("email") != expected_email
        or service_account.get("disabled") is True
        or not isinstance(service_account.get("name"), str)
        or not service_account["name"].endswith(
            f"/serviceAccounts/{expected_email}"
        )
    ):
        fail("foundation_observer_service_account_invalid")
    bindings = _bindings(
        service_account_policy, "foundation_observer_impersonation_invalid"
    )
    if bindings != [
        {
            "role": "roles/iam.workloadIdentityUser",
            "members": [expected_member],
        }
    ]:
        fail("foundation_observer_impersonation_invalid")
    if user_keys != []:
        fail("foundation_observer_user_managed_key_present")


def _expect_roles(
    policy: Any,
    *,
    member: str,
    expected: set[str],
    code: str,
) -> None:
    if member_roles(policy, member, code) != expected:
        fail(code)


def validate_observation(value: dict[str, Any]) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "serviceAccount",
            "provider",
            "checks",
            "evidenceDigests",
            "claims",
        },
        "foundation_observer_authority_observation_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or not isinstance(value["serviceAccount"], str)
        or not value["serviceAccount"].startswith(
            "orchestra-foundation-observer@"
        )
        or not value["serviceAccount"].endswith(".iam.gserviceaccount.com")
        or not isinstance(value["provider"], str)
        or not value["provider"].endswith(
            "/workloadIdentityPools/orchestra-lab-github/providers/"
            "foundation-observation"
        )
    ):
        fail("foundation_observer_authority_observation_identity_invalid")
    if value["checks"] != {
        "providerConditionExact": True,
        "impersonationBindingExact": True,
        "noUserManagedKeys": True,
        "targetProjectRolesExact": True,
        "servicesProjectRolesExact": True,
        "customStorageRoleExact": True,
        "directAncestorBindingsExact": True,
        "storageRolesExact": True,
        "kmsRolesExact": True,
    }:
        fail("foundation_observer_authority_observation_checks_invalid")
    evidence = strict_keys(
        value["evidenceDigests"],
        {
            "provider",
            "serviceAccount",
            "serviceAccountPolicy",
            "userManagedKeys",
            "targetProjectPolicy",
            "servicesProjectPolicy",
            "customStorageRole",
            "ancestorPolicies",
            "stateBucketPolicy",
            "stateFolderPolicy",
            "planFolderPolicy",
            "receiptFolderPolicy",
            "observationFolderPolicy",
            "planKeyPolicy",
            "receiptKeyPolicy",
            "observationKeyPolicy",
        },
        "foundation_observer_authority_observation_evidence_invalid",
    )
    if any(
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != 71
        for digest in evidence.values()
    ):
        fail("foundation_observer_authority_observation_evidence_invalid")
    if value["claims"] != {
        "directReadOnlyBoundaryObserved": True,
        "infrastructureMutationGranted": False,
        "sourceObjectMutationGranted": False,
        "reportReadGranted": False,
        "reportCreateOnlyGranted": True,
        "artifactMirrorWriteGranted": False,
        "campaignAuthorityGranted": False,
    }:
        fail("foundation_observer_authority_observation_claims_invalid")
    return payload_digest(value)


def collect(
    *,
    target_project_id: str,
    services_project_id: str,
    state_bucket: str,
    run_json: RunJson = gcloud_json,
) -> dict[str, Any]:
    authority, release_set, policy, apply_authority = load_contract()
    validate_authority(authority, release_set, policy, apply_authority)
    federation = expected_federation()
    service_account_email = (
        f"orchestra-foundation-observer@{services_project_id}."
        "iam.gserviceaccount.com"
    )
    service_account_member = f"serviceAccount:{service_account_email}"
    provider = run_json(
        [
            "iam",
            "workload-identity-pools",
            "providers",
            "describe",
            "foundation-observation",
            "--workload-identity-pool=orchestra-lab-github",
            "--location=global",
            f"--project={services_project_id}",
        ]
    )
    provider_resource, impersonation_member = _verify_provider(
        provider, federation
    )
    service_account = run_json(
        [
            "iam",
            "service-accounts",
            "describe",
            service_account_email,
            f"--project={services_project_id}",
        ]
    )
    service_account_policy = run_json(
        [
            "iam",
            "service-accounts",
            "get-iam-policy",
            service_account_email,
            f"--project={services_project_id}",
        ]
    )
    user_keys = run_json(
        [
            "iam",
            "service-accounts",
            "keys",
            "list",
            f"--iam-account={service_account_email}",
            "--managed-by=user",
            f"--project={services_project_id}",
        ]
    )
    _verify_service_account(
        service_account,
        service_account_policy,
        user_keys,
        expected_email=service_account_email,
        expected_member=impersonation_member,
    )
    target_policy = run_json(
        ["projects", "get-iam-policy", target_project_id]
    )
    services_policy = run_json(
        ["projects", "get-iam-policy", services_project_id]
    )
    custom_role = (
        f"projects/{services_project_id}/roles/{CUSTOM_ROLE_ID}"
    )
    custom_role_definition = run_json(
        [
            "iam",
            "roles",
            "describe",
            CUSTOM_ROLE_ID,
            f"--project={services_project_id}",
        ]
    )
    if (
        not isinstance(custom_role_definition, dict)
        or custom_role_definition.get("name") != custom_role
        or custom_role_definition.get("stage") != "GA"
        or set(custom_role_definition.get("includedPermissions", []))
        != CUSTOM_ROLE_PERMISSIONS
    ):
        fail("foundation_observer_custom_role_invalid")
    _expect_roles(
        target_policy,
        member=service_account_member,
        expected=TARGET_ROLES,
        code="foundation_observer_target_roles_invalid",
    )
    _expect_roles(
        services_policy,
        member=service_account_member,
        expected=SERVICES_ROLES | {custom_role},
        code="foundation_observer_services_roles_invalid",
    )
    ancestors: dict[tuple[str, str], Any] = {}
    for project_id in (target_project_id, services_project_id):
        project_ancestors = run_json(["projects", "get-ancestors", project_id])
        if not isinstance(project_ancestors, list):
            fail("foundation_observer_ancestors_invalid")
        for ancestor in project_ancestors:
            if (
                not isinstance(ancestor, dict)
                or ancestor.get("type")
                not in {"project", "folder", "organization"}
                or not isinstance(ancestor.get("id"), str)
                or not ancestor["id"].isdigit()
            ):
                fail("foundation_observer_ancestors_invalid")
            if ancestor["type"] == "project":
                continue
            key = (ancestor["type"], ancestor["id"])
            if key in ancestors:
                continue
            command = (
                [
                    "resource-manager",
                    "folders",
                    "get-iam-policy",
                    ancestor["id"],
                ]
                if ancestor["type"] == "folder"
                else ["organizations", "get-iam-policy", ancestor["id"]]
            )
            ancestors[key] = run_json(command)
    pool_resource = provider_resource.rsplit("/providers/", maxsplit=1)[0]
    for ancestor_policy in ancestors.values():
        bindings = _bindings(
            ancestor_policy, "foundation_observer_ancestor_policy_invalid"
        )
        if {
            binding["role"]
            for binding in bindings
            if service_account_member in binding["members"]
        } != {"roles/iam.securityReviewer"}:
            fail("foundation_observer_ancestor_reviewer_role_invalid")
        for binding in bindings:
            if any(
                pool_resource in member
                for member in binding["members"]
            ):
                fail("foundation_observer_ancestor_binding_present")

    state_bucket_policy = run_json(
        [
            "storage",
            "buckets",
            "get-iam-policy",
            f"gs://{state_bucket}",
        ]
    )
    _expect_roles(
        state_bucket_policy,
        member=service_account_member,
        expected=set(),
        code="foundation_observer_state_bucket_roles_invalid",
    )
    folder_policies: dict[str, Any] = {}
    for name in (
        "foundation/",
        "foundation-plans/",
        "foundation-apply-reports/",
        "foundation-observations/",
    ):
        folder_policies[name] = run_json(
            [
                "storage",
                "managed-folders",
                "get-iam-policy",
                f"gs://{state_bucket}/{name}",
            ]
        )
    for name in (
        "foundation/",
        "foundation-plans/",
        "foundation-apply-reports/",
    ):
        _expect_roles(
            folder_policies[name],
            member=service_account_member,
            expected={"roles/storage.objectViewer"},
            code="foundation_observer_source_folder_roles_invalid",
        )
    _expect_roles(
        folder_policies["foundation-observations/"],
        member=service_account_member,
        expected={"roles/storage.objectCreator"},
        code="foundation_observer_report_folder_roles_invalid",
    )

    key_policies: dict[str, Any] = {}
    for key_id in (
        "foundation-plan-signing",
        "foundation-apply-receipt-signing",
        "foundation-observation-signing",
    ):
        key_policies[key_id] = run_json(
            [
                "kms",
                "keys",
                "get-iam-policy",
                key_id,
                "--keyring=orchestra-lab-foundation-execution",
                "--location=europe-west1",
                f"--project={services_project_id}",
            ]
        )
    for key_id in (
        "foundation-plan-signing",
        "foundation-apply-receipt-signing",
    ):
        _expect_roles(
            key_policies[key_id],
            member=service_account_member,
            expected={"roles/cloudkms.publicKeyViewer"},
            code="foundation_observer_source_key_roles_invalid",
        )
    _expect_roles(
        key_policies["foundation-observation-signing"],
        member=service_account_member,
        expected={"roles/cloudkms.signerVerifier"},
        code="foundation_observer_signing_key_roles_invalid",
    )
    report = {
        "schemaVersion": 1,
        "kind": KIND,
        "serviceAccount": service_account_email,
        "provider": provider_resource,
        "checks": {
            "providerConditionExact": True,
            "impersonationBindingExact": True,
            "noUserManagedKeys": True,
            "targetProjectRolesExact": True,
            "servicesProjectRolesExact": True,
            "customStorageRoleExact": True,
            "directAncestorBindingsExact": True,
            "storageRolesExact": True,
            "kmsRolesExact": True,
        },
        "evidenceDigests": {
            "provider": payload_digest(provider),
            "serviceAccount": payload_digest(service_account),
            "serviceAccountPolicy": payload_digest(service_account_policy),
            "userManagedKeys": payload_digest(user_keys),
            "targetProjectPolicy": payload_digest(target_policy),
            "servicesProjectPolicy": payload_digest(services_policy),
            "customStorageRole": payload_digest(custom_role_definition),
            "ancestorPolicies": payload_digest(
                [
                    {
                        "type": key[0],
                        "id": key[1],
                        "policyDigest": payload_digest(ancestors[key]),
                    }
                    for key in sorted(ancestors)
                ]
            ),
            "stateBucketPolicy": payload_digest(state_bucket_policy),
            "stateFolderPolicy": payload_digest(folder_policies["foundation/"]),
            "planFolderPolicy": payload_digest(
                folder_policies["foundation-plans/"]
            ),
            "receiptFolderPolicy": payload_digest(
                folder_policies["foundation-apply-reports/"]
            ),
            "observationFolderPolicy": payload_digest(
                folder_policies["foundation-observations/"]
            ),
            "planKeyPolicy": payload_digest(
                key_policies["foundation-plan-signing"]
            ),
            "receiptKeyPolicy": payload_digest(
                key_policies["foundation-apply-receipt-signing"]
            ),
            "observationKeyPolicy": payload_digest(
                key_policies["foundation-observation-signing"]
            ),
        },
        "claims": {
            "directReadOnlyBoundaryObserved": True,
            "infrastructureMutationGranted": False,
            "sourceObjectMutationGranted": False,
            "reportReadGranted": False,
            "reportCreateOnlyGranted": True,
            "artifactMirrorWriteGranted": False,
            "campaignAuthorityGranted": False,
        },
    }
    validate_observation(report)
    return report


def write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    if path.exists() or not path.parent.is_dir():
        fail("foundation_observer_authority_output_invalid")
    encoded = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except OSError as error:
        raise ValueError("foundation_observer_authority_write_failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-project-id", required=True)
    parser.add_argument("--services-project-id", required=True)
    parser.add_argument("--state-bucket", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = collect(
        target_project_id=args.target_project_id,
        services_project_id=args.services_project_id,
        state_bucket=args.state_bucket,
    )
    write_new(args.output, report)
    print(
        "foundation_observer_authority_observed "
        f"digest={validate_observation(report)} "
        "directReadOnlyBoundaryObserved=true "
        "infrastructureMutationGranted=false reportReadGranted=false "
        "campaignAuthorityGranted=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
