#!/usr/bin/env python3
"""Collect read-only prerequisite observations without granting readiness."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.github_environment_contract import (
        GithubGetter,
        fetch_environment_evidence,
    )
except ModuleNotFoundError:
    from github_environment_contract import GithubGetter, fetch_environment_evidence

try:
    from scripts.prerequisite_observation import (
        COLLECTOR_PATH,
        GATE_CHECKS,
        GATE_ORDER,
        OBSERVATION_ID,
        PROFILE_ID,
        ROOT,
        blob_digest,
        expected_bindings,
        load_contract,
        parse_utc,
        payload_digest,
        require_digest,
        validate_observation,
        validate_policy,
    )
    from scripts.validate_release_set import validate_release_set
except ModuleNotFoundError:
    from prerequisite_observation import (
        COLLECTOR_PATH,
        GATE_CHECKS,
        GATE_ORDER,
        OBSERVATION_ID,
        PROFILE_ID,
        ROOT,
        blob_digest,
        expected_bindings,
        load_contract,
        parse_utc,
        payload_digest,
        require_digest,
        validate_observation,
        validate_policy,
    )
    from validate_release_set import validate_release_set


CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class Inputs:
    observation_id: str
    actor_identity_digest: str
    execution_mode: str
    red_hat_entitlement_statement: Path | None = None
    pull_secret: Path | None = None
    installer_binary: Path | None = None
    installer_digest: str | None = None
    github_token_file: Path | None = None
    target_project_id: str | None = None
    services_project_id: str | None = None
    dns_managed_zone: str | None = None


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )


def passed(check_id: str, evidence: Any, observed_at: datetime) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": "passed",
        "evidenceDigest": payload_digest(evidence),
        "observedAt": utc_text(observed_at),
        "reasonCode": "OBSERVED",
    }


def failed(
    check_id: str, reason: str, observed_at: datetime, evidence: Any | None = None
) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": "failed",
        "evidenceDigest": payload_digest(
            evidence if evidence is not None else {"reasonCode": reason}
        ),
        "observedAt": utc_text(observed_at),
        "reasonCode": reason,
    }


def not_run(check_id: str, reason: str) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": "not-run",
        "evidenceDigest": None,
        "observedAt": None,
        "reasonCode": reason,
    }


def gate(checks: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = sorted(
        {check["reasonCode"] for check in checks if check["status"] != "passed"}
    )
    if blocked:
        return {"status": "blocked", "checks": checks, "reasonCodes": blocked}
    return {
        "status": "passed",
        "checks": checks,
        "reasonCodes": ["OBSERVATIONS_COMPLETE_REVIEW_REQUIRED"],
    }


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value


def observe_entitlement(path: Path | None, now: datetime) -> dict[str, Any]:
    check_id = GATE_CHECKS["redHatEntitlement"][0]
    if path is None:
        return not_run(check_id, "ENTITLEMENT_STATEMENT_MISSING")
    try:
        value = read_json(path)
        if set(value) != {
            "schemaVersion",
            "kind",
            "status",
            "product",
            "openshiftVersion",
            "architecture",
            "accountIdentityDigest",
            "issuerEvidenceDigest",
            "observedAt",
            "expiresAt",
        }:
            raise ValueError("shape")
        observed_at = parse_utc(value["observedAt"], "time")
        expires_at = parse_utc(value["expiresAt"], "time")
        if (
            value["schemaVersion"] != 1
            or value["kind"] != "orchestra.external.red-hat-entitlement-observation.v1"
            or value["status"] != "active"
            or value["product"] != "OpenShift Container Platform"
            or value["openshiftVersion"] != "4.20.27"
            or value["architecture"] != "linux/amd64"
            or observed_at > now
            or expires_at <= now
        ):
            raise ValueError("semantic")
        require_digest(value["accountIdentityDigest"], "account_digest")
        require_digest(value["issuerEvidenceDigest"], "issuer_digest")
    except (OSError, json.JSONDecodeError, ValueError):
        return failed(check_id, "ENTITLEMENT_STATEMENT_INVALID", now)
    return passed(check_id, value, now)


def observe_pull_secret(path: Path | None, now: datetime) -> dict[str, Any]:
    check_id = GATE_CHECKS["openshiftPullSecret"][0]
    if path is None:
        return not_run(check_id, "PULL_SECRET_MISSING")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        auths = value.get("auths") if isinstance(value, dict) else None
        required = {"cloud.openshift.com", "quay.io", "registry.redhat.io"}
        if not isinstance(auths, dict) or not required.issubset(auths):
            raise ValueError("registries")
        for registry in required:
            credential = auths[registry]
            if not isinstance(credential, dict) or not any(
                isinstance(credential.get(field), str) and credential[field]
                for field in ("auth", "identitytoken", "username")
            ):
                raise ValueError("credential")
    except (OSError, json.JSONDecodeError, ValueError):
        return failed(check_id, "PULL_SECRET_INVALID", now)
    return passed(
        check_id,
        {"secretDigest": blob_digest(raw), "requiredRegistries": sorted(required)},
        now,
    )


def observe_installer(
    binary: Path | None,
    expected_digest: str | None,
    now: datetime,
    run: CommandRunner,
) -> dict[str, Any]:
    check_id = GATE_CHECKS["openshiftInstaller"][0]
    if binary is None or expected_digest is None:
        return not_run(check_id, "INSTALLER_INPUT_MISSING")
    try:
        actual_digest = blob_digest(binary.read_bytes())
        if actual_digest != expected_digest:
            return failed(check_id, "INSTALLER_DIGEST_MISMATCH", now)
        result = run([str(binary), "version"])
        version_output = result.stdout
        if "openshift-install 4.20.27" not in version_output:
            return failed(check_id, "INSTALLER_VERSION_MISMATCH", now)
        file_output = run(["file", "-b", str(binary)]).stdout
        if "ELF 64-bit" not in file_output or not any(
            marker in file_output for marker in ("x86-64", "x86_64")
        ):
            return failed(check_id, "INSTALLER_ARCHITECTURE_MISMATCH", now)
    except (OSError, subprocess.SubprocessError):
        return failed(check_id, "INSTALLER_EXECUTION_FAILED", now)
    return passed(
        check_id,
        {
            "binaryDigest": actual_digest,
            "versionOutputDigest": blob_digest(version_output.encode("utf-8")),
            "fileOutputDigest": blob_digest(file_output.encode("utf-8")),
            "version": "4.20.27",
            "architecture": "linux/amd64",
        },
        now,
    )


def run_json(run: CommandRunner, command: list[str]) -> Any:
    return json.loads(run(command).stdout)


def quota_snapshot(value: Any) -> dict[str, float]:
    if not isinstance(value, dict) or not isinstance(value.get("quotas"), list):
        raise ValueError("quota_shape")
    result: dict[str, float] = {}
    for item in value["quotas"]:
        if not isinstance(item, dict) or not isinstance(item.get("metric"), str):
            continue
        limit = item.get("limit")
        usage = item.get("usage", 0)
        if isinstance(limit, (int, float)) and isinstance(usage, (int, float)):
            result[item["metric"]] = float(limit) - float(usage)
    return result


def quotas_satisfy(actual: dict[str, float], required: dict[str, int | float]) -> bool:
    return all(
        metric in actual and actual[metric] >= minimum
        for metric, minimum in required.items()
    )


def enabled_apis(value: Any) -> set[str]:
    if not isinstance(value, list):
        raise ValueError("services_shape")
    result: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        name = (
            item.get("config", {}).get("name")
            if isinstance(item.get("config"), dict)
            else None
        )
        if not isinstance(name, str):
            raw_name = item.get("name")
            if isinstance(raw_name, str):
                name = raw_name.rsplit("/", 1)[-1]
        if name and item.get("state", "ENABLED") == "ENABLED":
            result.add(name)
    return result


def collect_project(project_id: str, region: str, run: CommandRunner) -> dict[str, Any]:
    return {
        "project": run_json(
            run, ["gcloud", "projects", "describe", project_id, "--format=json"]
        ),
        "billing": run_json(
            run,
            ["gcloud", "billing", "projects", "describe", project_id, "--format=json"],
        ),
        "services": run_json(
            run,
            [
                "gcloud",
                "services",
                "list",
                "--enabled",
                f"--project={project_id}",
                "--format=json",
            ],
        ),
        "globalQuotas": run_json(
            run,
            [
                "gcloud",
                "compute",
                "project-info",
                "describe",
                f"--project={project_id}",
                "--format=json",
            ],
        ),
        "regionalQuotas": run_json(
            run,
            [
                "gcloud",
                "compute",
                "regions",
                "describe",
                region,
                f"--project={project_id}",
                "--format=json",
            ],
        ),
    }


def project_evidence(
    project_id: str,
    snapshot: dict[str, Any],
    required_labels: dict[str, str],
    required_apis: list[str],
) -> tuple[bool, dict[str, Any]]:
    project = snapshot["project"]
    billing = snapshot["billing"]
    actual_apis = enabled_apis(snapshot["services"])
    labels = project.get("labels") if isinstance(project, dict) else None
    valid = (
        isinstance(project, dict)
        and project.get("lifecycleState") == "ACTIVE"
        and isinstance(labels, dict)
        and all(labels.get(key) == value for key, value in required_labels.items())
        and isinstance(billing, dict)
        and billing.get("billingEnabled") is True
        and set(required_apis).issubset(actual_apis)
    )
    return valid, {
        "projectIdentityDigest": payload_digest(project_id),
        "lifecycleState": project.get("lifecycleState")
        if isinstance(project, dict)
        else None,
        "labels": {
            key: labels.get(key) if isinstance(labels, dict) else None
            for key in sorted(required_labels)
        },
        "billingEnabled": billing.get("billingEnabled")
        if isinstance(billing, dict)
        else None,
        "enabledRequiredApis": sorted(set(required_apis) & actual_apis),
        "requiredApiCount": len(required_apis),
    }


def observe_gcp(
    target_project: str | None,
    services_project: str | None,
    now: datetime,
    run: CommandRunner,
    policy: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    check_ids = {
        name: GATE_CHECKS[name][0]
        for name in (
            "gcpBillingAndQuotas",
            "targetProject",
            "servicesEvidenceProject",
        )
    }
    if not target_project or not services_project:
        return {
            name: not_run(check_id, "GCP_PROJECT_INPUT_MISSING")
            for name, check_id in check_ids.items()
        }
    if target_project == services_project:
        return {
            name: failed(check_id, "GCP_PROJECTS_NOT_DISTINCT", now)
            for name, check_id in check_ids.items()
        }
    try:
        target = collect_project(target_project, policy["gcp"]["region"], run)
        services = collect_project(services_project, policy["gcp"]["region"], run)
        target_ok, target_evidence = project_evidence(
            target_project,
            target,
            policy["gcp"]["targetLabels"],
            policy["gcp"]["targetRequiredApis"],
        )
        services_ok, services_evidence = project_evidence(
            services_project,
            services,
            policy["gcp"]["servicesLabels"],
            policy["gcp"]["servicesRequiredApis"],
        )
        quota_evidence: dict[str, Any] = {}
        quotas_ok = True
        for plane, snapshot in (("target", target), ("services", services)):
            actual_global = quota_snapshot(snapshot["globalQuotas"])
            actual_regional = quota_snapshot(snapshot["regionalQuotas"])
            required = policy["gcp"]["quotaMinimumAvailable"][plane]
            plane_ok = quotas_satisfy(
                actual_global, required["global"]
            ) and quotas_satisfy(actual_regional, required["regional"])
            quotas_ok = quotas_ok and plane_ok
            quota_evidence[plane] = {
                "globalAvailable": {
                    key: actual_global.get(key) for key in sorted(required["global"])
                },
                "regionalAvailable": {
                    key: actual_regional.get(key)
                    for key in sorted(required["regional"])
                },
                "minimums": required,
            }
        billing_ok = (
            target_evidence["billingEnabled"] is True
            and services_evidence["billingEnabled"] is True
        )
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
        return {
            name: failed(check_id, "GCP_READ_ONLY_OBSERVATION_FAILED", now)
            for name, check_id in check_ids.items()
        }
    return {
        "targetProject": (
            passed(check_ids["targetProject"], target_evidence, now)
            if target_ok
            else failed(
                check_ids["targetProject"],
                "TARGET_PROJECT_POLICY_MISMATCH",
                now,
                target_evidence,
            )
        ),
        "servicesEvidenceProject": (
            passed(check_ids["servicesEvidenceProject"], services_evidence, now)
            if services_ok
            else failed(
                check_ids["servicesEvidenceProject"],
                "SERVICES_PROJECT_POLICY_MISMATCH",
                now,
                services_evidence,
            )
        ),
        "gcpBillingAndQuotas": (
            passed(check_ids["gcpBillingAndQuotas"], quota_evidence, now)
            if billing_ok and quotas_ok
            else failed(
                check_ids["gcpBillingAndQuotas"],
                "GCP_BILLING_OR_QUOTA_INSUFFICIENT",
                now,
                quota_evidence,
            )
        ),
    }


def observe_dns(
    zone: str | None,
    services_project: str | None,
    now: datetime,
    run: CommandRunner,
    policy: dict[str, Any],
) -> dict[str, Any]:
    check_id = GATE_CHECKS["dnsDelegation"][0]
    if not zone or not services_project:
        return not_run(check_id, "DNS_INPUT_MISSING")
    if zone != policy["dns"]["managedZoneName"]:
        return failed(
            check_id,
            "DNS_MANAGED_ZONE_POLICY_MISMATCH",
            now,
            {"zoneIdentityDigest": payload_digest(zone)},
        )
    try:
        managed = run_json(
            run,
            [
                "gcloud",
                "dns",
                "managed-zones",
                "describe",
                zone,
                f"--project={services_project}",
                "--format=json",
            ],
        )
        delegated = {
            item.strip().rstrip(".") + "."
            for item in run(
                ["dig", "+short", "NS", policy["dns"]["dnsName"]]
            ).stdout.splitlines()
            if item.strip()
        }
        expected = {
            item.strip().rstrip(".") + "."
            for item in managed.get("nameServers", [])
            if isinstance(item, str) and item.strip()
        }
        valid = (
            managed.get("name") == policy["dns"]["managedZoneName"]
            and managed.get("dnsName") == policy["dns"]["dnsName"]
            and managed.get("visibility", "public") == policy["dns"]["visibility"]
            and bool(expected)
            and delegated == expected
        )
        evidence = {
            "zoneIdentityDigest": payload_digest(managed.get("name")),
            "zoneProjectIdentityDigest": payload_digest(services_project),
            "dnsName": policy["dns"]["dnsName"],
            "visibility": managed.get("visibility", "public"),
            "nameServerSetDigest": payload_digest(sorted(expected)),
            "delegatedSetDigest": payload_digest(sorted(delegated)),
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
        return failed(check_id, "DNS_READ_ONLY_OBSERVATION_FAILED", now)
    return (
        passed(check_id, evidence, now)
        if valid
        else failed(check_id, "DNS_DELEGATION_MISMATCH", now, evidence)
    )


def observe_github_environment(
    token_file: Path | None,
    now: datetime,
    policy: dict[str, Any],
    *,
    get_json: GithubGetter | None = None,
) -> dict[str, Any]:
    check_id = GATE_CHECKS["shortLivedIdentityFederation"][0]
    if token_file is None:
        return not_run(check_id, "GITHUB_ENVIRONMENT_TOKEN_MISSING")
    try:
        evidence = fetch_environment_evidence(
            token_file,
            policy["gcp"]["wif"],
            get_json=get_json,
        )
    except (OSError, ValueError):
        return failed(check_id, "GITHUB_ENVIRONMENT_PROTECTION_INVALID", now)
    return passed(check_id, evidence, now)


def observe_wif(
    services_project: str | None,
    now: datetime,
    run: CommandRunner,
    policy: dict[str, Any],
) -> dict[str, Any]:
    check_id = GATE_CHECKS["shortLivedIdentityFederation"][1]
    if not services_project:
        return not_run(check_id, "WIF_PROJECT_INPUT_MISSING")
    wif = policy["gcp"]["wif"]
    planner_service_account = (
        f"{wif['serviceAccountId']}@{services_project}.iam.gserviceaccount.com"
    )
    packager_service_account = (
        f"{wif['planPackagerServiceAccountId']}@"
        f"{services_project}.iam.gserviceaccount.com"
    )
    executor_service_account = (
        f"{wif['executorServiceAccountId']}@{services_project}.iam.gserviceaccount.com"
    )
    try:
        plan_provider = run_json(
            run,
            [
                "gcloud",
                "iam",
                "workload-identity-pools",
                "providers",
                "describe",
                wif["providerId"],
                f"--workload-identity-pool={wif['poolId']}",
                "--location=global",
                f"--project={services_project}",
                "--format=json",
            ],
        )
        apply_provider = run_json(
            run,
            [
                "gcloud",
                "iam",
                "workload-identity-pools",
                "providers",
                "describe",
                wif["applyProviderId"],
                f"--workload-identity-pool={wif['poolId']}",
                "--location=global",
                f"--project={services_project}",
                "--format=json",
            ],
        )
        planner_keys = run_json(
            run,
            [
                "gcloud",
                "iam",
                "service-accounts",
                "keys",
                "list",
                f"--iam-account={planner_service_account}",
                f"--project={services_project}",
                "--format=json",
            ],
        )
        packager_keys = run_json(
            run,
            [
                "gcloud",
                "iam",
                "service-accounts",
                "keys",
                "list",
                f"--iam-account={packager_service_account}",
                f"--project={services_project}",
                "--format=json",
            ],
        )
        executor_keys = run_json(
            run,
            [
                "gcloud",
                "iam",
                "service-accounts",
                "keys",
                "list",
                f"--iam-account={executor_service_account}",
                f"--project={services_project}",
                "--format=json",
            ],
        )
        planner_iam_policy = run_json(
            run,
            [
                "gcloud",
                "iam",
                "service-accounts",
                "get-iam-policy",
                planner_service_account,
                f"--project={services_project}",
                "--format=json",
            ],
        )
        packager_iam_policy = run_json(
            run,
            [
                "gcloud",
                "iam",
                "service-accounts",
                "get-iam-policy",
                packager_service_account,
                f"--project={services_project}",
                "--format=json",
            ],
        )
        executor_iam_policy = run_json(
            run,
            [
                "gcloud",
                "iam",
                "service-accounts",
                "get-iam-policy",
                executor_service_account,
                f"--project={services_project}",
                "--format=json",
            ],
        )
        plan_provider_name = plan_provider.get("name", "")
        apply_provider_name = apply_provider.get("name", "")
        expected_plan_subject = (
            f"{wif['providerId']}:{wif['repositoryId']}:{wif['environment']}"
        )
        expected_plan_member = (
            "principal://iam.googleapis.com/"
            f"{plan_provider_name.rsplit('/providers/', 1)[0]}"
            f"/subject/{expected_plan_subject}"
        )
        expected_apply_member = (
            "principal://iam.googleapis.com/"
            f"{apply_provider_name.rsplit('/providers/', 1)[0]}"
            f"/subject/{wif['applySubject']}"
        )
        planner_bindings = (
            planner_iam_policy.get("bindings", [])
            if isinstance(planner_iam_policy, dict)
            else []
        )
        packager_bindings = (
            packager_iam_policy.get("bindings", [])
            if isinstance(packager_iam_policy, dict)
            else []
        )
        executor_bindings = (
            executor_iam_policy.get("bindings", [])
            if isinstance(executor_iam_policy, dict)
            else []
        )

        def federated_members(bindings: Any) -> list[tuple[str, str]]:
            if not isinstance(bindings, list):
                return [("invalid", "invalid")]
            result: list[tuple[str, str]] = []
            for binding in bindings:
                if not isinstance(binding, dict):
                    return [("invalid", "invalid")]
                role = binding.get("role")
                members = binding.get("members", [])
                if (
                    not isinstance(role, str)
                    or not isinstance(members, list)
                    or not all(isinstance(member, str) for member in members)
                ):
                    return [("invalid", "invalid")]
                result.extend(
                    (role, member)
                    for member in members
                    if isinstance(member, str)
                    and member.startswith(
                        (
                            "principal://iam.googleapis.com/",
                            "principalSet://iam.googleapis.com/",
                        )
                    )
                )
            return sorted(result)

        planner_federated = federated_members(planner_bindings)
        packager_federated = federated_members(packager_bindings)
        executor_federated = federated_members(executor_bindings)
        planner_binding_exact = planner_federated == [
            ("roles/iam.workloadIdentityUser", expected_plan_member)
        ]
        packager_binding_exact = packager_federated == [
            ("roles/iam.workloadIdentityUser", expected_plan_member)
        ]
        executor_binding_exact = executor_federated == [
            ("roles/iam.workloadIdentityUser", expected_apply_member)
        ]

        def user_managed_keys(keys: Any) -> list[Any]:
            return (
                [
                    item
                    for item in keys
                    if isinstance(item, dict) and item.get("keyType") == "USER_MANAGED"
                ]
                if isinstance(keys, list)
                else ["invalid"]
            )

        planner_user_keys = user_managed_keys(planner_keys)
        packager_user_keys = user_managed_keys(packager_keys)
        executor_user_keys = user_managed_keys(executor_keys)
        plan_mapping = (
            plan_provider.get("attributeMapping", {})
            if isinstance(plan_provider, dict)
            else {}
        )
        apply_mapping = (
            apply_provider.get("attributeMapping", {})
            if isinstance(apply_provider, dict)
            else {}
        )
        expected_common_mapping = {
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
        expected_plan_mapping = {
            "google.subject": (
                f"'{wif['providerId']}:' + assertion.repository_id + ':' + "
                "assertion.environment"
            ),
            **expected_common_mapping,
        }
        expected_apply_mapping = {
            "google.subject": (
                f"'{wif['applyProviderId']}:' + assertion.repository_id + ':' + "
                "assertion.environment"
            ),
            **expected_common_mapping,
        }
        valid = (
            plan_provider.get("state", "ACTIVE") == "ACTIVE"
            and apply_provider.get("state", "ACTIVE") == "ACTIVE"
            and plan_provider.get("oidc", {}).get("issuerUri") == wif["issuerUri"]
            and apply_provider.get("oidc", {}).get("issuerUri") == wif["issuerUri"]
            and plan_provider.get("attributeCondition") == wif["attributeCondition"]
            and apply_provider.get("attributeCondition")
            == wif["applyAttributeCondition"]
            and plan_mapping == expected_plan_mapping
            and apply_mapping == expected_apply_mapping
            and planner_binding_exact
            and packager_binding_exact
            and executor_binding_exact
            and wif["executorFederated"] is True
            and not planner_user_keys
            and not packager_user_keys
            and not executor_user_keys
        )
        evidence = {
            "planProviderIdentityDigest": payload_digest(plan_provider_name),
            "applyProviderIdentityDigest": payload_digest(apply_provider_name),
            "plannerServiceAccountIdentityDigest": payload_digest(
                planner_service_account
            ),
            "planPackagerServiceAccountIdentityDigest": payload_digest(
                packager_service_account
            ),
            "executorServiceAccountIdentityDigest": payload_digest(
                executor_service_account
            ),
            "planConditionDigest": payload_digest(
                plan_provider.get("attributeCondition")
            ),
            "applyConditionDigest": payload_digest(
                apply_provider.get("attributeCondition")
            ),
            "plannerBindingExact": planner_binding_exact,
            "planPackagerBindingExact": packager_binding_exact,
            "executorBindingExact": executor_binding_exact,
            "plannerFederatedBindingCount": len(planner_federated),
            "planPackagerFederatedBindingCount": len(packager_federated),
            "executorFederatedBindingCount": len(executor_federated),
            "plannerUserManagedKeyCount": len(planner_user_keys),
            "planPackagerUserManagedKeyCount": len(packager_user_keys),
            "executorUserManagedKeyCount": len(executor_user_keys),
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
        return failed(check_id, "WIF_READ_ONLY_OBSERVATION_FAILED", now)
    return (
        passed(check_id, evidence, now)
        if valid
        else failed(check_id, "WIF_POLICY_MISMATCH", now, evidence)
    )


def observe_runner(
    now: datetime, run: CommandRunner, policy: dict[str, Any]
) -> dict[str, Any]:
    check_id = GATE_CHECKS["certificationRunner"][0]
    if shutil.which("cosign") is None:
        return not_run(check_id, "COSIGN_UNAVAILABLE")
    runner = policy["runner"]
    identity = (
        "https://github.com/caglarsubas/agent-hook-v2/"
        ".github/workflows/publish-platform-release.yml@refs/tags/"
        f"{runner['release']}"
    )
    constraints = [
        "--certificate-identity",
        identity,
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--certificate-github-workflow-sha",
        runner["revision"],
        "--certificate-github-workflow-ref",
        f"refs/tags/{runner['release']}",
        "--certificate-github-workflow-repository",
        runner["repository"],
        "--certificate-github-workflow-trigger",
        "push",
    ]
    commands = [
        ["cosign", "verify", runner["image"], *constraints],
        [
            "cosign",
            "verify-attestation",
            runner["image"],
            "--type",
            "cyclonedx",
            *constraints,
        ],
    ]
    try:
        outputs = [run(command).stdout for command in commands]
    except (OSError, subprocess.SubprocessError):
        return failed(check_id, "RUNNER_SIGSTORE_VERIFICATION_FAILED", now)
    return passed(
        check_id,
        {
            "runnerImageDigest": runner["imageDigest"],
            "runnerToolchainDigest": runner["toolchainDigest"],
            "verificationOutputDigests": [
                blob_digest(item.encode("utf-8")) for item in outputs
            ],
        },
        now,
    )


def observe_release_set(now: datetime) -> dict[str, Any]:
    check_id = GATE_CHECKS["crossPlaneReleaseSet"][0]
    try:
        _, release_set = load_contract()
        digest = validate_release_set(release_set)
    except (OSError, ValueError):
        return failed(check_id, "RELEASE_SET_CONTRACT_INVALID", now)
    return passed(
        check_id,
        {
            "releaseSetDigest": digest,
            "releaseSetId": release_set["releaseSetId"],
            "planeCount": len(release_set["planes"]),
        },
        now,
    )


def collect(
    inputs: Inputs,
    *,
    run: CommandRunner = default_runner,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> dict[str, Any]:
    started = started_at or datetime.now(timezone.utc)
    observed = completed_at or datetime.now(timezone.utc)
    policy, release_set = load_contract()
    validate_policy(policy, release_set)
    gcp = observe_gcp(
        inputs.target_project_id,
        inputs.services_project_id,
        observed,
        run,
        policy,
    )
    checks = {
        "redHatEntitlement": [
            observe_entitlement(inputs.red_hat_entitlement_statement, observed)
        ],
        "openshiftPullSecret": [observe_pull_secret(inputs.pull_secret, observed)],
        "openshiftInstaller": [
            observe_installer(
                inputs.installer_binary, inputs.installer_digest, observed, run
            )
        ],
        "gcpBillingAndQuotas": [gcp["gcpBillingAndQuotas"]],
        "targetProject": [gcp["targetProject"]],
        "servicesEvidenceProject": [gcp["servicesEvidenceProject"]],
        "dnsDelegation": [
            observe_dns(
                inputs.dns_managed_zone,
                inputs.services_project_id,
                observed,
                run,
                policy,
            )
        ],
        "shortLivedIdentityFederation": [
            observe_github_environment(inputs.github_token_file, observed, policy),
            observe_wif(inputs.services_project_id, observed, run, policy),
        ],
        "certificationRunner": [observe_runner(observed, run, policy)],
        "crossPlaneReleaseSet": [observe_release_set(observed)],
    }
    gates = {name: gate(checks[name]) for name in GATE_ORDER}
    passed_count = sum(item["status"] == "passed" for item in gates.values())
    live = inputs.execution_mode == "live"
    runner = policy["runner"]
    report = {
        "schemaVersion": 1,
        "kind": "orchestra.reference-lab.prerequisite-observation.v1",
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab" if live else "fixture",
        "executionMode": inputs.execution_mode,
        "observationId": inputs.observation_id,
        "bindings": expected_bindings(),
        "collection": {
            "executionClass": (
                policy["observationPolicy"]["liveExecutionClass"]
                if live
                else policy["observationPolicy"]["diagnosticExecutionClass"]
            ),
            "runnerRelease": runner["release"] if live else None,
            "runnerImageDigest": runner["imageDigest"] if live else None,
            "runnerToolchainDigest": runner["toolchainDigest"] if live else None,
            "collectorScriptDigest": blob_digest(COLLECTOR_PATH.read_bytes()),
            "actorIdentityDigest": inputs.actor_identity_digest,
            "startedAt": utc_text(started),
            "completedAt": utc_text(observed),
            "commandPolicy": "read-only",
            "rawProviderOutputStored": False,
            "secretValuesStored": False,
        },
        "gates": gates,
        "summary": {
            "passedGates": passed_count,
            "blockedGates": len(GATE_ORDER) - passed_count,
            "totalGates": len(GATE_ORDER),
        },
        "claims": {
            "allRequiredObservationsPassed": passed_count == len(GATE_ORDER),
            "eligibleForIndependentReview": live and passed_count == len(GATE_ORDER),
            "verifiedPrerequisiteGates": 0,
            "provisioningReady": False,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
        },
    }
    validate_observation(report, now=observed, require_fresh=True)
    return report


def write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        raise ValueError("prerequisite_observation_output_exists")
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def require_live_storage(output: Path, sensitive_inputs: list[Path | None]) -> None:
    restricted_root = (ROOT / "restricted").resolve()
    if not output.resolve().is_relative_to(restricted_root):
        raise ValueError("live_observation_output_outside_restricted_storage")
    for path in sensitive_inputs:
        if path is not None and not path.resolve().is_relative_to(restricted_root):
            raise ValueError("live_observation_input_outside_restricted_storage")


def verify_live_runner_environment(
    policy: dict[str, Any],
    *,
    environ: Mapping[str, str] = os.environ,
    run: CommandRunner = default_runner,
    toolchain_path: Path | None = None,
    system_name: str | None = None,
    machine: str | None = None,
) -> None:
    runner = policy["runner"]
    if (
        environ.get("ORCHESTRA_CERTIFICATION_RUNNER_IMAGE") != runner["image"]
        or environ.get("ORCHESTRA_CERTIFICATION_RUNNER_TOOLCHAIN_DIGEST")
        != runner["toolchainDigest"]
    ):
        raise ValueError("live_collection_runner_environment_invalid")
    if (system_name or platform.system()) != "Linux" or (
        machine or platform.machine()
    ) not in {"x86_64", "amd64"}:
        raise ValueError("live_collection_runner_platform_invalid")
    lock_path = toolchain_path or Path(
        environ.get(
            "ORCHESTRA_RUNNER_TOOLCHAIN_LOCK",
            "/opt/orchestra/certification/toolchain-lock.json",
        )
    )
    try:
        if blob_digest(lock_path.read_bytes()) != runner["toolchainDigest"]:
            raise ValueError("live_collection_runner_toolchain_mismatch")
    except OSError as error:
        raise ValueError("live_collection_runner_toolchain_missing") from error
    for command in ("orchestra-certification", "cosign", "gcloud", "dig", "file"):
        if shutil.which(command) is None:
            raise ValueError(f"live_collection_runner_command_missing:{command}")
    try:
        run(["orchestra-certification", "self-test"])
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("live_collection_runner_self_test_failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observation-id", required=True)
    parser.add_argument("--actor-identity-digest", required=True)
    parser.add_argument(
        "--execution-mode", choices=("simulated", "live"), default="simulated"
    )
    parser.add_argument("--red-hat-entitlement-statement", type=Path)
    parser.add_argument("--pull-secret", type=Path)
    parser.add_argument("--installer-binary", type=Path)
    parser.add_argument("--installer-digest")
    parser.add_argument("--github-token-file", type=Path)
    parser.add_argument("--target-project-id")
    parser.add_argument("--services-project-id")
    parser.add_argument("--dns-managed-zone")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    policy, release_set = load_contract()
    validate_policy(policy, release_set)
    if not OBSERVATION_ID.fullmatch(args.observation_id):
        raise ValueError("prerequisite_observation_id_invalid")
    require_digest(args.actor_identity_digest, "actor_identity_digest_invalid")
    if args.installer_digest is not None:
        require_digest(args.installer_digest, "installer_digest_invalid")
    if args.execution_mode == "live":
        require_live_storage(
            args.output,
            [
                args.red_hat_entitlement_statement,
                args.pull_secret,
                args.installer_binary,
                args.github_token_file,
            ],
        )
        verify_live_runner_environment(policy)
    report = collect(
        Inputs(
            observation_id=args.observation_id,
            actor_identity_digest=args.actor_identity_digest,
            execution_mode=args.execution_mode,
            red_hat_entitlement_statement=args.red_hat_entitlement_statement,
            pull_secret=args.pull_secret,
            installer_binary=args.installer_binary,
            installer_digest=args.installer_digest,
            github_token_file=args.github_token_file,
            target_project_id=args.target_project_id,
            services_project_id=args.services_project_id,
            dns_managed_zone=args.dns_managed_zone,
        )
    )
    write_new(args.output, report)
    print(
        "prerequisite_observation_collected "
        f"digest={validate_observation(report)} "
        f"passed={report['summary']['passedGates']} "
        f"blocked={report['summary']['blockedGates']} "
        "verified=0 provisioningReady=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(error)
        raise SystemExit(1)
