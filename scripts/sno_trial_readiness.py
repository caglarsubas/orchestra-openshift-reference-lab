#!/usr/bin/env python3
"""Produce a read-only, non-certifying SNO trial readiness assessment."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_sno_trial_profile import (
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_production_isolation,
        validate_profile,
    )
except ModuleNotFoundError:
    from validate_release_set import validate_release_set
    from validate_sno_trial_profile import (  # type: ignore[no-redef]
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_production_isolation,
        validate_profile,
    )


ROOT = Path(__file__).resolve().parents[1]
RELEASE_SET = ROOT / "config" / "cross-plane-release-set.lock.json"
REPORT_KIND = "orchestra.openshift.sno-trial-readiness.v1"
SNAPSHOT_KIND = "orchestra.gcp.sno-trial-project-snapshot.v1"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
ASSESSMENT_ID = re.compile(r"^sno-readiness-[a-z0-9][a-z0-9.-]{5,79}$")
API_NAME = re.compile(r"^[a-z][a-z0-9.-]+\.googleapis\.com$")
QUOTA_STATUSES = {"not-submitted", "pending", "approved", "rejected"}
EXECUTION_MODES = {"simulated", "live-diagnostic"}
REQUIRED_APIS = (
    "billingbudgets.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
)
CLAIMS = {
    "campaignEvidence": False,
    "referenceProfileVerified": False,
    "customerCertified": False,
    "redHatCertified": False,
    "contractualSla": False,
    "productionSupported": False,
    "highAvailability": False,
    "rpoRtoVerified": False,
}
CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(code)
    return parsed


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def run_json(run: CommandRunner, command: list[str], code: str) -> Any:
    try:
        return json.loads(run(command).stdout)
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        subprocess.TimeoutExpired,
    ):
        fail(code)


def service_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        fail("sno_readiness_services_invalid")
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            fail("sno_readiness_services_invalid")
        config = item.get("config")
        name = config.get("name") if isinstance(config, dict) else item.get("name")
        if not isinstance(name, str):
            fail("sno_readiness_services_invalid")
        normalized = name.rsplit("/", 1)[-1]
        if not API_NAME.fullmatch(normalized):
            fail("sno_readiness_service_name_invalid")
        if item.get("state", "ENABLED") == "ENABLED":
            names.add(normalized)
    return sorted(names)


def collect_snapshot(
    project_id: str,
    quota_request_status: str,
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    if not PROJECT_ID.fullmatch(project_id):
        fail("sno_readiness_project_id_invalid")
    if quota_request_status not in QUOTA_STATUSES:
        fail("sno_readiness_quota_status_invalid")
    project = run_json(
        run,
        [
            "gcloud",
            "projects",
            "describe",
            project_id,
            "--format=json(projectId,projectNumber,lifecycleState)",
        ],
        "sno_readiness_project_observation_failed",
    )
    billing = run_json(
        run,
        [
            "gcloud",
            "billing",
            "projects",
            "describe",
            project_id,
            "--format=json(projectId,billingEnabled)",
        ],
        "sno_readiness_billing_observation_failed",
    )
    services = run_json(
        run,
        [
            "gcloud",
            "services",
            "list",
            "--enabled",
            f"--project={project_id}",
            "--format=json(config.name,state)",
        ],
        "sno_readiness_services_observation_failed",
    )
    if (
        not isinstance(project, dict)
        or project.get("projectId") != project_id
        or not isinstance(project.get("projectNumber"), (str, int))
        or not isinstance(project.get("lifecycleState"), str)
    ):
        fail("sno_readiness_project_observation_invalid")
    if (
        not isinstance(billing, dict)
        or billing.get("projectId") != project_id
        or type(billing.get("billingEnabled")) is not bool
    ):
        fail("sno_readiness_billing_observation_invalid")
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-diagnostic",
        "observedAt": utc_text(observed_at),
        "projectId": project_id,
        "projectNumberDigest": canonical_digest(str(project["projectNumber"])),
        "lifecycleState": project["lifecycleState"],
        "billingEnabled": billing["billingEnabled"],
        "enabledApis": service_names(services),
        "quotaRequest": {
            "status": quota_request_status,
            "source": "operator-declared",
            "requestedAdditionalProjects": (
                0 if quota_request_status == "not-submitted" else 1
            ),
        },
    }
    validate_snapshot(snapshot)
    return snapshot


def validate_snapshot(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "executionMode",
            "observedAt",
            "projectId",
            "projectNumberDigest",
            "lifecycleState",
            "billingEnabled",
            "enabledApis",
            "quotaRequest",
        },
        "sno_readiness_snapshot_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in EXECUTION_MODES
        or not PROJECT_ID.fullmatch(str(value["projectId"]))
        or not DIGEST.fullmatch(str(value["projectNumberDigest"]))
        or not isinstance(value["lifecycleState"], str)
        or not value["lifecycleState"]
        or type(value["billingEnabled"]) is not bool
    ):
        fail("sno_readiness_snapshot_identity_invalid")
    parse_utc(value["observedAt"], "sno_readiness_snapshot_time_invalid")
    apis = value["enabledApis"]
    if not isinstance(apis, list) or any(
        not isinstance(item, str) or not API_NAME.fullmatch(item) for item in apis
    ):
        fail("sno_readiness_snapshot_apis_invalid")
    if apis != sorted(set(apis)):
        fail("sno_readiness_snapshot_apis_invalid")
    quota = object_value(value["quotaRequest"], "sno_readiness_snapshot_quota_invalid")
    exact_keys(
        quota,
        {"status", "source", "requestedAdditionalProjects"},
        "sno_readiness_snapshot_quota_keys_invalid",
    )
    status = quota["status"]
    expected_count = 0 if status == "not-submitted" else 1
    if (
        status not in QUOTA_STATUSES
        or quota["source"] != "operator-declared"
        or type(quota["requestedAdditionalProjects"]) is not int
        or quota["requestedAdditionalProjects"] != expected_count
    ):
        fail("sno_readiness_snapshot_quota_invalid")


def decision_for(snapshot: dict[str, Any]) -> dict[str, Any]:
    quota_status = snapshot["quotaRequest"]["status"]
    missing_apis = sorted(set(REQUIRED_APIS) - set(snapshot["enabledApis"]))
    reason_codes: list[str] = []
    if snapshot["lifecycleState"] != "ACTIVE":
        reason_codes.append("PROJECT_NOT_ACTIVE")
    if quota_status == "not-submitted":
        reason_codes.append("QUOTA_REQUEST_NOT_SUBMITTED")
    elif quota_status == "pending":
        reason_codes.append("QUOTA_REVIEW_PENDING")
    elif quota_status == "rejected":
        reason_codes.append("QUOTA_REQUEST_REJECTED")
    if snapshot["billingEnabled"] is not True:
        reason_codes.append("BILLING_DISABLED")
    if missing_apis:
        reason_codes.append("REQUIRED_APIS_MISSING")
    reason_codes.append("DOWNSTREAM_GATES_NOT_ASSESSED")

    if snapshot["lifecycleState"] != "ACTIVE" or quota_status in {
        "not-submitted",
        "rejected",
    }:
        status = "BLOCKED"
        next_action = (
            "restore-active-project"
            if snapshot["lifecycleState"] != "ACTIVE"
            else "submit-or-revise-quota-request"
        )
    elif quota_status == "pending":
        status = "WAITING_PROVIDER"
        next_action = "await-quota-review"
    elif snapshot["billingEnabled"] is not True:
        status = "READY_FOR_FRESH_PLAN"
        next_action = "discard-old-plan-and-generate-fresh-foundation-plan"
    elif missing_apis:
        status = "FOUNDATION_RECHECK_REQUIRED"
        next_action = "verify-reviewed-foundation-apply"
    else:
        status = "DOWNSTREAM_VERIFICATION_REQUIRED"
        next_action = "verify-budget-dns-source-cidr-and-operator-lease"
    return {
        "status": status,
        "reasonCodes": reason_codes,
        "nextAction": next_action,
        "freshPlanRequired": True,
    }


def load_source_contracts() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    release_set = load_json(RELEASE_SET)
    validate_profile(profile, production)
    validate_production_isolation()
    validate_release_set(release_set)
    return profile, production, release_set


def build_assessment(
    snapshot: dict[str, Any],
    assessment_id: str,
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_readiness_assessment_id_invalid")
    profile, production, release_set = load_source_contracts()
    profile_digest = canonical_digest(profile)
    production_digest = canonical_digest(production)
    release_set_digest = validate_release_set(release_set)
    missing_apis = sorted(set(REQUIRED_APIS) - set(snapshot["enabledApis"]))
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "assessmentId": assessment_id,
        "generatedAt": snapshot["observedAt"],
        "targetClass": "engineering-trial",
        "executionMode": snapshot["executionMode"],
        "bindings": {
            "profileId": TRIAL_PROFILE_ID,
            "profileDigest": profile_digest,
            "productionProfileDigest": production_digest,
            "releaseSetId": release_set["releaseSetId"],
            "releaseSetDigest": release_set_digest,
            "requiredApisDigest": canonical_digest(list(REQUIRED_APIS)),
        },
        "offlineChecks": [
            {
                "id": "trial-profile-contract",
                "status": "passed",
                "subjectDigest": profile_digest,
            },
            {
                "id": "production-profile-isolation",
                "status": "passed",
                "subjectDigest": production_digest,
            },
            {
                "id": "cross-plane-release-set",
                "status": "passed",
                "subjectDigest": release_set_digest,
            },
            {
                "id": "non-certifying-claim-boundary",
                "status": "passed",
                "subjectDigest": canonical_digest(CLAIMS),
            },
        ],
        "providerState": {
            "observedAt": snapshot["observedAt"],
            "projectId": snapshot["projectId"],
            "projectIdentityDigest": canonical_digest(snapshot["projectId"]),
            "projectNumberDigest": snapshot["projectNumberDigest"],
            "lifecycleState": snapshot["lifecycleState"],
            "billingEnabled": snapshot["billingEnabled"],
            "enabledRequiredApiCount": len(
                set(REQUIRED_APIS) & set(snapshot["enabledApis"])
            ),
            "requiredApiCount": len(REQUIRED_APIS),
            "missingRequiredApis": missing_apis,
            "quotaRequestStatus": snapshot["quotaRequest"]["status"],
            "quotaRequestStatusSource": snapshot["quotaRequest"]["source"],
            "requestedAdditionalProjects": snapshot["quotaRequest"][
                "requestedAdditionalProjects"
            ],
        },
        "decision": decision_for(snapshot),
        "controls": {
            "commandPolicy": "read-only",
            "rawProviderOutputStored": False,
            "secretValuesStored": False,
            "cloudMutationAuthorized": False,
            "foundationPlanApplied": False,
            "activeOperatorLeaseObserved": False,
            "campaignEligible": False,
            "allowedCertificationSlots": [],
        },
        "claims": dict(CLAIMS),
    }
    report["reportDigest"] = canonical_digest(report)
    validate_assessment(report)
    return report


def snapshot_from_report(value: dict[str, Any]) -> dict[str, Any]:
    provider = object_value(
        value["providerState"], "sno_readiness_provider_state_invalid"
    )
    exact_keys(
        provider,
        {
            "observedAt",
            "projectId",
            "projectIdentityDigest",
            "projectNumberDigest",
            "lifecycleState",
            "billingEnabled",
            "enabledRequiredApiCount",
            "requiredApiCount",
            "missingRequiredApis",
            "quotaRequestStatus",
            "quotaRequestStatusSource",
            "requestedAdditionalProjects",
        },
        "sno_readiness_provider_state_keys_invalid",
    )
    enabled_count = provider["enabledRequiredApiCount"]
    missing = provider["missingRequiredApis"]
    if (
        type(enabled_count) is not int
        or not isinstance(missing, list)
        or any(
            not isinstance(item, str) or item not in REQUIRED_APIS for item in missing
        )
    ):
        fail("sno_readiness_provider_state_invalid")
    if missing != sorted(set(missing)):
        fail("sno_readiness_provider_state_invalid")
    enabled = sorted(set(REQUIRED_APIS) - set(missing))
    if len(enabled) != enabled_count:
        fail("sno_readiness_provider_api_counts_invalid")
    return {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": value["executionMode"],
        "observedAt": provider["observedAt"],
        "projectId": provider["projectId"],
        "projectNumberDigest": provider["projectNumberDigest"],
        "lifecycleState": provider["lifecycleState"],
        "billingEnabled": provider["billingEnabled"],
        "enabledApis": enabled,
        "quotaRequest": {
            "status": provider["quotaRequestStatus"],
            "source": provider["quotaRequestStatusSource"],
            "requestedAdditionalProjects": provider["requestedAdditionalProjects"],
        },
    }


def validate_assessment(value: dict[str, Any]) -> str:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "assessmentId",
            "generatedAt",
            "targetClass",
            "executionMode",
            "bindings",
            "offlineChecks",
            "providerState",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_readiness_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_readiness_report_identity_invalid")
    parse_utc(value["generatedAt"], "sno_readiness_report_time_invalid")
    snapshot = snapshot_from_report(value)
    validate_snapshot(snapshot)
    if value["generatedAt"] != snapshot["observedAt"]:
        fail("sno_readiness_report_time_mismatch")

    profile, production, release_set = load_source_contracts()
    expected_bindings = {
        "profileId": TRIAL_PROFILE_ID,
        "profileDigest": canonical_digest(profile),
        "productionProfileDigest": canonical_digest(production),
        "releaseSetId": release_set["releaseSetId"],
        "releaseSetDigest": validate_release_set(release_set),
        "requiredApisDigest": canonical_digest(list(REQUIRED_APIS)),
    }
    if value["bindings"] != expected_bindings:
        fail("sno_readiness_bindings_invalid")
    expected_checks = [
        {
            "id": "trial-profile-contract",
            "status": "passed",
            "subjectDigest": expected_bindings["profileDigest"],
        },
        {
            "id": "production-profile-isolation",
            "status": "passed",
            "subjectDigest": expected_bindings["productionProfileDigest"],
        },
        {
            "id": "cross-plane-release-set",
            "status": "passed",
            "subjectDigest": expected_bindings["releaseSetDigest"],
        },
        {
            "id": "non-certifying-claim-boundary",
            "status": "passed",
            "subjectDigest": canonical_digest(CLAIMS),
        },
    ]
    if value["offlineChecks"] != expected_checks:
        fail("sno_readiness_offline_checks_invalid")

    provider = value["providerState"]
    expected_provider = {
        "observedAt": snapshot["observedAt"],
        "projectId": snapshot["projectId"],
        "projectIdentityDigest": canonical_digest(snapshot["projectId"]),
        "projectNumberDigest": snapshot["projectNumberDigest"],
        "lifecycleState": snapshot["lifecycleState"],
        "billingEnabled": snapshot["billingEnabled"],
        "enabledRequiredApiCount": len(snapshot["enabledApis"]),
        "requiredApiCount": len(REQUIRED_APIS),
        "missingRequiredApis": sorted(
            set(REQUIRED_APIS) - set(snapshot["enabledApis"])
        ),
        "quotaRequestStatus": snapshot["quotaRequest"]["status"],
        "quotaRequestStatusSource": snapshot["quotaRequest"]["source"],
        "requestedAdditionalProjects": snapshot["quotaRequest"][
            "requestedAdditionalProjects"
        ],
    }
    if provider != expected_provider:
        fail("sno_readiness_provider_state_invalid")
    if value["decision"] != decision_for(snapshot):
        fail("sno_readiness_decision_invalid")
    if value["controls"] != {
        "commandPolicy": "read-only",
        "rawProviderOutputStored": False,
        "secretValuesStored": False,
        "cloudMutationAuthorized": False,
        "foundationPlanApplied": False,
        "activeOperatorLeaseObserved": False,
        "campaignEligible": False,
        "allowedCertificationSlots": [],
    }:
        fail("sno_readiness_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_readiness_claims_invalid")
    claimed_digest = value["reportDigest"]
    if not DIGEST.fullmatch(str(claimed_digest)):
        fail("sno_readiness_report_digest_invalid")
    unsigned = dict(value)
    unsigned.pop("reportDigest")
    actual_digest = canonical_digest(unsigned)
    if claimed_digest != actual_digest:
        fail("sno_readiness_report_digest_mismatch")
    return actual_digest


def write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="ascii") as handle:
            json.dump(value, handle, sort_keys=True, indent=2, ensure_ascii=True)
            handle.write("\n")
    except FileExistsError:
        fail("sno_readiness_output_exists")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect = subparsers.add_parser("collect")
    collect.add_argument("--project-id", required=True)
    collect.add_argument(
        "--quota-request-status", choices=sorted(QUOTA_STATUSES), required=True
    )
    collect.add_argument("--assessment-id", required=True)
    collect.add_argument("--output", type=Path, required=True)

    assess = subparsers.add_parser("assess")
    assess.add_argument("--snapshot", type=Path, required=True)
    assess.add_argument("--assessment-id", required=True)
    assess.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "collect":
        snapshot = collect_snapshot(
            args.project_id,
            args.quota_request_status,
            datetime.now(timezone.utc),
        )
        report = build_assessment(snapshot, args.assessment_id)
        write_new(args.output, report)
        print(
            "sno_trial_readiness_collected "
            f"status={report['decision']['status']} "
            f"nextAction={report['decision']['nextAction']} "
            "mutationAuthorized=false campaignEvidence=false"
        )
        return 0
    if args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_readiness_live_snapshot_requires_collect")
        report = build_assessment(snapshot, args.assessment_id)
        write_new(args.output, report)
        print(
            "sno_trial_readiness_assessed "
            f"executionMode={report['executionMode']} "
            f"status={report['decision']['status']} "
            "mutationAuthorized=false campaignEvidence=false"
        )
        return 0
    report = load_json(args.report)
    digest = validate_assessment(report)
    print(
        "sno_trial_readiness_valid "
        f"digest={digest} status={report['decision']['status']} "
        "mutationAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
