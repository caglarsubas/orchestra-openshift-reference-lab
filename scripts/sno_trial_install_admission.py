#!/usr/bin/env python3
"""Bind live SNO prerequisites into a short-lived render admission."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.openshift_toolchain_intake import (
        LOCK_PATH as TOOLCHAIN_LOCK,
        validate_report as validate_toolchain_report,
    )
    from scripts.sno_trial_dns_delegation import (
        validate_assessment as validate_dns_report,
    )
    from scripts.sno_trial_network_hygiene import (
        validate_assessment as validate_network_report,
    )
    from scripts.sno_trial_operator_path import (
        validate_assessment as validate_operator_report,
    )
    from scripts.sno_trial_readiness import (
        validate_assessment as validate_readiness_report,
    )
    from scripts.trial_lease import (
        load_profile,
        read_lease,
        validate_lease,
    )
    from scripts.validate_sno_trial_profile import (
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
    )
except ModuleNotFoundError:
    from openshift_toolchain_intake import (  # type: ignore[no-redef]
        LOCK_PATH as TOOLCHAIN_LOCK,
        validate_report as validate_toolchain_report,
    )
    from sno_trial_dns_delegation import (  # type: ignore[no-redef]
        validate_assessment as validate_dns_report,
    )
    from sno_trial_network_hygiene import (  # type: ignore[no-redef]
        validate_assessment as validate_network_report,
    )
    from sno_trial_operator_path import (  # type: ignore[no-redef]
        validate_assessment as validate_operator_report,
    )
    from sno_trial_readiness import (  # type: ignore[no-redef]
        validate_assessment as validate_readiness_report,
    )
    from trial_lease import (  # type: ignore[no-redef]
        load_profile,
        read_lease,
        validate_lease,
    )
    from validate_sno_trial_profile import (  # type: ignore[no-redef]
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
    )


REPORT_KIND = "orchestra.openshift.sno-trial-render-admission.v1"
ADMISSION_ID = re.compile(r"^sno-render-[a-z0-9][a-z0-9.-]{5,79}$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
MAX_AGE_MINUTES = {
    "provider-readiness": 15,
    "network-hygiene": 15,
    "dns-delegation": 15,
    "operator-path": 15,
    "toolchain-intake": 43_200,
}
ADMISSION_TTL_MINUTES = 15
FUTURE_SKEW = timedelta(minutes=2)
EVIDENCE_ORDER = tuple(MAX_AGE_MINUTES)
LIVE_MODE_BY_TYPE = {
    "provider-readiness": "live-diagnostic",
    "network-hygiene": "live-diagnostic",
    "dns-delegation": "live-diagnostic",
    "operator-path": "live-diagnostic",
    "toolchain-intake": "live-local",
}
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


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


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


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def evidence_is_fresh(
    generated_at: datetime, assessed_at: datetime, max_age_minutes: int
) -> bool:
    return (
        generated_at <= assessed_at + FUTURE_SKEW
        and assessed_at - generated_at
        < timedelta(minutes=max_age_minutes)
    )


def evidence_binding(
    evidence_type: str,
    report: dict[str, Any],
    accepted: bool,
    assessed_at: datetime,
) -> dict[str, Any]:
    generated_at = parse_utc(
        report["generatedAt"], "sno_render_admission_evidence_time_invalid"
    )
    max_age = MAX_AGE_MINUTES[evidence_type]
    identifier_key = (
        "intakeId" if evidence_type == "toolchain-intake" else "assessmentId"
    )
    return {
        "type": evidence_type,
        "kind": report["kind"],
        "id": report[identifier_key],
        "reportDigest": report["reportDigest"],
        "generatedAt": report["generatedAt"],
        "executionMode": report["executionMode"],
        "maxAgeMinutes": max_age,
        "fresh": evidence_is_fresh(generated_at, assessed_at, max_age),
        "accepted": accepted,
    }


def readiness_accepted(report: dict[str, Any]) -> bool:
    state = report["providerState"]
    return (
        state["lifecycleState"] == "ACTIVE"
        and state["billingEnabled"] is True
        and state["enabledRequiredApiCount"] == state["requiredApiCount"]
        and state["missingRequiredApis"] == []
        and state["quotaRequestStatus"] == "approved"
        and report["decision"]["status"]
        == "DOWNSTREAM_VERIFICATION_REQUIRED"
    )


def report_projects(
    readiness: dict[str, Any],
    network: dict[str, Any],
    dns: dict[str, Any],
    operator: dict[str, Any],
) -> list[str]:
    return [
        readiness["providerState"]["projectId"],
        network["bindings"]["projectId"],
        dns["bindings"]["projectId"],
        operator["bindings"]["projectId"],
    ]


def decision_for(
    evidence: list[dict[str, Any]],
    project_matches: bool,
    lease_operator_matches: bool,
) -> dict[str, Any]:
    reasons: list[str] = []
    if any(
        item["executionMode"] != LIVE_MODE_BY_TYPE[item["type"]]
        for item in evidence
    ):
        reasons.append("LIVE_EVIDENCE_REQUIRED")
    if not all(item["fresh"] for item in evidence):
        reasons.append("EVIDENCE_STALE_OR_FUTURE")
    if not project_matches:
        reasons.append("PROJECT_BINDING_MISMATCH")
    if not evidence[0]["accepted"]:
        reasons.append("READINESS_NOT_ACCEPTED")
    if not evidence[1]["accepted"]:
        reasons.append("NETWORK_NOT_CLEAN")
    if not evidence[2]["accepted"]:
        reasons.append("DNS_NOT_OBSERVED")
    if not evidence[3]["accepted"]:
        reasons.append("OPERATOR_PATH_NOT_OBSERVED")
    if not evidence[4]["accepted"]:
        reasons.append("TOOLCHAIN_NOT_ACCEPTED")
    if not lease_operator_matches:
        reasons.append("LEASE_OPERATOR_IDENTITY_MISMATCH")
    ready = not reasons
    return {
        "status": "READY_TO_RENDER" if ready else "BLOCKED",
        "reasonCodes": reasons,
        "nextAction": (
            "render-secret-free-install-config"
            if ready
            else "refresh-and-reconcile-prerequisites"
        ),
    }


def build_admission(
    *,
    readiness: dict[str, Any],
    network: dict[str, Any],
    dns: dict[str, Any],
    operator: dict[str, Any],
    toolchain: dict[str, Any],
    lease: dict[str, Any],
    project_id: str,
    admission_id: str,
    assessed_at: datetime,
) -> dict[str, Any]:
    if not PROJECT_ID.fullmatch(project_id):
        fail("sno_render_admission_project_invalid")
    if not ADMISSION_ID.fullmatch(admission_id):
        fail("sno_render_admission_id_invalid")
    if (
        assessed_at.tzinfo is None
        or assessed_at.utcoffset() != timedelta(0)
    ):
        fail("sno_render_admission_assessment_not_utc")
    validate_readiness_report(readiness)
    validate_network_report(network)
    validate_dns_report(dns)
    validate_operator_report(operator)
    toolchain_lock = load_json(TOOLCHAIN_LOCK)
    validate_toolchain_report(toolchain, toolchain_lock)
    profile = load_profile()
    validate_lease(
        lease,
        profile,
        assessed_at,
        expected_project_id=project_id,
    )
    projects = report_projects(readiness, network, dns, operator)
    project_matches = all(item == project_id for item in projects)
    operator_identities = operator["operatorPathState"][
        "activeIdentityDigests"
    ]
    lease_operator_matches = (
        len(operator_identities) == 1
        and lease["operatorIdentityDigest"] == operator_identities[0]
    )
    evidence = [
        evidence_binding(
            "provider-readiness",
            readiness,
            readiness_accepted(readiness),
            assessed_at,
        ),
        evidence_binding(
            "network-hygiene",
            network,
            network["decision"]["status"] == "CLEAN",
            assessed_at,
        ),
        evidence_binding(
            "dns-delegation",
            dns,
            dns["decision"]["status"] == "DELEGATION_OBSERVED",
            assessed_at,
        ),
        evidence_binding(
            "operator-path",
            operator,
            operator["decision"]["status"] == "OPERATOR_PATH_OBSERVED",
            assessed_at,
        ),
        evidence_binding(
            "toolchain-intake",
            toolchain,
            True,
            assessed_at,
        ),
    ]
    decision = decision_for(evidence, project_matches, lease_operator_matches)
    expiry_candidates = [
        assessed_at + timedelta(minutes=ADMISSION_TTL_MINUTES),
        parse_utc(lease["expiresAt"], "sno_render_admission_lease_time_invalid"),
    ]
    expiry_candidates.extend(
        parse_utc(
            item["generatedAt"],
            "sno_render_admission_evidence_time_invalid",
        )
        + timedelta(minutes=item["maxAgeMinutes"])
        for item in evidence
    )
    valid_until = min(expiry_candidates)
    if decision["status"] != "READY_TO_RENDER":
        valid_until = assessed_at
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "admissionId": admission_id,
        "generatedAt": utc_text(assessed_at),
        "validUntil": utc_text(valid_until),
        "targetClass": "engineering-trial",
        "bindings": {
            "profileId": TRIAL_PROFILE_ID,
            "profileDigest": canonical_digest(profile),
            "projectId": project_id,
            "projectIdentityDigest": canonical_digest(project_id),
            "leaseId": lease["leaseId"],
            "leaseDigest": canonical_digest(lease),
            "operatorIdentityDigest": lease["operatorIdentityDigest"],
            "sourceCidrDigest": operator["operatorPathState"][
                "sourceCidrDigest"
            ],
            "evidenceSetDigest": canonical_digest(evidence),
        },
        "evidence": evidence,
        "decision": decision,
        "controls": {
            "installConfigRenderAuthorized": (
                decision["status"] == "READY_TO_RENDER"
            ),
            "cloudMutationAuthorized": False,
            "firewallMutationAuthorized": False,
            "clusterCreationAuthorized": False,
            "campaignEligible": False,
            "allowedCertificationSlots": [],
        },
        "claims": copy.deepcopy(CLAIMS),
    }
    report["reportDigest"] = canonical_digest(report)
    validate_admission(
        report,
        assessed_at,
        expected_project_id=project_id,
        lease=lease,
    )
    return report


def validate_admission(
    value: dict[str, Any],
    at: datetime,
    *,
    expected_project_id: str,
    lease: dict[str, Any],
) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "admissionId",
            "generatedAt",
            "validUntil",
            "targetClass",
            "bindings",
            "evidence",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_render_admission_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ADMISSION_ID.fullmatch(str(value["admissionId"]))
        or value["targetClass"] != "engineering-trial"
        or not PROJECT_ID.fullmatch(expected_project_id)
        or at.tzinfo is None
        or at.utcoffset() != timedelta(0)
    ):
        fail("sno_render_admission_identity_invalid")
    generated_at = parse_utc(
        value["generatedAt"], "sno_render_admission_time_invalid"
    )
    valid_until = parse_utc(
        value["validUntil"], "sno_render_admission_time_invalid"
    )
    if generated_at > at + FUTURE_SKEW:
        fail("sno_render_admission_not_active")
    profile = load_profile()
    validate_lease(
        lease,
        profile,
        at,
        expected_project_id=expected_project_id,
    )
    bindings = object_value(
        value["bindings"], "sno_render_admission_bindings_invalid"
    )
    exact_keys(
        bindings,
        {
            "profileId",
            "profileDigest",
            "projectId",
            "projectIdentityDigest",
            "leaseId",
            "leaseDigest",
            "operatorIdentityDigest",
            "sourceCidrDigest",
            "evidenceSetDigest",
        },
        "sno_render_admission_bindings_keys_invalid",
    )
    if (
        bindings["profileId"] != TRIAL_PROFILE_ID
        or bindings["profileDigest"] != canonical_digest(profile)
        or bindings["projectId"] != expected_project_id
        or bindings["projectIdentityDigest"]
        != canonical_digest(expected_project_id)
        or bindings["leaseId"] != lease["leaseId"]
        or bindings["leaseDigest"] != canonical_digest(lease)
        or bindings["operatorIdentityDigest"]
        != lease["operatorIdentityDigest"]
        or not DIGEST.fullmatch(str(bindings["sourceCidrDigest"]))
    ):
        fail("sno_render_admission_bindings_invalid")
    evidence = value["evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(EVIDENCE_ORDER):
        fail("sno_render_admission_evidence_invalid")
    for actual, expected_type in zip(evidence, EVIDENCE_ORDER, strict=True):
        item = object_value(actual, "sno_render_admission_evidence_invalid")
        exact_keys(
            item,
            {
                "type",
                "kind",
                "id",
                "reportDigest",
                "generatedAt",
                "executionMode",
                "maxAgeMinutes",
                "fresh",
                "accepted",
            },
            "sno_render_admission_evidence_keys_invalid",
        )
        if (
            item["type"] != expected_type
            or not isinstance(item["kind"], str)
            or not isinstance(item["id"], str)
            or not DIGEST.fullmatch(str(item["reportDigest"]))
            or item["executionMode"]
            not in {"simulated", "live-diagnostic", "live-local"}
            or item["maxAgeMinutes"] != MAX_AGE_MINUTES[expected_type]
            or type(item["fresh"]) is not bool
            or type(item["accepted"]) is not bool
        ):
            fail("sno_render_admission_evidence_invalid")
        evidence_time = parse_utc(
            item["generatedAt"],
            "sno_render_admission_evidence_time_invalid",
        )
        if item["fresh"] != evidence_is_fresh(
            evidence_time, generated_at, item["maxAgeMinutes"]
        ):
            fail("sno_render_admission_evidence_freshness_invalid")
    if bindings["evidenceSetDigest"] != canonical_digest(evidence):
        fail("sno_render_admission_evidence_digest_invalid")
    decision = object_value(
        value["decision"], "sno_render_admission_decision_invalid"
    )
    exact_keys(
        decision,
        {"status", "reasonCodes", "nextAction"},
        "sno_render_admission_decision_keys_invalid",
    )
    if (
        decision["status"] not in {"READY_TO_RENDER", "BLOCKED"}
        or not isinstance(decision["reasonCodes"], list)
        or len(decision["reasonCodes"]) != len(set(decision["reasonCodes"]))
        or decision["nextAction"]
        not in {
            "render-secret-free-install-config",
            "refresh-and-reconcile-prerequisites",
        }
    ):
        fail("sno_render_admission_decision_invalid")
    ready = decision["status"] == "READY_TO_RENDER"
    controls = object_value(
        value["controls"], "sno_render_admission_controls_invalid"
    )
    expected_controls = {
        "installConfigRenderAuthorized": ready,
        "cloudMutationAuthorized": False,
        "firewallMutationAuthorized": False,
        "clusterCreationAuthorized": False,
        "campaignEligible": False,
        "allowedCertificationSlots": [],
    }
    if controls != expected_controls:
        fail("sno_render_admission_controls_invalid")
    if ready:
        if (
            decision["reasonCodes"] != []
            or decision["nextAction"]
            != "render-secret-free-install-config"
            or at >= valid_until
            or not all(
                item["fresh"]
                and item["accepted"]
                and item["executionMode"]
                == LIVE_MODE_BY_TYPE[item["type"]]
                for item in evidence
            )
        ):
            fail("sno_render_admission_ready_invalid")
    elif (
        not decision["reasonCodes"]
        or decision["nextAction"]
        != "refresh-and-reconcile-prerequisites"
        or valid_until != generated_at
    ):
        fail("sno_render_admission_blocked_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_render_admission_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_render_admission_report_digest_invalid")


def write_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fail("sno_render_admission_output_exists")
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
        stream.write("\n")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--readiness", type=Path, required=True)
    create.add_argument("--network", type=Path, required=True)
    create.add_argument("--dns", type=Path, required=True)
    create.add_argument("--operator-path", type=Path, required=True)
    create.add_argument("--toolchain", type=Path, required=True)
    create.add_argument("--lease", type=Path, required=True)
    create.add_argument("--project-id", required=True)
    create.add_argument("--admission-id", required=True)
    create.add_argument("--at")
    create.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--admission", type=Path, required=True)
    verify.add_argument("--lease", type=Path, required=True)
    verify.add_argument("--project-id", required=True)
    verify.add_argument("--at")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    at = (
        parse_utc(args.at, "sno_render_admission_assessment_time_invalid")
        if args.at
        else datetime.now(timezone.utc)
    )
    lease = read_lease(args.lease.resolve())
    if args.command == "create":
        report = build_admission(
            readiness=load_json(args.readiness),
            network=load_json(args.network),
            dns=load_json(args.dns),
            operator=load_json(args.operator_path),
            toolchain=load_json(args.toolchain),
            lease=lease,
            project_id=args.project_id,
            admission_id=args.admission_id,
            assessed_at=at,
        )
        write_create_only(args.output, report)
        print(
            "sno_render_admission_created "
            f"status={report['decision']['status']} "
            f"validUntil={report['validUntil']} "
            "clusterCreationAuthorized=false campaignEvidence=false"
        )
        return 0
    report = load_json(args.admission)
    validate_admission(
        report,
        at,
        expected_project_id=args.project_id,
        lease=lease,
    )
    print(
        "sno_render_admission_valid "
        f"digest={report['reportDigest']} "
        f"status={report['decision']['status']} "
        "clusterCreationAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
