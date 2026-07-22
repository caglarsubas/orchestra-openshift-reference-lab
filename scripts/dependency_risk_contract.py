#!/usr/bin/env python3
"""Contracts for unsigned dependency risk evidence and human exceptions."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_dependency_supply_chain import (
        ADMISSION,
        ADMISSION_DIGEST,
        EXPECTED_SOURCE_VERIFICATION_DIGEST,
        SOURCE_VERIFICATION,
        TOPOLOGY_DIGEST,
        UNSIGNED_SUBJECTS,
        admission_subjects,
    )
    from scripts.validate_repository import DIGEST, ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_dependency_supply_chain import (
        ADMISSION,
        ADMISSION_DIGEST,
        EXPECTED_SOURCE_VERIFICATION_DIGEST,
        SOURCE_VERIFICATION,
        TOPOLOGY_DIGEST,
        UNSIGNED_SUBJECTS,
        admission_subjects,
    )
    from validate_repository import DIGEST, ROOT, canonical_digest, load_json


RISK_POLICY = ROOT / "config" / "dependency-risk-policy.lock.json"
EXCEPTION_TEMPLATE = ROOT / "config" / "dependency-signature-exceptions.example.json"
EXPECTED_RISK_POLICY_DIGEST = (
    "sha256:c0f22c02e37447a97a6d97c6352d7fb2207c601969ba7857d7910ab661f3731e"
)
EXPECTED_EXCEPTION_TEMPLATE_DIGEST = (
    "sha256:ddff89276316a21d25770cfbfc5095dcf2781281e4026236d98d6bbf784cf848"
)
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
BLOCKING_SEVERITIES = ("CRITICAL", "HIGH", "UNKNOWN")
REVIEWER_ROLES = ("security-reviewer", "service-owner")
EVIDENCE_KEYS = {
    "riskEvidenceDigest",
    "collectionAttestationDigest",
    "runnerImageDigest",
    "runnerProvenanceBundleDigest",
    "sbomDigest",
    "vulnerabilityReportDigest",
    "licenseInventoryDigest",
    "machineReviewDigest",
    "licenseReviewDigest",
    "riskReviewDigest",
    "compensatingControlsDigest",
}
EMPTY_EVIDENCE = {key: None for key in EVIDENCE_KEYS}
EMPTY_REQUEST = {
    "status": "evidence-required",
    "exceptionId": None,
    "requestedAt": None,
    "requestorIdentityDigest": None,
    "candidateDigest": None,
}
EMPTY_DECISION = {
    "status": "required-not-approved",
    "approvedAt": None,
    "expiresAt": None,
    "approvalDigest": None,
}
EMPTY_REASON_CODES = [
    "RISK_EVIDENCE_MISSING",
    "INDEPENDENT_REVIEWS_MISSING",
    "SIGNED_RUNNER_REVERIFICATION_REQUIRED",
]
CONTROL_PLAN = [
    {"id": "exact-source-and-platform-digests", "requiredBefore": "review"},
    {
        "id": "signed-runner-evidence-and-independent-verification",
        "requiredBefore": "review",
    },
    {"id": "private-mirror-by-digest", "requiredBefore": "activation"},
    {"id": "lab-kms-signature", "requiredBefore": "activation"},
    {
        "id": "admission-policy-rejects-unapproved-destination",
        "requiredBefore": "activation",
    },
    {
        "id": "restricted-runtime-default-deny-and-allowlisted-egress",
        "requiredBefore": "activation",
    },
    {
        "id": "continuous-rescan-and-expiry-enforcement",
        "requiredBefore": "activation",
    },
]
EVIDENCE_ID = re.compile(r"^orchestra-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$")
EXCEPTION_ID = re.compile(
    r"^orchestra-upstream-signature-exception-[a-z0-9][a-z0-9.-]+$"
)


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(code)
    return value


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None:
        fail(code)
    return parsed


def blob_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def image_base(reference: str) -> str:
    separator = reference.rfind(":")
    if separator <= reference.rfind("/"):
        fail("dependency_risk_image_tag_missing")
    return reference[:separator]


def unsigned_subjects(admission: dict[str, Any]) -> dict[str, dict[str, str]]:
    source_by_id = admission_subjects(admission)
    result: dict[str, dict[str, str]] = {}
    for image in admission["images"]:
        subject_id = image["id"]
        if subject_id not in UNSIGNED_SUBJECTS:
            continue
        base = image_base(image["source"]["reference"])
        result[subject_id] = {
            "sourceSubject": source_by_id[subject_id],
            "platformSubject": f"{base}@{image['source']['platformDigest']}",
        }
    if set(result) != UNSIGNED_SUBJECTS:
        fail("dependency_risk_unsigned_inventory_invalid")
    return result


def expected_bindings() -> dict[str, str]:
    return {
        "topologyDigest": TOPOLOGY_DIGEST,
        "dependencyAdmissionDigest": ADMISSION_DIGEST,
        "sourceVerificationDigest": EXPECTED_SOURCE_VERIFICATION_DIGEST,
        "riskPolicyDigest": EXPECTED_RISK_POLICY_DIGEST,
    }


def validate_risk_policy(value: dict[str, Any]) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "profileId",
            "policyId",
            "bindings",
            "scope",
            "collectionPolicy",
            "vulnerabilityPolicy",
            "licensePolicy",
            "exceptionPolicy",
            "compensatingControls",
            "claim",
        },
        "dependency_risk_policy_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != "orchestra-ocp-4.20-amd64-v1"
        or value["policyId"] != "orchestra-unsigned-source-risk-policy-v1"
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "dependencyAdmissionDigest": ADMISSION_DIGEST,
            "sourceVerificationDigest": EXPECTED_SOURCE_VERIFICATION_DIGEST,
        }
    ):
        fail("dependency_risk_policy_identity_invalid")
    if value["scope"] != {
        "signatureObservation": "no-cosign-signature-at-locked-index",
        "platform": "linux/amd64",
        "subjectIds": sorted(UNSIGNED_SUBJECTS),
    }:
        fail("dependency_risk_policy_scope_invalid")
    if value["collectionPolicy"] != {
        "executionClass": "signed-certification-runner",
        "maximumCollectionDurationHours": 6,
        "maximumEvidenceAgeHours": 72,
        "requiredArtifactTypes": [
            "trivy-vulnerability-json",
            "spdx-2.3-json",
        ],
        "runnerProvenanceRequired": True,
        "collectionAttestationRequired": True,
        "rawArtifactsRestricted": True,
    }:
        fail("dependency_risk_policy_collection_invalid")
    if value["vulnerabilityPolicy"] != {
        "blockingSeverities": list(BLOCKING_SEVERITIES),
        "recognizedSeverities": list(SEVERITIES),
        "ignoreFileAllowed": False,
        "ignoreUnfixedAllowed": False,
        "severityFilterAllowed": False,
        "databaseDigestRequired": True,
        "scanTargetRequired": True,
    }:
        fail("dependency_risk_policy_vulnerability_invalid")
    if value["licensePolicy"] != {
        "format": "SPDX-2.3",
        "packageInventoryRequired": True,
        "humanReviewRequired": True,
        "automatedApprovalAllowed": False,
        "unknownLicenseRequiresExplicitDecision": True,
    }:
        fail("dependency_risk_policy_license_invalid")
    if value["exceptionPolicy"] != {
        "maximumLifetimeHours": 720,
        "minimumReviewers": 2,
        "requiredReviewerRoles": list(REVIEWER_ROLES),
        "distinctReviewerIdentities": True,
        "requestorMayReview": False,
        "collectorMayReview": False,
        "approvalBindsCandidateDigest": True,
        "expiryBlocksNewSync": True,
    }:
        fail("dependency_risk_policy_exception_invalid")
    if value["compensatingControls"] != CONTROL_PLAN:
        fail("dependency_risk_policy_controls_invalid")
    if value["claim"] != {
        "riskEvidenceBundles": 0,
        "exceptionsApproved": 0,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "applied": False,
        "campaignEvidence": False,
    }:
        fail("dependency_risk_policy_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_RISK_POLICY_DIGEST:
        fail(f"dependency_risk_policy_digest_changed:{digest}")
    return digest


def validate_collection(
    value: Any,
    source_verification: dict[str, Any],
) -> dict[str, Any]:
    collection = strict_keys(
        value,
        {
            "executionClass",
            "runnerImageDigest",
            "runnerProvenanceBundleDigest",
            "actorIdentityDigest",
            "startedAt",
            "completedAt",
            "collectionAttestationDigest",
            "vulnerabilityScanner",
            "sbomScanner",
            "invocationPolicy",
        },
        "dependency_risk_collection_shape_invalid",
    )
    if collection["executionClass"] != "signed-certification-runner":
        fail("dependency_risk_collection_execution_class_invalid")
    for field in (
        "runnerImageDigest",
        "runnerProvenanceBundleDigest",
        "actorIdentityDigest",
        "collectionAttestationDigest",
    ):
        require_digest(
            collection[field], f"dependency_risk_collection_digest_invalid:{field}"
        )
    started_at = parse_utc(
        collection["startedAt"], "dependency_risk_collection_time_invalid"
    )
    completed_at = parse_utc(
        collection["completedAt"], "dependency_risk_collection_time_invalid"
    )
    observed_at = parse_utc(
        source_verification["observationWindow"]["observedAt"],
        "dependency_risk_source_window_invalid",
    )
    valid_until = parse_utc(
        source_verification["observationWindow"]["validUntil"],
        "dependency_risk_source_window_invalid",
    )
    if (
        completed_at < started_at
        or completed_at - started_at > timedelta(hours=6)
        or started_at < observed_at
        or completed_at > valid_until
    ):
        fail("dependency_risk_collection_time_invalid")
    vulnerability_scanner = strict_keys(
        collection["vulnerabilityScanner"],
        {"name", "version", "databaseDigest"},
        "dependency_risk_vulnerability_scanner_invalid",
    )
    if (
        vulnerability_scanner["name"] != "trivy"
        or not isinstance(vulnerability_scanner["version"], str)
        or not vulnerability_scanner["version"].strip()
    ):
        fail("dependency_risk_vulnerability_scanner_invalid")
    require_digest(
        vulnerability_scanner["databaseDigest"],
        "dependency_risk_vulnerability_database_digest_invalid",
    )
    sbom_scanner = strict_keys(
        collection["sbomScanner"],
        {"name", "version"},
        "dependency_risk_sbom_scanner_invalid",
    )
    if (
        sbom_scanner["name"] != "syft"
        or not isinstance(sbom_scanner["version"], str)
        or not sbom_scanner["version"].strip()
    ):
        fail("dependency_risk_sbom_scanner_invalid")
    if collection["invocationPolicy"] != {
        "platform": "linux/amd64",
        "vulnerabilityScanners": ["vuln"],
        "ignoreFileUsed": False,
        "ignoreUnfixed": False,
        "severityFilter": [],
        "sbomFormat": "spdx-2.3-json",
    }:
        fail("dependency_risk_invocation_policy_invalid")
    return collection


def expected_machine_review(
    vulnerability_summary: dict[str, Any],
) -> tuple[str, list[str]]:
    blocking = [
        severity
        for severity in BLOCKING_SEVERITIES
        if vulnerability_summary["bySeverity"][severity] > 0
    ]
    if blocking:
        return "blocked", [f"{severity}_FINDINGS_PRESENT" for severity in blocking]
    return "eligible-for-human-review", [
        "VULNERABILITY_THRESHOLD_PASSED",
        "LICENSE_REVIEW_REQUIRED",
        "UNSIGNED_UPSTREAM_EXCEPTION_REQUIRED",
    ]


def validate_risk_evidence(
    value: dict[str, Any],
    admission: dict[str, Any],
    source_verification: dict[str, Any],
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "profileId",
            "targetClass",
            "executionMode",
            "evidenceId",
            "bindings",
            "collection",
            "subjects",
            "claim",
        },
        "dependency_risk_evidence_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != "orchestra-ocp-4.20-amd64-v1"
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or not isinstance(value["evidenceId"], str)
        or not EVIDENCE_ID.fullmatch(value["evidenceId"])
        or value["bindings"] != expected_bindings()
    ):
        fail("dependency_risk_evidence_identity_invalid")
    collection = validate_collection(value["collection"], source_verification)
    expected_subjects = unsigned_subjects(admission)
    items = value["subjects"]
    if not isinstance(items, list) or len(items) != len(expected_subjects):
        fail("dependency_risk_evidence_inventory_invalid")
    seen: set[str] = set()
    threshold_passed = 0
    review_eligible = 0
    for item in items:
        strict_keys(
            item,
            {
                "id",
                "sourceSubject",
                "platformSubject",
                "artifacts",
                "vulnerabilities",
                "licenses",
                "compensatingControls",
                "machineReview",
            },
            "dependency_risk_evidence_subject_shape_invalid",
        )
        subject_id = item["id"]
        if subject_id not in expected_subjects or subject_id in seen:
            fail("dependency_risk_evidence_inventory_invalid")
        seen.add(subject_id)
        if (
            item["sourceSubject"] != expected_subjects[subject_id]["sourceSubject"]
            or item["platformSubject"]
            != expected_subjects[subject_id]["platformSubject"]
        ):
            fail(f"dependency_risk_evidence_subject_binding_invalid:{subject_id}")
        artifacts = strict_keys(
            item["artifacts"],
            {"vulnerability", "sbom"},
            f"dependency_risk_artifacts_invalid:{subject_id}",
        )
        for kind in ("vulnerability", "sbom"):
            artifact = strict_keys(
                artifacts[kind],
                {"fileName", "digest"},
                f"dependency_risk_artifact_invalid:{subject_id}:{kind}",
            )
            if (
                not isinstance(artifact["fileName"], str)
                or Path(artifact["fileName"]).name != artifact["fileName"]
            ):
                fail(f"dependency_risk_artifact_name_invalid:{subject_id}:{kind}")
            require_digest(
                artifact["digest"],
                f"dependency_risk_artifact_digest_invalid:{subject_id}:{kind}",
            )
        vulnerabilities = strict_keys(
            item["vulnerabilities"],
            {
                "total",
                "bySeverity",
                "fixAvailableBySeverity",
                "scanTargetCount",
                "thresholdState",
            },
            f"dependency_risk_vulnerability_summary_invalid:{subject_id}",
        )
        by_severity = strict_keys(
            vulnerabilities["bySeverity"],
            set(SEVERITIES),
            f"dependency_risk_vulnerability_counts_invalid:{subject_id}",
        )
        fix_available = strict_keys(
            vulnerabilities["fixAvailableBySeverity"],
            set(SEVERITIES),
            f"dependency_risk_vulnerability_fix_counts_invalid:{subject_id}",
        )
        if any(
            not isinstance(by_severity[severity], int)
            or isinstance(by_severity[severity], bool)
            or by_severity[severity] < 0
            or not isinstance(fix_available[severity], int)
            or isinstance(fix_available[severity], bool)
            or fix_available[severity] < 0
            or fix_available[severity] > by_severity[severity]
            for severity in SEVERITIES
        ):
            fail(f"dependency_risk_vulnerability_counts_invalid:{subject_id}")
        threshold_state = (
            "passed"
            if all(by_severity[severity] == 0 for severity in BLOCKING_SEVERITIES)
            else "blocked"
        )
        if (
            vulnerabilities["total"] != sum(by_severity.values())
            or not isinstance(vulnerabilities["scanTargetCount"], int)
            or isinstance(vulnerabilities["scanTargetCount"], bool)
            or vulnerabilities["scanTargetCount"] < 1
            or vulnerabilities["thresholdState"] != threshold_state
        ):
            fail(f"dependency_risk_vulnerability_summary_invalid:{subject_id}")
        if threshold_state == "passed":
            threshold_passed += 1
        licenses = strict_keys(
            item["licenses"],
            {
                "packageCount",
                "expressions",
                "noAssertionCount",
                "noneCount",
                "inventoryDigest",
                "humanReviewState",
            },
            f"dependency_risk_license_summary_invalid:{subject_id}",
        )
        expressions = licenses["expressions"]
        if (
            not isinstance(licenses["packageCount"], int)
            or isinstance(licenses["packageCount"], bool)
            or licenses["packageCount"] < 1
            or not isinstance(expressions, list)
            or expressions != sorted(set(expressions))
            or any(
                not isinstance(expression, str) or not expression
                for expression in expressions
            )
            or not isinstance(licenses["noAssertionCount"], int)
            or isinstance(licenses["noAssertionCount"], bool)
            or licenses["noAssertionCount"] < 0
            or not isinstance(licenses["noneCount"], int)
            or isinstance(licenses["noneCount"], bool)
            or licenses["noneCount"] < 0
            or licenses["noAssertionCount"] > licenses["packageCount"] * 2
            or licenses["noneCount"] > licenses["packageCount"] * 2
            or licenses["humanReviewState"] != "required"
        ):
            fail(f"dependency_risk_license_summary_invalid:{subject_id}")
        require_digest(
            licenses["inventoryDigest"],
            f"dependency_risk_license_inventory_digest_invalid:{subject_id}",
        )
        controls = strict_keys(
            item["compensatingControls"],
            {"planDigest", "controls"},
            f"dependency_risk_controls_invalid:{subject_id}",
        )
        expected_control_states = [
            {
                "id": control["id"],
                "requiredBefore": control["requiredBefore"],
                "status": "declared-not-proven",
            }
            for control in CONTROL_PLAN
        ]
        if controls["controls"] != expected_control_states:
            fail(f"dependency_risk_controls_invalid:{subject_id}")
        expected_plan_digest = canonical_digest(
            {
                "subject": item["sourceSubject"],
                "controls": expected_control_states,
            }
        )
        if controls["planDigest"] != expected_plan_digest:
            fail(f"dependency_risk_controls_digest_invalid:{subject_id}")
        machine_review = strict_keys(
            item["machineReview"],
            {"state", "reasonCodes", "reviewDigest"},
            f"dependency_risk_machine_review_invalid:{subject_id}",
        )
        expected_state, expected_reasons = expected_machine_review(vulnerabilities)
        review_payload = {
            "subject": item["sourceSubject"],
            "platformSubject": item["platformSubject"],
            "artifacts": artifacts,
            "vulnerabilities": vulnerabilities,
            "licenses": licenses,
            "compensatingControls": controls,
            "collectionAttestationDigest": collection["collectionAttestationDigest"],
        }
        if (
            machine_review["state"] != expected_state
            or machine_review["reasonCodes"] != expected_reasons
            or machine_review["reviewDigest"] != canonical_digest(review_payload)
        ):
            fail(f"dependency_risk_machine_review_invalid:{subject_id}")
        if expected_state == "eligible-for-human-review":
            review_eligible += 1
    if seen != set(expected_subjects):
        fail("dependency_risk_evidence_inventory_invalid")
    if value["claim"] != {
        "allSubjectsCollected": True,
        "vulnerabilityThresholdPassedCount": threshold_passed,
        "eligibleForHumanReviewCount": review_eligible,
        "licenseReviewsComplete": False,
        "exceptionsApproved": False,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
    }:
        fail("dependency_risk_evidence_claim_invalid")
    return canonical_digest(value)


def exception_candidate_digest(intake: dict[str, Any], subject: dict[str, Any]) -> str:
    request = subject["request"]
    return canonical_digest(
        {
            "schemaVersion": intake["schemaVersion"],
            "profileId": intake["profileId"],
            "targetClass": intake["targetClass"],
            "executionMode": intake["executionMode"],
            "intakeId": intake["intakeId"],
            "bindings": intake["bindings"],
            "subject": {
                "id": subject["id"],
                "sourceSubject": subject["sourceSubject"],
                "platformSubject": subject["platformSubject"],
                "evidence": subject["evidence"],
            },
            "request": {
                "exceptionId": request["exceptionId"],
                "requestedAt": request["requestedAt"],
                "requestorIdentityDigest": request["requestorIdentityDigest"],
            },
        }
    )


def exception_approval_digest(
    candidate_digest: str, approvals: list[dict[str, Any]]
) -> str:
    return canonical_digest(
        {
            "candidateDigest": candidate_digest,
            "approvals": sorted(approvals, key=lambda approval: approval["role"]),
        }
    )


def expected_intake_summary(subjects: list[dict[str, Any]]) -> tuple[dict, dict]:
    evidence_digests = {
        subject["evidence"]["riskEvidenceDigest"]
        for subject in subjects
        if subject["evidence"]["riskEvidenceDigest"] is not None
    }
    review_ready = sum(
        subject["request"]["status"] in {"review-pending", "approved"}
        for subject in subjects
    )
    approved = sum(subject["request"]["status"] == "approved" for subject in subjects)
    claim = {
        "riskEvidenceBundles": len(evidence_digests),
        "reviewReadySubjects": review_ready,
        "approvedExceptions": approved,
        "allExceptionsApproved": approved == len(UNSIGNED_SUBJECTS),
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "applied": False,
        "campaignEvidence": False,
    }
    reasons: list[str] = []
    if review_ready != len(UNSIGNED_SUBJECTS):
        reasons.extend(
            [
                "RISK_EVIDENCE_BUNDLES_MISSING",
                "LICENSE_REVIEWS_MISSING",
                "RISK_REVIEWS_MISSING",
                "COMPENSATING_CONTROL_PLANS_MISSING",
            ]
        )
    if approved != len(UNSIGNED_SUBJECTS):
        reasons.append("TWO_PERSON_APPROVALS_MISSING")
    reasons.extend(
        [
            "SIGNED_RUNNER_REVERIFICATION_REQUIRED",
            "SOURCE_ADMISSION_INCOMPLETE",
            "MIRRORING_NOT_AUTHORIZED",
        ]
    )
    admission = {
        "status": "blocked",
        "requiredExceptionCount": len(UNSIGNED_SUBJECTS),
        "reviewReadyCount": review_ready,
        "approvedExceptionCount": approved,
        "reasonCodes": reasons,
    }
    return claim, admission


def validate_exception_intake(
    value: dict[str, Any],
    admission: dict[str, Any],
    risk_evidence: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
    require_template_digest: bool = False,
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "profileId",
            "targetClass",
            "executionMode",
            "intakeId",
            "bindings",
            "claim",
            "subjects",
            "admission",
        },
        "dependency_exception_intake_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != "orchestra-ocp-4.20-amd64-v1"
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or not isinstance(value["intakeId"], str)
        or not value["intakeId"].startswith(
            "orchestra-dependency-signature-exceptions-"
        )
        or value["bindings"] != expected_bindings()
    ):
        fail("dependency_exception_intake_identity_invalid")
    expected_subjects = unsigned_subjects(admission)
    items = value["subjects"]
    if not isinstance(items, list) or len(items) != len(expected_subjects):
        fail("dependency_exception_inventory_invalid")
    evidence_by_id: dict[str, dict[str, Any]] = {}
    evidence_digest: str | None = None
    collector_identity: str | None = None
    evidence_completed_at: datetime | None = None
    if risk_evidence is not None:
        source_verification = load_json(SOURCE_VERIFICATION)
        evidence_digest = validate_risk_evidence(
            risk_evidence, admission, source_verification
        )
        evidence_by_id = {item["id"]: item for item in risk_evidence["subjects"]}
        collector_identity = risk_evidence["collection"]["actorIdentityDigest"]
        evidence_completed_at = parse_utc(
            risk_evidence["collection"]["completedAt"],
            "dependency_exception_evidence_time_invalid",
        )
    assessed_at = now or datetime.now(timezone.utc)
    seen: set[str] = set()
    for item in items:
        strict_keys(
            item,
            {
                "id",
                "sourceSubject",
                "platformSubject",
                "evidence",
                "request",
                "approvals",
                "decision",
                "sourceAdmissionState",
                "reasonCodes",
            },
            "dependency_exception_subject_shape_invalid",
        )
        subject_id = item["id"]
        if subject_id not in expected_subjects or subject_id in seen:
            fail("dependency_exception_inventory_invalid")
        seen.add(subject_id)
        if (
            item["sourceSubject"] != expected_subjects[subject_id]["sourceSubject"]
            or item["platformSubject"]
            != expected_subjects[subject_id]["platformSubject"]
        ):
            fail(f"dependency_exception_subject_binding_invalid:{subject_id}")
        evidence = strict_keys(
            item["evidence"],
            EVIDENCE_KEYS,
            f"dependency_exception_evidence_invalid:{subject_id}",
        )
        request = strict_keys(
            item["request"],
            {
                "status",
                "exceptionId",
                "requestedAt",
                "requestorIdentityDigest",
                "candidateDigest",
            },
            f"dependency_exception_request_invalid:{subject_id}",
        )
        decision = strict_keys(
            item["decision"],
            {"status", "approvedAt", "expiresAt", "approvalDigest"},
            f"dependency_exception_decision_invalid:{subject_id}",
        )
        approvals = item["approvals"]
        if not isinstance(approvals, list):
            fail(f"dependency_exception_approvals_invalid:{subject_id}")
        if request["status"] == "evidence-required":
            if (
                evidence != EMPTY_EVIDENCE
                or request != EMPTY_REQUEST
                or approvals
                or decision != EMPTY_DECISION
                or item["sourceAdmissionState"] != "blocked"
                or item["reasonCodes"] != EMPTY_REASON_CODES
            ):
                fail(f"dependency_exception_empty_state_invalid:{subject_id}")
            continue
        if request["status"] not in {"review-pending", "approved"}:
            fail(f"dependency_exception_request_status_invalid:{subject_id}")
        if risk_evidence is None or evidence_digest is None:
            fail(f"dependency_exception_risk_evidence_required:{subject_id}")
        risk_subject = evidence_by_id[subject_id]
        expected_evidence = {
            "riskEvidenceDigest": evidence_digest,
            "collectionAttestationDigest": risk_evidence["collection"][
                "collectionAttestationDigest"
            ],
            "runnerImageDigest": risk_evidence["collection"]["runnerImageDigest"],
            "runnerProvenanceBundleDigest": risk_evidence["collection"][
                "runnerProvenanceBundleDigest"
            ],
            "sbomDigest": risk_subject["artifacts"]["sbom"]["digest"],
            "vulnerabilityReportDigest": risk_subject["artifacts"]["vulnerability"][
                "digest"
            ],
            "licenseInventoryDigest": risk_subject["licenses"]["inventoryDigest"],
            "machineReviewDigest": risk_subject["machineReview"]["reviewDigest"],
            "licenseReviewDigest": evidence["licenseReviewDigest"],
            "riskReviewDigest": evidence["riskReviewDigest"],
            "compensatingControlsDigest": risk_subject["compensatingControls"][
                "planDigest"
            ],
        }
        if evidence != expected_evidence:
            fail(f"dependency_exception_evidence_binding_invalid:{subject_id}")
        for field in ("licenseReviewDigest", "riskReviewDigest"):
            require_digest(
                evidence[field],
                f"dependency_exception_review_digest_invalid:{subject_id}:{field}",
            )
        if risk_subject["machineReview"]["state"] != "eligible-for-human-review":
            fail(f"dependency_exception_machine_review_blocked:{subject_id}")
        if (
            evidence_completed_at is None
            or assessed_at > evidence_completed_at + timedelta(hours=72)
        ):
            fail(f"dependency_exception_risk_evidence_stale:{subject_id}")
        if not isinstance(request["exceptionId"], str) or not EXCEPTION_ID.fullmatch(
            request["exceptionId"]
        ):
            fail(f"dependency_exception_id_invalid:{subject_id}")
        requested_at = parse_utc(
            request["requestedAt"],
            f"dependency_exception_request_time_invalid:{subject_id}",
        )
        requestor = require_digest(
            request["requestorIdentityDigest"],
            f"dependency_exception_requestor_invalid:{subject_id}",
        )
        if requested_at < evidence_completed_at or requested_at > assessed_at:
            fail(f"dependency_exception_request_time_invalid:{subject_id}")
        expected_candidate_digest = exception_candidate_digest(value, item)
        if request["candidateDigest"] != expected_candidate_digest:
            fail(f"dependency_exception_candidate_digest_invalid:{subject_id}")
        reviewer_identities: set[str] = set()
        reviewer_roles: set[str] = set()
        approval_times: list[datetime] = []
        for approval in approvals:
            strict_keys(
                approval,
                {
                    "role",
                    "reviewerIdentityDigest",
                    "decision",
                    "decidedAt",
                    "candidateDigest",
                    "signatureBundleDigest",
                },
                f"dependency_exception_approval_shape_invalid:{subject_id}",
            )
            role = approval["role"]
            reviewer = require_digest(
                approval["reviewerIdentityDigest"],
                f"dependency_exception_reviewer_invalid:{subject_id}",
            )
            if (
                role not in REVIEWER_ROLES
                or role in reviewer_roles
                or reviewer in reviewer_identities
                or reviewer == requestor
                or reviewer == collector_identity
                or approval["decision"] != "approve"
                or approval["candidateDigest"] != expected_candidate_digest
            ):
                fail(f"dependency_exception_approval_independence_invalid:{subject_id}")
            require_digest(
                approval["signatureBundleDigest"],
                f"dependency_exception_approval_signature_invalid:{subject_id}",
            )
            decided_at = parse_utc(
                approval["decidedAt"],
                f"dependency_exception_approval_time_invalid:{subject_id}",
            )
            if decided_at < requested_at or decided_at > assessed_at:
                fail(f"dependency_exception_approval_time_invalid:{subject_id}")
            reviewer_roles.add(role)
            reviewer_identities.add(reviewer)
            approval_times.append(decided_at)
        if request["status"] == "review-pending":
            if (
                len(approvals) >= 2
                or decision != EMPTY_DECISION
                or item["sourceAdmissionState"] != "blocked"
                or item["reasonCodes"]
                != [
                    "INDEPENDENT_REVIEWS_MISSING",
                    "SIGNED_RUNNER_REVERIFICATION_REQUIRED",
                ]
            ):
                fail(f"dependency_exception_pending_state_invalid:{subject_id}")
            continue
        if (
            len(approvals) != 2
            or reviewer_roles != set(REVIEWER_ROLES)
            or decision["status"] != "approved"
        ):
            fail(f"dependency_exception_approved_state_invalid:{subject_id}")
        approved_at = parse_utc(
            decision["approvedAt"],
            f"dependency_exception_decision_time_invalid:{subject_id}",
        )
        expires_at = parse_utc(
            decision["expiresAt"],
            f"dependency_exception_decision_time_invalid:{subject_id}",
        )
        if (
            approved_at < max(approval_times)
            or approved_at > assessed_at
            or expires_at <= approved_at
            or expires_at - approved_at > timedelta(hours=720)
            or assessed_at >= expires_at
            or decision["approvalDigest"]
            != exception_approval_digest(expected_candidate_digest, approvals)
            or item["sourceAdmissionState"]
            != "exception-approved-pending-source-aggregate"
            or item["reasonCodes"]
            != [
                "SIGNED_RUNNER_REVERIFICATION_REQUIRED",
                "SOURCE_ADMISSION_AGGREGATION_REQUIRED",
            ]
        ):
            fail(f"dependency_exception_approved_state_invalid:{subject_id}")
    if seen != set(expected_subjects):
        fail("dependency_exception_inventory_invalid")
    expected_claim, expected_admission = expected_intake_summary(items)
    if value["claim"] != expected_claim:
        fail("dependency_exception_claim_invalid")
    if value["admission"] != expected_admission:
        fail("dependency_exception_admission_invalid")
    digest = canonical_digest(value)
    if require_template_digest and digest != EXPECTED_EXCEPTION_TEMPLATE_DIGEST:
        fail(f"dependency_exception_template_digest_changed:{digest}")
    return digest


def load_contract_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return load_json(ADMISSION), load_json(SOURCE_VERIFICATION), load_json(RISK_POLICY)
