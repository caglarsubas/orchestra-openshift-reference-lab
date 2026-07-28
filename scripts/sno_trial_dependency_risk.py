#!/usr/bin/env python3
"""Validate SNO-only unsigned dependency risk evidence and exceptions."""

from __future__ import annotations

import argparse
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import DIGEST, ROOT, canonical_digest, load_json
    from scripts.validate_sno_trial_dependency_artifacts import (
        ADMISSION_PATH,
        ARTIFACT_SET_PATH,
        BOM_PATH,
        validate_artifact_set,
    )
except ModuleNotFoundError:
    from validate_release_set import validate_release_set
    from validate_repository import DIGEST, ROOT, canonical_digest, load_json
    from validate_sno_trial_dependency_artifacts import (
        ADMISSION_PATH,
        ARTIFACT_SET_PATH,
        BOM_PATH,
        validate_artifact_set,
    )


POLICY_PATH = ROOT / "config" / "sno-trial-dependency-risk-policy.lock.json"
EXCEPTION_TEMPLATE_PATH = (
    ROOT / "config" / "sno-trial-dependency-signature-exceptions.example.json"
)
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
COLLECTOR_SCRIPT_PATH = (
    ROOT / "scripts" / "collect_sno_trial_dependency_risk_evidence.sh"
)
EXPECTED_POLICY_DIGEST = (
    "sha256:e3a5e149a34d36ad4d3f187ffde43a299b5da4bfbf17236d52b10ca6cdaa69aa"
)
EXPECTED_EXCEPTION_TEMPLATE_DIGEST = (
    "sha256:9a6273de24871d092347d641f5687edcfa2f75680fe2d376a932df03b8fa9e98"
)
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
TARGET_CLASS = "engineering-trial"
EXECUTION_MODE = "live"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
BLOCKING_SEVERITIES = ("CRITICAL", "HIGH", "UNKNOWN")
REVIEWER_ROLES = ("security-reviewer", "service-owner")
EVIDENCE_ID = re.compile(
    r"^orchestra-sno-trial-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$"
)
EXCEPTION_ID = re.compile(
    r"^orchestra-sno-trial-dependency-signature-exception-[a-z0-9][a-z0-9.-]+$"
)
CUSTODY_VERIFICATION_ID = re.compile(
    r"^orchestra-sno-trial-dependency-risk-custody-verification-"
    r"[a-z0-9][a-z0-9.-]+$"
)
CONTROL_PLAN = [
    {"id": "exact-index-and-platform-digests", "requiredBefore": "review"},
    {
        "id": "signed-runner-vulnerability-and-license-evidence",
        "requiredBefore": "review",
    },
    {
        "id": "immutable-model-revision-digest-size-and-license",
        "requiredBefore": "review",
    },
    {"id": "private-mirror-by-digest", "requiredBefore": "activation"},
    {"id": "lab-kms-signature", "requiredBefore": "activation"},
    {
        "id": "restricted-runtime-default-deny-and-allowlisted-egress",
        "requiredBefore": "activation",
    },
    {
        "id": "continuous-rescan-and-expiry-enforcement",
        "requiredBefore": "activation",
    },
]
EVIDENCE_KEYS = {
    "riskEvidenceDigest",
    "collectionStatementDigest",
    "collectionSignatureBundleDigest",
    "runnerImageDigest",
    "runnerToolchainDigest",
    "signatureProbeDigest",
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
EMPTY_CUSTODY = {
    "status": "verification-required",
    "verificationId": None,
    "evidenceId": None,
    "reportDigest": None,
    "signatureBundleDigest": None,
    "verificationSigningPublicKeyDigest": None,
    "riskEvidenceDigest": None,
    "riskEvidenceCanonicalDigest": None,
    "verifierIdentityDigest": None,
    "verifiedAt": None,
}
EMPTY_REASONS = [
    "SIGNED_RUNNER_RISK_EVIDENCE_MISSING",
    "INDEPENDENT_CUSTODY_VERIFICATION_MISSING",
    "LICENSE_REVIEW_MISSING",
    "RISK_REVIEW_MISSING",
    "INDEPENDENT_REVIEWS_MISSING",
]
NON_AUTHORIZING_CLAIMS = {
    "sourceAdmissionAuthorized": False,
    "mirrorAuthorization": False,
    "activationAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEvidence": False,
    "referenceProfileVerified": False,
}


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


def load_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    artifacts = load_json(ARTIFACT_SET_PATH)
    validate_artifact_set(
        artifacts,
        load_json(BOM_PATH),
        load_json(ADMISSION_PATH),
    )
    release_set = load_json(RELEASE_SET_PATH)
    validate_release_set(release_set)
    return artifacts, release_set, load_json(POLICY_PATH)


def expected_bindings(
    artifacts: dict[str, Any], release_set: dict[str, Any]
) -> dict[str, str]:
    return {
        "artifactSetDigest": artifacts["artifactSetDigest"],
        "releaseSetDigest": validate_release_set(release_set),
    }


def image_base(reference: str) -> str:
    separator = reference.rfind(":")
    if separator <= reference.rfind("/"):
        fail("sno_dependency_risk_image_tag_missing")
    return reference[:separator]


def expected_subjects(artifacts: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for container in artifacts["containers"]:
        base = image_base(container["sourceReference"])
        result[container["id"]] = {
            "indexSubject": f"{base}@{container['indexDigest']}",
            "platformSubject": container["resolvedReference"],
            "sourceRevision": container["sourceRevision"],
            "declaredLicense": container["license"],
        }
    if set(result) != {"model-backend-image", "valkey-image"}:
        fail("sno_dependency_risk_subject_inventory_invalid")
    return result


def validate_policy(
    value: dict[str, Any],
    artifacts: dict[str, Any],
    release_set: dict[str, Any],
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "scope",
            "collectionPolicy",
            "vulnerabilityPolicy",
            "licensePolicy",
            "modelArtifactPolicy",
            "exceptionPolicy",
            "compensatingControls",
            "claims",
        },
        "sno_dependency_risk_policy_keys_invalid",
    )
    runner = release_set["certificationRunner"]
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.openshift.sno-trial-dependency-risk-policy.v1"
        or value["policyId"] != "orchestra-sno-trial-unsigned-dependency-risk-v1"
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != TARGET_CLASS
        or value["executionMode"] != EXECUTION_MODE
        or value["bindings"] != expected_bindings(artifacts, release_set)
    ):
        fail("sno_dependency_risk_policy_identity_invalid")
    if value["scope"] != {
        "platform": "linux/amd64",
        "signatureObservation": "no-cosign-signature-at-locked-index",
        "containerIds": ["model-backend-image", "valkey-image"],
        "modelArtifactIds": ["orchestra-reference-cpu-model"],
    }:
        fail("sno_dependency_risk_policy_scope_invalid")
    if value["collectionPolicy"] != {
        "executionClass": "signed-certification-runner",
        "runnerImage": runner["image"],
        "runnerToolchainDigest": runner["toolchainDigest"],
        "collectorScriptDigest": blob_digest(COLLECTOR_SCRIPT_PATH.read_bytes()),
        "maximumCollectionDurationHours": 6,
        "maximumEvidenceAgeHours": 72,
        "rawArtifactsRestricted": True,
        "collectionStatementSignatureRequired": True,
        "externalScannerConfigAllowed": False,
        "databaseUpdatesDuringScanAllowed": False,
        "requiredToolVersions": {
            "cosign": "3.1.1",
            "syft": "1.48.0",
            "trivy": "0.72.0",
        },
    }:
        fail("sno_dependency_risk_policy_collection_invalid")
    if value["vulnerabilityPolicy"] != {
        "blockingSeverities": list(BLOCKING_SEVERITIES),
        "recognizedSeverities": list(SEVERITIES),
        "ignoreFileAllowed": False,
        "ignoreUnfixedAllowed": False,
        "severityFilterAllowed": False,
        "databaseDigestsRequired": True,
    }:
        fail("sno_dependency_risk_policy_vulnerability_invalid")
    if value["licensePolicy"] != {
        "format": "SPDX-2.3",
        "packageInventoryRequired": True,
        "humanReviewRequired": True,
        "automatedApprovalAllowed": False,
        "unknownLicenseRequiresExplicitDecision": True,
    }:
        fail("sno_dependency_risk_policy_license_invalid")
    if value["modelArtifactPolicy"] != {
        "immutableRevisionRequired": True,
        "sha256VerificationRequired": True,
        "contentLengthVerificationRequired": True,
        "licenseReviewRequired": True,
        "runtimeDownloadAllowed": False,
        "maximumAllowedBytes": 4294967296,
    }:
        fail("sno_dependency_risk_policy_model_invalid")
    if value["exceptionPolicy"] != {
        "maximumLifetimeHours": 720,
        "minimumReviewers": 2,
        "requiredReviewerRoles": list(REVIEWER_ROLES),
        "distinctReviewerIdentities": True,
        "requestorMayReview": False,
        "collectorMayReview": False,
        "approvalBindsCandidateDigest": True,
        "expiryBlocksArtifactSetReissue": True,
    }:
        fail("sno_dependency_risk_policy_exception_invalid")
    if value["compensatingControls"] != CONTROL_PLAN:
        fail("sno_dependency_risk_policy_controls_invalid")
    if value["claims"] != {
        "riskEvidenceBundles": 0,
        "exceptionsApproved": 0,
        **NON_AUTHORIZING_CLAIMS,
    }:
        fail("sno_dependency_risk_policy_claims_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_POLICY_DIGEST:
        fail(f"sno_dependency_risk_policy_digest_changed:{digest}")
    return digest


def validate_collection(
    value: Any,
    release_set: dict[str, Any],
) -> tuple[dict[str, Any], datetime]:
    collection = strict_keys(
        value,
        {
            "executionClass",
            "runnerRelease",
            "runnerRevision",
            "runnerImage",
            "runnerImageDigest",
            "runnerToolchainDigest",
            "actorIdentityDigest",
            "startedAt",
            "completedAt",
            "collectionStatementDigest",
            "collectionSignatureBundleDigest",
            "vulnerabilityScanner",
            "sbomScanner",
            "signatureProbe",
            "rawArtifactsRestricted",
        },
        "sno_dependency_risk_collection_shape_invalid",
    )
    runner = release_set["certificationRunner"]
    if (
        collection["executionClass"] != "signed-certification-runner"
        or collection["runnerRelease"] != runner["release"]
        or collection["runnerRevision"] != runner["source"]["revision"]
        or collection["runnerImage"] != runner["image"]
        or collection["runnerImageDigest"] != runner["image"].rsplit("@", 1)[1]
        or collection["runnerToolchainDigest"] != runner["toolchainDigest"]
        or collection["rawArtifactsRestricted"] is not True
    ):
        fail("sno_dependency_risk_collection_runner_invalid")
    for field in (
        "runnerImageDigest",
        "runnerToolchainDigest",
        "actorIdentityDigest",
        "collectionStatementDigest",
        "collectionSignatureBundleDigest",
    ):
        require_digest(
            collection[field], f"sno_dependency_risk_collection_digest_invalid:{field}"
        )
    started = parse_utc(
        collection["startedAt"], "sno_dependency_risk_collection_time_invalid"
    )
    completed = parse_utc(
        collection["completedAt"], "sno_dependency_risk_collection_time_invalid"
    )
    if completed < started or completed - started > timedelta(hours=6):
        fail("sno_dependency_risk_collection_time_invalid")
    vulnerability = strict_keys(
        collection["vulnerabilityScanner"],
        {"name", "version", "databaseDigest", "javaDatabaseDigest"},
        "sno_dependency_risk_vulnerability_scanner_invalid",
    )
    if vulnerability["name"] != "trivy" or vulnerability["version"] != "0.72.0":
        fail("sno_dependency_risk_vulnerability_scanner_invalid")
    require_digest(
        vulnerability["databaseDigest"],
        "sno_dependency_risk_vulnerability_database_invalid",
    )
    require_digest(
        vulnerability["javaDatabaseDigest"],
        "sno_dependency_risk_vulnerability_java_database_invalid",
    )
    if collection["sbomScanner"] != {"name": "syft", "version": "1.48.0"}:
        fail("sno_dependency_risk_sbom_scanner_invalid")
    signature_probe = strict_keys(
        collection["signatureProbe"],
        {"name", "version", "trustedRootDigest", "offlineVerification"},
        "sno_dependency_risk_signature_probe_invalid",
    )
    if (
        signature_probe["name"] != "cosign"
        or signature_probe["version"] != "3.1.1"
        or signature_probe["offlineVerification"] is not False
    ):
        fail("sno_dependency_risk_signature_probe_invalid")
    require_digest(
        signature_probe["trustedRootDigest"],
        "sno_dependency_risk_signature_trust_root_invalid",
    )
    return collection, completed


def expected_machine_review(vulnerabilities: dict[str, Any]) -> tuple[str, list[str]]:
    blocking = [
        severity
        for severity in BLOCKING_SEVERITIES
        if vulnerabilities["bySeverity"][severity] > 0
    ]
    if blocking:
        return "blocked", [f"{severity}_FINDINGS_PRESENT" for severity in blocking]
    return "eligible-for-human-review", [
        "VULNERABILITY_THRESHOLD_PASSED",
        "LICENSE_REVIEW_REQUIRED",
        "UNSIGNED_UPSTREAM_EXCEPTION_REQUIRED",
    ]


def validate_vulnerabilities(value: Any, subject_id: str) -> dict[str, Any]:
    result = strict_keys(
        value,
        {
            "total",
            "bySeverity",
            "fixAvailableBySeverity",
            "scanTargetCount",
            "thresholdState",
        },
        f"sno_dependency_risk_vulnerability_summary_invalid:{subject_id}",
    )
    counts = strict_keys(
        result["bySeverity"],
        set(SEVERITIES),
        f"sno_dependency_risk_vulnerability_counts_invalid:{subject_id}",
    )
    fixed = strict_keys(
        result["fixAvailableBySeverity"],
        set(SEVERITIES),
        f"sno_dependency_risk_vulnerability_fix_counts_invalid:{subject_id}",
    )
    for severity in SEVERITIES:
        if (
            not isinstance(counts[severity], int)
            or isinstance(counts[severity], bool)
            or counts[severity] < 0
            or not isinstance(fixed[severity], int)
            or isinstance(fixed[severity], bool)
            or fixed[severity] < 0
            or fixed[severity] > counts[severity]
        ):
            fail(f"sno_dependency_risk_vulnerability_counts_invalid:{subject_id}")
    threshold = (
        "passed"
        if all(counts[severity] == 0 for severity in BLOCKING_SEVERITIES)
        else "blocked"
    )
    if (
        result["total"] != sum(counts.values())
        or not isinstance(result["scanTargetCount"], int)
        or isinstance(result["scanTargetCount"], bool)
        or result["scanTargetCount"] < 1
        or result["thresholdState"] != threshold
    ):
        fail(f"sno_dependency_risk_vulnerability_summary_invalid:{subject_id}")
    return result


def validate_licenses(value: Any, subject_id: str) -> dict[str, Any]:
    result = strict_keys(
        value,
        {
            "packageCount",
            "expressions",
            "noAssertionCount",
            "noneCount",
            "inventoryDigest",
            "humanReviewState",
        },
        f"sno_dependency_risk_license_summary_invalid:{subject_id}",
    )
    expressions = result["expressions"]
    if (
        not isinstance(result["packageCount"], int)
        or isinstance(result["packageCount"], bool)
        or result["packageCount"] < 1
        or not isinstance(expressions, list)
        or expressions != sorted(set(expressions))
        or any(not isinstance(item, str) or not item for item in expressions)
        or not isinstance(result["noAssertionCount"], int)
        or isinstance(result["noAssertionCount"], bool)
        or result["noAssertionCount"] < 0
        or not isinstance(result["noneCount"], int)
        or isinstance(result["noneCount"], bool)
        or result["noneCount"] < 0
        or result["humanReviewState"] != "required"
    ):
        fail(f"sno_dependency_risk_license_summary_invalid:{subject_id}")
    require_digest(
        result["inventoryDigest"],
        f"sno_dependency_risk_license_inventory_invalid:{subject_id}",
    )
    return result


def validate_model_verification(
    value: Any,
    artifacts: dict[str, Any],
    collector_identity: str,
) -> tuple[dict[str, Any], bool]:
    result = strict_keys(
        value,
        {
            "id",
            "immutableUrl",
            "revision",
            "expectedDigest",
            "observedDigest",
            "expectedSizeBytes",
            "observedSizeBytes",
            "declaredLicense",
            "bytesVerified",
            "contentLengthVerified",
            "verificationDigest",
            "licenseReview",
        },
        "sno_dependency_risk_model_verification_invalid",
    )
    model = artifacts["models"][0]
    if (
        result["id"] != model["id"]
        or result["immutableUrl"] != model["immutableUrl"]
        or result["revision"] != model["revision"]
        or result["expectedDigest"] != model["digest"]
        or result["observedDigest"] != model["digest"]
        or result["expectedSizeBytes"] != model["sizeBytes"]
        or result["observedSizeBytes"] != model["sizeBytes"]
        or result["declaredLicense"] != model["license"]
        or result["bytesVerified"] is not True
        or result["contentLengthVerified"] is not True
    ):
        fail("sno_dependency_risk_model_verification_invalid")
    review = strict_keys(
        result["licenseReview"],
        {"state", "reviewerIdentityDigest", "reviewDigest"},
        "sno_dependency_risk_model_license_review_invalid",
    )
    if review["state"] == "required":
        if review != {
            "state": "required",
            "reviewerIdentityDigest": None,
            "reviewDigest": None,
        }:
            fail("sno_dependency_risk_model_license_review_invalid")
        review_complete = False
    elif review["state"] == "complete":
        reviewer = require_digest(
            review["reviewerIdentityDigest"],
            "sno_dependency_risk_model_license_reviewer_invalid",
        )
        require_digest(
            review["reviewDigest"],
            "sno_dependency_risk_model_license_review_digest_invalid",
        )
        if reviewer == collector_identity:
            fail("sno_dependency_risk_model_license_review_independence_invalid")
        review_complete = True
    else:
        fail("sno_dependency_risk_model_license_review_invalid")
    expected_verification = canonical_digest(
        {key: result[key] for key in result if key != "verificationDigest"}
    )
    if result["verificationDigest"] != expected_verification:
        fail("sno_dependency_risk_model_verification_digest_invalid")
    return result, review_complete


def validate_risk_evidence(
    value: dict[str, Any],
    artifacts: dict[str, Any],
    release_set: dict[str, Any],
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "evidenceId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "collection",
            "subjects",
            "modelArtifact",
            "claims",
        },
        "sno_dependency_risk_evidence_keys_invalid",
    )
    expected_evidence_bindings = {
        **expected_bindings(artifacts, release_set),
        "riskPolicyDigest": EXPECTED_POLICY_DIGEST,
    }
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.openshift.sno-trial-dependency-risk-evidence.v1"
        or not isinstance(value["evidenceId"], str)
        or not EVIDENCE_ID.fullmatch(value["evidenceId"])
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != TARGET_CLASS
        or value["executionMode"] != EXECUTION_MODE
        or value["bindings"] != expected_evidence_bindings
    ):
        fail("sno_dependency_risk_evidence_identity_invalid")
    collection, _ = validate_collection(value["collection"], release_set)
    expected = expected_subjects(artifacts)
    subjects = value["subjects"]
    if not isinstance(subjects, list) or len(subjects) != len(expected):
        fail("sno_dependency_risk_evidence_inventory_invalid")
    seen: set[str] = set()
    threshold_passed = 0
    review_eligible = 0
    for item in subjects:
        strict_keys(
            item,
            {
                "id",
                "indexSubject",
                "platformSubject",
                "sourceRevision",
                "declaredLicense",
                "signatureObservation",
                "artifacts",
                "vulnerabilities",
                "licenses",
                "compensatingControls",
                "machineReview",
            },
            "sno_dependency_risk_subject_shape_invalid",
        )
        subject_id = item["id"]
        if subject_id not in expected or subject_id in seen:
            fail("sno_dependency_risk_evidence_inventory_invalid")
        seen.add(subject_id)
        if any(item[field] != expected[subject_id][field] for field in expected[subject_id]):
            fail(f"sno_dependency_risk_subject_binding_invalid:{subject_id}")
        signature = strict_keys(
            item["signatureObservation"],
            {"status", "indexSubject", "probeDigest"},
            f"sno_dependency_risk_signature_observation_invalid:{subject_id}",
        )
        if (
            signature["status"] != "no-signature-found"
            or signature["indexSubject"] != item["indexSubject"]
        ):
            fail(f"sno_dependency_risk_signature_observation_invalid:{subject_id}")
        require_digest(
            signature["probeDigest"],
            f"sno_dependency_risk_signature_probe_digest_invalid:{subject_id}",
        )
        raw_artifacts = strict_keys(
            item["artifacts"],
            {"vulnerability", "sbom"},
            f"sno_dependency_risk_artifacts_invalid:{subject_id}",
        )
        for artifact_kind in ("vulnerability", "sbom"):
            artifact = strict_keys(
                raw_artifacts[artifact_kind],
                {"fileName", "digest"},
                f"sno_dependency_risk_artifact_invalid:{subject_id}:{artifact_kind}",
            )
            if (
                not isinstance(artifact["fileName"], str)
                or Path(artifact["fileName"]).name != artifact["fileName"]
            ):
                fail(
                    f"sno_dependency_risk_artifact_name_invalid:{subject_id}:{artifact_kind}"
                )
            require_digest(
                artifact["digest"],
                f"sno_dependency_risk_artifact_digest_invalid:{subject_id}:{artifact_kind}",
            )
        vulnerabilities = validate_vulnerabilities(item["vulnerabilities"], subject_id)
        if vulnerabilities["thresholdState"] == "passed":
            threshold_passed += 1
        licenses = validate_licenses(item["licenses"], subject_id)
        controls = strict_keys(
            item["compensatingControls"],
            {"planDigest", "controls"},
            f"sno_dependency_risk_controls_invalid:{subject_id}",
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
            fail(f"sno_dependency_risk_controls_invalid:{subject_id}")
        expected_control_digest = canonical_digest(
            {"subject": item["indexSubject"], "controls": expected_control_states}
        )
        if controls["planDigest"] != expected_control_digest:
            fail(f"sno_dependency_risk_controls_digest_invalid:{subject_id}")
        machine_review = strict_keys(
            item["machineReview"],
            {"state", "reasonCodes", "reviewDigest"},
            f"sno_dependency_risk_machine_review_invalid:{subject_id}",
        )
        expected_state, expected_reasons = expected_machine_review(vulnerabilities)
        review_payload = {
            "indexSubject": item["indexSubject"],
            "platformSubject": item["platformSubject"],
            "signatureObservation": signature,
            "artifacts": raw_artifacts,
            "vulnerabilities": vulnerabilities,
            "licenses": licenses,
            "compensatingControls": controls,
            "collectionStatementDigest": collection["collectionStatementDigest"],
        }
        if (
            machine_review["state"] != expected_state
            or machine_review["reasonCodes"] != expected_reasons
            or machine_review["reviewDigest"] != canonical_digest(review_payload)
        ):
            fail(f"sno_dependency_risk_machine_review_invalid:{subject_id}")
        if expected_state == "eligible-for-human-review":
            review_eligible += 1
    if seen != set(expected):
        fail("sno_dependency_risk_evidence_inventory_invalid")
    _, model_review_complete = validate_model_verification(
        value["modelArtifact"], artifacts, collection["actorIdentityDigest"]
    )
    if value["claims"] != {
        "allSubjectsCollected": True,
        "vulnerabilityThresholdPassedCount": threshold_passed,
        "eligibleForHumanReviewCount": review_eligible,
        "modelIntegrityVerified": True,
        "modelLicenseReviewComplete": model_review_complete,
        "containerLicenseReviewsComplete": False,
        "exceptionsApproved": False,
        **NON_AUTHORIZING_CLAIMS,
    }:
        fail("sno_dependency_risk_evidence_claims_invalid")
    return canonical_digest(value)


def exception_candidate_digest(
    intake: dict[str, Any], subject: dict[str, Any]
) -> str:
    request = subject["request"]
    return canonical_digest(
        {
            "schemaVersion": intake["schemaVersion"],
            "kind": intake["kind"],
            "intakeId": intake["intakeId"],
            "profileId": intake["profileId"],
            "targetClass": intake["targetClass"],
            "executionMode": intake["executionMode"],
            "bindings": intake["bindings"],
            "custody": intake["custody"],
            "subject": {
                "id": subject["id"],
                "indexSubject": subject["indexSubject"],
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
            "approvals": sorted(approvals, key=lambda item: item["role"]),
        }
    )


def expected_intake_summary(
    subjects: list[dict[str, Any]],
    risk_evidence: dict[str, Any] | None,
    custody_verified: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence_digests = {
        item["evidence"]["riskEvidenceDigest"]
        for item in subjects
        if item["evidence"]["riskEvidenceDigest"] is not None
    }
    review_ready = sum(
        item["request"]["status"] in {"review-pending", "approved"}
        for item in subjects
    )
    approved = sum(item["request"]["status"] == "approved" for item in subjects)
    model_review_complete = bool(
        risk_evidence
        and risk_evidence["claims"]["modelLicenseReviewComplete"] is True
    )
    claims = {
        "riskEvidenceBundles": len(evidence_digests),
        "reviewReadySubjects": review_ready,
        "approvedExceptions": approved,
        "allExceptionsApproved": approved == 2,
        "custodyVerified": custody_verified,
        **NON_AUTHORIZING_CLAIMS,
    }
    reasons: list[str] = []
    if not evidence_digests:
        reasons.append("SIGNED_RUNNER_RISK_EVIDENCE_MISSING")
    if not custody_verified:
        reasons.append("INDEPENDENT_CUSTODY_VERIFICATION_MISSING")
    if review_ready != 2:
        reasons.extend(["LICENSE_REVIEWS_MISSING", "RISK_REVIEWS_MISSING"])
    if not model_review_complete:
        reasons.append("MODEL_LICENSE_REVIEW_MISSING")
    if approved != 2:
        reasons.append("TWO_PERSON_APPROVALS_MISSING")
    reasons.extend(
        [
            "ARTIFACT_SET_REISSUE_REQUIRED",
            "MIRRORING_NOT_AUTHORIZED",
            "ACTIVATION_NOT_AUTHORIZED",
        ]
    )
    admission = {
        "status": "blocked",
        "requiredExceptionCount": 2,
        "reviewReadyCount": review_ready,
        "approvedExceptionCount": approved,
        "reasonCodes": reasons,
    }
    return claims, admission


def validate_exception_intake(
    value: dict[str, Any],
    artifacts: dict[str, Any],
    release_set: dict[str, Any],
    risk_evidence: dict[str, Any] | None = None,
    custody_proof: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
    require_template_digest: bool = False,
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "intakeId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "custody",
            "subjects",
            "claims",
            "admission",
        },
        "sno_dependency_exception_intake_keys_invalid",
    )
    expected_exception_bindings = {
        **expected_bindings(artifacts, release_set),
        "riskPolicyDigest": EXPECTED_POLICY_DIGEST,
    }
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.openshift.sno-trial-dependency-signature-exceptions.v1"
        or not isinstance(value["intakeId"], str)
        or not value["intakeId"].startswith(
            "orchestra-sno-trial-dependency-signature-exceptions-"
        )
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != TARGET_CLASS
        or value["executionMode"] != EXECUTION_MODE
        or value["bindings"] != expected_exception_bindings
    ):
        fail("sno_dependency_exception_intake_identity_invalid")
    expected = expected_subjects(artifacts)
    subjects = value["subjects"]
    if not isinstance(subjects, list) or len(subjects) != len(expected):
        fail("sno_dependency_exception_inventory_invalid")
    review_requested = any(
        isinstance(item, dict)
        and isinstance(item.get("request"), dict)
        and item["request"].get("status") != "evidence-required"
        for item in subjects
    )
    if review_requested:
        if custody_proof is None:
            fail("sno_dependency_exception_custody_required")
        strict_keys(
            custody_proof,
            set(EMPTY_CUSTODY),
            "sno_dependency_exception_custody_shape_invalid",
        )
        if value["custody"] != custody_proof:
            fail("sno_dependency_exception_custody_binding_invalid")
    elif custody_proof is not None or value["custody"] != EMPTY_CUSTODY:
        fail("sno_dependency_exception_empty_custody_invalid")
    evidence_by_id: dict[str, dict[str, Any]] = {}
    evidence_digest: str | None = None
    collector_identity: str | None = None
    evidence_completed_at: datetime | None = None
    custody_verified_at: datetime | None = None
    assessed_at = now or datetime.now(timezone.utc)
    if risk_evidence is not None:
        evidence_digest = validate_risk_evidence(
            risk_evidence, artifacts, release_set
        )
        evidence_by_id = {item["id"]: item for item in risk_evidence["subjects"]}
        collector_identity = risk_evidence["collection"]["actorIdentityDigest"]
        evidence_completed_at = parse_utc(
            risk_evidence["collection"]["completedAt"],
            "sno_dependency_exception_evidence_time_invalid",
        )
    if custody_proof is not None:
        if risk_evidence is None or evidence_digest is None:
            fail("sno_dependency_exception_custody_evidence_required")
        if (
            custody_proof.get("status") != "verified"
            or not isinstance(custody_proof.get("verificationId"), str)
            or not CUSTODY_VERIFICATION_ID.fullmatch(
                custody_proof["verificationId"]
            )
            or custody_proof.get("evidenceId") != risk_evidence["evidenceId"]
            or custody_proof.get("riskEvidenceCanonicalDigest")
            != evidence_digest
        ):
            fail("sno_dependency_exception_custody_evidence_binding_invalid")
        for field in (
            "reportDigest",
            "signatureBundleDigest",
            "verificationSigningPublicKeyDigest",
            "riskEvidenceDigest",
            "riskEvidenceCanonicalDigest",
            "verifierIdentityDigest",
        ):
            require_digest(
                custody_proof.get(field),
                f"sno_dependency_exception_custody_digest_invalid:{field}",
            )
        custody_verified_at = parse_utc(
            custody_proof.get("verifiedAt"),
            "sno_dependency_exception_custody_time_invalid",
        )
        if (
            evidence_completed_at is None
            or custody_verified_at < evidence_completed_at
            or custody_verified_at > assessed_at
        ):
            fail("sno_dependency_exception_custody_time_invalid")
    seen: set[str] = set()
    for item in subjects:
        strict_keys(
            item,
            {
                "id",
                "indexSubject",
                "platformSubject",
                "evidence",
                "request",
                "approvals",
                "decision",
                "sourceAdmissionState",
                "reasonCodes",
            },
            "sno_dependency_exception_subject_shape_invalid",
        )
        subject_id = item["id"]
        if subject_id not in expected or subject_id in seen:
            fail("sno_dependency_exception_inventory_invalid")
        seen.add(subject_id)
        if (
            item["indexSubject"] != expected[subject_id]["indexSubject"]
            or item["platformSubject"] != expected[subject_id]["platformSubject"]
        ):
            fail(f"sno_dependency_exception_subject_binding_invalid:{subject_id}")
        evidence = strict_keys(
            item["evidence"],
            EVIDENCE_KEYS,
            f"sno_dependency_exception_evidence_invalid:{subject_id}",
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
            f"sno_dependency_exception_request_invalid:{subject_id}",
        )
        approvals = item["approvals"]
        if not isinstance(approvals, list):
            fail(f"sno_dependency_exception_approvals_invalid:{subject_id}")
        decision = strict_keys(
            item["decision"],
            {"status", "approvedAt", "expiresAt", "approvalDigest"},
            f"sno_dependency_exception_decision_invalid:{subject_id}",
        )
        if request["status"] == "evidence-required":
            if (
                evidence != EMPTY_EVIDENCE
                or request != EMPTY_REQUEST
                or approvals
                or decision != EMPTY_DECISION
                or item["sourceAdmissionState"] != "blocked"
                or item["reasonCodes"] != EMPTY_REASONS
            ):
                fail(f"sno_dependency_exception_empty_state_invalid:{subject_id}")
            continue
        if request["status"] not in {"review-pending", "approved"}:
            fail(f"sno_dependency_exception_request_status_invalid:{subject_id}")
        if risk_evidence is None or evidence_digest is None:
            fail(f"sno_dependency_exception_risk_evidence_required:{subject_id}")
        risk_subject = evidence_by_id[subject_id]
        expected_evidence = {
            "riskEvidenceDigest": evidence_digest,
            "collectionStatementDigest": risk_evidence["collection"][
                "collectionStatementDigest"
            ],
            "collectionSignatureBundleDigest": risk_evidence["collection"][
                "collectionSignatureBundleDigest"
            ],
            "runnerImageDigest": risk_evidence["collection"]["runnerImageDigest"],
            "runnerToolchainDigest": risk_evidence["collection"][
                "runnerToolchainDigest"
            ],
            "signatureProbeDigest": risk_subject["signatureObservation"][
                "probeDigest"
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
            fail(f"sno_dependency_exception_evidence_binding_invalid:{subject_id}")
        for field in ("licenseReviewDigest", "riskReviewDigest"):
            require_digest(
                evidence[field],
                f"sno_dependency_exception_review_digest_invalid:{subject_id}:{field}",
            )
        if risk_subject["machineReview"]["state"] != "eligible-for-human-review":
            fail(f"sno_dependency_exception_machine_review_blocked:{subject_id}")
        if (
            evidence_completed_at is None
            or assessed_at > evidence_completed_at + timedelta(hours=72)
        ):
            fail(f"sno_dependency_exception_risk_evidence_stale:{subject_id}")
        if not isinstance(request["exceptionId"], str) or not EXCEPTION_ID.fullmatch(
            request["exceptionId"]
        ):
            fail(f"sno_dependency_exception_id_invalid:{subject_id}")
        requested_at = parse_utc(
            request["requestedAt"],
            f"sno_dependency_exception_request_time_invalid:{subject_id}",
        )
        requestor = require_digest(
            request["requestorIdentityDigest"],
            f"sno_dependency_exception_requestor_invalid:{subject_id}",
        )
        if requested_at < evidence_completed_at or requested_at > assessed_at:
            fail(f"sno_dependency_exception_request_time_invalid:{subject_id}")
        if custody_verified_at is None or requested_at < custody_verified_at:
            fail(f"sno_dependency_exception_custody_time_invalid:{subject_id}")
        candidate = exception_candidate_digest(value, item)
        if request["candidateDigest"] != candidate:
            fail(f"sno_dependency_exception_candidate_digest_invalid:{subject_id}")
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
                f"sno_dependency_exception_approval_shape_invalid:{subject_id}",
            )
            role = approval["role"]
            reviewer = require_digest(
                approval["reviewerIdentityDigest"],
                f"sno_dependency_exception_reviewer_invalid:{subject_id}",
            )
            if (
                role not in REVIEWER_ROLES
                or role in reviewer_roles
                or reviewer in reviewer_identities
                or reviewer == requestor
                or reviewer == collector_identity
                or approval["decision"] != "approve"
                or approval["candidateDigest"] != candidate
            ):
                fail(
                    f"sno_dependency_exception_approval_independence_invalid:{subject_id}"
                )
            require_digest(
                approval["signatureBundleDigest"],
                f"sno_dependency_exception_approval_signature_invalid:{subject_id}",
            )
            decided_at = parse_utc(
                approval["decidedAt"],
                f"sno_dependency_exception_approval_time_invalid:{subject_id}",
            )
            if decided_at < requested_at or decided_at > assessed_at:
                fail(f"sno_dependency_exception_approval_time_invalid:{subject_id}")
            reviewer_roles.add(role)
            reviewer_identities.add(reviewer)
            approval_times.append(decided_at)
        if request["status"] == "review-pending":
            if (
                len(approvals) >= 2
                or decision != EMPTY_DECISION
                or item["sourceAdmissionState"] != "blocked"
                or item["reasonCodes"] != ["INDEPENDENT_REVIEWS_MISSING"]
            ):
                fail(f"sno_dependency_exception_pending_state_invalid:{subject_id}")
            continue
        if (
            len(approvals) != 2
            or reviewer_roles != set(REVIEWER_ROLES)
            or decision["status"] != "approved"
        ):
            fail(f"sno_dependency_exception_approved_state_invalid:{subject_id}")
        approved_at = parse_utc(
            decision["approvedAt"],
            f"sno_dependency_exception_decision_time_invalid:{subject_id}",
        )
        expires_at = parse_utc(
            decision["expiresAt"],
            f"sno_dependency_exception_decision_time_invalid:{subject_id}",
        )
        if (
            approved_at < max(approval_times)
            or approved_at > assessed_at
            or expires_at <= approved_at
            or expires_at - approved_at > timedelta(hours=720)
            or assessed_at >= expires_at
            or decision["approvalDigest"]
            != exception_approval_digest(candidate, approvals)
            or item["sourceAdmissionState"]
            != "exception-approved-pending-artifact-set-reissue"
            or item["reasonCodes"]
            != [
                "ARTIFACT_SET_REISSUE_REQUIRED",
                "MIRRORING_NOT_AUTHORIZED",
                "ACTIVATION_NOT_AUTHORIZED",
            ]
        ):
            fail(f"sno_dependency_exception_approved_state_invalid:{subject_id}")
    if seen != set(expected):
        fail("sno_dependency_exception_inventory_invalid")
    expected_claims, expected_admission = expected_intake_summary(
        subjects, risk_evidence, custody_verified=custody_proof is not None
    )
    if value["claims"] != expected_claims:
        fail("sno_dependency_exception_claims_invalid")
    if value["admission"] != expected_admission:
        fail("sno_dependency_exception_admission_invalid")
    digest = canonical_digest(value)
    if require_template_digest and digest != EXPECTED_EXCEPTION_TEMPLATE_DIGEST:
        fail(f"sno_dependency_exception_template_digest_changed:{digest}")
    return digest


def parse_assessed_at(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    return parse_utc(value, "sno_dependency_risk_validation_time_invalid")


def verified_custody_proof(
    *,
    report_path: Path,
    verification_public_key: Path,
    signature_bundle: Path,
    expected_verification_public_key_digest: str,
    risk_evidence_path: Path,
    risk_evidence: dict[str, Any],
    cosign: str = "cosign",
) -> dict[str, Any]:
    try:
        from scripts.validate_sno_trial_dependency_risk_custody_report import (
            validate_signed_report,
        )
        from scripts.verify_dependency_risk_raw_custody import file_digest
    except ModuleNotFoundError:
        from validate_sno_trial_dependency_risk_custody_report import (
            validate_signed_report,
        )
        from verify_dependency_risk_raw_custody import file_digest

    report, _, signature_verified = validate_signed_report(
        report_path=report_path,
        verification_public_key=verification_public_key,
        signature_bundle=signature_bundle,
        expected_verification_public_key_digest=(
            expected_verification_public_key_digest
        ),
        cosign=cosign,
    )
    risk_evidence_digest = file_digest(risk_evidence_path)
    risk_evidence_canonical_digest = canonical_digest(risk_evidence)
    if (
        signature_verified is not True
        or report["evidenceId"] != risk_evidence["evidenceId"]
        or report["collection"]["riskEvidenceDigest"] != risk_evidence_digest
        or report["collection"]["riskEvidenceCanonicalDigest"]
        != risk_evidence_canonical_digest
    ):
        fail("sno_dependency_exception_custody_evidence_binding_invalid")
    return {
        "status": "verified",
        "verificationId": report["verificationId"],
        "evidenceId": report["evidenceId"],
        "reportDigest": file_digest(report_path),
        "signatureBundleDigest": file_digest(signature_bundle),
        "verificationSigningPublicKeyDigest": (
            expected_verification_public_key_digest
        ),
        "riskEvidenceDigest": risk_evidence_digest,
        "riskEvidenceCanonicalDigest": risk_evidence_canonical_digest,
        "verifierIdentityDigest": report["verifier"]["actorIdentityDigest"],
        "verifiedAt": report["verifier"]["completedAt"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-policy")
    evidence_parser = subparsers.add_parser("validate-evidence")
    evidence_parser.add_argument("--report", type=Path, required=True)
    exception_parser = subparsers.add_parser("validate-exceptions")
    exception_parser.add_argument("--intake", type=Path)
    exception_parser.add_argument("--risk-evidence", type=Path)
    exception_parser.add_argument("--custody-report", type=Path)
    exception_parser.add_argument("--custody-public-key", type=Path)
    exception_parser.add_argument("--custody-signature-bundle", type=Path)
    exception_parser.add_argument("--expected-custody-public-key-digest")
    exception_parser.add_argument("--cosign", default="cosign")
    exception_parser.add_argument("--at")
    args = parser.parse_args(argv)
    artifacts, release_set, policy = load_inputs()
    policy_digest = validate_policy(policy, artifacts, release_set)
    if args.command == "validate-policy":
        template = load_json(EXCEPTION_TEMPLATE_PATH)
        template_digest = validate_exception_intake(
            template,
            artifacts,
            release_set,
            require_template_digest=True,
        )
        print(
            "sno_trial_dependency_risk_policy_valid "
            f"policyDigest={policy_digest} "
            f"exceptionTemplateDigest={template_digest} "
            "sourceAdmission=false activation=false deployment=false"
        )
        return 0
    if args.command == "validate-evidence":
        evidence = load_json(args.report)
        evidence_digest = validate_risk_evidence(evidence, artifacts, release_set)
        print(
            "sno_trial_dependency_risk_evidence_valid "
            f"evidenceDigest={evidence_digest} "
            f"eligible={evidence['claims']['eligibleForHumanReviewCount']} "
            "sourceAdmission=false activation=false deployment=false"
        )
        return 0
    intake_path = args.intake or EXCEPTION_TEMPLATE_PATH
    intake = load_json(intake_path)
    evidence = load_json(args.risk_evidence) if args.risk_evidence else None
    custody_arguments = (
        args.custody_report,
        args.custody_public_key,
        args.custody_signature_bundle,
        args.expected_custody_public_key_digest,
    )
    if any(value is not None for value in custody_arguments) and not all(
        value is not None for value in custody_arguments
    ):
        fail("sno_dependency_exception_custody_inputs_incomplete")
    custody_proof = None
    if all(value is not None for value in custody_arguments):
        if evidence is None or args.risk_evidence is None:
            fail("sno_dependency_exception_custody_evidence_required")
        custody_proof = verified_custody_proof(
            report_path=args.custody_report,
            verification_public_key=args.custody_public_key,
            signature_bundle=args.custody_signature_bundle,
            expected_verification_public_key_digest=(
                args.expected_custody_public_key_digest
            ),
            risk_evidence_path=args.risk_evidence,
            risk_evidence=evidence,
            cosign=args.cosign,
        )
    intake_digest = validate_exception_intake(
        intake,
        artifacts,
        release_set,
        evidence,
        custody_proof,
        now=parse_assessed_at(args.at),
        require_template_digest=args.intake is None,
    )
    print(
        "sno_trial_dependency_exceptions_valid "
        f"intakeDigest={intake_digest} "
        f"approved={intake['claims']['approvedExceptions']} "
        "sourceAdmission=false activation=false deployment=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
