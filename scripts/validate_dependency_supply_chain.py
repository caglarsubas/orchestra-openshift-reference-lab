#!/usr/bin/env python3
"""Validate source observations and the deliberately empty mirror intake."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, NoReturn

try:
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_repository import ROOT, canonical_digest, load_json


SOURCE_VERIFICATION = ROOT / "config" / "dependency-source-verification.lock.json"
MIRROR_INTAKE = ROOT / "config" / "dependency-mirror-intake.example.json"
ADMISSION = ROOT / "config" / "dependency-admission.lock.json"
TOPOLOGY = ROOT / "config" / "lab.lock.json"
TOPOLOGY_DIGEST = (
    "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0"
)
ADMISSION_DIGEST = (
    "sha256:fc1f22817a5959e18d3f4493f199bda61b30cea441929ee321b531402e846def"
)
EXPECTED_SOURCE_VERIFICATION_DIGEST = (
    "sha256:cbfaa95d09e7a9ca1812028ba13f21c40846c3c91b32424d1e834eab6ab69f89"
)
EXPECTED_MIRROR_INTAKE_DIGEST = (
    "sha256:fe357261b272cd8fb4d6917e55453b613967fe5557616550c49591d035a5fc21"
)
ISSUER = "https://token.actions.githubusercontent.com"
SIGNED_SUBJECTS = {
    "cloudnative-pg-operator": {
        "identity": "https://github.com/cloudnative-pg/cloudnative-pg/.github/workflows/release-publish.yml@refs/tags/v1.30.0",
        "bundleFormat": "sigstore-bundle-v3",
        "bundleDigest": "sha256:1a77d3f82f521663ed8ac25ebbd0d3da0d8081336b83651a714474ac5b30e360",
        "logIndex": "2011068540",
        "integratedAt": "2026-06-29T16:41:11Z",
    },
    "cloudnative-pg-postgresql-16": {
        "identity": "https://github.com/cloudnative-pg/postgres-containers/.github/workflows/bake_targets.yml@refs/heads/main",
        "bundleFormat": "legacy-cosign-bundle",
        "bundleDigest": "sha256:d5e82b8d056dd99b36b4eaed3213d831ab8699caba78214f2cc526de9d25eae8",
        "logIndex": "701956974",
        "integratedAt": "2025-11-15T07:46:58Z",
    },
    "external-secrets-controller": {
        "identity": "https://github.com/external-secrets/external-secrets/.github/workflows/release.yml@refs/heads/main",
        "bundleFormat": "legacy-cosign-bundle",
        "bundleDigest": "sha256:06996e714e21e1d60f715d839545b307122cb624cd74372784e93f8339090ca9",
        "logIndex": "2193530102",
        "integratedAt": "2026-07-18T05:38:26Z",
    },
}
UNSIGNED_SUBJECTS = {
    "barman-cloud-controller",
    "barman-cloud-sidecar",
    "clickhouse-operator",
    "clickhouse-metrics-exporter",
    "clickhouse-server-lts",
    "nats-server",
    "nats-config-reloader",
    "vault-server",
}
VERIFIED_CHECKS = {
    "subjectDigest": True,
    "certificateIdentity": True,
    "oidcIssuer": True,
    "certificateChain": True,
    "transparencyLog": True,
    "claims": True,
}
EMPTY_EXCEPTION = {
    "status": "required-not-approved",
    "exceptionId": None,
    "approvedByIdentityDigests": [],
    "approvedAt": None,
    "expiresAt": None,
    "riskReviewDigest": None,
    "licenseReviewDigest": None,
    "vulnerabilityReportDigest": None,
    "compensatingControlsDigest": None,
}
EMPTY_ARTIFACT_REGISTRY_RECEIPT = {
    "reference": None,
    "digest": None,
    "objectGeneration": None,
    "actorIdentityDigest": None,
    "receiptDigest": None,
}
EMPTY_HARBOR_RECEIPT = {
    "reference": None,
    "digest": None,
    "actorIdentityDigest": None,
    "receiptDigest": None,
}
EMPTY_LAB_SIGNATURE = {
    "bundleDigest": None,
    "signerIdentityDigest": None,
    "policyDigest": None,
    "verified": False,
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def source_subject(image: dict[str, Any]) -> str:
    reference = image["source"]["reference"]
    tag_separator = reference.rfind(":")
    if tag_separator <= reference.rfind("/"):
        fail(f"dependency_supply_chain_tag_missing:{image['id']}")
    return f"{reference[:tag_separator]}@{image['source']['indexDigest']}"


def admission_subjects(admission: dict[str, Any]) -> dict[str, str]:
    images = admission.get("images")
    if not isinstance(images, list):
        fail("dependency_supply_chain_admission_images_invalid")
    subjects = {
        image["id"]: source_subject(image)
        for image in images
        if isinstance(image, dict) and isinstance(image.get("id"), str)
    }
    if len(subjects) != len(images):
        fail("dependency_supply_chain_admission_images_invalid")
    return subjects


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    return parsed


def validate_source_verification(
    value: dict[str, Any], admission: dict[str, Any], topology: dict[str, Any]
) -> str:
    if set(value) != {
        "schemaVersion",
        "profileId",
        "verificationId",
        "bindings",
        "observationWindow",
        "observer",
        "claim",
        "verifiedSubjects",
        "exceptionRequiredSubjects",
        "admission",
    }:
        fail("dependency_source_verification_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != topology["profileId"]
        or value["verificationId"]
        != "orchestra-dependency-source-verification-2026-07-21.1"
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "dependencyAdmissionDigest": ADMISSION_DIGEST,
        }
        or canonical_digest(topology) != TOPOLOGY_DIGEST
        or canonical_digest(admission) != ADMISSION_DIGEST
    ):
        fail("dependency_source_verification_identity_invalid")

    window = value["observationWindow"]
    if not isinstance(window, dict) or set(window) != {
        "observedAt",
        "validUntil",
        "maxAgeDays",
    }:
        fail("dependency_source_verification_window_invalid")
    observed_at = parse_utc(
        window["observedAt"], "dependency_source_verification_window_invalid"
    )
    valid_until = parse_utc(
        window["validUntil"], "dependency_source_verification_window_invalid"
    )
    if window["maxAgeDays"] != 7 or valid_until - observed_at != timedelta(days=7):
        fail("dependency_source_verification_window_invalid")

    if value["observer"] != {
        "executionClass": "developer-workstation",
        "tool": "cosign",
        "toolVersion": "v3.1.1",
        "toolCommit": "7914231b348c4057891edeb321772aad3ed04fce",
        "platform": "darwin/arm64",
        "trustRootSource": "sigstore-tuf-default",
        "trustRootDigest": "sha256:6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
        "evidenceOrigin": "source-intake-non-campaign",
    }:
        fail("dependency_source_verification_observer_invalid")
    if value["claim"] != {
        "registrySubjectsObserved": 11,
        "signedSubjectsCryptographicallyVerified": 3,
        "unsignedSubjectsObserved": 8,
        "exceptionsApproved": 0,
        "signedRunnerReverified": False,
        "allSubjectsSourceAdmitted": False,
        "mirroringAuthorized": False,
        "campaignEvidence": False,
    }:
        fail("dependency_source_verification_claim_invalid")

    subjects = admission_subjects(admission)
    verified = value["verifiedSubjects"]
    if not isinstance(verified, list) or len(verified) != len(SIGNED_SUBJECTS):
        fail("dependency_source_verification_signed_inventory_invalid")
    verified_ids: set[str] = set()
    signed_keys = {
        "id",
        "subject",
        "signatureType",
        "issuer",
        "certificateIdentity",
        "bundleFormat",
        "bundleDigest",
        "transparencyLog",
        "checks",
        "sourceAdmissionState",
        "reasonCodes",
    }
    for item in verified:
        if not isinstance(item, dict) or set(item) != signed_keys:
            fail("dependency_source_verification_signed_shape_invalid")
        subject_id = item["id"]
        expected = SIGNED_SUBJECTS.get(subject_id)
        if expected is None or subject_id in verified_ids:
            fail("dependency_source_verification_signed_inventory_invalid")
        verified_ids.add(subject_id)
        if (
            item["subject"] != subjects[subject_id]
            or item["signatureType"] != "sigstore-keyless"
            or item["issuer"] != ISSUER
            or item["certificateIdentity"] != expected["identity"]
            or item["bundleFormat"] != expected["bundleFormat"]
            or item["bundleDigest"] != expected["bundleDigest"]
            or item["transparencyLog"]
            != {
                "logIndex": expected["logIndex"],
                "integratedAt": expected["integratedAt"],
            }
            or item["checks"] != VERIFIED_CHECKS
            or item["sourceAdmissionState"]
            != "observed-verified-runner-reverification-required"
            or item["reasonCodes"] != ["SIGNED_RUNNER_REVERIFICATION_REQUIRED"]
        ):
            fail(f"dependency_source_verification_signed_invalid:{subject_id}")
    if verified_ids != set(SIGNED_SUBJECTS):
        fail("dependency_source_verification_signed_inventory_invalid")

    unsigned = value["exceptionRequiredSubjects"]
    if not isinstance(unsigned, list) or len(unsigned) != len(UNSIGNED_SUBJECTS):
        fail("dependency_source_verification_unsigned_inventory_invalid")
    unsigned_ids: set[str] = set()
    unsigned_keys = {
        "id",
        "subject",
        "observation",
        "exception",
        "sourceAdmissionState",
        "reasonCodes",
    }
    for item in unsigned:
        if not isinstance(item, dict) or set(item) != unsigned_keys:
            fail("dependency_source_verification_unsigned_shape_invalid")
        subject_id = item["id"]
        if subject_id not in UNSIGNED_SUBJECTS or subject_id in unsigned_ids:
            fail("dependency_source_verification_unsigned_inventory_invalid")
        unsigned_ids.add(subject_id)
        if (
            item["subject"] != subjects[subject_id]
            or item["observation"] != "no-cosign-signature-at-locked-index"
            or item["exception"] != EMPTY_EXCEPTION
            or item["sourceAdmissionState"] != "blocked"
            or item["reasonCodes"] != ["UPSTREAM_SIGNATURE_EXCEPTION_REQUIRED"]
        ):
            fail(f"dependency_source_verification_unsigned_invalid:{subject_id}")
    if unsigned_ids != UNSIGNED_SUBJECTS or verified_ids | unsigned_ids != set(
        subjects
    ):
        fail("dependency_source_verification_inventory_incomplete")

    if value["admission"] != {
        "status": "blocked",
        "requiredExceptionCount": 8,
        "approvedExceptionCount": 0,
        "requiredEvidence": [
            "signed-certification-runner-reverification",
            "time-bounded-two-person-exceptions",
            "license-review-digests",
            "vulnerability-report-digests",
            "compensating-control-digests",
        ],
        "reasonCodes": [
            "SIGNED_RUNNER_REVERIFICATION_REQUIRED",
            "UPSTREAM_SIGNATURE_EXCEPTIONS_MISSING",
            "SOURCE_ADMISSION_INCOMPLETE",
            "MIRRORING_NOT_AUTHORIZED",
        ],
    }:
        fail("dependency_source_verification_admission_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_SOURCE_VERIFICATION_DIGEST:
        fail(f"dependency_source_verification_digest_changed:{digest}")
    return digest


def validate_mirror_intake(
    value: dict[str, Any],
    admission: dict[str, Any],
    source_verification_digest: str,
    topology: dict[str, Any],
) -> str:
    if set(value) != {
        "schemaVersion",
        "profileId",
        "targetClass",
        "executionMode",
        "intakeId",
        "bindings",
        "claim",
        "destinations",
        "subjects",
        "approvals",
        "admission",
    }:
        fail("dependency_mirror_intake_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != topology["profileId"]
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or value["intakeId"] != "orchestra-dependency-mirror-intake-template-v1"
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "dependencyAdmissionDigest": ADMISSION_DIGEST,
            "sourceVerificationDigest": source_verification_digest,
        }
    ):
        fail("dependency_mirror_intake_identity_invalid")
    if value["claim"] != {
        "sourceAdmissionComplete": False,
        "artifactRegistryReady": False,
        "harborReady": False,
        "allSubjectsMirrored": False,
        "allSubjectsLabSigned": False,
        "privatePullVerified": False,
        "twoPersonApproved": False,
        "activationAuthorized": False,
        "applied": False,
        "campaignEvidence": False,
    }:
        fail("dependency_mirror_intake_claim_invalid")
    if value["destinations"] != {
        "artifactRegistry": {
            "registry": "europe-west1-docker.pkg.dev",
            "repository": None,
            "registryIdentityDigest": None,
            "tlsPolicyDigest": None,
            "ready": False,
        },
        "harbor": {
            "registry": "harbor.services.ocp-lab.prometa.ai",
            "repository": None,
            "registryIdentityDigest": None,
            "tlsPolicyDigest": None,
            "ready": False,
        },
    }:
        fail("dependency_mirror_intake_destinations_invalid")

    subjects = admission_subjects(admission)
    items = value["subjects"]
    if not isinstance(items, list) or len(items) != len(subjects):
        fail("dependency_mirror_intake_subject_inventory_invalid")
    item_keys = {
        "id",
        "sourceSubject",
        "sourceAdmissionState",
        "artifactRegistry",
        "harbor",
        "labSignature",
        "privatePull",
    }
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != item_keys:
            fail("dependency_mirror_intake_subject_shape_invalid")
        subject_id = item["id"]
        if subject_id not in subjects or subject_id in seen:
            fail("dependency_mirror_intake_subject_inventory_invalid")
        seen.add(subject_id)
        expected_state = (
            "runner-reverification-required"
            if subject_id in SIGNED_SUBJECTS
            else "exception-required"
        )
        if (
            item["sourceSubject"] != subjects[subject_id]
            or item["sourceAdmissionState"] != expected_state
            or item["artifactRegistry"] != EMPTY_ARTIFACT_REGISTRY_RECEIPT
            or item["harbor"] != EMPTY_HARBOR_RECEIPT
            or item["labSignature"] != EMPTY_LAB_SIGNATURE
            or item["privatePull"] != {"gke": False, "openshift": False}
        ):
            fail(f"dependency_mirror_intake_subject_invalid:{subject_id}")
    if seen != set(subjects):
        fail("dependency_mirror_intake_subject_inventory_invalid")
    if value["approvals"] != {
        "requiredReviewers": 2,
        "reviewerIdentityDigests": [],
        "approvedAt": None,
        "approvalDigest": None,
    }:
        fail("dependency_mirror_intake_approvals_invalid")
    if value["admission"] != {
        "status": "blocked",
        "reasonCodes": [
            "SOURCE_ADMISSION_INCOMPLETE",
            "DESTINATION_REGISTRIES_UNBOUND",
            "MIRROR_RECEIPTS_MISSING",
            "LAB_SIGNATURES_MISSING",
            "PRIVATE_PULL_PROOFS_MISSING",
            "TWO_PERSON_APPROVAL_MISSING",
        ],
    }:
        fail("dependency_mirror_intake_admission_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_MIRROR_INTAKE_DIGEST:
        fail(f"dependency_mirror_intake_digest_changed:{digest}")
    return digest


def main() -> int:
    admission = load_json(ADMISSION)
    topology = load_json(TOPOLOGY)
    source_digest = validate_source_verification(
        load_json(SOURCE_VERIFICATION), admission, topology
    )
    mirror_digest = validate_mirror_intake(
        load_json(MIRROR_INTAKE), admission, source_digest, topology
    )
    print(
        "dependency_supply_chain_valid "
        f"sourceVerificationDigest={source_digest} "
        f"mirrorIntakeDigest={mirror_digest} "
        "verified=3 exceptionsRequired=8 mirrorAuthorization=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error)
        raise SystemExit(1)
