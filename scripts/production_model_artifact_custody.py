#!/usr/bin/env python3
"""Validate the source-only production model custody and review contract."""

from __future__ import annotations

import argparse
import copy
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.production_model_artifact_intake import (
        POLICY_PATH as SOURCE_POLICY_PATH,
        SCHEMA_PATH as SOURCE_OBSERVATION_SCHEMA_PATH,
        load_validated_candidate,
        validate_policy as validate_source_policy,
    )
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from production_model_artifact_intake import (
        POLICY_PATH as SOURCE_POLICY_PATH,
        SCHEMA_PATH as SOURCE_OBSERVATION_SCHEMA_PATH,
        load_validated_candidate,
        validate_policy as validate_source_policy,
    )
    from validate_repository import ROOT, canonical_digest, load_json


POLICY_PATH = ROOT / "config" / "production-model-artifact-custody-policy.lock.json"
CUSTODY_SCHEMA_PATH = (
    ROOT / "schemas" / "production-model-artifact-custody-record-v1.schema.json"
)
REVIEW_SCHEMA_PATH = (
    ROOT / "schemas" / "production-model-license-review-decision-v1.schema.json"
)
POLICY_KIND = "orchestra.openshift.production-model-artifact-custody-policy.v1"
CUSTODY_KIND = "orchestra.openshift.production-model-artifact-custody-record.v1"
REVIEW_KIND = "orchestra.openshift.production-model-license-review-decision.v1"
POLICY_ID = "orchestra-production-model-artifact-custody-2026-07-28.1"
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
EXPECTED_POLICY_DIGEST = (
    "sha256:ca2fc2092f0b1fdb652a465f8d1502804ee26ca3274edc130d312577edcad22a"
)
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
RECORD_ID = re.compile(r"^production-model-custody-[a-z0-9][a-z0-9._-]{7,127}$")
REVIEW_ID = re.compile(
    r"^production-model-license-review-[a-z0-9][a-z0-9._-]{7,127}$"
)
SOURCE_OBSERVATION_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
GENERATION = re.compile(r"^[1-9][0-9]*$")
CRC32C = re.compile(r"^[A-Za-z0-9+/]{6}==$")
KMS_ENCRYPTION_KEY = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/"
    r"keyRings/orchestra-reference-evidence/cryptoKeys/"
    r"production-model-artifact-custody/cryptoKeyVersions/[1-9][0-9]*$"
)
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
REVIEWER_ROLES = ["model-risk-reviewer", "service-owner"]

CUSTODY_CONTROLS = {
    "sourceObservationVerified": True,
    "createOnlyUpload": True,
    "generationPinnedVerification": True,
    "metagenerationPinnedVerification": True,
    "payloadBytesInRecord": False,
    "secretValuesInRecord": False,
    "runtimeDownloadAuthorized": False,
    "mirrorAuthorization": False,
    "deploymentAuthorized": False,
    "campaignEligible": False,
}
CUSTODY_CLAIMS = {
    "artifactCustodyVerified": True,
    "licenseApproved": False,
    "sourceAdmissionAuthorized": False,
    "dependencyAdmissionAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEvidence": False,
    "referenceProfileVerified": False,
    "customerCertified": False,
    "redHatCertified": False,
    "contractualSla": False,
}
REVIEW_ATTESTATION = {
    "humanPerformed": True,
    "automatedApproval": False,
    "independentFromUploader": True,
    "independentFromCustodyVerifier": True,
    "noConflictDeclared": True,
    "sourceTermsReviewed": True,
    "modelCardsReviewed": True,
}
REVIEW_CLAIMS = {
    "singleReviewerDecisionRecorded": True,
    "aggregateLicenseApproval": False,
    "sourceAdmissionAuthorized": False,
    "dependencyAdmissionAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEvidence": False,
    "referenceProfileVerified": False,
    "customerCertified": False,
    "redHatCertified": False,
    "contractualSla": False,
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def digest_without_field(value: dict[str, Any], field: str) -> str:
    unsigned = copy.deepcopy(value)
    unsigned.pop(field, None)
    return canonical_digest(unsigned)


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(code)
    return parsed


def validate_schema_strictness(
    schema: dict[str, Any], expected_id: str, code_prefix: str
) -> None:
    def visit(value: Any, location: str) -> None:
        if isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{location}/{index}")
            return
        if not isinstance(value, dict):
            return
        if (
            value.get("type") == "object"
            and value.get("additionalProperties") is not False
        ):
            fail(f"{code_prefix}_schema_not_strict:{location}")
        for key, child in value.items():
            visit(child, f"{location}/{key}")

    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id") != expected_id
        or schema.get("additionalProperties") is not False
    ):
        fail(f"{code_prefix}_schema_identity_invalid")
    visit(schema, "$")


def expected_artifacts(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "artifactId": model["id"],
            "serviceId": model["serviceId"],
            "filename": model["filename"],
            "revision": model["revision"],
            "digest": model["digest"],
            "sizeBytes": model["sizeBytes"],
            "declaredLicense": model["license"],
        }
        for model in candidate["models"]
    ]


def load_contract_inputs() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    candidate = load_validated_candidate()
    source_policy = load_json(SOURCE_POLICY_PATH)
    source_schema = load_json(SOURCE_OBSERVATION_SCHEMA_PATH)
    validate_source_policy(source_policy, candidate, source_schema)
    return (
        candidate,
        source_policy,
        load_json(POLICY_PATH),
        load_json(CUSTODY_SCHEMA_PATH),
        load_json(REVIEW_SCHEMA_PATH),
    )


def validate_policy(
    value: dict[str, Any],
    candidate: dict[str, Any],
    source_policy: dict[str, Any],
    custody_schema: dict[str, Any],
    review_schema: dict[str, Any],
) -> str:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "profileId",
            "targetClass",
            "bindings",
            "artifacts",
            "storage",
            "kms",
            "identities",
            "verification",
            "licenseReview",
            "promotionBoundary",
            "controls",
            "claims",
            "policyDigest",
        },
        "production_model_custody_policy_keys_invalid",
    )
    validate_schema_strictness(
        custody_schema,
        (
            "https://schemas.prometa.ai/orchestra/reference-lab/"
            "production-model-artifact-custody-record-v1.schema.json"
        ),
        "production_model_custody",
    )
    validate_schema_strictness(
        review_schema,
        (
            "https://schemas.prometa.ai/orchestra/reference-lab/"
            "production-model-license-review-decision-v1.schema.json"
        ),
        "production_model_review",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != POLICY_KIND
        or value["policyId"] != POLICY_ID
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
    ):
        fail("production_model_custody_policy_identity_invalid")
    if value["bindings"] != {
        "candidateId": candidate["candidateId"],
        "candidateDigest": candidate["candidateDigest"],
        "sourceIntakePolicyId": source_policy["policyId"],
        "sourceIntakePolicyDigest": source_policy["policyDigest"],
        "custodyRecordSchemaDigest": canonical_digest(custody_schema),
        "reviewDecisionSchemaDigest": canonical_digest(review_schema),
    }:
        fail("production_model_custody_policy_bindings_invalid")
    if value["artifacts"] != expected_artifacts(candidate):
        fail("production_model_custody_policy_artifacts_invalid")
    if value["storage"] != {
        "projectPlane": "services-evidence",
        "provisioningState": "not-declared",
        "bucketNameSource": "future-foundation-output",
        "artifactManagedFolder": "production-model-artifacts/",
        "artifactPrefixTemplate": (
            "production-model-artifacts/v1/{profileId}/{recordId}"
        ),
        "signedRecordManagedFolder": "production-model-custody/",
        "signedRecordPrefixTemplate": (
            "production-model-custody/v1/{profileId}/{recordId}"
        ),
        "signedRecordObject": "production-model-artifact-custody-record.json",
        "signedRecordPublicKeyObject": (
            "production-model-artifact-custody-public-key.pem"
        ),
        "signedRecordCompletionMarker": (
            "production-model-artifact-custody-signature.sigstore.json"
        ),
        "cmekRequired": True,
        "uniformBucketLevelAccess": True,
        "publicAccessPrevention": "enforced",
        "versioningRequired": True,
        "objectRetentionRequired": True,
        "minimumRetentionDays": 400,
        "createOnlyGenerationPrecondition": 0,
        "generationPinnedReads": True,
        "metagenerationPinnedReads": True,
        "eventBasedHoldRequired": True,
        "runtimeDirectReadAllowed": False,
    }:
        fail("production_model_custody_policy_storage_invalid")
    if value["kms"] != {
        "projectPlane": "services-evidence",
        "location": "europe-west1",
        "keyRingId": "orchestra-reference-evidence",
        "encryptionKeyId": "production-model-artifact-custody",
        "verificationSigningKeyId": (
            "production-model-artifact-custody-verification-signing"
        ),
        "verificationSigningPurpose": "ASYMMETRIC_SIGN",
        "verificationSigningAlgorithm": "EC_SIGN_P256_SHA256",
        "verificationSigningProtectionLevel": "SOFTWARE",
        "exactVersionsRequired": True,
        "preventDestroy": True,
    }:
        fail("production_model_custody_policy_kms_invalid")
    if value["identities"] != {
        "uploaderServiceAccountId": "orchestra-model-custody-writer",
        "uploaderManagedFolderRole": "roles/storage.objectCreator",
        "uploaderObjectReadGranted": False,
        "uploaderObjectDeleteGranted": False,
        "verifierServiceAccountId": "orchestra-model-custody-verify",
        "verifierManagedFolderRole": "roles/storage.objectViewer",
        "verifierSignedRecordRole": "roles/storage.objectCreator",
        "verifierReportCreateGranted": True,
        "verifierObjectWriteGranted": False,
        "verifierObjectDeleteGranted": False,
        "uploaderAndVerifierDistinct": True,
        "artifactMirrorWriteGranted": False,
        "sourceAdmissionAuthorityGranted": False,
        "deploymentAuthorityGranted": False,
        "campaignAuthorityGranted": False,
        "userManagedServiceAccountKeysAllowed": False,
    }:
        fail("production_model_custody_policy_identities_invalid")
    if value["verification"] != {
        "sourceObservationRequired": True,
        "maximumSourceObservationAgeHours": 24,
        "exactCandidateBindingRequired": True,
        "objectMetadataStableRequired": True,
        "contentDigestReplayRequired": True,
        "detachedKmsSignatureRequired": True,
        "signatureCompletionMarkerUploadedLast": True,
        "payloadFreeRecordRequired": True,
        "secretFreeRecordRequired": True,
    }:
        fail("production_model_custody_policy_verification_invalid")
    if value["licenseReview"] != {
        "humanReviewRequired": True,
        "automatedApprovalAllowed": False,
        "minimumReviewers": 2,
        "requiredReviewerRoles": REVIEWER_ROLES,
        "distinctReviewerIdentities": True,
        "reviewersDistinctFromUploader": True,
        "reviewersDistinctFromCustodyVerifier": True,
        "exactCustodyRecordBindingRequired": True,
        "licenseTextDigestRequired": True,
        "modelCardDigestRequired": True,
        "usageRestrictionDecisionRequired": True,
        "detachedReviewerSignatureRequired": True,
        "reviewRecordCreateOnly": True,
        "reviewCompletionMarkerUploadedLast": True,
        "twoApprovedDecisionsRequired": True,
    }:
        fail("production_model_custody_policy_license_review_invalid")
    if value["promotionBoundary"] != {
        "productionBomReissueRequired": True,
        "dependencyAdmissionReissueRequired": True,
        "custodyRecordMayAuthorizeAdmission": False,
        "reviewDecisionMayAuthorizeAdmission": False,
        "runtimeMaterializationSeparate": True,
        "gitOpsActivationSeparate": True,
    }:
        fail("production_model_custody_policy_promotion_boundary_invalid")
    if value["controls"] != {
        "scope": "production-model-custody-and-license-review-contract-only",
        "sourceOnly": True,
        "terraformMutationIncluded": False,
        "workflowIncluded": False,
        "cloudMutationAuthorized": False,
        "artifactDownloadPerformed": False,
        "artifactCopyPerformed": False,
        "modelBytesStoredInGit": False,
        "secretValuesStored": False,
        "campaignEligible": False,
    }:
        fail("production_model_custody_policy_controls_invalid")
    if value["claims"] != {
        "contractDeclared": True,
        "terraformDeclared": False,
        "workflowDeclared": False,
        "storageProvisioned": False,
        "liveIdentityVerified": False,
        "artifactCustodyVerified": False,
        "licenseApproved": False,
        "sourceAdmissionAuthorized": False,
        "dependencyAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "deploymentAuthorized": False,
        "campaignEvidence": False,
        "productionSupported": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }:
        fail("production_model_custody_policy_claims_invalid")
    digest = digest_without_field(value, "policyDigest")
    if value["policyDigest"] != digest or digest != EXPECTED_POLICY_DIGEST:
        fail("production_model_custody_policy_digest_invalid")
    return digest


def validate_custody_record(
    value: dict[str, Any],
    policy: dict[str, Any],
    candidate: dict[str, Any],
    custody_schema: dict[str, Any],
) -> str:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "recordId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "storage",
            "publication",
            "artifacts",
            "actors",
            "timestamps",
            "controls",
            "claims",
            "recordDigest",
        },
        "production_model_custody_record_keys_invalid",
    )
    record_id = value["recordId"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != CUSTODY_KIND
        or not isinstance(record_id, str)
        or not RECORD_ID.fullmatch(record_id)
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
    ):
        fail("production_model_custody_record_identity_invalid")
    bindings = exact_keys(
        value["bindings"],
        {
            "candidateId",
            "candidateDigest",
            "sourceIntakePolicyDigest",
            "sourceObservationId",
            "sourceObservationDigest",
            "sourceObservationObservedAt",
            "custodyPolicyId",
            "custodyPolicyDigest",
            "custodyRecordSchemaDigest",
        },
        "production_model_custody_record_bindings_keys_invalid",
    )
    if (
        bindings["candidateId"] != candidate["candidateId"]
        or bindings["candidateDigest"] != candidate["candidateDigest"]
        or bindings["sourceIntakePolicyDigest"]
        != policy["bindings"]["sourceIntakePolicyDigest"]
        or not isinstance(bindings["sourceObservationId"], str)
        or not SOURCE_OBSERVATION_ID.fullmatch(bindings["sourceObservationId"])
        or not isinstance(bindings["sourceObservationDigest"], str)
        or not DIGEST.fullmatch(bindings["sourceObservationDigest"])
        or bindings["custodyPolicyId"] != policy["policyId"]
        or bindings["custodyPolicyDigest"] != policy["policyDigest"]
        or bindings["custodyRecordSchemaDigest"] != canonical_digest(custody_schema)
    ):
        fail("production_model_custody_record_bindings_invalid")
    source_observed_at = parse_utc(
        bindings["sourceObservationObservedAt"],
        "production_model_custody_record_source_observed_at_invalid",
    )
    storage = exact_keys(
        value["storage"],
        {
            "projectPlane",
            "bucket",
            "managedFolder",
            "prefix",
            "cmekRequired",
            "uniformBucketLevelAccess",
            "publicAccessPrevention",
            "versioningEnabled",
            "objectRetentionEnabled",
            "createOnlyGenerationPrecondition",
        },
        "production_model_custody_record_storage_keys_invalid",
    )
    expected_prefix = f"production-model-artifacts/v1/{PROFILE_ID}/{record_id}"
    if (
        storage["projectPlane"] != "services-evidence"
        or not isinstance(storage["bucket"], str)
        or not re.fullmatch(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", storage["bucket"])
        or storage["managedFolder"] != "production-model-artifacts/"
        or storage["prefix"] != expected_prefix
        or storage["cmekRequired"] is not True
        or storage["uniformBucketLevelAccess"] is not True
        or storage["publicAccessPrevention"] != "enforced"
        or storage["versioningEnabled"] is not True
        or storage["objectRetentionEnabled"] is not True
        or storage["createOnlyGenerationPrecondition"] != 0
    ):
        fail("production_model_custody_record_storage_invalid")
    publication = exact_keys(
        value["publication"],
        {
            "bucket",
            "managedFolder",
            "prefix",
            "recordObject",
            "publicKeyObject",
            "completionMarker",
            "createOnlyGenerationPrecondition",
            "completionMarkerUploadedLast",
        },
        "production_model_custody_record_publication_keys_invalid",
    )
    if publication != {
        "bucket": publication["bucket"],
        "managedFolder": "production-model-custody/",
        "prefix": f"production-model-custody/v1/{PROFILE_ID}/{record_id}",
        "recordObject": "production-model-artifact-custody-record.json",
        "publicKeyObject": "production-model-artifact-custody-public-key.pem",
        "completionMarker": (
            "production-model-artifact-custody-signature.sigstore.json"
        ),
        "createOnlyGenerationPrecondition": 0,
        "completionMarkerUploadedLast": True,
    } or (
        not isinstance(publication["bucket"], str)
        or not re.fullmatch(
            r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", publication["bucket"]
        )
    ):
        fail("production_model_custody_record_publication_invalid")
    if not isinstance(value["artifacts"], list) or len(value["artifacts"]) != 2:
        fail("production_model_custody_record_artifacts_invalid")
    expected = expected_artifacts(candidate)
    artifact_verified_at: list[datetime] = []
    for index, artifact in enumerate(value["artifacts"]):
        exact_keys(
            artifact,
            {
                "artifactId",
                "serviceId",
                "filename",
                "revision",
                "expectedDigest",
                "expectedSizeBytes",
                "object",
                "verification",
            },
            "production_model_custody_record_artifact_keys_invalid",
        )
        source = expected[index]
        if {
            "artifactId": artifact["artifactId"],
            "serviceId": artifact["serviceId"],
            "filename": artifact["filename"],
            "revision": artifact["revision"],
            "digest": artifact["expectedDigest"],
            "sizeBytes": artifact["expectedSizeBytes"],
            "declaredLicense": source["declaredLicense"],
        } != source:
            fail("production_model_custody_record_artifact_binding_invalid")
        object_value = exact_keys(
            artifact["object"],
            {
                "name",
                "generation",
                "metageneration",
                "sizeBytes",
                "crc32c",
                "contentDigest",
                "kmsKeyVersion",
                "eventBasedHold",
                "temporaryHold",
                "timeCreated",
                "updated",
            },
            "production_model_custody_record_object_keys_invalid",
        )
        if (
            object_value["name"] != f"{expected_prefix}/{source['filename']}"
            or not isinstance(object_value["generation"], str)
            or not GENERATION.fullmatch(object_value["generation"])
            or not isinstance(object_value["metageneration"], str)
            or not GENERATION.fullmatch(object_value["metageneration"])
            or object_value["sizeBytes"] != source["sizeBytes"]
            or not isinstance(object_value["crc32c"], str)
            or not CRC32C.fullmatch(object_value["crc32c"])
            or object_value["contentDigest"] != source["digest"]
            or not isinstance(object_value["kmsKeyVersion"], str)
            or not KMS_ENCRYPTION_KEY.fullmatch(object_value["kmsKeyVersion"])
            or object_value["eventBasedHold"] is not True
            or object_value["temporaryHold"] is not False
            or parse_utc(
                object_value["updated"],
                "production_model_custody_record_object_updated_invalid",
            )
            < parse_utc(
                object_value["timeCreated"],
                "production_model_custody_record_object_created_invalid",
            )
        ):
            fail("production_model_custody_record_object_invalid")
        verification = exact_keys(
            artifact["verification"],
            {
                "generationPinnedRead",
                "metagenerationPinnedRead",
                "exactSizeMatched",
                "expectedDigestMatched",
                "objectMetadataStable",
                "verifiedAt",
            },
            "production_model_custody_record_verification_keys_invalid",
        )
        if verification != {
            "generationPinnedRead": True,
            "metagenerationPinnedRead": True,
            "exactSizeMatched": True,
            "expectedDigestMatched": True,
            "objectMetadataStable": True,
            "verifiedAt": verification["verifiedAt"],
        }:
            fail("production_model_custody_record_verification_invalid")
        artifact_verified_at.append(
            parse_utc(
                verification["verifiedAt"],
                "production_model_custody_record_verified_at_invalid",
            )
        )
    actors = exact_keys(
        value["actors"],
        {
            "uploaderIdentityDigest",
            "verifierIdentityDigest",
            "identitiesDistinct",
            "uploaderServiceAccountId",
            "verifierServiceAccountId",
        },
        "production_model_custody_record_actors_keys_invalid",
    )
    if (
        not isinstance(actors["uploaderIdentityDigest"], str)
        or not DIGEST.fullmatch(actors["uploaderIdentityDigest"])
        or not isinstance(actors["verifierIdentityDigest"], str)
        or not DIGEST.fullmatch(actors["verifierIdentityDigest"])
        or actors["uploaderIdentityDigest"] == actors["verifierIdentityDigest"]
        or actors["identitiesDistinct"] is not True
        or actors["uploaderServiceAccountId"]
        != policy["identities"]["uploaderServiceAccountId"]
        or actors["verifierServiceAccountId"]
        != policy["identities"]["verifierServiceAccountId"]
    ):
        fail("production_model_custody_record_actors_invalid")
    timestamps = exact_keys(
        value["timestamps"],
        {"copyStartedAt", "copyCompletedAt", "verifiedAt"},
        "production_model_custody_record_timestamps_keys_invalid",
    )
    copy_started = parse_utc(
        timestamps["copyStartedAt"],
        "production_model_custody_record_copy_started_invalid",
    )
    copy_completed = parse_utc(
        timestamps["copyCompletedAt"],
        "production_model_custody_record_copy_completed_invalid",
    )
    verified_at = parse_utc(
        timestamps["verifiedAt"], "production_model_custody_record_verified_invalid"
    )
    if (
        copy_started > copy_completed
        or copy_completed > verified_at
        or source_observed_at > copy_started
        or copy_started - source_observed_at > timedelta(hours=24)
        or any(item > verified_at for item in artifact_verified_at)
    ):
        fail("production_model_custody_record_timestamp_order_invalid")
    if value["controls"] != CUSTODY_CONTROLS:
        fail("production_model_custody_record_controls_invalid")
    if value["claims"] != CUSTODY_CLAIMS:
        fail("production_model_custody_record_claims_invalid")
    digest = digest_without_field(value, "recordDigest")
    if value["recordDigest"] != digest:
        fail("production_model_custody_record_digest_invalid")
    return digest


def validate_review_decision(
    value: dict[str, Any],
    policy: dict[str, Any],
    candidate: dict[str, Any],
    custody_record: dict[str, Any],
    review_schema: dict[str, Any],
) -> str:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "reviewId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "reviewer",
            "artifactReviews",
            "decision",
            "reviewedAt",
            "attestation",
            "claims",
            "reviewDigest",
        },
        "production_model_review_record_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REVIEW_KIND
        or not isinstance(value["reviewId"], str)
        or not REVIEW_ID.fullmatch(value["reviewId"])
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live-human-review"
    ):
        fail("production_model_review_record_identity_invalid")
    bindings = exact_keys(
        value["bindings"],
        {
            "candidateId",
            "candidateDigest",
            "custodyPolicyId",
            "custodyPolicyDigest",
            "custodyRecordId",
            "custodyRecordDigest",
            "reviewDecisionSchemaDigest",
        },
        "production_model_review_record_bindings_keys_invalid",
    )
    if bindings != {
        "candidateId": candidate["candidateId"],
        "candidateDigest": candidate["candidateDigest"],
        "custodyPolicyId": policy["policyId"],
        "custodyPolicyDigest": policy["policyDigest"],
        "custodyRecordId": custody_record["recordId"],
        "custodyRecordDigest": custody_record["recordDigest"],
        "reviewDecisionSchemaDigest": canonical_digest(review_schema),
    }:
        fail("production_model_review_record_bindings_invalid")
    reviewer = exact_keys(
        value["reviewer"],
        {"role", "identityDigest"},
        "production_model_review_reviewer_keys_invalid",
    )
    actors = custody_record["actors"]
    if (
        reviewer["role"] not in REVIEWER_ROLES
        or not isinstance(reviewer["identityDigest"], str)
        or not DIGEST.fullmatch(reviewer["identityDigest"])
        or reviewer["identityDigest"]
        in {
            actors["uploaderIdentityDigest"],
            actors["verifierIdentityDigest"],
        }
    ):
        fail("production_model_review_reviewer_invalid")
    if (
        not isinstance(value["artifactReviews"], list)
        or len(value["artifactReviews"]) != 2
    ):
        fail("production_model_review_artifacts_invalid")
    expected = expected_artifacts(candidate)
    artifact_decisions: list[str] = []
    for index, artifact in enumerate(value["artifactReviews"]):
        exact_keys(
            artifact,
            {
                "artifactId",
                "declaredLicense",
                "licenseTextDigest",
                "modelCardDigest",
                "usageRestrictions",
                "decision",
                "reasonCodes",
            },
            "production_model_review_artifact_keys_invalid",
        )
        if (
            artifact["artifactId"] != expected[index]["artifactId"]
            or artifact["declaredLicense"] != expected[index]["declaredLicense"]
            or not isinstance(artifact["licenseTextDigest"], str)
            or not DIGEST.fullmatch(artifact["licenseTextDigest"])
            or not isinstance(artifact["modelCardDigest"], str)
            or not DIGEST.fullmatch(artifact["modelCardDigest"])
            or not isinstance(artifact["usageRestrictions"], list)
            or not 1 <= len(artifact["usageRestrictions"]) <= 16
            or len(set(artifact["usageRestrictions"]))
            != len(artifact["usageRestrictions"])
            or any(
                not isinstance(code, str) or not REASON_CODE.fullmatch(code)
                for code in artifact["usageRestrictions"]
            )
            or artifact["decision"] not in {"APPROVED", "REJECTED"}
            or not isinstance(artifact["reasonCodes"], list)
            or len(set(artifact["reasonCodes"])) != len(artifact["reasonCodes"])
            or any(
                not isinstance(code, str) or not REASON_CODE.fullmatch(code)
                for code in artifact["reasonCodes"]
            )
        ):
            fail("production_model_review_artifact_invalid")
        if (
            artifact["decision"] == "APPROVED"
            and artifact["reasonCodes"]
        ) or (
            artifact["decision"] == "REJECTED"
            and not artifact["reasonCodes"]
        ):
            fail("production_model_review_artifact_reason_invalid")
        artifact_decisions.append(artifact["decision"])
    if value["decision"] == "APPROVED":
        if artifact_decisions != ["APPROVED", "APPROVED"]:
            fail("production_model_review_decision_inconsistent")
    elif value["decision"] == "REJECTED":
        if "REJECTED" not in artifact_decisions:
            fail("production_model_review_decision_inconsistent")
    else:
        fail("production_model_review_decision_invalid")
    reviewed_at = parse_utc(
        value["reviewedAt"], "production_model_review_reviewed_at_invalid"
    )
    custody_verified_at = parse_utc(
        custody_record["timestamps"]["verifiedAt"],
        "production_model_custody_record_verified_invalid",
    )
    if reviewed_at < custody_verified_at:
        fail("production_model_review_precedes_custody")
    if value["attestation"] != REVIEW_ATTESTATION:
        fail("production_model_review_attestation_invalid")
    if value["claims"] != REVIEW_CLAIMS:
        fail("production_model_review_claims_invalid")
    digest = digest_without_field(value, "reviewDigest")
    if value["reviewDigest"] != digest:
        fail("production_model_review_digest_invalid")
    return digest


def validate_review_set(
    reviews: list[dict[str, Any]],
    policy: dict[str, Any],
    candidate: dict[str, Any],
    custody_record: dict[str, Any],
    review_schema: dict[str, Any],
) -> None:
    if len(reviews) != 2:
        fail("production_model_review_set_count_invalid")
    for review in reviews:
        validate_review_decision(
            review, policy, candidate, custody_record, review_schema
        )
    if sorted(review["reviewer"]["role"] for review in reviews) != sorted(
        REVIEWER_ROLES
    ):
        fail("production_model_review_set_roles_invalid")
    identities = [review["reviewer"]["identityDigest"] for review in reviews]
    if len(set(identities)) != 2:
        fail("production_model_review_set_identity_reuse")
    if any(review["decision"] != "APPROVED" for review in reviews):
        fail("production_model_review_set_not_approved")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-policy")
    custody = subparsers.add_parser("validate-custody-record")
    custody.add_argument("--record", type=Path, required=True)
    review = subparsers.add_parser("validate-review-decision")
    review.add_argument("--record", type=Path, required=True)
    review.add_argument("--custody-record", type=Path, required=True)
    review_set = subparsers.add_parser("validate-review-set")
    review_set.add_argument("--custody-record", type=Path, required=True)
    review_set.add_argument("--model-risk-review", type=Path, required=True)
    review_set.add_argument("--service-owner-review", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    (
        candidate,
        source_policy,
        policy,
        custody_schema,
        review_schema,
    ) = load_contract_inputs()
    policy_digest = validate_policy(
        policy, candidate, source_policy, custody_schema, review_schema
    )
    if args.command == "validate-policy":
        print(
            "productionModelCustodyContractValid=true "
            f"policyDigest={policy_digest} storageProvisioned=false "
            "workflowDeclared=false artifactCustodyVerified=false "
            "licenseApproved=false admissionAuthorized=false"
        )
        return 0
    custody_record = load_json(
        args.record if args.command == "validate-custody-record" else args.custody_record
    )
    custody_digest = validate_custody_record(
        custody_record, policy, candidate, custody_schema
    )
    if args.command == "validate-custody-record":
        print(
            "productionModelCustodyRecordStructurallyValid=true "
            f"recordDigest={custody_digest} detachedSignatureVerified=false "
            "licenseApproved=false admissionAuthorized=false"
        )
        return 0
    if args.command == "validate-review-decision":
        review_digest = validate_review_decision(
            load_json(args.record),
            policy,
            candidate,
            custody_record,
            review_schema,
        )
        print(
            "productionModelReviewStructurallyValid=true "
            f"reviewDigest={review_digest} reviewerSignatureVerified=false "
            "aggregateLicenseApproval=false admissionAuthorized=false"
        )
        return 0
    validate_review_set(
        [load_json(args.model_risk_review), load_json(args.service_owner_review)],
        policy,
        candidate,
        custody_record,
        review_schema,
    )
    print(
        "productionModelReviewSetStructurallyComplete=true "
        "custodySignatureVerified=false reviewerSignaturesVerified=false "
        "admissionAuthorized=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
