#!/usr/bin/env python3
"""Strict authority contract for independent dependency-risk raw custody."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.dependency_risk_collection_execution import (
        EXPECTED_AUTHORITY_DIGEST as EXPECTED_COLLECTION_AUTHORITY_DIGEST,
        load_contract as load_collection_contract,
        validate_authority as validate_collection_authority,
    )
    from scripts.dependency_risk_contract import (
        EXPECTED_RISK_POLICY_DIGEST,
        EXPECTED_SOURCE_VERIFICATION_DIGEST,
        RISK_POLICY,
        blob_digest,
        validate_risk_policy,
    )
    from scripts.dependency_risk_execution import (
        EXPECTED_AUTHORITY_DIGEST as EXPECTED_PREFLIGHT_AUTHORITY_DIGEST,
    )
    from scripts.validate_dependency_admission import (
        ADMISSION_LOCK,
        EXPECTED_ADMISSION_DIGEST,
        validate_admission,
    )
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from dependency_risk_collection_execution import (
        EXPECTED_AUTHORITY_DIGEST as EXPECTED_COLLECTION_AUTHORITY_DIGEST,
        load_contract as load_collection_contract,
        validate_authority as validate_collection_authority,
    )
    from dependency_risk_contract import (
        EXPECTED_RISK_POLICY_DIGEST,
        EXPECTED_SOURCE_VERIFICATION_DIGEST,
        RISK_POLICY,
        blob_digest,
        validate_risk_policy,
    )
    from dependency_risk_execution import (
        EXPECTED_AUTHORITY_DIGEST as EXPECTED_PREFLIGHT_AUTHORITY_DIGEST,
    )
    from validate_dependency_admission import (
        ADMISSION_LOCK,
        EXPECTED_ADMISSION_DIGEST,
        validate_admission,
    )
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, canonical_digest, load_json


AUTHORITY_PATH = ROOT / "config" / "dependency-risk-custody-verification.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
DEPENDENCY_BOM_PATH = ROOT / "config" / "dependency-bom.lock.json"
TOPOLOGY_PATH = ROOT / "config" / "lab.lock.json"
RAW_CUSTODY_SCHEMA = (
    ROOT / "schemas" / "dependency-risk-raw-custody-statement-v1.schema.json"
)
VERIFICATION_SCHEMA = (
    ROOT / "schemas" / "dependency-risk-custody-verification-v1.schema.json"
)
VERIFIER_MODULE = ROOT / "scripts" / "verify_dependency_risk_raw_custody.py"
VERIFICATION_SCRIPT = ROOT / "scripts" / "verify_and_publish_dependency_risk_custody.sh"
REPORT_VALIDATOR = ROOT / "scripts" / "validate_dependency_risk_custody_report.py"
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "dependency-risk-custody-verification.yml"
)
BOOTSTRAP_TERRAFORM_PATH = ROOT / "infra" / "terraform" / "bootstrap" / "main.tf"
FOUNDATION_TERRAFORM_PATH = ROOT / "infra" / "terraform" / "foundation" / "main.tf"
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
TOPOLOGY_DIGEST = (
    "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0"
)
RAW_CUSTODY_SCHEMA_DIGEST = (
    "sha256:984fc129f63c9f333097df25d226fb33250d68948438e5958536cc1de0a72fd5"
)
EXPECTED_AUTHORITY_DIGEST = (
    "sha256:294e544928d032046a4b8a9cec85b067f9ce5b36982597f56029d6f349151eaf"
)
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REPOSITORY_ID = "1307302690"
REPOSITORY_OWNER_ID = "37515097"
ENVIRONMENT = "reference-lab-dependency-risk-custody-verification"
WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/"
    "dependency-risk-custody-verification.yml@refs/heads/main"
)
ATTRIBUTE_CONDITION = " && ".join(
    (
        f"assertion.repository == '{REPOSITORY}'",
        f"assertion.repository_id == '{REPOSITORY_ID}'",
        f"assertion.repository_owner_id == '{REPOSITORY_OWNER_ID}'",
        "assertion.repository_visibility == 'private'",
        "assertion.ref == 'refs/heads/main'",
        "assertion.event_name == 'workflow_dispatch'",
        f"assertion.workflow_ref == '{WORKFLOW_REF}'",
        f"assertion.environment == '{ENVIRONMENT}'",
    )
)


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def load_contract() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        load_json(AUTHORITY_PATH),
        load_json(RELEASE_SET_PATH),
        load_json(RISK_POLICY),
    )


def expected_federation() -> dict[str, Any]:
    return {
        "poolId": "orchestra-lab-github",
        "providerId": "dependency-risk-custody",
        "issuerUri": "https://token.actions.githubusercontent.com",
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "repositoryOwnerId": REPOSITORY_OWNER_ID,
        "repositoryVisibility": "private",
        "workflowRef": WORKFLOW_REF,
        "environment": ENVIRONMENT,
        "minimumIndependentReviewers": 1,
        "reviewerType": "User",
        "preventSelfReview": True,
        "deploymentBranch": "main",
        "attributeCondition": ATTRIBUTE_CONDITION,
    }


def validate_authority(
    value: dict[str, Any],
    release_set: dict[str, Any],
    risk_policy: dict[str, Any],
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "authorityId",
            "profileId",
            "bindings",
            "kms",
            "identity",
            "federation",
            "storage",
            "workflow",
            "claim",
        },
        "dependency_risk_custody_authority_keys_invalid",
    )
    release_set_digest = validate_release_set(release_set)
    risk_policy_digest = validate_risk_policy(risk_policy)
    admission_digest = validate_admission(
        load_json(ADMISSION_LOCK),
        load_json(DEPENDENCY_BOM_PATH),
        load_json(TOPOLOGY_PATH),
    )
    collection_authority, collection_release_set, collection_risk_policy = (
        load_collection_contract()
    )
    collection_authority_digest = validate_collection_authority(
        collection_authority,
        collection_release_set,
        collection_risk_policy,
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.dependency-risk.custody-verification-authority.v1"
        or value["authorityId"] != "orchestra-dependency-risk-custody-verification-v1"
        or value["profileId"] != PROFILE_ID
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "dependencyAdmissionDigest": admission_digest,
            "releaseSetDigest": release_set_digest,
            "sourceVerificationDigest": EXPECTED_SOURCE_VERIFICATION_DIGEST,
            "riskPolicyDigest": risk_policy_digest,
            "preflightAuthorityDigest": EXPECTED_PREFLIGHT_AUTHORITY_DIGEST,
            "collectionExecutionAuthorityDigest": collection_authority_digest,
            "rawCustodySchemaDigest": blob_digest(RAW_CUSTODY_SCHEMA.read_bytes()),
            "custodyVerificationSchemaDigest": blob_digest(
                VERIFICATION_SCHEMA.read_bytes()
            ),
            "verifierModuleDigest": blob_digest(VERIFIER_MODULE.read_bytes()),
            "verificationScriptDigest": blob_digest(VERIFICATION_SCRIPT.read_bytes()),
            "reportValidatorDigest": blob_digest(REPORT_VALIDATOR.read_bytes()),
        }
    ):
        fail("dependency_risk_custody_authority_identity_invalid")
    if (
        admission_digest != EXPECTED_ADMISSION_DIGEST
        or risk_policy_digest != EXPECTED_RISK_POLICY_DIGEST
        or collection_authority_digest != EXPECTED_COLLECTION_AUTHORITY_DIGEST
        or value["bindings"]["rawCustodySchemaDigest"] != RAW_CUSTODY_SCHEMA_DIGEST
    ):
        fail("dependency_risk_custody_authority_upstream_invalid")
    if value["kms"] != {
        "projectPlane": "services-evidence",
        "location": "europe-west1",
        "keyRingId": "orchestra-reference-evidence",
        "collectionKeyId": "dependency-risk-collection-signing",
        "collectionKeyRole": "roles/cloudkms.publicKeyViewer",
        "verificationKeyId": "dependency-risk-custody-verification-signing",
        "verificationKeyPurpose": "ASYMMETRIC_SIGN",
        "verificationKeyAlgorithm": "EC_SIGN_P256_SHA256",
        "verificationKeyProtectionLevel": "SOFTWARE",
        "verificationKeyRole": "roles/cloudkms.signerVerifier",
        "exactVersionsRequired": True,
        "preventDestroy": True,
    }:
        fail("dependency_risk_custody_authority_kms_invalid")
    if value["identity"] != {
        "serviceAccountId": "orchestra-custody-verifier",
        "projectRoles": [],
        "rawManagedFolderRole": "roles/storage.objectViewer",
        "rawObjectReadGranted": True,
        "rawObjectListGranted": True,
        "rawObjectWriteGranted": False,
        "rawObjectDeleteGranted": False,
        "signedManagedFolderRole": "roles/storage.objectCreator",
        "signedEvidenceCreateGranted": True,
        "signedEvidenceReadGranted": False,
        "signedEvidenceDeleteGranted": False,
        "artifactMirrorWriteGranted": False,
        "sourceAdmissionAuthorityGranted": False,
        "activationAuthorityGranted": False,
        "userManagedServiceAccountKeyDeclared": False,
    }:
        fail("dependency_risk_custody_authority_identity_boundary_invalid")
    if value["federation"] != expected_federation():
        fail("dependency_risk_custody_authority_federation_invalid")
    if value["storage"] != {
        "rawManagedFolder": "dependency-risk/",
        "rawPrefixTemplate": "dependency-risk/v1/{profileId}/{evidenceId}",
        "requiredRawObjectCount": 4,
        "generationPinnedDownloads": True,
        "metagenerationPinnedDownloads": True,
        "objectGenerationsRecorded": True,
        "signedManagedFolder": "dependency-risk-custody/",
        "reportPrefixTemplate": (
            "dependency-risk-custody/v1/{profileId}/{evidenceId}/{verificationId}"
        ),
        "createOnlyGenerationPrecondition": 0,
        "completionMarker": (
            "dependency-risk-custody-verification-signature.sigstore.json"
        ),
        "completionMarkerUploadedLast": True,
        "reportGenerationRecordedByVerifier": False,
        "workflowArtifactUploaded": False,
    }:
        fail("dependency_risk_custody_authority_storage_invalid")
    if value["workflow"] != {
        "path": ".github/workflows/dependency-risk-custody-verification.yml",
        "trigger": "workflow_dispatch",
        "exactMainRevisionRequired": True,
        "currentRunApprovalRequired": True,
        "rerunAllowed": False,
        "rawCustodyVerificationRequired": True,
        "safeArchiveExtractionRequired": True,
        "fullCollectionReplayRequired": True,
        "signedReportRequired": True,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
    }:
        fail("dependency_risk_custody_authority_workflow_invalid")
    if value["claim"] != {
        "terraformDeclared": True,
        "workflowDeclared": True,
        "applied": False,
        "liveIdentityVerified": False,
        "liveKmsVerified": False,
        "liveRawCustodyVerified": False,
        "signedReportPublished": False,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("dependency_risk_custody_authority_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_AUTHORITY_DIGEST:
        fail(f"dependency_risk_custody_authority_digest_changed:{digest}")
    return digest


def _read(path: Path, code: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(code) from error


def _terraform_resource_blocks(content: str) -> list[tuple[str, str, str]]:
    blocks: list[tuple[str, str, str]] = []
    pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
    for match in pattern.finditer(content):
        depth = 0
        end = None
        for offset, character in enumerate(content[match.end() - 1 :]):
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    end = match.end() + offset
                    break
        if end is None:
            fail("dependency_risk_custody_terraform_resource_unclosed")
        blocks.append((match.group(1), match.group(2), content[match.start() : end]))
    return blocks


def validate_declared_implementation() -> None:
    bootstrap = _read(
        BOOTSTRAP_TERRAFORM_PATH,
        "dependency_risk_custody_bootstrap_terraform_missing",
    )
    foundation = _read(
        FOUNDATION_TERRAFORM_PATH,
        "dependency_risk_custody_foundation_terraform_missing",
    )
    workflow = _read(WORKFLOW_PATH, "dependency_risk_custody_workflow_missing")
    verification_script = _read(
        VERIFICATION_SCRIPT, "dependency_risk_custody_verification_script_missing"
    )
    report_validator = _read(
        REPORT_VALIDATOR, "dependency_risk_custody_report_validator_missing"
    )

    bootstrap_required = (
        'resource "google_iam_workload_identity_pool_provider" "dependency_risk_custody_verification"',
        'workload_identity_pool_provider_id = "dependency-risk-custody"',
        "attribute_condition = local.dependency_risk_custody_verification_wif_condition",
        'resource "google_service_account" "dependency_risk_custody_verifier"',
        'account_id   = "orchestra-custody-verifier"',
        'dependency_risk_custody_verification_subject      = "dependency-risk-custody:${var.github_repository_id}:${local.dependency_risk_custody_verification_environment}"',
        "\"google.subject\"                  = \"'dependency-risk-custody:' + assertion.repository_id + ':' + assertion.environment\"",
        'resource "google_service_account_iam_member" "dependency_risk_custody_verification_wif"',
        'member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.dependency_risk_custody_verification_subject}"',
    )
    foundation_required = (
        'resource "google_kms_crypto_key" "dependency_risk_custody_verification_signing"',
        'name     = "dependency-risk-custody-verification-signing"',
        'resource "google_kms_crypto_key_iam_member" "dependency_risk_custody_collection_public_key"',
        'role          = "roles/cloudkms.publicKeyViewer"',
        'resource "google_kms_crypto_key_iam_member" "dependency_risk_custody_verifier_signer"',
        'role          = "roles/cloudkms.signerVerifier"',
        'resource "google_storage_managed_folder" "dependency_risk_raw"',
        'name            = "dependency-risk/"',
        'resource "google_storage_managed_folder_iam_member" "dependency_risk_custody_raw_reader"',
        'role           = "roles/storage.objectViewer"',
        'resource "google_storage_managed_folder" "dependency_risk_signed"',
        'name            = "dependency-risk-custody/"',
        'resource "google_storage_managed_folder_iam_member" "dependency_risk_custody_report_writer"',
        'role           = "roles/storage.objectCreator"',
        "orchestra-custody-verifier@${var.services_project_id}.iam.gserviceaccount.com",
    )
    workflow_required = (
        "workflow_dispatch:",
        "expected_main_sha:",
        "evidence_id:",
        "collection_kms_key_version:",
        "verification_kms_key_version:",
        f"environment: {ENVIRONMENT}",
        "persist-credentials: false",
        "DEPENDENCY_RISK_CUSTODY_REVIEW_GATE_CONFIGURED",
        "GCP_DEPENDENCY_RISK_CUSTODY_WIF_PROVIDER",
        "GCP_DEPENDENCY_RISK_CUSTODY_SERVICE_ACCOUNT",
        "GCP_RAW_EVIDENCE_BUCKET",
        "GCP_SIGNED_EVIDENCE_BUCKET",
        "--contract dependency-risk-custody-verification",
        "DEPENDENCY_RISK_GITHUB_APP_INSTALLATION_ID",
        "operator_control_plane_readiness.py verify-app",
        "GITHUB_APP_INSTALLATION_DIGEST",
        "scripts/verify_and_publish_dependency_risk_custody.sh",
        "custodyVerified=true",
    )
    script_required = (
        'gcloud storage ls --json "gs://$RAW_EVIDENCE_BUCKET/$RAW_PREFIX/*"',
        '--if-generation-match="$generation"',
        '--if-metageneration-match="$metageneration"',
        "verify_dependency_risk_raw_custody.py",
        "validate_dependency_risk_custody_report.py",
        "cosign sign-blob",
        "dependency-risk-custody-verification-signature.sigstore.json",
        "objectGenerationsRecorded=true custodyVerified=true",
    )
    report_validator_required = (
        "--verification-public-key",
        "--signature-bundle",
        "--expected-verification-public-key-digest",
        "run_cosign(",
        '"verify-blob"',
        "signatureVerified=",
    )
    if any(fragment not in bootstrap for fragment in bootstrap_required):
        fail("dependency_risk_custody_bootstrap_contract_invalid")
    if any(fragment not in foundation for fragment in foundation_required):
        fail("dependency_risk_custody_foundation_contract_invalid")
    if any(fragment not in workflow for fragment in workflow_required):
        fail("dependency_risk_custody_workflow_contract_invalid")
    if any(fragment not in verification_script for fragment in script_required):
        fail("dependency_risk_custody_verification_script_contract_invalid")
    if any(fragment not in report_validator for fragment in report_validator_required):
        fail("dependency_risk_custody_report_validator_contract_invalid")

    authority_references = (
        "google_service_account.dependency_risk_custody_verifier.name",
        "orchestra-custody-verifier@",
    )
    allowed_iam_resources = {
        (
            "google_service_account_iam_member",
            "dependency_risk_custody_verification_wif",
        ),
        (
            "google_kms_crypto_key_iam_member",
            "dependency_risk_custody_collection_public_key",
        ),
        (
            "google_kms_crypto_key_iam_member",
            "dependency_risk_custody_verifier_signer",
        ),
        (
            "google_storage_managed_folder_iam_member",
            "dependency_risk_custody_raw_reader",
        ),
        (
            "google_storage_managed_folder_iam_member",
            "dependency_risk_custody_report_writer",
        ),
    }
    for resource_type, resource_name, block in _terraform_resource_blocks(
        bootstrap + "\n" + foundation
    ):
        if (
            "_iam_" in resource_type
            and any(reference in block for reference in authority_references)
            and (resource_type, resource_name) not in allowed_iam_resources
        ):
            fail("dependency_risk_custody_terraform_authority_invalid")
        if resource_type == "google_service_account_key" and (
            resource_name.startswith("dependency_risk_custody")
            or any(reference in block for reference in authority_references)
        ):
            fail("dependency_risk_custody_terraform_authority_invalid")

    workflow_forbidden = (
        "actions/upload-artifact@",
        "terraform apply",
        "gcloud artifacts docker images copy",
        "docker push",
        "gh workflow run",
        "sourceAdmissionAuthorized=true",
        "mirrorAuthorization=true",
        "activationAuthorized=true",
        "campaignEvidence=true",
    )
    if any(fragment in workflow for fragment in workflow_forbidden):
        fail("dependency_risk_custody_workflow_authority_invalid")
    if workflow.count("scripts/verify_and_publish_dependency_risk_custody.sh") != 1:
        fail("dependency_risk_custody_workflow_invocation_invalid")
    if (
        workflow.count(
            "scripts/verify_and_publish_sno_trial_dependency_risk_custody.sh"
        )
        != 1
        or "default: production-dependencies" not in workflow
        or "sno-trial-dependencies" not in workflow
    ):
        fail("dependency_risk_custody_workflow_invocation_invalid")

    upload_order = (
        'upload_create_only "$REPORT" "$REPORT_NAME"',
        'upload_create_only "$VERIFICATION_PUBLIC_KEY" "$REPORT_PUBLIC_KEY_NAME"',
        'upload_create_only "$REPORT_SIGNATURE" "$REPORT_SIGNATURE_NAME"',
    )
    positions = [verification_script.find(fragment) for fragment in upload_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        fail("dependency_risk_custody_completion_marker_order_invalid")


def validate_contract_and_implementation() -> str:
    authority, release_set, risk_policy = load_contract()
    digest = validate_authority(authority, release_set, risk_policy)
    validate_declared_implementation()
    return digest
