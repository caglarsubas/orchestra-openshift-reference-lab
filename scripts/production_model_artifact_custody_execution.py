#!/usr/bin/env python3
"""Validate source-declared production model custody cloud authority."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.production_model_artifact_custody import (
        EXPECTED_POLICY_DIGEST,
        load_contract_inputs as load_custody_contract_inputs,
        validate_policy as validate_custody_policy,
    )
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import (
        ROOT,
        canonical_digest,
        load_json,
        validate_lock,
    )
except ModuleNotFoundError:
    from production_model_artifact_custody import (
        EXPECTED_POLICY_DIGEST,
        load_contract_inputs as load_custody_contract_inputs,
        validate_policy as validate_custody_policy,
    )
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, canonical_digest, load_json, validate_lock


AUTHORITY_PATH = (
    ROOT / "config" / "production-model-artifact-custody-execution.lock.json"
)
TOPOLOGY_PATH = ROOT / "config" / "lab.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
BOOTSTRAP_TERRAFORM_PATH = (
    ROOT / "infra" / "terraform" / "bootstrap" / "production_model_custody.tf"
)
BOOTSTRAP_OUTPUTS_PATH = (
    ROOT
    / "infra"
    / "terraform"
    / "bootstrap"
    / "production_model_custody_outputs.tf"
)
FOUNDATION_TERRAFORM_PATH = (
    ROOT / "infra" / "terraform" / "foundation" / "production_model_custody.tf"
)
FOUNDATION_VARIABLES_PATH = (
    ROOT
    / "infra"
    / "terraform"
    / "foundation"
    / "production_model_custody_variables.tf"
)
FOUNDATION_OUTPUTS_PATH = (
    ROOT
    / "infra"
    / "terraform"
    / "foundation"
    / "production_model_custody_outputs.tf"
)
WORKFLOW_PATH = (
    ROOT
    / ".github"
    / "workflows"
    / "production-model-artifact-custody.yml"
)
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
EXPECTED_AUTHORITY_DIGEST = (
    "sha256:06177cea76457b3ba7bee48521eb02a7ecfbaec93ded4c157099b277e0eb4195"
)
EXPECTED_TOPOLOGY_DIGEST = (
    "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0"
)
EXPECTED_RELEASE_SET_DIGEST = (
    "sha256:4f571fade2a1566a53d797c82561f30292734fcfcc75b23667dc08007ee8b6fe"
)
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REPOSITORY_ID = "1307302690"
REPOSITORY_OWNER_ID = "37515097"
WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/"
    "production-model-artifact-custody.yml@refs/heads/main"
)
UPLOADER_ID = "orchestra-model-custody-writer"
VERIFIER_ID = "orchestra-model-custody-verify"
UPLOADER_ENVIRONMENT = "reference-lab-production-model-custody-upload"
VERIFIER_ENVIRONMENT = "reference-lab-production-model-custody-verification"


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def blob_digest(path: Path) -> str:
    try:
        content = path.read_bytes()
    except OSError as error:
        raise ValueError(
            f"production_model_custody_authority_file_missing:{path.relative_to(ROOT)}"
        ) from error
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def load_contract() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    tuple[dict[str, Any], ...],
]:
    custody_inputs = load_custody_contract_inputs()
    return (
        load_json(AUTHORITY_PATH),
        load_json(TOPOLOGY_PATH),
        load_json(RELEASE_SET_PATH),
        custody_inputs,
    )


def expected_bindings(
    topology: dict[str, Any],
    release_set: dict[str, Any],
    custody_inputs: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    candidate, source_policy, policy, custody_schema, review_schema = custody_inputs
    validate_lock(topology)
    topology_digest = canonical_digest(topology)
    release_set_digest = validate_release_set(release_set)
    policy_digest = validate_custody_policy(
        policy, candidate, source_policy, custody_schema, review_schema
    )
    if (
        topology_digest != EXPECTED_TOPOLOGY_DIGEST
        or release_set_digest != EXPECTED_RELEASE_SET_DIGEST
        or policy_digest != EXPECTED_POLICY_DIGEST
    ):
        fail("production_model_custody_authority_upstream_invalid")
    return {
        "topologyDigest": topology_digest,
        "releaseSetDigest": release_set_digest,
        "candidateDigest": candidate["candidateDigest"],
        "custodyPolicyDigest": policy_digest,
        "bootstrapTerraformDigest": blob_digest(BOOTSTRAP_TERRAFORM_PATH),
        "bootstrapOutputsDigest": blob_digest(BOOTSTRAP_OUTPUTS_PATH),
        "foundationTerraformDigest": blob_digest(FOUNDATION_TERRAFORM_PATH),
        "foundationVariablesDigest": blob_digest(FOUNDATION_VARIABLES_PATH),
        "foundationOutputsDigest": blob_digest(FOUNDATION_OUTPUTS_PATH),
    }


def validate_authority(
    value: dict[str, Any],
    topology: dict[str, Any],
    release_set: dict[str, Any],
    custody_inputs: tuple[dict[str, Any], ...],
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "authorityId",
            "profileId",
            "targetClass",
            "bindings",
            "storage",
            "kms",
            "identities",
            "federation",
            "workflowReservation",
            "claim",
        },
        "production_model_custody_authority_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.openshift.production-model-artifact-custody-authority.v1"
        or value["authorityId"]
        != "orchestra-production-model-artifact-custody-authority-v1"
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
    ):
        fail("production_model_custody_authority_identity_invalid")
    if value["bindings"] != expected_bindings(
        topology, release_set, custody_inputs
    ):
        fail("production_model_custody_authority_bindings_invalid")
    if value["storage"] != {
        "projectPlane": "services-evidence",
        "region": "europe-west1",
        "bucketNameOverrideInput": "production_model_artifact_bucket_name",
        "defaultBucketNameTemplate": "{servicesProjectId}-production-model-artifacts",
        "dedicatedBucketRequired": True,
        "artifactManagedFolder": "production-model-artifacts/",
        "signedRecordManagedFolder": "production-model-custody/",
        "cmekRequired": True,
        "uniformBucketLevelAccess": True,
        "publicAccessPrevention": "enforced",
        "versioningRequired": True,
        "objectRetentionRequired": True,
        "retentionDays": 400,
        "retentionLocked": False,
        "eventBasedHoldRequiredPerArtifact": True,
        "preventDestroy": True,
    }:
        fail("production_model_custody_authority_storage_invalid")
    if value["kms"] != {
        "keyRingId": "orchestra-reference-evidence",
        "encryptionKeyId": "production-model-artifact-custody",
        "encryptionKeyPurpose": "ENCRYPT_DECRYPT",
        "storageAgentRole": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "verificationSigningKeyId": (
            "production-model-artifact-custody-verification-signing"
        ),
        "verificationSigningPurpose": "ASYMMETRIC_SIGN",
        "verificationSigningAlgorithm": "EC_SIGN_P256_SHA256",
        "verificationSigningProtectionLevel": "SOFTWARE",
        "verifierSigningRole": "roles/cloudkms.signerVerifier",
        "preventDestroy": True,
    }:
        fail("production_model_custody_authority_kms_invalid")
    if value["identities"] != {
        "uploader": {
            "serviceAccountId": UPLOADER_ID,
            "projectRoles": [],
            "artifactManagedFolderRole": "roles/storage.objectCreator",
            "artifactCreateGranted": True,
            "artifactReadGranted": False,
            "artifactDeleteGranted": False,
            "signedRecordAccessGranted": False,
            "userManagedServiceAccountKeyDeclared": False,
        },
        "verifier": {
            "serviceAccountId": VERIFIER_ID,
            "projectRoles": [],
            "artifactManagedFolderRole": "roles/storage.objectViewer",
            "artifactReadGranted": True,
            "artifactWriteGranted": False,
            "artifactDeleteGranted": False,
            "signedRecordManagedFolderRole": "roles/storage.objectCreator",
            "signedRecordCreateGranted": True,
            "signedRecordReadGranted": False,
            "signedRecordDeleteGranted": False,
            "userManagedServiceAccountKeyDeclared": False,
        },
        "uploaderAndVerifierDistinct": True,
        "artifactMirrorWriteGranted": False,
        "sourceAdmissionAuthorityGranted": False,
        "deploymentAuthorityGranted": False,
        "campaignAuthorityGranted": False,
    }:
        fail("production_model_custody_authority_identity_boundary_invalid")
    if value["federation"] != {
        "poolId": "orchestra-lab-github",
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "repositoryOwnerId": REPOSITORY_OWNER_ID,
        "repositoryVisibility": "private",
        "deploymentBranch": "main",
        "trigger": "workflow_dispatch",
        "workflowRef": WORKFLOW_REF,
        "uploaderProviderId": "production-model-custody-upload",
        "uploaderEnvironment": UPLOADER_ENVIRONMENT,
        "uploaderMinimumIndependentReviewers": 1,
        "verifierProviderId": "production-model-custody-verify",
        "verifierEnvironment": VERIFIER_ENVIRONMENT,
        "verifierMinimumIndependentReviewers": 1,
        "preventSelfReview": True,
    }:
        fail("production_model_custody_authority_federation_invalid")
    if value["workflowReservation"] != {
        "path": ".github/workflows/production-model-artifact-custody.yml",
        "declared": False,
        "protectedEnvironmentsConfigured": False,
        "exactMainRevisionRequired": True,
        "currentRunApprovalRequired": True,
        "rerunAllowed": False,
        "localRestrictedDirectoryReadableByGitHubHostedRunner": False,
        "transferBoundaryDecisionRequired": True,
        "artifactDownloadPerformed": False,
        "artifactCopyPerformed": False,
        "signedCustodyRecordPublished": False,
    }:
        fail("production_model_custody_authority_workflow_boundary_invalid")
    if value["claim"] != {
        "terraformDeclared": True,
        "workflowDeclared": False,
        "applied": False,
        "storageProvisioned": False,
        "protectedEnvironmentsConfigured": False,
        "liveIdentityVerified": False,
        "liveKmsVerified": False,
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
        fail("production_model_custody_authority_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_AUTHORITY_DIGEST:
        fail(f"production_model_custody_authority_digest_changed:{digest}")
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
            fail("production_model_custody_terraform_resource_unclosed")
        blocks.append((match.group(1), match.group(2), content[match.start() : end]))
    return blocks


def validate_declared_implementation(authority: dict[str, Any]) -> None:
    bootstrap = _read(
        BOOTSTRAP_TERRAFORM_PATH,
        "production_model_custody_bootstrap_terraform_missing",
    )
    bootstrap_outputs = _read(
        BOOTSTRAP_OUTPUTS_PATH,
        "production_model_custody_bootstrap_outputs_missing",
    )
    foundation = _read(
        FOUNDATION_TERRAFORM_PATH,
        "production_model_custody_foundation_terraform_missing",
    )
    foundation_variables = _read(
        FOUNDATION_VARIABLES_PATH,
        "production_model_custody_foundation_variables_missing",
    )
    foundation_outputs = _read(
        FOUNDATION_OUTPUTS_PATH,
        "production_model_custody_foundation_outputs_missing",
    )
    if WORKFLOW_PATH.exists() or authority["workflowReservation"]["declared"]:
        fail("production_model_custody_workflow_unexpected")

    required_bootstrap = (
        'workload_identity_pool_provider_id = "production-model-custody-upload"',
        'workload_identity_pool_provider_id = "production-model-custody-verify"',
        'account_id   = "orchestra-model-custody-writer"',
        'account_id   = "orchestra-model-custody-verify"',
        "assertion.repository_visibility == 'private'",
        "assertion.ref == 'refs/heads/main'",
        "assertion.event_name == 'workflow_dispatch'",
        "production-model-artifact-custody.yml@refs/heads/main",
        'resource "google_service_account_iam_member" "production_model_custody_upload_wif"',
        'resource "google_service_account_iam_member" "production_model_custody_verify_wif"',
    )
    required_foundation = (
        'name            = "production-model-artifact-custody"',
        'purpose         = "ENCRYPT_DECRYPT"',
        'name     = "production-model-artifact-custody-verification-signing"',
        'purpose  = "ASYMMETRIC_SIGN"',
        'algorithm        = "EC_SIGN_P256_SHA256"',
        'public_access_prevention    = "enforced"',
        "uniform_bucket_level_access = true",
        "enable_object_retention     = true",
        "retention_period = 400 * 24 * 60 * 60",
        "prevent_destroy = true",
        'name            = "production-model-artifacts/"',
        'name            = "production-model-custody/"',
        'role           = "roles/storage.objectCreator"',
        'role           = "roles/storage.objectViewer"',
        "orchestra-model-custody-writer@${var.services_project_id}.iam.gserviceaccount.com",
        "orchestra-model-custody-verify@${var.services_project_id}.iam.gserviceaccount.com",
        'role          = "roles/cloudkms.signerVerifier"',
    )
    required_outputs = (
        "workflow_declared  = false",
        "campaign_authority = false",
        "uploader_read_granted",
        "verifier_artifact_write_granted",
        "source_admission_authority_granted",
        "deployment_authority_granted",
        "campaign_authority_granted",
    )
    if any(fragment not in bootstrap for fragment in required_bootstrap):
        fail("production_model_custody_bootstrap_contract_invalid")
    if any(fragment not in foundation for fragment in required_foundation):
        fail("production_model_custody_foundation_contract_invalid")
    if any(
        fragment not in bootstrap_outputs + foundation_outputs
        for fragment in required_outputs
    ):
        fail("production_model_custody_output_contract_invalid")
    if (
        'variable "production_model_artifact_bucket_name"' not in foundation_variables
        or 'default     = ""' not in foundation_variables
        or '"${var.services_project_id}-production-model-artifacts"'
        not in foundation
        or "local.production_model_artifact_bucket_name != var.signed_evidence_bucket_name"
        not in foundation
        or "local.production_model_artifact_bucket_name != var.raw_evidence_bucket_name"
        not in foundation
    ):
        fail("production_model_custody_dedicated_bucket_contract_invalid")

    all_terraform = "\n".join(
        path.read_text(encoding="utf-8")
        for directory in (
            ROOT / "infra" / "terraform" / "bootstrap",
            ROOT / "infra" / "terraform" / "foundation",
        )
        for path in sorted(directory.glob("*.tf"))
    )
    if 'resource "google_service_account_key"' in all_terraform:
        fail("production_model_custody_static_key_resource_forbidden")
    allowed_identity_iam = {
        (
            "google_service_account_iam_member",
            "production_model_custody_upload_wif",
        ),
        (
            "google_service_account_iam_member",
            "production_model_custody_verify_wif",
        ),
        (
            "google_kms_crypto_key_iam_member",
            "production_model_custody_verifier_signer",
        ),
        (
            "google_storage_managed_folder_iam_member",
            "production_model_custody_writer",
        ),
        (
            "google_storage_managed_folder_iam_member",
            "production_model_custody_artifact_reader",
        ),
        (
            "google_storage_managed_folder_iam_member",
            "production_model_custody_record_writer",
        ),
    }
    identity_references = (
        "google_service_account.production_model_custody_writer",
        "google_service_account.production_model_custody_verifier",
        "orchestra-model-custody-writer@",
        "orchestra-model-custody-verify@",
    )
    for resource_type, resource_name, block in _terraform_resource_blocks(
        all_terraform
    ):
        if (
            "_iam_" in resource_type
            and any(reference in block for reference in identity_references)
            and (resource_type, resource_name) not in allowed_identity_iam
        ):
            fail(
                "production_model_custody_iam_scope_invalid:"
                f"{resource_type}.{resource_name}"
            )

    if len(UPLOADER_ID) > 30 or len(VERIFIER_ID) > 30:
        fail("production_model_custody_service_account_id_too_long")


def validate_contract_and_implementation() -> str:
    authority, topology, release_set, custody_inputs = load_contract()
    digest = validate_authority(authority, topology, release_set, custody_inputs)
    validate_declared_implementation(authority)
    return digest


def main() -> int:
    digest = validate_contract_and_implementation()
    print(
        "productionModelCustodyAuthorityValid=true "
        f"digest={digest} terraformDeclared=true workflowDeclared=false "
        "applied=false artifactCustodyVerified=false licenseApproved=false "
        "admissionAuthorized=false campaignEvidence=false "
        "referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
