#!/usr/bin/env python3
"""Strict authority contract for independent foundation observation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.foundation_apply_execution import (
        EXPECTED_AUTHORITY_DIGEST as EXPECTED_APPLY_AUTHORITY_DIGEST,
        load_contract as load_apply_contract,
        validate_authority as validate_apply_authority,
    )
    from scripts.prerequisite_observation import (
        EXPECTED_POLICY_DIGEST,
        POLICY_PATH,
        blob_digest,
        validate_policy,
    )
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from foundation_apply_execution import (
        EXPECTED_AUTHORITY_DIGEST as EXPECTED_APPLY_AUTHORITY_DIGEST,
        load_contract as load_apply_contract,
        validate_authority as validate_apply_authority,
    )
    from prerequisite_observation import (
        EXPECTED_POLICY_DIGEST,
        POLICY_PATH,
        blob_digest,
        validate_policy,
    )
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, canonical_digest, load_json


AUTHORITY_PATH = ROOT / "config" / "foundation-observation.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
REPORT_SCHEMA = ROOT / "schemas" / "foundation-observation-v1.schema.json"
REPORT_MODULE = ROOT / "scripts" / "foundation_observation_report.py"
AUTHORITY_COLLECTOR = (
    ROOT / "scripts" / "collect_foundation_observer_authority.py"
)
OBSERVER_SCRIPT = ROOT / "scripts" / "observe_foundation_apply.sh"
BOOTSTRAP_TERRAFORM = ROOT / "infra" / "terraform" / "bootstrap" / "main.tf"
BOOTSTRAP_VARIABLES = ROOT / "infra" / "terraform" / "bootstrap" / "variables.tf"
BOOTSTRAP_OUTPUTS = ROOT / "infra" / "terraform" / "bootstrap" / "outputs.tf"
FOUNDATION_SOURCE_FILES = (
    ROOT / "infra" / "terraform" / "foundation" / "dns.tf",
    ROOT / "infra" / "terraform" / "foundation" / "locals.tf",
    ROOT / "infra" / "terraform" / "foundation" / "main.tf",
    ROOT / "infra" / "terraform" / "foundation" / "outputs.tf",
    ROOT / "infra" / "terraform" / "foundation" / "variables.tf",
    ROOT / "infra" / "terraform" / "foundation" / "versions.tf",
)
WORKFLOW = ROOT / ".github" / "workflows" / "foundation-observation.yml"

PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
TOPOLOGY_DIGEST = (
    "sha256:7c72982c74afd5d5ebdb1c5ea92054b477cd70cc604d7f14a1f4c348ec670fc5"
)
EXPECTED_AUTHORITY_DIGEST = (
    "sha256:bf1e225217a421ec222c767004ec1b87420a40a8c8ad8851e5b6a44fec2f9d93"
)
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REPOSITORY_ID = "1307302690"
REPOSITORY_OWNER_ID = "37515097"
ENVIRONMENT = "reference-lab-foundation-observation"
WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/foundation-observation.yml@refs/heads/main"
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


def source_tree_digest(paths: tuple[Path, ...]) -> str:
    return canonical_digest(
        {
            str(path.relative_to(ROOT)): blob_digest(path.read_bytes())
            for path in sorted(paths)
        }
    )


def load_contract() -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    apply_authority, _, _ = load_apply_contract()
    return (
        load_json(AUTHORITY_PATH),
        load_json(RELEASE_SET_PATH),
        load_json(POLICY_PATH),
        apply_authority,
    )


def expected_federation() -> dict[str, Any]:
    return {
        "poolId": "orchestra-lab-github",
        "providerId": "foundation-observation",
        "subject": f"foundation-observation:{REPOSITORY_ID}:{ENVIRONMENT}",
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


def expected_bindings(
    release_set: dict[str, Any],
    policy: dict[str, Any],
    apply_authority: dict[str, Any],
) -> dict[str, str]:
    validated_apply_digest = validate_apply_authority(
        apply_authority, release_set, policy
    )
    return {
        "topologyDigest": TOPOLOGY_DIGEST,
        "releaseSetDigest": validate_release_set(release_set),
        "prerequisitePolicyDigest": validate_policy(policy, release_set),
        "foundationApplyAuthorityDigest": validated_apply_digest,
        "reportSchemaDigest": blob_digest(REPORT_SCHEMA.read_bytes()),
        "reportModuleDigest": blob_digest(REPORT_MODULE.read_bytes()),
        "observerAuthorityCollectorDigest": blob_digest(
            AUTHORITY_COLLECTOR.read_bytes()
        ),
        "observerScriptDigest": blob_digest(OBSERVER_SCRIPT.read_bytes()),
        "bootstrapTerraformDigest": blob_digest(BOOTSTRAP_TERRAFORM.read_bytes()),
        "bootstrapVariablesDigest": blob_digest(BOOTSTRAP_VARIABLES.read_bytes()),
        "bootstrapOutputsDigest": blob_digest(BOOTSTRAP_OUTPUTS.read_bytes()),
        "foundationSourceDigest": source_tree_digest(FOUNDATION_SOURCE_FILES),
        "workflowDigest": blob_digest(WORKFLOW.read_bytes()),
    }


def validate_authority(
    value: dict[str, Any],
    release_set: dict[str, Any],
    policy: dict[str, Any],
    apply_authority: dict[str, Any],
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "authorityId",
            "profileId",
            "bindings",
            "observer",
            "federation",
            "kms",
            "storage",
            "workflow",
            "claim",
        },
        "foundation_observation_authority_keys_invalid",
    )
    bindings = expected_bindings(release_set, policy, apply_authority)
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.reference-lab.foundation-observation-authority.v1"
        or value["authorityId"] != "orchestra-foundation-observation-v1"
        or value["profileId"] != PROFILE_ID
        or value["bindings"] != bindings
        or bindings["prerequisitePolicyDigest"] != EXPECTED_POLICY_DIGEST
        or bindings["foundationApplyAuthorityDigest"]
        != EXPECTED_APPLY_AUTHORITY_DIGEST
    ):
        fail("foundation_observation_authority_identity_invalid")
    if value["observer"] != {
        "serviceAccountId": "orchestra-foundation-observer",
        "targetProjectRoles": [
            "roles/browser",
            "roles/compute.viewer",
            "roles/dns.reader",
            "roles/iam.securityReviewer",
            "roles/iam.serviceAccountViewer",
            "roles/serviceusage.serviceUsageConsumer",
        ],
        "servicesProjectRoles": [
            "roles/artifactregistry.reader",
            "roles/browser",
            "roles/cloudkms.viewer",
            "roles/compute.viewer",
            "roles/container.clusterViewer",
            "roles/dns.reader",
            "roles/iam.securityReviewer",
            "roles/iam.serviceAccountViewer",
            "roles/serviceusage.serviceUsageConsumer",
        ],
        "servicesProjectCustomRoles": [
            "orchestraFoundationStorageMetadataObserver"
        ],
        "ancestorProjectHierarchyRoles": ["roles/iam.securityReviewer"],
        "ancestorRoleExternallyManaged": True,
        "stateReadGranted": True,
        "planPackageReadGranted": True,
        "applyReceiptReadGranted": True,
        "reportObjectCreateGranted": True,
        "reportObjectReadGranted": False,
        "sourceObjectWriteGranted": False,
        "objectDeleteGranted": False,
        "stateLockGranted": False,
        "infrastructureMutationGranted": False,
        "artifactMirrorWriteGranted": False,
        "campaignAuthorityGranted": False,
        "userManagedServiceAccountKeyDeclared": False,
    }:
        fail("foundation_observation_boundary_invalid")
    if value["federation"] != expected_federation():
        fail("foundation_observation_federation_invalid")
    if value["kms"] != {
        "projectPlane": "services-evidence",
        "location": "europe-west1",
        "keyRingId": "orchestra-lab-foundation-execution",
        "planSigningKeyId": "foundation-plan-signing",
        "receiptSigningKeyId": "foundation-apply-receipt-signing",
        "observationSigningKeyId": "foundation-observation-signing",
        "sourceKeyRole": "roles/cloudkms.publicKeyViewer",
        "observationKeyRole": "roles/cloudkms.signerVerifier",
        "purpose": "ASYMMETRIC_SIGN",
        "algorithm": "EC_SIGN_P256_SHA256",
        "protectionLevel": "SOFTWARE",
        "exactVersionsRequired": True,
        "preventDestroy": True,
    }:
        fail("foundation_observation_kms_invalid")
    if value["storage"] != {
        "bucket": "bootstrap-state-bucket",
        "stateManagedFolder": "foundation/",
        "planManagedFolder": "foundation-plans/",
        "applyReportManagedFolder": "foundation-apply-reports/",
        "observationManagedFolder": "foundation-observations/",
        "observationPrefixTemplate": (
            "foundation-observations/v1/{profileId}/{sourceRevision}/"
            "{planId}/{applyId}/{observationId}"
        ),
        "requiredObservationObjectCount": 3,
        "generationPinnedDownloads": True,
        "metagenerationPinnedDownloads": True,
        "stateGenerationStableRequired": True,
        "completionMarker": "foundation-observation-signature.sigstore.json",
        "completionMarkerUploadedLast": True,
        "createOnlyGenerationPrecondition": 0,
        "valueBearingArtifactsUploadedToGitHub": False,
    }:
        fail("foundation_observation_storage_invalid")
    if value["workflow"] != {
        "path": ".github/workflows/foundation-observation.yml",
        "trigger": "workflow_dispatch",
        "exactMainRevisionRequired": True,
        "currentRunApprovalRequired": True,
        "rerunAllowed": False,
        "receiptSignatureVerificationRequired": True,
        "planSignatureVerificationRequired": True,
        "terraformRefreshOnly": True,
        "terraformStateLockUsed": False,
        "detailedExitCodeZeroRequired": True,
        "resourceIdentitySetMatchRequired": True,
        "stateReceiptMatchRequired": True,
        "stateGenerationStableRequired": True,
        "infrastructureMutationAllowed": False,
        "artifactMirrorOperationsAllowed": False,
        "campaignEvidence": False,
    }:
        fail("foundation_observation_workflow_invalid")
    if value["claim"] != {
        "terraformDeclared": True,
        "workflowDeclared": True,
        "bootstrapApplied": False,
        "foundationApplied": False,
        "applyReceiptVerified": False,
        "providerRefreshExecuted": False,
        "observationPublished": False,
        "independentlyObserved": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }:
        fail("foundation_observation_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_AUTHORITY_DIGEST:
        fail(f"foundation_observation_authority_digest_changed:{digest}")
    return digest


def _read(path: Path, code: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(code) from error


def validate_declared_implementation() -> None:
    bootstrap = _read(
        BOOTSTRAP_TERRAFORM, "foundation_observation_bootstrap_missing"
    )
    outputs = _read(BOOTSTRAP_OUTPUTS, "foundation_observation_outputs_missing")
    workflow = _read(WORKFLOW, "foundation_observation_workflow_missing")
    observer_script = _read(
        OBSERVER_SCRIPT, "foundation_observation_script_missing"
    )
    required_bootstrap = (
        'workload_identity_pool_provider_id = "foundation-observation"',
        'account_id   = "orchestra-foundation-observer"',
        'name     = "foundation-observation-signing"',
        'name          = "foundation-observations/"',
        'resource "google_service_account_iam_member" "foundation_observation_wif"',
        'resource "google_project_iam_member" "foundation_observer"',
        'resource "google_project_iam_custom_role" "foundation_storage_metadata_observer"',
        'resource "google_storage_managed_folder_iam_member" "foundation_observer_state_reader"',
        'resource "google_storage_managed_folder_iam_member" "foundation_observer_plan_reader"',
        'resource "google_storage_managed_folder_iam_member" "foundation_observer_receipt_reader"',
        'resource "google_storage_managed_folder_iam_member" "foundation_observer_report_writer"',
        'role           = "roles/storage.objectCreator"',
        '"storage.buckets.getIamPolicy"',
    )
    if any(item not in bootstrap for item in required_bootstrap):
        fail("foundation_observation_bootstrap_contract_missing")
    for output_name in (
        'output "foundation_observation_workload_identity_provider"',
        'output "foundation_observation_service_account"',
        'output "foundation_observation_contract"',
    ):
        if output_name not in outputs:
            fail("foundation_observation_output_contract_missing")
    required_workflow = (
        "environment: reference-lab-foundation-observation",
        "github.ref == 'refs/heads/main'",
        "--contract foundation-observation",
        "persist-credentials: false",
        "observe_foundation_apply.sh",
        "GITHUB_RUN_ATTEMPT",
    )
    if any(item not in workflow for item in required_workflow):
        fail("foundation_observation_workflow_contract_missing")
    forbidden_workflow = (
        "terraform apply",
        "terraform destroy",
        "-auto-approve",
        "artifactregistry repositories",
        "campaignEvidence=true",
        "referenceProfileVerified=true",
    )
    if any(item in workflow for item in forbidden_workflow):
        fail("foundation_observation_workflow_boundary_invalid")
    required_script = (
        "--if-generation-match=",
        "--if-metageneration-match=",
        "terraform -chdir=\"$FOUNDATION_DIR\" plan",
        "-refresh-only",
        "-lock=false",
        "-detailed-exitcode",
        "foundation-observation-signature.sigstore.json",
        "--if-generation-match=0",
        "campaignEvidence=false",
        "referenceProfileVerified=false",
    )
    if any(item not in observer_script for item in required_script):
        fail("foundation_observation_script_contract_missing")
    forbidden_script = (
        "terraform apply",
        "terraform destroy",
        "-auto-approve",
        "gcloud artifacts",
        "campaignEvidence=true",
        "referenceProfileVerified=true",
    )
    if any(item in observer_script for item in forbidden_script):
        fail("foundation_observation_script_boundary_invalid")


def validate_contract_and_implementation() -> str:
    authority, release_set, policy, apply_authority = load_contract()
    digest = validate_authority(
        authority, release_set, policy, apply_authority
    )
    validate_declared_implementation()
    return digest
