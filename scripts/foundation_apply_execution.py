#!/usr/bin/env python3
"""Strict authority contract for review-bound foundation application."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.prerequisite_observation import (
        EXPECTED_POLICY_DIGEST,
        POLICY_PATH,
        blob_digest,
        validate_policy,
    )
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from prerequisite_observation import (
        EXPECTED_POLICY_DIGEST,
        POLICY_PATH,
        blob_digest,
        validate_policy,
    )
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, canonical_digest, load_json


AUTHORITY_PATH = ROOT / "config" / "foundation-apply-execution.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
PLAN_SUMMARY_SCHEMA = ROOT / "schemas" / "foundation-plan-summary-v1.schema.json"
PLAN_PACKAGE_SCHEMA = ROOT / "schemas" / "foundation-plan-package-v1.schema.json"
APPLY_RECEIPT_SCHEMA = ROOT / "schemas" / "foundation-apply-receipt-v1.schema.json"
PLAN_PACKAGE_MODULE = ROOT / "scripts" / "foundation_plan_package.py"
PLAN_PUBLISHER = ROOT / "scripts" / "publish_foundation_plan_package.sh"
PLAN_REVIEWER = ROOT / "scripts" / "review_foundation_plan_package.sh"
PLAN_VERIFIER = ROOT / "scripts" / "verify_foundation_plan_package.py"
APPLY_RECEIPT_MODULE = ROOT / "scripts" / "foundation_apply_receipt.py"
APPLY_SCRIPT = ROOT / "scripts" / "verify_and_apply_foundation_plan.sh"
BOOTSTRAP_TERRAFORM = ROOT / "infra" / "terraform" / "bootstrap" / "main.tf"
BOOTSTRAP_VARIABLES = ROOT / "infra" / "terraform" / "bootstrap" / "variables.tf"
BOOTSTRAP_OUTPUTS = ROOT / "infra" / "terraform" / "bootstrap" / "outputs.tf"
PLAN_WORKFLOW = ROOT / ".github" / "workflows" / "foundation-plan.yml"
APPLY_WORKFLOW = ROOT / ".github" / "workflows" / "foundation-apply.yml"

PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
TOPOLOGY_DIGEST = (
    "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0"
)
EXPECTED_AUTHORITY_DIGEST = (
    "sha256:6d658bc8cba37642dbca5bf7370c00dced6b1f312e71ad2c4f531101f2ab4d7d"
)
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REPOSITORY_ID = "1307302690"
REPOSITORY_OWNER_ID = "37515097"
PLAN_ENVIRONMENT = "reference-lab-foundation-plan"
PLAN_WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/foundation-plan.yml@refs/heads/main"
)
APPLY_ENVIRONMENT = "reference-lab-foundation-apply"
APPLY_WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/foundation-apply.yml@refs/heads/main"
)
APPLY_ATTRIBUTE_CONDITION = " && ".join(
    (
        f"assertion.repository == '{REPOSITORY}'",
        f"assertion.repository_id == '{REPOSITORY_ID}'",
        f"assertion.repository_owner_id == '{REPOSITORY_OWNER_ID}'",
        "assertion.repository_visibility == 'private'",
        "assertion.ref == 'refs/heads/main'",
        "assertion.event_name == 'workflow_dispatch'",
        f"assertion.workflow_ref == '{APPLY_WORKFLOW_REF}'",
        f"assertion.environment == '{APPLY_ENVIRONMENT}'",
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
        load_json(POLICY_PATH),
    )


def expected_apply_federation() -> dict[str, Any]:
    return {
        "poolId": "orchestra-lab-github",
        "providerId": "foundation-apply",
        "subject": f"foundation-apply:{REPOSITORY_ID}:{APPLY_ENVIRONMENT}",
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "repositoryOwnerId": REPOSITORY_OWNER_ID,
        "repositoryVisibility": "private",
        "workflowRef": APPLY_WORKFLOW_REF,
        "environment": APPLY_ENVIRONMENT,
        "minimumIndependentReviewers": 1,
        "reviewerType": "User",
        "preventSelfReview": True,
        "deploymentBranch": "main",
        "attributeCondition": APPLY_ATTRIBUTE_CONDITION,
    }


def expected_bindings(
    release_set: dict[str, Any], policy: dict[str, Any]
) -> dict[str, str]:
    return {
        "topologyDigest": TOPOLOGY_DIGEST,
        "releaseSetDigest": validate_release_set(release_set),
        "prerequisitePolicyDigest": validate_policy(policy, release_set),
        "foundationPlanSummarySchemaDigest": blob_digest(
            PLAN_SUMMARY_SCHEMA.read_bytes()
        ),
        "planPackageSchemaDigest": blob_digest(PLAN_PACKAGE_SCHEMA.read_bytes()),
        "applyReceiptSchemaDigest": blob_digest(APPLY_RECEIPT_SCHEMA.read_bytes()),
        "planPackageModuleDigest": blob_digest(PLAN_PACKAGE_MODULE.read_bytes()),
        "planPublisherDigest": blob_digest(PLAN_PUBLISHER.read_bytes()),
        "planReviewerScriptDigest": blob_digest(PLAN_REVIEWER.read_bytes()),
        "planVerifierDigest": blob_digest(PLAN_VERIFIER.read_bytes()),
        "applyReceiptModuleDigest": blob_digest(APPLY_RECEIPT_MODULE.read_bytes()),
        "applyScriptDigest": blob_digest(APPLY_SCRIPT.read_bytes()),
        "bootstrapTerraformDigest": blob_digest(BOOTSTRAP_TERRAFORM.read_bytes()),
        "bootstrapVariablesDigest": blob_digest(BOOTSTRAP_VARIABLES.read_bytes()),
        "bootstrapOutputsDigest": blob_digest(BOOTSTRAP_OUTPUTS.read_bytes()),
        "planWorkflowDigest": blob_digest(PLAN_WORKFLOW.read_bytes()),
        "applyWorkflowDigest": blob_digest(APPLY_WORKFLOW.read_bytes()),
    }


def validate_authority(
    value: dict[str, Any],
    release_set: dict[str, Any],
    policy: dict[str, Any],
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "authorityId",
            "profileId",
            "bindings",
            "planPublisher",
            "planReviewer",
            "applyExecutor",
            "planFederation",
            "applyFederation",
            "kms",
            "storage",
            "workflow",
            "claim",
        },
        "foundation_apply_authority_keys_invalid",
    )
    bindings = expected_bindings(release_set, policy)
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.reference-lab.foundation-apply-authority.v1"
        or value["authorityId"] != "orchestra-reference-lab-foundation-apply-v1"
        or value["profileId"] != PROFILE_ID
        or value["bindings"] != bindings
        or bindings["prerequisitePolicyDigest"] != EXPECTED_POLICY_DIGEST
    ):
        fail("foundation_apply_authority_identity_invalid")
    if value["planPublisher"] != {
        "serviceAccountId": "orchestra-plan-packager",
        "projectRoles": [],
        "stateReadGranted": False,
        "planObjectCreateGranted": True,
        "planObjectReadGranted": False,
        "planObjectDeleteGranted": False,
        "infrastructureMutationGranted": False,
        "userManagedServiceAccountKeyDeclared": False,
    }:
        fail("foundation_apply_plan_publisher_boundary_invalid")
    if value["planReviewer"] != {
        "principalType": "group",
        "managedFolder": "foundation-plans/",
        "role": "roles/storage.objectViewer",
        "packageReadGranted": True,
        "stateReadGranted": False,
        "objectWriteGranted": False,
        "objectDeleteGranted": False,
        "infrastructureMutationGranted": False,
        "requiredBeforeApply": True,
    }:
        fail("foundation_apply_plan_reviewer_boundary_invalid")
    if value["applyExecutor"] != {
        "serviceAccountId": "orchestra-lab-foundation",
        "exactProjectRolesRequired": True,
        "stateLockRequired": True,
        "planObjectReadGranted": True,
        "planObjectWriteGranted": True,
        "receiptObjectCreateGranted": True,
        "infrastructureMutationGranted": True,
        "artifactMirrorWriteGranted": True,
        "campaignAuthorityGranted": False,
        "userManagedServiceAccountKeyDeclared": False,
    }:
        fail("foundation_apply_executor_boundary_invalid")
    if value["planFederation"] != {
        "poolId": "orchestra-lab-github",
        "providerId": "github",
        "subject": f"github:{REPOSITORY_ID}:{PLAN_ENVIRONMENT}",
        "workflowRef": PLAN_WORKFLOW_REF,
        "environment": PLAN_ENVIRONMENT,
    }:
        fail("foundation_apply_plan_federation_invalid")
    if value["applyFederation"] != expected_apply_federation():
        fail("foundation_apply_federation_invalid")
    if value["kms"] != {
        "projectPlane": "services-evidence",
        "location": "europe-west1",
        "keyRingId": "orchestra-lab-foundation-execution",
        "planSigningKeyId": "foundation-plan-signing",
        "applyReceiptSigningKeyId": "foundation-apply-receipt-signing",
        "purpose": "ASYMMETRIC_SIGN",
        "algorithm": "EC_SIGN_P256_SHA256",
        "protectionLevel": "SOFTWARE",
        "role": "roles/cloudkms.signerVerifier",
        "exactVersionsRequired": True,
        "preventDestroy": True,
    }:
        fail("foundation_apply_kms_invalid")
    if value["storage"] != {
        "bucket": "bootstrap-state-bucket",
        "planManagedFolder": "foundation-plans/",
        "planPrefixTemplate": (
            "foundation-plans/v1/{profileId}/{sourceRevision}/{planId}"
        ),
        "requiredPlanObjectCount": 5,
        "generationPinnedDownloads": True,
        "metagenerationPinnedDownloads": True,
        "planCompletionMarker": "foundation-plan-package-signature.sigstore.json",
        "planCompletionMarkerUploadedLast": True,
        "applyReportManagedFolder": "foundation-apply-reports/",
        "applyReportPrefixTemplate": (
            "foundation-apply-reports/v1/{profileId}/{sourceRevision}/"
            "{planId}/{applyId}"
        ),
        "applyReportCompletionMarker": (
            "foundation-apply-receipt-signature.sigstore.json"
        ),
        "applyReportCompletionMarkerUploadedLast": True,
        "createOnlyGenerationPrecondition": 0,
        "valueBearingArtifactsUploadedToGitHub": False,
    }:
        fail("foundation_apply_storage_invalid")
    if value["workflow"] != {
        "planPath": ".github/workflows/foundation-plan.yml",
        "applyPath": ".github/workflows/foundation-apply.yml",
        "trigger": "workflow_dispatch",
        "exactMainRevisionRequired": True,
        "currentRunApprovalRequired": True,
        "rerunAllowed": False,
        "maximumPlanAgeHours": 24,
        "exactSavedPlanRequired": True,
        "securePlanReviewRequired": True,
        "stateLockRequired": True,
        "destructiveActionsAllowed": False,
        "artifactMirrorOperationsAllowed": False,
        "receiptSelfAttested": True,
        "independentPostApplyObservationRequired": True,
        "campaignEvidence": False,
    }:
        fail("foundation_apply_workflow_invalid")
    if value["claim"] != {
        "terraformDeclared": True,
        "workflowsDeclared": True,
        "bootstrapApplied": False,
        "foundationPlanPublished": False,
        "foundationApplied": False,
        "applyReceiptPublished": False,
        "independentlyObserved": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("foundation_apply_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_AUTHORITY_DIGEST:
        fail(f"foundation_apply_authority_digest_changed:{digest}")
    return digest


def _read(path: Path, code: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(code) from error


def validate_declared_implementation() -> None:
    bootstrap = _read(BOOTSTRAP_TERRAFORM, "foundation_apply_bootstrap_missing")
    bootstrap_variables = _read(
        BOOTSTRAP_VARIABLES, "foundation_apply_bootstrap_variables_missing"
    )
    outputs = _read(BOOTSTRAP_OUTPUTS, "foundation_apply_outputs_missing")
    plan_workflow = _read(PLAN_WORKFLOW, "foundation_apply_plan_workflow_missing")
    apply_workflow = _read(APPLY_WORKFLOW, "foundation_apply_workflow_missing")
    publisher_script = _read(
        PLAN_PUBLISHER, "foundation_plan_publisher_script_missing"
    )
    review_script = _read(PLAN_REVIEWER, "foundation_plan_reviewer_script_missing")
    apply_script = _read(APPLY_SCRIPT, "foundation_apply_script_missing")

    required_bootstrap = (
        'resource "google_iam_workload_identity_pool_provider" "foundation_apply"',
        'workload_identity_pool_provider_id = "foundation-apply"',
        "\"google.subject\"                  = \"'foundation-apply:' + assertion.repository_id + ':' + assertion.environment\"",
        'resource "google_service_account" "foundation_plan_packager"',
        'account_id   = "orchestra-plan-packager"',
        'resource "google_service_account_iam_member" "foundation_plan_packager_wif"',
        'resource "google_service_account_iam_member" "foundation_apply_wif"',
        'resource "google_kms_key_ring" "foundation_execution"',
        'name     = "orchestra-lab-foundation-execution"',
        'name     = "foundation-plan-signing"',
        'name     = "foundation-apply-receipt-signing"',
        'resource "google_storage_managed_folder" "foundation_plans"',
        'name          = "foundation-plans/"',
        'resource "google_storage_managed_folder" "foundation_apply_reports"',
        'name          = "foundation-apply-reports/"',
        'resource "google_storage_managed_folder_iam_member" "foundation_plan_reviewer"',
        'role           = "roles/storage.objectViewer"',
    )
    if any(item not in bootstrap for item in required_bootstrap):
        fail("foundation_apply_bootstrap_contract_missing")
    forbidden_bootstrap = (
        "principalSet://",
        'account_id   = "orchestra-plan-packager"\n  disabled',
    )
    if any(item in bootstrap for item in forbidden_bootstrap):
        fail("foundation_apply_bootstrap_boundary_invalid")
    required_reviewer_variable = (
        'variable "foundation_plan_reviewer_members"',
        "length(var.foundation_plan_reviewer_members) >= 1",
        'can(regex("^group:[^@]+@[^@]+$", member))',
    )
    if (
        any(item not in bootstrap_variables for item in required_reviewer_variable)
        or re.search(
            r'variable "foundation_plan_reviewer_members"\s*\{[^}]*'
            r"default\s*=",
            bootstrap_variables,
            flags=re.DOTALL,
        )
    ):
        fail("foundation_apply_plan_reviewer_variable_invalid")
    for output_name in (
        'output "foundation_apply_workload_identity_provider"',
        'output "foundation_plan_packager_service_account"',
        'output "foundation_apply_execution_contract"',
    ):
        if output_name not in outputs:
            fail("foundation_apply_output_contract_missing")

    if (
        "terraform -chdir=infra/terraform/foundation apply" in plan_workflow
        or "publish_foundation_plan_package.sh" not in plan_workflow
        or "ENVIRONMENT_APPROVAL_DIGEST" not in plan_workflow
        or "persist-credentials: false" not in plan_workflow
    ):
        fail("foundation_apply_plan_workflow_boundary_invalid")
    publisher_required = (
        "https://storage.googleapis.com/upload/storage/v1/b/",
        "uploadType=media",
        "ifGenerationMatch=0",
        "gcloud auth print-access-token",
        "foundation-plan-package-signature.sigstore.json",
    )
    if (
        any(item not in publisher_script for item in publisher_required)
        or "gcloud storage cp" in publisher_script
        or "gcloud storage ls" in publisher_script
    ):
        fail("foundation_apply_plan_publisher_script_boundary_invalid")
    apply_required = (
        "environment: reference-lab-foundation-apply",
        "github.ref == 'refs/heads/main'",
        "workflow-run-attempt",
        "--contract foundation-apply",
        "persist-credentials: false",
        "FOUNDATION_PLAN_REVIEW_ACCESS_CONFIGURED",
        "verify_and_apply_foundation_plan.sh",
        "TF_VAR_certification_mode: \"false\"",
        "TF_VAR_lock_signed_evidence_bucket: \"false\"",
    )
    if any(item not in apply_workflow for item in apply_required):
        fail("foundation_apply_workflow_contract_missing")
    forbidden_apply = (
        "terraform destroy",
        "-auto-approve",
        "artifactregistry repositories",
        "campaignEvidence=true",
        "referenceProfileVerified=true",
    )
    if any(item in apply_workflow for item in forbidden_apply):
        fail("foundation_apply_workflow_boundary_invalid")
    script_required = (
        "--if-generation-match=",
        "--if-metageneration-match=",
        "https://storage.googleapis.com/storage/v1/b/"
        "$STATE_BUCKET/o/foundation%2Fdefault.tfstate",
        "terraform -chdir=\"$FOUNDATION_DIR\" apply",
        "-lock=true",
        "-lock-timeout=300s",
        "foundation-apply-receipt-signature.sigstore.json",
        "independentlyObserved=false",
        "campaignEvidence=false",
        "referenceProfileVerified=false",
    )
    if any(item not in apply_script for item in script_required):
        fail("foundation_apply_script_contract_missing")
    if '"gs://$STATE_BUCKET/foundation/**"' in apply_script:
        fail("foundation_apply_state_inventory_boundary_invalid")
    if re.search(
        r"terraform\s+(?:-[^\n ]+\s+)*apply(?![^\n]*foundation\.tfplan)",
        apply_script,
    ):
        fail("foundation_apply_unsaved_plan_forbidden")
    review_required = (
        "--if-generation-match=",
        "--if-metageneration-match=",
        'git -C "$ROOT" rev-parse HEAD',
        'git -C "$ROOT" status --porcelain --untracked-files=all',
        "verify_foundation_plan_package.py",
        "terraform -chdir=\"$ROOT/infra/terraform/foundation\" show -no-color",
        "restricted",
        "applyAuthorized=false",
        "infrastructureApplied=false",
        "independentlyObserved=false",
    )
    if any(item not in review_script for item in review_required):
        fail("foundation_plan_reviewer_script_contract_missing")
    review_forbidden = (
        "terraform apply",
        "terraform destroy",
        "cosign sign-blob",
        "--if-generation-match=0",
        "campaignEvidence=true",
        "referenceProfileVerified=true",
    )
    if any(item in review_script for item in review_forbidden):
        fail("foundation_plan_reviewer_script_boundary_invalid")


def validate_contract_and_implementation() -> str:
    authority, release_set, policy = load_contract()
    digest = validate_authority(authority, release_set, policy)
    validate_declared_implementation()
    return digest
