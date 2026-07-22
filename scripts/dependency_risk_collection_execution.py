#!/usr/bin/env python3
"""Strict contract for dependency-risk collection and raw custody."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.dependency_risk_contract import (
        COLLECTOR_SCRIPT,
        EXPECTED_RISK_POLICY_DIGEST,
        EXPECTED_SOURCE_VERIFICATION_DIGEST,
        RISK_POLICY,
        blob_digest,
        validate_risk_policy,
    )
    from scripts.dependency_risk_execution import (
        EXPECTED_AUTHORITY_DIGEST as EXPECTED_PREFLIGHT_AUTHORITY_DIGEST,
        load_contract as load_preflight_contract,
        validate_authority as validate_preflight_authority,
    )
    from scripts.validate_dependency_admission import (
        ADMISSION_LOCK,
        EXPECTED_ADMISSION_DIGEST,
        validate_admission,
    )
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from dependency_risk_contract import (
        COLLECTOR_SCRIPT,
        EXPECTED_RISK_POLICY_DIGEST,
        EXPECTED_SOURCE_VERIFICATION_DIGEST,
        RISK_POLICY,
        blob_digest,
        validate_risk_policy,
    )
    from dependency_risk_execution import (
        EXPECTED_AUTHORITY_DIGEST as EXPECTED_PREFLIGHT_AUTHORITY_DIGEST,
        load_contract as load_preflight_contract,
        validate_authority as validate_preflight_authority,
    )
    from validate_dependency_admission import (
        ADMISSION_LOCK,
        EXPECTED_ADMISSION_DIGEST,
        validate_admission,
    )
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, canonical_digest, load_json


AUTHORITY_PATH = ROOT / "config" / "dependency-risk-collection-execution.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
DEPENDENCY_BOM_PATH = ROOT / "config" / "dependency-bom.lock.json"
TOPOLOGY_PATH = ROOT / "config" / "lab.lock.json"
PREFLIGHT_AUTHORITY_PATH = ROOT / "config" / "dependency-risk-execution.lock.json"
PUBLISHER_SCRIPT = ROOT / "scripts" / "publish_dependency_risk_collection.sh"
CUSTODY_SCHEMA = (
    ROOT / "schemas" / "dependency-risk-raw-custody-statement-v1.schema.json"
)
CUSTODY_VALIDATOR = ROOT / "scripts" / "validate_dependency_risk_collection_custody.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "dependency-risk-collection.yml"
BOOTSTRAP_TERRAFORM_PATH = ROOT / "infra" / "terraform" / "bootstrap" / "main.tf"
FOUNDATION_TERRAFORM_PATH = ROOT / "infra" / "terraform" / "foundation" / "main.tf"
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
TOPOLOGY_DIGEST = (
    "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0"
)
EXPECTED_AUTHORITY_DIGEST = (
    "sha256:120cb99523e13116473548ee6e34e1b0fd7f2fdce9ea98b2d22861697ab1c4b0"
)
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REPOSITORY_ID = "1307302690"
REPOSITORY_OWNER_ID = "37515097"
ENVIRONMENT = "reference-lab-dependency-risk-collection"
WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/dependency-risk-collection.yml@refs/heads/main"
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
        "providerId": "dependency-risk-collection",
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
        "dependency_risk_collection_authority_keys_invalid",
    )
    release_set_digest = validate_release_set(release_set)
    risk_policy_digest = validate_risk_policy(risk_policy)
    admission_digest = validate_admission(
        load_json(ADMISSION_LOCK),
        load_json(DEPENDENCY_BOM_PATH),
        load_json(TOPOLOGY_PATH),
    )
    preflight_authority, preflight_release_set, preflight_risk_policy = (
        load_preflight_contract()
    )
    preflight_digest = validate_preflight_authority(
        preflight_authority,
        preflight_release_set,
        preflight_risk_policy,
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "orchestra.dependency-risk.collection-authority.v1"
        or value["authorityId"] != "orchestra-dependency-risk-collection-v1"
        or value["profileId"] != PROFILE_ID
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "dependencyAdmissionDigest": admission_digest,
            "releaseSetDigest": release_set_digest,
            "sourceVerificationDigest": EXPECTED_SOURCE_VERIFICATION_DIGEST,
            "riskPolicyDigest": risk_policy_digest,
            "preflightAuthorityDigest": preflight_digest,
            "collectorScriptDigest": blob_digest(COLLECTOR_SCRIPT.read_bytes()),
            "publisherScriptDigest": blob_digest(PUBLISHER_SCRIPT.read_bytes()),
            "rawCustodySchemaDigest": blob_digest(CUSTODY_SCHEMA.read_bytes()),
        }
    ):
        fail("dependency_risk_collection_authority_identity_invalid")
    if (
        admission_digest != EXPECTED_ADMISSION_DIGEST
        or risk_policy_digest != EXPECTED_RISK_POLICY_DIGEST
        or preflight_digest != EXPECTED_PREFLIGHT_AUTHORITY_DIGEST
    ):
        fail("dependency_risk_collection_authority_upstream_invalid")
    if value["kms"] != {
        "projectPlane": "services-evidence",
        "location": "europe-west1",
        "keyRingId": "orchestra-reference-evidence",
        "cryptoKeyId": "dependency-risk-collection-signing",
        "purpose": "ASYMMETRIC_SIGN",
        "algorithm": "EC_SIGN_P256_SHA256",
        "protectionLevel": "SOFTWARE",
        "exactVersionRequired": True,
        "preventDestroy": True,
    }:
        fail("dependency_risk_collection_authority_kms_invalid")
    if value["identity"] != {
        "serviceAccountId": "orchestra-risk-collector",
        "allowedKmsRole": "roles/cloudkms.signerVerifier",
        "rawEvidenceRole": "roles/storage.objectCreator",
        "projectRoles": [],
        "rawEvidenceReadGranted": False,
        "rawEvidenceDeleteGranted": False,
        "signedEvidenceWriteGranted": False,
        "artifactMirrorWriteGranted": False,
        "userManagedServiceAccountKeyDeclared": False,
    }:
        fail("dependency_risk_collection_authority_identity_boundary_invalid")
    if value["federation"] != expected_federation():
        fail("dependency_risk_collection_authority_federation_invalid")
    if value["storage"] != {
        "bucketClass": "restricted-raw-evidence",
        "prefixTemplate": "dependency-risk/v1/{profileId}/{evidenceId}",
        "createOnlyGenerationPrecondition": 0,
        "completionMarker": ("dependency-risk-raw-custody-signature.sigstore.json"),
        "completionMarkerUploadedLast": True,
        "objectGenerationRecordedByCollector": False,
        "independentGenerationCaptureRequired": True,
        "workflowArtifactUploaded": False,
    }:
        fail("dependency_risk_collection_authority_storage_invalid")
    if value["workflow"] != {
        "path": ".github/workflows/dependency-risk-collection.yml",
        "trigger": "workflow_dispatch",
        "exactMainRevisionRequired": True,
        "currentRunApprovalRequired": True,
        "rerunAllowed": False,
        "mode": "preflight-then-collection",
        "preflightRequiredInSameRun": True,
        "collectionVerificationRequiredBeforeUpload": True,
        "rawCustodySignatureRequired": True,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
    }:
        fail("dependency_risk_collection_authority_workflow_invalid")
    if value["claim"] != {
        "terraformDeclared": True,
        "workflowDeclared": True,
        "applied": False,
        "liveIdentityVerified": False,
        "liveKmsVerified": False,
        "liveCollectionPassed": False,
        "rawEvidencePublished": False,
        "custodyVerified": False,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("dependency_risk_collection_authority_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_AUTHORITY_DIGEST:
        fail(f"dependency_risk_collection_authority_digest_changed:{digest}")
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
            fail("dependency_risk_collection_terraform_resource_unclosed")
        blocks.append((match.group(1), match.group(2), content[match.start() : end]))
    return blocks


def validate_declared_implementation() -> None:
    bootstrap = _read(
        BOOTSTRAP_TERRAFORM_PATH,
        "dependency_risk_collection_bootstrap_terraform_missing",
    )
    foundation = _read(
        FOUNDATION_TERRAFORM_PATH,
        "dependency_risk_collection_foundation_terraform_missing",
    )
    workflow = _read(WORKFLOW_PATH, "dependency_risk_collection_workflow_missing")
    publisher = _read(PUBLISHER_SCRIPT, "dependency_risk_collection_publisher_missing")
    _read(CUSTODY_VALIDATOR, "dependency_risk_collection_custody_validator_missing")

    bootstrap_required = (
        'resource "google_iam_workload_identity_pool_provider" "dependency_risk_collection"',
        'workload_identity_pool_provider_id = "dependency-risk-collection"',
        "attribute_condition = local.dependency_risk_collection_wif_condition",
        'resource "google_service_account" "dependency_risk_collector"',
        'account_id   = "orchestra-risk-collector"',
        'dependency_risk_collection_subject      = "dependency-risk-collection:${var.github_repository_id}:${local.dependency_risk_collection_environment}"',
        "\"google.subject\"                  = \"'dependency-risk-collection:' + assertion.repository_id + ':' + assertion.environment\"",
        'resource "google_service_account_iam_member" "dependency_risk_collection_wif"',
        'member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.dependency_risk_collection_subject}"',
    )
    foundation_required = (
        'resource "google_kms_crypto_key_iam_member" "dependency_risk_collector_signer"',
        'role          = "roles/cloudkms.signerVerifier"',
        'resource "google_storage_bucket_iam_member" "dependency_risk_collector_writer"',
        'role   = "roles/storage.objectCreator"',
        "orchestra-risk-collector@${var.services_project_id}.iam.gserviceaccount.com",
    )
    workflow_required = (
        "workflow_dispatch:",
        "expected_main_sha:",
        "kms_key_version:",
        "expected_signing_public_key_digest:",
        "if: github.ref == 'refs/heads/main'",
        f"environment: {ENVIRONMENT}",
        "persist-credentials: false",
        "DEPENDENCY_RISK_COLLECTION_REVIEW_GATE_CONFIGURED",
        "GCP_DEPENDENCY_RISK_COLLECTION_WIF_PROVIDER",
        "GCP_DEPENDENCY_RISK_COLLECTION_SERVICE_ACCOUNT",
        "GCP_RAW_EVIDENCE_BUCKET",
        "--contract dependency-risk-collection",
        "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349",
        "permission-contents: read",
        "permission-packages: read",
        "scripts/publish_dependency_risk_collection.sh",
        "--raw-evidence-bucket",
        "custodyVerified=false",
    )
    publisher_required = (
        "verify_dependency_risk_collection.py",
        "validate_dependency_risk_collection_custody.py",
        "--if-generation-match=0",
        "dependency-risk-raw-custody-signature.sigstore.json",
        "cosign sign-blob",
        "custodyVerified=false",
        "objectGenerationRecorded=false",
    )
    if any(fragment not in bootstrap for fragment in bootstrap_required):
        fail("dependency_risk_collection_bootstrap_contract_invalid")
    if any(fragment not in foundation for fragment in foundation_required):
        fail("dependency_risk_collection_foundation_contract_invalid")
    if any(fragment not in workflow for fragment in workflow_required):
        fail("dependency_risk_collection_workflow_contract_invalid")
    if any(fragment not in publisher for fragment in publisher_required):
        fail("dependency_risk_collection_publisher_contract_invalid")

    authority_references = (
        "google_service_account.dependency_risk_collector.name",
        "orchestra-risk-collector@",
    )
    allowed_iam_resources = {
        ("google_service_account_iam_member", "dependency_risk_collection_wif"),
        (
            "google_kms_crypto_key_iam_member",
            "dependency_risk_collector_signer",
        ),
        (
            "google_storage_bucket_iam_member",
            "dependency_risk_collector_writer",
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
            fail("dependency_risk_collection_terraform_authority_invalid")
        if resource_type == "google_service_account_key" and (
            resource_name.startswith("dependency_risk")
            or any(reference in block for reference in authority_references)
        ):
            fail("dependency_risk_collection_terraform_authority_invalid")

    workflow_forbidden = (
        "actions/upload-artifact@",
        "terraform apply",
        "gcloud artifacts docker images copy",
        "docker push",
        "gh workflow run",
        "GCP_SIGNED_EVIDENCE_BUCKET",
        "sourceAdmissionAuthorized=true",
        "mirrorAuthorization=true",
        "campaignEvidence=true",
    )
    if any(fragment in workflow for fragment in workflow_forbidden):
        fail("dependency_risk_collection_workflow_authority_invalid")
    if workflow.count("scripts/collect_dependency_risk_evidence.sh") != 2:
        fail("dependency_risk_collection_workflow_invocation_invalid")
    if workflow.count("--preflight-only") != 1:
        fail("dependency_risk_collection_workflow_preflight_invalid")
    if workflow.count("scripts/publish_dependency_risk_collection.sh") != 1:
        fail("dependency_risk_collection_workflow_publish_invalid")

    upload_order = (
        'upload_create_only "$RAW_ARCHIVE" "$RAW_ARCHIVE_NAME"',
        'upload_create_only "$KMS_PUBLIC_KEY" "$CUSTODY_PUBLIC_KEY_NAME"',
        'upload_create_only "$CUSTODY_STATEMENT" "$CUSTODY_STATEMENT_NAME"',
        'upload_create_only "$CUSTODY_SIGNATURE" "$CUSTODY_SIGNATURE_NAME"',
    )
    positions = [publisher.find(fragment) for fragment in upload_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        fail("dependency_risk_collection_completion_marker_order_invalid")
    if (
        "roles/storage.objectViewer" in foundation
        or "roles/storage.objectAdmin" in foundation
    ):
        for _, _, block in _terraform_resource_blocks(foundation):
            if any(reference in block for reference in authority_references) and (
                "roles/storage.objectViewer" in block
                or "roles/storage.objectAdmin" in block
            ):
                fail("dependency_risk_collection_storage_authority_invalid")


def validate_contract_and_implementation() -> str:
    authority, release_set, risk_policy = load_contract()
    digest = validate_authority(authority, release_set, risk_policy)
    validate_declared_implementation()
    return digest
