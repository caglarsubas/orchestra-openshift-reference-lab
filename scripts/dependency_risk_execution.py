#!/usr/bin/env python3
"""Strict contract for the dependency-risk preflight execution authority."""

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
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, canonical_digest, load_json


AUTHORITY_PATH = ROOT / "config" / "dependency-risk-execution.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "dependency-risk-preflight.yml"
BOOTSTRAP_TERRAFORM_PATH = ROOT / "infra" / "terraform" / "bootstrap" / "main.tf"
FOUNDATION_TERRAFORM_PATH = ROOT / "infra" / "terraform" / "foundation" / "main.tf"
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
TOPOLOGY_DIGEST = (
    "sha256:7c72982c74afd5d5ebdb1c5ea92054b477cd70cc604d7f14a1f4c348ec670fc5"
)
EXPECTED_AUTHORITY_DIGEST = (
    "sha256:324b683e473bd474fdb2f48e48bb4737a1cbd681f762203ba7e0410553ee2f99"
)
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REPOSITORY_ID = "1307302690"
REPOSITORY_OWNER_ID = "37515097"
ENVIRONMENT = "reference-lab-dependency-risk-preflight"
WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/dependency-risk-preflight.yml@refs/heads/main"
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
        "providerId": "dependency-risk-preflight",
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
            "workflow",
            "claim",
        },
        "dependency_risk_authority_keys_invalid",
    )
    release_set_digest = validate_release_set(release_set)
    risk_policy_digest = validate_risk_policy(risk_policy)
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "orchestra.dependency-risk.preflight-authority.v1"
        or value["authorityId"] != "orchestra-dependency-risk-preflight-v1"
        or value["profileId"] != PROFILE_ID
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "releaseSetDigest": release_set_digest,
            "sourceVerificationDigest": EXPECTED_SOURCE_VERIFICATION_DIGEST,
            "riskPolicyDigest": risk_policy_digest,
            "collectorScriptDigest": blob_digest(COLLECTOR_SCRIPT.read_bytes()),
        }
    ):
        fail("dependency_risk_authority_identity_invalid")
    if risk_policy_digest != EXPECTED_RISK_POLICY_DIGEST:
        fail("dependency_risk_authority_risk_policy_invalid")
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
        fail("dependency_risk_authority_kms_invalid")
    if value["identity"] != {
        "serviceAccountId": "orchestra-dependency-risk",
        "allowedKmsRole": "roles/cloudkms.signerVerifier",
        "projectRoles": [],
        "evidenceBucketWriteGranted": False,
        "artifactMirrorWriteGranted": False,
        "userManagedServiceAccountKeyDeclared": False,
    }:
        fail("dependency_risk_authority_identity_boundary_invalid")
    if value["federation"] != expected_federation():
        fail("dependency_risk_authority_federation_invalid")
    if value["workflow"] != {
        "path": ".github/workflows/dependency-risk-preflight.yml",
        "trigger": "workflow_dispatch",
        "exactMainRevisionRequired": True,
        "currentRunApprovalRequired": True,
        "rerunAllowed": False,
        "mode": "preflight-only",
        "collectionOutputPersisted": False,
        "workflowArtifactUploaded": False,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
    }:
        fail("dependency_risk_authority_workflow_invalid")
    if value["claim"] != {
        "terraformDeclared": True,
        "workflowDeclared": True,
        "applied": False,
        "liveIdentityVerified": False,
        "liveKmsVerified": False,
        "livePreflightPassed": False,
        "collectionStarted": False,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("dependency_risk_authority_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_AUTHORITY_DIGEST:
        fail(f"dependency_risk_authority_digest_changed:{digest}")
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
            fail("dependency_risk_terraform_resource_unclosed")
        blocks.append((match.group(1), match.group(2), content[match.start() : end]))
    return blocks


def validate_declared_implementation() -> None:
    bootstrap = _read(
        BOOTSTRAP_TERRAFORM_PATH, "dependency_risk_bootstrap_terraform_missing"
    )
    foundation = _read(
        FOUNDATION_TERRAFORM_PATH, "dependency_risk_foundation_terraform_missing"
    )
    workflow = _read(WORKFLOW_PATH, "dependency_risk_preflight_workflow_missing")

    bootstrap_required = (
        'resource "google_iam_workload_identity_pool_provider" "dependency_risk"',
        'workload_identity_pool_provider_id = "dependency-risk-preflight"',
        "attribute_condition = local.dependency_risk_preflight_wif_condition",
        'resource "google_service_account" "dependency_risk"',
        'account_id   = "orchestra-dependency-risk"',
        'dependency_risk_preflight_subject      = "dependency-risk-preflight:${var.github_repository_id}:${local.dependency_risk_preflight_environment}"',
        "\"google.subject\"                  = \"'dependency-risk-preflight:' + assertion.repository_id + ':' + assertion.environment\"",
        'resource "google_service_account_iam_member" "dependency_risk_wif"',
        'role               = "roles/iam.workloadIdentityUser"',
        'member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.dependency_risk_preflight_subject}"',
    )
    foundation_required = (
        'resource "google_kms_crypto_key" "dependency_risk_signing"',
        'name     = "dependency-risk-collection-signing"',
        'purpose  = "ASYMMETRIC_SIGN"',
        'algorithm        = "EC_SIGN_P256_SHA256"',
        'protection_level = "SOFTWARE"',
        'resource "google_kms_crypto_key_iam_member" "dependency_risk_signer"',
        'role          = "roles/cloudkms.signerVerifier"',
        "orchestra-dependency-risk@${var.services_project_id}.iam.gserviceaccount.com",
    )
    workflow_required = (
        "workflow_dispatch:",
        "expected_main_sha:",
        "kms_key_version:",
        "expected_signing_public_key_digest:",
        "if: github.ref == 'refs/heads/main'",
        f"environment: {ENVIRONMENT}",
        "persist-credentials: false",
        "DEPENDENCY_RISK_PREFLIGHT_REVIEW_GATE_CONFIGURED",
        "GCP_DEPENDENCY_RISK_WIF_PROVIDER",
        "GCP_DEPENDENCY_RISK_COLLECTOR_SERVICE_ACCOUNT",
        "github_environment_contract.py verify",
        "--contract dependency-risk-preflight",
        "DEPENDENCY_RISK_GITHUB_APP_INSTALLATION_ID",
        "operator_control_plane_readiness.py verify-app",
        "GITHUB_APP_INSTALLATION_DIGEST",
        "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "permission-contents: read",
        "permission-packages: read",
        "google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
        "dependency-risk-collection-signing/cryptoKeyVersions/",
        "scripts/collect_dependency_risk_evidence.sh",
        "--preflight-only",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--tmpfs /tmp:rw,noexec,nosuid,size=2g",
        "--env CLOUDSDK_CONFIG=/tmp/gcloud",
        "collectionStarted=false",
    )
    if any(fragment not in bootstrap for fragment in bootstrap_required):
        fail("dependency_risk_bootstrap_terraform_contract_invalid")
    if any(fragment not in foundation for fragment in foundation_required):
        fail("dependency_risk_foundation_terraform_contract_invalid")
    if any(fragment not in workflow for fragment in workflow_required):
        fail("dependency_risk_preflight_workflow_contract_invalid")

    workflow_forbidden = (
        "actions/upload-artifact@",
        "terraform apply",
        "gcloud artifacts docker images copy",
        "docker push",
        "gh workflow run",
        "--require-ready",
        "PROMOTE",
    )
    authority_references = (
        "google_service_account.dependency_risk.name",
        "orchestra-dependency-risk@",
    )
    allowed_iam_resources = {
        ("google_service_account_iam_member", "dependency_risk_wif"),
        ("google_kms_crypto_key_iam_member", "dependency_risk_signer"),
    }
    for resource_type, resource_name, block in _terraform_resource_blocks(
        bootstrap + "\n" + foundation
    ):
        if (
            "_iam_" in resource_type
            and any(reference in block for reference in authority_references)
            and (resource_type, resource_name) not in allowed_iam_resources
        ):
            fail("dependency_risk_terraform_authority_invalid")
        if resource_type == "google_service_account_key" and (
            resource_name.startswith("dependency_risk")
            or any(reference in block for reference in authority_references)
        ):
            fail("dependency_risk_terraform_authority_invalid")
    if any(fragment in workflow for fragment in workflow_forbidden):
        fail("dependency_risk_preflight_workflow_authority_invalid")
    if workflow.count("scripts/collect_dependency_risk_evidence.sh") != 1:
        fail("dependency_risk_preflight_workflow_invocation_invalid")


def validate_contract_and_implementation() -> str:
    authority, release_set, risk_policy = load_contract()
    digest = validate_authority(authority, release_set, risk_policy)
    validate_declared_implementation()
    return digest
