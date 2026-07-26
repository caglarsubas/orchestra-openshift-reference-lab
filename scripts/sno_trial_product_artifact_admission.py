#!/usr/bin/env python3
"""Build and verify fail-closed human admission for an SNO artifact replay."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.github_environment_contract import (
        fetch_environment_evidence,
        payload_digest,
    )
    from scripts.sno_trial_product_artifacts import (
        CANDIDATE_PATH,
        CLAIMS,
        LOCK_PATH,
        load_json,
        validate_report,
        write_create_only,
    )
    from scripts.validate_sno_trial_profile import canonical_digest
except ModuleNotFoundError:
    from github_environment_contract import (
        fetch_environment_evidence,
        payload_digest,
    )
    from sno_trial_product_artifacts import (
        CANDIDATE_PATH,
        CLAIMS,
        LOCK_PATH,
        load_json,
        validate_report,
        write_create_only,
    )
    from validate_sno_trial_profile import canonical_digest


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = (
    ROOT / "config" / "sno-trial-product-artifact-admission-policy.lock.json"
)
POLICY_KIND = (
    "orchestra.openshift.sno-trial-product-artifact-admission-policy.v1"
)
ADMISSION_KIND = "orchestra.openshift.sno-trial-product-artifact-admission.v1"
POLICY_ID = "orchestra-sno-trial-product-admission-2026-07-27.1"
TARGET_CLASS = "engineering-trial"
ADMISSION_ID = re.compile(r"^sno-product-admission-[a-z0-9][a-z0-9.-]{5,79}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
REQUIRED_CHECKS = [
    "replay-report-schema-and-digest",
    "three-plane-publication-lineage",
    "image-signatures-and-cyclonedx-attestations",
    "chart-packages-and-sno-values",
    "non-authorizing-claims-and-controls",
]
REPLAY_REFRESH_REASON = "product-artifact-replay-refresh-required"
DEPLOYMENT_REASONS = [
    "destination-mirror-verification-missing",
    "live-cluster-pull-verification-missing",
    "operator-secret-and-ca-inputs-missing",
    "openshift-server-side-dry-run-missing",
    "provider-readiness-not-approved",
]
REMAINING_REASONS = [REPLAY_REFRESH_REASON, *DEPLOYMENT_REASONS]
POLICY_CONTROLS = {
    "productionReleaseSetMutated": False,
    "manifestsEmitted": False,
    "cloudMutationAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
}
ADMISSION_CONTROLS = {
    "independentHumanReview": True,
    "payloadsCollected": False,
    "secretsCollected": False,
    "manifestsEmitted": False,
    "cloudMutationAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def validate_digest(value: Any, code: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(code)


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        fail(code)
    return parsed


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def unsigned_digest(value: dict[str, Any], field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(field, None)
    return canonical_digest(unsigned)


def validate_policy(
    policy: dict[str, Any],
    lock: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    exact_keys(
        policy,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "targetClass",
            "bindings",
            "github",
            "review",
            "activation",
            "controls",
            "claims",
            "policyDigest",
        },
        "sno_product_admission_policy_keys_invalid",
    )
    if (
        policy["schemaVersion"] != 1
        or policy["kind"] != POLICY_KIND
        or policy["policyId"] != POLICY_ID
        or policy["targetClass"] != TARGET_CLASS
    ):
        fail("sno_product_admission_policy_identity_invalid")

    bindings = exact_keys(
        policy["bindings"],
        {
            "profileId",
            "artifactSetId",
            "artifactSetDigest",
            "workloadCandidateDigest",
            "replay",
        },
        "sno_product_admission_policy_bindings_invalid",
    )
    if bindings != {
        "profileId": lock["profileId"],
        "artifactSetId": lock["artifactSetId"],
        "artifactSetDigest": lock["artifactSetDigest"],
        "workloadCandidateDigest": candidate["candidateDigest"],
        "replay": bindings["replay"],
    }:
        fail("sno_product_admission_policy_bindings_invalid")
    replay = exact_keys(
        bindings["replay"],
        {
            "verificationId",
            "generatedAt",
            "reportDigest",
            "verifierRevision",
            "verifierRunId",
            "verifierRunAttempt",
            "artifactId",
            "artifactName",
        },
        "sno_product_admission_policy_replay_invalid",
    )
    run_id = replay["verifierRunId"]
    run_attempt = replay["verifierRunAttempt"]
    artifact_id = replay["artifactId"]
    if (
        not isinstance(run_id, int)
        or isinstance(run_id, bool)
        or run_id <= 0
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt != 1
        or not isinstance(artifact_id, int)
        or isinstance(artifact_id, bool)
        or artifact_id <= 0
        or replay["verificationId"] != f"sno-product-replay-{run_id}.1"
        or replay["artifactName"]
        != f"sno-trial-product-artifact-replay-{run_id}-1"
    ):
        fail("sno_product_admission_policy_replay_invalid")
    parse_utc(replay["generatedAt"], "sno_product_admission_policy_replay_invalid")
    validate_digest(
        replay["reportDigest"], "sno_product_admission_policy_replay_invalid"
    )
    if (
        not isinstance(replay["verifierRevision"], str)
        or not REVISION.fullmatch(replay["verifierRevision"])
    ):
        fail("sno_product_admission_policy_replay_invalid")

    github = exact_keys(
        policy["github"],
        {
            "repository",
            "repositoryId",
            "repositoryOwnerId",
            "repositoryVisibility",
            "workflowRef",
            "environment",
            "minimumIndependentReviewers",
            "reviewerType",
            "preventSelfReview",
            "deploymentBranch",
        },
        "sno_product_admission_policy_github_invalid",
    )
    if github != {
        "repository": "caglarsubas/orchestra-openshift-reference-lab",
        "repositoryId": "1307302690",
        "repositoryOwnerId": "37515097",
        "repositoryVisibility": "private",
        "workflowRef": (
            "caglarsubas/orchestra-openshift-reference-lab/"
            ".github/workflows/sno-trial-product-artifact-admission.yml"
            "@refs/heads/main"
        ),
        "environment": "sno-trial-product-artifact-admission",
        "minimumIndependentReviewers": 1,
        "reviewerType": "User",
        "preventSelfReview": True,
        "deploymentBranch": "main",
    }:
        fail("sno_product_admission_policy_github_invalid")

    review = exact_keys(
        policy["review"],
        {
            "maximumReplayAgeSeconds",
            "maximumAdmissionAgeSeconds",
            "requiredChecks",
            "replayState",
        },
        "sno_product_admission_policy_review_invalid",
    )
    if (
        review["maximumReplayAgeSeconds"] != 14 * 24 * 60 * 60
        or review["maximumAdmissionAgeSeconds"] != 30 * 24 * 60 * 60
        or review["requiredChecks"] != REQUIRED_CHECKS
        or review["replayState"] not in {"refresh-required", "current"}
    ):
        fail("sno_product_admission_policy_review_invalid")
    expected_reasons = (
        REMAINING_REASONS
        if review["replayState"] == "refresh-required"
        else DEPLOYMENT_REASONS
    )
    if policy["activation"] != {
        "state": "blocked",
        "remainingReasonCodes": expected_reasons,
    }:
        fail("sno_product_admission_policy_activation_invalid")
    if policy["controls"] != POLICY_CONTROLS:
        fail("sno_product_admission_policy_controls_invalid")
    if policy["claims"] != CLAIMS:
        fail("sno_product_admission_policy_claims_invalid")
    validate_digest(
        policy["policyDigest"], "sno_product_admission_policy_digest_invalid"
    )
    if policy["policyDigest"] != unsigned_digest(policy, "policyDigest"):
        fail("sno_product_admission_policy_digest_mismatch")


def validate_replay_binding(
    report: dict[str, Any],
    policy: dict[str, Any],
    lock: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    if policy["review"]["replayState"] != "current":
        fail("sno_product_admission_replay_refresh_required")
    validate_report(report, lock, candidate)
    replay = policy["bindings"]["replay"]
    bindings = report["bindings"]
    if (
        report["verificationId"] != replay["verificationId"]
        or report["generatedAt"] != replay["generatedAt"]
        or report["reportDigest"] != replay["reportDigest"]
        or bindings["verifierRevision"] != replay["verifierRevision"]
        or bindings["verifierRunId"] != replay["verifierRunId"]
        or bindings["verifierRunAttempt"] != replay["verifierRunAttempt"]
    ):
        fail("sno_product_admission_replay_binding_invalid")


def normalize_environment_evidence(
    evidence: dict[str, Any],
    policy: dict[str, Any],
    workflow_actor_id: int | None = None,
) -> dict[str, Any]:
    exact_keys(
        evidence,
        {
            "repositoryIdentityDigest",
            "environmentIdentityDigest",
            "reviewerIdentityDigests",
            "reviewerCount",
            "preventSelfReview",
            "deploymentBranchPolicyDigest",
            "workflowApproval",
        },
        "sno_product_admission_environment_evidence_invalid",
    )
    for field in (
        "repositoryIdentityDigest",
        "environmentIdentityDigest",
        "deploymentBranchPolicyDigest",
    ):
        validate_digest(
            evidence[field], "sno_product_admission_environment_evidence_invalid"
        )
    reviewers = evidence["reviewerIdentityDigests"]
    if (
        not isinstance(reviewers, list)
        or len(reviewers) != evidence["reviewerCount"]
        or len(reviewers) < policy["github"]["minimumIndependentReviewers"]
        or len(reviewers) != len(set(reviewers))
        or evidence["preventSelfReview"] is not True
    ):
        fail("sno_product_admission_environment_evidence_invalid")
    for reviewer in reviewers:
        validate_digest(
            reviewer, "sno_product_admission_environment_evidence_invalid"
        )

    approval = exact_keys(
        evidence["workflowApproval"],
        {
            "workflowRunIdentityDigest",
            "requesterIdentityDigest",
            "reviewerIdentityDigest",
            "approvalIdentityDigest",
            "independentApproval",
        },
        "sno_product_admission_workflow_approval_invalid",
    )
    for field in (
        "workflowRunIdentityDigest",
        "requesterIdentityDigest",
        "reviewerIdentityDigest",
        "approvalIdentityDigest",
    ):
        validate_digest(
            approval[field], "sno_product_admission_workflow_approval_invalid"
        )
    requester_digest = approval["requesterIdentityDigest"]
    if workflow_actor_id is not None and requester_digest != payload_digest(
        {"type": policy["github"]["reviewerType"], "id": workflow_actor_id}
    ):
        fail("sno_product_admission_workflow_approval_invalid")
    if (
        approval["independentApproval"] is not True
        or approval["reviewerIdentityDigest"] not in reviewers
        or approval["reviewerIdentityDigest"] == requester_digest
    ):
        fail("sno_product_admission_workflow_approval_invalid")
    return {
        **evidence,
        "workflowApproval": {
            "workflowRunIdentityDigest": approval["workflowRunIdentityDigest"],
            "requesterIdentityDigest": requester_digest,
            "reviewerIdentityDigest": approval["reviewerIdentityDigest"],
            "approvalIdentityDigest": approval["approvalIdentityDigest"],
            "independentApproval": True,
        },
    }


def build_admission(
    report: dict[str, Any],
    policy: dict[str, Any],
    lock: dict[str, Any],
    candidate: dict[str, Any],
    environment_evidence: dict[str, Any],
    *,
    admission_id: str,
    admitted_at: datetime,
    expires_at: datetime,
    admission_workflow_revision: str,
    admission_workflow_run_id: int,
    admission_workflow_run_attempt: int,
    workflow_actor_id: int,
) -> dict[str, Any]:
    validate_policy(policy, lock, candidate)
    validate_replay_binding(report, policy, lock, candidate)
    if not ADMISSION_ID.fullmatch(admission_id):
        fail("sno_product_admission_id_invalid")
    if (
        not REVISION.fullmatch(admission_workflow_revision)
        or admission_workflow_run_id <= 0
        or admission_workflow_run_attempt != 1
        or workflow_actor_id <= 0
    ):
        fail("sno_product_admission_workflow_invalid")
    replay_time = parse_utc(report["generatedAt"], "sno_product_admission_time_invalid")
    if (
        admitted_at.tzinfo is None
        or admitted_at.utcoffset() != timezone.utc.utcoffset(admitted_at)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() != timezone.utc.utcoffset(expires_at)
    ):
        fail("sno_product_admission_time_invalid")
    admitted_at = admitted_at.astimezone(timezone.utc).replace(microsecond=0)
    expires_at = expires_at.astimezone(timezone.utc).replace(microsecond=0)
    if (
        admitted_at < replay_time
        or (admitted_at - replay_time).total_seconds()
        > policy["review"]["maximumReplayAgeSeconds"]
        or expires_at <= admitted_at
        or (expires_at - admitted_at).total_seconds()
        > policy["review"]["maximumAdmissionAgeSeconds"]
    ):
        fail("sno_product_admission_time_invalid")
    evidence = normalize_environment_evidence(
        environment_evidence, policy, workflow_actor_id
    )
    expected_workflow_run_digest = payload_digest(
        {
            "repositoryId": policy["github"]["repositoryId"],
            "runId": admission_workflow_run_id,
            "runAttempt": admission_workflow_run_attempt,
        }
    )
    if (
        evidence["workflowApproval"]["workflowRunIdentityDigest"]
        != expected_workflow_run_digest
    ):
        fail("sno_product_admission_workflow_approval_invalid")
    replay = policy["bindings"]["replay"]
    report_bindings = report["bindings"]
    value = {
        "schemaVersion": 1,
        "kind": ADMISSION_KIND,
        "admissionId": admission_id,
        "admittedAt": utc_text(admitted_at),
        "expiresAt": utc_text(expires_at),
        "targetClass": TARGET_CLASS,
        "decision": "approved",
        "bindings": {
            "policyId": policy["policyId"],
            "policyDigest": policy["policyDigest"],
            "profileId": report_bindings["profileId"],
            "artifactSetId": report_bindings["artifactSetId"],
            "artifactSetDigest": report_bindings["artifactSetDigest"],
            "workloadCandidateDigest": report_bindings[
                "workloadCandidateDigest"
            ],
            "verificationId": report["verificationId"],
            "replayGeneratedAt": report["generatedAt"],
            "replayReportDigest": report["reportDigest"],
            "verifierRevision": report_bindings["verifierRevision"],
            "verifierRunId": report_bindings["verifierRunId"],
            "verifierRunAttempt": report_bindings["verifierRunAttempt"],
            "replayArtifactId": replay["artifactId"],
            "replayArtifactName": replay["artifactName"],
            "admissionWorkflowRevision": admission_workflow_revision,
            "admissionWorkflowRunId": admission_workflow_run_id,
            "admissionWorkflowRunAttempt": admission_workflow_run_attempt,
        },
        "review": {
            "reviewType": "independent-github-environment-review",
            "requiredChecks": list(REQUIRED_CHECKS),
            "checksPassed": True,
            "environmentEvidence": evidence,
        },
        "admission": {
            "state": "source-replay-admitted",
            "scope": "sno-trial-product-artifacts-only",
            "replayAccepted": True,
            "destinationMirrorVerified": False,
            "liveClusterPullVerified": False,
            "secretReferencesResolved": False,
            "serverSideDryRunVerified": False,
            "providerReadinessApproved": False,
            "activationAuthorized": False,
        },
        "activation": {
            "state": "blocked",
            "reasonCodes": list(
                policy["activation"]["remainingReasonCodes"]
            ),
        },
        "controls": dict(ADMISSION_CONTROLS),
        "claims": dict(CLAIMS),
    }
    value["admissionDigest"] = unsigned_digest(value, "admissionDigest")
    validate_admission(value, policy, report, lock, candidate)
    return value


def validate_admission(
    value: dict[str, Any],
    policy: dict[str, Any],
    report: dict[str, Any],
    lock: dict[str, Any],
    candidate: dict[str, Any],
    *,
    at: datetime | None = None,
) -> None:
    validate_policy(policy, lock, candidate)
    validate_replay_binding(report, policy, lock, candidate)
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "admissionId",
            "admittedAt",
            "expiresAt",
            "targetClass",
            "decision",
            "bindings",
            "review",
            "admission",
            "activation",
            "controls",
            "claims",
            "admissionDigest",
        },
        "sno_product_admission_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != ADMISSION_KIND
        or not isinstance(value["admissionId"], str)
        or not ADMISSION_ID.fullmatch(value["admissionId"])
        or value["targetClass"] != TARGET_CLASS
        or value["decision"] != "approved"
    ):
        fail("sno_product_admission_identity_invalid")
    admitted_at = parse_utc(value["admittedAt"], "sno_product_admission_time_invalid")
    expires_at = parse_utc(value["expiresAt"], "sno_product_admission_time_invalid")
    replay_time = parse_utc(report["generatedAt"], "sno_product_admission_time_invalid")
    if (
        admitted_at < replay_time
        or (admitted_at - replay_time).total_seconds()
        > policy["review"]["maximumReplayAgeSeconds"]
        or expires_at <= admitted_at
        or (expires_at - admitted_at).total_seconds()
        > policy["review"]["maximumAdmissionAgeSeconds"]
    ):
        fail("sno_product_admission_time_invalid")
    if at is not None:
        if (
            at.tzinfo is None
            or at.utcoffset() != timezone.utc.utcoffset(at)
            or at.astimezone(timezone.utc) > expires_at
        ):
            fail("sno_product_admission_time_invalid")

    replay = policy["bindings"]["replay"]
    report_bindings = report["bindings"]
    bindings = exact_keys(
        value["bindings"],
        {
            "policyId",
            "policyDigest",
            "profileId",
            "artifactSetId",
            "artifactSetDigest",
            "workloadCandidateDigest",
            "verificationId",
            "replayGeneratedAt",
            "replayReportDigest",
            "verifierRevision",
            "verifierRunId",
            "verifierRunAttempt",
            "replayArtifactId",
            "replayArtifactName",
            "admissionWorkflowRevision",
            "admissionWorkflowRunId",
            "admissionWorkflowRunAttempt",
        },
        "sno_product_admission_bindings_invalid",
    )
    expected_bindings = {
        "policyId": policy["policyId"],
        "policyDigest": policy["policyDigest"],
        "profileId": report_bindings["profileId"],
        "artifactSetId": report_bindings["artifactSetId"],
        "artifactSetDigest": report_bindings["artifactSetDigest"],
        "workloadCandidateDigest": report_bindings["workloadCandidateDigest"],
        "verificationId": report["verificationId"],
        "replayGeneratedAt": report["generatedAt"],
        "replayReportDigest": report["reportDigest"],
        "verifierRevision": report_bindings["verifierRevision"],
        "verifierRunId": report_bindings["verifierRunId"],
        "verifierRunAttempt": report_bindings["verifierRunAttempt"],
        "replayArtifactId": replay["artifactId"],
        "replayArtifactName": replay["artifactName"],
        "admissionWorkflowRevision": bindings["admissionWorkflowRevision"],
        "admissionWorkflowRunId": bindings["admissionWorkflowRunId"],
        "admissionWorkflowRunAttempt": bindings["admissionWorkflowRunAttempt"],
    }
    if bindings != expected_bindings:
        fail("sno_product_admission_bindings_invalid")
    if (
        not REVISION.fullmatch(bindings["admissionWorkflowRevision"])
        or not isinstance(bindings["admissionWorkflowRunId"], int)
        or bindings["admissionWorkflowRunId"] <= 0
        or bindings["admissionWorkflowRunAttempt"] != 1
    ):
        fail("sno_product_admission_bindings_invalid")

    review = exact_keys(
        value["review"],
        {
            "reviewType",
            "requiredChecks",
            "checksPassed",
            "environmentEvidence",
        },
        "sno_product_admission_review_invalid",
    )
    if (
        review["reviewType"] != "independent-github-environment-review"
        or review["requiredChecks"] != REQUIRED_CHECKS
        or review["checksPassed"] is not True
    ):
        fail("sno_product_admission_review_invalid")
    evidence = review["environmentEvidence"]
    if not isinstance(evidence, dict):
        fail("sno_product_admission_environment_evidence_invalid")
    normalized = normalize_environment_evidence(evidence, policy)
    normalized_approval = normalized["workflowApproval"]
    stored_approval = evidence["workflowApproval"]
    exact_keys(
        stored_approval,
        {
            "workflowRunIdentityDigest",
            "requesterIdentityDigest",
            "reviewerIdentityDigest",
            "approvalIdentityDigest",
            "independentApproval",
        },
        "sno_product_admission_workflow_approval_invalid",
    )
    for field in (
        "workflowRunIdentityDigest",
        "requesterIdentityDigest",
        "reviewerIdentityDigest",
        "approvalIdentityDigest",
    ):
        validate_digest(
            stored_approval[field],
            "sno_product_admission_workflow_approval_invalid",
        )
    if (
        stored_approval["independentApproval"] is not True
        or stored_approval["reviewerIdentityDigest"]
        not in evidence["reviewerIdentityDigests"]
        or stored_approval["requesterIdentityDigest"]
        == stored_approval["reviewerIdentityDigest"]
        or normalized_approval["reviewerIdentityDigest"]
        != stored_approval["reviewerIdentityDigest"]
        or stored_approval["workflowRunIdentityDigest"]
        != payload_digest(
            {
                "repositoryId": policy["github"]["repositoryId"],
                "runId": bindings["admissionWorkflowRunId"],
                "runAttempt": bindings["admissionWorkflowRunAttempt"],
            }
        )
    ):
        fail("sno_product_admission_workflow_approval_invalid")

    if value["admission"] != {
        "state": "source-replay-admitted",
        "scope": "sno-trial-product-artifacts-only",
        "replayAccepted": True,
        "destinationMirrorVerified": False,
        "liveClusterPullVerified": False,
        "secretReferencesResolved": False,
        "serverSideDryRunVerified": False,
        "providerReadinessApproved": False,
        "activationAuthorized": False,
    }:
        fail("sno_product_admission_scope_invalid")
    if value["activation"] != {
        "state": "blocked",
        "reasonCodes": policy["activation"]["remainingReasonCodes"],
    }:
        fail("sno_product_admission_activation_invalid")
    if value["controls"] != ADMISSION_CONTROLS:
        fail("sno_product_admission_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_product_admission_claims_invalid")
    validate_digest(
        value["admissionDigest"], "sno_product_admission_digest_invalid"
    )
    if value["admissionDigest"] != unsigned_digest(value, "admissionDigest"):
        fail("sno_product_admission_digest_mismatch")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-policy")

    admit = subparsers.add_parser("admit")
    admit.add_argument("--report", type=Path, required=True)
    admit.add_argument("--github-token-file", type=Path, required=True)
    admit.add_argument("--admission-id", required=True)
    admit.add_argument("--admitted-at", required=True)
    admit.add_argument("--expires-at", required=True)
    admit.add_argument("--workflow-revision", required=True)
    admit.add_argument("--workflow-run-id", type=int, required=True)
    admit.add_argument("--workflow-run-attempt", type=int, required=True)
    admit.add_argument("--workflow-actor-id", type=int, required=True)
    admit.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    verify.add_argument("--admission", type=Path, required=True)
    verify.add_argument("--at")

    args = parser.parse_args(argv)
    policy = load_json(POLICY_PATH)
    lock = load_json(LOCK_PATH)
    candidate = load_json(CANDIDATE_PATH)
    if args.command == "validate-policy":
        validate_policy(policy, lock, candidate)
        print(f"sno_product_admission_policy_valid digest={policy['policyDigest']}")
        return 0

    report = load_json(args.report.resolve())
    if args.command == "admit":
        admitted_at = parse_utc(
            args.admitted_at, "sno_product_admission_time_invalid"
        )
        expires_at = parse_utc(
            args.expires_at, "sno_product_admission_time_invalid"
        )
        evidence = fetch_environment_evidence(
            args.github_token_file.resolve(),
            policy["github"],
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            workflow_actor_id=args.workflow_actor_id,
        )
        value = build_admission(
            report,
            policy,
            lock,
            candidate,
            evidence,
            admission_id=args.admission_id,
            admitted_at=admitted_at,
            expires_at=expires_at,
            admission_workflow_revision=args.workflow_revision,
            admission_workflow_run_id=args.workflow_run_id,
            admission_workflow_run_attempt=args.workflow_run_attempt,
            workflow_actor_id=args.workflow_actor_id,
        )
        write_create_only(args.output.resolve(), value)
        print(json.dumps(value, indent=2, sort_keys=True))
        return 0

    admission = load_json(args.admission.resolve())
    at = None
    if args.at:
        at = parse_utc(args.at, "sno_product_admission_time_invalid")
    validate_admission(admission, policy, report, lock, candidate, at=at)
    print(f"verified {args.admission}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
