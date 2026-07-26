from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone

from scripts.github_environment_contract import (
    payload_digest,
    validate_workflow_approvals,
)
from scripts.sno_trial_product_artifact_admission import (
    ADMISSION_CONTROLS,
    POLICY_PATH,
    REMAINING_REASONS,
    build_admission,
    unsigned_digest,
    validate_admission,
    validate_policy,
)
from scripts.sno_trial_product_artifacts import (
    CANDIDATE_PATH,
    CLAIMS,
    LOCK_PATH,
    REPORT_CONTROLS,
    REPORT_EXECUTION_MODE,
    REPORT_KIND,
    load_json,
    report_digest,
    validate_report,
)
from scripts.validate_repository import ROOT


class SnoTrialProductArtifactAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_json(POLICY_PATH)
        self.lock = load_json(LOCK_PATH)
        self.candidate = load_json(CANDIDATE_PATH)
        self.report = self.valid_replay_report()
        self.environment_evidence = self.valid_environment_evidence()
        self.admitted_at = datetime(2026, 7, 26, 9, 0, tzinfo=timezone.utc)
        self.expires_at = datetime(2026, 8, 9, 9, 0, tzinfo=timezone.utc)

    def valid_replay_report(self) -> dict[str, object]:
        artifacts = []
        for artifact in self.lock["artifacts"]:
            publication = artifact["publication"]
            source = artifact["source"]
            image = artifact["image"]
            chart = artifact["chart"]
            artifacts.append(
                {
                    "plane": artifact["plane"],
                    "publication": {
                        "runId": publication["runId"],
                        "runAttempt": publication["runAttempt"],
                        "runUrl": publication["runUrl"],
                        "tag": publication["tag"],
                        "sourceRevision": source["revision"],
                        "workflow": publication["workflow"],
                        "workflowName": publication["workflowName"],
                        "conclusion": "success",
                    },
                    "image": {
                        **image,
                        "platformManifestVerified": True,
                        "signatureVerified": True,
                        "cycloneDxAttestationVerified": True,
                    },
                    "chart": {
                        "reference": chart["reference"],
                        "digest": chart["digest"],
                        "name": chart["name"],
                        "version": chart["version"],
                        "appVersion": chart["appVersion"],
                        "packageDigest": chart["packageDigest"],
                        "trialValuesPath": chart["trialValuesPath"],
                        "trialValuesDigest": chart["trialValuesDigest"],
                        "signatureVerified": True,
                        "cycloneDxAttestationVerified": True,
                        "packagePulled": True,
                        "trialValuesVerified": True,
                    },
                    "admission": copy.deepcopy(artifact["admission"]),
                }
            )
        value: dict[str, object] = {
            "schemaVersion": 2,
            "kind": REPORT_KIND,
            "verificationId": "sno-product-replay-30194136809.1",
            "generatedAt": "2026-07-26T08:10:51Z",
            "targetClass": "engineering-trial",
            "executionMode": REPORT_EXECUTION_MODE,
            "bindings": {
                "profileId": self.lock["profileId"],
                "artifactSetId": self.lock["artifactSetId"],
                "artifactSetDigest": self.lock["artifactSetDigest"],
                "workloadCandidateDigest": self.candidate["candidateDigest"],
                "verifierRevision": "9f1b153a1d11805a1dcca34f8b5e3e3f7d0b739e",
                "verifierRunId": 30194136809,
                "verifierRunAttempt": 1,
            },
            "artifacts": artifacts,
            "activation": copy.deepcopy(self.lock["activation"]),
            "controls": copy.deepcopy(REPORT_CONTROLS),
            "claims": copy.deepcopy(CLAIMS),
        }
        value["reportDigest"] = report_digest(value)
        self.assertEqual(
            value["reportDigest"],
            "sha256:e664bf181d4e0a4b8023f0633957774b292e80747c6ae39833c006ad553bc280",
        )
        validate_report(value, self.lock, self.candidate)
        return value

    def valid_environment_evidence(self) -> dict[str, object]:
        requester_id = 13579
        reviewer_id = 24681012
        expected = self.policy["github"]
        environment = {
            "id": 987654,
            "name": expected["environment"],
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {
                            "type": "User",
                            "reviewer": {"id": reviewer_id},
                        }
                    ],
                }
            ],
        }
        approval = validate_workflow_approvals(
            [
                {
                    "state": "approved",
                    "environments": [
                        {"id": 987654, "name": expected["environment"]}
                    ],
                    "user": {"id": reviewer_id, "type": "User"},
                }
            ],
            environment,
            expected,
            workflow_run_id=999,
            workflow_run_attempt=1,
            workflow_actor_id=requester_id,
        )
        reviewer_digest = payload_digest({"type": "User", "id": reviewer_id})
        self.assertEqual(approval["reviewerIdentityDigest"], reviewer_digest)
        return {
            "repositoryIdentityDigest": payload_digest({"repository": "fixture"}),
            "environmentIdentityDigest": payload_digest({"environment": "fixture"}),
            "reviewerIdentityDigests": [reviewer_digest],
            "reviewerCount": 1,
            "preventSelfReview": True,
            "deploymentBranchPolicyDigest": payload_digest({"branch": "main"}),
            "workflowApproval": approval,
        }

    def build_valid_admission(self) -> dict[str, object]:
        return build_admission(
            self.report,
            self.policy,
            self.lock,
            self.candidate,
            self.environment_evidence,
            admission_id="sno-product-admission-test-001",
            admitted_at=self.admitted_at,
            expires_at=self.expires_at,
            admission_workflow_revision="a" * 40,
            admission_workflow_run_id=999,
            admission_workflow_run_attempt=1,
            workflow_actor_id=13579,
        )

    def test_policy_is_digest_bound_and_non_authorizing(self) -> None:
        validate_policy(self.policy, self.lock, self.candidate)
        self.assertFalse(self.policy["controls"]["deploymentAuthorized"])
        self.assertFalse(self.policy["claims"]["campaignEvidence"])

        changed = copy.deepcopy(self.policy)
        changed["github"]["preventSelfReview"] = False
        changed["policyDigest"] = unsigned_digest(changed, "policyDigest")
        with self.assertRaisesRegex(ValueError, "policy_github_invalid"):
            validate_policy(changed, self.lock, self.candidate)

    def test_admission_accepts_only_replay_review_and_remains_blocked(self) -> None:
        admission = self.build_valid_admission()
        validate_admission(
            admission,
            self.policy,
            self.report,
            self.lock,
            self.candidate,
            at=self.admitted_at,
        )
        self.assertEqual(admission["activation"]["reasonCodes"], REMAINING_REASONS)
        self.assertNotIn(
            "product-artifact-replay-review-missing",
            admission["activation"]["reasonCodes"],
        )
        self.assertTrue(admission["controls"]["independentHumanReview"])
        self.assertEqual(admission["controls"], ADMISSION_CONTROLS)
        self.assertFalse(admission["admission"]["activationAuthorized"])
        self.assertFalse(admission["claims"]["campaignEvidence"])

    def test_replay_or_authority_drift_fails_closed(self) -> None:
        changed_report = copy.deepcopy(self.report)
        changed_report["bindings"]["verifierRunId"] += 1
        changed_report["reportDigest"] = report_digest(changed_report)
        with self.assertRaisesRegex(ValueError, "replay_binding_invalid"):
            build_admission(
                changed_report,
                self.policy,
                self.lock,
                self.candidate,
                self.environment_evidence,
                admission_id="sno-product-admission-test-001",
                admitted_at=self.admitted_at,
                expires_at=self.expires_at,
                admission_workflow_revision="a" * 40,
                admission_workflow_run_id=999,
                admission_workflow_run_attempt=1,
                workflow_actor_id=13579,
            )

        admission = self.build_valid_admission()
        admission["controls"]["deploymentAuthorized"] = True
        admission["admissionDigest"] = unsigned_digest(
            admission, "admissionDigest"
        )
        with self.assertRaisesRegex(ValueError, "admission_controls_invalid"):
            validate_admission(
                admission,
                self.policy,
                self.report,
                self.lock,
                self.candidate,
            )

        admission = self.build_valid_admission()
        admission["review"]["environmentEvidence"]["workflowApproval"][
            "workflowRunIdentityDigest"
        ] = payload_digest({"runId": 1000})
        admission["admissionDigest"] = unsigned_digest(
            admission, "admissionDigest"
        )
        with self.assertRaisesRegex(ValueError, "workflow_approval_invalid"):
            validate_admission(
                admission,
                self.policy,
                self.report,
                self.lock,
                self.candidate,
            )

    def test_self_review_expiry_and_rerun_are_rejected(self) -> None:
        evidence = copy.deepcopy(self.environment_evidence)
        evidence["workflowApproval"]["reviewerIdentityDigest"] = payload_digest(
            {"type": "User", "id": 13579}
        )
        with self.assertRaisesRegex(ValueError, "workflow_approval_invalid"):
            build_admission(
                self.report,
                self.policy,
                self.lock,
                self.candidate,
                evidence,
                admission_id="sno-product-admission-test-001",
                admitted_at=self.admitted_at,
                expires_at=self.expires_at,
                admission_workflow_revision="a" * 40,
                admission_workflow_run_id=999,
                admission_workflow_run_attempt=1,
                workflow_actor_id=13579,
            )

        with self.assertRaisesRegex(ValueError, "workflow_invalid"):
            build_admission(
                self.report,
                self.policy,
                self.lock,
                self.candidate,
                self.environment_evidence,
                admission_id="sno-product-admission-test-001",
                admitted_at=self.admitted_at,
                expires_at=self.expires_at,
                admission_workflow_revision="a" * 40,
                admission_workflow_run_id=999,
                admission_workflow_run_attempt=2,
                workflow_actor_id=13579,
            )

        admission = self.build_valid_admission()
        with self.assertRaisesRegex(ValueError, "admission_time_invalid"):
            validate_admission(
                admission,
                self.policy,
                self.report,
                self.lock,
                self.candidate,
                at=datetime(2026, 8, 10, tzinfo=timezone.utc),
            )

        with self.assertRaisesRegex(ValueError, "admission_time_invalid"):
            build_admission(
                self.report,
                self.policy,
                self.lock,
                self.candidate,
                self.environment_evidence,
                admission_id="sno-product-admission-test-001",
                admitted_at=datetime(2026, 8, 10, tzinfo=timezone.utc),
                expires_at=datetime(2026, 8, 11, tzinfo=timezone.utc),
                admission_workflow_revision="a" * 40,
                admission_workflow_run_id=999,
                admission_workflow_run_attempt=1,
                workflow_actor_id=13579,
            )

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "schemas"
                / "sno-trial-product-artifact-admission-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        for name, definition in schema["$defs"].items():
            if definition.get("type") == "object":
                self.assertIs(definition.get("additionalProperties"), False, name)

    def test_workflow_is_first_attempt_review_bound_and_non_mutating(self) -> None:
        source = (
            ROOT
            / ".github"
            / "workflows"
            / "sno-trial-product-artifact-admission.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "environment: sno-trial-product-artifact-admission", source
        )
        self.assertIn('[[ "$GITHUB_RUN_ATTEMPT" == "1" ]]', source)
        self.assertIn('[[ "$REPLAY_ARTIFACT_ID" == "8629559616" ]]', source)
        self.assertIn("actions: read", source)
        self.assertNotIn("packages: write", source)
        self.assertNotIn("id-token: write", source)
        self.assertNotIn("gcloud", source)
        self.assertNotIn("oc apply", source)
        self.assertNotIn("kubectl apply", source)


if __name__ == "__main__":
    unittest.main()
