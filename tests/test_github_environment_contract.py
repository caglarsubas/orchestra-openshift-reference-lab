from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.collect_prerequisite_observation import observe_github_environment
from scripts.github_environment_contract import (
    fetch_environment_evidence,
    payload_digest,
    read_restricted_token,
    validate_environment_payloads,
    validate_workflow_approvals,
)
from scripts.validate_repository import ROOT


class GithubEnvironmentContractTests(unittest.TestCase):
    def setUp(self) -> None:
        policy = json.loads(
            (ROOT / "config" / "prerequisite-observation-policy.lock.json").read_text(
                encoding="utf-8"
            )
        )
        self.expected = policy["gcp"]["wif"]
        self.repository = {
            "id": 1307302690,
            "full_name": "caglarsubas/orchestra-openshift-reference-lab",
            "private": True,
            "visibility": "private",
            "default_branch": "main",
            "archived": False,
            "owner": {"id": 37515097, "login": "repository-owner-fixture"},
        }
        self.environment = {
            "id": 987654,
            "name": "reference-lab-foundation-plan",
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
            "protection_rules": [
                {
                    "id": 1,
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {
                            "type": "User",
                            "reviewer": {
                                "id": 24681012,
                                "login": "independent-reviewer-fixture",
                            },
                        }
                    ],
                },
                {"id": 2, "type": "branch_policy"},
            ],
        }
        self.branches = {
            "total_count": 1,
            "branch_policies": [{"id": 3, "name": "main"}],
        }
        self.approvals = [
            {
                "state": "approved",
                "comment": "fixture comment must not enter evidence",
                "environments": [
                    {
                        "id": 987654,
                        "name": "reference-lab-foundation-plan",
                    }
                ],
                "user": {
                    "id": 24681012,
                    "login": "independent-reviewer-fixture",
                    "type": "User",
                },
            }
        ]

    def test_valid_environment_emits_payload_free_evidence(self) -> None:
        evidence = validate_environment_payloads(
            self.repository,
            self.environment,
            self.branches,
            self.expected,
        )
        encoded = json.dumps(evidence)
        self.assertEqual(evidence["reviewerCount"], 1)
        self.assertTrue(evidence["preventSelfReview"])
        self.assertNotIn("independent-reviewer-fixture", encoded)
        self.assertNotIn("repository-owner-fixture", encoded)
        self.assertEqual(
            evidence["reviewerIdentityDigests"],
            [payload_digest({"type": "User", "id": 24681012})],
        )

    def test_repository_owner_cannot_be_the_required_reviewer(self) -> None:
        changed = copy.deepcopy(self.environment)
        changed["protection_rules"][0]["reviewers"][0]["reviewer"]["id"] = 37515097
        with self.assertRaisesRegex(ValueError, "owner_reviewer_forbidden"):
            validate_environment_payloads(
                self.repository, changed, self.branches, self.expected
            )

    def test_self_review_or_missing_reviewer_is_rejected(self) -> None:
        changed = copy.deepcopy(self.environment)
        changed["protection_rules"][0]["prevent_self_review"] = False
        with self.assertRaisesRegex(ValueError, "self_review_invalid"):
            validate_environment_payloads(
                self.repository, changed, self.branches, self.expected
            )
        changed = copy.deepcopy(self.environment)
        changed["protection_rules"][0]["reviewers"] = []
        with self.assertRaisesRegex(ValueError, "reviewers_invalid"):
            validate_environment_payloads(
                self.repository, changed, self.branches, self.expected
            )

    def test_duplicate_reviewer_is_rejected(self) -> None:
        changed = copy.deepcopy(self.environment)
        changed["protection_rules"][0]["reviewers"].append(
            copy.deepcopy(changed["protection_rules"][0]["reviewers"][0])
        )
        with self.assertRaisesRegex(ValueError, "reviewers_invalid"):
            validate_environment_payloads(
                self.repository, changed, self.branches, self.expected
            )

    def test_only_exact_main_branch_policy_is_accepted(self) -> None:
        changed = copy.deepcopy(self.branches)
        changed["branch_policies"][0]["name"] = "release/*"
        with self.assertRaisesRegex(ValueError, "branch_policy_invalid"):
            validate_environment_payloads(
                self.repository, self.environment, changed, self.expected
            )
        changed = copy.deepcopy(self.environment)
        changed["deployment_branch_policy"] = {
            "protected_branches": True,
            "custom_branch_policies": False,
        }
        with self.assertRaisesRegex(ValueError, "deployment_policy_invalid"):
            validate_environment_payloads(
                self.repository, changed, self.branches, self.expected
            )

    def test_repository_identity_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.repository)
        changed["id"] = 999
        with self.assertRaisesRegex(ValueError, "repository_invalid"):
            validate_environment_payloads(
                changed, self.environment, self.branches, self.expected
            )

    def test_current_workflow_approval_is_bound_without_identity_payloads(self) -> None:
        evidence = validate_workflow_approvals(
            self.approvals,
            self.environment,
            self.expected,
            workflow_run_id=123456,
            workflow_run_attempt=1,
            workflow_actor_id=13579,
        )
        encoded = json.dumps(evidence)
        self.assertTrue(evidence["independentApproval"])
        self.assertNotIn("fixture comment", encoded)
        self.assertNotIn("independent-reviewer-fixture", encoded)
        self.assertNotIn("24681012", encoded)
        self.assertNotIn("123456", encoded)

    def test_workflow_initiator_or_unconfigured_approver_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "approval_not_independent"):
            validate_workflow_approvals(
                self.approvals,
                self.environment,
                self.expected,
                workflow_run_id=123456,
                workflow_run_attempt=1,
                workflow_actor_id=24681012,
            )
        changed = copy.deepcopy(self.approvals)
        changed[0]["user"]["id"] = 99999
        with self.assertRaisesRegex(ValueError, "approval_not_independent"):
            validate_workflow_approvals(
                changed,
                self.environment,
                self.expected,
                workflow_run_id=123456,
                workflow_run_attempt=1,
                workflow_actor_id=13579,
            )

    def test_rejected_or_ambiguous_workflow_review_is_rejected(self) -> None:
        changed = copy.deepcopy(self.approvals)
        changed[0]["state"] = "rejected"
        with self.assertRaisesRegex(ValueError, "approval_rejected"):
            validate_workflow_approvals(
                changed,
                self.environment,
                self.expected,
                workflow_run_id=123456,
                workflow_run_attempt=1,
                workflow_actor_id=13579,
            )
        with self.assertRaisesRegex(ValueError, "missing_or_ambiguous"):
            validate_workflow_approvals(
                self.approvals + copy.deepcopy(self.approvals),
                self.environment,
                self.expected,
                workflow_run_id=123456,
                workflow_run_attempt=1,
                workflow_actor_id=13579,
            )

    def test_workflow_rerun_cannot_reuse_an_approval(self) -> None:
        with self.assertRaisesRegex(ValueError, "workflow_rerun_forbidden"):
            validate_workflow_approvals(
                self.approvals,
                self.environment,
                self.expected,
                workflow_run_id=123456,
                workflow_run_attempt=2,
                workflow_actor_id=13579,
            )

    def test_token_file_must_be_private_and_is_never_returned(self) -> None:
        token = "fixture-github-read-token-1234567890"
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "github-token"
            token_path.write_text(token, encoding="ascii")
            token_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "permissions_invalid"):
                read_restricted_token(token_path)
            token_path.chmod(0o600)
            self.assertEqual(read_restricted_token(token_path), token)

            calls: list[tuple[str, str]] = []

            def get_json(path: str, supplied_token: str) -> dict:
                calls.append((path, supplied_token))
                if path.endswith("?per_page=100"):
                    return self.branches
                if "/environments/" in path:
                    return self.environment
                return self.repository

            evidence = fetch_environment_evidence(
                token_path,
                self.expected,
                get_json=get_json,
            )
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(supplied == token for _, supplied in calls))
        self.assertNotIn(token, json.dumps(evidence))

    def test_fetch_can_bind_the_current_workflow_approval(self) -> None:
        token = "fixture-github-read-token-1234567890"
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "github-token"
            token_path.write_text(token, encoding="ascii")
            token_path.chmod(0o600)
            calls: list[str] = []

            def get_json(path: str, supplied_token: str):
                self.assertEqual(supplied_token, token)
                calls.append(path)
                if path.endswith("/approvals"):
                    return self.approvals
                if path.endswith("?per_page=100"):
                    return self.branches
                if "/environments/" in path:
                    return self.environment
                return self.repository

            evidence = fetch_environment_evidence(
                token_path,
                self.expected,
                get_json=get_json,
                workflow_run_id=123456,
                workflow_run_attempt=1,
                workflow_actor_id=13579,
            )
        self.assertEqual(len(calls), 4)
        self.assertTrue(evidence["workflowApproval"]["independentApproval"])
        self.assertTrue(calls[-1].endswith("/actions/runs/123456/approvals"))

    def test_prerequisite_observer_is_fail_closed(self) -> None:
        token = "fixture-github-read-token-1234567890"
        policy = {"gcp": {"wif": self.expected}}
        now = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)

        def get_json(path: str, supplied_token: str) -> dict:
            self.assertEqual(supplied_token, token)
            if path.endswith("?per_page=100"):
                return self.branches
            if "/environments/" in path:
                return self.environment
            return self.repository

        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "github-token"
            token_path.write_text(token, encoding="ascii")
            token_path.chmod(0o600)
            self.assertEqual(
                observe_github_environment(
                    token_path,
                    now,
                    policy,
                    get_json=get_json,
                )["status"],
                "passed",
            )
            changed_environment = copy.deepcopy(self.environment)
            changed_environment["protection_rules"][0]["prevent_self_review"] = False

            def invalid_get_json(path: str, supplied_token: str) -> dict:
                self.assertEqual(supplied_token, token)
                if path.endswith("?per_page=100"):
                    return self.branches
                if "/environments/" in path:
                    return changed_environment
                return self.repository

            check = observe_github_environment(
                token_path,
                now,
                policy,
                get_json=invalid_get_json,
            )
        self.assertEqual(check["status"], "failed")
        self.assertEqual(check["reasonCode"], "GITHUB_ENVIRONMENT_PROTECTION_INVALID")
        self.assertEqual(
            observe_github_environment(None, now, policy)["reasonCode"],
            "GITHUB_ENVIRONMENT_TOKEN_MISSING",
        )


if __name__ == "__main__":
    unittest.main()
