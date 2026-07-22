from __future__ import annotations

import copy
import json
import unittest

from scripts.foundation_plan_summary import build_summary, validate_summary
from scripts.validate_repository import ROOT


class FoundationPlanSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = {
            "format_version": "1.2",
            "terraform_version": "1.14.6",
            "resource_changes": [
                {
                    "address": "google_compute_network.target",
                    "mode": "managed",
                    "type": "google_compute_network",
                    "name": "target",
                    "provider_name": "registry.terraform.io/hashicorp/google",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {"name": "orchestra-ocp-network"},
                    },
                },
                {
                    "address": 'google_project_iam_member.iap_operator["user:operator@example.com"]',
                    "mode": "managed",
                    "type": "google_project_iam_member",
                    "name": "foundation",
                    "provider_name": "registry.terraform.io/hashicorp/google",
                    "change": {
                        "actions": ["update"],
                        "before": {"value": "sensitive-fixture-before"},
                        "after": {"value": "sensitive-fixture-after"},
                    },
                },
            ],
        }
        self.summary = build_summary(
            self.plan,
            plan_digest=f"sha256:{1:064x}",
            prerequisite_projection_digest=f"sha256:{2:064x}",
            source_revision="a" * 40,
            workflow_run_id="12345",
            workflow_run_attempt="1",
            actor_id="37515097",
            reason="Generate the reviewed foundation preview",
            execution_mode="simulated",
            created_at="2026-07-22T07:00:00Z",
        )

    def test_summary_is_payload_free_and_non_authorizing(self) -> None:
        validate_summary(self.summary)
        encoded = json.dumps(self.summary)
        self.assertNotIn("sensitive-fixture", encoded)
        self.assertNotIn("operator@example.com", encoded)
        self.assertNotIn("google_compute_network.target", encoded)
        self.assertNotIn('"before"', encoded)
        self.assertNotIn('"after"', encoded)
        self.assertEqual(
            self.summary["terraform"]["actionCounts"],
            {
                "noOp": 0,
                "create": 1,
                "read": 0,
                "update": 1,
                "delete": 0,
                "replace": 0,
            },
        )
        self.assertEqual(
            self.summary["claims"],
            {
                "readOnlyPlan": True,
                "applyAuthorized": False,
                "infrastructureApplied": False,
                "campaignEvidence": False,
                "referenceProfileVerified": False,
            },
        )

    def test_apply_claim_tamper_is_rejected(self) -> None:
        changed = copy.deepcopy(self.summary)
        changed["claims"]["applyAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "claims_invalid"):
            validate_summary(changed)

    def test_unknown_terraform_action_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["resource_changes"][0]["change"]["actions"] = ["forget"]
        with self.assertRaisesRegex(ValueError, "actions_invalid"):
            build_summary(
                changed,
                plan_digest=f"sha256:{1:064x}",
                prerequisite_projection_digest=f"sha256:{2:064x}",
                source_revision="a" * 40,
                workflow_run_id="12345",
                workflow_run_attempt="1",
                actor_id="37515097",
                reason="Generate the reviewed foundation preview",
                execution_mode="simulated",
                created_at="2026-07-22T07:00:00Z",
            )

    def test_source_or_binding_replay_is_rejected(self) -> None:
        changed = copy.deepcopy(self.summary)
        changed["source"]["workflowRef"] = "other/workflow.yml@refs/heads/main"
        with self.assertRaisesRegex(ValueError, "source_invalid"):
            validate_summary(changed)
        changed = copy.deepcopy(self.summary)
        changed["bindings"]["topologyDigest"] = f"sha256:{9:064x}"
        with self.assertRaisesRegex(ValueError, "bindings_invalid"):
            validate_summary(changed)

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "foundation-plan-summary-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(schema["properties"]["bindings"]["additionalProperties"])
        self.assertFalse(schema["properties"]["source"]["additionalProperties"])
        self.assertFalse(schema["properties"]["terraform"]["additionalProperties"])
        self.assertFalse(schema["properties"]["claims"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["resourceChange"]["additionalProperties"])

    def test_workflow_is_environment_bound_and_cannot_apply(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "foundation-plan.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("environment: reference-lab-foundation-plan", workflow)
        self.assertIn("FOUNDATION_PLAN_REVIEW_GATE_CONFIGURED", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("github_environment_contract.py verify", workflow)
        self.assertIn('"$RUNNER_TEMP/github-token"', workflow)
        self.assertIn('--workflow-run-id "$GITHUB_RUN_ID"', workflow)
        self.assertIn('--workflow-run-attempt "$GITHUB_RUN_ATTEMPT"', workflow)
        self.assertIn('--workflow-actor-id "$GITHUB_ACTOR_ID"', workflow)
        self.assertIn("expected_main_sha", workflow)
        self.assertIn("-lock=false", workflow)
        self.assertIn('> "$RUNNER_TEMP/foundation-plan.log" 2>&1', workflow)
        self.assertNotIn("terraform apply", workflow)
        self.assertIn("path: ${{ runner.temp }}/foundation-plan-summary.json", workflow)
        self.assertNotIn("path: ${{ runner.temp }}/foundation.tfplan", workflow)

    def test_bootstrap_keeps_apply_identity_out_of_github_wif(self) -> None:
        bootstrap = (ROOT / "infra" / "terraform" / "bootstrap" / "main.tf").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'resource "google_service_account" "foundation_planner"', bootstrap
        )
        self.assertIn(
            'resource "google_service_account_iam_member" "foundation_plan_wif"',
            bootstrap,
        )
        self.assertNotIn(
            'resource "google_service_account_iam_member" "foundation_wif"',
            bootstrap,
        )
        self.assertIn("attribute.repository_id", bootstrap)
        self.assertIn("assertion.workflow_ref", bootstrap)
        self.assertIn("assertion.environment", bootstrap)


if __name__ == "__main__":
    unittest.main()
