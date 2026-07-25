from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_readiness import (
    CLAIMS,
    REQUIRED_APIS,
    ROOT,
    build_assessment,
    collect_snapshot,
    validate_assessment,
    validate_snapshot,
)
from scripts.validate_sno_trial_profile import canonical_digest


FIXTURE = ROOT / "tests" / "fixtures" / "sno-trial-cloud-pending.json"


def snapshot(**updates: object) -> dict[str, object]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    value.update(updates)
    return value


class SnoTrialReadinessTests(unittest.TestCase):
    def test_pending_fixture_is_waiting_and_cannot_authorize_mutation(self) -> None:
        report = build_assessment(snapshot(), "sno-readiness-fixture-pending.1")
        validate_assessment(report)
        self.assertEqual(report["executionMode"], "simulated")
        self.assertEqual(report["decision"]["status"], "WAITING_PROVIDER")
        self.assertEqual(report["decision"]["nextAction"], "await-quota-review")
        self.assertIn("QUOTA_REVIEW_PENDING", report["decision"]["reasonCodes"])
        self.assertIn("BILLING_DISABLED", report["decision"]["reasonCodes"])
        self.assertEqual(report["providerState"]["enabledRequiredApiCount"], 0)
        self.assertFalse(report["controls"]["cloudMutationAuthorized"])
        self.assertFalse(report["controls"]["campaignEligible"])
        self.assertEqual(report["controls"]["allowedCertificationSlots"], [])
        self.assertEqual(report["claims"], CLAIMS)

    def test_approved_quota_requires_a_fresh_plan(self) -> None:
        value = snapshot(
            quotaRequest={
                "status": "approved",
                "source": "operator-declared",
                "requestedAdditionalProjects": 1,
            }
        )
        report = build_assessment(value, "sno-readiness-fixture-approved.1")
        self.assertEqual(report["decision"]["status"], "READY_FOR_FRESH_PLAN")
        self.assertEqual(
            report["decision"]["nextAction"],
            "discard-old-plan-and-generate-fresh-foundation-plan",
        )
        self.assertTrue(report["decision"]["freshPlanRequired"])
        self.assertFalse(report["controls"]["foundationPlanApplied"])

    def test_enabled_apis_still_require_downstream_verification(self) -> None:
        value = snapshot(
            billingEnabled=True,
            enabledApis=sorted([*REQUIRED_APIS, "artifactregistry.googleapis.com"]),
            quotaRequest={
                "status": "approved",
                "source": "operator-declared",
                "requestedAdditionalProjects": 1,
            },
        )
        report = build_assessment(value, "sno-readiness-fixture-foundation.1")
        self.assertEqual(
            report["decision"]["status"], "DOWNSTREAM_VERIFICATION_REQUIRED"
        )
        self.assertEqual(
            report["decision"]["nextAction"],
            "verify-budget-dns-source-cidr-and-operator-lease",
        )
        self.assertEqual(report["providerState"]["missingRequiredApis"], [])
        self.assertEqual(
            report["providerState"]["enabledRequiredApiCount"],
            len(REQUIRED_APIS),
        )
        self.assertFalse(report["controls"]["cloudMutationAuthorized"])

    def test_partial_api_enablement_is_not_ready(self) -> None:
        value = snapshot(
            billingEnabled=True,
            enabledApis=[REQUIRED_APIS[0]],
            quotaRequest={
                "status": "approved",
                "source": "operator-declared",
                "requestedAdditionalProjects": 1,
            },
        )
        report = build_assessment(value, "sno-readiness-fixture-partial.1")
        self.assertEqual(report["decision"]["status"], "FOUNDATION_RECHECK_REQUIRED")
        self.assertIn("REQUIRED_APIS_MISSING", report["decision"]["reasonCodes"])

    def test_report_tampering_is_rejected(self) -> None:
        report = build_assessment(snapshot(), "sno-readiness-fixture-tamper.1")
        changed = copy.deepcopy(report)
        changed["controls"]["cloudMutationAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "sno_readiness_controls_invalid"):
            validate_assessment(changed)
        changed = copy.deepcopy(report)
        changed["providerState"]["billingEnabled"] = True
        with self.assertRaisesRegex(ValueError, "sno_readiness_decision_invalid"):
            validate_assessment(changed)
        changed = copy.deepcopy(report)
        changed["reportDigest"] = f"sha256:{'f' * 64}"
        with self.assertRaisesRegex(ValueError, "sno_readiness_report_digest_mismatch"):
            validate_assessment(changed)

    def test_snapshot_rejects_extra_fields_and_unsorted_apis(self) -> None:
        changed = snapshot(extra="not-allowed")
        with self.assertRaisesRegex(ValueError, "sno_readiness_snapshot_keys_invalid"):
            validate_snapshot(changed)
        changed = snapshot(
            enabledApis=["storage.googleapis.com", "compute.googleapis.com"]
        )
        with self.assertRaisesRegex(ValueError, "sno_readiness_snapshot_apis_invalid"):
            validate_snapshot(changed)
        changed = snapshot(enabledApis=[{"name": "compute.googleapis.com"}])
        with self.assertRaisesRegex(ValueError, "sno_readiness_snapshot_apis_invalid"):
            validate_snapshot(changed)

    def test_live_collector_reduces_gcloud_output_to_payload_free_facts(
        self,
    ) -> None:
        observed_commands: list[list[str]] = []

        def run(command: list[str]) -> subprocess.CompletedProcess[str]:
            observed_commands.append(command)
            if command[1:3] == ["projects", "describe"]:
                value: object = {
                    "projectId": "prometa-orch-sno-fixture",
                    "projectNumber": "123456789",
                    "lifecycleState": "ACTIVE",
                    "name": "must-not-survive",
                }
            elif command[1:4] == ["billing", "projects", "describe"]:
                value = {
                    "projectId": "prometa-orch-sno-fixture",
                    "billingEnabled": False,
                    "billingAccountName": "must-not-survive",
                }
            else:
                value = []
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps(value), stderr=""
            )

        result = collect_snapshot(
            "prometa-orch-sno-fixture",
            "pending",
            datetime(2026, 7, 25, 5, 0, tzinfo=timezone.utc),
            run,
        )
        encoded = json.dumps(result)
        self.assertEqual(result["executionMode"], "live-diagnostic")
        self.assertEqual(result["quotaRequest"]["source"], "operator-declared")
        self.assertNotIn("must-not-survive", encoded)
        self.assertNotIn("billingAccountName", encoded)
        self.assertNotIn("123456789", encoded)
        self.assertEqual(result["projectNumberDigest"], canonical_digest("123456789"))
        self.assertEqual(len(observed_commands), 3)
        self.assertTrue(all(command[0] == "gcloud" for command in observed_commands))

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "sno-trial-readiness-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        for name in (
            "bindings",
            "offlineCheck",
            "providerState",
            "decision",
            "controls",
            "claims",
        ):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])

    def test_cli_assessment_is_create_only_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "assessment.json"
            from scripts.sno_trial_readiness import main

            self.assertEqual(
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-readiness-fixture-cli.1",
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(["verify", "--report", str(output)]),
                0,
            )
            with self.assertRaisesRegex(ValueError, "sno_readiness_output_exists"):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-readiness-fixture-cli.2",
                        "--output",
                        str(output),
                    ]
                )

    def test_cli_fixture_lane_cannot_impersonate_live_collection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "snapshot.json"
            output = Path(directory) / "assessment.json"
            value = snapshot(executionMode="live-diagnostic")
            source.write_text(json.dumps(value), encoding="utf-8")
            from scripts.sno_trial_readiness import main

            with self.assertRaisesRegex(
                ValueError, "sno_readiness_live_snapshot_requires_collect"
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(source),
                        "--assessment-id",
                        "sno-readiness-fixture-live.1",
                        "--output",
                        str(output),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
