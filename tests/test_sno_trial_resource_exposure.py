from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_resource_exposure import (
    CLAIMS,
    CONTROLS,
    RATE_CARD,
    RESOURCE_CLASSES,
    build_assessment,
    collect_snapshot,
    validate_assessment,
    validate_rate_card,
    validate_snapshot,
)
from scripts.validate_sno_trial_profile import ROOT


FIXTURE = (
    ROOT / "tests" / "fixtures" / "sno-trial-resource-exposure-active.json"
)


def snapshot(**updates: object) -> dict[str, object]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    value.update(updates)
    return value


def post_teardown_snapshot() -> dict[str, object]:
    value = snapshot(phase="post-teardown")
    value["target"]["instances"] = []  # type: ignore[index]
    value["target"]["disks"] = []  # type: ignore[index]
    value["operator"]["instances"] = []  # type: ignore[index]
    value["operator"]["disks"] = []  # type: ignore[index]
    for resource_class in RESOURCE_CLASSES:
        value["target"]["resourceNames"][resource_class] = []  # type: ignore[index]
    return value


class SnoTrialResourceExposureTests(unittest.TestCase):
    def test_active_exposure_is_estimated_but_never_billed_spend(self) -> None:
        report = build_assessment(
            snapshot(), "sno-exposure-fixture-active.1"
        )
        validate_assessment(report)
        self.assertEqual(
            report["decision"]["status"], "ACTIVE_EXPOSURE_OBSERVED"
        )
        self.assertEqual(report["decision"]["reasonCodes"], [])
        self.assertEqual(
            report["costEstimate"]["estimatedUsdSubtotal"], "0.620026"
        )
        self.assertFalse(report["costEstimate"]["estimateComplete"])
        self.assertFalse(report["costEstimate"]["billingExportVerified"])
        self.assertEqual(
            report["costEstimate"]["excludedChargeClasses"],
            [
                "cloud-dns",
                "credits-and-discounts",
                "external-ip",
                "load-balancing",
                "network-egress",
                "tax",
            ],
        )
        self.assertEqual(report["controls"], CONTROLS)
        self.assertEqual(report["claims"], CLAIMS)

    def test_post_teardown_requires_zero_target_and_operator_residuals(
        self,
    ) -> None:
        clean = build_assessment(
            post_teardown_snapshot(), "sno-exposure-fixture-clean.1"
        )
        self.assertEqual(
            clean["decision"]["status"], "TEARDOWN_RESIDUALS_CLEAN"
        )
        self.assertEqual(clean["decision"]["reasonCodes"], [])
        self.assertEqual(
            clean["decision"]["nextAction"],
            "close-lease-and-preserve-payload-free-receipt",
        )
        dirty = post_teardown_snapshot()
        dirty["target"]["resourceNames"]["buckets"] = [  # type: ignore[index]
            "orchestra-trial-oidc"
        ]
        dirty["operator"]["instances"] = [  # type: ignore[index]
            copy.deepcopy(snapshot()["operator"]["instances"][0])  # type: ignore[index]
        ]
        report = build_assessment(
            dirty, "sno-exposure-fixture-residual.1"
        )
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertEqual(
            report["decision"]["reasonCodes"],
            ["TARGET_RESIDUALS_PRESENT", "OPERATOR_RESIDUALS_PRESENT"],
        )

    def test_unknown_machine_type_and_cost_ceiling_fail_closed(self) -> None:
        unknown = snapshot()
        unknown["target"]["instances"][0][  # type: ignore[index]
            "machineType"
        ] = "c4-standard-8"
        report = build_assessment(
            unknown, "sno-exposure-fixture-unpriced.1"
        )
        self.assertIn(
            "UNPRICED_RESOURCE_PRESENT", report["decision"]["reasonCodes"]
        )
        self.assertEqual(
            report["costEstimate"]["unpricedResourceClasses"],
            ["machine:c4-standard-8"],
        )
        expensive = snapshot(observedAt="2026-08-10T16:05:00Z")
        report = build_assessment(
            expensive, "sno-exposure-fixture-ceiling.1"
        )
        self.assertIn(
            "ESTIMATE_AT_OR_ABOVE_ALERT_CEILING",
            report["decision"]["reasonCodes"],
        )

    def test_snapshot_and_report_tamper_fail_closed(self) -> None:
        changed = snapshot(extra="forbidden")
        with self.assertRaisesRegex(
            ValueError, "sno_exposure_snapshot_keys_invalid"
        ):
            validate_snapshot(changed)
        report = build_assessment(
            snapshot(), "sno-exposure-fixture-tamper.1"
        )
        changed_report = copy.deepcopy(report)
        changed_report["controls"]["teardownAuthorized"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_exposure_controls_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["costEstimate"]["estimatedUsdSubtotal"] = "12.000000"
        with self.assertRaisesRegex(
            ValueError, "sno_exposure_estimate_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["reportDigest"] = f"sha256:{'f' * 64}"
        with self.assertRaisesRegex(
            ValueError, "sno_exposure_report_digest_invalid"
        ):
            validate_assessment(changed_report)

    def test_rate_card_and_schema_are_strict(self) -> None:
        rate_card = json.loads(RATE_CARD.read_text(encoding="utf-8"))
        validate_rate_card(rate_card)
        changed = copy.deepcopy(rate_card)
        changed["estimateIsBilledSpend"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_exposure_rate_card_identity_invalid"
        ):
            validate_rate_card(changed)
        schema = json.loads(
            (
                ROOT
                / "schemas"
                / "sno-trial-resource-exposure-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        for name in (
            "bindings",
            "managedNameCounts",
            "targetState",
            "operatorState",
            "resourceState",
            "costEstimate",
            "decision",
            "controls",
            "claims",
        ):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])

    def test_live_collection_reduces_names_to_counts_and_digests(self) -> None:
        fixture = snapshot()
        observed: list[list[str]] = []

        def run(command: list[str]) -> subprocess.CompletedProcess[str]:
            observed.append(command)
            joined = " ".join(command)
            if "compute instances list" in joined:
                value = (
                    fixture["operator"]["instances"]
                    if "prometa-staging-fixture" in joined
                    else fixture["target"]["instances"]
                )
                value = [
                    {
                        **item,
                        "machineType": (
                            "https://compute.googleapis.com/compute/v1/"
                            f"machineTypes/{item['machineType']}"
                        ),
                    }
                    for item in value  # type: ignore[union-attr]
                ]
            elif "compute disks list" in joined:
                source = (
                    fixture["operator"]["disks"]
                    if "prometa-staging-fixture" in joined
                    else fixture["target"]["disks"]
                )
                value = [
                    {
                        "name": item["name"],
                        "type": (
                            "https://compute.googleapis.com/compute/v1/"
                            f"diskTypes/{item['diskType']}"
                        ),
                        "sizeGb": str(item["sizeGiB"]),
                        "creationTimestamp": item["creationTimestamp"],
                    }
                    for item in source  # type: ignore[union-attr]
                ]
            else:
                class_by_token = {
                    "addresses": "addresses",
                    "buckets": "buckets",
                    "roles": "customRoles",
                    "firewall-rules": "firewalls",
                    "forwarding-rules": "forwardingRules",
                    "networks": "networks",
                    "routers": "routers",
                    "service-accounts": "serviceAccounts",
                    "subnets": "subnetworks",
                    "workload-identity-pools": "workloadIdentityPools",
                }
                resource_class = next(
                    class_name
                    for token, class_name in class_by_token.items()
                    if token in command
                )
                field = "email" if resource_class == "serviceAccounts" else "name"
                value = [
                    {field: name}
                    for name in fixture["target"]["resourceNames"][  # type: ignore[index]
                        resource_class
                    ]
                ]
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps(value), stderr=""
            )

        collected = collect_snapshot(
            "prometa-orch-sno-fixture",
            "prometa-staging-fixture",
            "orchestra-sno-operator-fixture",
            "active",
            datetime(2026, 7, 27, 16, 5, tzinfo=timezone.utc),
            run,
        )
        report = build_assessment(
            collected, "sno-exposure-fixture-live.1"
        )
        encoded = json.dumps(report)
        self.assertEqual(len(observed), 14)
        self.assertNotIn("orchestra-trial-fixture-master-0", encoded)
        self.assertNotIn("orchestra-sno-operator-fixture", encoded)
        self.assertTrue(
            all(
                command[0] == "gcloud"
                and not any(
                    token in command
                    for token in ("create", "delete", "update", "set-iam-policy")
                )
                for command in observed
            )
        )

    def test_cli_is_create_only_and_fixture_cannot_impersonate_live(
        self,
    ) -> None:
        from scripts.sno_trial_resource_exposure import main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            args = [
                "assess",
                "--snapshot",
                str(FIXTURE),
                "--assessment-id",
                "sno-exposure-fixture-cli.1",
                "--output",
                str(output),
            ]
            self.assertEqual(main(args), 0)
            with self.assertRaisesRegex(
                ValueError, "sno_exposure_output_exists"
            ):
                main(args)
            live = snapshot(executionMode="live-diagnostic")
            live_path = Path(directory) / "live.json"
            live_path.write_text(json.dumps(live), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "sno_exposure_live_snapshot_requires_collect"
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(live_path),
                        "--assessment-id",
                        "sno-exposure-fixture-cli.2",
                        "--output",
                        str(Path(directory) / "live-report.json"),
                    ]
                )

    def test_default_ci_and_make_targets_include_the_contract(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "scripts/sno_trial_resource_exposure.py assess", workflow
        )
        self.assertIn(
            "scripts/sno_trial_resource_exposure.py verify", workflow
        )
        self.assertIn("observe-sno-trial-resource-exposure:", makefile)
        self.assertIn("verify-sno-trial-resource-exposure:", makefile)


if __name__ == "__main__":
    unittest.main()
