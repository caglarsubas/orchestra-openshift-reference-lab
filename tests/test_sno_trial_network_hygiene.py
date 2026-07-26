from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_network_hygiene import (
    CLAIMS,
    CONTROLS,
    build_assessment,
    collect_snapshot,
    validate_assessment,
    validate_snapshot,
)
from scripts.validate_sno_trial_profile import ROOT, canonical_digest


FIXTURE = ROOT / "tests" / "fixtures" / "sno-trial-network-dirty.json"


def snapshot(**updates: object) -> dict[str, object]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    value.update(updates)
    return value


class SnoTrialNetworkHygieneTests(unittest.TestCase):
    def test_dirty_default_network_is_blocked_and_non_authorizing(self) -> None:
        report = build_assessment(
            snapshot(), "sno-network-fixture-dirty.1"
        )
        validate_assessment(report)
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertEqual(
            report["decision"]["nextAction"],
            "remove-unused-default-network-resources",
        )
        self.assertIn(
            "DEFAULT_NETWORK_PRESENT", report["decision"]["reasonCodes"]
        )
        self.assertIn(
            "PUBLIC_INGRESS_RULES_PRESENT",
            report["decision"]["reasonCodes"],
        )
        self.assertEqual(report["providerState"]["networkCount"], 1)
        self.assertEqual(report["providerState"]["firewallRuleCount"], 4)
        self.assertEqual(report["providerState"]["internetIngressRuleCount"], 3)
        self.assertEqual(report["controls"], CONTROLS)
        self.assertEqual(report["claims"], CLAIMS)

    def test_empty_inventory_is_clean_but_grants_no_install_authority(self) -> None:
        report = build_assessment(
            snapshot(networks=[], firewalls=[]),
            "sno-network-fixture-clean.1",
        )
        self.assertEqual(report["decision"]["status"], "CLEAN")
        self.assertEqual(report["decision"]["reasonCodes"], [])
        self.assertEqual(
            report["decision"]["nextAction"],
            "continue-downstream-prerequisites",
        )
        self.assertFalse(report["controls"]["cleanupAuthorized"])
        self.assertFalse(report["controls"]["installAuthorized"])

    def test_live_collection_reduces_provider_output_to_digests_and_counts(
        self,
    ) -> None:
        observed_commands: list[list[str]] = []

        def run(command: list[str]) -> subprocess.CompletedProcess[str]:
            observed_commands.append(command)
            if command[2:4] == ["networks", "list"]:
                value: object = [
                    {
                        "name": "default",
                        "autoCreateSubnetworks": True,
                        "subnetworks": [
                            "https://compute.googleapis.com/projects/x/"
                            "regions/europe-west1/subnetworks/default"
                        ],
                        "description": "must-not-survive",
                    }
                ]
            else:
                value = [
                    {
                        "name": "default-allow-ssh",
                        "network": (
                            "https://compute.googleapis.com/projects/x/"
                            "global/networks/default"
                        ),
                        "direction": "INGRESS",
                        "disabled": False,
                        "sourceRanges": ["0.0.0.0/0"],
                        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                    }
                ]
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps(value), stderr=""
            )

        result = collect_snapshot(
            "prometa-orch-sno-fixture",
            datetime(2026, 7, 26, 13, 55, tzinfo=timezone.utc),
            run,
        )
        encoded = json.dumps(result)
        self.assertEqual(len(observed_commands), 2)
        self.assertNotIn("must-not-survive", encoded)
        self.assertNotIn("0.0.0.0/0", encoded)
        self.assertNotIn("ports", encoded)
        self.assertTrue(result["firewalls"][0]["internetIngress"])

    def test_snapshot_and_report_tamper_fail_closed(self) -> None:
        changed = snapshot(extra="not-allowed")
        with self.assertRaisesRegex(
            ValueError, "sno_network_hygiene_snapshot_keys_invalid"
        ):
            validate_snapshot(changed)
        report = build_assessment(
            snapshot(), "sno-network-fixture-tamper.1"
        )
        changed_report = copy.deepcopy(report)
        changed_report["controls"]["cleanupAuthorized"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_network_hygiene_controls_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["providerState"]["firewallRuleCount"] = 0
        with self.assertRaisesRegex(
            ValueError, "sno_network_hygiene_provider_state_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["reportDigest"] = f"sha256:{'f' * 64}"
        with self.assertRaisesRegex(
            ValueError, "sno_network_hygiene_report_digest_invalid"
        ):
            validate_assessment(changed_report)

    def test_inventory_digests_are_stable_and_payload_free(self) -> None:
        report = build_assessment(
            snapshot(), "sno-network-fixture-digest.1"
        )
        self.assertEqual(
            report["providerState"]["networkInventoryDigest"],
            canonical_digest(snapshot()["networks"]),
        )
        self.assertEqual(
            report["providerState"]["firewallInventoryDigest"],
            canonical_digest(snapshot()["firewalls"]),
        )

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "schemas"
                / "sno-trial-network-hygiene-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        for name in (
            "bindings",
            "providerState",
            "decision",
            "controls",
            "claims",
        ):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])

    def test_default_ci_and_make_targets_include_the_contract(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "scripts/sno_trial_network_hygiene.py assess", workflow
        )
        self.assertIn(
            "scripts/sno_trial_network_hygiene.py verify", workflow
        )
        self.assertIn("observe-sno-trial-network-hygiene:", makefile)
        self.assertIn("verify-sno-trial-network-hygiene:", makefile)

    def test_cli_is_create_only_and_fixture_cannot_impersonate_live(self) -> None:
        from scripts.sno_trial_network_hygiene import main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            self.assertEqual(
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-network-fixture-cli.1",
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(["verify", "--report", str(output)]), 0
            )
            with self.assertRaisesRegex(
                ValueError, "sno_network_hygiene_output_exists"
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-network-fixture-cli.2",
                        "--output",
                        str(output),
                    ]
                )
            live = snapshot(executionMode="live-diagnostic")
            source = Path(directory) / "live.json"
            source.write_text(json.dumps(live), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "sno_network_hygiene_live_snapshot_requires_collect",
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(source),
                        "--assessment-id",
                        "sno-network-fixture-live.1",
                        "--output",
                        str(Path(directory) / "live-report.json"),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
