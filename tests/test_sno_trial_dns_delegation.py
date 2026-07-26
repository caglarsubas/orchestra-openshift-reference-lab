from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_dns_delegation import (
    CLAIMS,
    CONTROLS,
    DNS_NAME,
    MANAGED_ZONE_NAME,
    build_assessment,
    collect_snapshot,
    validate_assessment,
    validate_snapshot,
)
from scripts.validate_sno_trial_profile import ROOT


FIXTURE = (
    ROOT / "tests" / "fixtures" / "sno-trial-dns-delegation-missing.json"
)


def snapshot(**updates: object) -> dict[str, object]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    value.update(updates)
    return value


def expected_nameservers() -> list[str]:
    return list(snapshot()["managedZone"]["nameServers"])  # type: ignore[index]


class SnoTrialDnsDelegationTests(unittest.TestCase):
    def test_missing_delegation_waits_without_install_authority(self) -> None:
        report = build_assessment(
            snapshot(), "sno-dns-fixture-missing.1"
        )
        validate_assessment(report)
        self.assertEqual(
            report["decision"]["status"], "WAITING_DELEGATION"
        )
        self.assertEqual(
            report["decision"]["reasonCodes"],
            ["PUBLIC_DELEGATION_MISSING"],
        )
        self.assertEqual(
            report["decision"]["nextAction"],
            "publish-parent-ns-delegation",
        )
        self.assertEqual(report["controls"], CONTROLS)
        self.assertEqual(report["claims"], CLAIMS)
        self.assertFalse(report["controls"]["installAuthorized"])

    def test_exact_delegation_is_observed_but_not_install_ready(self) -> None:
        report = build_assessment(
            snapshot(delegatedNameServers=expected_nameservers()),
            "sno-dns-fixture-observed.1",
        )
        self.assertEqual(
            report["decision"]["status"], "DELEGATION_OBSERVED"
        )
        self.assertEqual(report["decision"]["reasonCodes"], [])
        self.assertEqual(
            report["decision"]["nextAction"],
            "verify-source-cidr-admin-path-and-operator-lease",
        )
        self.assertTrue(report["providerState"]["delegationExact"])
        self.assertFalse(report["controls"]["installAuthorized"])
        self.assertFalse(report["claims"]["campaignEvidence"])

    def test_partial_or_wrong_delegation_blocks(self) -> None:
        report = build_assessment(
            snapshot(delegatedNameServers=expected_nameservers()[:3]),
            "sno-dns-fixture-mismatch.1",
        )
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertEqual(
            report["decision"]["reasonCodes"],
            ["PUBLIC_DELEGATION_MISMATCH"],
        )
        self.assertEqual(
            report["decision"]["nextAction"],
            "correct-parent-ns-delegation",
        )

    def test_managed_zone_mismatch_blocks(self) -> None:
        managed = copy.deepcopy(snapshot()["managedZone"])
        managed["dnsName"] = "ocp-lab.example.invalid."
        report = build_assessment(
            snapshot(managedZone=managed),
            "sno-dns-fixture-zone-mismatch.1",
        )
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertEqual(
            report["decision"]["reasonCodes"],
            ["MANAGED_ZONE_POLICY_MISMATCH"],
        )

    def test_live_collection_uses_only_read_only_commands(self) -> None:
        observed_commands: list[list[str]] = []
        nameservers = expected_nameservers()

        def run(command: list[str]) -> subprocess.CompletedProcess[str]:
            observed_commands.append(command)
            if command[0] == "gcloud":
                value = {
                    "name": MANAGED_ZONE_NAME,
                    "dnsName": DNS_NAME,
                    "visibility": "public",
                    "nameServers": [
                        item.rstrip(".").upper() for item in nameservers
                    ],
                    "description": "must-not-survive",
                }
                stdout = json.dumps(value)
            else:
                stdout = "\n".join(reversed(nameservers)) + "\n"
            return subprocess.CompletedProcess(
                command, 0, stdout=stdout, stderr=""
            )

        result = collect_snapshot(
            "prometa-orch-sno-fixture",
            datetime(2026, 7, 27, 0, 5, tzinfo=timezone.utc),
            run,
        )
        self.assertEqual(
            observed_commands,
            [
                [
                    "gcloud",
                    "dns",
                    "managed-zones",
                    "describe",
                    MANAGED_ZONE_NAME,
                    "--project=prometa-orch-sno-fixture",
                    "--format=json(name,dnsName,visibility,nameServers)",
                ],
                ["dig", "+short", "NS", DNS_NAME],
            ],
        )
        self.assertNotIn("must-not-survive", json.dumps(result))
        self.assertEqual(result["managedZone"]["nameServers"], nameservers)
        self.assertEqual(result["delegatedNameServers"], nameservers)

    def test_persisted_report_contains_no_raw_nameserver_values(self) -> None:
        report = build_assessment(
            snapshot(delegatedNameServers=expected_nameservers()),
            "sno-dns-fixture-payload-free.1",
        )
        encoded = json.dumps(report)
        self.assertNotIn("ns-cloud-", encoded)
        self.assertEqual(
            report["providerState"]["providerNameServerCount"], 4
        )
        self.assertEqual(
            report["providerState"]["delegatedNameServerCount"], 4
        )

    def test_snapshot_and_report_tamper_fail_closed(self) -> None:
        changed = snapshot(extra="not-allowed")
        with self.assertRaisesRegex(
            ValueError, "sno_dns_delegation_snapshot_keys_invalid"
        ):
            validate_snapshot(changed)
        report = build_assessment(
            snapshot(), "sno-dns-fixture-tamper.1"
        )
        changed_report = copy.deepcopy(report)
        changed_report["controls"]["installAuthorized"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_dns_delegation_controls_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["providerState"]["delegatedNameServerCount"] = 4
        with self.assertRaisesRegex(
            ValueError, "sno_dns_delegation_decision_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["reportDigest"] = f"sha256:{'f' * 64}"
        with self.assertRaisesRegex(
            ValueError, "sno_dns_delegation_report_digest_invalid"
        ):
            validate_assessment(changed_report)

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "schemas"
                / "sno-trial-dns-delegation-v1.schema.json"
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
            "scripts/sno_trial_dns_delegation.py assess", workflow
        )
        self.assertIn(
            "scripts/sno_trial_dns_delegation.py verify", workflow
        )
        self.assertIn("observe-sno-trial-dns-delegation:", makefile)
        self.assertIn("verify-sno-trial-dns-delegation:", makefile)

    def test_cli_is_create_only_and_fixture_cannot_impersonate_live(self) -> None:
        from scripts.sno_trial_dns_delegation import main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            self.assertEqual(
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-dns-fixture-cli.1",
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
                ValueError, "sno_dns_delegation_output_exists"
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-dns-fixture-cli.2",
                        "--output",
                        str(output),
                    ]
                )
            live = snapshot(executionMode="live-diagnostic")
            source = Path(directory) / "live.json"
            source.write_text(json.dumps(live), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "sno_dns_delegation_live_snapshot_requires_collect",
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(source),
                        "--assessment-id",
                        "sno-dns-fixture-live.1",
                        "--output",
                        str(Path(directory) / "live-report.json"),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
