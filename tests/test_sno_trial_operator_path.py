from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_operator_path import (
    CLAIMS,
    CONTROLS,
    build_assessment,
    collect_snapshot,
    read_source_network,
    validate_assessment,
    validate_snapshot,
)
from scripts.validate_sno_trial_profile import ROOT


FIXTURE = ROOT / "tests" / "fixtures" / "sno-trial-operator-path-ready.json"


def snapshot(**updates: object) -> dict[str, object]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    value.update(updates)
    return value


class SnoTrialOperatorPathTests(unittest.TestCase):
    def test_ready_path_is_observed_but_never_authorizes_install(self) -> None:
        report = build_assessment(
            snapshot(), "sno-operator-fixture-ready.1"
        )
        validate_assessment(report)
        self.assertEqual(
            report["decision"]["status"], "OPERATOR_PATH_OBSERVED"
        )
        self.assertEqual(report["decision"]["reasonCodes"], [])
        self.assertEqual(
            report["decision"]["nextAction"],
            "create-short-lived-lease-and-build-install-admission",
        )
        self.assertEqual(report["controls"], CONTROLS)
        self.assertEqual(report["claims"], CLAIMS)
        self.assertFalse(report["controls"]["installAuthorized"])

    def test_mac_arm64_path_is_blocked(self) -> None:
        report = build_assessment(
            snapshot(operatingSystem="darwin", architecture="arm64"),
            "sno-operator-fixture-mac.1",
        )
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertEqual(
            report["decision"]["reasonCodes"],
            [
                "ADMIN_HOST_OS_UNSUPPORTED",
                "ADMIN_HOST_ARCHITECTURE_UNSUPPORTED",
            ],
        )

    def test_identity_project_and_toolchain_drift_are_blocked(self) -> None:
        toolchain = {
            "installerVersion": "4.20.26",
            "clientVersion": "4.20.25",
        }
        report = build_assessment(
            snapshot(
                activeIdentityDigests=[],
                configuredProjectId="different-sno-project",
                toolchain=toolchain,
            ),
            "sno-operator-fixture-drift.1",
        )
        self.assertEqual(
            report["decision"]["reasonCodes"],
            [
                "ACTIVE_GCP_IDENTITY_INVALID",
                "GCP_PROJECT_MISMATCH",
                "INSTALLER_VERSION_MISMATCH",
                "CLIENT_VERSION_MISMATCH",
            ],
        )

    def test_live_collection_reduces_identity_and_cidr_to_digests(self) -> None:
        restricted = ROOT / "restricted"
        restricted.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="operator-path-test-", dir=restricted
        ) as directory:
            root = Path(directory)
            source = root / "source-cidr.txt"
            source.write_text("8.8.8.8/32\n", encoding="ascii")
            source.chmod(0o600)
            installer = root / "openshift-install"
            installer.write_text("fixture\n", encoding="ascii")
            installer.chmod(0o700)
            client = root / "oc"
            client.write_text("fixture\n", encoding="ascii")
            client.chmod(0o700)
            observed_commands: list[list[str]] = []

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                observed_commands.append(command)
                if command[:2] == ["gcloud", "auth"]:
                    stdout = json.dumps(
                        [{"account": "operator@example.com"}]
                    )
                elif command[:2] == ["gcloud", "config"]:
                    stdout = "prometa-orch-sno-fixture\n"
                elif command == [str(installer.resolve()), "version"]:
                    stdout = (
                        "openshift-install 4.20.27\n"
                        "built from commit must-not-survive\n"
                    )
                else:
                    stdout = (
                        "Client Version: 4.20.27\n"
                        "Kustomize Version: must-not-survive\n"
                    )
                return subprocess.CompletedProcess(
                    command, 0, stdout=stdout, stderr=""
                )

            collected = collect_snapshot(
                "prometa-orch-sno-fixture",
                source,
                installer,
                client,
                datetime(2026, 7, 27, 1, 5, tzinfo=timezone.utc),
                run,
                system=lambda: "Linux",
                machine=lambda: "x86_64",
            )
            report = build_assessment(
                collected, "sno-operator-fixture-live.1"
            )
        encoded = json.dumps(report)
        self.assertEqual(len(observed_commands), 4)
        self.assertNotIn("operator@example.com", encoded)
        self.assertNotIn("8.8.8.8", encoded)
        self.assertNotIn("must-not-survive", encoded)
        self.assertEqual(
            report["decision"]["status"], "OPERATOR_PATH_OBSERVED"
        )

    def test_source_cidr_file_must_be_private_public_and_host_scoped(
        self,
    ) -> None:
        restricted = ROOT / "restricted"
        restricted.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="operator-cidr-test-", dir=restricted
        ) as directory:
            source = Path(directory) / "source-cidr.txt"
            source.write_text("8.8.8.8/32\n", encoding="ascii")
            source.chmod(0o644)
            with self.assertRaisesRegex(
                ValueError, "sno_operator_path_source_cidr_file_invalid"
            ):
                read_source_network(source)
            source.chmod(0o600)
            self.assertEqual(read_source_network(source)["prefixLength"], 32)
            source.write_text("10.0.0.1/32\n", encoding="ascii")
            with self.assertRaisesRegex(
                ValueError, "sno_operator_path_source_cidr_invalid"
            ):
                read_source_network(source)
            source.write_text("8.8.8.0/24\n", encoding="ascii")
            with self.assertRaisesRegex(
                ValueError, "sno_operator_path_source_cidr_invalid"
            ):
                read_source_network(source)

    def test_snapshot_and_report_tamper_fail_closed(self) -> None:
        changed = snapshot(extra="not-allowed")
        with self.assertRaisesRegex(
            ValueError, "sno_operator_path_snapshot_keys_invalid"
        ):
            validate_snapshot(changed)
        report = build_assessment(
            snapshot(), "sno-operator-fixture-tamper.1"
        )
        changed_report = copy.deepcopy(report)
        changed_report["controls"]["installAuthorized"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_operator_path_controls_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["operatorPathState"]["architecture"] = "arm64"
        with self.assertRaisesRegex(
            ValueError, "sno_operator_path_decision_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["reportDigest"] = f"sha256:{'f' * 64}"
        with self.assertRaisesRegex(
            ValueError, "sno_operator_path_report_digest_invalid"
        ):
            validate_assessment(changed_report)

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (
                ROOT / "schemas" / "sno-trial-operator-path-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        for name in (
            "bindings",
            "operatorPathState",
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
        self.assertIn("scripts/sno_trial_operator_path.py assess", workflow)
        self.assertIn("scripts/sno_trial_operator_path.py verify", workflow)
        self.assertIn("observe-sno-trial-operator-path:", makefile)
        self.assertIn("verify-sno-trial-operator-path:", makefile)

    def test_cli_is_create_only_and_fixture_cannot_impersonate_live(self) -> None:
        from scripts.sno_trial_operator_path import main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            self.assertEqual(
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-operator-fixture-cli.1",
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
                ValueError, "sno_operator_path_output_exists"
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-operator-fixture-cli.2",
                        "--output",
                        str(output),
                    ]
                )
            live = snapshot(executionMode="live-diagnostic")
            source = Path(directory) / "live.json"
            source.write_text(json.dumps(live), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "sno_operator_path_live_snapshot_requires_collect",
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(source),
                        "--assessment-id",
                        "sno-operator-fixture-live-cli.1",
                        "--output",
                        str(Path(directory) / "live-report.json"),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
