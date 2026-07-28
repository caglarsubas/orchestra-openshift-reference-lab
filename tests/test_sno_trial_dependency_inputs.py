from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_dependency_inputs import (
    build_assessment,
    collect_snapshot,
    simulated_snapshot,
    validate_assessment,
    write_json_create_only,
)
from scripts.validate_repository import ROOT, canonical_digest


OBSERVED_AT = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)


class LiveOcFixture:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        get_index = command.index("get")
        kind = command[get_index + 1]
        name = command[get_index + 2]
        outputs = {
            ("storageclass", "standard-csi"): (
                "standard-csi\npd.csi.storage.gke.io\nWaitForFirstConsumer\ntrue\n"
            ),
            ("secret", "orchestra-sno-valkey-auth"): (
                "orchestra-sno-valkey-auth\nOpaque\npassword\n"
            ),
            ("secret", "orchestra-sno-valkey-server-tls"): (
                "orchestra-sno-valkey-server-tls\n"
                "kubernetes.io/tls\n"
                "ca.crt\n"
                "tls.crt\n"
                "tls.key\n"
            ),
            ("persistentvolumeclaim", "orchestra-sno-model-artifact"): (
                "orchestra-sno-model-artifact\n"
                "Bound\n"
                "ReadWriteOnce\n"
                "Filesystem\n"
                "standard-csi\n"
                "10Gi\n"
            ),
            ("secret", "orchestra-sno-model-auth"): (
                "orchestra-sno-model-auth\nOpaque\napi-keys\n"
            ),
            ("secret", "orchestra-sno-model-server-tls"): (
                "orchestra-sno-model-server-tls\nkubernetes.io/tls\ntls.crt\ntls.key\n"
            ),
        }
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=outputs[(kind, name)],
            stderr="",
        )


class SnoTrialDependencyInputTests(unittest.TestCase):
    def tooling(self, root: Path) -> tuple[Path, Path]:
        client = root / "oc"
        kubeconfig = root / "kubeconfig"
        client.write_text("#!/bin/sh\n", encoding="ascii")
        kubeconfig.write_text("fixture\n", encoding="ascii")
        client.chmod(0o700)
        kubeconfig.chmod(0o600)
        return client, kubeconfig

    def live_report(
        self,
    ) -> tuple[dict, LiveOcFixture, tempfile.TemporaryDirectory[str]]:
        temporary = tempfile.TemporaryDirectory()
        client, kubeconfig = self.tooling(Path(temporary.name))
        runner = LiveOcFixture()
        snapshot = collect_snapshot(
            client,
            kubeconfig,
            "standard-csi",
            OBSERVED_AT,
            runner,
        )
        report = build_assessment(
            snapshot,
            "sno-dependency-inputs-live.1",
            OBSERVED_AT,
        )
        return report, runner, temporary

    def test_simulated_observation_stays_unresolved_and_non_authorizing(self) -> None:
        report = build_assessment(
            simulated_snapshot(OBSERVED_AT),
            "sno-dependency-inputs-simulated.1",
            OBSERVED_AT,
        )
        validate_assessment(report)
        self.assertEqual(
            report["decision"],
            {
                "status": "DEPENDENCY_INPUTS_UNRESOLVED",
                "reasonCodes": [
                    "LIVE_OBSERVATION_REQUIRED",
                    "INPUT_OBJECT_MISSING",
                ],
            },
        )
        self.assertEqual(report["aggregate"]["observedCount"], 0)
        self.assertFalse(report["controls"]["secretValuesObserved"])
        self.assertFalse(report["controls"]["secretValuesStored"])
        self.assertFalse(report["controls"]["manifestsMaterialized"])
        self.assertFalse(report["controls"]["deploymentAuthorized"])
        self.assertFalse(report["claims"]["campaignEvidence"])

    def test_live_observer_records_metadata_only_and_can_pass(self) -> None:
        report, runner, temporary = self.live_report()
        self.addCleanup(temporary.cleanup)
        validate_assessment(report)
        self.assertEqual(
            report["decision"],
            {"status": "DEPENDENCY_INPUTS_OBSERVED", "reasonCodes": []},
        )
        self.assertEqual(report["aggregate"]["inputCount"], 6)
        self.assertEqual(report["aggregate"]["observedCount"], 6)
        self.assertEqual(report["aggregate"]["validCount"], 6)
        self.assertEqual(report["aggregate"]["unresolvedCount"], 0)
        self.assertEqual(
            report["aggregate"]["storageClassNameDigest"],
            canonical_digest("standard-csi"),
        )
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("standard-csi", serialized)
        self.assertNotIn("fixture-secret-value", serialized)
        self.assertNotIn("api-key-value", serialized)
        self.assertEqual(len(runner.commands), 6)
        for command in runner.commands:
            joined = " ".join(command)
            self.assertNotIn("-o json", joined)
            self.assertNotIn("--output json", joined)
            self.assertNotIn("base64decode", joined.lower())
            self.assertNotIn(".stringData", joined)
        secret_commands = [
            command for command in runner.commands if "secret" in command
        ]
        self.assertEqual(len(secret_commands), 4)
        for command in secret_commands:
            template = command[-1]
            self.assertIn("range $k,$v := .data", template)
            self.assertNotIn("{{$v}}", template)

    def test_missing_key_and_wrong_type_are_fail_closed(self) -> None:
        report, _, temporary = self.live_report()
        self.addCleanup(temporary.cleanup)
        changed = copy.deepcopy(report)
        observation = changed["observations"][1]
        observation["observedRequiredKeyCount"] = 0
        observation["missingRequiredKeyCount"] = 1
        observation["propertiesValid"] = False
        observation["reasonCodes"] = ["INPUT_KEY_MISSING"]
        changed["aggregate"]["validCount"] = 5
        changed["aggregate"]["unresolvedCount"] = 1
        changed["decision"] = {
            "status": "DEPENDENCY_INPUTS_UNRESOLVED",
            "reasonCodes": ["INPUT_KEY_MISSING"],
        }
        changed["reportDigest"] = canonical_digest(
            {key: value for key, value in changed.items() if key != "reportDigest"}
        )
        validate_assessment(changed)

        malformed = copy.deepcopy(changed)
        malformed["observations"][1]["propertiesValid"] = True
        malformed["reportDigest"] = canonical_digest(
            {key: value for key, value in malformed.items() if key != "reportDigest"}
        )
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_inputs_observation_invalid"
        ):
            validate_assessment(malformed)

    def test_report_tamper_and_live_snapshot_replay_are_rejected(self) -> None:
        report, _, temporary = self.live_report()
        self.addCleanup(temporary.cleanup)
        changed = copy.deepcopy(report)
        changed["aggregate"]["validCount"] = 5
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_inputs_report_aggregate_invalid"
        ):
            validate_assessment(changed)

        changed = copy.deepcopy(report)
        changed["assessmentId"] = "sno-dependency-inputs-live.2"
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_inputs_report_digest_invalid"
        ):
            validate_assessment(changed)

        changed = copy.deepcopy(report)
        changed["observations"][0]["observed"] = False
        changed["observations"][0]["resolvedNameDigest"] = None
        changed["observations"][0]["propertiesValid"] = False
        changed["observations"][0]["reasonCodes"] = []
        changed["aggregate"]["observedCount"] = 5
        changed["aggregate"]["validCount"] = 5
        changed["aggregate"]["unresolvedCount"] = 1
        changed["reportDigest"] = canonical_digest(
            {key: value for key, value in changed.items() if key != "reportDigest"}
        )
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_inputs_observation_semantics_invalid"
        ):
            validate_assessment(changed)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        from scripts.sno_trial_dependency_inputs import load_json

        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "duplicate.json"
            payload.write_text(
                '{"schemaVersion":1,"schemaVersion":2}', encoding="ascii"
            )
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_inputs_json_duplicate_key"
            ):
                load_json(payload)

    def test_private_tooling_and_create_only_output_are_enforced(self) -> None:
        report = build_assessment(
            simulated_snapshot(OBSERVED_AT),
            "sno-dependency-inputs-output.1",
            OBSERVED_AT,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client, kubeconfig = self.tooling(root)
            kubeconfig.chmod(0o644)
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_inputs_tooling_invalid"
            ):
                collect_snapshot(
                    client,
                    kubeconfig,
                    "standard-csi",
                    OBSERVED_AT,
                    LiveOcFixture(),
                )

            output = root / "report.json"
            write_json_create_only(output, report)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_inputs_output_write_failed"
            ):
                write_json_create_only(output, report)

    def test_schema_is_closed_and_accepts_reports(self) -> None:
        schema = (
            ROOT / "schemas" / "sno-trial-dependency-input-observation-v1.schema.json"
        )
        report = build_assessment(
            simulated_snapshot(OBSERVED_AT),
            "sno-dependency-inputs-schema.1",
            OBSERVED_AT,
        )
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "report.json"
            payload.write_text(json.dumps(report), encoding="utf-8")
            completed = subprocess.run(
                [
                    "npx",
                    "--yes",
                    "ajv-cli@5.0.0",
                    "validate",
                    "--spec=draft2020",
                    f"-s={schema}",
                    f"-d={payload}",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0)

            changed = copy.deepcopy(report)
            changed["unexpected"] = True
            payload.write_text(json.dumps(changed), encoding="utf-8")
            completed = subprocess.run(
                [
                    "npx",
                    "--yes",
                    "ajv-cli@5.0.0",
                    "validate",
                    "--spec=draft2020",
                    f"-s={schema}",
                    f"-d={payload}",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)

    def test_repository_wires_operator_targets_docs_and_ci(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        runbook = (ROOT / "docs" / "runbooks" / "sno-trial.md").read_text(
            encoding="utf-8"
        )
        for target in (
            "observe-sno-trial-dependency-inputs:",
            "verify-sno-trial-dependency-inputs:",
            "materialize-sno-trial-dependency-manifests:",
            "verify-sno-trial-dependency-materialization:",
        ):
            self.assertIn(target, makefile)
        self.assertIn("tests.test_sno_trial_dependency_inputs", workflow)
        self.assertIn("tests.test_materialize_sno_trial_dependency_manifests", workflow)
        self.assertIn("DEPENDENCY_INPUTS_OBSERVED", runbook)
        self.assertIn("grants no apply authority", runbook)


if __name__ == "__main__":
    unittest.main()
