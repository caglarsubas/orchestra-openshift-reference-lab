from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.materialize_sno_trial_dependency_manifests import (
    KUSTOMIZATION_PATH,
    RESOURCE_FILES,
    build_receipt,
    materialize_resources,
)
from scripts.sno_trial_cluster_observation import build_assessment as build_cluster
from scripts.sno_trial_dependency_dry_run import (
    build_assessment,
    collect_snapshot,
    validate_assessment,
)
from scripts.validate_repository import ROOT, canonical_digest


AT = datetime(2026, 7, 28, 5, 0, tzinfo=timezone.utc)
CLUSTER_FIXTURE = ROOT / "tests" / "fixtures" / "sno-trial-cluster-healthy.json"


def live_cluster() -> dict:
    snapshot = json.loads(CLUSTER_FIXTURE.read_text(encoding="utf-8"))
    snapshot["executionMode"] = "live-diagnostic"
    snapshot["observedAt"] = "2026-07-28T05:00:00Z"
    return build_cluster(snapshot, "sno-cluster-dependency-dry-run.1")


class DryRunFixture:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if "apply" in command:
            path = Path(command[command.index("--filename") + 1])
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=path.read_text(encoding="utf-8"),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


class SnoTrialDependencyDryRunTests(unittest.TestCase):
    def materialization(self, parent: Path) -> Path:
        resources, replacements = materialize_resources("standard-csi")
        input_report = {
            "assessmentId": "sno-dependency-inputs-dry-run.1",
            "reportDigest": canonical_digest("dependency-inputs"),
        }
        receipt = build_receipt(
            input_report,
            resources,
            "standard-csi",
            replacements,
            "sno-dependency-materialization-dry-run.1",
            AT,
        )
        directory = parent / "materialized"
        directory.mkdir(mode=0o700)
        for filename, resource in zip(RESOURCE_FILES, resources, strict=True):
            path = directory / filename
            path.write_text(json.dumps(resource), encoding="ascii")
            path.chmod(0o600)
        kustomization = directory / "kustomization.yaml"
        kustomization.write_text(
            KUSTOMIZATION_PATH.read_text(encoding="ascii"), encoding="ascii"
        )
        kustomization.chmod(0o600)
        receipt_path = directory / "materialization-receipt.json"
        receipt_path.write_text(json.dumps(receipt), encoding="ascii")
        receipt_path.chmod(0o600)
        return directory

    def tooling(self, parent: Path) -> tuple[Path, Path]:
        client = parent / "oc"
        client.write_text("#!/bin/sh\n", encoding="ascii")
        client.chmod(0o700)
        kubeconfig = parent / "kubeconfig"
        kubeconfig.write_text("fixture\n", encoding="ascii")
        kubeconfig.chmod(0o600)
        return client, kubeconfig

    def test_live_dry_run_is_payload_free_and_non_authorizing(self) -> None:
        restricted = ROOT / "restricted"
        restricted.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="dependency-dry-run-", dir=restricted
        ) as raw:
            root = Path(raw)
            directory = self.materialization(root)
            client, kubeconfig = self.tooling(root)
            runner = DryRunFixture()
            snapshot = collect_snapshot(
                live_cluster(), client, kubeconfig, directory, AT, runner
            )
        report = build_assessment(snapshot, "sno-dependency-dry-run-live.1", AT)
        validate_assessment(report)
        self.assertEqual(
            report["decision"]["status"], "SERVER_DRY_RUN_OBSERVED_WITH_GAPS"
        )
        self.assertEqual(report["aggregate"]["acceptedCount"], 12)
        self.assertEqual(report["aggregate"]["unchangedCount"], 12)
        self.assertFalse(report["controls"]["deploymentAuthorized"])
        self.assertFalse(report["controls"]["connectivityVerified"])
        self.assertNotIn("orchestra-sno-valkey", json.dumps(report))
        for command in runner.commands:
            self.assertTrue("get" in command or "apply" in command)
            if "apply" in command:
                self.assertIn("--dry-run=server", command)
                self.assertIn("--validate=strict", command)

    def test_stale_cluster_or_materialization_is_rejected(self) -> None:
        restricted = ROOT / "restricted"
        restricted.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="dependency-dry-run-", dir=restricted
        ) as raw:
            root = Path(raw)
            directory = self.materialization(root)
            client, kubeconfig = self.tooling(root)
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_dry_run_prerequisite_not_ready"
            ):
                collect_snapshot(
                    live_cluster(),
                    client,
                    kubeconfig,
                    directory,
                    AT + timedelta(hours=2),
                    DryRunFixture(),
                )

    def test_report_tamper_cannot_remove_remaining_gaps(self) -> None:
        restricted = ROOT / "restricted"
        restricted.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="dependency-dry-run-", dir=restricted
        ) as raw:
            root = Path(raw)
            snapshot = collect_snapshot(
                live_cluster(),
                *self.tooling(root),
                self.materialization(root),
                AT,
                DryRunFixture(),
            )
        report = build_assessment(snapshot, "sno-dependency-dry-run-tamper.1", AT)
        forged = copy.deepcopy(report)
        forged["decision"] = {
            "status": "SERVER_DRY_RUN_OBSERVED_WITH_GAPS",
            "reasonCodes": [],
        }
        forged["reportDigest"] = canonical_digest(
            {key: value for key, value in forged.items() if key != "reportDigest"}
        )
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_dry_run_report_semantics_invalid"
        ):
            validate_assessment(forged)

    def test_schema_is_closed(self) -> None:
        restricted = ROOT / "restricted"
        restricted.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="dependency-dry-run-", dir=restricted
        ) as raw:
            root = Path(raw)
            snapshot = collect_snapshot(
                live_cluster(),
                *self.tooling(root),
                self.materialization(root),
                AT,
                DryRunFixture(),
            )
        report = build_assessment(snapshot, "sno-dependency-dry-run-schema.1", AT)
        with tempfile.TemporaryDirectory() as raw:
            payload = Path(raw) / "report.json"
            payload.write_text(json.dumps(report), encoding="ascii")
            schema = (
                ROOT / "schemas" / "sno-trial-dependency-server-dry-run-v1.schema.json"
            )
            subprocess.run(
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
            )
            report["unexpected"] = True
            payload.write_text(json.dumps(report), encoding="ascii")
            rejected = subprocess.run(
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
            )
            self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
