from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.materialize_sno_trial_dependency_manifests import (
    main as materialize_main,
    validate_materialized_directory,
)
from scripts.sno_trial_dependency_inputs import (
    build_assessment,
    collect_snapshot,
    simulated_snapshot,
)
from scripts.validate_repository import ROOT
from scripts.validate_sno_trial_dependency_manifests import (
    RESOURCE_FILES,
    STORAGE_CLASS_PLACEHOLDER,
    load_resources,
)


AT = datetime(2026, 7, 28, 9, 0, tzinfo=timezone.utc)


class OcMetadataFixture:
    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        get_index = command.index("get")
        identity = (command[get_index + 1], command[get_index + 2])
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
            command, 0, stdout=outputs[identity], stderr=""
        )


class SnoTrialDependencyMaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.restricted = ROOT / "restricted"
        self.restricted.mkdir(exist_ok=True)

    def live_report(self, root: Path) -> dict:
        client = root / "oc"
        kubeconfig = root / "kubeconfig"
        client.write_text("#!/bin/sh\n", encoding="ascii")
        kubeconfig.write_text("fixture\n", encoding="ascii")
        client.chmod(0o700)
        kubeconfig.chmod(0o600)
        snapshot = collect_snapshot(
            client,
            kubeconfig,
            "standard-csi",
            AT,
            OcMetadataFixture(),
        )
        return build_assessment(
            snapshot,
            "sno-dependency-inputs-materialize.1",
            AT,
        )

    def prepare(self, root: Path, report: dict) -> tuple[Path, Path, Path]:
        report_path = root / "input-report.json"
        storage_path = root / "storage-class.txt"
        output = root / "materialized"
        report_path.write_text(json.dumps(report), encoding="ascii")
        storage_path.write_text("standard-csi\n", encoding="ascii")
        report_path.chmod(0o600)
        storage_path.chmod(0o600)
        return report_path, storage_path, output

    def arguments(
        self,
        report: Path,
        storage: Path,
        output: Path,
        at: datetime = AT,
    ) -> list[str]:
        return [
            "materialize",
            "--input-report",
            str(report),
            "--storage-class-file",
            str(storage),
            "--output-dir",
            str(output),
            "--materialization-id",
            "sno-dependency-materialization-test.1",
            "--at",
            at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        ]

    def test_materializes_exactly_one_storage_reference_and_stays_blocked(
        self,
    ) -> None:
        source_before = copy.deepcopy(load_resources())
        with tempfile.TemporaryDirectory(
            prefix="dependency-materialization-", dir=self.restricted
        ) as directory:
            root = Path(directory)
            report_path, storage_path, output = self.prepare(
                root, self.live_report(root)
            )
            self.assertEqual(
                materialize_main(self.arguments(report_path, storage_path, output)),
                0,
            )
            receipt = validate_materialized_directory(output)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            for path in output.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            valkey = json.loads(
                (output / "valkey-stateful-set.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                valkey["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"],
                "standard-csi",
            )
            rendered = "\n".join(
                (output / name).read_text(encoding="utf-8") for name in RESOURCE_FILES
            )
            self.assertNotIn(STORAGE_CLASS_PLACEHOLDER, rendered)
            self.assertNotIn('"kind": "Secret"', rendered)
            self.assertNotIn("fixture-secret-value", rendered)
            self.assertNotIn("standard-csi", json.dumps(receipt, sort_keys=True))
            self.assertTrue(receipt["controls"]["manifestsMaterialized"])
            self.assertFalse(receipt["controls"]["deploymentAuthorized"])
            self.assertFalse(receipt["claims"]["campaignEvidence"])
            self.assertEqual(load_resources(), source_before)

            with self.assertRaisesRegex(
                ValueError, "sno_dependency_materialization_output_invalid"
            ):
                materialize_main(self.arguments(report_path, storage_path, output))

    def test_rejects_simulated_stale_mismatched_and_untrusted_inputs(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-materialization-reject-", dir=self.restricted
        ) as directory:
            root = Path(directory)
            live = self.live_report(root)
            report_path, storage_path, output = self.prepare(root, live)

            with self.assertRaisesRegex(
                ValueError, "sno_dependency_materialization_input_report_stale"
            ):
                materialize_main(
                    self.arguments(
                        report_path,
                        storage_path,
                        output,
                        AT + timedelta(hours=2),
                    )
                )
            self.assertFalse(output.exists())

            storage_path.write_text("premium-rwo\n", encoding="ascii")
            storage_path.chmod(0o600)
            with self.assertRaisesRegex(
                ValueError,
                "sno_dependency_materialization_input_report_not_ready",
            ):
                materialize_main(self.arguments(report_path, storage_path, output))
            storage_path.write_text("standard-csi\n", encoding="ascii")
            storage_path.chmod(0o600)

            simulated = build_assessment(
                simulated_snapshot(AT),
                "sno-dependency-inputs-simulated-materialize.1",
                AT,
            )
            report_path.write_text(json.dumps(simulated), encoding="ascii")
            report_path.chmod(0o600)
            with self.assertRaisesRegex(
                ValueError,
                "sno_dependency_materialization_input_report_not_ready",
            ):
                materialize_main(self.arguments(report_path, storage_path, output))

            link = root / "storage-link.txt"
            link.symlink_to(storage_path)
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_materialization_storage_file_invalid"
            ):
                materialize_main(self.arguments(report_path, link, output))

            report_path.write_text(json.dumps(live), encoding="ascii")
            report_path.chmod(0o600)
            outside = Path(tempfile.gettempdir()) / "orchestra-materialized-outside"
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_materialization_output_invalid"
            ):
                materialize_main(self.arguments(report_path, storage_path, outside))

    def test_verifier_rejects_resource_tamper(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-materialization-tamper-", dir=self.restricted
        ) as directory:
            root = Path(directory)
            report_path, storage_path, output = self.prepare(
                root, self.live_report(root)
            )
            materialize_main(self.arguments(report_path, storage_path, output))
            valkey_path = output / "valkey-stateful-set.json"
            valkey = json.loads(valkey_path.read_text(encoding="utf-8"))
            valkey["spec"]["replicas"] = 2
            valkey_path.write_text(json.dumps(valkey), encoding="ascii")
            valkey_path.chmod(0o600)
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_materialization_resource_lineage_invalid"
            ):
                validate_materialized_directory(output)

    def test_verifier_rejects_public_output_directory(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-materialization-mode-", dir=self.restricted
        ) as directory:
            root = Path(directory)
            report_path, storage_path, output = self.prepare(
                root, self.live_report(root)
            )
            materialize_main(self.arguments(report_path, storage_path, output))
            output.chmod(0o755)
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_materialization_directory_invalid"
            ):
                validate_materialized_directory(output)

    def test_receipt_schema_is_closed_and_accepts_materialization(self) -> None:
        schema = (
            ROOT
            / "schemas"
            / "sno-trial-dependency-manifest-materialization-v1.schema.json"
        )
        with tempfile.TemporaryDirectory(
            prefix="dependency-materialization-schema-", dir=self.restricted
        ) as directory:
            root = Path(directory)
            report_path, storage_path, output = self.prepare(
                root, self.live_report(root)
            )
            materialize_main(self.arguments(report_path, storage_path, output))
            receipt_path = output / "materialization-receipt.json"
            completed = subprocess.run(
                [
                    "npx",
                    "--yes",
                    "ajv-cli@5.0.0",
                    "validate",
                    "--spec=draft2020",
                    f"-s={schema}",
                    f"-d={receipt_path}",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["unexpected"] = True
            changed = root / "changed-receipt.json"
            changed.write_text(json.dumps(receipt), encoding="ascii")
            completed = subprocess.run(
                [
                    "npx",
                    "--yes",
                    "ajv-cli@5.0.0",
                    "validate",
                    "--spec=draft2020",
                    f"-s={schema}",
                    f"-d={changed}",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
