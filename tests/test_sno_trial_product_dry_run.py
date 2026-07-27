from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_cluster_observation import (
    build_assessment as build_cluster_assessment,
)
from scripts.sno_trial_product_dry_run import (
    CLAIMS,
    CONTROLS,
    build_assessment,
    collect_snapshot,
    cpu_millicores,
    memory_bytes,
    validate_assessment,
    validate_snapshot,
)
from scripts.validate_sno_trial_profile import ROOT


SNAPSHOT_FIXTURE = (
    ROOT / "tests" / "fixtures" / "sno-trial-product-dry-run-observed.json"
)
CLUSTER_FIXTURE = (
    ROOT / "tests" / "fixtures" / "sno-trial-cluster-healthy.json"
)


def fixture(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def cluster() -> dict[str, object]:
    return build_cluster_assessment(
        fixture(CLUSTER_FIXTURE), "sno-cluster-fixture-dry-run.1"
    )


class SnoTrialProductDryRunTests(unittest.TestCase):
    def test_observed_dry_run_preserves_all_gaps_and_claim_boundaries(
        self,
    ) -> None:
        report = build_assessment(
            fixture(SNAPSHOT_FIXTURE),
            cluster(),
            "sno-product-dry-run-fixture-observed.1",
        )
        validate_assessment(report)
        self.assertEqual(
            report["decision"]["status"],
            "SERVER_DRY_RUN_OBSERVED_WITH_GAPS",
        )
        self.assertEqual(report["aggregate"]["objectCount"], 18)
        self.assertEqual(report["aggregate"]["acceptedObjectCount"], 18)
        self.assertEqual(
            report["decision"]["reasonCodes"],
            [
                "CAPACITY_MARGIN_TIGHT",
                "MIGRATION_IMAGE_NOT_ARTIFACT_BOUND",
                "EXTERNAL_REFERENCES_UNRESOLVED",
                "LIVE_PULL_NOT_VERIFIED",
                "DESTINATION_MIRROR_NOT_VERIFIED",
            ],
        )
        self.assertEqual(report["controls"], CONTROLS)
        self.assertEqual(report["claims"], CLAIMS)
        self.assertFalse(report["controls"]["deploymentAuthorized"])
        self.assertFalse(
            report["controls"]["artifactAdmissionStateAdvanced"]
        )
        self.assertFalse(report["claims"]["campaignEvidence"])

    def test_failed_dry_run_and_negative_capacity_block(self) -> None:
        snapshot = fixture(SNAPSHOT_FIXTURE)
        snapshot["manifests"][0]["serverDryRunAccepted"] = False  # type: ignore[index]
        snapshot["manifests"][0]["acceptedObjectCount"] = 5  # type: ignore[index]
        capacity = snapshot["capacity"]  # type: ignore[assignment]
        capacity["existingRequestedCpuMillicores"] = 4000  # type: ignore[index]
        capacity["projectedHeadroomCpuMillicores"] = -150  # type: ignore[index]
        capacity["positiveProjectedHeadroom"] = False  # type: ignore[index]
        capacity["capacityMarginTight"] = False  # type: ignore[index]
        report = build_assessment(
            snapshot,
            cluster(),
            "sno-product-dry-run-fixture-blocked.1",
        )
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertEqual(
            report["decision"]["reasonCodes"][:2],
            ["SERVER_DRY_RUN_FAILED", "CAPACITY_HEADROOM_NEGATIVE"],
        )

    def test_tamper_fails_closed(self) -> None:
        snapshot = fixture(SNAPSHOT_FIXTURE)
        changed = copy.deepcopy(snapshot)
        changed["capacity"]["projectedHeadroomCpuMillicores"] = 999  # type: ignore[index]
        with self.assertRaisesRegex(
            ValueError, "sno_product_dry_run_capacity_invalid"
        ):
            validate_snapshot(changed)
        report = build_assessment(
            snapshot,
            cluster(),
            "sno-product-dry-run-fixture-tamper.1",
        )
        changed_report = copy.deepcopy(report)
        changed_report["controls"]["deploymentAuthorized"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_product_dry_run_controls_invalid"
        ):
            validate_assessment(changed_report)

    def test_quantity_parsing_is_conservative(self) -> None:
        self.assertEqual(cpu_millicores("7500m"), 7500)
        self.assertEqual(cpu_millicores("8"), 8000)
        self.assertEqual(cpu_millicores("1u"), 1)
        self.assertEqual(memory_bytes("31708140Ki"), 32469135360)
        self.assertEqual(memory_bytes("1.5Gi"), 1610612736)

    def test_public_schema_is_strict_for_every_object(self) -> None:
        schema = fixture(
            ROOT / "schemas" / "sno-trial-product-dry-run-v1.schema.json"
        )
        objects = [schema]
        objects.extend(
            value
            for value in schema["$defs"].values()  # type: ignore[union-attr]
            if isinstance(value, dict) and value.get("type") == "object"
        )
        for value in objects:
            self.assertIs(value["additionalProperties"], False)
            self.assertEqual(
                set(value["required"]), set(value["properties"])
            )

    def test_live_collection_reduces_raw_names_and_executes_no_mutation(
        self,
    ) -> None:
        manifest_texts = {
            "platform": """---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: platform-sensitive-name
spec:
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/caglarsubas/agent-hook-v2/prometa-ubi@sha256:f2444f162328d0716338d0c3d151310a908e2f022c1f32d2d01e08f320e9e56d
        - name: migration
          image: ghcr.io/example/migration@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      volumes:
        - name: tls
          secret:
            secretName: platform-sensitive-secret
""",
            "runtimeHost": """---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: runtime-sensitive-name
spec:
  template:
    spec:
      containers:
        - name: runtime
          image: ghcr.io/prometa-ai/orchestra-python-sdk/prometa-runtime-host-ubi9@sha256:0ad1cc268da818d1b0c6ed850d50fdd937df79f1ab5e29cb6f7c3740b380029b
""",
            "modelPlane": """---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: model-sensitive-name
spec:
  template:
    spec:
      containers:
        - name: model
          image: ghcr.io/caglarsubas/llm_inference_engine/inference-engine-ubi@sha256:6eb6052cfc38fa6304021a2887536b5d7c77dc9f0ca4331491324021a0732549
""",
        }
        node = {
            "metadata": {"name": "node-sensitive-name"},
            "spec": {},
            "status": {
                "nodeInfo": {"architecture": "amd64"},
                "conditions": [{"type": "Ready", "status": "True"}],
                "allocatable": {"cpu": "7500m", "memory": "31708140Ki"},
            },
        }
        pod = {
            "metadata": {
                "namespace": "openshift-sensitive",
                "name": "pod-sensitive-name",
            },
            "spec": {
                "nodeName": "node-sensitive-name",
                "containers": [
                    {
                        "resources": {
                            "requests": {"cpu": "3222m", "memory": "13774Mi"}
                        }
                    }
                ],
            },
            "status": {"phase": "Running"},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = root / "oc"
            client.write_text("#!/bin/sh\n", encoding="ascii")
            client.chmod(0o700)
            kubeconfig = root / "kubeconfig"
            kubeconfig.write_text("sensitive\n", encoding="ascii")
            kubeconfig.chmod(0o600)
            manifests: dict[str, Path] = {}
            for plane, content in manifest_texts.items():
                path = root / f"{plane}.yaml"
                path.write_text(content, encoding="utf-8")
                manifests[plane] = path
            observed: list[list[str]] = []

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                observed.append(command)
                if command[-4:] == ["get", "nodes", "-o", "json"]:
                    output = json.dumps({"items": [node]})
                elif command[-5:] == ["get", "pods", "-A", "-o", "json"]:
                    output = json.dumps({"items": [pod]})
                elif "apply" in command:
                    manifest = Path(command[-1])
                    count = manifest.read_text().count("kind:")
                    output = "".join(
                        f"resource/{index} configured (server dry run)\n"
                        for index in range(count)
                    )
                else:
                    output = ""
                return subprocess.CompletedProcess(
                    command, 0, stdout=output, stderr=""
                )

            snapshot = collect_snapshot(
                cluster(),
                client,
                kubeconfig,
                manifests,
                datetime(2026, 7, 27, 16, 45, tzinfo=timezone.utc),
                run,
            )
        report = build_assessment(
            snapshot,
            cluster(),
            "sno-product-dry-run-fixture-live.1",
        )
        encoded = json.dumps(report)
        self.assertEqual(sum("apply" in item for item in observed), 3)
        self.assertEqual(sum("get" in item for item in observed), 5)
        self.assertNotIn("platform-sensitive-name", encoded)
        self.assertNotIn("platform-sensitive-secret", encoded)
        self.assertNotIn("node-sensitive-name", encoded)
        self.assertNotIn("pod-sensitive-name", encoded)
        self.assertNotIn("sensitive", encoded)
        self.assertTrue(report["aggregate"]["allNonPersistent"])


if __name__ == "__main__":
    unittest.main()
