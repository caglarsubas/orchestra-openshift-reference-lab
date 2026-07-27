from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_cluster_observation import (
    CLAIMS,
    CONTROLS,
    build_assessment,
    collect_snapshot,
    validate_assessment,
    validate_snapshot,
)
from scripts.validate_sno_trial_profile import ROOT


FIXTURE = (
    ROOT / "tests" / "fixtures" / "sno-trial-cluster-healthy.json"
)


def snapshot(**updates: object) -> dict[str, object]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    value.update(updates)
    return value


class SnoTrialClusterObservationTests(unittest.TestCase):
    def test_healthy_trial_is_observed_without_certification_claim(self) -> None:
        report = build_assessment(
            snapshot(), "sno-cluster-fixture-healthy.1"
        )
        validate_assessment(report)
        self.assertEqual(
            report["decision"]["status"], "TRIAL_CLUSTER_OBSERVED"
        )
        self.assertEqual(report["decision"]["reasonCodes"], [])
        self.assertEqual(
            report["decision"]["nextAction"],
            "capture-cost-and-plan-teardown",
        )
        self.assertTrue(report["clusterState"]["trialShapeMatches"])
        self.assertEqual(report["clusterState"]["nodeCount"], 1)
        self.assertEqual(report["clusterState"]["workerMachineCount"], 0)
        self.assertGreaterEqual(report["clusterState"]["operatorCount"], 30)
        self.assertEqual(report["controls"], CONTROLS)
        self.assertEqual(report["claims"], CLAIMS)
        self.assertFalse(report["claims"]["campaignEvidence"])
        self.assertFalse(report["claims"]["referenceProfileVerified"])

    def test_cluster_drift_blocks_with_stable_reason_order(self) -> None:
        value = snapshot()
        value["clusterVersion"]["version"] = "4.20.26"  # type: ignore[index]
        value["credentials"]["mode"] = "Mint"  # type: ignore[index]
        value["nodes"][0]["ready"] = "False"  # type: ignore[index]
        value["operators"][0]["degraded"] = "True"  # type: ignore[index]
        value["compute"].append(  # type: ignore[union-attr]
            {
                "name": "orchestra-trial-fixture-bootstrap",
                "status": "RUNNING",
                "machineType": "n2-standard-8",
            }
        )
        value["compute"].sort(key=lambda item: item["name"])  # type: ignore[index]
        value["console"]["statusCode"] = "503"  # type: ignore[index]
        report = build_assessment(
            value, "sno-cluster-fixture-drift.1"
        )
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertEqual(
            report["decision"]["reasonCodes"],
            [
                "VERSION_MISMATCH",
                "CREDENTIAL_CONFIGURATION_MISMATCH",
                "NODE_SHAPE_MISMATCH",
                "OPERATOR_HEALTH_MISMATCH",
                "COMPUTE_INVENTORY_MISMATCH",
                "CONSOLE_UNAVAILABLE",
            ],
        )

    def test_wrong_api_source_and_storage_block(self) -> None:
        value = snapshot()
        value["apiFirewalls"][0]["sourceRanges"] = [  # type: ignore[index]
            "1.1.1.1/32"
        ]
        value["storageClasses"][1]["default"] = False  # type: ignore[index]
        report = build_assessment(
            value, "sno-cluster-fixture-boundary.1"
        )
        self.assertEqual(
            report["decision"]["reasonCodes"],
            [
                "ADMIN_SOURCE_MISMATCH",
                "STORAGE_CONFIGURATION_MISMATCH",
            ],
        )

    def test_live_collection_reduces_names_hosts_and_cidr_to_digests(
        self,
    ) -> None:
        fixture = snapshot()
        restricted = ROOT / "restricted"
        restricted.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="cluster-observation-test-", dir=restricted
        ) as directory:
            root = Path(directory)
            source = root / "source-cidr.txt"
            source.write_text("8.8.8.8/32\n", encoding="ascii")
            source.chmod(0o600)
            client = root / "oc"
            client.write_text("fixture\n", encoding="ascii")
            client.chmod(0o700)
            observed: list[list[str]] = []

            def k8s_list(items: list[dict[str, object]]) -> dict[str, object]:
                return {"items": items}

            conditions = lambda item: [  # noqa: E731
                {"type": name.capitalize(), "status": item[name]}
                for name in ("available", "progressing", "degraded")
            ]
            responses: dict[tuple[str, ...], object] = {
                ("get", "clusterversion", "version"): {
                    "status": {
                        "desired": {
                            "version": fixture["clusterVersion"]["version"]  # type: ignore[index]
                        },
                        "conditions": [
                            {
                                "type": "Available",
                                "status": fixture["clusterVersion"]["available"],  # type: ignore[index]
                            },
                            {
                                "type": "Progressing",
                                "status": fixture["clusterVersion"]["progressing"],  # type: ignore[index]
                            },
                            {
                                "type": "Failing",
                                "status": fixture["clusterVersion"]["failing"],  # type: ignore[index]
                            },
                        ],
                    }
                },
                ("get", "infrastructure", "cluster"): {
                    "status": {
                        "platform": fixture["infrastructure"]["platform"],  # type: ignore[index]
                        "controlPlaneTopology": fixture["infrastructure"]["topology"],  # type: ignore[index]
                        "infrastructureName": fixture["infrastructure"]["infrastructureName"],  # type: ignore[index]
                        "platformStatus": {
                            "gcp": {
                                "region": fixture["infrastructure"]["region"]  # type: ignore[index]
                            }
                        },
                    }
                },
                ("get", "cloudcredential", "cluster"): {
                    "spec": {
                        "credentialsMode": fixture["credentials"]["mode"]  # type: ignore[index]
                    }
                },
                ("get", "authentication", "cluster"): {
                    "spec": {
                        "serviceAccountIssuer": fixture["credentials"]["serviceAccountIssuer"]  # type: ignore[index]
                    }
                },
                ("get", "nodes"): k8s_list(
                    [
                        {
                            "metadata": {
                                "name": item["name"],
                                "labels": {
                                    f"node-role.kubernetes.io/{role}": ""
                                    for role in item["roles"]
                                },
                            },
                            "spec": {"unschedulable": not item["schedulable"]},
                            "status": {
                                "nodeInfo": {
                                    "architecture": item["architecture"]
                                },
                                "conditions": [
                                    {
                                        "type": "Ready",
                                        "status": item["ready"],
                                    }
                                ],
                            },
                        }
                        for item in fixture["nodes"]  # type: ignore[union-attr]
                    ]
                ),
                ("get", "clusteroperators"): k8s_list(
                    [
                        {
                            "metadata": {"name": item["name"]},
                            "status": {
                                "versions": [
                                    {
                                        "name": "operator",
                                        "version": item["version"],
                                    }
                                ],
                                "conditions": conditions(item),
                            },
                        }
                        for item in fixture["operators"]  # type: ignore[union-attr]
                    ]
                ),
                (
                    "get",
                    "machines",
                    "-n",
                    "openshift-machine-api",
                ): k8s_list(
                    [
                        {
                            "metadata": {
                                "name": item["name"],
                                "labels": {
                                    "machine.openshift.io/cluster-api-machine-role": item[
                                        "role"
                                    ]
                                },
                            },
                            "spec": {
                                "providerSpec": {
                                    "value": {
                                        "machineType": item["machineType"]
                                    }
                                }
                            },
                            "status": {"phase": item["phase"]},
                        }
                        for item in fixture["machines"]  # type: ignore[union-attr]
                    ]
                ),
                (
                    "get",
                    "route",
                    "console",
                    "-n",
                    "openshift-console",
                ): {"spec": {"host": fixture["console"]["host"]}},  # type: ignore[index]
                ("get", "storageclasses"): k8s_list(
                    [
                        {
                            "metadata": {
                                "name": item["name"],
                                "annotations": {
                                    "storageclass.kubernetes.io/is-default-class": (
                                        "true" if item["default"] else "false"
                                    )
                                },
                            },
                            "provisioner": item["provisioner"],
                            "volumeBindingMode": item["volumeBindingMode"],
                            "allowVolumeExpansion": item["allowExpansion"],
                        }
                        for item in fixture["storageClasses"]  # type: ignore[union-attr]
                    ]
                ),
            }

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                observed.append(command)
                if command[0] == str(client.resolve()):
                    key = tuple(command[1:-2])
                    value = responses[key]
                elif command[:3] == ["gcloud", "compute", "instances"]:
                    value = [
                        {
                            **item,
                            "machineType": (
                                "https://compute.googleapis.com/compute/v1/"
                                f"projects/fixture/zones/europe-west1-b/"
                                f"machineTypes/{item['machineType']}"
                            ),
                        }
                        for item in fixture["compute"]  # type: ignore[union-attr]
                    ]
                elif command[:3] == [
                    "gcloud",
                    "compute",
                    "firewall-rules",
                ]:
                    value = fixture["apiFirewalls"]
                else:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=fixture["console"]["statusCode"],  # type: ignore[index]
                        stderr="",
                    )
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(value), stderr=""
                )

            collected = collect_snapshot(
                "prometa-orch-sno-fixture",
                source,
                client,
                datetime(2026, 7, 27, 16, 5, tzinfo=timezone.utc),
                run,
            )
            report = build_assessment(
                collected, "sno-cluster-fixture-live.1"
            )
        encoded = json.dumps(report)
        self.assertEqual(len(observed), 12)
        self.assertNotIn("8.8.8.8", encoded)
        self.assertNotIn("orchestra-trial-fixture-master-0", encoded)
        self.assertNotIn(
            "console-openshift-console.apps.orchestra-trial", encoded
        )
        self.assertEqual(
            report["decision"]["status"], "TRIAL_CLUSTER_OBSERVED"
        )

    def test_snapshot_and_report_tamper_fail_closed(self) -> None:
        changed = snapshot(extra="not-allowed")
        with self.assertRaisesRegex(
            ValueError, "sno_cluster_snapshot_keys_invalid"
        ):
            validate_snapshot(changed)
        report = build_assessment(
            snapshot(), "sno-cluster-fixture-tamper.1"
        )
        changed_report = copy.deepcopy(report)
        changed_report["controls"]["workloadMutationAuthorized"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_cluster_controls_invalid"
        ):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["clusterState"]["consoleReachable"] = False
        with self.assertRaisesRegex(ValueError, "sno_cluster_state_invalid"):
            validate_assessment(changed_report)
        changed_report = copy.deepcopy(report)
        changed_report["reportDigest"] = f"sha256:{'f' * 64}"
        with self.assertRaisesRegex(
            ValueError, "sno_cluster_report_digest_invalid"
        ):
            validate_assessment(changed_report)

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "schemas"
                / "sno-trial-cluster-observation-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        for name in (
            "bindings",
            "clusterState",
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
            "scripts/sno_trial_cluster_observation.py assess", workflow
        )
        self.assertIn(
            "scripts/sno_trial_cluster_observation.py verify", workflow
        )
        self.assertIn("observe-sno-trial-cluster:", makefile)
        self.assertIn("verify-sno-trial-cluster:", makefile)

    def test_cli_is_create_only_and_fixture_cannot_impersonate_live(
        self,
    ) -> None:
        from scripts.sno_trial_cluster_observation import main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            self.assertEqual(
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-cluster-fixture-cli.1",
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
                ValueError, "sno_cluster_output_exists"
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(FIXTURE),
                        "--assessment-id",
                        "sno-cluster-fixture-cli.2",
                        "--output",
                        str(output),
                    ]
                )
            live = snapshot(executionMode="live-diagnostic")
            live_path = Path(directory) / "live.json"
            live_path.write_text(json.dumps(live), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "sno_cluster_live_snapshot_requires_collect"
            ):
                main(
                    [
                        "assess",
                        "--snapshot",
                        str(live_path),
                        "--assessment-id",
                        "sno-cluster-fixture-live-cli.1",
                        "--output",
                        str(Path(directory) / "live-report.json"),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
