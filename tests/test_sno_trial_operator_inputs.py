from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.sno_trial_operator_inputs import (
    CLAIMS,
    CONTROLS,
    LOCK_PATH,
    build_assessment,
    collect_snapshot,
    load_contract,
    manifest_input_inventory,
    report_resolves_manifests,
    simulated_snapshot,
    validate_assessment,
    validate_contract,
)
from scripts.validate_sno_trial_profile import ROOT, canonical_digest


def rendered_manifests(root: Path, contract: dict[str, object]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for plane in ("platform", "runtimeHost", "modelPlane"):
        lines = [
            "apiVersion: apps/v1",
            "kind: Deployment",
            "metadata:",
            f"  name: {plane.lower()}-fixture",
            "spec:",
            "  template:",
            "    spec:",
            "      containers:",
            "        - name: app",
            "          image: example.invalid/app@sha256:" + "1" * 64,
            "          env:",
        ]
        plane_inputs = [
            item
            for item in contract["inputs"]  # type: ignore[index]
            if item["plane"] == plane
        ]
        optional_index = 0
        for item in plane_inputs:
            for key in item["optionalKeys"]:
                optional_index += 1
                ref_kind = (
                    "secretKeyRef" if item["kind"] == "Secret" else "configMapKeyRef"
                )
                lines.extend(
                    [
                        f"            - name: OPTIONAL_{optional_index}",
                        "              valueFrom:",
                        f"                {ref_kind}:",
                        f"                  name: {item['name']}",
                        f"                  key: {key}",
                        "                  optional: true",
                    ]
                )
        lines.append("          envFrom:")
        whole_inputs = [item for item in plane_inputs if item["wholeObjectImport"]]
        if whole_inputs:
            for item in whole_inputs:
                ref_kind = "secretRef" if item["kind"] == "Secret" else "configMapRef"
                lines.extend(
                    [
                        f"            - {ref_kind}:",
                        f"                name: {item['name']}",
                    ]
                )
        else:
            lines.extend(
                [
                    "            - configMapRef:",
                    "                name: generated-config",
                ]
            )
        lines.append("      volumes:")
        for index, item in enumerate(plane_inputs):
            if item["wholeObjectImport"]:
                continue
            block = "secret" if item["kind"] == "Secret" else "configMap"
            name_key = "secretName" if item["kind"] == "Secret" else "name"
            lines.extend(
                [
                    f"        - name: input-{index}",
                    f"          {block}:",
                    f"            {name_key}: {item['name']}",
                    "            items:",
                ]
            )
            for key in item["requiredKeys"]:
                lines.extend(
                    [
                        f"              - key: {key}",
                        f"                path: {key}",
                    ]
                )
        lines.extend(
            [
                "---",
                "apiVersion: v1",
                "kind: ConfigMap",
                "metadata:",
                "  name: generated-config",
                "data:",
                "  mode: fixture",
            ]
        )
        path = root / f"{plane}.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result[plane] = path
    return result


class SnoTrialOperatorInputTests(unittest.TestCase):
    def test_locked_contract_is_value_free_and_fail_closed(self) -> None:
        contract = load_contract()
        validate_contract(contract)
        self.assertEqual(len(contract["inputs"]), 17)
        self.assertEqual(
            sum(item["kind"] == "Secret" for item in contract["inputs"]),
            14,
        )
        self.assertEqual(
            sum(item["kind"] == "ConfigMap" for item in contract["inputs"]),
            3,
        )
        self.assertFalse(contract["controls"]["secretValuesStored"])
        self.assertFalse(contract["controls"]["deploymentAuthorized"])
        self.assertEqual(contract["claims"], CLAIMS)
        encoded = LOCK_PATH.read_text(encoding="utf-8")
        self.assertNotIn("stringData", encoded)
        self.assertNotIn("dataValues", encoded)

    def test_contract_drift_is_rejected_even_with_a_new_self_digest(self) -> None:
        changed = copy.deepcopy(load_contract())
        changed["inputs"][0]["requiredKeys"].append("unexpected.pem")
        unsigned = copy.deepcopy(changed)
        unsigned.pop("contractDigest")
        changed["contractDigest"] = canonical_digest(unsigned)
        with self.assertRaisesRegex(
            ValueError, "sno_operator_inputs_contract_digest_invalid"
        ):
            validate_contract(changed)

    def test_manifest_inventory_captures_env_from_and_optional_key(self) -> None:
        content = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: example
spec:
  template:
    spec:
      containers:
        - name: app
          envFrom:
            - secretRef:
                name: imported-secret
          env:
            - name: OPTIONAL
              valueFrom:
                secretKeyRef:
                  name: direct-secret
                  key: optional-key
                  optional: true
      volumes:
        - name: direct
          secret:
            secretName: direct-secret
            items:
              - key: required-key
                path: required-key
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rendered.yaml"
            path.write_text(content, encoding="utf-8")
            inventory = manifest_input_inventory("platform", path)
        self.assertEqual(
            inventory,
            [
                {
                    "plane": "platform",
                    "namespace": "default",
                    "kind": "Secret",
                    "name": "direct-secret",
                    "requiredKeys": ["required-key"],
                    "optionalKeys": ["optional-key"],
                    "wholeObjectImport": False,
                },
                {
                    "plane": "platform",
                    "namespace": "default",
                    "kind": "Secret",
                    "name": "imported-secret",
                    "requiredKeys": [],
                    "optionalKeys": [],
                    "wholeObjectImport": True,
                },
            ],
        )

    def test_simulation_cannot_claim_live_resolution(self) -> None:
        report = build_assessment(
            simulated_snapshot(observed=True),
            "sno-operator-inputs-fixture-complete.1",
        )
        validate_assessment(report)
        self.assertEqual(report["decision"]["status"], "OPERATOR_INPUTS_UNRESOLVED")
        self.assertEqual(
            report["decision"]["reasonCodes"], ["LIVE_OBSERVATION_REQUIRED"]
        )
        self.assertFalse(report["aggregate"]["externalReferencesResolved"])
        self.assertEqual(report["controls"], CONTROLS)
        self.assertEqual(report["claims"], CLAIMS)

    def test_read_only_collection_can_observe_complete_metadata(self) -> None:
        contract = load_contract()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = root / "oc"
            client.write_text("#!/bin/sh\n", encoding="ascii")
            client.chmod(0o700)
            kubeconfig = root / "kubeconfig"
            kubeconfig.write_text("fixture\n", encoding="ascii")
            kubeconfig.chmod(0o600)
            manifests = rendered_manifests(root, contract)
            by_name = {item["name"]: item for item in contract["inputs"]}
            commands: list[list[str]] = []

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                name = command[command.index("get") + 2]
                item = by_name[name]
                observed_type = item["expectedType"] or "ConfigMap"
                keys = item["requiredKeys"] + item["optionalKeys"]
                output = "\n".join([observed_type, *keys]) + "\n"
                return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

            snapshot = collect_snapshot(
                client,
                kubeconfig,
                manifests,
                datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc),
                run,
            )
            report = build_assessment(snapshot, "sno-operator-inputs-fixture-live.1")
            self.assertTrue(report_resolves_manifests(report, manifests))
        self.assertEqual(len(commands), 17)
        self.assertTrue(all("get" in command for command in commands))
        self.assertTrue(all("apply" not in command for command in commands))
        self.assertTrue(all("go-template=" in command[-1] for command in commands))
        self.assertEqual(report["decision"]["status"], "OPERATOR_INPUTS_OBSERVED")
        self.assertTrue(report["aggregate"]["externalReferencesResolved"])
        encoded = json.dumps(report)
        self.assertNotIn("orchestra-platform-trial-secrets", encoded)
        self.assertNotIn("AUTH_SECRET", encoded)
        self.assertNotIn("fixture\n", encoded)

    def test_missing_input_and_type_mismatch_fail_closed(self) -> None:
        snapshot = simulated_snapshot(observed=True)
        snapshot["executionMode"] = "live-read-only"
        snapshot["observations"][0]["observed"] = False
        snapshot["observations"][0]["typeMatches"] = False
        snapshot["observations"][0]["observedRequiredKeyCount"] = 0
        snapshot["observations"][0]["missingRequiredKeyCount"] = 1
        snapshot["observations"][0]["missingRequiredKeySetDigest"] = (
            "sha256:" + "0" * 64
        )
        snapshot["allObjectsObserved"] = False
        snapshot["allRequiredKeysPresent"] = False
        snapshot["allTypesMatch"] = False
        report = build_assessment(snapshot, "sno-operator-inputs-fixture-missing.1")
        self.assertEqual(
            report["decision"]["reasonCodes"],
            [
                "INPUT_OBJECT_MISSING",
                "INPUT_KEY_MISSING",
                "INPUT_TYPE_MISMATCH",
            ],
        )

    def test_tamper_is_rejected(self) -> None:
        report = build_assessment(
            simulated_snapshot(observed=False),
            "sno-operator-inputs-fixture-tamper.1",
        )
        changed = copy.deepcopy(report)
        changed["controls"]["deploymentAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "sno_operator_inputs_controls_invalid"):
            validate_assessment(changed)

    def test_public_schema_is_strict_for_every_object(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "sno-trial-operator-inputs-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        objects = [schema]
        objects.extend(
            value
            for value in schema["$defs"].values()
            if isinstance(value, dict) and value.get("type") == "object"
        )
        for value in objects:
            self.assertIs(value["additionalProperties"], False)
            self.assertEqual(set(value["required"]), set(value["properties"]))

    def test_default_validation_and_ci_include_the_contract(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        command = "scripts/sno_trial_operator_inputs.py validate-lock"
        self.assertIn(command, makefile)
        self.assertIn(command, workflow)


if __name__ == "__main__":
    unittest.main()
