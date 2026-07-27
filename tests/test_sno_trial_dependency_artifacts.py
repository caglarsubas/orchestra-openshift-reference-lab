from __future__ import annotations

import copy
import json
import subprocess
import unittest

from scripts.validate_repository import ROOT, canonical_digest, load_json
from scripts.validate_sno_trial_dependency_artifacts import (
    ADMISSION_PATH,
    ARTIFACT_SET_PATH,
    BOM_PATH,
    EXPECTED_ARTIFACT_SET_DIGEST,
    RUNTIME_CONTRACT_PATH,
    validate_artifact_set,
)


class SnoTrialDependencyArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = load_json(ARTIFACT_SET_PATH)
        self.bom = load_json(BOM_PATH)
        self.admission = load_json(ADMISSION_PATH)
        self.runtime = load_json(RUNTIME_CONTRACT_PATH)

    def validate(self, value: dict) -> str:
        return validate_artifact_set(
            value,
            self.bom,
            self.admission,
            self.runtime,
        )

    def container(self, value: dict, identifier: str) -> dict:
        return next(item for item in value["containers"] if item["id"] == identifier)

    def resign(self, value: dict) -> None:
        unsigned = copy.deepcopy(value)
        unsigned.pop("artifactSetDigest", None)
        value["artifactSetDigest"] = canonical_digest(unsigned)

    def test_artifact_set_is_valid_and_stable(self) -> None:
        self.assertEqual(self.validate(self.value), EXPECTED_ARTIFACT_SET_DIGEST)

    def test_default_validation_and_ci_include_the_contract(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        script = "scripts/validate_sno_trial_dependency_artifacts.py"
        self.assertIn(script, makefile)
        self.assertIn(script, workflow)
        self.assertIn("validate-sno-trial-dependency-artifacts:", makefile)

    def test_valkey_image_matches_locked_chart_version(self) -> None:
        valkey = self.container(self.value, "valkey-image")
        chart = next(
            item for item in self.bom["chartPackages"] if item["id"] == "valkey"
        )
        self.assertEqual(valkey["version"], chart["appVersion"])
        self.assertTrue(valkey["resolvedReference"].endswith(valkey["platformDigest"]))

    def test_model_bytes_are_small_immutable_and_prestaged(self) -> None:
        model = self.value["models"][0]
        self.assertLess(model["sizeBytes"], model["maximumAllowedBytes"])
        self.assertIn(model["revision"], model["immutableUrl"])
        self.assertFalse(model["runtimeDownloadAllowed"])
        self.assertEqual(model["materialization"], "operator-prestaged-read-only-pvc")

    def test_binding_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.value)
        changed["bindings"]["runtimeContractSetDigest"] = "sha256:" + ("f" * 64)
        self.resign(changed)
        with self.assertRaisesRegex(ValueError, "dependency_artifact_bindings_invalid"):
            self.validate(changed)

    def test_mutable_resolved_reference_is_rejected(self) -> None:
        changed = copy.deepcopy(self.value)
        changed["containers"][0]["resolvedReference"] = "docker.io/valkey/valkey:latest"
        self.resign(changed)
        with self.assertRaisesRegex(
            ValueError, "dependency_artifact_container_invalid:valkey-image"
        ):
            self.validate(changed)

    def test_model_digest_or_size_drift_is_rejected(self) -> None:
        for key, value in (
            ("digest", "sha256:" + ("f" * 64)),
            ("sizeBytes", 4294967297),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.value)
                changed["models"][0][key] = value
                self.resign(changed)
                with self.assertRaisesRegex(
                    ValueError, "dependency_artifact_model_invalid"
                ):
                    self.validate(changed)

    def test_activation_and_claim_overstatement_are_rejected(self) -> None:
        changed = copy.deepcopy(self.value)
        changed["activation"]["state"] = "ready"
        self.resign(changed)
        with self.assertRaisesRegex(
            ValueError, "dependency_artifact_activation_invalid"
        ):
            self.validate(changed)

        changed = copy.deepcopy(self.value)
        changed["claims"]["campaignEvidence"] = True
        self.resign(changed)
        with self.assertRaisesRegex(ValueError, "dependency_artifact_claims_invalid"):
            self.validate(changed)

    def test_inline_manifest_or_secret_material_is_rejected(self) -> None:
        for key in ("manifest", "secretValue"):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.value)
                changed["containers"][0][key] = "forbidden"
                self.resign(changed)
                with self.assertRaisesRegex(
                    ValueError, "dependency_artifact_forbidden_key"
                ):
                    self.validate(changed)

    def test_schema_is_closed_and_accepts_the_lock(self) -> None:
        schema = ROOT / "schemas" / "sno-trial-dependency-artifact-set-v1.schema.json"
        subprocess.run(
            [
                "npx",
                "--yes",
                "ajv-cli@5.0.0",
                "validate",
                "--spec=draft2020",
                f"-s={schema}",
                f"-d={ARTIFACT_SET_PATH}",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        changed = copy.deepcopy(self.value)
        changed["unexpected"] = True
        completed = subprocess.run(
            [
                "npx",
                "--yes",
                "ajv-cli@5.0.0",
                "validate",
                "--spec=draft2020",
                f"-s={schema}",
                "-d=/dev/stdin",
            ],
            cwd=ROOT,
            input=json.dumps(changed),
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
