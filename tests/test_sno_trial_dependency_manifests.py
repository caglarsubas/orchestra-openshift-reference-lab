from __future__ import annotations

import copy
import json
import subprocess
import unittest

from scripts.validate_repository import ROOT, load_json
from scripts.validate_sno_trial_dependency_manifests import (
    ACTIVE_DEPENDENCY_KUSTOMIZATION,
    ARTIFACT_PATH,
    CANDIDATE_PATH,
    EXPECTED_CANDIDATE_DIGEST,
    EXPECTED_MANIFEST_SET_DIGEST,
    KUSTOMIZATION_PATH,
    MANIFEST_ROOT,
    RESOURCE_FILES,
    RUNTIME_PATH,
    WORKLOAD_PATH,
    digest_without_self,
    kustomization_resources,
    load_resources,
    manifest_set_digest,
    validate_candidate,
)


class SnoTrialDependencyManifestCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = load_json(CANDIDATE_PATH)
        self.resources = load_resources()
        self.workload = load_json(WORKLOAD_PATH)
        self.runtime = load_json(RUNTIME_PATH)
        self.artifact = load_json(ARTIFACT_PATH)
        self.active = ACTIVE_DEPENDENCY_KUSTOMIZATION.read_text(encoding="utf-8")
        self.kustomization_files = kustomization_resources(KUSTOMIZATION_PATH)

    def validate(
        self,
        *,
        candidate: dict | None = None,
        resources: list[dict] | None = None,
        active: str | None = None,
    ) -> tuple[str, str]:
        return validate_candidate(
            candidate or copy.deepcopy(self.candidate),
            resources or copy.deepcopy(self.resources),
            copy.deepcopy(self.workload),
            copy.deepcopy(self.runtime),
            copy.deepcopy(self.artifact),
            active_kustomization_text=self.active if active is None else active,
            kustomization_file_list=list(self.kustomization_files),
        )

    def test_candidate_is_valid_and_digest_bound(self) -> None:
        manifest_digest, candidate_digest = self.validate()
        self.assertEqual(manifest_digest, EXPECTED_MANIFEST_SET_DIGEST)
        self.assertEqual(candidate_digest, EXPECTED_CANDIDATE_DIGEST)
        self.assertEqual(
            self.candidate["candidateDigest"], digest_without_self(self.candidate)
        )
        self.assertEqual(manifest_digest, manifest_set_digest(self.resources))
        self.assertEqual(self.kustomization_files, RESOURCE_FILES)

    def test_default_validation_and_ci_include_the_contract_and_render(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        script = "scripts/validate_sno_trial_dependency_manifests.py"
        render = "kubectl kustomize gitops/dependencies/candidates/sno-trial"
        self.assertIn(script, makefile)
        self.assertIn(script, workflow)
        self.assertIn(render, makefile)
        self.assertIn(render, workflow)
        self.assertIn("validate-sno-trial-dependency-manifests:", makefile)

    def test_candidate_digest_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.candidate)
        changed["controls"]["deploymentAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "dependency_manifest_controls_invalid"):
            self.validate(candidate=changed)

    def test_manifest_digest_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[3]["spec"]["ports"][0]["port"] = 6380
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_valkey_service_invalid"
        ):
            self.validate(resources=changed)

    def test_secret_object_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[0]["kind"] = "Secret"
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_resource_kind_forbidden"
        ):
            self.validate(resources=changed)

    def test_mutable_image_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[4]["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "docker.io/valkey/valkey:9.1.0"
        )
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_valkey_workload_invalid"
        ):
            self.validate(resources=changed)

    def test_fixed_uid_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[9]["spec"]["template"]["spec"]["securityContext"]["runAsUser"] = 1000
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_fixed_identity_forbidden"
        ):
            self.validate(resources=changed)

    def test_service_account_token_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[4]["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_pod_security_invalid"
        ):
            self.validate(resources=changed)

    def test_runtime_model_download_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[9]["spec"]["template"]["spec"]["containers"][0]["args"].extend(
            ["--model-url", "https://example.invalid/model.gguf"]
        )
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_model_workload_invalid"
        ):
            self.validate(resources=changed)

    def test_writable_model_mount_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[9]["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0][
            "readOnly"
        ] = False
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_model_pvc_invalid"
        ):
            self.validate(resources=changed)

    def test_broad_network_client_is_rejected(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[6]["spec"]["ingress"][0]["from"][0]["namespaceSelector"] = {}
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_ingress_scope_invalid"
        ):
            self.validate(resources=changed)

    def test_active_kustomization_reference_is_rejected(self) -> None:
        changed = f"{self.active}\n  - ../candidates/sno-trial\n"
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_active_kustomization_reference_forbidden"
        ):
            self.validate(active=changed)

    def test_storage_class_materialization_is_not_silently_accepted(self) -> None:
        changed = copy.deepcopy(self.resources)
        changed[4]["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"] = (
            "standard-csi"
        )
        with self.assertRaisesRegex(
            ValueError, "dependency_manifest_valkey_storage_invalid"
        ):
            self.validate(resources=changed)

    def test_schema_is_closed_and_accepts_the_lock(self) -> None:
        schema = (
            ROOT / "schemas" / "sno-trial-dependency-manifest-candidate-v1.schema.json"
        )
        subprocess.run(
            [
                "npx",
                "--yes",
                "ajv-cli@5.0.0",
                "validate",
                "--spec=draft2020",
                f"-s={schema}",
                f"-d={CANDIDATE_PATH}",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        changed = copy.deepcopy(self.candidate)
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

    def test_manifest_root_contains_only_declared_json_resources(self) -> None:
        actual = sorted(path.name for path in MANIFEST_ROOT.glob("*.json"))
        self.assertEqual(actual, sorted(RESOURCE_FILES))


if __name__ == "__main__":
    unittest.main()
