from __future__ import annotations

import copy
import json
import unittest
from typing import Any

from scripts.validate_production_model_artifact_candidate import (
    ADMISSION_PATH,
    BOM_PATH,
    CANDIDATE_PATH,
    RELEASE_SET_PATH,
    SCHEMA_PATH,
    TOPOLOGY_PATH,
    digest_without_self,
    validate_candidate,
)
from scripts.validate_repository import ROOT, load_json


class ProductionModelArtifactCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = load_json(CANDIDATE_PATH)
        self.bom = load_json(BOM_PATH)
        self.admission = load_json(ADMISSION_PATH)
        self.release_set = load_json(RELEASE_SET_PATH)
        self.topology = load_json(TOPOLOGY_PATH)
        self.schema = load_json(SCHEMA_PATH)

    def validate(
        self,
        candidate: dict[str, Any] | None = None,
        *,
        schema: dict[str, Any] | None = None,
    ) -> str:
        return validate_candidate(
            candidate or self.candidate,
            self.bom,
            self.admission,
            self.release_set,
            self.topology,
            schema or self.schema,
        )

    @staticmethod
    def resign(candidate: dict[str, Any]) -> None:
        candidate["candidateDigest"] = digest_without_self(candidate)

    def test_locked_candidate_is_valid_and_non_authorizing(self) -> None:
        digest = self.validate()
        self.assertEqual(digest, self.candidate["candidateDigest"])
        self.assertEqual(
            [binding["replicas"] for binding in self.candidate["runtimeBindings"]],
            [2, 1],
        )
        self.assertTrue(self.candidate["controls"]["sourceOnly"])
        self.assertFalse(self.candidate["controls"]["deploymentAuthorized"])
        self.assertFalse(self.candidate["controls"]["campaignEligible"])
        self.assertTrue(
            all(value is False for value in self.candidate["claims"].values())
        )

    def test_container_digest_or_hardening_drift_is_rejected(self) -> None:
        for mutation in ("platformDigest", "readOnlyRootFilesystemRequired"):
            candidate = copy.deepcopy(self.candidate)
            if mutation == "platformDigest":
                candidate["container"][mutation] = f"sha256:{'a' * 64}"
            else:
                candidate["container"]["runtimeCompatibility"][mutation] = False
            self.resign(candidate)
            with self.assertRaisesRegex(ValueError, "container_invalid"):
                self.validate(candidate)

    def test_chat_and_embedding_artifacts_are_exact(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["models"][1]["sizeBytes"] += 1
        self.resign(candidate)
        with self.assertRaisesRegex(ValueError, "artifacts_invalid"):
            self.validate(candidate)

        candidate = copy.deepcopy(self.candidate)
        candidate["models"].reverse()
        self.resign(candidate)
        with self.assertRaisesRegex(ValueError, "artifacts_invalid"):
            self.validate(candidate)

    def test_model_url_revision_and_mount_are_immutable(self) -> None:
        for field, value in (
            ("revision", "f" * 40),
            (
                "immutableUrl",
                "https://huggingface.co/example/model/resolve/main/a.gguf",
            ),
            ("mountPath", "/tmp/model.gguf"),
        ):
            candidate = copy.deepcopy(self.candidate)
            candidate["models"][0][field] = value
            self.resign(candidate)
            with self.assertRaisesRegex(ValueError, "artifacts_invalid"):
                self.validate(candidate)

    def test_runtime_download_and_quality_claims_cannot_advance(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["models"][0]["runtimeDownloadAllowed"] = True
        self.resign(candidate)
        with self.assertRaisesRegex(ValueError, "artifacts_invalid"):
            self.validate(candidate)

        candidate = copy.deepcopy(self.candidate)
        candidate["claims"]["embeddingQualityVerified"] = True
        self.resign(candidate)
        with self.assertRaisesRegex(ValueError, "claims_invalid"):
            self.validate(candidate)

    def test_replica_and_endpoint_contracts_are_exact(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["runtimeBindings"][0]["replicas"] = 1
        self.resign(candidate)
        with self.assertRaisesRegex(ValueError, "runtime_bindings_invalid"):
            self.validate(candidate)

        candidate = copy.deepcopy(self.candidate)
        candidate["runtimeBindings"][1]["openAiPath"] = "/v1/chat/completions"
        self.resign(candidate)
        with self.assertRaisesRegex(ValueError, "runtime_bindings_invalid"):
            self.validate(candidate)

    def test_activation_and_controls_remain_fail_closed(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["activation"]["reasonCodes"].remove("DEPENDENCY_BOM_REISSUE_REQUIRED")
        self.resign(candidate)
        with self.assertRaisesRegex(ValueError, "activation_invalid"):
            self.validate(candidate)

        candidate = copy.deepcopy(self.candidate)
        candidate["controls"]["productionDependencyBomMutated"] = True
        self.resign(candidate)
        with self.assertRaisesRegex(ValueError, "controls_invalid"):
            self.validate(candidate)

    def test_secret_or_manifest_payload_keys_are_rejected(self) -> None:
        for key in ("secretValue", "manifest", "valuesObject"):
            candidate = copy.deepcopy(self.candidate)
            candidate["controls"][key] = "fixture"
            self.resign(candidate)
            with self.assertRaisesRegex(ValueError, f"forbidden_key:{key}"):
                self.validate(candidate)

    def test_candidate_is_bound_to_frozen_inputs(self) -> None:
        for field in ("dependencyBomDigest", "schemaDigest"):
            candidate = copy.deepcopy(self.candidate)
            candidate["bindings"][field] = f"sha256:{'a' * 64}"
            self.resign(candidate)
            with self.assertRaisesRegex(ValueError, "bindings_invalid"):
                self.validate(candidate)

        services = {service["id"]: service for service in self.bom["serviceContracts"]}
        for service_id in ("model-backend", "embedding-model"):
            self.assertEqual(services[service_id]["provider"], "unselected")
            self.assertEqual(
                services[service_id]["reasonCodes"],
                ["MODEL_ARTIFACT_CONTRACT_MISSING"],
            )

    def test_schema_is_closed_at_every_object_boundary(self) -> None:
        def visit(value: Any) -> None:
            if isinstance(value, list):
                for child in value:
                    visit(child)
                return
            if not isinstance(value, dict):
                return
            if value.get("type") == "object":
                self.assertIs(value.get("additionalProperties"), False)
            for child in value.values():
                visit(child)

        visit(self.schema)
        changed = copy.deepcopy(self.schema)
        changed["$defs"]["container"]["additionalProperties"] = True
        with self.assertRaisesRegex(ValueError, "schema_not_strict"):
            self.validate(schema=changed)

    def test_candidate_is_not_referenced_by_active_gitops(self) -> None:
        token = CANDIDATE_PATH.name
        references: list[str] = []
        for path in (ROOT / "gitops").rglob("*"):
            if path.is_file() and token in path.read_text(encoding="utf-8"):
                references.append(str(path.relative_to(ROOT)))
        self.assertEqual(references, [])
        self.assertFalse(self.candidate["controls"]["activeKustomizationReferenced"])

    def test_default_validation_and_ci_include_candidate(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        command = "python3 scripts/validate_production_model_artifact_candidate.py"
        self.assertIn(
            "scripts/validate_production_model_artifact_candidate.py", makefile
        )
        self.assertIn(command, workflow)

    def test_candidate_json_is_canonical_and_schema_is_checked_in(self) -> None:
        candidate_bytes = CANDIDATE_PATH.read_bytes()
        expected = (
            json.dumps(
                json.loads(candidate_bytes),
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
        self.assertEqual(candidate_bytes, expected)
        self.assertTrue(SCHEMA_PATH.is_file())


if __name__ == "__main__":
    unittest.main()
