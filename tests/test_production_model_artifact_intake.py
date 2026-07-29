from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts.production_model_artifact_intake import (
    CLAIMS,
    CONTROLS,
    POLICY_PATH,
    RESTRICTED_ROOT,
    SCHEMA_PATH,
    build_report,
    digest_without_field,
    expected_artifacts,
    inspect_artifact_file,
    load_validated_candidate,
    restricted_path_state,
    restricted_report,
    simulated_artifact,
    validate_policy,
    validate_report,
    validate_snapshot,
    write_create_only,
)
from scripts.validate_repository import ROOT, canonical_digest, load_json


class ProductionModelArtifactIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = load_validated_candidate()
        self.policy = load_json(POLICY_PATH)
        self.schema = load_json(SCHEMA_PATH)
        self.artifacts = expected_artifacts(self.candidate)
        validate_policy(self.policy, self.candidate, self.schema)

    @staticmethod
    def resign(value: dict[str, object], field: str) -> None:
        value[field] = digest_without_field(value, field)

    @staticmethod
    def synthetic_artifact(data: bytes) -> dict[str, object]:
        return {
            "artifactId": "synthetic-model",
            "serviceId": "synthetic",
            "filename": "synthetic.gguf",
            "immutableUrl": "https://example.invalid/resolve/" + "a" * 40 + "/x",
            "revision": "a" * 40,
            "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
            "sizeBytes": len(data),
            "maximumAllowedBytes": max(len(data), 1),
        }

    @staticmethod
    def verified_artifact(artifact: dict[str, object]) -> dict[str, object]:
        return {
            "artifactId": artifact["artifactId"],
            "preReadSizeBytes": artifact["sizeBytes"],
            "postReadSizeBytes": artifact["sizeBytes"],
            "observedDigest": artifact["digest"],
            "preReadGuardPassed": True,
            "descriptorStable": True,
            "expectedSizeMatched": True,
            "expectedDigestMatched": True,
            "reasonCodes": [],
            "result": "VERIFIED",
        }

    def test_policy_is_bound_stable_and_non_authorizing(self) -> None:
        digest = validate_policy(self.policy, self.candidate, self.schema)
        self.assertEqual(digest, self.policy["policyDigest"])
        self.assertEqual(
            self.policy["bindings"]["observationSchemaDigest"],
            canonical_digest(self.schema),
        )
        self.assertFalse(self.policy["controls"]["networkDownloadPerformed"])
        self.assertFalse(self.policy["controls"]["artifactCopyPerformed"])
        self.assertTrue(all(value is False for value in self.policy["claims"].values()))

    def test_policy_drift_is_rejected_even_when_resigned(self) -> None:
        changed = copy.deepcopy(self.policy)
        changed["execution"]["preReadExactSizeRequired"] = False
        self.resign(changed, "policyDigest")
        with self.assertRaisesRegex(ValueError, "execution_invalid"):
            validate_policy(changed, self.candidate, self.schema)

        changed = copy.deepcopy(self.policy)
        changed["bindings"]["candidateDigest"] = f"sha256:{'a' * 64}"
        self.resign(changed, "policyDigest")
        with self.assertRaisesRegex(ValueError, "bindings_invalid"):
            validate_policy(changed, self.candidate, self.schema)

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        def visit(value: object) -> None:
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
        changed["$defs"]["artifact"]["additionalProperties"] = True
        with self.assertRaisesRegex(ValueError, "schema_not_strict"):
            validate_policy(self.policy, self.candidate, changed)

    def test_candidate_and_frozen_bom_boundary_remain_unchanged(self) -> None:
        self.assertEqual(
            [artifact["artifactId"] for artifact in self.policy["artifacts"]],
            [model["id"] for model in self.candidate["models"]],
        )
        bom = load_json(ROOT / "config" / "dependency-bom.lock.json")
        services = {service["id"]: service for service in bom["serviceContracts"]}
        for service_id in ("model-backend", "embedding-model"):
            self.assertEqual(services[service_id]["provider"], "unselected")
            self.assertEqual(
                services[service_id]["reasonCodes"],
                ["MODEL_ARTIFACT_CONTRACT_MISSING"],
            )

    def test_size_mismatch_is_rejected_before_open_or_read(self) -> None:
        with tempfile.TemporaryDirectory(dir=RESTRICTED_ROOT) as directory:
            path = Path(directory) / "model.gguf"
            path.write_bytes(b"short")
            path.chmod(0o600)
            artifact = self.synthetic_artifact(b"expected-longer")
            with mock.patch(
                "scripts.production_model_artifact_intake.os.open"
            ) as open_mock:
                result = inspect_artifact_file(path, artifact)
            open_mock.assert_not_called()
        self.assertEqual(result["result"], "BLOCKED_PRE_READ")
        self.assertEqual(result["reasonCodes"], ["ARTIFACT_SIZE_MISMATCH"])
        self.assertIsNone(result["observedDigest"])

    def test_valid_restricted_file_is_hashed_without_copying(self) -> None:
        data = b"small deterministic model"
        artifact = self.synthetic_artifact(data)
        with tempfile.TemporaryDirectory(dir=RESTRICTED_ROOT) as directory:
            path = Path(directory) / "model.gguf"
            path.write_bytes(data)
            path.chmod(0o600)
            result = inspect_artifact_file(path, artifact)
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(result["result"], "VERIFIED")
        self.assertTrue(result["descriptorStable"])
        self.assertEqual(result["observedDigest"], artifact["digest"])
        self.assertNotIn("path", result)

    def test_digest_mismatch_is_blocked_after_stable_read(self) -> None:
        data = b"same-size-wrong-bytes"
        artifact = self.synthetic_artifact(b"x" * len(data))
        with tempfile.TemporaryDirectory(dir=RESTRICTED_ROOT) as directory:
            path = Path(directory) / "model.gguf"
            path.write_bytes(data)
            path.chmod(0o600)
            result = inspect_artifact_file(path, artifact)
        self.assertEqual(result["result"], "BLOCKED_DURING_READ")
        self.assertEqual(result["reasonCodes"], ["ARTIFACT_DIGEST_MISMATCH"])
        self.assertTrue(result["expectedSizeMatched"])
        self.assertFalse(result["expectedDigestMatched"])

    def test_symlink_outside_file_and_writable_file_fail_closed(self) -> None:
        data = b"model"
        artifact = self.synthetic_artifact(data)
        with tempfile.TemporaryDirectory(dir=RESTRICTED_ROOT) as directory:
            root = Path(directory)
            target = root / "target.gguf"
            target.write_bytes(data)
            target.chmod(0o600)
            link = root / "link.gguf"
            link.symlink_to(target)
            self.assertEqual(
                inspect_artifact_file(link, artifact)["reasonCodes"],
                ["ARTIFACT_SYMLINK"],
            )

            target.chmod(0o622)
            self.assertEqual(
                inspect_artifact_file(target, artifact)["reasonCodes"],
                ["ARTIFACT_GROUP_OR_WORLD_WRITABLE"],
            )

            unsafe_parent = root / "unsafe"
            unsafe_parent.mkdir(mode=0o700)
            nested = unsafe_parent / "nested.gguf"
            nested.write_bytes(data)
            nested.chmod(0o600)
            unsafe_parent.chmod(0o722)
            self.assertEqual(
                inspect_artifact_file(nested, artifact)["reasonCodes"],
                ["ARTIFACT_PARENT_UNSAFE"],
            )

        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "model.gguf"
            outside.write_bytes(data)
            outside.chmod(0o600)
            self.assertEqual(
                inspect_artifact_file(outside, artifact)["reasonCodes"],
                ["ARTIFACT_OUTSIDE_RESTRICTED"],
            )

    def test_descriptor_substitution_is_detected(self) -> None:
        data = b"descriptor-race"
        artifact = self.synthetic_artifact(data)
        with tempfile.TemporaryDirectory(dir=RESTRICTED_ROOT) as directory:
            path = Path(directory) / "model.gguf"
            path.write_bytes(data)
            path.chmod(0o600)
            real_fstat = os.fstat

            def changed_descriptor(descriptor: int) -> os.stat_result:
                result = real_fstat(descriptor)
                values = list(result)
                values[1] += 1
                return os.stat_result(values)

            with mock.patch(
                "scripts.production_model_artifact_intake.os.fstat",
                side_effect=changed_descriptor,
            ):
                result = inspect_artifact_file(path, artifact)
        self.assertEqual(result["result"], "BLOCKED_DURING_READ")
        self.assertEqual(result["reasonCodes"], ["ARTIFACT_DESCRIPTOR_CHANGED"])

    def test_parent_substitution_is_detected_before_leaf_open(self) -> None:
        data = b"ancestor-race"
        artifact = self.synthetic_artifact(data)
        with tempfile.TemporaryDirectory(dir=RESTRICTED_ROOT) as directory:
            root = Path(directory)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            path = parent / "model.gguf"
            path.write_bytes(data)
            path.chmod(0o600)
            replacement = root / "replacement"
            replacement.mkdir(mode=0o700)
            replacement_file = replacement / "model.gguf"
            replacement_file.write_bytes(data)
            replacement_file.chmod(0o600)

            def substitute(candidate: Path, restricted_root: Path) -> str | None:
                state = restricted_path_state(candidate, restricted_root)
                path.unlink()
                parent.rmdir()
                parent.symlink_to(replacement, target_is_directory=True)
                return state

            with mock.patch(
                "scripts.production_model_artifact_intake.restricted_path_state",
                side_effect=substitute,
            ):
                result = inspect_artifact_file(path, artifact)
        self.assertEqual(result["result"], "BLOCKED_DURING_READ")
        self.assertEqual(result["reasonCodes"], ["ARTIFACT_DESCRIPTOR_CHANGED"])

    def test_simulated_snapshot_cannot_claim_source_observation(self) -> None:
        snapshot = load_json(
            ROOT
            / "tests"
            / "fixtures"
            / "production-model-artifact-intake-simulated.json"
        )
        mode, observed_at = validate_snapshot(snapshot, self.candidate)
        report = build_report(
            observation_id="model-intake-simulated.1",
            execution_mode=mode,
            observed_at=observed_at,
            artifacts=[
                simulated_artifact(artifact["artifactId"])
                for artifact in self.artifacts
            ],
            policy=self.policy,
            candidate=self.candidate,
            schema=self.schema,
        )
        validate_report(report, self.policy, self.candidate, self.schema)
        self.assertEqual(report["decision"]["status"], "SIMULATED")
        self.assertEqual(report["decision"]["reasonCodes"], ["SIMULATED_INPUT"])
        self.assertFalse(report["claims"]["artifactCustodyVerified"])

        report["executionMode"] = "local-file-inspection"
        self.resign(report, "reportDigest")
        with self.assertRaisesRegex(ValueError, "artifact_result_invalid"):
            validate_report(
                report,
                self.policy,
                self.candidate,
                self.schema,
                now=observed_at,
            )

    def test_matching_local_report_is_still_non_authorizing(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        report = build_report(
            observation_id="model-intake-local.1",
            execution_mode="local-file-inspection",
            observed_at=now,
            artifacts=[self.verified_artifact(artifact) for artifact in self.artifacts],
            policy=self.policy,
            candidate=self.candidate,
            schema=self.schema,
        )
        validate_report(report, self.policy, self.candidate, self.schema, now=now)
        self.assertEqual(report["decision"]["status"], "SOURCE_BYTES_OBSERVED")
        self.assertEqual(report["claims"], CLAIMS)
        self.assertEqual(report["controls"], CONTROLS)

    def test_stale_tampered_or_escalated_report_is_rejected(self) -> None:
        observed_at = datetime.now(timezone.utc).replace(microsecond=0)
        report = build_report(
            observation_id="model-intake-local.2",
            execution_mode="local-file-inspection",
            observed_at=observed_at,
            artifacts=[self.verified_artifact(artifact) for artifact in self.artifacts],
            policy=self.policy,
            candidate=self.candidate,
            schema=self.schema,
        )
        with self.assertRaisesRegex(ValueError, "report_stale"):
            validate_report(
                report,
                self.policy,
                self.candidate,
                self.schema,
                now=observed_at + timedelta(days=2),
            )

        changed = copy.deepcopy(report)
        changed["artifacts"][0]["observedDigest"] = f"sha256:{'a' * 64}"
        with self.assertRaisesRegex(ValueError, "verified_artifact_invalid"):
            validate_report(
                changed,
                self.policy,
                self.candidate,
                self.schema,
                now=observed_at,
            )

        changed = copy.deepcopy(report)
        changed["claims"]["artifactCustodyVerified"] = True
        self.resign(changed, "reportDigest")
        with self.assertRaisesRegex(ValueError, "claims_invalid"):
            validate_report(
                changed,
                self.policy,
                self.candidate,
                self.schema,
                now=observed_at,
            )

    def test_report_contains_no_paths_bytes_or_secret_values(self) -> None:
        report = build_report(
            observation_id="model-intake-simulated.2",
            execution_mode="simulated",
            observed_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
            artifacts=[
                simulated_artifact(artifact["artifactId"])
                for artifact in self.artifacts
            ],
            policy=self.policy,
            candidate=self.candidate,
            schema=self.schema,
        )
        keys: set[str] = set()

        def visit(value: object) -> None:
            if isinstance(value, dict):
                keys.update(value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(report)
        for key in ("localPath", "inputPath", "secretValue", "modelBytes"):
            self.assertNotIn(key, keys)

    def test_output_is_restricted_private_and_create_only(self) -> None:
        report = build_report(
            observation_id="model-intake-simulated.3",
            execution_mode="simulated",
            observed_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
            artifacts=[
                simulated_artifact(artifact["artifactId"])
                for artifact in self.artifacts
            ],
            policy=self.policy,
            candidate=self.candidate,
            schema=self.schema,
        )
        with tempfile.TemporaryDirectory(dir=RESTRICTED_ROOT) as directory:
            output = Path(directory) / "report.json"
            write_create_only(output, report)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(restricted_report(output), report)
            with self.assertRaisesRegex(ValueError, "output_exists"):
                write_create_only(output, report)

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "output_not_restricted"):
                write_create_only(Path(directory) / "report.json", report)

    def test_report_reader_rejects_duplicate_noncanonical_and_oversized_json(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=RESTRICTED_ROOT) as directory:
            root = Path(directory)
            root.chmod(0o700)
            report = root / "report.json"

            report.write_text('{"a":1,"a":1}\n', encoding="ascii")
            report.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "json_duplicate"):
                restricted_report(report)

            report.write_text('{"a": 1}\n', encoding="ascii")
            report.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "json_noncanonical"):
                restricted_report(report)

            report.write_bytes(b"x" * 65537)
            report.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "report_file_unsafe"):
                restricted_report(report)

    def test_default_validation_ci_and_docs_include_intake(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        readme = (ROOT / "docs" / "runbooks" / "README.md").read_text(encoding="utf-8")
        command = "python3 scripts/production_model_artifact_intake.py validate-policy"
        self.assertIn("production_model_artifact_intake.py validate-policy", makefile)
        self.assertIn(command, workflow)
        self.assertIn("Production model artifact intake", readme)

    def test_json_contracts_are_canonical(self) -> None:
        for path in (POLICY_PATH, SCHEMA_PATH):
            raw = path.read_bytes()
            value = json.loads(raw)
            expected = (
                json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
            ).encode("ascii")
            self.assertEqual(raw, expected)


if __name__ == "__main__":
    unittest.main()
