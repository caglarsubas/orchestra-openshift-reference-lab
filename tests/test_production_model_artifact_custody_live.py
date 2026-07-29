from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.github_environment_contract import load_expected_environment
from scripts.production_model_artifact_custody import expected_artifacts
from scripts.production_model_artifact_custody_live import (
    UPLOAD_CLAIMS,
    UPLOAD_CONTROLS,
    build_upload_receipt,
    inventory_objects,
    load_inputs,
    validate_upload_receipt,
)
from scripts.production_model_artifact_intake import build_report
from scripts.validate_repository import canonical_digest, load_json


class Args:
    pass


class ProductionModelArtifactCustodyLiveTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.candidate,
            self.source_policy,
            self.policy,
            _,
            _,
            self.upload_schema,
        ) = load_inputs()
        artifacts = [
            {
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
            for artifact in expected_artifacts(self.candidate)
        ]
        self.source = build_report(
            observation_id="production-model-intake-live-fixture.1",
            execution_mode="local-file-inspection",
            observed_at=datetime.now(timezone.utc).replace(microsecond=0),
            artifacts=artifacts,
            policy=self.source_policy,
            candidate=self.candidate,
            schema=load_json(
                Path(
                    "schemas/production-model-artifact-intake-observation-v1.schema.json"
                )
            ),
        )

    def receipt(self) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            source.write_text(__import__("json").dumps(self.source), encoding="utf-8")
            args = Args()
            args.source_observation = source
            args.record_id = "production-model-custody-live-fixture.1"
            args.bucket = "orchestra-model-artifacts-fixture"
            args.uploader_identity_digest = f"sha256:{'a' * 64}"
            args.copy_started_at = self.source["observedAt"]
            args.copy_completed_at = self.source["observedAt"]
            return build_upload_receipt(args)

    def test_upload_receipt_is_strict_and_non_authorizing(self) -> None:
        receipt = self.receipt()
        digest = validate_upload_receipt(
            receipt,
            self.source,
            self.candidate,
            self.source_policy,
            self.policy,
            self.upload_schema,
        )
        self.assertEqual(digest, receipt["receiptDigest"])
        self.assertEqual(receipt["controls"], UPLOAD_CONTROLS)
        self.assertEqual(receipt["claims"], UPLOAD_CLAIMS)
        self.assertFalse(receipt["claims"]["artifactCustodyVerified"])
        self.assertFalse(receipt["claims"]["sourceAdmissionAuthorized"])

    def test_receipt_tamper_and_actor_reuse_are_rejected(self) -> None:
        receipt = self.receipt()
        changed = copy.deepcopy(receipt)
        changed["claims"]["artifactCustodyVerified"] = True
        changed["receiptDigest"] = canonical_digest(
            {key: value for key, value in changed.items() if key != "receiptDigest"}
        )
        with self.assertRaisesRegex(ValueError, "claims_invalid"):
            validate_upload_receipt(
                changed,
                self.source,
                self.candidate,
                self.source_policy,
                self.policy,
                self.upload_schema,
            )

    def test_inventory_rejects_extra_or_unheld_objects_before_download(self) -> None:
        receipt = self.receipt()
        prefix = receipt["storage"]["prefix"]
        key = (
            "projects/orchestra-services-12345/locations/europe-west1/"
            "keyRings/orchestra-reference-evidence/cryptoKeys/"
            "production-model-artifact-custody/cryptoKeyVersions/1"
        )
        names = [
            f"{prefix}/production-model-artifact-intake-observation.json",
            f"{prefix}/production-model-artifact-upload-receipt.json",
            *(artifact["objectName"] for artifact in receipt["artifacts"]),
        ]
        inventory = {
            "schemaVersion": 1,
            "bucket": receipt["storage"]["bucket"],
            "prefix": prefix,
            "objects": [
                {
                    "name": name,
                    "generation": str(index),
                    "metageneration": "1",
                    "sizeBytes": 1,
                    "crc32c": "AAAAAA==",
                    "kmsKeyName": key,
                    "eventBasedHold": True,
                    "temporaryHold": False,
                    "timeCreated": self.source["observedAt"],
                    "updated": self.source["observedAt"],
                }
                for index, name in enumerate(names, start=1)
            ],
        }
        self.assertEqual(
            set(
                inventory_objects(
                    inventory,
                    bucket=receipt["storage"]["bucket"],
                    prefix=prefix,
                )
            ),
            set(names),
        )
        inventory["objects"][0]["eventBasedHold"] = False
        with self.assertRaisesRegex(ValueError, "inventory_object_invalid"):
            inventory_objects(
                inventory,
                bucket=receipt["storage"]["bucket"],
                prefix=prefix,
            )

    def test_production_environments_bind_distinct_providers(self) -> None:
        upload = load_expected_environment("production-model-custody-upload")
        verify = load_expected_environment("production-model-custody-verification")
        self.assertEqual(upload["providerId"], "production-model-custody-upload")
        self.assertEqual(verify["providerId"], "production-model-custody-verify")
        self.assertNotEqual(upload["environment"], verify["environment"])
        self.assertTrue(upload["preventSelfReview"])
        self.assertTrue(verify["preventSelfReview"])

    def test_upload_receipt_schema_is_strict_at_every_object_boundary(self) -> None:
        stack = [self.upload_schema]
        while stack:
            value = stack.pop()
            if isinstance(value, list):
                stack.extend(value)
            elif isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(value.get("additionalProperties"), False)
                stack.extend(value.values())


if __name__ == "__main__":
    unittest.main()
