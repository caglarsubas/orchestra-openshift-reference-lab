from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.lab_service_publication import (
    ATTESTATION_MEDIA_TYPE,
    CERTIFICATE_IDENTITY,
    IMAGE_CONFIG_MEDIA_TYPE,
    IMAGE_MANIFEST_MEDIA_TYPE,
    INDEX_MEDIA_TYPE,
    OIDC_ISSUER,
    PROVENANCE_PREDICATE,
    SBOM_PREDICATE,
    build_observation,
    canonical_digest,
    expected_claims,
    load_policy,
    package_metadata,
    parse_json_bytes,
    source_tree_digest,
    validate_declared_implementation,
    validate_report,
    verify_oci_image,
    write_create_only,
)


def encoded(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


class OciFixture:
    def __init__(
        self,
        repository: str,
        tag: str,
        *,
        predicates: list[str] | None = None,
        attestation_subject: str | None = None,
        platforms: list[dict[str, str]] | None = None,
        seed: int = 1,
    ) -> None:
        self.repository = repository
        self.tag = tag
        predicates = predicates or [SBOM_PREDICATE, PROVENANCE_PREDICATE]
        image_manifest_digest = "sha256:" + (f"{seed:x}" * 64)
        layers = [
            {
                "mediaType": ATTESTATION_MEDIA_TYPE,
                "digest": "sha256:" + (f"{seed + index + 1:x}" * 64),
                "size": 1024 + index,
                "annotations": {"in-toto.io/predicate-type": predicate},
            }
            for index, predicate in enumerate(predicates)
        ]
        attestation = {
            "schemaVersion": 2,
            "mediaType": IMAGE_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": IMAGE_CONFIG_MEDIA_TYPE,
                "digest": "sha256:" + (f"{seed + 3:x}" * 64),
                "size": 241,
            },
            "layers": layers,
        }
        self.attestation_raw = encoded(attestation)
        self.attestation_digest = digest(self.attestation_raw)
        manifest_platforms = platforms or [
            {"architecture": "amd64", "os": "linux"},
            {"architecture": "unknown", "os": "unknown"},
        ]
        manifests: list[dict[str, Any]] = []
        for platform in manifest_platforms:
            if platform == {"architecture": "amd64", "os": "linux"}:
                manifests.append(
                    {
                        "mediaType": IMAGE_MANIFEST_MEDIA_TYPE,
                        "digest": image_manifest_digest,
                        "size": 2009,
                        "platform": platform,
                    }
                )
            else:
                manifests.append(
                    {
                        "mediaType": IMAGE_MANIFEST_MEDIA_TYPE,
                        "digest": self.attestation_digest,
                        "size": len(self.attestation_raw),
                        "annotations": {
                            "vnd.docker.reference.digest": (
                                attestation_subject or image_manifest_digest
                            ),
                            "vnd.docker.reference.type": "attestation-manifest",
                        },
                        "platform": platform,
                    }
                )
        self.index_raw = encoded(
            {
                "schemaVersion": 2,
                "mediaType": INDEX_MEDIA_TYPE,
                "manifests": manifests,
            }
        )
        self.index_digest = digest(self.index_raw)
        self.values = {
            f"{repository}:{tag}": self.index_raw,
            f"{repository}@{self.index_digest}": self.index_raw,
            f"{repository}@{self.attestation_digest}": self.attestation_raw,
        }

    def inspect(self, reference: str) -> bytes:
        try:
            return self.values[reference]
        except KeyError as error:
            raise AssertionError(
                f"unexpected registry reference: {reference}"
            ) from error


class LabServicePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy, self.policy_digest = load_policy()
        self.revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.release = "lab-services-v0.1.0-rc.1"
        self.tag = f"{self.release}-{self.revision}"

    def fixtures(self) -> tuple[dict[str, OciFixture], dict[str, str]]:
        fixtures = {
            service["id"]: OciFixture(
                service["imageRepository"], self.tag, seed=(index * 5) + 1
            )
            for index, service in enumerate(self.policy["services"])
        }
        return fixtures, {
            service_id: fixture.index_digest for service_id, fixture in fixtures.items()
        }

    def inspector(self, fixtures: dict[str, OciFixture]):
        values = {
            reference: raw
            for fixture in fixtures.values()
            for reference, raw in fixture.values.items()
        }

        def inspect(reference: str) -> bytes:
            try:
                return values[reference]
            except KeyError as error:
                raise AssertionError(
                    f"unexpected registry reference: {reference}"
                ) from error

        return inspect

    def observation(self) -> dict[str, Any]:
        fixtures, image_digests = self.fixtures()
        signature_calls: list[tuple[str, str, str]] = []

        def verify(subject: str, identity: str, issuer: str) -> None:
            signature_calls.append((subject, identity, issuer))

        report = build_observation(
            release=self.release,
            revision=self.revision,
            run_id="424242",
            run_attempt=1,
            actor_id="37515097",
            published_at="2026-07-23T12:00:00Z",
            image_digests=image_digests,
            inspect_raw=self.inspector(fixtures),
            verify_signature=verify,
        )
        self.assertEqual(len(signature_calls), 2)
        self.assertTrue(
            all(
                identity == CERTIFICATE_IDENTITY and issuer == OIDC_ISSUER
                for _, identity, issuer in signature_calls
            )
        )
        return report

    def test_policy_schema_and_workflow_are_locked(self) -> None:
        self.assertEqual(
            self.policy_digest,
            "sha256:61e1af0f3c2874df6ec8077e3ac03f2a036197e0998d224a7cafea8c5130b8e1",
        )
        self.assertFalse(self.policy["build"]["sbomGenerator"]["certificationScanner"])
        self.assertEqual(
            self.policy["build"]["sbomGenerator"]["embeddedSyftVersion"],
            "1.42.3",
        )
        validate_declared_implementation(self.policy)
        makefile = Path("Makefile").read_text(encoding="utf-8")
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        command = "scripts/lab_service_publication.py validate-policy"
        self.assertIn(command, makefile)
        self.assertIn(command, workflow)
        self.assertIn("verify-lab-service-publication:", makefile)

    def test_valid_oci_index_binds_platform_subject_and_predicates(self) -> None:
        service = self.policy["services"][0]
        fixture = OciFixture(service["imageRepository"], self.tag)
        result = verify_oci_image(
            service["imageRepository"],
            self.tag,
            fixture.index_digest,
            inspect_raw=fixture.inspect,
        )
        self.assertEqual(
            set(result),
            {
                "imageManifestDigest",
                "attestationManifestDigest",
                "sbomDigest",
                "provenanceDigest",
            },
        )
        self.assertNotEqual(result["sbomDigest"], result["provenanceDigest"])

    def test_tag_must_resolve_to_the_declared_index_digest(self) -> None:
        service = self.policy["services"][0]
        fixture = OciFixture(service["imageRepository"], self.tag)
        wrong = "sha256:" + ("f" * 64)
        fixture.values[f"{service['imageRepository']}@{wrong}"] = fixture.index_raw
        with self.assertRaisesRegex(ValueError, "tag_digest_mismatch"):
            verify_oci_image(
                service["imageRepository"],
                self.tag,
                wrong,
                inspect_raw=fixture.inspect,
            )

    def test_exact_sbom_and_provenance_predicates_are_required(self) -> None:
        service = self.policy["services"][0]
        fixture = OciFixture(
            service["imageRepository"],
            self.tag,
            predicates=[SBOM_PREDICATE, SBOM_PREDICATE],
        )
        with self.assertRaisesRegex(ValueError, "predicate_duplicate"):
            verify_oci_image(
                service["imageRepository"],
                self.tag,
                fixture.index_digest,
                inspect_raw=fixture.inspect,
            )
        fixture = OciFixture(
            service["imageRepository"],
            self.tag,
            predicates=[SBOM_PREDICATE, "https://example.invalid/predicate"],
        )
        with self.assertRaisesRegex(ValueError, "layer_semantics_invalid"):
            verify_oci_image(
                service["imageRepository"],
                self.tag,
                fixture.index_digest,
                inspect_raw=fixture.inspect,
            )

    def test_attestation_must_bind_the_only_amd64_image_manifest(self) -> None:
        service = self.policy["services"][0]
        fixture = OciFixture(
            service["imageRepository"],
            self.tag,
            attestation_subject="sha256:" + ("9" * 64),
        )
        with self.assertRaisesRegex(ValueError, "attestation_subject_invalid"):
            verify_oci_image(
                service["imageRepository"],
                self.tag,
                fixture.index_digest,
                inspect_raw=fixture.inspect,
            )
        fixture = OciFixture(
            service["imageRepository"],
            self.tag,
            platforms=[
                {"architecture": "amd64", "os": "linux"},
                {"architecture": "amd64", "os": "linux"},
            ],
        )
        with self.assertRaisesRegex(ValueError, "image_manifest_duplicate"):
            verify_oci_image(
                service["imageRepository"],
                self.tag,
                fixture.index_digest,
                inspect_raw=fixture.inspect,
            )

    def test_observation_is_payload_free_and_cannot_escalate_claims(self) -> None:
        report = self.observation()
        validate_report(
            report,
            self.policy,
            self.policy_digest,
            assessed_at=datetime(2026, 7, 23, 12, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(report["claims"], expected_claims())

        def keys(value: Any) -> list[str]:
            if isinstance(value, dict):
                return list(value) + [
                    child_key for child in value.values() for child_key in keys(child)
                ]
            if isinstance(value, list):
                return [child_key for child in value for child_key in keys(child)]
            return []

        report_keys = [key.lower() for key in keys(report)]
        self.assertFalse(any("token" in key for key in report_keys))
        self.assertFalse(any("secret" in key for key in report_keys))
        tampered = copy.deepcopy(report)
        tampered["claims"]["harborMirrored"] = True
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(tampered, self.policy, self.policy_digest)
        tampered = copy.deepcopy(report)
        tampered["claims"]["campaignEvidence"] = True
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(tampered, self.policy, self.policy_digest)

    def test_observation_rejects_service_reordering_and_signature_substitution(
        self,
    ) -> None:
        report = self.observation()
        tampered = copy.deepcopy(report)
        tampered["services"].reverse()
        with self.assertRaisesRegex(ValueError, "report_service_invalid"):
            validate_report(tampered, self.policy, self.policy_digest)
        tampered = copy.deepcopy(report)
        tampered["services"][0]["signature"]["certificateIdentity"] = (
            "https://example.invalid/workflow"
        )
        with self.assertRaisesRegex(ValueError, "report_service_invalid"):
            validate_report(tampered, self.policy, self.policy_digest)
        tampered = copy.deepcopy(report)
        tampered["services"][1]["image"]["digest"] = tampered["services"][0]["image"][
            "digest"
        ]
        tampered["services"][1]["signature"]["subject"] = (
            f"{tampered['services'][1]['image']['repository']}@"
            f"{tampered['services'][1]['image']['digest']}"
        )
        with self.assertRaisesRegex(ValueError, "service_substitution"):
            validate_report(tampered, self.policy, self.policy_digest)

    def test_observation_rejects_future_time_and_wrong_release_identity(self) -> None:
        report = self.observation()
        with self.assertRaisesRegex(ValueError, "report_from_future"):
            validate_report(
                report,
                self.policy,
                self.policy_digest,
                assessed_at=datetime(2026, 7, 23, 11, 0, tzinfo=timezone.utc),
            )
        tampered = copy.deepcopy(report)
        tampered["release"]["name"] = "lab-services-v0.1.0"
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(tampered, self.policy, self.policy_digest)

    def test_source_digests_and_package_identity_bind_exact_revision(self) -> None:
        digests = [
            source_tree_digest(self.revision, service["sourcePath"])
            for service in self.policy["services"]
        ]
        self.assertEqual(len(set(digests)), 2)
        self.assertTrue(all(value.startswith("sha256:") for value in digests))
        for service in self.policy["services"]:
            metadata = package_metadata(self.revision, service)
            self.assertEqual(metadata["name"], service["packageName"])
            self.assertEqual(metadata["version"], "0.1.0")
        wrong = copy.deepcopy(self.policy["services"][0])
        wrong["packageName"] = "substituted-package"
        with self.assertRaisesRegex(ValueError, "package_identity_invalid"):
            package_metadata(self.revision, wrong)

    def test_observation_output_is_create_only_and_private(self) -> None:
        report = self.observation()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "observation.json"
            write_create_only(output, report)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            self.assertEqual(
                canonical_digest(json.loads(output.read_text(encoding="ascii"))),
                canonical_digest(report),
            )
            with self.assertRaisesRegex(ValueError, "output_create_failed"):
                write_create_only(output, report)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate_key"):
            parse_json_bytes(b'{"schemaVersion":1,"schemaVersion":1}', "fixture")


if __name__ == "__main__":
    unittest.main()
