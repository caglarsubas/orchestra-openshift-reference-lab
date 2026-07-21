from __future__ import annotations

import copy
import hashlib
import unittest

from scripts.validate_dependency_admission import ADMISSION_LOCK
from scripts.validate_repository import load_json
from scripts.verify_dependency_sources import (
    resolved_digests,
    verify_artifact,
    verify_image,
)


class DependencySourceVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admission = load_json(ADMISSION_LOCK)
        self.image = self.admission["images"][0]

    def manifest(self) -> dict:
        source = self.image["source"]
        return {
            "digest": source["indexDigest"],
            "manifests": [
                {
                    "digest": source["platformDigest"],
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "digest": f"sha256:{2:064x}",
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
            ],
        }

    def test_locked_image_matches_resolved_index_and_platform(self) -> None:
        verify_image(self.image, self.manifest())

    def test_changed_platform_manifest_is_rejected(self) -> None:
        manifest = self.manifest()
        manifest["manifests"][0]["digest"] = f"sha256:{3:064x}"
        with self.assertRaisesRegex(ValueError, "digest_mismatch"):
            verify_image(self.image, manifest)

    def test_ambiguous_amd64_manifest_is_rejected(self) -> None:
        manifest = self.manifest()
        manifest["manifests"].append(copy.deepcopy(manifest["manifests"][0]))
        with self.assertRaisesRegex(ValueError, "amd64_manifest_not_unique"):
            resolved_digests(manifest)

    def test_single_platform_manifest_uses_subject_digest(self) -> None:
        digest = f"sha256:{4:064x}"
        self.assertEqual(resolved_digests({"digest": digest}), (digest, digest))

    def test_release_manifest_bytes_are_digest_bound(self) -> None:
        artifact = copy.deepcopy(self.admission["sourceArtifacts"][0])
        content = b"locked release manifest"
        artifact["sourceDigest"] = f"sha256:{hashlib.sha256(content).hexdigest()}"
        verify_artifact(artifact, fetch=lambda _: content)
        with self.assertRaisesRegex(ValueError, "artifact_digest_mismatch"):
            verify_artifact(artifact, fetch=lambda _: b"changed")


if __name__ == "__main__":
    unittest.main()
