from __future__ import annotations

import unittest

from scripts.validate_release_set import PROFILE_DIGEST, validate_release_set
from scripts.validate_repository import ROOT, load_json


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def image(name: str, character: str) -> str:
    return f"ghcr.io/example/{name}@{digest(character)}"


def release_set() -> dict:
    revisions = {"platform": "1" * 40, "runtimeHost": "2" * 40, "modelPlane": "3" * 40}
    platform_image = image("platform", "a")
    runner_image = image("runner", "c")
    runtime_image = image("runtime", "e")
    model_image = image("model", "1")
    return {
        "schemaVersion": 1,
        "kind": "orchestra.cross-plane.release-set.v1",
        "releaseSetId": "orchestra-reference-lab-2026.07.22-rc8",
        "createdAt": "2026-07-21T07:30:00Z",
        "profile": {
            "id": "orchestra-ocp-4.20-amd64-v1",
            "digest": PROFILE_DIGEST,
        },
        "contracts": {
            "modelWorkloadSurface": "orchestra-model-plane-workload-v1",
            "runtimeEdgeOverload": "orchestra-runtime-edge-overload-v1",
        },
        "planes": [
            {
                "plane": "platform",
                "release": "platform-v0.1.0-rc.8",
                "source": {
                    "repository": "caglarsubas/agent-hook-v2",
                    "revision": revisions["platform"],
                },
                "deploymentImage": platform_image,
                "subjects": [
                    {"role": "platform-image-ubi9", "ref": platform_image},
                    {"role": "tools-image-ubi9", "ref": image("tools", "b")},
                    {
                        "role": "certification-runner-image-ubi9",
                        "ref": runner_image,
                    },
                    {"role": "helm-chart", "ref": image("platform-chart", "d")},
                ],
            },
            {
                "plane": "runtimeHost",
                "release": "v0.18.3",
                "source": {
                    "repository": "prometa-ai/orchestra-python-sdk",
                    "revision": revisions["runtimeHost"],
                },
                "deploymentImage": runtime_image,
                "subjects": [
                    {"role": "runtime-host-image-ubi9", "ref": runtime_image},
                    {"role": "helm-chart", "ref": image("runtime-chart", "f")},
                ],
            },
            {
                "plane": "modelPlane",
                "release": "v0.1.10",
                "source": {
                    "repository": "caglarsubas/llm_inference_engine",
                    "revision": revisions["modelPlane"],
                },
                "deploymentImage": model_image,
                "subjects": [
                    {"role": "inference-engine-image-ubi9", "ref": model_image},
                    {"role": "helm-chart", "ref": image("model-chart", "2")},
                ],
            },
        ],
        "certificationRunner": {
            "release": "platform-v0.1.0-rc.8",
            "source": {
                "repository": "caglarsubas/agent-hook-v2",
                "revision": revisions["platform"],
            },
            "image": runner_image,
            "toolchainDigest": digest("3"),
            "baseImage": "ubi9",
            "architecture": "linux/amd64",
        },
    }


class ReleaseSetTests(unittest.TestCase):
    def test_checked_in_release_set_matches_platform_canonical_digest(self) -> None:
        result = validate_release_set(
            load_json(ROOT / "config" / "cross-plane-release-set.lock.json")
        )
        self.assertEqual(
            result,
            "sha256:d4b4ef7e33a6918d8a31d1f62cf704ae4bd8d4973e406f5a8a6d7ef0c1786428",
        )

    def test_valid_release_set_is_canonically_bound(self) -> None:
        result = validate_release_set(release_set())
        self.assertRegex(result, r"^sha256:[a-f0-9]{64}$")

    def test_mutable_deployment_tag_is_rejected(self) -> None:
        changed = release_set()
        changed["planes"][1]["deploymentImage"] = "ghcr.io/example/runtime:v0.18.3"
        with self.assertRaisesRegex(ValueError, "deployment_image_invalid"):
            validate_release_set(changed)

    def test_missing_plane_is_rejected(self) -> None:
        changed = release_set()
        changed["planes"].pop()
        with self.assertRaisesRegex(ValueError, "planes_incomplete"):
            validate_release_set(changed)

    def test_runner_must_match_platform_subject(self) -> None:
        changed = release_set()
        changed["certificationRunner"]["image"] = image("other-runner", "4")
        with self.assertRaisesRegex(ValueError, "runner_invalid"):
            validate_release_set(changed)

    def test_subject_roles_cannot_alias_one_artifact(self) -> None:
        changed = release_set()
        changed["planes"][0]["subjects"][1]["ref"] = changed["planes"][0]["subjects"][
            0
        ]["ref"]
        with self.assertRaisesRegex(ValueError, "subject_roles_invalid"):
            validate_release_set(changed)

    def test_unknown_fields_are_rejected(self) -> None:
        changed = release_set()
        changed["certified"] = True
        with self.assertRaisesRegex(ValueError, "release_set_keys_invalid"):
            validate_release_set(changed)


if __name__ == "__main__":
    unittest.main()
