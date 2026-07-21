#!/usr/bin/env python3
"""Re-resolve dependency source subjects without claiming signature admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import urllib.request
from collections.abc import Callable
from typing import Any, NoReturn

try:
    from scripts.validate_dependency_admission import ADMISSION_LOCK
    from scripts.validate_repository import load_json
except ModuleNotFoundError:
    from validate_dependency_admission import ADMISSION_LOCK
    from validate_repository import load_json


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def resolved_digests(manifest: dict[str, Any]) -> tuple[str, str]:
    index_digest = manifest.get("digest")
    if not isinstance(index_digest, str):
        fail("dependency_source_index_digest_missing")
    manifests = manifest.get("manifests")
    if manifests is None:
        return index_digest, index_digest
    if not isinstance(manifests, list):
        fail("dependency_source_manifest_list_invalid")
    matches = []
    for item in manifests:
        if not isinstance(item, dict):
            continue
        platform = item.get("platform")
        if (
            isinstance(platform, dict)
            and platform.get("os") == "linux"
            and platform.get("architecture") == "amd64"
            and isinstance(item.get("digest"), str)
        ):
            matches.append(item["digest"])
    if len(matches) != 1:
        fail("dependency_source_amd64_manifest_not_unique")
    return index_digest, matches[0]


def inspect_image(reference: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            reference,
            "--format",
            "{{json .Manifest}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        fail("dependency_source_manifest_object_required")
    return value


def verify_image(image: dict[str, Any], manifest: dict[str, Any]) -> None:
    source = image["source"]
    index_digest, platform_digest = resolved_digests(manifest)
    if (
        index_digest != source["indexDigest"]
        or platform_digest != source["platformDigest"]
    ):
        fail(f"dependency_source_digest_mismatch:{image['id']}")


def verify_artifact(
    artifact: dict[str, Any],
    fetch: Callable[[str], bytes] | None = None,
) -> None:
    def download(url: str) -> bytes:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
            return response.read()

    downloader = fetch or download
    content = downloader(artifact["sourceUrl"])
    digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
    if digest != artifact["sourceDigest"]:
        fail(f"dependency_source_artifact_digest_mismatch:{artifact['id']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--image",
        action="append",
        default=[],
        help="Verify only the named image id; repeat to select several.",
    )
    parser.add_argument(
        "--skip-artifacts",
        action="store_true",
        help="Skip release-manifest downloads during an image-only check.",
    )
    args = parser.parse_args(argv)
    admission = load_json(ADMISSION_LOCK)
    selected = set(args.image)
    known = {image["id"] for image in admission["images"]}
    unknown = selected - known
    if unknown:
        fail(f"dependency_source_image_unknown:{sorted(unknown)[0]}")

    verified = 0
    for image in admission["images"]:
        if selected and image["id"] not in selected:
            continue
        verify_image(image, inspect_image(image["source"]["reference"]))
        verified += 1
        print(
            "dependency_source_image_ok "
            f"id={image['id']} platform={image['source']['platform']}"
        )
    artifacts = 0
    if not args.skip_artifacts:
        for artifact in admission["sourceArtifacts"]:
            verify_artifact(artifact)
            artifacts += 1
            print(f"dependency_source_artifact_ok id={artifact['id']}")
    print(
        "dependency_sources_resolved "
        f"images={verified} artifacts={artifacts} signatureAdmission=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ValueError,
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
    ) as error:
        print(error)
        raise SystemExit(1)
