#!/usr/bin/env python3
"""Independently verify signed-runner dependency scan collection evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

try:
    from scripts.dependency_risk_contract import (
        blob_digest,
        fail,
        load_contract_inputs,
        strict_keys,
        validate_risk_policy,
    )
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import ROOT, load_json
except ModuleNotFoundError:
    from dependency_risk_contract import (
        blob_digest,
        fail,
        load_contract_inputs,
        strict_keys,
        validate_risk_policy,
    )
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, load_json


RELEASE_SET = ROOT / "config" / "cross-plane-release-set.lock.json"
PUBLISHER_ISSUER = "https://token.actions.githubusercontent.com"


def load_json_bytes(path: Path, code: str) -> tuple[dict[str, Any], bytes]:
    try:
        content = path.read_bytes()
        value = json.loads(content)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{code}:{error}")
    if not isinstance(value, dict):
        fail(code)
    return value, content


def sibling_artifact(
    directory: Path, file_name: Any, expected_name: str, code: str
) -> Path:
    if file_name != expected_name or Path(str(file_name)).name != file_name:
        fail(code)
    path = (directory / file_name).resolve()
    if path.parent != directory.resolve() or not path.is_file():
        fail(code)
    return path


def require_artifact_digest(path: Path, expected: Any, code: str) -> None:
    if blob_digest(path.read_bytes()) != expected:
        fail(code)


def run_cosign(cosign: str, arguments: list[str], code: str) -> None:
    try:
        subprocess.run(
            [cosign, *arguments],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=210,
        )
    except subprocess.TimeoutExpired:
        fail(f"{code}:timeout")
    except (OSError, subprocess.CalledProcessError) as error:
        detail = (
            error.stderr.strip()
            if isinstance(error, subprocess.CalledProcessError)
            else str(error)
        )
        fail(f"{code}:{detail}")


def expected_collection_statement(manifest: dict[str, Any]) -> dict[str, Any]:
    collection = manifest["collection"]
    return {
        "schemaVersion": 1,
        "kind": "orchestra.dependency-risk.collection-statement.v1",
        "profileId": manifest["profileId"],
        "targetClass": manifest["targetClass"],
        "executionMode": manifest["executionMode"],
        "evidenceId": manifest["evidenceId"],
        "bindings": manifest["bindings"],
        "runner": {
            "release": collection["runnerRelease"],
            "revision": collection["runnerRevision"],
            "image": collection["runnerImage"],
            "imageDigest": collection["runnerImageDigest"],
            "toolchainDigest": collection["runnerToolchainDigest"],
            "releaseManifestDigest": collection["runnerReleaseManifestDigest"],
            "releaseManifestSignatureBundleDigest": collection[
                "runnerReleaseManifestSignatureBundleDigest"
            ],
            "provenanceBundleDigest": collection["runnerProvenanceBundleDigest"],
            "releaseMetadataDigest": collection["runnerReleaseMetadataDigest"],
        },
        "collector": {
            "executionClass": collection["executionClass"],
            "scriptDigest": collection["collectorScriptDigest"],
            "actorIdentityDigest": collection["actorIdentityDigest"],
            "signingPublicKeyDigest": collection["signingPublicKeyDigest"],
            "startedAt": collection["startedAt"],
            "completedAt": collection["completedAt"],
        },
        "scanners": {
            "vulnerability": collection["vulnerabilityScanner"],
            "sbom": collection["sbomScanner"],
        },
        "invocationPolicy": collection["invocationPolicy"],
        "subjects": manifest["subjects"],
        "claims": {
            "rawArtifactsRestricted": True,
            "sourceAdmissionAuthorized": False,
            "mirrorAuthorization": False,
            "activationAuthorized": False,
            "campaignEvidence": False,
        },
    }


def validate_runner_release_projection(
    collection: dict[str, Any], release_set: dict[str, Any], directory: Path
) -> tuple[Path, Path, Path, Path, Path]:
    runner = release_set["certificationRunner"]
    if (
        collection["runnerRelease"] != runner["release"]
        or collection["runnerRevision"] != runner["source"]["revision"]
        or collection["runnerImage"] != runner["image"]
        or collection["runnerImageDigest"] != runner["image"].rsplit("@", 1)[1]
        or collection["runnerToolchainDigest"] != runner["toolchainDigest"]
    ):
        fail("dependency_risk_runner_release_binding_invalid")

    manifest_path = sibling_artifact(
        directory,
        collection["runnerReleaseManifestFile"],
        "platform-release-manifest.json",
        "dependency_risk_runner_release_manifest_invalid",
    )
    signature_path = sibling_artifact(
        directory,
        collection["runnerReleaseManifestSignatureBundleFile"],
        "platform-release-manifest.sigstore.json",
        "dependency_risk_runner_release_signature_invalid",
    )
    provenance_path = sibling_artifact(
        directory,
        collection["runnerProvenanceBundleFile"],
        "platform-release-manifest.provenance.sigstore.json",
        "dependency_risk_runner_provenance_invalid",
    )
    metadata_path = sibling_artifact(
        directory,
        collection["runnerReleaseMetadataFile"],
        "release-orchestra-certification-runner-ubi.json",
        "dependency_risk_runner_metadata_invalid",
    )
    toolchain_path = sibling_artifact(
        directory,
        collection["runnerToolchainLockFile"],
        "certification-runner-toolchain-lock.json",
        "dependency_risk_runner_toolchain_invalid",
    )
    for path, field, code in (
        (
            manifest_path,
            "runnerReleaseManifestDigest",
            "dependency_risk_runner_release_manifest_digest_mismatch",
        ),
        (
            signature_path,
            "runnerReleaseManifestSignatureBundleDigest",
            "dependency_risk_runner_release_signature_digest_mismatch",
        ),
        (
            provenance_path,
            "runnerProvenanceBundleDigest",
            "dependency_risk_runner_provenance_digest_mismatch",
        ),
        (
            metadata_path,
            "runnerReleaseMetadataDigest",
            "dependency_risk_runner_metadata_digest_mismatch",
        ),
        (
            toolchain_path,
            "runnerToolchainDigest",
            "dependency_risk_runner_toolchain_digest_mismatch",
        ),
    ):
        require_artifact_digest(path, collection[field], code)

    release_manifest, _ = load_json_bytes(
        manifest_path, "dependency_risk_runner_release_manifest_json_invalid"
    )
    release_metadata, _ = load_json_bytes(
        metadata_path, "dependency_risk_runner_metadata_json_invalid"
    )
    if (
        release_manifest.get("release", {}).get("tag") != runner["release"]
        or release_manifest.get("source", {}).get("revision")
        != runner["source"]["revision"]
        or release_manifest.get("source", {}).get("repository")
        != runner["source"]["repository"]
        or release_manifest.get("source", {}).get("ref")
        != f"refs/tags/{runner['release']}"
        or release_manifest.get("productionProfile", {}).get("id")
        != release_set["profile"]["id"]
        or release_manifest.get("productionProfile", {}).get("digest")
        != release_set["profile"]["digest"]
        or runner["image"]
        not in [
            image.get("ref")
            for image in release_manifest.get("subjects", {}).get("images", [])
            if isinstance(image, dict)
        ]
    ):
        fail("dependency_risk_runner_release_manifest_projection_invalid")
    metadata_ref = (
        f"{release_metadata.get('repository')}@{release_metadata.get('digest')}"
    )
    if (
        release_metadata.get("tag") != runner["release"]
        or release_metadata.get("revision") != runner["source"]["revision"]
        or release_metadata.get("role") != "certification-runner"
        or release_metadata.get("flavor") != "ubi9"
        or metadata_ref != runner["image"]
        or release_metadata.get("toolchain", {}).get("digest")
        != runner["toolchainDigest"]
    ):
        fail("dependency_risk_runner_metadata_projection_invalid")
    return (
        manifest_path,
        signature_path,
        provenance_path,
        metadata_path,
        toolchain_path,
    )


def verify_collection_attestation(
    manifest: dict[str, Any], directory: Path, *, cosign: str = "cosign"
) -> str:
    strict_keys(
        manifest,
        {
            "schemaVersion",
            "profileId",
            "targetClass",
            "executionMode",
            "evidenceId",
            "bindings",
            "collection",
            "subjects",
        },
        "dependency_risk_manifest_keys_invalid",
    )
    admission, source_verification, risk_policy = load_contract_inputs()
    validate_risk_policy(risk_policy)
    try:
        from scripts.build_dependency_risk_evidence import validate_manifest
    except ModuleNotFoundError:
        from build_dependency_risk_evidence import validate_manifest

    validate_manifest(manifest, admission, source_verification)
    release_set = load_json(RELEASE_SET)
    release_set_digest = validate_release_set(release_set)
    if manifest["bindings"]["releaseSetDigest"] != release_set_digest:
        fail("dependency_risk_release_set_digest_mismatch")

    collection = manifest["collection"]
    manifest_path, release_signature_path, provenance_path, _, _ = (
        validate_runner_release_projection(collection, release_set, directory)
    )
    statement_path = sibling_artifact(
        directory,
        collection["collectionAttestationFile"],
        "dependency-risk-collection-statement.json",
        "dependency_risk_collection_statement_invalid",
    )
    signature_path = sibling_artifact(
        directory,
        collection["collectionSignatureBundleFile"],
        "dependency-risk-collection-signature.sigstore.json",
        "dependency_risk_collection_signature_invalid",
    )
    public_key_path = sibling_artifact(
        directory,
        collection["signingPublicKeyFile"],
        "collection-signing-public-key.pem",
        "dependency_risk_collection_public_key_invalid",
    )
    collector_script_path = sibling_artifact(
        directory,
        collection["collectorScriptFile"],
        "dependency-risk-collector.sh",
        "dependency_risk_collector_script_invalid",
    )
    require_artifact_digest(
        statement_path,
        collection["collectionAttestationDigest"],
        "dependency_risk_collection_statement_digest_mismatch",
    )
    require_artifact_digest(
        signature_path,
        collection["collectionSignatureBundleDigest"],
        "dependency_risk_collection_signature_digest_mismatch",
    )
    require_artifact_digest(
        public_key_path,
        collection["signingPublicKeyDigest"],
        "dependency_risk_collection_public_key_digest_mismatch",
    )
    require_artifact_digest(
        collector_script_path,
        collection["collectorScriptDigest"],
        "dependency_risk_collector_script_digest_mismatch",
    )
    for subject in manifest["subjects"]:
        subject_id = subject["id"]
        for file_field, digest_field, kind in (
            ("vulnerabilityReportFile", "vulnerabilityReportDigest", "vulnerability"),
            ("sbomFile", "sbomDigest", "sbom"),
        ):
            file_name = subject[file_field]
            artifact_path = sibling_artifact(
                directory,
                file_name,
                file_name,
                f"dependency_risk_collection_artifact_invalid:{subject_id}:{kind}",
            )
            require_artifact_digest(
                artifact_path,
                subject[digest_field],
                f"dependency_risk_collection_artifact_digest_mismatch:{subject_id}:{kind}",
            )
    statement, statement_bytes = load_json_bytes(
        statement_path, "dependency_risk_collection_statement_json_invalid"
    )
    if statement != expected_collection_statement(manifest):
        fail("dependency_risk_collection_statement_projection_invalid")

    publisher_identity = (
        "https://github.com/caglarsubas/agent-hook-v2/"
        ".github/workflows/publish-platform-release.yml@refs/tags/"
        f"{collection['runnerRelease']}"
    )
    publisher_constraints = [
        "--timeout",
        "3m",
        "--certificate-identity",
        publisher_identity,
        "--certificate-oidc-issuer",
        PUBLISHER_ISSUER,
        "--certificate-github-workflow-sha",
        collection["runnerRevision"],
        "--certificate-github-workflow-ref",
        f"refs/tags/{collection['runnerRelease']}",
        "--certificate-github-workflow-repository",
        "caglarsubas/agent-hook-v2",
        "--certificate-github-workflow-trigger",
        "push",
    ]
    run_cosign(
        cosign,
        [
            "verify-blob",
            "--bundle",
            str(signature_path),
            "--key",
            str(public_key_path),
            str(statement_path),
        ],
        "dependency_risk_collection_signature_verification_failed",
    )
    run_cosign(
        cosign,
        [
            "verify-blob",
            "--bundle",
            str(release_signature_path),
            *publisher_constraints,
            str(manifest_path),
        ],
        "dependency_risk_runner_release_signature_verification_failed",
    )
    run_cosign(
        cosign,
        [
            "verify-blob-attestation",
            "--bundle",
            str(provenance_path),
            "--type",
            "https://slsa.dev/provenance/v1",
            *publisher_constraints,
            str(manifest_path),
        ],
        "dependency_risk_runner_provenance_verification_failed",
    )
    run_cosign(
        cosign,
        [
            "verify",
            collection["runnerImage"],
            *publisher_constraints,
        ],
        "dependency_risk_runner_image_signature_verification_failed",
    )
    run_cosign(
        cosign,
        [
            "verify-attestation",
            collection["runnerImage"],
            "--type",
            "cyclonedx",
            *publisher_constraints,
        ],
        "dependency_risk_runner_image_attestation_verification_failed",
    )
    return blob_digest(statement_bytes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)
    manifest_path = args.manifest.resolve()
    manifest, _ = load_json_bytes(
        manifest_path, "dependency_risk_manifest_json_invalid"
    )
    digest = verify_collection_attestation(
        manifest, manifest_path.parent, cosign=args.cosign
    )
    print(
        "dependency_risk_collection_verified "
        f"statement={digest} sourceAdmission=false mirrorAuthorization=false "
        "campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
