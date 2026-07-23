#!/usr/bin/env python3
"""Publish-proof contract for the two lab-owned source service images."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "lab-service-publication.lock.json"
SCHEMA_PATH = ROOT / "schemas" / "lab-service-publication-observation-v1.schema.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "lab-service-publication.yml"
EXPECTED_POLICY_DIGEST = (
    "sha256:61e1af0f3c2874df6ec8077e3ac03f2a036197e0998d224a7cafea8c5130b8e1"
)
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
POLICY_KIND = "orchestra.reference-lab.lab-service-publication-policy.v1"
OBSERVATION_KIND = "orchestra.reference-lab.lab-service-publication-observation.v1"
REPOSITORY_ID = 1307302690
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
WORKFLOW_REF = "refs/heads/main"
WORKFLOW_RELATIVE_PATH = ".github/workflows/lab-service-publication.yml"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
CERTIFICATE_IDENTITY = (
    "https://github.com/caglarsubas/orchestra-openshift-reference-lab/"
    ".github/workflows/lab-service-publication.yml@refs/heads/main"
)
INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
IMAGE_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
ATTESTATION_MEDIA_TYPE = "application/vnd.in-toto+json"
SBOM_PREDICATE = "https://spdx.dev/Document"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
SBOM_GENERATOR = (
    "docker.io/docker/buildkit-syft-scanner@"
    "sha256:79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68"
)
PACKAGE_VERSION = "0.1.0"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
RELEASE = re.compile(r"^lab-services-v0\.1\.0-rc\.[1-9][0-9]*$")
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ATTESTATION_LAYER_BYTES = 128 * 1024 * 1024
InspectRaw = Callable[[str], bytes]
VerifySignature = Callable[[str, str, str], None]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def parse_json_bytes(raw: bytes, code: str) -> dict[str, Any]:
    if len(raw) > MAX_MANIFEST_BYTES:
        fail(f"{code}_too_large")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{code}_duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{code}_json_invalid") from error
    if not isinstance(value, dict):
        fail(f"{code}_object_required")
    return value


def read_json(path: Path, code: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"{code}_read_failed") from error
    return raw, parse_json_bytes(raw, code)


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def canonical_digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_bytes(value)).hexdigest()}"


def raw_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(code) from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(code)
    return parsed.astimezone(timezone.utc)


def expected_services() -> list[dict[str, Any]]:
    return [
        {
            "id": "release-validation-receiver",
            "sourcePath": "services/release-validation-receiver",
            "containerfile": "services/release-validation-receiver/Containerfile",
            "packageName": "orchestra-reference-lab-release-receiver",
            "imageRepository": (
                "ghcr.io/caglarsubas/orchestra-lab-release-validation-receiver"
            ),
        },
        {
            "id": "synthetic-tenant-kit",
            "sourcePath": "services/synthetic-tenant-kit",
            "containerfile": "services/synthetic-tenant-kit/Containerfile",
            "packageName": "orchestra-reference-lab-synthetic-tenant-kit",
            "imageRepository": (
                "ghcr.io/caglarsubas/orchestra-lab-synthetic-tenant-kit"
            ),
        },
    ]


def expected_claims() -> dict[str, bool]:
    return {
        "sourceArtifactsPublished": True,
        "digestVerified": True,
        "keylessSignatureVerified": True,
        "embeddedSbomVerified": True,
        "provenanceVerified": True,
        "certificationRiskScan": False,
        "harborMirrored": False,
        "rhtasAdmissionVerified": False,
        "gitOpsReferenced": False,
        "deployed": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }


def expected_policy(schema_digest: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": POLICY_KIND,
        "profileId": PROFILE_ID,
        "repository": {
            "id": REPOSITORY_ID,
            "fullName": REPOSITORY,
            "visibility": "private",
            "defaultBranch": "main",
        },
        "workflow": {
            "path": WORKFLOW_RELATIVE_PATH,
            "ref": WORKFLOW_REF,
            "issuer": OIDC_ISSUER,
            "certificateIdentity": CERTIFICATE_IDENTITY,
            "requiredRunAttempt": 1,
        },
        "release": {
            "pattern": r"^lab-services-v0\.1\.0-rc\.[1-9][0-9]*$",
            "packageVersion": PACKAGE_VERSION,
            "tagTemplate": "{release}-{revision}",
        },
        "build": {
            "platform": {"os": "linux", "architecture": "amd64"},
            "indexMediaType": INDEX_MEDIA_TYPE,
            "imageManifestMediaType": IMAGE_MANIFEST_MEDIA_TYPE,
            "attestationMediaType": ATTESTATION_MEDIA_TYPE,
            "attestationManifestType": "attestation-manifest",
            "provenanceMode": "max",
            "requiredPredicates": [SBOM_PREDICATE, PROVENANCE_PREDICATE],
            "sbomGenerator": {
                "image": SBOM_GENERATOR,
                "scannerVersion": "1.11.0",
                "embeddedSyftVersion": "1.42.3",
                "certificationScanner": False,
            },
        },
        "services": expected_services(),
        "observation": {
            "schema": ("schemas/lab-service-publication-observation-v1.schema.json"),
            "schemaDigest": schema_digest,
        },
        "requiredClaims": expected_claims(),
    }


def validate_schema(schema: dict[str, Any]) -> None:
    def require_strict_objects(value: Any, path: str = "$") -> None:
        if isinstance(value, list):
            for index, child in enumerate(value):
                require_strict_objects(child, f"{path}/{index}")
            return
        if not isinstance(value, dict):
            return
        if (
            value.get("type") == "object"
            and value.get("additionalProperties") is not False
        ):
            fail(f"lab_service_publication_schema_not_strict:{path}")
        for key, child in value.items():
            require_strict_objects(child, f"{path}/{key}")

    strict_keys(
        schema,
        {
            "$schema",
            "$id",
            "additionalProperties",
            "properties",
            "required",
            "type",
        },
        "lab_service_publication_schema_keys_invalid",
    )
    properties = schema["properties"]
    if (
        schema["type"] != "object"
        or schema["additionalProperties"] is not False
        or properties.get("kind", {}).get("const") != OBSERVATION_KIND
        or properties.get("profileId", {}).get("const") != PROFILE_ID
    ):
        fail("lab_service_publication_schema_identity_invalid")
    require_strict_objects(schema)


def load_policy() -> tuple[dict[str, Any], str]:
    _, schema = read_json(SCHEMA_PATH, "lab_service_publication_schema")
    validate_schema(schema)
    schema_digest = canonical_digest(schema)
    _, policy = read_json(POLICY_PATH, "lab_service_publication_policy")
    if policy != expected_policy(schema_digest):
        fail("lab_service_publication_policy_semantics_invalid")
    policy_digest = canonical_digest(policy)
    if policy_digest != EXPECTED_POLICY_DIGEST:
        fail("lab_service_publication_policy_digest_invalid")
    return policy, policy_digest


def validate_declared_implementation(policy: dict[str, Any]) -> None:
    try:
        content = WORKFLOW_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError("lab_service_publication_workflow_missing") from error
    required = (
        "workflow_dispatch:",
        "expected_main_sha:",
        "release:",
        "packages: write",
        "id-token: write",
        "if: github.ref == 'refs/heads/main'",
        '[[ "$GITHUB_RUN_ATTEMPT" == "1" ]]',
        '[[ "$EXPECTED_MAIN_SHA" == "$GITHUB_SHA" ]]',
        "persist-credentials: false",
        "registry: ghcr.io",
        "push: true",
        "platforms: linux/amd64",
        "type=provenance,mode=max",
        f"type=sbom,generator={SBOM_GENERATOR}",
        "cosign sign --yes",
        "lab_service_publication.py observe",
        "lab-service-publication-observation-",
        policy["services"][0]["imageRepository"],
        policy["services"][1]["imageRepository"],
    )
    if any(fragment not in content for fragment in required):
        fail("lab_service_publication_workflow_contract_invalid")
    forbidden = (
        "pull_request:",
        ":latest",
        "tags: latest",
        "load: true",
        "docker tag ",
        "kubectl ",
        "oc ",
        "helm ",
        "argocd ",
        "harbor",
        "artifactregistry",
    )
    if any(fragment in content.lower() for fragment in forbidden):
        fail("lab_service_publication_workflow_authority_invalid")


def _run(
    arguments: list[str],
    *,
    code: str,
    cwd: Path = ROOT,
    text: bool = False,
) -> bytes | str:
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(code) from error
    return result.stdout


def require_exact_checkout(revision: str) -> None:
    if not REVISION.fullmatch(revision):
        fail("lab_service_publication_revision_invalid")
    head = str(
        _run(
            ["git", "rev-parse", "HEAD"],
            code="lab_service_publication_git_head_failed",
            text=True,
        )
    ).strip()
    if head != revision:
        fail("lab_service_publication_checkout_mismatch")
    _run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        code="lab_service_publication_revision_missing",
    )


def source_tree_digest(revision: str, source_path: str) -> str:
    listing = bytes(
        _run(
            ["git", "ls-tree", "-r", "-z", revision, "--", source_path],
            code="lab_service_publication_source_tree_failed",
        )
    )
    records = [record for record in listing.split(b"\0") if record]
    if not records:
        fail("lab_service_publication_source_tree_empty")
    digest = hashlib.sha256()
    seen: set[str] = set()
    for record in records:
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("lab_service_publication_git_tree_invalid") from error
        if (
            mode not in {"100644", "100755"}
            or object_type != "blob"
            or path in seen
            or not path.startswith(f"{source_path}/")
        ):
            fail("lab_service_publication_git_tree_invalid")
        seen.add(path)
        content = bytes(
            _run(
                ["git", "cat-file", "blob", object_id],
                code="lab_service_publication_git_blob_failed",
            )
        )
        encoded_path = path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def package_metadata(revision: str, service: dict[str, Any]) -> dict[str, Any]:
    raw = bytes(
        _run(
            [
                "git",
                "show",
                f"{revision}:{service['sourcePath']}/pyproject.toml",
            ],
            code="lab_service_publication_pyproject_missing",
        )
    )
    try:
        project = tomllib.loads(raw.decode("utf-8"))["project"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise ValueError("lab_service_publication_pyproject_invalid") from error
    if (
        project.get("name") != service["packageName"]
        or project.get("version") != PACKAGE_VERSION
    ):
        fail(f"lab_service_publication_package_identity_invalid:{service['id']}")
    return {"name": project["name"], "version": project["version"]}


def registry_inspect_raw(reference: str) -> bytes:
    if not reference.startswith("ghcr.io/caglarsubas/"):
        fail("lab_service_publication_registry_reference_invalid")
    return bytes(
        _run(
            ["docker", "buildx", "imagetools", "inspect", "--raw", reference],
            code="lab_service_publication_registry_inspect_failed",
        )
    )


def _digest_descriptor(
    value: Any,
    *,
    keys: set[str],
    code: str,
) -> dict[str, Any]:
    descriptor = strict_keys(value, keys, code)
    if not DIGEST.fullmatch(str(descriptor.get("digest"))):
        fail(f"{code}_digest_invalid")
    size = descriptor.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        fail(f"{code}_size_invalid")
    return descriptor


def verify_oci_image(
    repository: str,
    tag: str,
    digest: str,
    *,
    inspect_raw: InspectRaw = registry_inspect_raw,
) -> dict[str, Any]:
    if not DIGEST.fullmatch(digest):
        fail("lab_service_publication_image_digest_invalid")
    tag_raw = inspect_raw(f"{repository}:{tag}")
    digest_raw = inspect_raw(f"{repository}@{digest}")
    if raw_digest(tag_raw) != digest or raw_digest(digest_raw) != digest:
        fail("lab_service_publication_tag_digest_mismatch")
    index = parse_json_bytes(digest_raw, "lab_service_publication_index")
    strict_keys(
        index,
        {"schemaVersion", "mediaType", "manifests"},
        "lab_service_publication_index_shape_invalid",
    )
    if (
        index["schemaVersion"] != 2
        or index["mediaType"] != INDEX_MEDIA_TYPE
        or not isinstance(index["manifests"], list)
        or len(index["manifests"]) != 2
    ):
        fail("lab_service_publication_index_semantics_invalid")

    image_descriptor: dict[str, Any] | None = None
    attestation_descriptor: dict[str, Any] | None = None
    for candidate in index["manifests"]:
        if isinstance(candidate, dict) and candidate.get("platform") == {
            "architecture": "amd64",
            "os": "linux",
        }:
            if image_descriptor is not None:
                fail("lab_service_publication_image_manifest_duplicate")
            image_descriptor = _digest_descriptor(
                candidate,
                keys={"mediaType", "digest", "size", "platform"},
                code="lab_service_publication_image_descriptor_invalid",
            )
        elif isinstance(candidate, dict) and candidate.get("platform") == {
            "architecture": "unknown",
            "os": "unknown",
        }:
            if attestation_descriptor is not None:
                fail("lab_service_publication_attestation_manifest_duplicate")
            attestation_descriptor = _digest_descriptor(
                candidate,
                keys={
                    "mediaType",
                    "digest",
                    "size",
                    "annotations",
                    "platform",
                },
                code="lab_service_publication_attestation_descriptor_invalid",
            )
        else:
            fail("lab_service_publication_platform_invalid")
    if image_descriptor is None or attestation_descriptor is None:
        fail("lab_service_publication_manifest_set_invalid")
    if (
        image_descriptor["mediaType"] != IMAGE_MANIFEST_MEDIA_TYPE
        or attestation_descriptor["mediaType"] != IMAGE_MANIFEST_MEDIA_TYPE
        or image_descriptor["digest"] == attestation_descriptor["digest"]
    ):
        fail("lab_service_publication_manifest_media_type_invalid")
    if attestation_descriptor["annotations"] != {
        "vnd.docker.reference.digest": image_descriptor["digest"],
        "vnd.docker.reference.type": "attestation-manifest",
    }:
        fail("lab_service_publication_attestation_subject_invalid")

    attestation_raw = inspect_raw(f"{repository}@{attestation_descriptor['digest']}")
    if (
        raw_digest(attestation_raw) != attestation_descriptor["digest"]
        or len(attestation_raw) != attestation_descriptor["size"]
    ):
        fail("lab_service_publication_attestation_digest_mismatch")
    attestation = parse_json_bytes(
        attestation_raw, "lab_service_publication_attestation"
    )
    strict_keys(
        attestation,
        {"schemaVersion", "mediaType", "config", "layers"},
        "lab_service_publication_attestation_shape_invalid",
    )
    if (
        attestation["schemaVersion"] != 2
        or attestation["mediaType"] != IMAGE_MANIFEST_MEDIA_TYPE
        or not isinstance(attestation["layers"], list)
        or len(attestation["layers"]) != 2
    ):
        fail("lab_service_publication_attestation_semantics_invalid")
    config = _digest_descriptor(
        attestation["config"],
        keys={"mediaType", "digest", "size"},
        code="lab_service_publication_attestation_config_invalid",
    )
    if config["mediaType"] != IMAGE_CONFIG_MEDIA_TYPE:
        fail("lab_service_publication_attestation_config_media_type_invalid")

    predicates: dict[str, str] = {}
    for layer_value in attestation["layers"]:
        layer = _digest_descriptor(
            layer_value,
            keys={"mediaType", "digest", "size", "annotations"},
            code="lab_service_publication_attestation_layer_invalid",
        )
        if (
            layer["mediaType"] != ATTESTATION_MEDIA_TYPE
            or layer["size"] > MAX_ATTESTATION_LAYER_BYTES
            or layer["annotations"]
            not in (
                {"in-toto.io/predicate-type": SBOM_PREDICATE},
                {"in-toto.io/predicate-type": PROVENANCE_PREDICATE},
            )
        ):
            fail("lab_service_publication_attestation_layer_semantics_invalid")
        predicate = layer["annotations"]["in-toto.io/predicate-type"]
        if predicate in predicates:
            fail("lab_service_publication_attestation_predicate_duplicate")
        predicates[predicate] = layer["digest"]
    if set(predicates) != {SBOM_PREDICATE, PROVENANCE_PREDICATE}:
        fail("lab_service_publication_attestation_predicates_invalid")
    return {
        "imageManifestDigest": image_descriptor["digest"],
        "attestationManifestDigest": attestation_descriptor["digest"],
        "sbomDigest": predicates[SBOM_PREDICATE],
        "provenanceDigest": predicates[PROVENANCE_PREDICATE],
    }


def cosign_verify(subject: str, identity: str, issuer: str) -> None:
    try:
        result = subprocess.run(
            [
                "cosign",
                "verify",
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                issuer,
                "--output",
                "json",
                subject,
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("lab_service_publication_signature_invalid") from error
    try:
        verification = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("lab_service_publication_signature_output_invalid") from error
    if not isinstance(verification, list) or not verification:
        fail("lab_service_publication_signature_output_invalid")


def validate_report(
    report: dict[str, Any],
    policy: dict[str, Any],
    policy_digest: str,
    *,
    assessed_at: datetime | None = None,
) -> None:
    strict_keys(
        report,
        {
            "schemaVersion",
            "kind",
            "observationId",
            "profileId",
            "targetClass",
            "executionMode",
            "policyDigest",
            "repository",
            "workflow",
            "release",
            "publishedAt",
            "services",
            "claims",
        },
        "lab_service_publication_report_shape_invalid",
    )
    workflow = strict_keys(
        report["workflow"],
        {
            "path",
            "ref",
            "runId",
            "runAttempt",
            "actorId",
            "certificateIdentity",
            "issuer",
        },
        "lab_service_publication_report_workflow_invalid",
    )
    repository = strict_keys(
        report["repository"],
        {"id", "fullName", "revision"},
        "lab_service_publication_report_repository_invalid",
    )
    release = strict_keys(
        report["release"],
        {"name", "packageVersion"},
        "lab_service_publication_report_release_invalid",
    )
    if (
        report["schemaVersion"] != 1
        or report["kind"] != OBSERVATION_KIND
        or report["profileId"] != PROFILE_ID
        or report["targetClass"] != "vendor-reference-lab"
        or report["executionMode"] != "live"
        or report["policyDigest"] != policy_digest
        or repository
        != {
            "id": REPOSITORY_ID,
            "fullName": REPOSITORY,
            "revision": repository["revision"],
        }
        or not REVISION.fullmatch(str(repository["revision"]))
        or workflow
        != {
            "path": WORKFLOW_RELATIVE_PATH,
            "ref": WORKFLOW_REF,
            "runId": workflow["runId"],
            "runAttempt": 1,
            "actorId": workflow["actorId"],
            "certificateIdentity": CERTIFICATE_IDENTITY,
            "issuer": OIDC_ISSUER,
        }
        or not POSITIVE_INTEGER.fullmatch(str(workflow["runId"]))
        or not POSITIVE_INTEGER.fullmatch(str(workflow["actorId"]))
        or report["observationId"] != f"lab-services-publication-{workflow['runId']}.1"
        or not RELEASE.fullmatch(str(release["name"]))
        or release["packageVersion"] != PACKAGE_VERSION
        or report["claims"] != expected_claims()
    ):
        fail("lab_service_publication_report_identity_invalid")
    published_at = parse_time(
        report["publishedAt"], "lab_service_publication_report_time_invalid"
    )
    if assessed_at is not None:
        normalized = assessed_at.astimezone(timezone.utc)
        if published_at > normalized + timedelta(minutes=5):
            fail("lab_service_publication_report_from_future")

    services = report["services"]
    if not isinstance(services, list) or len(services) != 2:
        fail("lab_service_publication_report_services_invalid")
    for actual, expected in zip(services, policy["services"], strict=True):
        strict_keys(
            actual,
            {
                "id",
                "sourcePath",
                "sourceTreeDigest",
                "packageName",
                "packageVersion",
                "image",
                "attestations",
                "signature",
            },
            "lab_service_publication_report_service_shape_invalid",
        )
        image = strict_keys(
            actual["image"],
            {
                "repository",
                "tag",
                "digest",
                "indexMediaType",
                "platform",
                "imageManifestDigest",
                "attestationManifestDigest",
            },
            "lab_service_publication_report_image_shape_invalid",
        )
        attestations = strict_keys(
            actual["attestations"],
            {
                "sbomPredicate",
                "sbomDigest",
                "provenancePredicate",
                "provenanceDigest",
                "sbomGeneratorImage",
                "embeddedSyftVersion",
                "provenanceMode",
            },
            "lab_service_publication_report_attestations_shape_invalid",
        )
        signature = strict_keys(
            actual["signature"],
            {
                "type",
                "subject",
                "certificateIdentity",
                "issuer",
                "verified",
            },
            "lab_service_publication_report_signature_shape_invalid",
        )
        expected_tag = f"{release['name']}-{repository['revision']}"
        if (
            actual["id"] != expected["id"]
            or actual["sourcePath"] != expected["sourcePath"]
            or actual["packageName"] != expected["packageName"]
            or actual["packageVersion"] != PACKAGE_VERSION
            or not DIGEST.fullmatch(str(actual["sourceTreeDigest"]))
            or image
            != {
                "repository": expected["imageRepository"],
                "tag": expected_tag,
                "digest": image["digest"],
                "indexMediaType": INDEX_MEDIA_TYPE,
                "platform": {"os": "linux", "architecture": "amd64"},
                "imageManifestDigest": image["imageManifestDigest"],
                "attestationManifestDigest": image["attestationManifestDigest"],
            }
            or not all(
                DIGEST.fullmatch(str(image[field]))
                for field in (
                    "digest",
                    "imageManifestDigest",
                    "attestationManifestDigest",
                )
            )
            or attestations
            != {
                "sbomPredicate": SBOM_PREDICATE,
                "sbomDigest": attestations["sbomDigest"],
                "provenancePredicate": PROVENANCE_PREDICATE,
                "provenanceDigest": attestations["provenanceDigest"],
                "sbomGeneratorImage": SBOM_GENERATOR,
                "embeddedSyftVersion": "1.42.3",
                "provenanceMode": "max",
            }
            or not DIGEST.fullmatch(str(attestations["sbomDigest"]))
            or not DIGEST.fullmatch(str(attestations["provenanceDigest"]))
            or signature
            != {
                "type": "sigstore-keyless",
                "subject": (f"{expected['imageRepository']}@{image['digest']}"),
                "certificateIdentity": CERTIFICATE_IDENTITY,
                "issuer": OIDC_ISSUER,
                "verified": True,
            }
        ):
            fail(f"lab_service_publication_report_service_invalid:{expected['id']}")
    if (
        len({service["sourceTreeDigest"] for service in services}) != 2
        or len({service["image"]["digest"] for service in services}) != 2
        or len({service["image"]["imageManifestDigest"] for service in services}) != 2
    ):
        fail("lab_service_publication_report_service_substitution")


def build_observation(
    *,
    release: str,
    revision: str,
    run_id: str,
    run_attempt: int,
    actor_id: str,
    published_at: str,
    image_digests: dict[str, str],
    inspect_raw: InspectRaw = registry_inspect_raw,
    verify_signature: VerifySignature = cosign_verify,
) -> dict[str, Any]:
    policy, policy_digest = load_policy()
    validate_declared_implementation(policy)
    require_exact_checkout(revision)
    if (
        not RELEASE.fullmatch(release)
        or run_attempt != 1
        or not POSITIVE_INTEGER.fullmatch(run_id)
        or not POSITIVE_INTEGER.fullmatch(actor_id)
        or set(image_digests) != {service["id"] for service in policy["services"]}
    ):
        fail("lab_service_publication_invocation_invalid")
    parse_time(published_at, "lab_service_publication_time_invalid")

    services: list[dict[str, Any]] = []
    for service in policy["services"]:
        package = package_metadata(revision, service)
        image_digest = image_digests[service["id"]]
        tag = f"{release}-{revision}"
        image = verify_oci_image(
            service["imageRepository"],
            tag,
            image_digest,
            inspect_raw=inspect_raw,
        )
        subject = f"{service['imageRepository']}@{image_digest}"
        verify_signature(subject, CERTIFICATE_IDENTITY, OIDC_ISSUER)
        services.append(
            {
                "id": service["id"],
                "sourcePath": service["sourcePath"],
                "sourceTreeDigest": source_tree_digest(revision, service["sourcePath"]),
                "packageName": package["name"],
                "packageVersion": package["version"],
                "image": {
                    "repository": service["imageRepository"],
                    "tag": tag,
                    "digest": image_digest,
                    "indexMediaType": INDEX_MEDIA_TYPE,
                    "platform": {"os": "linux", "architecture": "amd64"},
                    "imageManifestDigest": image["imageManifestDigest"],
                    "attestationManifestDigest": image["attestationManifestDigest"],
                },
                "attestations": {
                    "sbomPredicate": SBOM_PREDICATE,
                    "sbomDigest": image["sbomDigest"],
                    "provenancePredicate": PROVENANCE_PREDICATE,
                    "provenanceDigest": image["provenanceDigest"],
                    "sbomGeneratorImage": SBOM_GENERATOR,
                    "embeddedSyftVersion": "1.42.3",
                    "provenanceMode": "max",
                },
                "signature": {
                    "type": "sigstore-keyless",
                    "subject": subject,
                    "certificateIdentity": CERTIFICATE_IDENTITY,
                    "issuer": OIDC_ISSUER,
                    "verified": True,
                },
            }
        )
    report = {
        "schemaVersion": 1,
        "kind": OBSERVATION_KIND,
        "observationId": f"lab-services-publication-{run_id}.1",
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab",
        "executionMode": "live",
        "policyDigest": policy_digest,
        "repository": {
            "id": REPOSITORY_ID,
            "fullName": REPOSITORY,
            "revision": revision,
        },
        "workflow": {
            "path": WORKFLOW_RELATIVE_PATH,
            "ref": WORKFLOW_REF,
            "runId": run_id,
            "runAttempt": run_attempt,
            "actorId": actor_id,
            "certificateIdentity": CERTIFICATE_IDENTITY,
            "issuer": OIDC_ISSUER,
        },
        "release": {"name": release, "packageVersion": PACKAGE_VERSION},
        "publishedAt": published_at,
        "services": services,
        "claims": expected_claims(),
    }
    validate_report(report, policy, policy_digest)
    return report


def write_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ValueError("lab_service_publication_output_create_failed") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value))
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or (
        os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        fail("lab_service_publication_output_permissions_invalid")


def command_validate_policy() -> None:
    policy, digest = load_policy()
    validate_declared_implementation(policy)
    print(f"lab_service_publication_policy_valid digest={digest}")


def command_observe(args: argparse.Namespace) -> None:
    report = build_observation(
        release=args.release,
        revision=args.repository_revision,
        run_id=args.workflow_run_id,
        run_attempt=args.workflow_run_attempt,
        actor_id=args.actor_id,
        published_at=args.published_at,
        image_digests={
            "release-validation-receiver": args.receiver_digest,
            "synthetic-tenant-kit": args.synthetic_digest,
        },
    )
    write_create_only(args.output.resolve(), report)
    print(
        "lab_service_publication_observed "
        f"observationId={report['observationId']} "
        f"digest={canonical_digest(report)}"
    )


def command_verify(args: argparse.Namespace) -> None:
    policy, policy_digest = load_policy()
    _, report = read_json(args.report.resolve(), "lab_service_publication_observation")
    assessed_at = (
        parse_time(args.at, "lab_service_publication_assessed_at_invalid")
        if args.at
        else datetime.now(timezone.utc)
    )
    validate_report(report, policy, policy_digest, assessed_at=assessed_at)
    print(
        "lab_service_publication_observation_valid "
        f"observationId={report['observationId']} "
        f"digest={canonical_digest(report)}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-policy")

    observe = commands.add_parser("observe")
    observe.add_argument("--release", required=True)
    observe.add_argument("--repository-revision", required=True)
    observe.add_argument("--workflow-run-id", required=True)
    observe.add_argument("--workflow-run-attempt", type=int, required=True)
    observe.add_argument("--actor-id", required=True)
    observe.add_argument("--published-at", required=True)
    observe.add_argument("--receiver-digest", required=True)
    observe.add_argument("--synthetic-digest", required=True)
    observe.add_argument("--output", type=Path, required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    verify.add_argument("--at")

    args = parser.parse_args(argv)
    if args.command == "validate-policy":
        command_validate_policy()
    elif args.command == "observe":
        command_observe(args)
    else:
        command_verify(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
