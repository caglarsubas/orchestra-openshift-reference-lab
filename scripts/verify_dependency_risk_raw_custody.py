#!/usr/bin/env python3
"""Verify generation-pinned dependency-risk raw custody and build a report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

try:
    from scripts.dependency_risk_collection_execution import (
        load_contract as load_collection_contract,
        validate_authority as validate_collection_authority,
    )
    from scripts.dependency_risk_contract import blob_digest
    from scripts.dependency_risk_custody_verification import (
        load_contract,
        validate_authority,
    )
    from scripts.validate_dependency_risk_collection_custody import (
        validate_statement,
    )
    from scripts.validate_repository import DIGEST, canonical_digest
    from scripts.verify_dependency_risk_collection import (
        verify_collection_attestation,
    )
except ModuleNotFoundError:
    from dependency_risk_collection_execution import (
        load_contract as load_collection_contract,
        validate_authority as validate_collection_authority,
    )
    from dependency_risk_contract import blob_digest
    from dependency_risk_custody_verification import (
        load_contract,
        validate_authority,
    )
    from validate_dependency_risk_collection_custody import validate_statement
    from validate_repository import DIGEST, canonical_digest
    from verify_dependency_risk_collection import verify_collection_attestation


PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
EVIDENCE_ID = re.compile(r"^orchestra-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$")
VERIFICATION_ID = re.compile(
    r"^orchestra-dependency-risk-custody-verification-[a-z0-9][a-z0-9.-]+$"
)
BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
BASE64_CRC32C = re.compile(r"^[A-Za-z0-9+/]{6}==$")
BASE64_MD5 = re.compile(r"^[A-Za-z0-9+/]{22}==$")
COLLECTION_KEY = re.compile(
    r"^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/"
    r"europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/"
    r"dependency-risk-collection-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
VERIFICATION_KEY = re.compile(
    r"^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/"
    r"europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/"
    r"dependency-risk-custody-verification-signing/cryptoKeyVersions/"
    r"[1-9][0-9]*$"
)
RAW_OBJECTS = {
    "dependency-risk-raw-collection.tar.gz": "raw-archive",
    "dependency-risk-raw-custody-public-key.pem": ("collection-signing-public-key"),
    "dependency-risk-raw-custody-statement.json": "custody-statement",
    "dependency-risk-raw-custody-signature.sigstore.json": "completion-marker",
}
MAX_ARCHIVE_BYTES = 12 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_ARCHIVE_MEMBER_BYTES = 4 * 1024 * 1024 * 1024


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(code)
    return value


def parse_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        fail(code)
    return parsed


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ValueError("dependency_risk_custody_artifact_read_failed") from error
    return f"sha256:{digest.hexdigest()}"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail("dependency_risk_custody_json_duplicate_key")
        value[key] = item
    return value


def load_json_object(path: Path, code: str) -> tuple[dict[str, Any], bytes]:
    try:
        content = path.read_bytes()
        value = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(code) from error
    if not isinstance(value, dict):
        fail(code)
    return value, content


def validate_inventory(
    value: dict[str, Any], evidence_id: str
) -> tuple[str, str, list[dict[str, Any]]]:
    strict_keys(
        value,
        {"schemaVersion", "bucket", "prefix", "objects"},
        "dependency_risk_custody_inventory_keys_invalid",
    )
    bucket = value["bucket"]
    prefix = value["prefix"]
    expected_prefix = f"dependency-risk/v1/{PROFILE_ID}/{evidence_id}"
    if (
        value["schemaVersion"] != 1
        or not isinstance(bucket, str)
        or not BUCKET.fullmatch(bucket)
        or prefix != expected_prefix
        or not isinstance(value["objects"], list)
        or len(value["objects"]) != len(RAW_OBJECTS)
    ):
        fail("dependency_risk_custody_inventory_identity_invalid")

    expected_names = {f"{prefix}/{name}" for name in RAW_OBJECTS}
    objects: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in value["objects"]:
        item = strict_keys(
            raw,
            {
                "name",
                "generation",
                "metageneration",
                "sizeBytes",
                "crc32c",
                "md5Hash",
                "etag",
                "timeCreated",
                "updated",
            },
            "dependency_risk_custody_inventory_object_invalid",
        )
        name = item["name"]
        if (
            not isinstance(name, str)
            or name not in expected_names
            or name in seen
            or not isinstance(item["generation"], str)
            or not POSITIVE_INTEGER.fullmatch(item["generation"])
            or not isinstance(item["metageneration"], str)
            or not POSITIVE_INTEGER.fullmatch(item["metageneration"])
            or not isinstance(item["sizeBytes"], int)
            or isinstance(item["sizeBytes"], bool)
            or item["sizeBytes"] <= 0
            or not isinstance(item["crc32c"], str)
            or not BASE64_CRC32C.fullmatch(item["crc32c"])
            or (
                item["md5Hash"] is not None
                and (
                    not isinstance(item["md5Hash"], str)
                    or not BASE64_MD5.fullmatch(item["md5Hash"])
                )
            )
            or not isinstance(item["etag"], str)
            or not item["etag"]
        ):
            fail("dependency_risk_custody_inventory_object_invalid")
        parse_timestamp(
            item["timeCreated"], "dependency_risk_custody_inventory_time_invalid"
        )
        parse_timestamp(
            item["updated"], "dependency_risk_custody_inventory_time_invalid"
        )
        seen.add(name)
        objects.append(item)
    if seen != expected_names:
        fail("dependency_risk_custody_inventory_completeness_invalid")

    marker_name = f"{prefix}/dependency-risk-raw-custody-signature.sigstore.json"
    marker = next(item for item in objects if item["name"] == marker_name)
    marker_time = parse_timestamp(
        marker["timeCreated"], "dependency_risk_custody_marker_time_invalid"
    )
    if any(
        item["name"] != marker_name
        and parse_timestamp(
            item["timeCreated"], "dependency_risk_custody_inventory_time_invalid"
        )
        >= marker_time
        for item in objects
    ):
        fail("dependency_risk_custody_completion_marker_order_invalid")
    return bucket, prefix, sorted(objects, key=lambda item: item["name"])


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


def safe_extract_collection(archive: Path, destination: Path) -> Path:
    if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE_BYTES:
        fail("dependency_risk_custody_archive_size_invalid")
    try:
        handle = tarfile.open(archive, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("dependency_risk_custody_archive_invalid") from error

    with handle:
        members = handle.getmembers()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            fail("dependency_risk_custody_archive_member_count_invalid")
        seen: set[PurePosixPath] = set()
        top_levels: set[str] = set()
        total_size = 0
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or not path.parts
                or any(part in {"", ".", ".."} for part in path.parts)
                or len(member.name.encode("utf-8")) > 1024
                or path in seen
                or not (member.isdir() or member.isfile())
                or member.issym()
                or member.islnk()
                or member.isdev()
                or member.isfifo()
            ):
                fail("dependency_risk_custody_archive_member_invalid")
            if (
                member.size < 0
                or member.size > MAX_ARCHIVE_MEMBER_BYTES
                or total_size + member.size > MAX_ARCHIVE_BYTES
            ):
                fail("dependency_risk_custody_archive_expansion_invalid")
            seen.add(path)
            top_levels.add(path.parts[0])
            total_size += member.size
        if len(top_levels) != 1:
            fail("dependency_risk_custody_archive_root_invalid")
        top_level = next(iter(top_levels))
        if not re.fullmatch(r"dependency-risk-collection-[A-Za-z0-9._-]+", top_level):
            fail("dependency_risk_custody_archive_root_invalid")

        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
        for member in members:
            path = PurePosixPath(member.name)
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = handle.extractfile(member)
            if source is None:
                fail("dependency_risk_custody_archive_member_invalid")
            written = 0
            try:
                with source, target.open("xb") as output:
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > member.size:
                            fail("dependency_risk_custody_archive_member_size_invalid")
                        output.write(chunk)
            except OSError as error:
                raise ValueError(
                    "dependency_risk_custody_archive_extract_failed"
                ) from error
            if written != member.size:
                fail("dependency_risk_custody_archive_member_size_invalid")

    collection_dir = destination / top_level
    manifest = collection_dir / "dependency-risk-scan-manifest.json"
    if not collection_dir.is_dir() or not manifest.is_file():
        fail("dependency_risk_custody_archive_manifest_missing")
    return manifest


def expected_report_bindings(
    authority: dict[str, Any], authority_digest: str
) -> dict[str, Any]:
    bindings = authority["bindings"]
    return {
        "topologyDigest": bindings["topologyDigest"],
        "dependencyAdmissionDigest": bindings["dependencyAdmissionDigest"],
        "releaseSetDigest": bindings["releaseSetDigest"],
        "sourceVerificationDigest": bindings["sourceVerificationDigest"],
        "riskPolicyDigest": bindings["riskPolicyDigest"],
        "preflightAuthorityDigest": bindings["preflightAuthorityDigest"],
        "collectionExecutionAuthorityDigest": bindings[
            "collectionExecutionAuthorityDigest"
        ],
        "rawCustodySchemaDigest": bindings["rawCustodySchemaDigest"],
        "custodyVerificationAuthorityDigest": authority_digest,
        "custodyVerificationSchemaDigest": bindings["custodyVerificationSchemaDigest"],
        "verifierModuleDigest": bindings["verifierModuleDigest"],
        "verificationScriptDigest": bindings["verificationScriptDigest"],
        "reportValidatorDigest": bindings["reportValidatorDigest"],
    }


def validate_report(value: dict[str, Any], authority: dict[str, Any]) -> None:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "targetClass",
            "executionMode",
            "verificationId",
            "evidenceId",
            "bindings",
            "rawCustody",
            "collection",
            "verifier",
            "claims",
        },
        "dependency_risk_custody_report_keys_invalid",
    )
    evidence_id = value["evidenceId"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "orchestra.dependency-risk.custody-verification.v1"
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or not isinstance(value["verificationId"], str)
        or not VERIFICATION_ID.fullmatch(value["verificationId"])
        or not isinstance(evidence_id, str)
        or not EVIDENCE_ID.fullmatch(evidence_id)
    ):
        fail("dependency_risk_custody_report_identity_invalid")
    authority_digest = canonical_digest(authority)
    if value["bindings"] != expected_report_bindings(authority, authority_digest):
        fail("dependency_risk_custody_report_bindings_invalid")

    raw_custody = strict_keys(
        value["rawCustody"],
        {
            "bucket",
            "prefix",
            "managedFolder",
            "objectCount",
            "objects",
            "completionMarkerObject",
            "completionMarkerGeneration",
            "custodyStatementDigest",
            "custodySignatureBundleDigest",
            "collectionSigningPublicKeyDigest",
            "collectionSigningKeyVersionResource",
        },
        "dependency_risk_custody_report_raw_invalid",
    )
    bucket, prefix, inventory_objects = validate_inventory(
        {
            "schemaVersion": 1,
            "bucket": raw_custody["bucket"],
            "prefix": raw_custody["prefix"],
            "objects": [
                {
                    key: item[key]
                    for key in (
                        "name",
                        "generation",
                        "metageneration",
                        "sizeBytes",
                        "crc32c",
                        "md5Hash",
                        "etag",
                        "timeCreated",
                        "updated",
                    )
                }
                for item in raw_custody.get("objects", [])
                if isinstance(item, dict)
            ],
        },
        evidence_id,
    )
    if (
        raw_custody["managedFolder"] != "dependency-risk/"
        or raw_custody["objectCount"] != 4
        or not isinstance(raw_custody["objects"], list)
        or len(raw_custody["objects"]) != 4
        or raw_custody["completionMarkerObject"]
        != "dependency-risk-raw-custody-signature.sigstore.json"
        or not isinstance(raw_custody["completionMarkerGeneration"], str)
        or not POSITIVE_INTEGER.fullmatch(raw_custody["completionMarkerGeneration"])
        or not COLLECTION_KEY.fullmatch(
            str(raw_custody["collectionSigningKeyVersionResource"])
        )
    ):
        fail("dependency_risk_custody_report_raw_invalid")
    for key in (
        "custodyStatementDigest",
        "custodySignatureBundleDigest",
        "collectionSigningPublicKeyDigest",
    ):
        require_digest(raw_custody[key], "dependency_risk_custody_report_raw_invalid")

    expected_by_name = {item["name"]: item for item in inventory_objects}
    for item in raw_custody["objects"]:
        strict_keys(
            item,
            {
                "role",
                "name",
                "generation",
                "metageneration",
                "sizeBytes",
                "crc32c",
                "md5Hash",
                "etag",
                "contentDigest",
                "timeCreated",
                "updated",
            },
            "dependency_risk_custody_report_object_invalid",
        )
        basename = item["name"].removeprefix(f"{prefix}/")
        if (
            item["name"] not in expected_by_name
            or item["role"] != RAW_OBJECTS.get(basename)
            or any(
                item[key] != expected_by_name[item["name"]][key]
                for key in expected_by_name[item["name"]]
            )
        ):
            fail("dependency_risk_custody_report_object_invalid")
        require_digest(
            item["contentDigest"], "dependency_risk_custody_report_object_invalid"
        )
    marker = next(
        item for item in raw_custody["objects"] if item["role"] == "completion-marker"
    )
    if marker["generation"] != raw_custody["completionMarkerGeneration"]:
        fail("dependency_risk_custody_report_completion_marker_invalid")

    collection = strict_keys(
        value["collection"],
        {
            "rawArchiveDigest",
            "manifestDigest",
            "collectionAttestationDigest",
            "collectionSignatureBundleDigest",
            "safeArchiveVerified",
            "collectionVerified",
        },
        "dependency_risk_custody_report_collection_invalid",
    )
    for key in (
        "rawArchiveDigest",
        "manifestDigest",
        "collectionAttestationDigest",
        "collectionSignatureBundleDigest",
    ):
        require_digest(
            collection[key], "dependency_risk_custody_report_collection_invalid"
        )
    if (
        collection["safeArchiveVerified"] is not True
        or collection["collectionVerified"] is not True
    ):
        fail("dependency_risk_custody_report_collection_invalid")

    verifier = strict_keys(
        value["verifier"],
        {
            "executionClass",
            "actorIdentityDigest",
            "startedAt",
            "completedAt",
            "verificationSigningKeyVersionResource",
            "verificationSigningPublicKeyDigest",
        },
        "dependency_risk_custody_report_verifier_invalid",
    )
    started = parse_timestamp(
        verifier["startedAt"], "dependency_risk_custody_report_verifier_invalid"
    )
    completed = parse_timestamp(
        verifier["completedAt"], "dependency_risk_custody_report_verifier_invalid"
    )
    require_digest(
        verifier["actorIdentityDigest"],
        "dependency_risk_custody_report_verifier_invalid",
    )
    require_digest(
        verifier["verificationSigningPublicKeyDigest"],
        "dependency_risk_custody_report_verifier_invalid",
    )
    if (
        verifier["executionClass"] != "signed-certification-runner"
        or completed < started
        or not VERIFICATION_KEY.fullmatch(
            str(verifier["verificationSigningKeyVersionResource"])
        )
    ):
        fail("dependency_risk_custody_report_verifier_invalid")
    if value["claims"] != {
        "custodyVerified": True,
        "objectGenerationsRecorded": True,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("dependency_risk_custody_report_claim_invalid")
    if bucket != raw_custody["bucket"]:
        fail("dependency_risk_custody_report_raw_invalid")


def verify_and_build_report(
    *,
    inventory_path: Path,
    download_dir: Path,
    collection_kms_public_key: Path,
    collection_signing_key: str,
    expected_collection_public_key_digest: str,
    verification_signing_key: str,
    verification_signing_public_key: Path,
    expected_verification_public_key_digest: str,
    verification_id: str,
    evidence_id: str,
    actor_identity_digest: str,
    started_at: str,
    output: Path,
    cosign: str = "cosign",
) -> dict[str, Any]:
    authority, release_set, risk_policy = load_contract()
    authority_digest = validate_authority(authority, release_set, risk_policy)
    if (
        not VERIFICATION_ID.fullmatch(verification_id)
        or not EVIDENCE_ID.fullmatch(evidence_id)
        or not COLLECTION_KEY.fullmatch(collection_signing_key)
        or not VERIFICATION_KEY.fullmatch(verification_signing_key)
    ):
        fail("dependency_risk_custody_verification_identity_invalid")
    require_digest(
        expected_collection_public_key_digest,
        "dependency_risk_custody_collection_public_key_digest_invalid",
    )
    require_digest(
        expected_verification_public_key_digest,
        "dependency_risk_custody_verification_public_key_digest_invalid",
    )
    require_digest(
        actor_identity_digest, "dependency_risk_custody_actor_identity_invalid"
    )
    started = parse_timestamp(
        started_at, "dependency_risk_custody_verification_time_invalid"
    )
    if output.exists() or not output.parent.is_dir():
        fail("dependency_risk_custody_report_output_invalid")

    inventory, _ = load_json_object(
        inventory_path, "dependency_risk_custody_inventory_json_invalid"
    )
    bucket, prefix, inventory_objects = validate_inventory(inventory, evidence_id)
    inventory_by_basename = {
        item["name"].removeprefix(f"{prefix}/"): item for item in inventory_objects
    }
    downloaded: dict[str, Path] = {}
    content_digests: dict[str, str] = {}
    for name in RAW_OBJECTS:
        path = (download_dir / name).resolve()
        if path.parent != download_dir.resolve() or not path.is_file():
            fail("dependency_risk_custody_download_missing")
        if path.stat().st_size != inventory_by_basename[name]["sizeBytes"]:
            fail("dependency_risk_custody_download_size_mismatch")
        downloaded[name] = path
        content_digests[name] = file_digest(path)

    statement, statement_bytes = load_json_object(
        downloaded["dependency-risk-raw-custody-statement.json"],
        "dependency_risk_custody_statement_json_invalid",
    )
    collection_authority, collection_release_set, collection_risk_policy = (
        load_collection_contract()
    )
    validate_collection_authority(
        collection_authority,
        collection_release_set,
        collection_risk_policy,
    )
    validate_statement(statement, collection_authority)
    if (
        statement["evidenceId"] != evidence_id
        or statement["storage"]["bucket"] != bucket
        or statement["storage"]["prefix"] != prefix
        or statement["collection"]["rawArchiveDigest"]
        != content_digests["dependency-risk-raw-collection.tar.gz"]
        or statement["publisher"]["signingPublicKeyDigest"]
        != expected_collection_public_key_digest
    ):
        fail("dependency_risk_custody_statement_binding_invalid")

    raw_public_key = downloaded["dependency-risk-raw-custody-public-key.pem"]
    try:
        collection_kms_bytes = collection_kms_public_key.read_bytes()
        raw_public_key_bytes = raw_public_key.read_bytes()
    except OSError as error:
        raise ValueError("dependency_risk_custody_public_key_read_failed") from error
    if (
        file_digest(raw_public_key) != expected_collection_public_key_digest
        or file_digest(collection_kms_public_key)
        != expected_collection_public_key_digest
        or raw_public_key_bytes != collection_kms_bytes
    ):
        fail("dependency_risk_custody_collection_public_key_mismatch")
    if (
        file_digest(verification_signing_public_key)
        != expected_verification_public_key_digest
    ):
        fail("dependency_risk_custody_verification_public_key_mismatch")

    run_cosign(
        cosign,
        [
            "verify-blob",
            "--bundle",
            str(downloaded["dependency-risk-raw-custody-signature.sigstore.json"]),
            "--key",
            str(raw_public_key),
            str(downloaded["dependency-risk-raw-custody-statement.json"]),
        ],
        "dependency_risk_custody_signature_verification_failed",
    )

    with tempfile.TemporaryDirectory(
        prefix="dependency-risk-custody-extract.", dir=download_dir.parent
    ) as temporary:
        manifest_path = safe_extract_collection(
            downloaded["dependency-risk-raw-collection.tar.gz"],
            Path(temporary) / "extracted",
        )
        manifest, manifest_bytes = load_json_object(
            manifest_path, "dependency_risk_custody_manifest_json_invalid"
        )
        if (
            blob_digest(manifest_bytes) != statement["collection"]["manifestDigest"]
            or manifest.get("evidenceId") != evidence_id
            or not isinstance(manifest.get("collection"), dict)
            or manifest["collection"].get("collectionAttestationDigest")
            != statement["collection"]["collectionAttestationDigest"]
            or manifest["collection"].get("collectionSignatureBundleDigest")
            != statement["collection"]["collectionSignatureBundleDigest"]
        ):
            fail("dependency_risk_custody_manifest_binding_invalid")
        archived_public_key = manifest_path.parent / "collection-signing-public-key.pem"
        if (
            not archived_public_key.is_file()
            or archived_public_key.read_bytes() != raw_public_key_bytes
        ):
            fail("dependency_risk_custody_archive_public_key_mismatch")
        attestation_digest = verify_collection_attestation(
            manifest, manifest_path.parent, cosign=cosign
        )
        if attestation_digest != statement["collection"]["collectionAttestationDigest"]:
            fail("dependency_risk_custody_collection_verification_mismatch")
        manifest_digest = blob_digest(manifest_bytes)

    completed_at = utc_now()
    completed = parse_timestamp(
        completed_at, "dependency_risk_custody_verification_time_invalid"
    )
    published = parse_timestamp(
        statement["publisher"]["publishedAt"],
        "dependency_risk_custody_statement_publish_time_invalid",
    )
    latest_object = max(
        parse_timestamp(
            item["updated"], "dependency_risk_custody_inventory_time_invalid"
        )
        for item in inventory_objects
    )
    if completed < started or completed < published or completed < latest_object:
        fail("dependency_risk_custody_verification_time_invalid")

    report_objects = []
    for item in inventory_objects:
        basename = item["name"].removeprefix(f"{prefix}/")
        report_objects.append(
            {
                "role": RAW_OBJECTS[basename],
                **item,
                "contentDigest": content_digests[basename],
            }
        )
    marker = next(
        item for item in report_objects if item["role"] == "completion-marker"
    )
    report = {
        "schemaVersion": 1,
        "kind": "orchestra.dependency-risk.custody-verification.v1",
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab",
        "executionMode": "live",
        "verificationId": verification_id,
        "evidenceId": evidence_id,
        "bindings": expected_report_bindings(authority, authority_digest),
        "rawCustody": {
            "bucket": bucket,
            "prefix": prefix,
            "managedFolder": "dependency-risk/",
            "objectCount": 4,
            "objects": report_objects,
            "completionMarkerObject": (
                "dependency-risk-raw-custody-signature.sigstore.json"
            ),
            "completionMarkerGeneration": marker["generation"],
            "custodyStatementDigest": blob_digest(statement_bytes),
            "custodySignatureBundleDigest": content_digests[
                "dependency-risk-raw-custody-signature.sigstore.json"
            ],
            "collectionSigningPublicKeyDigest": (expected_collection_public_key_digest),
            "collectionSigningKeyVersionResource": collection_signing_key,
        },
        "collection": {
            "rawArchiveDigest": content_digests[
                "dependency-risk-raw-collection.tar.gz"
            ],
            "manifestDigest": manifest_digest,
            "collectionAttestationDigest": statement["collection"][
                "collectionAttestationDigest"
            ],
            "collectionSignatureBundleDigest": statement["collection"][
                "collectionSignatureBundleDigest"
            ],
            "safeArchiveVerified": True,
            "collectionVerified": True,
        },
        "verifier": {
            "executionClass": "signed-certification-runner",
            "actorIdentityDigest": actor_identity_digest,
            "startedAt": started_at,
            "completedAt": completed_at,
            "verificationSigningKeyVersionResource": verification_signing_key,
            "verificationSigningPublicKeyDigest": (
                expected_verification_public_key_digest
            ),
        },
        "claims": {
            "custodyVerified": True,
            "objectGenerationsRecorded": True,
            "sourceAdmissionAuthorized": False,
            "mirrorAuthorization": False,
            "activationAuthorized": False,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
        },
    }
    validate_report(report, authority)
    encoded = (
        json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except OSError as error:
        raise ValueError("dependency_risk_custody_report_write_failed") from error
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--download-dir", type=Path, required=True)
    parser.add_argument("--collection-kms-public-key", type=Path, required=True)
    parser.add_argument("--collection-signing-key", required=True)
    parser.add_argument(
        "--expected-collection-signing-public-key-digest", required=True
    )
    parser.add_argument("--verification-signing-key", required=True)
    parser.add_argument("--verification-signing-public-key", type=Path, required=True)
    parser.add_argument(
        "--expected-verification-signing-public-key-digest", required=True
    )
    parser.add_argument("--verification-id", required=True)
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--actor-identity-digest", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)
    report = verify_and_build_report(
        inventory_path=args.inventory.resolve(),
        download_dir=args.download_dir.resolve(),
        collection_kms_public_key=args.collection_kms_public_key.resolve(),
        collection_signing_key=args.collection_signing_key,
        expected_collection_public_key_digest=(
            args.expected_collection_signing_public_key_digest
        ),
        verification_signing_key=args.verification_signing_key,
        verification_signing_public_key=(
            args.verification_signing_public_key.resolve()
        ),
        expected_verification_public_key_digest=(
            args.expected_verification_signing_public_key_digest
        ),
        verification_id=args.verification_id,
        evidence_id=args.evidence_id,
        actor_identity_digest=args.actor_identity_digest,
        started_at=args.started_at,
        output=args.output.resolve(),
        cosign=args.cosign,
    )
    print(
        "dependency_risk_raw_custody_verified "
        f"verificationId={report['verificationId']} "
        f"evidenceId={report['evidenceId']} custodyVerified=true "
        "objectGenerationsRecorded=true sourceAdmission=false "
        "mirrorAuthorization=false activation=false campaignEvidence=false "
        "referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
