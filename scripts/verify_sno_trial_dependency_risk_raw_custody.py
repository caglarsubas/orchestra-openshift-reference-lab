#!/usr/bin/env python3
"""Verify generation-pinned SNO dependency-risk custody and build a report."""

from __future__ import annotations

import argparse
import json
import os
import re
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.build_sno_trial_dependency_risk_evidence import build_evidence
    from scripts.sno_trial_dependency_risk import (
        load_inputs as load_risk_inputs,
        validate_risk_evidence,
    )
    from scripts.sno_trial_dependency_risk_custody import (
        BUCKET,
        COLLECTION_KEY,
        EVIDENCE_ID,
        POSITIVE_INTEGER,
        PROFILE_ID,
        RAW_OBJECTS,
        VERIFICATION_ID,
        VERIFICATION_KEY,
        expected_report_bindings,
        fail,
        load_policy,
        parse_timestamp,
        require_digest,
        strict_keys,
        validate_policy,
        validate_raw_statement,
        validate_report,
    )
    from scripts.validate_repository import canonical_digest
    from scripts.verify_dependency_risk_raw_custody import (
        file_digest,
        load_json_object,
        run_cosign,
    )
except ModuleNotFoundError:
    from build_sno_trial_dependency_risk_evidence import build_evidence
    from sno_trial_dependency_risk import (
        load_inputs as load_risk_inputs,
        validate_risk_evidence,
    )
    from sno_trial_dependency_risk_custody import (
        BUCKET,
        COLLECTION_KEY,
        EVIDENCE_ID,
        POSITIVE_INTEGER,
        PROFILE_ID,
        RAW_OBJECTS,
        VERIFICATION_ID,
        VERIFICATION_KEY,
        expected_report_bindings,
        fail,
        load_policy,
        parse_timestamp,
        require_digest,
        strict_keys,
        validate_policy,
        validate_raw_statement,
        validate_report,
    )
    from validate_repository import canonical_digest
    from verify_dependency_risk_raw_custody import (
        file_digest,
        load_json_object,
        run_cosign,
    )


BASE64_CRC32C = re.compile(r"^[A-Za-z0-9+/]{6}==$")
BASE64_MD5 = re.compile(r"^[A-Za-z0-9+/]{22}==$")
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 64
MAX_ARCHIVE_MEMBER_BYTES = 4 * 1024 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def validate_inventory(
    value: dict[str, Any], evidence_id: str
) -> tuple[str, str, list[dict[str, Any]]]:
    strict_keys(
        value,
        {"schemaVersion", "bucket", "prefix", "objects"},
        "sno_dependency_risk_custody_inventory_keys_invalid",
    )
    bucket = value["bucket"]
    prefix = value["prefix"]
    expected_prefix = (
        f"dependency-risk/sno-trial/v1/{PROFILE_ID}/{evidence_id}"
    )
    if (
        value["schemaVersion"] != 1
        or not isinstance(bucket, str)
        or not BUCKET.fullmatch(bucket)
        or prefix != expected_prefix
        or not isinstance(value["objects"], list)
        or len(value["objects"]) != len(RAW_OBJECTS)
    ):
        fail("sno_dependency_risk_custody_inventory_identity_invalid")
    expected_names = {f"{prefix}/{name}" for name in RAW_OBJECTS}
    seen: set[str] = set()
    objects: list[dict[str, Any]] = []
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
            "sno_dependency_risk_custody_inventory_object_invalid",
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
            fail("sno_dependency_risk_custody_inventory_object_invalid")
        parse_timestamp(
            item["timeCreated"],
            "sno_dependency_risk_custody_inventory_time_invalid",
        )
        parse_timestamp(
            item["updated"],
            "sno_dependency_risk_custody_inventory_time_invalid",
        )
        seen.add(name)
        objects.append(item)
    if seen != expected_names:
        fail("sno_dependency_risk_custody_inventory_completeness_invalid")
    marker_name = (
        f"{prefix}/sno-dependency-risk-raw-custody-signature.sigstore.json"
    )
    marker = next(item for item in objects if item["name"] == marker_name)
    marker_time = parse_timestamp(
        marker["timeCreated"],
        "sno_dependency_risk_custody_marker_time_invalid",
    )
    if any(
        item["name"] != marker_name
        and parse_timestamp(
            item["timeCreated"],
            "sno_dependency_risk_custody_inventory_time_invalid",
        )
        >= marker_time
        for item in objects
    ):
        fail("sno_dependency_risk_custody_completion_marker_order_invalid")
    return bucket, prefix, sorted(objects, key=lambda item: item["name"])


def safe_extract_collection(archive: Path, destination: Path) -> Path:
    if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE_BYTES:
        fail("sno_dependency_risk_custody_archive_size_invalid")
    try:
        handle = tarfile.open(archive, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("sno_dependency_risk_custody_archive_invalid") from error
    with handle:
        members = handle.getmembers()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            fail("sno_dependency_risk_custody_archive_member_count_invalid")
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
                fail("sno_dependency_risk_custody_archive_member_invalid")
            if (
                member.size < 0
                or member.size > MAX_ARCHIVE_MEMBER_BYTES
                or total_size + member.size > MAX_ARCHIVE_BYTES
            ):
                fail("sno_dependency_risk_custody_archive_expansion_invalid")
            seen.add(path)
            top_levels.add(path.parts[0])
            total_size += member.size
        if len(top_levels) != 1:
            fail("sno_dependency_risk_custody_archive_root_invalid")
        top_level = next(iter(top_levels))
        if not re.fullmatch(
            r"sno-dependency-risk-collection-[A-Za-z0-9._-]+", top_level
        ):
            fail("sno_dependency_risk_custody_archive_root_invalid")
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
                fail("sno_dependency_risk_custody_archive_member_invalid")
            written = 0
            try:
                with source, target.open("xb") as output:
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > member.size:
                            fail(
                                "sno_dependency_risk_custody_archive_member_size_invalid"
                            )
                        output.write(chunk)
            except OSError as error:
                raise ValueError(
                    "sno_dependency_risk_custody_archive_extract_failed"
                ) from error
            if written != member.size:
                fail("sno_dependency_risk_custody_archive_member_size_invalid")
    collection_dir = destination / top_level
    required = (
        "collection-manifest.json",
        "risk-evidence.json",
        "collection-statement.json",
        "collection-statement.sigstore.json",
        "collection-signing-public-key.pem",
    )
    if not collection_dir.is_dir() or any(
        not (collection_dir / name).is_file() for name in required
    ):
        fail("sno_dependency_risk_custody_archive_contract_missing")
    return collection_dir


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
    policy = load_policy()
    validate_policy(policy)
    if (
        not VERIFICATION_ID.fullmatch(verification_id)
        or not EVIDENCE_ID.fullmatch(evidence_id)
        or not COLLECTION_KEY.fullmatch(collection_signing_key)
        or not VERIFICATION_KEY.fullmatch(verification_signing_key)
    ):
        fail("sno_dependency_risk_custody_verification_identity_invalid")
    require_digest(
        expected_collection_public_key_digest,
        "sno_dependency_risk_custody_collection_public_key_digest_invalid",
    )
    require_digest(
        expected_verification_public_key_digest,
        "sno_dependency_risk_custody_verification_public_key_digest_invalid",
    )
    require_digest(
        actor_identity_digest,
        "sno_dependency_risk_custody_actor_identity_invalid",
    )
    started = parse_timestamp(
        started_at,
        "sno_dependency_risk_custody_verification_time_invalid",
    )
    if output.exists() or not output.parent.is_dir():
        fail("sno_dependency_risk_custody_report_output_invalid")
    inventory, _ = load_json_object(
        inventory_path,
        "sno_dependency_risk_custody_inventory_json_invalid",
    )
    bucket, prefix, inventory_objects = validate_inventory(inventory, evidence_id)
    inventory_by_basename = {
        item["name"].removeprefix(f"{prefix}/"): item
        for item in inventory_objects
    }
    downloaded: dict[str, Path] = {}
    content_digests: dict[str, str] = {}
    for name in RAW_OBJECTS:
        path = (download_dir / name).resolve()
        if path.parent != download_dir.resolve() or not path.is_file():
            fail("sno_dependency_risk_custody_download_missing")
        if path.stat().st_size != inventory_by_basename[name]["sizeBytes"]:
            fail("sno_dependency_risk_custody_download_size_mismatch")
        downloaded[name] = path
        content_digests[name] = file_digest(path)
    statement, statement_bytes = load_json_object(
        downloaded["sno-dependency-risk-raw-custody-statement.json"],
        "sno_dependency_risk_custody_statement_json_invalid",
    )
    _, _, risk_policy = load_risk_inputs()
    validate_raw_statement(statement, policy, risk_policy)
    if (
        statement["evidenceId"] != evidence_id
        or statement["storage"]["bucket"] != bucket
        or statement["storage"]["prefix"] != prefix
        or statement["collection"]["rawArchiveDigest"]
        != content_digests["sno-dependency-risk-raw-collection.tar.gz"]
        or statement["publisher"]["signingPublicKeyDigest"]
        != expected_collection_public_key_digest
    ):
        fail("sno_dependency_risk_custody_statement_binding_invalid")
    raw_public_key = downloaded[
        "sno-dependency-risk-raw-custody-public-key.pem"
    ]
    try:
        kms_public_key_bytes = collection_kms_public_key.read_bytes()
        raw_public_key_bytes = raw_public_key.read_bytes()
    except OSError as error:
        raise ValueError(
            "sno_dependency_risk_custody_public_key_read_failed"
        ) from error
    if (
        file_digest(raw_public_key) != expected_collection_public_key_digest
        or file_digest(collection_kms_public_key)
        != expected_collection_public_key_digest
        or raw_public_key_bytes != kms_public_key_bytes
        or file_digest(verification_signing_public_key)
        != expected_verification_public_key_digest
    ):
        fail("sno_dependency_risk_custody_public_key_mismatch")
    run_cosign(
        cosign,
        [
            "verify-blob",
            "--bundle",
            str(
                downloaded[
                    "sno-dependency-risk-raw-custody-signature.sigstore.json"
                ]
            ),
            "--key",
            str(raw_public_key),
            str(
                downloaded[
                    "sno-dependency-risk-raw-custody-statement.json"
                ]
            ),
        ],
        "sno_dependency_risk_custody_signature_verification_failed",
    )
    with tempfile.TemporaryDirectory(
        prefix="sno-dependency-risk-custody-extract.",
        dir=download_dir.parent,
    ) as temporary:
        collection_dir = safe_extract_collection(
            downloaded["sno-dependency-risk-raw-collection.tar.gz"],
            Path(temporary) / "extracted",
        )
        manifest_path = collection_dir / "collection-manifest.json"
        evidence_path = collection_dir / "risk-evidence.json"
        collection_statement_path = collection_dir / "collection-statement.json"
        collection_signature_path = (
            collection_dir / "collection-statement.sigstore.json"
        )
        archived_public_key = collection_dir / "collection-signing-public-key.pem"
        manifest, manifest_bytes = load_json_object(
            manifest_path,
            "sno_dependency_risk_custody_manifest_json_invalid",
        )
        evidence, evidence_bytes = load_json_object(
            evidence_path,
            "sno_dependency_risk_custody_evidence_json_invalid",
        )
        collection_statement, collection_statement_bytes = load_json_object(
            collection_statement_path,
            "sno_dependency_risk_custody_collection_statement_json_invalid",
        )
        if (
            file_digest(manifest_path)
            != statement["collection"]["manifestDigest"]
            or file_digest(evidence_path)
            != statement["collection"]["riskEvidenceDigest"]
            or file_digest(collection_statement_path)
            != statement["collection"]["collectionStatementDigest"]
            or file_digest(collection_signature_path)
            != statement["collection"]["collectionSignatureBundleDigest"]
            or manifest.get("evidenceId") != evidence_id
            or evidence.get("evidenceId") != evidence_id
            or collection_statement.get("evidenceId") != evidence_id
            or archived_public_key.read_bytes() != raw_public_key_bytes
        ):
            fail("sno_dependency_risk_custody_archive_binding_invalid")
        run_cosign(
            cosign,
            [
                "verify-blob",
                "--bundle",
                str(collection_signature_path),
                "--key",
                str(archived_public_key),
                str(collection_statement_path),
            ],
            "sno_dependency_risk_collection_statement_verification_failed",
        )
        if (
            evidence["collection"]["collectionStatementDigest"]
            != file_digest(collection_statement_path)
            or evidence["collection"]["collectionSignatureBundleDigest"]
            != file_digest(collection_signature_path)
        ):
            fail("sno_dependency_risk_custody_evidence_binding_invalid")
        artifacts, release_set, _ = load_risk_inputs()
        validate_risk_evidence(evidence, artifacts, release_set)
        recomputed = build_evidence(
            manifest,
            collection_dir,
            artifacts,
            release_set,
        )
        if canonical_digest(recomputed) != canonical_digest(evidence):
            fail("sno_dependency_risk_custody_evidence_recompute_invalid")
        manifest_digest = file_digest(manifest_path)
        risk_evidence_digest = file_digest(evidence_path)
        risk_evidence_canonical_digest = canonical_digest(evidence)
        collection_statement_digest = file_digest(collection_statement_path)
        collection_signature_digest = file_digest(collection_signature_path)
        del manifest_bytes, evidence_bytes, collection_statement_bytes
    completed_at = utc_now()
    completed = parse_timestamp(
        completed_at,
        "sno_dependency_risk_custody_verification_time_invalid",
    )
    published = parse_timestamp(
        statement["publisher"]["publishedAt"],
        "sno_dependency_risk_custody_statement_publish_time_invalid",
    )
    latest_object = max(
        parse_timestamp(
            item["updated"],
            "sno_dependency_risk_custody_inventory_time_invalid",
        )
        for item in inventory_objects
    )
    if completed < started or completed < published or completed < latest_object:
        fail("sno_dependency_risk_custody_verification_time_invalid")
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
        "kind": (
            "orchestra.openshift.sno-trial-dependency-risk."
            "custody-verification.v1"
        ),
        "profileId": PROFILE_ID,
        "targetClass": "engineering-trial",
        "executionMode": "live",
        "verificationId": verification_id,
        "evidenceId": evidence_id,
        "bindings": expected_report_bindings(policy),
        "rawCustody": {
            "bucket": bucket,
            "prefix": prefix,
            "managedFolder": "dependency-risk/",
            "objectCount": 4,
            "objects": report_objects,
            "completionMarkerObject": (
                "sno-dependency-risk-raw-custody-signature.sigstore.json"
            ),
            "completionMarkerGeneration": marker["generation"],
            "custodyStatementDigest": file_digest(
                downloaded[
                    "sno-dependency-risk-raw-custody-statement.json"
                ]
            ),
            "custodySignatureBundleDigest": content_digests[
                "sno-dependency-risk-raw-custody-signature.sigstore.json"
            ],
            "collectionSigningPublicKeyDigest": (
                expected_collection_public_key_digest
            ),
            "collectionSigningKeyVersionResource": collection_signing_key,
        },
        "collection": {
            "rawArchiveDigest": content_digests[
                "sno-dependency-risk-raw-collection.tar.gz"
            ],
            "manifestDigest": manifest_digest,
            "riskEvidenceDigest": risk_evidence_digest,
            "riskEvidenceCanonicalDigest": risk_evidence_canonical_digest,
            "collectionStatementDigest": collection_statement_digest,
            "collectionSignatureBundleDigest": collection_signature_digest,
            "safeArchiveVerified": True,
            "collectionStatementVerified": True,
            "riskEvidenceRecomputed": True,
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
            "deploymentAuthorized": False,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
        },
    }
    validate_report(report, policy)
    encoded = (
        json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except OSError as error:
        raise ValueError(
            "sno_dependency_risk_custody_report_write_failed"
        ) from error
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--download-dir", type=Path, required=True)
    parser.add_argument("--collection-kms-public-key", type=Path, required=True)
    parser.add_argument("--collection-signing-key", required=True)
    parser.add_argument(
        "--expected-collection-signing-public-key-digest",
        required=True,
    )
    parser.add_argument("--verification-signing-key", required=True)
    parser.add_argument(
        "--verification-signing-public-key",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--expected-verification-signing-public-key-digest",
        required=True,
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
        "sno_dependency_risk_raw_custody_verified "
        f"verificationId={report['verificationId']} "
        f"evidenceId={report['evidenceId']} custodyVerified=true "
        "objectGenerationsRecorded=true sourceAdmission=false "
        "mirrorAuthorization=false activation=false deployment=false "
        "campaignEvidence=false referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
