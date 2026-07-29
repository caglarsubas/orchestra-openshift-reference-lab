#!/usr/bin/env python3
"""Build and verify fail-closed live production model custody records."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.production_model_artifact_custody import (
        CUSTODY_CLAIMS,
        CUSTODY_CONTROLS,
        PROFILE_ID,
        digest_without_field,
        expected_artifacts,
        load_contract_inputs,
        parse_utc,
        validate_custody_record,
    )
    from scripts.production_model_artifact_intake import validate_report
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from production_model_artifact_custody import (
        CUSTODY_CLAIMS,
        CUSTODY_CONTROLS,
        PROFILE_ID,
        digest_without_field,
        expected_artifacts,
        load_contract_inputs,
        parse_utc,
        validate_custody_record,
    )
    from production_model_artifact_intake import validate_report
    from validate_repository import ROOT, canonical_digest, load_json


UPLOAD_SCHEMA_PATH = (
    ROOT / "schemas" / "production-model-artifact-upload-receipt-v1.schema.json"
)
RECORD_ID = re.compile(r"^production-model-custody-[a-z0-9][a-z0-9._-]{7,127}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
GENERATION = re.compile(r"^[1-9][0-9]*$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
CRC32C = re.compile(r"^[A-Za-z0-9+/]{6}==$")
KMS_VERSION = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/"
    r"keyRings/orchestra-reference-evidence/cryptoKeys/"
    r"production-model-artifact-custody/cryptoKeyVersions/[1-9][0-9]*$"
)
UPLOAD_KIND = "orchestra.openshift.production-model-artifact-upload-receipt.v1"
UPLOAD_CONTROLS = {
    "sourceObservationVerified": True,
    "createOnlyUpload": True,
    "completionMarkerUploadedLast": True,
    "modelBytesInReceipt": False,
    "secretValuesInReceipt": False,
}
UPLOAD_CLAIMS = {
    "artifactCopyCompleted": True,
    "artifactCustodyVerified": False,
    "licenseApproved": False,
    "sourceAdmissionAuthorized": False,
    "dependencyAdmissionAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEvidence": False,
    "referenceProfileVerified": False,
    "customerCertified": False,
    "redHatCertified": False,
    "contractualSla": False,
}
MAX_CONTROL_OBJECT_BYTES = 65536


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def write_create_only(path: Path, value: dict[str, Any]) -> None:
    data = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    if len(data) > MAX_CONTROL_OBJECT_BYTES:
        fail("production_model_custody_live_output_too_large")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = path.open("xb")
    try:
        descriptor.write(data)
        descriptor.flush()
    finally:
        descriptor.close()
    path.chmod(0o600)


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def load_inputs() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    candidate, source_policy, policy, custody_schema, review_schema = (
        load_contract_inputs()
    )
    return (
        candidate,
        source_policy,
        policy,
        custody_schema,
        review_schema,
        load_json(UPLOAD_SCHEMA_PATH),
    )


def validate_source_observation(
    value: dict[str, Any],
    candidate: dict[str, Any],
    source_policy: dict[str, Any],
    *,
    now: datetime | None = None,
) -> str:
    try:
        from scripts.production_model_artifact_intake import SCHEMA_PATH
    except ModuleNotFoundError:
        from production_model_artifact_intake import SCHEMA_PATH

    digest = validate_report(
        value,
        source_policy,
        candidate,
        load_json(SCHEMA_PATH),
        now=now,
    )
    if value["executionMode"] != "local-file-inspection" or value["decision"] != {
        "status": "SOURCE_BYTES_OBSERVED",
        "reasonCodes": [],
    }:
        fail("production_model_custody_source_observation_not_verified")
    return digest


def expected_upload_artifacts(
    candidate: dict[str, Any], prefix: str
) -> list[dict[str, Any]]:
    return [
        {
            "artifactId": artifact["artifactId"],
            "filename": artifact["filename"],
            "expectedDigest": artifact["digest"],
            "expectedSizeBytes": artifact["sizeBytes"],
            "objectName": f"{prefix}/{artifact['filename']}",
        }
        for artifact in expected_artifacts(candidate)
    ]


def validate_upload_receipt(
    value: dict[str, Any],
    source_observation: dict[str, Any],
    candidate: dict[str, Any],
    source_policy: dict[str, Any],
    policy: dict[str, Any],
    upload_schema: dict[str, Any],
    *,
    now: datetime | None = None,
) -> str:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "recordId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "storage",
            "artifacts",
            "actor",
            "timestamps",
            "controls",
            "claims",
            "receiptDigest",
        },
        "production_model_upload_receipt_keys_invalid",
    )
    record_id = value["recordId"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != UPLOAD_KIND
        or not isinstance(record_id, str)
        or not RECORD_ID.fullmatch(record_id)
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live-upload"
    ):
        fail("production_model_upload_receipt_identity_invalid")
    source_digest = validate_source_observation(
        source_observation, candidate, source_policy, now=now
    )
    if value["bindings"] != {
        "candidateId": candidate["candidateId"],
        "candidateDigest": candidate["candidateDigest"],
        "sourceObservationId": source_observation["observationId"],
        "sourceObservationDigest": source_digest,
        "sourceObservationObservedAt": source_observation["observedAt"],
        "custodyPolicyId": policy["policyId"],
        "custodyPolicyDigest": policy["policyDigest"],
        "uploadReceiptSchemaDigest": canonical_digest(upload_schema),
    }:
        fail("production_model_upload_receipt_bindings_invalid")
    storage = exact_keys(
        value["storage"],
        {
            "bucket",
            "prefix",
            "createOnlyGenerationPrecondition",
            "completionMarker",
        },
        "production_model_upload_receipt_storage_keys_invalid",
    )
    expected_prefix = f"production-model-artifacts/v1/{PROFILE_ID}/{record_id}"
    if (
        not isinstance(storage["bucket"], str)
        or not BUCKET.fullmatch(storage["bucket"])
        or storage["prefix"] != expected_prefix
        or storage["createOnlyGenerationPrecondition"] != 0
        or storage["completionMarker"]
        != "production-model-artifact-upload-receipt.json"
    ):
        fail("production_model_upload_receipt_storage_invalid")
    if value["artifacts"] != expected_upload_artifacts(candidate, expected_prefix):
        fail("production_model_upload_receipt_artifacts_invalid")
    actor = exact_keys(
        value["actor"],
        {"identityDigest", "serviceAccountId"},
        "production_model_upload_receipt_actor_keys_invalid",
    )
    if (
        not isinstance(actor["identityDigest"], str)
        or not DIGEST.fullmatch(actor["identityDigest"])
        or actor["serviceAccountId"] != "orchestra-model-custody-writer"
    ):
        fail("production_model_upload_receipt_actor_invalid")
    timestamps = exact_keys(
        value["timestamps"],
        {"copyStartedAt", "copyCompletedAt"},
        "production_model_upload_receipt_timestamps_keys_invalid",
    )
    copy_started = parse_utc(
        timestamps["copyStartedAt"],
        "production_model_upload_receipt_copy_started_invalid",
    )
    copy_completed = parse_utc(
        timestamps["copyCompletedAt"],
        "production_model_upload_receipt_copy_completed_invalid",
    )
    observed_at = parse_utc(
        source_observation["observedAt"],
        "production_model_upload_receipt_observed_at_invalid",
    )
    if (
        observed_at > copy_started
        or copy_started > copy_completed
        or copy_started - observed_at > timedelta(hours=24)
    ):
        fail("production_model_upload_receipt_timestamp_order_invalid")
    if value["controls"] != UPLOAD_CONTROLS:
        fail("production_model_upload_receipt_controls_invalid")
    if value["claims"] != UPLOAD_CLAIMS:
        fail("production_model_upload_receipt_claims_invalid")
    digest = digest_without_field(value, "receiptDigest")
    if value["receiptDigest"] != digest:
        fail("production_model_upload_receipt_digest_invalid")
    return digest


def build_upload_receipt(args: argparse.Namespace) -> dict[str, Any]:
    candidate, source_policy, policy, _, _, upload_schema = load_inputs()
    source = load_json(args.source_observation)
    validate_source_observation(source, candidate, source_policy)
    if not RECORD_ID.fullmatch(args.record_id):
        fail("production_model_upload_receipt_record_id_invalid")
    if not BUCKET.fullmatch(args.bucket):
        fail("production_model_upload_receipt_bucket_invalid")
    if not DIGEST.fullmatch(args.uploader_identity_digest):
        fail("production_model_upload_receipt_actor_invalid")
    copy_started = parse_utc(
        args.copy_started_at,
        "production_model_upload_receipt_copy_started_invalid",
    )
    copy_completed = parse_utc(
        args.copy_completed_at,
        "production_model_upload_receipt_copy_completed_invalid",
    )
    prefix = f"production-model-artifacts/v1/{PROFILE_ID}/{args.record_id}"
    receipt = {
        "schemaVersion": 1,
        "kind": UPLOAD_KIND,
        "recordId": args.record_id,
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab",
        "executionMode": "live-upload",
        "bindings": {
            "candidateId": candidate["candidateId"],
            "candidateDigest": candidate["candidateDigest"],
            "sourceObservationId": source["observationId"],
            "sourceObservationDigest": source["reportDigest"],
            "sourceObservationObservedAt": source["observedAt"],
            "custodyPolicyId": policy["policyId"],
            "custodyPolicyDigest": policy["policyDigest"],
            "uploadReceiptSchemaDigest": canonical_digest(upload_schema),
        },
        "storage": {
            "bucket": args.bucket,
            "prefix": prefix,
            "createOnlyGenerationPrecondition": 0,
            "completionMarker": "production-model-artifact-upload-receipt.json",
        },
        "artifacts": expected_upload_artifacts(candidate, prefix),
        "actor": {
            "identityDigest": args.uploader_identity_digest,
            "serviceAccountId": "orchestra-model-custody-writer",
        },
        "timestamps": {
            "copyStartedAt": utc_text(copy_started),
            "copyCompletedAt": utc_text(copy_completed),
        },
        "controls": copy.deepcopy(UPLOAD_CONTROLS),
        "claims": copy.deepcopy(UPLOAD_CLAIMS),
        "receiptDigest": "sha256:" + "0" * 64,
    }
    receipt["receiptDigest"] = digest_without_field(receipt, "receiptDigest")
    validate_upload_receipt(
        receipt,
        source,
        candidate,
        source_policy,
        policy,
        upload_schema,
    )
    return receipt


def inventory_objects(
    inventory: dict[str, Any],
    *,
    bucket: str,
    prefix: str,
) -> dict[str, dict[str, Any]]:
    exact_keys(
        inventory,
        {"schemaVersion", "bucket", "prefix", "objects"},
        "production_model_custody_inventory_keys_invalid",
    )
    if (
        inventory["schemaVersion"] != 1
        or inventory["bucket"] != bucket
        or inventory["prefix"] != prefix
        or not isinstance(inventory["objects"], list)
        or len(inventory["objects"]) != 4
    ):
        fail("production_model_custody_inventory_identity_invalid")
    result: dict[str, dict[str, Any]] = {}
    for item in inventory["objects"]:
        exact_keys(
            item,
            {
                "name",
                "generation",
                "metageneration",
                "sizeBytes",
                "crc32c",
                "kmsKeyName",
                "eventBasedHold",
                "temporaryHold",
                "timeCreated",
                "updated",
            },
            "production_model_custody_inventory_object_keys_invalid",
        )
        name = item["name"]
        if (
            not isinstance(name, str)
            or not name.startswith(prefix + "/")
            or name in result
            or not isinstance(item["generation"], str)
            or not GENERATION.fullmatch(item["generation"])
            or not isinstance(item["metageneration"], str)
            or not GENERATION.fullmatch(item["metageneration"])
            or not isinstance(item["sizeBytes"], int)
            or item["sizeBytes"] < 1
            or not isinstance(item["crc32c"], str)
            or not CRC32C.fullmatch(item["crc32c"])
            or not isinstance(item["kmsKeyName"], str)
            or not KMS_VERSION.fullmatch(item["kmsKeyName"])
            or item["eventBasedHold"] is not True
            or item["temporaryHold"] is not False
        ):
            fail("production_model_custody_inventory_object_invalid")
        parse_utc(item["timeCreated"], "production_model_custody_created_invalid")
        parse_utc(item["updated"], "production_model_custody_updated_invalid")
        result[name] = item
    return result


def file_digest(path: Path, expected_size: int) -> str:
    metadata = path.stat()
    if not path.is_file() or metadata.st_size != expected_size:
        fail("production_model_custody_download_size_invalid")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            if total > expected_size:
                fail("production_model_custody_download_size_invalid")
            digest.update(chunk)
    if total != expected_size:
        fail("production_model_custody_download_size_invalid")
    return f"sha256:{digest.hexdigest()}"


def build_custody_record(args: argparse.Namespace) -> dict[str, Any]:
    candidate, source_policy, policy, custody_schema, _, upload_schema = load_inputs()
    source = load_json(args.source_observation)
    receipt = load_json(args.upload_receipt)
    receipt_digest = validate_upload_receipt(
        receipt,
        source,
        candidate,
        source_policy,
        policy,
        upload_schema,
    )
    if (
        receipt["recordId"] != args.record_id
        or receipt["storage"]["bucket"] != args.bucket
    ):
        fail("production_model_custody_receipt_selection_invalid")
    if (
        not DIGEST.fullmatch(args.verifier_identity_digest)
        or args.verifier_identity_digest == receipt["actor"]["identityDigest"]
    ):
        fail("production_model_custody_verifier_identity_invalid")
    prefix = receipt["storage"]["prefix"]
    objects = inventory_objects(
        load_json(args.inventory), bucket=args.bucket, prefix=prefix
    )
    control_names = {
        f"{prefix}/production-model-artifact-intake-observation.json",
        f"{prefix}/production-model-artifact-upload-receipt.json",
    }
    expected_names = control_names | {
        artifact["objectName"] for artifact in receipt["artifacts"]
    }
    if set(objects) != expected_names:
        fail("production_model_custody_inventory_members_invalid")
    for name in control_names:
        if objects[name]["sizeBytes"] > MAX_CONTROL_OBJECT_BYTES:
            fail("production_model_custody_control_object_too_large")
    verified_at = datetime.now(timezone.utc).replace(microsecond=0)
    artifacts: list[dict[str, Any]] = []
    for expected in expected_artifacts(candidate):
        name = f"{prefix}/{expected['filename']}"
        metadata = objects[name]
        if metadata["sizeBytes"] != expected["sizeBytes"]:
            fail("production_model_custody_inventory_size_invalid")
        downloaded = args.download_dir / expected["filename"]
        observed_digest = file_digest(downloaded, expected["sizeBytes"])
        if observed_digest != expected["digest"]:
            fail("production_model_custody_download_digest_invalid")
        artifacts.append(
            {
                "artifactId": expected["artifactId"],
                "serviceId": expected["serviceId"],
                "filename": expected["filename"],
                "revision": expected["revision"],
                "expectedDigest": expected["digest"],
                "expectedSizeBytes": expected["sizeBytes"],
                "object": {
                    "name": name,
                    "generation": metadata["generation"],
                    "metageneration": metadata["metageneration"],
                    "sizeBytes": metadata["sizeBytes"],
                    "crc32c": metadata["crc32c"],
                    "contentDigest": observed_digest,
                    "kmsKeyVersion": metadata["kmsKeyName"],
                    "eventBasedHold": metadata["eventBasedHold"],
                    "temporaryHold": metadata["temporaryHold"],
                    "timeCreated": metadata["timeCreated"],
                    "updated": metadata["updated"],
                },
                "verification": {
                    "generationPinnedRead": True,
                    "metagenerationPinnedRead": True,
                    "exactSizeMatched": True,
                    "expectedDigestMatched": True,
                    "objectMetadataStable": True,
                    "verifiedAt": utc_text(verified_at),
                },
            }
        )
    record = {
        "schemaVersion": 1,
        "kind": ("orchestra.openshift.production-model-artifact-custody-record.v1"),
        "recordId": args.record_id,
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab",
        "executionMode": "live",
        "bindings": {
            "candidateId": candidate["candidateId"],
            "candidateDigest": candidate["candidateDigest"],
            "sourceIntakePolicyDigest": source_policy["policyDigest"],
            "sourceObservationId": source["observationId"],
            "sourceObservationDigest": source["reportDigest"],
            "sourceObservationObservedAt": source["observedAt"],
            "custodyPolicyId": policy["policyId"],
            "custodyPolicyDigest": policy["policyDigest"],
            "custodyRecordSchemaDigest": canonical_digest(custody_schema),
        },
        "storage": {
            "projectPlane": "services-evidence",
            "bucket": args.bucket,
            "managedFolder": "production-model-artifacts/",
            "prefix": prefix,
            "cmekRequired": True,
            "uniformBucketLevelAccess": True,
            "publicAccessPrevention": "enforced",
            "versioningEnabled": True,
            "objectRetentionEnabled": True,
            "createOnlyGenerationPrecondition": 0,
        },
        "publication": {
            "bucket": args.bucket,
            "managedFolder": "production-model-custody/",
            "prefix": (f"production-model-custody/v1/{PROFILE_ID}/{args.record_id}"),
            "recordObject": "production-model-artifact-custody-record.json",
            "publicKeyObject": "production-model-artifact-custody-public-key.pem",
            "completionMarker": (
                "production-model-artifact-custody-signature.sigstore.json"
            ),
            "createOnlyGenerationPrecondition": 0,
            "completionMarkerUploadedLast": True,
        },
        "artifacts": artifacts,
        "actors": {
            "uploaderIdentityDigest": receipt["actor"]["identityDigest"],
            "verifierIdentityDigest": args.verifier_identity_digest,
            "identitiesDistinct": True,
            "uploaderServiceAccountId": "orchestra-model-custody-writer",
            "verifierServiceAccountId": "orchestra-model-custody-verify",
        },
        "timestamps": {
            "copyStartedAt": receipt["timestamps"]["copyStartedAt"],
            "copyCompletedAt": receipt["timestamps"]["copyCompletedAt"],
            "verifiedAt": utc_text(verified_at),
        },
        "controls": copy.deepcopy(CUSTODY_CONTROLS),
        "claims": copy.deepcopy(CUSTODY_CLAIMS),
        "recordDigest": "sha256:" + "0" * 64,
    }
    record["recordDigest"] = digest_without_field(record, "recordDigest")
    validate_custody_record(record, policy, candidate, custody_schema)
    if receipt_digest != receipt["receiptDigest"]:
        fail("production_model_upload_receipt_digest_invalid")
    return record


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    receipt = commands.add_parser("build-upload-receipt")
    receipt.add_argument("--source-observation", type=Path, required=True)
    receipt.add_argument("--record-id", required=True)
    receipt.add_argument("--bucket", required=True)
    receipt.add_argument("--uploader-identity-digest", required=True)
    receipt.add_argument("--copy-started-at", required=True)
    receipt.add_argument("--copy-completed-at", required=True)
    receipt.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("validate-upload-receipt")
    verify.add_argument("--source-observation", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    custody = commands.add_parser("build-custody-record")
    custody.add_argument("--source-observation", type=Path, required=True)
    custody.add_argument("--upload-receipt", type=Path, required=True)
    custody.add_argument("--inventory", type=Path, required=True)
    custody.add_argument("--download-dir", type=Path, required=True)
    custody.add_argument("--record-id", required=True)
    custody.add_argument("--bucket", required=True)
    custody.add_argument("--verifier-identity-digest", required=True)
    custody.add_argument("--output", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    if args.command == "build-upload-receipt":
        receipt = build_upload_receipt(args)
        write_create_only(args.output, receipt)
        print(
            "productionModelArtifactUploadReceiptCreated=true "
            f"recordId={receipt['recordId']} receiptDigest={receipt['receiptDigest']} "
            "artifactCustodyVerified=false admissionAuthorized=false"
        )
        return 0
    candidate, source_policy, policy, _, _, upload_schema = load_inputs()
    if args.command == "validate-upload-receipt":
        digest = validate_upload_receipt(
            load_json(args.receipt),
            load_json(args.source_observation),
            candidate,
            source_policy,
            policy,
            upload_schema,
        )
        print(
            "productionModelArtifactUploadReceiptValid=true "
            f"receiptDigest={digest} artifactCustodyVerified=false "
            "admissionAuthorized=false"
        )
        return 0
    record = build_custody_record(args)
    write_create_only(args.output, record)
    print(
        "productionModelArtifactCustodyRecordCreated=true "
        f"recordId={record['recordId']} recordDigest={record['recordDigest']} "
        "artifactCustodyVerified=true licenseApproved=false "
        "admissionAuthorized=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
