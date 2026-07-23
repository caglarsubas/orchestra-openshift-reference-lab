#!/usr/bin/env python3
"""Verify immutable foundation plan custody before any Terraform apply."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.foundation_apply_execution import (
        PROFILE_ID,
        load_contract,
        validate_authority,
    )
    from scripts.foundation_plan_package import (
        PLAN_ID,
        file_digest,
        load_json_object,
        run_cosign,
        strict_keys,
        validate_statement,
    )
    from scripts.foundation_plan_summary import summarize_changes, validate_summary
    from scripts.prerequisite_observation import parse_utc
    from scripts.validate_repository import DIGEST
except ModuleNotFoundError:
    from foundation_apply_execution import PROFILE_ID, load_contract, validate_authority
    from foundation_plan_package import (
        PLAN_ID,
        file_digest,
        load_json_object,
        run_cosign,
        strict_keys,
        validate_statement,
    )
    from foundation_plan_summary import summarize_changes, validate_summary
    from prerequisite_observation import parse_utc
    from validate_repository import DIGEST


SHA = re.compile(r"^[a-f0-9]{40}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
BASE64_CRC32C = re.compile(r"^[A-Za-z0-9+/]{6}==$")
BASE64_MD5 = re.compile(r"^[A-Za-z0-9+/]{22}==$")
PLAN_OBJECTS = {
    "foundation.tfplan": "saved-plan",
    "foundation-plan-summary.json": "plan-summary",
    "foundation-plan-package-public-key.pem": "plan-signing-public-key",
    "foundation-plan-package-statement.json": "plan-package-statement",
    "foundation-plan-package-signature.sigstore.json": "completion-marker",
}
MAX_OBJECT_BYTES = {
    "foundation.tfplan": 1024 * 1024 * 1024,
    "foundation-plan-summary.json": 16 * 1024 * 1024,
    "foundation-plan-package-public-key.pem": 64 * 1024,
    "foundation-plan-package-statement.json": 1024 * 1024,
    "foundation-plan-package-signature.sigstore.json": 4 * 1024 * 1024,
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(code)
    return value


def validate_inventory(
    value: dict[str, Any], source_revision: str, plan_id: str
) -> tuple[str, str, list[dict[str, Any]]]:
    strict_keys(
        value,
        {"schemaVersion", "bucket", "prefix", "objects"},
        "foundation_plan_inventory_keys_invalid",
    )
    if not SHA.fullmatch(source_revision) or not PLAN_ID.fullmatch(plan_id):
        fail("foundation_plan_inventory_identity_invalid")
    bucket = value["bucket"]
    prefix = value["prefix"]
    expected_prefix = (
        f"foundation-plans/v1/{PROFILE_ID}/{source_revision}/{plan_id}"
    )
    if (
        value["schemaVersion"] != 1
        or not isinstance(bucket, str)
        or not BUCKET.fullmatch(bucket)
        or prefix != expected_prefix
        or not isinstance(value["objects"], list)
        or len(value["objects"]) != len(PLAN_OBJECTS)
    ):
        fail("foundation_plan_inventory_identity_invalid")
    expected_names = {f"{prefix}/{name}" for name in PLAN_OBJECTS}
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
            "foundation_plan_inventory_object_invalid",
        )
        name = item["name"]
        basename = name.removeprefix(f"{prefix}/") if isinstance(name, str) else ""
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
            or item["sizeBytes"] > MAX_OBJECT_BYTES.get(basename, 0)
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
            fail("foundation_plan_inventory_object_invalid")
        created = parse_utc(
            item["timeCreated"], "foundation_plan_inventory_time_invalid"
        )
        updated = parse_utc(item["updated"], "foundation_plan_inventory_time_invalid")
        if updated < created:
            fail("foundation_plan_inventory_time_invalid")
        seen.add(name)
        objects.append(item)
    if seen != expected_names:
        fail("foundation_plan_inventory_completeness_invalid")
    marker_name = (
        f"{prefix}/foundation-plan-package-signature.sigstore.json"
    )
    marker = next(item for item in objects if item["name"] == marker_name)
    marker_time = parse_utc(
        marker["timeCreated"], "foundation_plan_completion_marker_time_invalid"
    )
    if any(
        item["name"] != marker_name
        and parse_utc(
            item["timeCreated"], "foundation_plan_inventory_time_invalid"
        )
        >= marker_time
        for item in objects
    ):
        fail("foundation_plan_completion_marker_order_invalid")
    return bucket, prefix, sorted(objects, key=lambda item: item["name"])


def verify_package(
    *,
    inventory_path: Path,
    download_dir: Path,
    plan_json_path: Path,
    source_revision: str,
    plan_id: str,
    expected_statement_digest: str,
    expected_public_key_digest: str,
    verified_at: str,
    output: Path,
    cosign: str = "cosign",
) -> dict[str, Any]:
    authority, release_set, policy = load_contract()
    validate_authority(authority, release_set, policy)
    require_digest(
        expected_statement_digest,
        "foundation_plan_expected_statement_digest_invalid",
    )
    require_digest(
        expected_public_key_digest,
        "foundation_plan_expected_public_key_digest_invalid",
    )
    verified_time = parse_utc(verified_at, "foundation_plan_verified_at_invalid")
    if output.exists() or not output.parent.is_dir():
        fail("foundation_plan_verified_output_invalid")
    inventory, _ = load_json_object(
        inventory_path, "foundation_plan_inventory_json_invalid"
    )
    bucket, prefix, objects = validate_inventory(
        inventory, source_revision, plan_id
    )
    inventory_by_basename = {
        item["name"].removeprefix(f"{prefix}/"): item for item in objects
    }
    downloaded: dict[str, Path] = {}
    content_digests: dict[str, str] = {}
    for name in PLAN_OBJECTS:
        path = (download_dir / name).resolve()
        if path.parent != download_dir.resolve() or not path.is_file():
            fail("foundation_plan_download_missing")
        if path.stat().st_size != inventory_by_basename[name]["sizeBytes"]:
            fail("foundation_plan_download_size_mismatch")
        downloaded[name] = path
        content_digests[name] = file_digest(path)

    statement_path = downloaded["foundation-plan-package-statement.json"]
    statement, _ = load_json_object(
        statement_path, "foundation_plan_package_json_invalid"
    )
    statement_digest = file_digest(statement_path)
    validate_statement(statement, authority)
    if (
        statement_digest != expected_statement_digest
        or statement["planId"] != plan_id
        or statement["source"]["revision"] != source_revision
        or statement["package"]["bucket"] != bucket
        or statement["package"]["prefix"] != prefix
    ):
        fail("foundation_plan_package_expected_binding_invalid")
    signing_time = parse_utc(
        statement["signer"]["signedAt"], "foundation_plan_package_signer_invalid"
    )
    if (
        signing_time > verified_time
        or verified_time - signing_time > timedelta(hours=24)
    ):
        fail("foundation_plan_package_stale")
    public_key = downloaded["foundation-plan-package-public-key.pem"]
    if (
        file_digest(public_key) != expected_public_key_digest
        or statement["signer"]["publicKeyDigest"] != expected_public_key_digest
    ):
        fail("foundation_plan_package_public_key_mismatch")
    run_cosign(
        cosign,
        [
            "verify-blob",
            "--bundle",
            str(
                downloaded[
                    "foundation-plan-package-signature.sigstore.json"
                ]
            ),
            "--key",
            str(public_key),
            str(statement_path),
        ],
        "foundation_plan_package_signature_verification_failed",
    )

    plan = downloaded["foundation.tfplan"]
    summary_path = downloaded["foundation-plan-summary.json"]
    summary, _ = load_json_object(
        summary_path, "foundation_plan_package_summary_json_invalid"
    )
    summary_canonical_digest = validate_summary(summary)
    if (
        content_digests["foundation.tfplan"]
        != statement["package"]["planDigest"]
        or plan.stat().st_size != statement["package"]["planSizeBytes"]
        or content_digests["foundation-plan-summary.json"]
        != statement["package"]["summaryDigest"]
        or summary_canonical_digest
        != statement["package"]["summaryCanonicalDigest"]
        or summary_path.stat().st_size != statement["package"]["summarySizeBytes"]
        or summary["source"]["revision"] != source_revision
        or summary["source"]["workflowRunId"]
        != statement["source"]["workflowRunId"]
        or summary["source"]["workflowRunAttempt"] != "1"
        or summary["bindings"]["prerequisiteProjectionDigest"]
        != statement["bindings"]["prerequisiteProjectionDigest"]
        or summary["terraform"]["planDigest"]
        != content_digests["foundation.tfplan"]
    ):
        fail("foundation_plan_package_artifact_binding_invalid")
    plan_json, _ = load_json_object(
        plan_json_path, "foundation_plan_replay_json_invalid"
    )
    replay_changes, replay_counts = summarize_changes(plan_json)
    if (
        plan_json.get("terraform_version") != "1.14.6"
        or replay_changes != summary["terraform"]["resourceChanges"]
        or replay_counts != summary["terraform"]["actionCounts"]
        or replay_counts["delete"] != 0
        or replay_counts["replace"] != 0
        or replay_counts["create"] + replay_counts["update"] <= 0
    ):
        fail("foundation_plan_replay_mismatch")

    report_objects = [
        {
            "role": PLAN_OBJECTS[
                item["name"].removeprefix(f"{prefix}/")
            ],
            **item,
            "contentDigest": content_digests[
                item["name"].removeprefix(f"{prefix}/")
            ],
        }
        for item in objects
    ]
    marker = next(
        item for item in report_objects if item["role"] == "completion-marker"
    )
    verified = {
        "schemaVersion": 1,
        "planId": plan_id,
        "sourceRevision": source_revision,
        "statement": statement,
        "statementDigest": statement_digest,
        "summaryCanonicalDigest": summary_canonical_digest,
        "planDigest": content_digests["foundation.tfplan"],
        "bucket": bucket,
        "prefix": prefix,
        "objects": report_objects,
        "completionMarkerGeneration": marker["generation"],
        "resourceChangeCount": len(replay_changes),
        "actionCounts": replay_counts,
        "verifiedAt": verified_at,
    }
    encoded = (
        json.dumps(verified, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except OSError as error:
        raise ValueError("foundation_plan_verified_output_write_failed") from error
    return verified


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    inventory_parser = subparsers.add_parser("inventory")
    inventory_parser.add_argument("--inventory", type=Path, required=True)
    inventory_parser.add_argument("--source-revision", required=True)
    inventory_parser.add_argument("--plan-id", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--inventory", type=Path, required=True)
    verify_parser.add_argument("--download-dir", type=Path, required=True)
    verify_parser.add_argument("--plan-json", type=Path, required=True)
    verify_parser.add_argument("--source-revision", required=True)
    verify_parser.add_argument("--plan-id", required=True)
    verify_parser.add_argument("--expected-statement-digest", required=True)
    verify_parser.add_argument("--expected-public-key-digest", required=True)
    verify_parser.add_argument("--verified-at", required=True)
    verify_parser.add_argument("--output", type=Path, required=True)
    verify_parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)
    if args.command == "inventory":
        inventory, _ = load_json_object(
            args.inventory.resolve(), "foundation_plan_inventory_json_invalid"
        )
        _, prefix, objects = validate_inventory(
            inventory, args.source_revision, args.plan_id
        )
        print(
            "foundation_plan_inventory_valid "
            f"inventoryDigest={file_digest(args.inventory.resolve())} "
            f"prefix={prefix} objects={len(objects)} downloadAuthorized=true"
        )
        return 0
    verified = verify_package(
        inventory_path=args.inventory.resolve(),
        download_dir=args.download_dir.resolve(),
        plan_json_path=args.plan_json.resolve(),
        source_revision=args.source_revision,
        plan_id=args.plan_id,
        expected_statement_digest=args.expected_statement_digest,
        expected_public_key_digest=args.expected_public_key_digest,
        verified_at=args.verified_at,
        output=args.output.resolve(),
        cosign=args.cosign,
    )
    print(
        "foundation_plan_package_replayed "
        f"planId={verified['planId']} "
        f"statementDigest={verified['statementDigest']} "
        f"changes={verified['resourceChangeCount']} "
        "destructiveActions=false applyAuthorized=false "
        "infrastructureApplied=false independentlyObserved=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
