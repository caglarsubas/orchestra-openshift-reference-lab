#!/usr/bin/env python3
"""Build and verify signed independent foundation-observation reports."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.collect_foundation_observer_authority import (
        validate_observation as validate_observer_authority_observation,
    )
    from scripts.foundation_apply_receipt import validate_receipt
    from scripts.foundation_observation import (
        ENVIRONMENT,
        PROFILE_ID,
        REPOSITORY,
        WORKFLOW_REF,
        load_contract,
        validate_authority,
    )
    from scripts.foundation_plan_package import (
        file_digest,
        load_json_object,
        require_digest,
        run_cosign,
        validate_statement,
    )
    from scripts.foundation_plan_summary import validate_summary
    from scripts.prerequisite_observation import parse_utc, payload_digest
    from scripts.validate_repository import canonical_digest
    from scripts.verify_foundation_plan_package import (
        PLAN_OBJECTS,
        validate_inventory as validate_plan_inventory,
    )
except ModuleNotFoundError:
    from collect_foundation_observer_authority import (
        validate_observation as validate_observer_authority_observation,
    )
    from foundation_apply_receipt import validate_receipt
    from foundation_observation import (
        ENVIRONMENT,
        PROFILE_ID,
        REPOSITORY,
        WORKFLOW_REF,
        load_contract,
        validate_authority,
    )
    from foundation_plan_package import (
        file_digest,
        load_json_object,
        require_digest,
        run_cosign,
        validate_statement,
    )
    from foundation_plan_summary import validate_summary
    from prerequisite_observation import parse_utc, payload_digest
    from validate_repository import canonical_digest
    from verify_foundation_plan_package import (
        PLAN_OBJECTS,
        validate_inventory as validate_plan_inventory,
    )


KIND = "orchestra.reference-lab.foundation-observation.v1"
REF = "refs/heads/main"
OBSERVATION_ID = re.compile(
    r"^orchestra-foundation-observation-[1-9][0-9]*\.[1-9][0-9]*$"
)
SHA = re.compile(r"^[a-f0-9]{40}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
OBSERVATION_KEY = re.compile(
    r"^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/"
    r"europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/"
    r"foundation-observation-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
RECEIPT_OBJECTS = {
    "foundation-apply-receipt.json",
    "foundation-apply-receipt-public-key.pem",
    "foundation-apply-receipt-signature.sigstore.json",
}
RECEIPT_MARKER = "foundation-apply-receipt-signature.sigstore.json"
STATE_OBJECT = "foundation/default.tfstate"
MAX_OBJECT_BYTES = {
    "foundation-apply-receipt.json": 2 * 1024 * 1024,
    "foundation-apply-receipt-public-key.pem": 64 * 1024,
    "foundation-apply-receipt-signature.sigstore.json": 2 * 1024 * 1024,
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def _positive_integer(value: Any, code: str) -> str:
    if not isinstance(value, str) or not POSITIVE_INTEGER.fullmatch(value):
        fail(code)
    return value


def _object_metadata(value: Any, code: str) -> dict[str, Any]:
    item = strict_keys(
        value,
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
        code,
    )
    if (
        not isinstance(item["name"], str)
        or not item["name"]
        or not isinstance(item["sizeBytes"], int)
        or isinstance(item["sizeBytes"], bool)
        or item["sizeBytes"] <= 0
        or not isinstance(item["crc32c"], str)
        or not item["crc32c"]
        or (
            item["md5Hash"] is not None
            and (
                not isinstance(item["md5Hash"], str)
                or not item["md5Hash"]
            )
        )
        or not isinstance(item["etag"], str)
        or not item["etag"]
    ):
        fail(code)
    _positive_integer(item["generation"], code)
    _positive_integer(item["metageneration"], code)
    created = parse_utc(item["timeCreated"], code)
    updated = parse_utc(item["updated"], code)
    if updated < created:
        fail(code)
    return item


def validate_receipt_inventory(
    value: dict[str, Any],
    *,
    bucket: str,
    prefix: str,
) -> list[dict[str, Any]]:
    strict_keys(
        value,
        {"schemaVersion", "bucket", "prefix", "objects"},
        "foundation_observation_receipt_inventory_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["bucket"] != bucket
        or value["prefix"] != prefix
        or not isinstance(value["objects"], list)
        or len(value["objects"]) != 3
    ):
        fail("foundation_observation_receipt_inventory_invalid")
    objects = [
        _object_metadata(
            item, "foundation_observation_receipt_inventory_object_invalid"
        )
        for item in value["objects"]
    ]
    if [item["name"] for item in objects] != sorted(
        item["name"] for item in objects
    ):
        fail("foundation_observation_receipt_inventory_invalid")
    by_name: dict[str, dict[str, Any]] = {}
    for item in objects:
        if not item["name"].startswith(f"{prefix}/"):
            fail("foundation_observation_receipt_inventory_object_invalid")
        basename = item["name"].removeprefix(f"{prefix}/")
        if (
            basename not in RECEIPT_OBJECTS
            or basename in by_name
            or item["sizeBytes"] > MAX_OBJECT_BYTES[basename]
        ):
            fail("foundation_observation_receipt_inventory_object_invalid")
        by_name[basename] = item
    if set(by_name) != RECEIPT_OBJECTS:
        fail("foundation_observation_receipt_inventory_invalid")
    marker_time = parse_utc(
        by_name[RECEIPT_MARKER]["timeCreated"],
        "foundation_observation_receipt_marker_invalid",
    )
    if any(
        marker_time
        <= parse_utc(
            item["timeCreated"],
            "foundation_observation_receipt_marker_invalid",
        )
        for name, item in by_name.items()
        if name != RECEIPT_MARKER
    ):
        fail("foundation_observation_receipt_marker_invalid")
    return objects


def validate_state_metadata(value: dict[str, Any]) -> dict[str, Any]:
    metadata = _object_metadata(
        value, "foundation_observation_state_metadata_invalid"
    )
    if metadata["name"] != STATE_OBJECT or metadata["sizeBytes"] > 64 * 1024 * 1024:
        fail("foundation_observation_state_metadata_invalid")
    return metadata


def _state_identity(path: Path, code: str) -> tuple[dict[str, Any], str]:
    value, _ = load_json_object(path, code)
    serial = value.get("serial")
    lineage = value.get("lineage")
    if (
        not isinstance(serial, int)
        or isinstance(serial, bool)
        or serial <= 0
        or not isinstance(lineage, str)
        or not lineage
    ):
        fail(code)
    return (
        {
            "serial": serial,
            "lineageDigest": payload_digest(lineage),
        },
        file_digest(path),
    )


def _resource_identity_projection(
    changes: Any,
    *,
    require_observed_actions: bool,
) -> tuple[list[dict[str, str]], int, int]:
    if not isinstance(changes, list) or not changes:
        fail("foundation_observation_resource_changes_invalid")
    projected: list[dict[str, str]] = []
    seen: set[str] = set()
    managed_count = 0
    data_count = 0
    for change in changes:
        if not isinstance(change, dict):
            fail("foundation_observation_resource_change_invalid")
        if require_observed_actions:
            keys = {
                "address",
                "mode",
                "type",
                "provider_name",
                "change",
            }
            if not keys.issubset(change):
                fail("foundation_observation_resource_change_invalid")
            address = change["address"]
            mode = change["mode"]
            resource_type = change["type"]
            provider = change["provider_name"]
            action = change["change"]
            actions = action.get("actions") if isinstance(action, dict) else None
            allowed_actions = (
                actions == ["no-op"]
                if mode == "managed"
                else actions in (["no-op"], ["read"])
            )
            if not allowed_actions:
                fail("foundation_observation_drift_detected")
            address_digest = payload_digest(address)
        else:
            strict_keys(
                change,
                {
                    "addressDigest",
                    "mode",
                    "type",
                    "provider",
                    "actions",
                    "category",
                },
                "foundation_observation_source_resource_invalid",
            )
            address_digest = change["addressDigest"]
            mode = change["mode"]
            resource_type = change["type"]
            provider = change["provider"]
        require_digest(
            address_digest, "foundation_observation_resource_identity_invalid"
        )
        if (
            mode not in {"managed", "data"}
            or not isinstance(resource_type, str)
            or not resource_type.startswith("google_")
            or provider != "registry.terraform.io/hashicorp/google"
            or address_digest in seen
        ):
            fail("foundation_observation_resource_identity_invalid")
        seen.add(address_digest)
        managed_count += mode == "managed"
        data_count += mode == "data"
        projected.append(
            {
                "addressDigest": address_digest,
                "mode": mode,
                "type": resource_type,
                "provider": provider,
            }
        )
    projected.sort(key=lambda item: item["addressDigest"])
    return projected, managed_count, data_count


def _validate_plan_and_receipt_binding(
    *,
    receipt: dict[str, Any],
    plan_statement: dict[str, Any],
    plan_summary: dict[str, Any],
    receipt_digest: str,
    apply_authority: dict[str, Any],
) -> None:
    summary_digest = validate_summary(plan_summary)
    validate_statement(plan_statement, apply_authority)
    if (
        receipt["source"]["revision"] != plan_statement["source"]["revision"]
        or receipt["planId"] != plan_statement["planId"]
        or receipt["bindings"]["planPackageStatementDigest"]
        != canonical_digest(plan_statement)
        or receipt["bindings"]["planDigest"]
        != plan_statement["package"]["planDigest"]
        or receipt["bindings"]["planSummaryCanonicalDigest"] != summary_digest
        or receipt["bindings"]["prerequisiteProjectionDigest"]
        != plan_statement["bindings"]["prerequisiteProjectionDigest"]
        or plan_statement["package"]["summaryCanonicalDigest"] != summary_digest
        or not receipt_digest.startswith("sha256:")
    ):
        fail("foundation_observation_source_binding_invalid")


def validate_report(
    value: dict[str, Any],
    authority: dict[str, Any],
    release_set: dict[str, Any],
    policy: dict[str, Any],
    apply_authority: dict[str, Any],
) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "targetClass",
            "executionMode",
            "observationId",
            "applyId",
            "planId",
            "bindings",
            "source",
            "receiptCustody",
            "planCustody",
            "state",
            "providerRefresh",
            "observerAuthority",
            "signer",
            "claims",
        },
        "foundation_observation_report_keys_invalid",
    )
    authority_digest = validate_authority(
        authority, release_set, policy, apply_authority
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or not isinstance(value["observationId"], str)
        or not OBSERVATION_ID.fullmatch(value["observationId"])
        or not isinstance(value["applyId"], str)
        or not isinstance(value["planId"], str)
    ):
        fail("foundation_observation_report_identity_invalid")
    bindings = strict_keys(
        value["bindings"],
        {
            "topologyDigest",
            "releaseSetDigest",
            "prerequisitePolicyDigest",
            "foundationApplyAuthorityDigest",
            "foundationObservationAuthorityDigest",
            "reportSchemaDigest",
            "applyReceiptDigest",
            "applyReceiptSignatureDigest",
            "planPackageStatementDigest",
            "planPackageSignatureDigest",
            "planSummaryCanonicalDigest",
            "observerAuthorityObservationDigest",
        },
        "foundation_observation_report_bindings_invalid",
    )
    if any(
        not isinstance(item, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", item)
        for item in bindings.values()
    ):
        fail("foundation_observation_report_bindings_invalid")
    static = authority["bindings"]
    if (
        bindings["topologyDigest"] != static["topologyDigest"]
        or bindings["releaseSetDigest"] != static["releaseSetDigest"]
        or bindings["prerequisitePolicyDigest"]
        != static["prerequisitePolicyDigest"]
        or bindings["foundationApplyAuthorityDigest"]
        != static["foundationApplyAuthorityDigest"]
        or bindings["foundationObservationAuthorityDigest"] != authority_digest
        or bindings["reportSchemaDigest"] != static["reportSchemaDigest"]
    ):
        fail("foundation_observation_report_bindings_invalid")
    source = strict_keys(
        value["source"],
        {
            "repository",
            "revision",
            "ref",
            "workflowRef",
            "environment",
            "workflowRunId",
            "workflowRunAttempt",
            "environmentApprovalDigest",
            "actorIdentityDigest",
            "authorizationReasonDigest",
            "startedAt",
            "completedAt",
        },
        "foundation_observation_report_source_invalid",
    )
    started = parse_utc(
        source["startedAt"], "foundation_observation_report_source_invalid"
    )
    completed = parse_utc(
        source["completedAt"], "foundation_observation_report_source_invalid"
    )
    if (
        source["repository"] != REPOSITORY
        or source["ref"] != REF
        or source["workflowRef"] != WORKFLOW_REF
        or source["environment"] != ENVIRONMENT
        or source["workflowRunAttempt"] != "1"
        or not isinstance(source["revision"], str)
        or not SHA.fullmatch(source["revision"])
        or not isinstance(source["workflowRunId"], str)
        or not POSITIVE_INTEGER.fullmatch(source["workflowRunId"])
        or value["observationId"]
        != (
            f"orchestra-foundation-observation-{source['workflowRunId']}."
            f"{source['workflowRunAttempt']}"
        )
        or completed < started
        or completed - started > timedelta(minutes=90)
    ):
        fail("foundation_observation_report_source_invalid")
    for key in (
        "environmentApprovalDigest",
        "actorIdentityDigest",
        "authorizationReasonDigest",
    ):
        require_digest(source[key], "foundation_observation_report_source_invalid")
    receipt = strict_keys(
        value["receiptCustody"],
        {
            "bucket",
            "prefix",
            "inventoryDigest",
            "receiptDigest",
            "publicKeyDigest",
            "signatureBundleDigest",
            "completionMarkerGeneration",
            "signatureVerified",
            "selfAttestedReceiptAcknowledged",
        },
        "foundation_observation_report_receipt_invalid",
    )
    plan = strict_keys(
        value["planCustody"],
        {
            "bucket",
            "prefix",
            "inventoryDigest",
            "statementDigest",
            "summaryCanonicalDigest",
            "publicKeyDigest",
            "signatureBundleDigest",
            "completionMarkerGeneration",
            "signatureVerified",
        },
        "foundation_observation_report_plan_invalid",
    )
    if (
        not BUCKET.fullmatch(str(receipt["bucket"]))
        or not BUCKET.fullmatch(str(plan["bucket"]))
        or receipt["bucket"] != plan["bucket"]
        or receipt["receiptDigest"] != bindings["applyReceiptDigest"]
        or receipt["signatureBundleDigest"]
        != bindings["applyReceiptSignatureDigest"]
        or plan["statementDigest"] != bindings["planPackageStatementDigest"]
        or plan["signatureBundleDigest"] != bindings["planPackageSignatureDigest"]
        or plan["summaryCanonicalDigest"]
        != bindings["planSummaryCanonicalDigest"]
        or receipt["signatureVerified"] is not True
        or receipt["selfAttestedReceiptAcknowledged"] is not True
        or plan["signatureVerified"] is not True
    ):
        fail("foundation_observation_report_custody_invalid")
    for section in (receipt, plan):
        for key in section:
            if key.endswith("Digest"):
                require_digest(
                    section[key], "foundation_observation_report_custody_invalid"
                )
        _positive_integer(
            section["completionMarkerGeneration"],
            "foundation_observation_report_custody_invalid",
        )
    state = strict_keys(
        value["state"],
        {
            "bucket",
            "object",
            "generation",
            "metageneration",
            "sizeBytes",
            "rawObjectDigest",
            "statePullDigest",
            "serial",
            "lineageDigest",
            "generationStable",
            "matchesApplyReceipt",
        },
        "foundation_observation_report_state_invalid",
    )
    if (
        state["bucket"] != receipt["bucket"]
        or state["object"] != STATE_OBJECT
        or not isinstance(state["sizeBytes"], int)
        or isinstance(state["sizeBytes"], bool)
        or state["sizeBytes"] <= 0
        or not isinstance(state["serial"], int)
        or isinstance(state["serial"], bool)
        or state["serial"] <= 0
        or state["generationStable"] is not True
        or state["matchesApplyReceipt"] is not True
    ):
        fail("foundation_observation_report_state_invalid")
    _positive_integer(
        state["generation"], "foundation_observation_report_state_invalid"
    )
    _positive_integer(
        state["metageneration"], "foundation_observation_report_state_invalid"
    )
    for key in ("rawObjectDigest", "statePullDigest", "lineageDigest"):
        require_digest(state[key], "foundation_observation_report_state_invalid")
    refresh = strict_keys(
        value["providerRefresh"],
        {
            "terraformVersion",
            "formatVersion",
            "refreshOnly",
            "stateLockUsed",
            "detailedExitCode",
            "driftDetected",
            "managedResourceCount",
            "dataResourceCount",
            "resourceIdentityDigest",
            "sourcePlanResourceIdentityDigest",
            "resourceIdentitySetMatches",
        },
        "foundation_observation_report_refresh_invalid",
    )
    if (
        refresh["terraformVersion"] != "1.14.6"
        or not isinstance(refresh["formatVersion"], str)
        or not refresh["formatVersion"]
        or refresh["refreshOnly"] is not True
        or refresh["stateLockUsed"] is not False
        or refresh["detailedExitCode"] != 0
        or refresh["driftDetected"] is not False
        or not isinstance(refresh["managedResourceCount"], int)
        or isinstance(refresh["managedResourceCount"], bool)
        or refresh["managedResourceCount"] < 1
        or not isinstance(refresh["dataResourceCount"], int)
        or isinstance(refresh["dataResourceCount"], bool)
        or refresh["dataResourceCount"] < 0
        or refresh["resourceIdentityDigest"]
        != refresh["sourcePlanResourceIdentityDigest"]
        or refresh["resourceIdentitySetMatches"] is not True
    ):
        fail("foundation_observation_report_refresh_invalid")
    require_digest(
        refresh["resourceIdentityDigest"],
        "foundation_observation_report_refresh_invalid",
    )
    observer_authority = strict_keys(
        value["observerAuthority"],
        {
            "observationDigest",
            "providerConditionExact",
            "impersonationBindingExact",
            "noUserManagedKeys",
            "directProjectAndAncestorRolesExact",
            "customStorageRoleExact",
            "storageRolesExact",
            "kmsRolesExact",
            "directReadOnlyBoundaryObserved",
        },
        "foundation_observation_report_observer_authority_invalid",
    )
    require_digest(
        observer_authority["observationDigest"],
        "foundation_observation_report_observer_authority_invalid",
    )
    if (
        observer_authority["observationDigest"]
        != bindings["observerAuthorityObservationDigest"]
        or any(
            observer_authority[key] is not True
            for key in (
                "providerConditionExact",
                "impersonationBindingExact",
                "noUserManagedKeys",
                "directProjectAndAncestorRolesExact",
                "customStorageRoleExact",
                "storageRolesExact",
                "kmsRolesExact",
                "directReadOnlyBoundaryObserved",
            )
        )
    ):
        fail("foundation_observation_report_observer_authority_invalid")
    signer = strict_keys(
        value["signer"],
        {"executionClass", "keyVersionResource", "publicKeyDigest"},
        "foundation_observation_report_signer_invalid",
    )
    if (
        signer["executionClass"] != "github-hosted-read-only-observer"
        or not isinstance(signer["keyVersionResource"], str)
        or not OBSERVATION_KEY.fullmatch(signer["keyVersionResource"])
    ):
        fail("foundation_observation_report_signer_invalid")
    require_digest(
        signer["publicKeyDigest"], "foundation_observation_report_signer_invalid"
    )
    if value["claims"] != {
        "applyReceiptSignatureVerified": True,
        "planPackageSignatureVerified": True,
        "observerDirectReadOnlyAuthorityVerified": True,
        "stateGenerationStable": True,
        "stateMatchesApplyReceipt": True,
        "providerRefreshCompleted": True,
        "terraformDriftDetected": False,
        "foundationPostApplyObserved": True,
        "independentlyObserved": True,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }:
        fail("foundation_observation_report_claims_invalid")
    return canonical_digest(value)


def build_report(
    *,
    receipt_path: Path,
    receipt_inventory_path: Path,
    receipt_public_key: Path,
    receipt_signature: Path,
    expected_receipt_public_key_digest: str,
    expected_receipt_digest: str,
    plan_statement_path: Path,
    plan_summary_path: Path,
    plan_inventory_path: Path,
    plan_public_key: Path,
    plan_signature: Path,
    expected_plan_public_key_digest: str,
    state_object_path: Path,
    state_pull_path: Path,
    state_metadata_before_path: Path,
    state_metadata_after_path: Path,
    refresh_plan_path: Path,
    observer_authority_observation_path: Path,
    observation_id: str,
    environment_approval_digest: str,
    actor_id: str,
    reason: str,
    source_revision: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    started_at: str,
    completed_at: str,
    signing_key: str,
    signing_public_key: Path,
    expected_signing_public_key_digest: str,
    cosign: str = "cosign",
) -> dict[str, Any]:
    authority, release_set, policy, apply_authority = load_contract()
    authority_digest = validate_authority(
        authority, release_set, policy, apply_authority
    )
    if (
        not OBSERVATION_ID.fullmatch(observation_id)
        or not SHA.fullmatch(source_revision)
        or workflow_run_attempt != "1"
        or observation_id
        != f"orchestra-foundation-observation-{workflow_run_id}.1"
        or not POSITIVE_INTEGER.fullmatch(workflow_run_id)
        or not POSITIVE_INTEGER.fullmatch(actor_id)
        or not isinstance(reason, str)
        or not 12 <= len(reason.strip()) <= 500
        or not OBSERVATION_KEY.fullmatch(signing_key)
    ):
        fail("foundation_observation_input_invalid")
    for digest, code in (
        (
            environment_approval_digest,
            "foundation_observation_environment_approval_invalid",
        ),
        (
            expected_receipt_public_key_digest,
            "foundation_observation_receipt_public_key_invalid",
        ),
        (
            expected_receipt_digest,
            "foundation_observation_expected_receipt_digest_invalid",
        ),
        (
            expected_plan_public_key_digest,
            "foundation_observation_plan_public_key_invalid",
        ),
        (
            expected_signing_public_key_digest,
            "foundation_observation_signing_public_key_invalid",
        ),
    ):
        require_digest(digest, code)
    started = parse_utc(started_at, "foundation_observation_time_invalid")
    completed = parse_utc(completed_at, "foundation_observation_time_invalid")
    if completed < started or completed - started > timedelta(minutes=90):
        fail("foundation_observation_time_invalid")
    if file_digest(signing_public_key) != expected_signing_public_key_digest:
        fail("foundation_observation_signing_public_key_mismatch")

    receipt, _ = load_json_object(
        receipt_path, "foundation_observation_receipt_json_invalid"
    )
    receipt_digest = validate_receipt(receipt, apply_authority)
    if (
        receipt_digest != expected_receipt_digest
        or receipt["source"]["revision"] != source_revision
    ):
        fail("foundation_observation_receipt_binding_invalid")
    if (
        file_digest(receipt_public_key) != expected_receipt_public_key_digest
        or receipt["signer"]["publicKeyDigest"]
        != expected_receipt_public_key_digest
    ):
        fail("foundation_observation_receipt_public_key_mismatch")
    run_cosign(
        cosign,
        [
            "verify-blob",
            "--bundle",
            str(receipt_signature),
            "--key",
            str(receipt_public_key),
            str(receipt_path),
        ],
        "foundation_observation_receipt_signature_invalid",
    )
    receipt_prefix = (
        f"foundation-apply-reports/v1/{PROFILE_ID}/{source_revision}/"
        f"{receipt['planId']}/{receipt['applyId']}"
    )
    receipt_inventory, _ = load_json_object(
        receipt_inventory_path,
        "foundation_observation_receipt_inventory_json_invalid",
    )
    receipt_objects = validate_receipt_inventory(
        receipt_inventory,
        bucket=receipt["planCustody"]["bucket"],
        prefix=receipt_prefix,
    )

    plan_statement, _ = load_json_object(
        plan_statement_path, "foundation_observation_plan_statement_invalid"
    )
    plan_summary, _ = load_json_object(
        plan_summary_path, "foundation_observation_plan_summary_invalid"
    )
    if (
        file_digest(plan_public_key) != expected_plan_public_key_digest
        or plan_statement.get("signer", {}).get("publicKeyDigest")
        != expected_plan_public_key_digest
        or file_digest(plan_statement_path)
        != receipt["bindings"]["planPackageStatementDigest"]
        or file_digest(plan_summary_path)
        != plan_statement.get("package", {}).get("summaryDigest")
    ):
        fail("foundation_observation_plan_public_key_mismatch")
    run_cosign(
        cosign,
        [
            "verify-blob",
            "--bundle",
            str(plan_signature),
            "--key",
            str(plan_public_key),
            str(plan_statement_path),
        ],
        "foundation_observation_plan_signature_invalid",
    )
    _validate_plan_and_receipt_binding(
        receipt=receipt,
        plan_statement=plan_statement,
        plan_summary=plan_summary,
        receipt_digest=receipt_digest,
        apply_authority=apply_authority,
    )
    plan_inventory, _ = load_json_object(
        plan_inventory_path, "foundation_observation_plan_inventory_json_invalid"
    )
    _, plan_prefix, plan_objects = validate_plan_inventory(
        plan_inventory, source_revision, receipt["planId"]
    )

    state_before, _ = load_json_object(
        state_metadata_before_path,
        "foundation_observation_state_metadata_json_invalid",
    )
    state_after, _ = load_json_object(
        state_metadata_after_path,
        "foundation_observation_state_metadata_json_invalid",
    )
    state_before = validate_state_metadata(state_before)
    state_after = validate_state_metadata(state_after)
    if state_before != state_after:
        fail("foundation_observation_state_generation_changed")
    raw_identity, raw_digest = _state_identity(
        state_object_path, "foundation_observation_state_object_invalid"
    )
    pull_identity, pull_digest = _state_identity(
        state_pull_path, "foundation_observation_state_pull_invalid"
    )
    receipt_state = receipt["terraform"]["stateAfter"]
    if (
        raw_identity != pull_identity
        or pull_identity["serial"] != receipt_state["serial"]
        or pull_identity["lineageDigest"] != receipt_state["lineageDigest"]
        or pull_digest != receipt_state["stateDigest"]
    ):
        fail("foundation_observation_state_receipt_mismatch")

    refresh_plan, _ = load_json_object(
        refresh_plan_path, "foundation_observation_refresh_plan_invalid"
    )
    if (
        refresh_plan.get("terraform_version") != "1.14.6"
        or not isinstance(refresh_plan.get("format_version"), str)
        or not refresh_plan["format_version"]
    ):
        fail("foundation_observation_refresh_plan_invalid")
    observed_resources, managed_count, data_count = _resource_identity_projection(
        refresh_plan.get("resource_changes"),
        require_observed_actions=True,
    )
    source_resources, _, _ = _resource_identity_projection(
        plan_summary["terraform"]["resourceChanges"],
        require_observed_actions=False,
    )
    if observed_resources != source_resources:
        fail("foundation_observation_resource_identity_mismatch")
    resource_identity_digest = canonical_digest(observed_resources)
    observer_authority_observation, _ = load_json_object(
        observer_authority_observation_path,
        "foundation_observation_observer_authority_json_invalid",
    )
    observer_authority_digest = validate_observer_authority_observation(
        observer_authority_observation
    )
    expected_observer_email = (
        signing_key.split("/projects/", maxsplit=1)[-1].split(
            "/locations/", maxsplit=1
        )[0]
    )
    if (
        observer_authority_observation["serviceAccount"]
        != (
            f"orchestra-foundation-observer@{expected_observer_email}."
            "iam.gserviceaccount.com"
        )
    ):
        fail("foundation_observation_observer_authority_binding_invalid")

    receipt_marker = next(
        item
        for item in receipt_objects
        if item["name"].endswith(RECEIPT_MARKER)
    )
    plan_marker = next(
        item
        for item in plan_objects
        if item["name"].endswith(
            "foundation-plan-package-signature.sigstore.json"
        )
    )
    report = {
        "schemaVersion": 1,
        "kind": KIND,
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab",
        "executionMode": "live",
        "observationId": observation_id,
        "applyId": receipt["applyId"],
        "planId": receipt["planId"],
        "bindings": {
            "topologyDigest": authority["bindings"]["topologyDigest"],
            "releaseSetDigest": authority["bindings"]["releaseSetDigest"],
            "prerequisitePolicyDigest": authority["bindings"][
                "prerequisitePolicyDigest"
            ],
            "foundationApplyAuthorityDigest": authority["bindings"][
                "foundationApplyAuthorityDigest"
            ],
            "foundationObservationAuthorityDigest": authority_digest,
            "reportSchemaDigest": authority["bindings"]["reportSchemaDigest"],
            "applyReceiptDigest": receipt_digest,
            "applyReceiptSignatureDigest": file_digest(receipt_signature),
            "planPackageStatementDigest": canonical_digest(plan_statement),
            "planPackageSignatureDigest": file_digest(plan_signature),
            "planSummaryCanonicalDigest": canonical_digest(plan_summary),
            "observerAuthorityObservationDigest": observer_authority_digest,
        },
        "source": {
            "repository": REPOSITORY,
            "revision": source_revision,
            "ref": REF,
            "workflowRef": WORKFLOW_REF,
            "environment": ENVIRONMENT,
            "workflowRunId": workflow_run_id,
            "workflowRunAttempt": workflow_run_attempt,
            "environmentApprovalDigest": environment_approval_digest,
            "actorIdentityDigest": payload_digest(actor_id),
            "authorizationReasonDigest": payload_digest(reason.strip()),
            "startedAt": started_at,
            "completedAt": completed_at,
        },
        "receiptCustody": {
            "bucket": receipt_inventory["bucket"],
            "prefix": receipt_inventory["prefix"],
            "inventoryDigest": canonical_digest(receipt_inventory),
            "receiptDigest": receipt_digest,
            "publicKeyDigest": file_digest(receipt_public_key),
            "signatureBundleDigest": file_digest(receipt_signature),
            "completionMarkerGeneration": receipt_marker["generation"],
            "signatureVerified": True,
            "selfAttestedReceiptAcknowledged": True,
        },
        "planCustody": {
            "bucket": plan_inventory["bucket"],
            "prefix": plan_prefix,
            "inventoryDigest": canonical_digest(plan_inventory),
            "statementDigest": canonical_digest(plan_statement),
            "summaryCanonicalDigest": canonical_digest(plan_summary),
            "publicKeyDigest": file_digest(plan_public_key),
            "signatureBundleDigest": file_digest(plan_signature),
            "completionMarkerGeneration": plan_marker["generation"],
            "signatureVerified": True,
        },
        "state": {
            "bucket": receipt_inventory["bucket"],
            "object": STATE_OBJECT,
            "generation": state_before["generation"],
            "metageneration": state_before["metageneration"],
            "sizeBytes": state_before["sizeBytes"],
            "rawObjectDigest": raw_digest,
            "statePullDigest": pull_digest,
            "serial": pull_identity["serial"],
            "lineageDigest": pull_identity["lineageDigest"],
            "generationStable": True,
            "matchesApplyReceipt": True,
        },
        "providerRefresh": {
            "terraformVersion": refresh_plan["terraform_version"],
            "formatVersion": refresh_plan["format_version"],
            "refreshOnly": True,
            "stateLockUsed": False,
            "detailedExitCode": 0,
            "driftDetected": False,
            "managedResourceCount": managed_count,
            "dataResourceCount": data_count,
            "resourceIdentityDigest": resource_identity_digest,
            "sourcePlanResourceIdentityDigest": resource_identity_digest,
            "resourceIdentitySetMatches": True,
        },
        "observerAuthority": {
            "observationDigest": observer_authority_digest,
            "providerConditionExact": observer_authority_observation["checks"][
                "providerConditionExact"
            ],
            "impersonationBindingExact": observer_authority_observation[
                "checks"
            ]["impersonationBindingExact"],
            "noUserManagedKeys": observer_authority_observation["checks"][
                "noUserManagedKeys"
            ],
            "directProjectAndAncestorRolesExact": (
                observer_authority_observation["checks"][
                    "targetProjectRolesExact"
                ]
                and observer_authority_observation["checks"][
                    "servicesProjectRolesExact"
                ]
                and observer_authority_observation["checks"][
                    "directAncestorBindingsExact"
                ]
            ),
            "customStorageRoleExact": observer_authority_observation["checks"][
                "customStorageRoleExact"
            ],
            "storageRolesExact": observer_authority_observation["checks"][
                "storageRolesExact"
            ],
            "kmsRolesExact": observer_authority_observation["checks"][
                "kmsRolesExact"
            ],
            "directReadOnlyBoundaryObserved": observer_authority_observation[
                "claims"
            ]["directReadOnlyBoundaryObserved"],
        },
        "signer": {
            "executionClass": "github-hosted-read-only-observer",
            "keyVersionResource": signing_key,
            "publicKeyDigest": expected_signing_public_key_digest,
        },
        "claims": {
            "applyReceiptSignatureVerified": True,
            "planPackageSignatureVerified": True,
            "observerDirectReadOnlyAuthorityVerified": True,
            "stateGenerationStable": True,
            "stateMatchesApplyReceipt": True,
            "providerRefreshCompleted": True,
            "terraformDriftDetected": False,
            "foundationPostApplyObserved": True,
            "independentlyObserved": True,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
            "customerCertified": False,
            "redHatCertified": False,
            "contractualSla": False,
        },
    }
    validate_report(
        report, authority, release_set, policy, apply_authority
    )
    return report


def write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    if path.exists() or not path.parent.is_dir():
        fail("foundation_observation_output_invalid")
    encoded = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except OSError as error:
        raise ValueError("foundation_observation_write_failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    receipt_inventory = subparsers.add_parser("receipt-inventory")
    receipt_inventory.add_argument("--inventory", type=Path, required=True)
    receipt_inventory.add_argument("--bucket", required=True)
    receipt_inventory.add_argument("--prefix", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--receipt", type=Path, required=True)
    build.add_argument("--receipt-inventory", type=Path, required=True)
    build.add_argument("--receipt-public-key", type=Path, required=True)
    build.add_argument("--receipt-signature", type=Path, required=True)
    build.add_argument("--expected-receipt-public-key-digest", required=True)
    build.add_argument("--expected-receipt-digest", required=True)
    build.add_argument("--plan-statement", type=Path, required=True)
    build.add_argument("--plan-summary", type=Path, required=True)
    build.add_argument("--plan-inventory", type=Path, required=True)
    build.add_argument("--plan-public-key", type=Path, required=True)
    build.add_argument("--plan-signature", type=Path, required=True)
    build.add_argument("--expected-plan-public-key-digest", required=True)
    build.add_argument("--state-object", type=Path, required=True)
    build.add_argument("--state-pull", type=Path, required=True)
    build.add_argument("--state-metadata-before", type=Path, required=True)
    build.add_argument("--state-metadata-after", type=Path, required=True)
    build.add_argument("--refresh-plan", type=Path, required=True)
    build.add_argument(
        "--observer-authority-observation", type=Path, required=True
    )
    build.add_argument("--observation-id", required=True)
    build.add_argument("--environment-approval-digest", required=True)
    build.add_argument("--actor-id", required=True)
    build.add_argument("--reason", required=True)
    build.add_argument("--source-revision", required=True)
    build.add_argument("--workflow-run-id", required=True)
    build.add_argument("--workflow-run-attempt", required=True)
    build.add_argument("--started-at", required=True)
    build.add_argument("--completed-at", required=True)
    build.add_argument("--signing-key", required=True)
    build.add_argument("--signing-public-key", type=Path, required=True)
    build.add_argument("--expected-signing-public-key-digest", required=True)
    build.add_argument("--cosign", default="cosign")
    build.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--signing-public-key", type=Path)
    validate.add_argument("--signature-bundle", type=Path)
    validate.add_argument("--expected-public-key-digest")
    validate.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)
    authority, release_set, policy, apply_authority = load_contract()
    validate_authority(authority, release_set, policy, apply_authority)
    if args.command == "receipt-inventory":
        inventory, _ = load_json_object(
            args.inventory.resolve(),
            "foundation_observation_receipt_inventory_json_invalid",
        )
        objects = validate_receipt_inventory(
            inventory,
            bucket=args.bucket,
            prefix=args.prefix,
        )
        print(
            "foundation_receipt_inventory_valid "
            f"inventoryDigest={file_digest(args.inventory.resolve())} "
            f"prefix={args.prefix} objects={len(objects)} "
            "downloadAuthorized=true"
        )
        return 0
    signature_verified = False
    if args.command == "build":
        report = build_report(
            receipt_path=args.receipt.resolve(),
            receipt_inventory_path=args.receipt_inventory.resolve(),
            receipt_public_key=args.receipt_public_key.resolve(),
            receipt_signature=args.receipt_signature.resolve(),
            expected_receipt_public_key_digest=args.expected_receipt_public_key_digest,
            expected_receipt_digest=args.expected_receipt_digest,
            plan_statement_path=args.plan_statement.resolve(),
            plan_summary_path=args.plan_summary.resolve(),
            plan_inventory_path=args.plan_inventory.resolve(),
            plan_public_key=args.plan_public_key.resolve(),
            plan_signature=args.plan_signature.resolve(),
            expected_plan_public_key_digest=args.expected_plan_public_key_digest,
            state_object_path=args.state_object.resolve(),
            state_pull_path=args.state_pull.resolve(),
            state_metadata_before_path=args.state_metadata_before.resolve(),
            state_metadata_after_path=args.state_metadata_after.resolve(),
            refresh_plan_path=args.refresh_plan.resolve(),
            observer_authority_observation_path=(
                args.observer_authority_observation.resolve()
            ),
            observation_id=args.observation_id,
            environment_approval_digest=args.environment_approval_digest,
            actor_id=args.actor_id,
            reason=args.reason,
            source_revision=args.source_revision,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            started_at=args.started_at,
            completed_at=args.completed_at,
            signing_key=args.signing_key,
            signing_public_key=args.signing_public_key.resolve(),
            expected_signing_public_key_digest=(
                args.expected_signing_public_key_digest
            ),
            cosign=args.cosign,
        )
        write_new(args.output, report)
    else:
        report, _ = load_json_object(
            args.report.resolve(), "foundation_observation_report_json_invalid"
        )
        signature_inputs = (
            args.signing_public_key,
            args.signature_bundle,
            args.expected_public_key_digest,
        )
        if any(value is not None for value in signature_inputs) and not all(
            value is not None for value in signature_inputs
        ):
            fail("foundation_observation_signature_inputs_incomplete")
        if all(value is not None for value in signature_inputs):
            expected = require_digest(
                args.expected_public_key_digest,
                "foundation_observation_public_key_digest_invalid",
            )
            if (
                file_digest(args.signing_public_key.resolve()) != expected
                or report.get("signer", {}).get("publicKeyDigest") != expected
                or not args.signature_bundle.resolve().is_file()
            ):
                fail("foundation_observation_signature_binding_invalid")
            run_cosign(
                args.cosign,
                [
                    "verify-blob",
                    "--bundle",
                    str(args.signature_bundle.resolve()),
                    "--key",
                    str(args.signing_public_key.resolve()),
                    str(args.report.resolve()),
                ],
                "foundation_observation_signature_verification_failed",
            )
            signature_verified = True
    digest = validate_report(
        report, authority, release_set, policy, apply_authority
    )
    print(
        "foundation_observation_report_valid "
        f"observationId={report['observationId']} applyId={report['applyId']} "
        f"digest={digest} signatureVerified={str(signature_verified).lower()} "
        "independentlyObserved=true campaignEvidence=false "
        "referenceProfileVerified=false customerCertified=false "
        "redHatCertified=false contractualSla=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
