#!/usr/bin/env python3
"""Build and validate self-attested foundation apply receipts."""

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
        file_digest,
        load_json_object,
        require_digest,
        run_cosign,
        strict_keys,
        validate_statement,
    )
    from scripts.prerequisite_observation import parse_utc, payload_digest
    from scripts.validate_repository import canonical_digest
    from scripts.verify_foundation_plan_package import (
        PLAN_OBJECTS,
        validate_inventory,
    )
except ModuleNotFoundError:
    from foundation_apply_execution import PROFILE_ID, load_contract, validate_authority
    from foundation_plan_package import (
        file_digest,
        load_json_object,
        require_digest,
        run_cosign,
        strict_keys,
        validate_statement,
    )
    from prerequisite_observation import parse_utc, payload_digest
    from validate_repository import canonical_digest
    from verify_foundation_plan_package import PLAN_OBJECTS, validate_inventory


KIND = "orchestra.reference-lab.foundation-apply-receipt.v1"
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REF = "refs/heads/main"
WORKFLOW_REF = f"{REPOSITORY}/.github/workflows/foundation-apply.yml@{REF}"
ENVIRONMENT = "reference-lab-foundation-apply"
APPLY_ID = re.compile(r"^orchestra-foundation-apply-[1-9][0-9]*\.[1-9][0-9]*$")
SHA = re.compile(r"^[a-f0-9]{40}$")
RECEIPT_KEY = re.compile(
    r"^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/"
    r"europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/"
    r"foundation-apply-receipt-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
ACTION_COUNT_KEYS = ("noOp", "create", "read", "update", "delete", "replace")


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def _validate_state_shape(
    value: dict[str, Any], *, present_required: bool
) -> dict[str, Any]:
    state = strict_keys(
        value,
        {"present", "serial", "lineageDigest", "stateDigest"},
        "foundation_apply_receipt_state_invalid",
    )
    if (
        not isinstance(state["present"], bool)
        or not isinstance(state["serial"], int)
        or isinstance(state["serial"], bool)
        or state["serial"] < 0
        or (present_required and state["present"] is not True)
    ):
        fail("foundation_apply_receipt_state_invalid")
    if state["present"]:
        require_digest(
            state["lineageDigest"], "foundation_apply_receipt_state_invalid"
        )
        require_digest(state["stateDigest"], "foundation_apply_receipt_state_invalid")
    elif (
        state["serial"] != 0
        or state["lineageDigest"] is not None
        or state["stateDigest"] is not None
    ):
        fail("foundation_apply_receipt_state_invalid")
    return state


def _state_projection(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file() or path.stat().st_size == 0:
        return {
            "present": False,
            "serial": 0,
            "lineageDigest": None,
            "stateDigest": None,
        }
    state, _ = load_json_object(path, "foundation_apply_state_json_invalid")
    serial = state.get("serial")
    lineage = state.get("lineage")
    if (
        not isinstance(serial, int)
        or isinstance(serial, bool)
        or serial < 0
        or not isinstance(lineage, str)
        or not lineage
    ):
        fail("foundation_apply_state_identity_invalid")
    return {
        "present": True,
        "serial": serial,
        "lineageDigest": payload_digest(lineage),
        "stateDigest": file_digest(path),
    }


def expected_receipt_bindings(
    authority: dict[str, Any],
    authority_digest: str,
    verified: dict[str, Any],
) -> dict[str, str]:
    bindings = authority["bindings"]
    statement = verified["statement"]
    return {
        "topologyDigest": bindings["topologyDigest"],
        "releaseSetDigest": bindings["releaseSetDigest"],
        "prerequisitePolicyDigest": bindings["prerequisitePolicyDigest"],
        "prerequisiteProjectionDigest": statement["bindings"][
            "prerequisiteProjectionDigest"
        ],
        "foundationApplyAuthorityDigest": authority_digest,
        "planPackageSchemaDigest": bindings["planPackageSchemaDigest"],
        "applyReceiptSchemaDigest": bindings["applyReceiptSchemaDigest"],
        "planPackageStatementDigest": verified["statementDigest"],
        "planDigest": verified["planDigest"],
        "planSummaryCanonicalDigest": verified["summaryCanonicalDigest"],
    }


def validate_receipt(value: dict[str, Any], authority: dict[str, Any]) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "targetClass",
            "executionMode",
            "applyId",
            "planId",
            "bindings",
            "source",
            "planCustody",
            "terraform",
            "signer",
            "claims",
        },
        "foundation_apply_receipt_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or not isinstance(value["applyId"], str)
        or not APPLY_ID.fullmatch(value["applyId"])
        or not isinstance(value["planId"], str)
    ):
        fail("foundation_apply_receipt_identity_invalid")
    bindings = strict_keys(
        value["bindings"],
        {
            "topologyDigest",
            "releaseSetDigest",
            "prerequisitePolicyDigest",
            "prerequisiteProjectionDigest",
            "foundationApplyAuthorityDigest",
            "planPackageSchemaDigest",
            "applyReceiptSchemaDigest",
            "planPackageStatementDigest",
            "planDigest",
            "planSummaryCanonicalDigest",
        },
        "foundation_apply_receipt_bindings_invalid",
    )
    for item in bindings.values():
        require_digest(item, "foundation_apply_receipt_bindings_invalid")
    expected_static = authority["bindings"]
    authority_digest = canonical_digest(authority)
    if (
        bindings["topologyDigest"] != expected_static["topologyDigest"]
        or bindings["releaseSetDigest"] != expected_static["releaseSetDigest"]
        or bindings["prerequisitePolicyDigest"]
        != expected_static["prerequisitePolicyDigest"]
        or bindings["foundationApplyAuthorityDigest"] != authority_digest
        or bindings["planPackageSchemaDigest"]
        != expected_static["planPackageSchemaDigest"]
        or bindings["applyReceiptSchemaDigest"]
        != expected_static["applyReceiptSchemaDigest"]
    ):
        fail("foundation_apply_receipt_bindings_invalid")

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
        "foundation_apply_receipt_source_invalid",
    )
    started = parse_utc(source["startedAt"], "foundation_apply_receipt_source_invalid")
    completed = parse_utc(
        source["completedAt"], "foundation_apply_receipt_source_invalid"
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
        or not source["workflowRunId"].isdigit()
        or source["workflowRunId"].startswith("0")
        or value["applyId"]
        != (
            f"orchestra-foundation-apply-{source['workflowRunId']}."
            f"{source['workflowRunAttempt']}"
        )
        or completed < started
        or completed - started > timedelta(minutes=90)
    ):
        fail("foundation_apply_receipt_source_invalid")
    for key in (
        "environmentApprovalDigest",
        "actorIdentityDigest",
        "authorizationReasonDigest",
    ):
        require_digest(source[key], "foundation_apply_receipt_source_invalid")

    custody = strict_keys(
        value["planCustody"],
        {
            "bucket",
            "prefix",
            "managedFolder",
            "objectCount",
            "objects",
            "completionMarkerObject",
            "completionMarkerGeneration",
            "planPackageSignatureVerified",
            "exactPlanReplayed",
        },
        "foundation_apply_receipt_custody_invalid",
    )
    projected_objects = []
    if isinstance(custody.get("objects"), list):
        for item in custody["objects"]:
            if not isinstance(item, dict):
                fail("foundation_apply_receipt_custody_invalid")
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
                "foundation_apply_receipt_custody_object_invalid",
            )
            require_digest(
                item["contentDigest"],
                "foundation_apply_receipt_custody_object_invalid",
            )
            projected_objects.append(
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
            )
    _, prefix, inventory_objects = validate_inventory(
        {
            "schemaVersion": 1,
            "bucket": custody.get("bucket"),
            "prefix": custody.get("prefix"),
            "objects": projected_objects,
        },
        source["revision"],
        value["planId"],
    )
    expected_by_name = {item["name"]: item for item in inventory_objects}
    for item in custody["objects"]:
        basename = item["name"].removeprefix(f"{prefix}/")
        if (
            item["name"] not in expected_by_name
            or item["role"] != PLAN_OBJECTS.get(basename)
            or any(
                item[key] != expected_by_name[item["name"]][key]
                for key in expected_by_name[item["name"]]
            )
        ):
            fail("foundation_apply_receipt_custody_object_invalid")
    marker = next(
        item for item in custody["objects"] if item["role"] == "completion-marker"
    )
    saved_plan = next(
        item for item in custody["objects"] if item["role"] == "saved-plan"
    )
    statement_object = next(
        item for item in custody["objects"] if item["role"] == "plan-package-statement"
    )
    if (
        custody["managedFolder"] != "foundation-plans/"
        or custody["objectCount"] != 5
        or custody["completionMarkerObject"]
        != "foundation-plan-package-signature.sigstore.json"
        or custody["completionMarkerGeneration"] != marker["generation"]
        or custody["planPackageSignatureVerified"] is not True
        or custody["exactPlanReplayed"] is not True
        or saved_plan["contentDigest"] != bindings["planDigest"]
        or statement_object["contentDigest"]
        != bindings["planPackageStatementDigest"]
    ):
        fail("foundation_apply_receipt_custody_invalid")

    terraform = strict_keys(
        value["terraform"],
        {
            "version",
            "stateLockUsed",
            "lockTimeoutSeconds",
            "applyExitCode",
            "resourceChangeCount",
            "actionCounts",
            "stateBefore",
            "stateAfter",
        },
        "foundation_apply_receipt_terraform_invalid",
    )
    counts = strict_keys(
        terraform["actionCounts"],
        set(ACTION_COUNT_KEYS),
        "foundation_apply_receipt_action_counts_invalid",
    )
    if (
        terraform["version"] != "1.14.6"
        or terraform["stateLockUsed"] is not True
        or terraform["lockTimeoutSeconds"] != 300
        or terraform["applyExitCode"] != 0
        or not isinstance(terraform["resourceChangeCount"], int)
        or isinstance(terraform["resourceChangeCount"], bool)
        or terraform["resourceChangeCount"] < 1
        or any(
            not isinstance(counts[key], int)
            or isinstance(counts[key], bool)
            or counts[key] < 0
            for key in ACTION_COUNT_KEYS
        )
        or counts["delete"] != 0
        or counts["replace"] != 0
        or counts["create"] + counts["update"] <= 0
        or sum(counts.values()) != terraform["resourceChangeCount"]
    ):
        fail("foundation_apply_receipt_terraform_invalid")
    before = _validate_state_shape(terraform["stateBefore"], present_required=False)
    after = _validate_state_shape(terraform["stateAfter"], present_required=True)
    if (
        after["serial"] <= before["serial"]
        or (
            before["present"]
            and before["lineageDigest"] != after["lineageDigest"]
        )
    ):
        fail("foundation_apply_receipt_state_transition_invalid")

    signer = strict_keys(
        value["signer"],
        {"executionClass", "keyVersionResource", "publicKeyDigest"},
        "foundation_apply_receipt_signer_invalid",
    )
    if (
        signer["executionClass"] != "github-hosted-runner"
        or not isinstance(signer["keyVersionResource"], str)
        or not RECEIPT_KEY.fullmatch(signer["keyVersionResource"])
    ):
        fail("foundation_apply_receipt_signer_invalid")
    require_digest(signer["publicKeyDigest"], "foundation_apply_receipt_signer_invalid")
    if value["claims"] != {
        "exactReviewedPlanApplied": True,
        "infrastructureApplied": True,
        "receiptSelfAttested": True,
        "independentlyObserved": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("foundation_apply_receipt_claims_invalid")
    return canonical_digest(value)


def build_receipt(
    *,
    verified_package_path: Path,
    state_before_path: Path | None,
    state_after_path: Path,
    apply_id: str,
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
    expected_public_key_digest: str,
    expected_plan_statement_digest: str,
) -> dict[str, Any]:
    authority, release_set, policy = load_contract()
    authority_digest = validate_authority(authority, release_set, policy)
    if (
        not APPLY_ID.fullmatch(apply_id)
        or not SHA.fullmatch(source_revision)
        or workflow_run_attempt != "1"
        or apply_id
        != f"orchestra-foundation-apply-{workflow_run_id}.{workflow_run_attempt}"
        or not workflow_run_id.isdigit()
        or workflow_run_id.startswith("0")
        or not actor_id.isdigit()
        or actor_id.startswith("0")
        or not isinstance(reason, str)
        or not 12 <= len(reason.strip()) <= 500
        or not RECEIPT_KEY.fullmatch(signing_key)
    ):
        fail("foundation_apply_receipt_input_invalid")
    require_digest(
        environment_approval_digest,
        "foundation_apply_receipt_environment_approval_invalid",
    )
    require_digest(
        expected_public_key_digest,
        "foundation_apply_receipt_public_key_digest_invalid",
    )
    require_digest(
        expected_plan_statement_digest,
        "foundation_apply_receipt_plan_statement_digest_invalid",
    )
    started = parse_utc(started_at, "foundation_apply_receipt_time_invalid")
    completed = parse_utc(completed_at, "foundation_apply_receipt_time_invalid")
    if completed < started or completed - started > timedelta(minutes=90):
        fail("foundation_apply_receipt_time_invalid")
    if file_digest(signing_public_key) != expected_public_key_digest:
        fail("foundation_apply_receipt_public_key_mismatch")
    verified, _ = load_json_object(
        verified_package_path, "foundation_apply_verified_package_invalid"
    )
    statement = verified.get("statement")
    if not isinstance(statement, dict):
        fail("foundation_apply_verified_package_invalid")
    validate_statement(statement, authority)
    expected_verified_keys = {
        "schemaVersion",
        "planId",
        "sourceRevision",
        "statement",
        "statementDigest",
        "summaryCanonicalDigest",
        "planDigest",
        "bucket",
        "prefix",
        "objects",
        "completionMarkerGeneration",
        "resourceChangeCount",
        "actionCounts",
        "verifiedAt",
    }
    strict_keys(
        verified, expected_verified_keys, "foundation_apply_verified_package_invalid"
    )
    if (
        verified["schemaVersion"] != 1
        or verified["sourceRevision"] != source_revision
        or verified["planId"] != statement["planId"]
        or verified["statementDigest"] != expected_plan_statement_digest
        or verified["planDigest"] != statement["package"]["planDigest"]
        or verified["summaryCanonicalDigest"]
        != statement["package"]["summaryCanonicalDigest"]
    ):
        fail("foundation_apply_verified_package_binding_invalid")
    before = _state_projection(state_before_path)
    after = _state_projection(state_after_path)
    if (
        not after["present"]
        or after["serial"] <= before["serial"]
        or (
            before["present"]
            and before["lineageDigest"] != after["lineageDigest"]
        )
    ):
        fail("foundation_apply_state_transition_invalid")
    receipt = {
        "schemaVersion": 1,
        "kind": KIND,
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab",
        "executionMode": "live",
        "applyId": apply_id,
        "planId": verified["planId"],
        "bindings": expected_receipt_bindings(
            authority, authority_digest, verified
        ),
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
        "planCustody": {
            "bucket": verified["bucket"],
            "prefix": verified["prefix"],
            "managedFolder": "foundation-plans/",
            "objectCount": 5,
            "objects": verified["objects"],
            "completionMarkerObject": (
                "foundation-plan-package-signature.sigstore.json"
            ),
            "completionMarkerGeneration": verified[
                "completionMarkerGeneration"
            ],
            "planPackageSignatureVerified": True,
            "exactPlanReplayed": True,
        },
        "terraform": {
            "version": "1.14.6",
            "stateLockUsed": True,
            "lockTimeoutSeconds": 300,
            "applyExitCode": 0,
            "resourceChangeCount": verified["resourceChangeCount"],
            "actionCounts": verified["actionCounts"],
            "stateBefore": before,
            "stateAfter": after,
        },
        "signer": {
            "executionClass": "github-hosted-runner",
            "keyVersionResource": signing_key,
            "publicKeyDigest": expected_public_key_digest,
        },
        "claims": {
            "exactReviewedPlanApplied": True,
            "infrastructureApplied": True,
            "receiptSelfAttested": True,
            "independentlyObserved": False,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
        },
    }
    validate_receipt(receipt, authority)
    return receipt


def write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    if path.exists() or not path.parent.is_dir():
        fail("foundation_apply_receipt_output_invalid")
    encoded = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except OSError as error:
        raise ValueError("foundation_apply_receipt_write_failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--verified-package", type=Path, required=True)
    build.add_argument("--state-before", type=Path)
    build.add_argument("--state-after", type=Path, required=True)
    build.add_argument("--apply-id", required=True)
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
    build.add_argument("--expected-public-key-digest", required=True)
    build.add_argument("--expected-plan-statement-digest", required=True)
    build.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--receipt", type=Path, required=True)
    validate.add_argument("--signing-public-key", type=Path)
    validate.add_argument("--signature-bundle", type=Path)
    validate.add_argument("--expected-public-key-digest")
    validate.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)

    authority, release_set, policy = load_contract()
    validate_authority(authority, release_set, policy)
    signature_verified = False
    if args.command == "build":
        receipt = build_receipt(
            verified_package_path=args.verified_package.resolve(),
            state_before_path=(
                args.state_before.resolve() if args.state_before else None
            ),
            state_after_path=args.state_after.resolve(),
            apply_id=args.apply_id,
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
            expected_public_key_digest=args.expected_public_key_digest,
            expected_plan_statement_digest=args.expected_plan_statement_digest,
        )
        write_new(args.output, receipt)
    else:
        signature_inputs = (
            args.signing_public_key,
            args.signature_bundle,
            args.expected_public_key_digest,
        )
        if any(value is not None for value in signature_inputs) and not all(
            value is not None for value in signature_inputs
        ):
            fail("foundation_apply_receipt_signature_inputs_incomplete")
        receipt, _ = load_json_object(
            args.receipt.resolve(), "foundation_apply_receipt_json_invalid"
        )
        digest = validate_receipt(receipt, authority)
        if all(value is not None for value in signature_inputs):
            expected = require_digest(
                args.expected_public_key_digest,
                "foundation_apply_receipt_public_key_digest_invalid",
            )
            if (
                file_digest(args.signing_public_key.resolve()) != expected
                or receipt["signer"]["publicKeyDigest"] != expected
                or not args.signature_bundle.resolve().is_file()
            ):
                fail("foundation_apply_receipt_signature_binding_invalid")
            run_cosign(
                args.cosign,
                [
                    "verify-blob",
                    "--bundle",
                    str(args.signature_bundle.resolve()),
                    "--key",
                    str(args.signing_public_key.resolve()),
                    str(args.receipt.resolve()),
                ],
                "foundation_apply_receipt_signature_verification_failed",
            )
            signature_verified = True
    if args.command == "build":
        digest = validate_receipt(receipt, authority)
    print(
        "foundation_apply_receipt_valid "
        f"applyId={receipt['applyId']} planId={receipt['planId']} "
        f"digest={digest} signatureVerified={str(signature_verified).lower()} "
        "infrastructureApplied=true receiptSelfAttested=true "
        "independentlyObserved=false campaignEvidence=false "
        "referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
