#!/usr/bin/env python3
"""Build and validate immutable, signed foundation plan package statements."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.foundation_apply_execution import (
        PROFILE_ID,
        load_contract,
        validate_authority,
    )
    from scripts.foundation_plan_summary import validate_summary
    from scripts.prerequisite_observation import blob_digest, parse_utc
    from scripts.validate_repository import DIGEST, canonical_digest
except ModuleNotFoundError:
    from foundation_apply_execution import (
        PROFILE_ID,
        load_contract,
        validate_authority,
    )
    from foundation_plan_summary import validate_summary
    from prerequisite_observation import blob_digest, parse_utc
    from validate_repository import DIGEST, canonical_digest


KIND = "orchestra.reference-lab.foundation-plan-package.v1"
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REF = "refs/heads/main"
WORKFLOW_REF = f"{REPOSITORY}/.github/workflows/foundation-plan.yml@{REF}"
ENVIRONMENT = "reference-lab-foundation-plan"
PLAN_ID = re.compile(r"^orchestra-foundation-plan-[1-9][0-9]*\.[1-9][0-9]*$")
SHA = re.compile(r"^[a-f0-9]{40}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
PLAN_KEY = re.compile(
    r"^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/"
    r"europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/"
    r"foundation-plan-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
MAX_PLAN_BYTES = 1024 * 1024 * 1024
MAX_SUMMARY_BYTES = 16 * 1024 * 1024


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


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ValueError("foundation_plan_package_file_read_failed") from error
    return f"sha256:{digest.hexdigest()}"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail("foundation_plan_package_json_duplicate_key")
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


def expected_statement_bindings(
    authority: dict[str, Any],
    authority_digest: str,
    prerequisite_projection_digest: str,
) -> dict[str, str]:
    bindings = authority["bindings"]
    return {
        "topologyDigest": bindings["topologyDigest"],
        "releaseSetDigest": bindings["releaseSetDigest"],
        "prerequisitePolicyDigest": bindings["prerequisitePolicyDigest"],
        "prerequisiteProjectionDigest": prerequisite_projection_digest,
        "foundationApplyAuthorityDigest": authority_digest,
        "foundationPlanSummarySchemaDigest": bindings[
            "foundationPlanSummarySchemaDigest"
        ],
        "planPackageSchemaDigest": bindings["planPackageSchemaDigest"],
    }


def validate_statement(value: dict[str, Any], authority: dict[str, Any]) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "targetClass",
            "executionMode",
            "planId",
            "bindings",
            "source",
            "package",
            "signer",
            "claims",
        },
        "foundation_plan_package_keys_invalid",
    )
    plan_id = value["planId"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or not isinstance(plan_id, str)
        or not PLAN_ID.fullmatch(plan_id)
    ):
        fail("foundation_plan_package_identity_invalid")
    bindings = strict_keys(
        value["bindings"],
        {
            "topologyDigest",
            "releaseSetDigest",
            "prerequisitePolicyDigest",
            "prerequisiteProjectionDigest",
            "foundationApplyAuthorityDigest",
            "foundationPlanSummarySchemaDigest",
            "planPackageSchemaDigest",
        },
        "foundation_plan_package_bindings_invalid",
    )
    prerequisite_projection_digest = require_digest(
        bindings["prerequisiteProjectionDigest"],
        "foundation_plan_package_bindings_invalid",
    )
    authority_digest = canonical_digest(authority)
    if bindings != expected_statement_bindings(
        authority, authority_digest, prerequisite_projection_digest
    ):
        fail("foundation_plan_package_bindings_invalid")

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
        },
        "foundation_plan_package_source_invalid",
    )
    if (
        source["repository"] != REPOSITORY
        or source["ref"] != REF
        or source["workflowRef"] != WORKFLOW_REF
        or source["environment"] != ENVIRONMENT
        or not isinstance(source["revision"], str)
        or not SHA.fullmatch(source["revision"])
        or source["workflowRunAttempt"] != "1"
        or plan_id
        != (
            f"orchestra-foundation-plan-{source['workflowRunId']}."
            f"{source['workflowRunAttempt']}"
        )
        or not isinstance(source["workflowRunId"], str)
        or not source["workflowRunId"].isdigit()
        or source["workflowRunId"].startswith("0")
    ):
        fail("foundation_plan_package_source_invalid")
    for key in (
        "environmentApprovalDigest",
        "actorIdentityDigest",
        "authorizationReasonDigest",
    ):
        require_digest(source[key], "foundation_plan_package_source_invalid")

    package = strict_keys(
        value["package"],
        {
            "bucket",
            "prefix",
            "managedFolder",
            "requiredObjectCount",
            "planObject",
            "planDigest",
            "planSizeBytes",
            "summaryObject",
            "summaryDigest",
            "summaryCanonicalDigest",
            "summarySizeBytes",
            "signingPublicKeyObject",
            "statementObject",
            "signatureObject",
            "createOnly",
            "signatureUploadedLast",
        },
        "foundation_plan_package_artifacts_invalid",
    )
    expected_prefix = (
        f"foundation-plans/v1/{PROFILE_ID}/{source['revision']}/{plan_id}"
    )
    if (
        not isinstance(package["bucket"], str)
        or not BUCKET.fullmatch(package["bucket"])
        or package["prefix"] != expected_prefix
        or package["managedFolder"] != "foundation-plans/"
        or package["requiredObjectCount"] != 5
        or package["planObject"] != "foundation.tfplan"
        or not isinstance(package["planSizeBytes"], int)
        or isinstance(package["planSizeBytes"], bool)
        or not 1 <= package["planSizeBytes"] <= MAX_PLAN_BYTES
        or package["summaryObject"] != "foundation-plan-summary.json"
        or not isinstance(package["summarySizeBytes"], int)
        or isinstance(package["summarySizeBytes"], bool)
        or not 1 <= package["summarySizeBytes"] <= MAX_SUMMARY_BYTES
        or package["signingPublicKeyObject"]
        != "foundation-plan-package-public-key.pem"
        or package["statementObject"] != "foundation-plan-package-statement.json"
        or package["signatureObject"]
        != "foundation-plan-package-signature.sigstore.json"
        or package["createOnly"] is not True
        or package["signatureUploadedLast"] is not True
    ):
        fail("foundation_plan_package_artifacts_invalid")
    for key in ("planDigest", "summaryDigest", "summaryCanonicalDigest"):
        require_digest(package[key], "foundation_plan_package_artifacts_invalid")

    signer = strict_keys(
        value["signer"],
        {"executionClass", "keyVersionResource", "publicKeyDigest", "signedAt"},
        "foundation_plan_package_signer_invalid",
    )
    if (
        signer["executionClass"] != "github-hosted-runner"
        or not isinstance(signer["keyVersionResource"], str)
        or not PLAN_KEY.fullmatch(signer["keyVersionResource"])
    ):
        fail("foundation_plan_package_signer_invalid")
    require_digest(signer["publicKeyDigest"], "foundation_plan_package_signer_invalid")
    parse_utc(signer["signedAt"], "foundation_plan_package_signer_invalid")
    if value["claims"] != {
        "reviewablePlanPackage": True,
        "applyAuthorized": False,
        "infrastructureApplied": False,
        "independentlyObserved": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("foundation_plan_package_claims_invalid")
    return canonical_digest(value)


def build_statement(
    *,
    plan_path: Path,
    summary_path: Path,
    bucket: str,
    plan_id: str,
    environment_approval_digest: str,
    signing_key: str,
    signing_public_key: Path,
    expected_public_key_digest: str,
    signed_at: str,
) -> dict[str, Any]:
    authority, release_set, policy = load_contract()
    authority_digest = validate_authority(authority, release_set, policy)
    if not PLAN_ID.fullmatch(plan_id):
        fail("foundation_plan_package_plan_id_invalid")
    if not BUCKET.fullmatch(bucket):
        fail("foundation_plan_package_bucket_invalid")
    require_digest(
        environment_approval_digest,
        "foundation_plan_package_environment_approval_invalid",
    )
    require_digest(
        expected_public_key_digest, "foundation_plan_package_public_key_invalid"
    )
    if not PLAN_KEY.fullmatch(signing_key):
        fail("foundation_plan_package_signing_key_invalid")
    parse_utc(signed_at, "foundation_plan_package_signed_at_invalid")
    plan_path = plan_path.resolve()
    summary_path = summary_path.resolve()
    signing_public_key = signing_public_key.resolve()
    if (
        not plan_path.is_file()
        or not summary_path.is_file()
        or not signing_public_key.is_file()
        or not 1 <= plan_path.stat().st_size <= MAX_PLAN_BYTES
        or not 1 <= summary_path.stat().st_size <= MAX_SUMMARY_BYTES
        or file_digest(signing_public_key) != expected_public_key_digest
    ):
        fail("foundation_plan_package_artifact_invalid")
    summary, summary_bytes = load_json_object(
        summary_path, "foundation_plan_package_summary_json_invalid"
    )
    summary_canonical_digest = validate_summary(summary)
    if (
        summary["targetClass"] != "vendor-reference-lab"
        or summary["executionMode"] != "live"
        or summary["source"]["workflowRunAttempt"] != "1"
        or plan_id
        != (
            f"orchestra-foundation-plan-{summary['source']['workflowRunId']}."
            f"{summary['source']['workflowRunAttempt']}"
        )
        or summary["terraform"]["planDigest"] != file_digest(plan_path)
    ):
        fail("foundation_plan_package_summary_binding_invalid")
    source = summary["source"]
    prefix = f"foundation-plans/v1/{PROFILE_ID}/{source['revision']}/{plan_id}"
    statement = {
        "schemaVersion": 1,
        "kind": KIND,
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab",
        "executionMode": "live",
        "planId": plan_id,
        "bindings": expected_statement_bindings(
            authority,
            authority_digest,
            summary["bindings"]["prerequisiteProjectionDigest"],
        ),
        "source": {
            "repository": source["repository"],
            "revision": source["revision"],
            "ref": source["ref"],
            "workflowRef": source["workflowRef"],
            "environment": source["environment"],
            "workflowRunId": source["workflowRunId"],
            "workflowRunAttempt": source["workflowRunAttempt"],
            "environmentApprovalDigest": environment_approval_digest,
            "actorIdentityDigest": source["actorIdentityDigest"],
            "authorizationReasonDigest": source["authorizationReasonDigest"],
        },
        "package": {
            "bucket": bucket,
            "prefix": prefix,
            "managedFolder": "foundation-plans/",
            "requiredObjectCount": 5,
            "planObject": "foundation.tfplan",
            "planDigest": file_digest(plan_path),
            "planSizeBytes": plan_path.stat().st_size,
            "summaryObject": "foundation-plan-summary.json",
            "summaryDigest": blob_digest(summary_bytes),
            "summaryCanonicalDigest": summary_canonical_digest,
            "summarySizeBytes": len(summary_bytes),
            "signingPublicKeyObject": "foundation-plan-package-public-key.pem",
            "statementObject": "foundation-plan-package-statement.json",
            "signatureObject": "foundation-plan-package-signature.sigstore.json",
            "createOnly": True,
            "signatureUploadedLast": True,
        },
        "signer": {
            "executionClass": "github-hosted-runner",
            "keyVersionResource": signing_key,
            "publicKeyDigest": expected_public_key_digest,
            "signedAt": signed_at,
        },
        "claims": {
            "reviewablePlanPackage": True,
            "applyAuthorized": False,
            "infrastructureApplied": False,
            "independentlyObserved": False,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
        },
    }
    validate_statement(statement, authority)
    return statement


def write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    if path.exists() or not path.parent.is_dir():
        fail("foundation_plan_package_output_invalid")
    encoded = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
    except OSError as error:
        raise ValueError("foundation_plan_package_write_failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--plan", type=Path, required=True)
    build.add_argument("--summary", type=Path, required=True)
    build.add_argument("--bucket", required=True)
    build.add_argument("--plan-id", required=True)
    build.add_argument("--environment-approval-digest", required=True)
    build.add_argument("--signing-key", required=True)
    build.add_argument("--signing-public-key", type=Path, required=True)
    build.add_argument("--expected-public-key-digest", required=True)
    build.add_argument("--signed-at", required=True)
    build.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--statement", type=Path, required=True)
    validate.add_argument("--signing-public-key", type=Path)
    validate.add_argument("--signature-bundle", type=Path)
    validate.add_argument("--expected-public-key-digest")
    validate.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)

    authority, release_set, policy = load_contract()
    validate_authority(authority, release_set, policy)
    signature_verified = False
    if args.command == "build":
        statement = build_statement(
            plan_path=args.plan,
            summary_path=args.summary,
            bucket=args.bucket,
            plan_id=args.plan_id,
            environment_approval_digest=args.environment_approval_digest,
            signing_key=args.signing_key,
            signing_public_key=args.signing_public_key,
            expected_public_key_digest=args.expected_public_key_digest,
            signed_at=args.signed_at,
        )
        write_new(args.output, statement)
    else:
        signature_inputs = (
            args.signing_public_key,
            args.signature_bundle,
            args.expected_public_key_digest,
        )
        if any(value is not None for value in signature_inputs) and not all(
            value is not None for value in signature_inputs
        ):
            fail("foundation_plan_package_signature_inputs_incomplete")
        statement, _ = load_json_object(
            args.statement.resolve(), "foundation_plan_package_json_invalid"
        )
        digest = validate_statement(statement, authority)
        if all(value is not None for value in signature_inputs):
            expected = require_digest(
                args.expected_public_key_digest,
                "foundation_plan_package_public_key_digest_invalid",
            )
            if (
                file_digest(args.signing_public_key.resolve()) != expected
                or statement["signer"]["publicKeyDigest"] != expected
                or not args.signature_bundle.resolve().is_file()
            ):
                fail("foundation_plan_package_signature_binding_invalid")
            run_cosign(
                args.cosign,
                [
                    "verify-blob",
                    "--bundle",
                    str(args.signature_bundle.resolve()),
                    "--key",
                    str(args.signing_public_key.resolve()),
                    str(args.statement.resolve()),
                ],
                "foundation_plan_package_signature_verification_failed",
            )
            signature_verified = True
    if args.command == "build":
        digest = validate_statement(statement, authority)
    print(
        "foundation_plan_package_valid "
        f"planId={statement['planId']} digest={digest} "
        f"signatureVerified={str(signature_verified).lower()} "
        "applyAuthorized=false infrastructureApplied=false "
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
