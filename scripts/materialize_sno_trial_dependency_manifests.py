#!/usr/bin/env python3
"""Materialize the SNO dependency candidate into private operator storage."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.sno_trial_dependency_inputs import (
        CLAIMS,
        load_json,
        parse_utc,
        utc_text,
        validate_assessment,
    )
    from scripts.validate_repository import ROOT, canonical_digest
    from scripts.validate_sno_trial_dependency_manifests import (
        KUSTOMIZATION_PATH,
        RESOURCE_FILES,
        STORAGE_CLASS_PLACEHOLDER,
        load_resources,
        load_validated_candidate,
        manifest_set_digest,
    )
except ModuleNotFoundError:
    from sno_trial_dependency_inputs import (
        CLAIMS,
        load_json,
        parse_utc,
        utc_text,
        validate_assessment,
    )
    from validate_repository import ROOT, canonical_digest
    from validate_sno_trial_dependency_manifests import (
        KUSTOMIZATION_PATH,
        RESOURCE_FILES,
        STORAGE_CLASS_PLACEHOLDER,
        load_resources,
        load_validated_candidate,
        manifest_set_digest,
    )


KIND = "orchestra.openshift.sno-trial-dependency-manifest-materialization.v1"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
MAX_OBSERVATION_AGE = timedelta(hours=1)
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
KUBE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
BLOCKERS = [
    "UPSTREAM_VERIFICATION_PENDING",
    "DESTINATION_MIRROR_PROOF_MISSING",
    "LAB_SIGNATURE_MISSING",
    "MODEL_ARTIFACT_DIGEST_PROOF_MISSING",
    "CERTIFICATE_VALIDITY_PROOF_MISSING",
    "OPENSHIFT_SERVER_SIDE_DRY_RUN_MISSING",
    "LIVE_DEPENDENCY_CONNECTIVITY_MISSING",
    "ACTIVATION_REVIEW_MISSING",
]
CONTROLS = {
    "scope": "sno-engineering-trial-valkey-and-model-backend-only",
    "sourceCandidateMutated": False,
    "manifestsMaterialized": True,
    "storageClassNameStoredInReceipt": False,
    "secretObjectsEmitted": False,
    "secretValuesObserved": False,
    "secretValuesStored": False,
    "modelBytesStored": False,
    "activeKustomizationReferenced": False,
    "serverSideDryRunExecuted": False,
    "connectivityVerified": False,
    "cloudMutationAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def private_regular_file(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        fail(code)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o077
    ):
        fail(code)


def restricted_path(path: Path, *, existing: bool, code: str) -> Path:
    restricted = (ROOT / "restricted").resolve()
    lexical = path.absolute()
    try:
        resolved = path.resolve(strict=existing)
        resolved.relative_to(restricted)
    except (OSError, ValueError):
        fail(code)
    if lexical != resolved:
        fail(code)
    return resolved


def read_storage_class_name(path: Path) -> str:
    resolved = restricted_path(
        path,
        existing=True,
        code="sno_dependency_materialization_storage_file_invalid",
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o077
            or metadata.st_size > 255
        ):
            fail("sno_dependency_materialization_storage_file_invalid")
        with os.fdopen(descriptor, "r", encoding="ascii") as stream:
            descriptor = None
            raw = stream.read(256)
    except (OSError, UnicodeError):
        fail("sno_dependency_materialization_storage_file_invalid")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        len(raw) > 254
        or raw not in {raw.strip(), f"{raw.strip()}\n"}
        or not KUBE_NAME.fullmatch(raw.strip())
    ):
        fail("sno_dependency_materialization_storage_name_invalid")
    return raw.strip()


def replace_exact(value: Any, replacement: str) -> tuple[Any, int]:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            replaced, nested = replace_exact(item, replacement)
            result[key] = replaced
            count += nested
        return result, count
    if isinstance(value, list):
        result_list = []
        count = 0
        for item in value:
            replaced, nested = replace_exact(item, replacement)
            result_list.append(replaced)
            count += nested
        return result_list, count
    if value == STORAGE_CLASS_PLACEHOLDER:
        return replacement, 1
    return copy.deepcopy(value), 0


def materialize_resources(storage_class_name: str) -> tuple[list[dict[str, Any]], int]:
    resources = load_resources()
    result: list[dict[str, Any]] = []
    count = 0
    for resource in resources:
        replaced, resource_count = replace_exact(resource, storage_class_name)
        if not isinstance(replaced, dict):
            fail("sno_dependency_materialization_resource_invalid")
        result.append(replaced)
        count += resource_count
    if count != 1:
        fail("sno_dependency_materialization_placeholder_count_invalid")
    if any(STORAGE_CLASS_PLACEHOLDER in json.dumps(item) for item in result):
        fail("sno_dependency_materialization_placeholder_unresolved")
    return result, count


def resource_digests(resources: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {"file": filename, "digest": canonical_digest(resource)}
        for filename, resource in zip(RESOURCE_FILES, resources, strict=True)
    ]


def validate_input_report(
    report: dict[str, Any], storage_class_name: str, materialized_at: datetime
) -> None:
    validate_assessment(report)
    assessed_at = parse_utc(
        report["assessedAt"], "sno_dependency_materialization_report_time_invalid"
    )
    observed_at = parse_utc(
        report["observedAt"], "sno_dependency_materialization_report_time_invalid"
    )
    if materialized_at.tzinfo is None:
        fail("sno_dependency_materialization_input_report_stale")
    current = materialized_at.astimezone(timezone.utc)
    if (
        report["executionMode"] != "live-read-only"
        or report["decision"]
        != {"status": "DEPENDENCY_INPUTS_OBSERVED", "reasonCodes": []}
        or report["aggregate"]["unresolvedCount"] != 0
        or report["aggregate"]["storageClassNameDigest"]
        != canonical_digest(storage_class_name)
    ):
        fail("sno_dependency_materialization_input_report_not_ready")
    if (
        assessed_at > current
        or observed_at > assessed_at
        or current - observed_at > MAX_OBSERVATION_AGE
    ):
        fail("sno_dependency_materialization_input_report_stale")


def build_receipt(
    report: dict[str, Any],
    resources: list[dict[str, Any]],
    storage_class_name: str,
    replacement_count: int,
    materialization_id: str,
    materialized_at: datetime,
) -> dict[str, Any]:
    if not IDENTIFIER.fullmatch(materialization_id):
        fail("sno_dependency_materialization_id_invalid")
    candidate = load_validated_candidate()
    kustomization = KUSTOMIZATION_PATH.read_text(encoding="utf-8")
    receipt = {
        "schemaVersion": 1,
        "kind": KIND,
        "materializationId": materialization_id,
        "profileId": PROFILE_ID,
        "targetClass": "engineering-trial",
        "executionMode": "local-restricted-materialization",
        "materializedAt": utc_text(materialized_at),
        "bindings": {
            "candidateId": candidate["candidateId"],
            "candidateDigest": candidate["candidateDigest"],
            "sourceManifestSetDigest": candidate["manifestSetDigest"],
            "inputObservationId": report["assessmentId"],
            "inputObservationDigest": report["reportDigest"],
            "storageClassNameDigest": canonical_digest(storage_class_name),
        },
        "outputs": {
            "resourceCount": len(resources),
            "storageClassReplacementCount": replacement_count,
            "kustomizationDigest": canonical_digest(kustomization),
            "materializedManifestSetDigest": manifest_set_digest(resources),
            "resourceDigests": resource_digests(resources),
        },
        "decision": {
            "state": "materialized-non-authorizing",
            "remainingReasonCodes": BLOCKERS,
        },
        "controls": copy.deepcopy(CONTROLS),
        "claims": copy.deepcopy(CLAIMS),
    }
    receipt["receiptDigest"] = canonical_digest(receipt)
    validate_receipt(receipt)
    return receipt


def validate_receipt(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "materializationId",
            "profileId",
            "targetClass",
            "executionMode",
            "materializedAt",
            "bindings",
            "outputs",
            "decision",
            "controls",
            "claims",
            "receiptDigest",
        },
        "sno_dependency_materialization_receipt_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or not IDENTIFIER.fullmatch(str(value["materializationId"]))
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "local-restricted-materialization"
    ):
        fail("sno_dependency_materialization_receipt_invalid")
    parse_utc(
        value["materializedAt"],
        "sno_dependency_materialization_receipt_time_invalid",
    )
    candidate = load_validated_candidate()
    bindings = value["bindings"]
    exact_keys(
        bindings,
        {
            "candidateId",
            "candidateDigest",
            "sourceManifestSetDigest",
            "inputObservationId",
            "inputObservationDigest",
            "storageClassNameDigest",
        },
        "sno_dependency_materialization_bindings_invalid",
    )
    if (
        bindings["candidateId"] != candidate["candidateId"]
        or bindings["candidateDigest"] != candidate["candidateDigest"]
        or bindings["sourceManifestSetDigest"] != candidate["manifestSetDigest"]
        or not IDENTIFIER.fullmatch(str(bindings["inputObservationId"]))
        or any(
            not DIGEST.fullmatch(str(bindings[key]))
            for key in (
                "inputObservationDigest",
                "storageClassNameDigest",
            )
        )
    ):
        fail("sno_dependency_materialization_bindings_invalid")
    outputs = value["outputs"]
    exact_keys(
        outputs,
        {
            "resourceCount",
            "storageClassReplacementCount",
            "kustomizationDigest",
            "materializedManifestSetDigest",
            "resourceDigests",
        },
        "sno_dependency_materialization_outputs_invalid",
    )
    digests = outputs["resourceDigests"]
    if (
        outputs["resourceCount"] != len(RESOURCE_FILES)
        or outputs["storageClassReplacementCount"] != 1
        or outputs["kustomizationDigest"]
        != canonical_digest(KUSTOMIZATION_PATH.read_text(encoding="utf-8"))
        or not DIGEST.fullmatch(str(outputs["materializedManifestSetDigest"]))
        or not isinstance(digests, list)
        or len(digests) != len(RESOURCE_FILES)
        or [item.get("file") for item in digests] != RESOURCE_FILES
        or any(
            set(item) != {"file", "digest"} or not DIGEST.fullmatch(str(item["digest"]))
            for item in digests
        )
    ):
        fail("sno_dependency_materialization_outputs_invalid")
    if value["decision"] != {
        "state": "materialized-non-authorizing",
        "remainingReasonCodes": BLOCKERS,
    }:
        fail("sno_dependency_materialization_decision_invalid")
    if value["controls"] != CONTROLS or value["claims"] != CLAIMS:
        fail("sno_dependency_materialization_claims_invalid")
    digest = value["receiptDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("receiptDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_dependency_materialization_receipt_digest_invalid")


def validate_materialized_directory(directory: Path) -> dict[str, Any]:
    resolved = restricted_path(
        directory,
        existing=True,
        code="sno_dependency_materialization_directory_invalid",
    )
    if (
        resolved.is_symlink()
        or not resolved.is_dir()
        or resolved.stat().st_mode & 0o077
    ):
        fail("sno_dependency_materialization_directory_invalid")
    actual = sorted(path.name for path in resolved.iterdir())
    expected = sorted(
        [*RESOURCE_FILES, "kustomization.yaml", "materialization-receipt.json"]
    )
    if actual != expected:
        fail("sno_dependency_materialization_directory_shape_invalid")
    for name in expected:
        private_regular_file(
            resolved / name,
            "sno_dependency_materialization_output_file_invalid",
        )
    receipt = load_json(resolved / "materialization-receipt.json")
    validate_receipt(receipt)
    resources = [load_json(resolved / name) for name in RESOURCE_FILES]
    if any(item.get("kind") == "Secret" for item in resources):
        fail("sno_dependency_materialization_secret_object_forbidden")
    try:
        valkey = resources[RESOURCE_FILES.index("valkey-stateful-set.json")]
        storage_class_name = valkey["spec"]["volumeClaimTemplates"][0]["spec"][
            "storageClassName"
        ]
    except (KeyError, IndexError, TypeError):
        fail("sno_dependency_materialization_storage_binding_invalid")
    if (
        not isinstance(storage_class_name, str)
        or not KUBE_NAME.fullmatch(storage_class_name)
        or canonical_digest(storage_class_name)
        != receipt["bindings"]["storageClassNameDigest"]
    ):
        fail("sno_dependency_materialization_storage_binding_invalid")
    expected_resources, replacement_count = materialize_resources(storage_class_name)
    if replacement_count != 1 or resources != expected_resources:
        fail("sno_dependency_materialization_resource_lineage_invalid")
    if (
        manifest_set_digest(resources)
        != receipt["outputs"]["materializedManifestSetDigest"]
    ):
        fail("sno_dependency_materialization_manifest_digest_invalid")
    if resource_digests(resources) != receipt["outputs"]["resourceDigests"]:
        fail("sno_dependency_materialization_resource_digests_invalid")
    if (
        canonical_digest((resolved / "kustomization.yaml").read_text(encoding="utf-8"))
        != receipt["outputs"]["kustomizationDigest"]
    ):
        fail("sno_dependency_materialization_kustomization_invalid")
    return receipt


def write_create_only(path: Path, content: str) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(content)
    except OSError:
        fail("sno_dependency_materialization_output_write_failed")


def emit_directory(
    output_directory: Path,
    resources: list[dict[str, Any]],
    receipt: dict[str, Any],
) -> None:
    resolved = restricted_path(
        output_directory,
        existing=False,
        code="sno_dependency_materialization_output_invalid",
    )
    if output_directory.exists() or output_directory.is_symlink():
        fail("sno_dependency_materialization_output_invalid")
    parent = resolved.parent
    if not parent.is_dir() or parent.is_symlink():
        fail("sno_dependency_materialization_output_invalid")
    staging = Path(tempfile.mkdtemp(prefix=".dependency-materialization-", dir=parent))
    staging.chmod(0o700)
    try:
        for name, resource in zip(RESOURCE_FILES, resources, strict=True):
            write_create_only(
                staging / name,
                json.dumps(resource, sort_keys=True, indent=2, ensure_ascii=True)
                + "\n",
            )
        write_create_only(
            staging / "kustomization.yaml",
            KUSTOMIZATION_PATH.read_text(encoding="ascii"),
        )
        write_create_only(
            staging / "materialization-receipt.json",
            json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        )
        os.rename(staging, resolved)
    except (OSError, ValueError):
        shutil.rmtree(staging, ignore_errors=True)
        fail("sno_dependency_materialization_output_write_failed")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    materialize = commands.add_parser("materialize")
    materialize.add_argument("--input-report", type=Path, required=True)
    materialize.add_argument("--storage-class-file", type=Path, required=True)
    materialize.add_argument("--output-dir", type=Path, required=True)
    materialize.add_argument("--materialization-id", required=True)
    materialize.add_argument("--at", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--directory", type=Path, required=True)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "materialize":
        report = load_json(args.input_report)
        storage_class_name = read_storage_class_name(args.storage_class_file)
        materialized_at = parse_utc(
            args.at, "sno_dependency_materialization_time_invalid"
        )
        validate_input_report(report, storage_class_name, materialized_at)
        resources, replacement_count = materialize_resources(storage_class_name)
        receipt = build_receipt(
            report,
            resources,
            storage_class_name,
            replacement_count,
            args.materialization_id,
            materialized_at,
        )
        emit_directory(args.output_dir, resources, receipt)
    else:
        receipt = validate_materialized_directory(args.directory)
    print(
        "sno_dependency_materialization_valid "
        f"digest={receipt['receiptDigest']} "
        f"manifestSetDigest={receipt['outputs']['materializedManifestSetDigest']} "
        "deploymentAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
