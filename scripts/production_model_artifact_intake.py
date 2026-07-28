#!/usr/bin/env python3
"""Inspect production model source files without copying or admitting them."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_production_model_artifact_candidate import (
        CANDIDATE_PATH,
        SCHEMA_PATH as CANDIDATE_SCHEMA_PATH,
        validate_candidate,
    )
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_production_model_artifact_candidate import (
        CANDIDATE_PATH,
        SCHEMA_PATH as CANDIDATE_SCHEMA_PATH,
        validate_candidate,
    )
    from validate_repository import ROOT, canonical_digest, load_json


POLICY_PATH = ROOT / "config" / "production-model-artifact-intake-policy.lock.json"
SCHEMA_PATH = (
    ROOT / "schemas" / "production-model-artifact-intake-observation-v1.schema.json"
)
BOM_PATH = ROOT / "config" / "dependency-bom.lock.json"
ADMISSION_PATH = ROOT / "config" / "dependency-admission.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
TOPOLOGY_PATH = ROOT / "config" / "lab.lock.json"
RESTRICTED_ROOT = ROOT / "restricted"
POLICY_KIND = "orchestra.openshift.production-model-artifact-intake-policy.v1"
REPORT_KIND = "orchestra.openshift.production-model-artifact-intake-observation.v1"
SNAPSHOT_KIND = "orchestra.openshift.production-model-artifact-intake-snapshot.v1"
POLICY_ID = "orchestra-production-model-artifact-intake-2026-07-28.1"
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
MAX_REPORT_BYTES = 65536
EXPECTED_POLICY_DIGEST = (
    "sha256:625372044bb5db2271f2c545a2420e95af6a4dd867f9c5775f73903fb7317ca7"
)
OBSERVATION_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
ARTIFACT_REASON_ORDER = [
    "ARTIFACT_INPUT_MISSING",
    "ARTIFACT_OUTSIDE_RESTRICTED",
    "ARTIFACT_PARENT_UNSAFE",
    "ARTIFACT_SYMLINK",
    "ARTIFACT_NOT_REGULAR",
    "ARTIFACT_GROUP_OR_WORLD_WRITABLE",
    "ARTIFACT_SIZE_MISMATCH",
    "ARTIFACT_DESCRIPTOR_CHANGED",
    "ARTIFACT_READ_FAILED",
    "ARTIFACT_DIGEST_MISMATCH",
]
SIMULATED_ARTIFACT = {
    "preReadSizeBytes": None,
    "postReadSizeBytes": None,
    "observedDigest": None,
    "preReadGuardPassed": False,
    "descriptorStable": False,
    "expectedSizeMatched": False,
    "expectedDigestMatched": False,
    "reasonCodes": ["SIMULATED_INPUT"],
    "result": "SIMULATED",
}
CONTROLS = {
    "scope": "production-model-source-file-inspection-only",
    "sourceOnly": True,
    "networkDownloadPerformed": False,
    "artifactCopyPerformed": False,
    "inputPathsStored": False,
    "modelBytesStoredInReport": False,
    "outputContainsPayloadBytes": False,
    "secretValuesStored": False,
    "cloudMutationAuthorized": False,
    "campaignEligible": False,
}
CLAIMS = {
    "artifactCustodyVerified": False,
    "campaignEvidence": False,
    "contractualSla": False,
    "customerCertified": False,
    "dependencyAdmissionAuthorized": False,
    "deploymentAuthorized": False,
    "licenseApproved": False,
    "mirrorAuthorization": False,
    "productionSupported": False,
    "redHatCertified": False,
    "referenceProfileVerified": False,
    "sourceAdmissionAuthorized": False,
}
FORBIDDEN_KEYS = {
    "apiKey",
    "artifactBytes",
    "credentials",
    "data",
    "inputPath",
    "localPath",
    "modelBytes",
    "path",
    "secret",
    "secretValue",
    "token",
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def digest_without_field(value: dict[str, Any], field: str) -> str:
    unsigned = copy.deepcopy(value)
    unsigned.pop(field, None)
    return canonical_digest(unsigned)


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(code)
    return parsed


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def reject_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_KEYS.intersection(value)
        if forbidden:
            fail(f"production_model_intake_forbidden_key:{sorted(forbidden)[0]}")
        for child in value.values():
            reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            reject_forbidden_keys(child)


def validate_schema_strictness(schema: dict[str, Any]) -> None:
    def visit(value: Any, path: str) -> None:
        if isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}/{index}")
            return
        if not isinstance(value, dict):
            return
        if (
            value.get("type") == "object"
            and value.get("additionalProperties") is not False
        ):
            fail(f"production_model_intake_schema_not_strict:{path}")
        for key, child in value.items():
            visit(child, f"{path}/{key}")

    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id")
        != (
            "https://schemas.prometa.ai/orchestra/reference-lab/"
            "production-model-artifact-intake-observation-v1.schema.json"
        )
        or schema.get("additionalProperties") is not False
    ):
        fail("production_model_intake_schema_identity_invalid")
    visit(schema, "$")


def load_validated_candidate() -> dict[str, Any]:
    candidate = load_json(CANDIDATE_PATH)
    validate_candidate(
        candidate,
        load_json(BOM_PATH),
        load_json(ADMISSION_PATH),
        load_json(RELEASE_SET_PATH),
        load_json(TOPOLOGY_PATH),
        load_json(CANDIDATE_SCHEMA_PATH),
    )
    return candidate


def expected_artifacts(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "artifactId": model["id"],
            "serviceId": model["serviceId"],
            "filename": model["filename"],
            "immutableUrl": model["immutableUrl"],
            "revision": model["revision"],
            "digest": model["digest"],
            "sizeBytes": model["sizeBytes"],
            "maximumAllowedBytes": model["maximumAllowedBytes"],
        }
        for model in candidate["models"]
    ]


def validate_policy(
    value: dict[str, Any],
    candidate: dict[str, Any],
    schema: dict[str, Any],
) -> str:
    reject_forbidden_keys(value)
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "profileId",
            "targetClass",
            "bindings",
            "artifacts",
            "execution",
            "reviewBoundary",
            "controls",
            "claims",
            "policyDigest",
        },
        "production_model_intake_policy_keys_invalid",
    )
    validate_schema_strictness(schema)
    if (
        value["schemaVersion"] != 1
        or value["kind"] != POLICY_KIND
        or value["policyId"] != POLICY_ID
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
    ):
        fail("production_model_intake_policy_identity_invalid")
    if value["bindings"] != {
        "candidateId": candidate["candidateId"],
        "candidateDigest": candidate["candidateDigest"],
        "candidateSchemaDigest": candidate["bindings"]["schemaDigest"],
        "observationSchemaDigest": canonical_digest(schema),
    }:
        fail("production_model_intake_policy_bindings_invalid")
    if value["artifacts"] != expected_artifacts(candidate):
        fail("production_model_intake_policy_artifacts_invalid")
    for artifact in value["artifacts"]:
        if (
            not REVISION.fullmatch(artifact["revision"])
            or not DIGEST.fullmatch(artifact["digest"])
            or artifact["sizeBytes"] > artifact["maximumAllowedBytes"]
            or f"/resolve/{artifact['revision']}/" not in artifact["immutableUrl"]
            or not artifact["immutableUrl"].endswith(artifact["filename"])
        ):
            fail(
                "production_model_intake_policy_artifact_derivation_invalid:"
                f"{artifact['artifactId']}"
            )
    if value["execution"] != {
        "requiredInputRoot": "restricted",
        "regularFilesOnly": True,
        "symlinksAllowed": False,
        "groupOrWorldWritableAllowed": False,
        "preReadExactSizeRequired": True,
        "noFollowOpenRequired": True,
        "ancestorDescriptorWalkRequired": True,
        "descriptorIdentityRecheckRequired": True,
        "postReadStatRequired": True,
        "chunkSizeBytes": 1048576,
        "networkDownloadPerformed": False,
        "artifactCopyPerformed": False,
        "outputCreateOnly": True,
        "outputMode": "0600",
        "maximumReportBytes": MAX_REPORT_BYTES,
        "maximumObservationAgeSeconds": 86400,
    }:
        fail("production_model_intake_policy_execution_invalid")
    if value["reviewBoundary"] != {
        "humanLicenseReviewRequired": True,
        "minimumReviewers": 2,
        "requiredReviewerRoles": ["model-risk-reviewer", "service-owner"],
        "distinctReviewerIdentities": True,
        "automatedApprovalAllowed": False,
        "observationMayApprove": False,
        "productionBomReissueRequired": True,
        "dependencyAdmissionReissueRequired": True,
    }:
        fail("production_model_intake_policy_review_boundary_invalid")
    if value["controls"] != CONTROLS:
        fail("production_model_intake_policy_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("production_model_intake_policy_claims_invalid")
    digest = digest_without_field(value, "policyDigest")
    if value["policyDigest"] != digest:
        fail(f"production_model_intake_policy_digest_invalid:{digest}")
    if digest != EXPECTED_POLICY_DIGEST:
        fail(f"production_model_intake_policy_digest_changed:{digest}")
    return digest


def blocked_artifact(
    artifact_id: str,
    reason: str,
    *,
    pre_size: int | None = None,
    post_size: int | None = None,
    observed_digest: str | None = None,
    pre_read_guard_passed: bool = False,
    descriptor_stable: bool = False,
    size_matched: bool = False,
    during_read: bool = False,
) -> dict[str, Any]:
    return {
        "artifactId": artifact_id,
        "preReadSizeBytes": pre_size,
        "postReadSizeBytes": post_size,
        "observedDigest": observed_digest,
        "preReadGuardPassed": pre_read_guard_passed,
        "descriptorStable": descriptor_stable,
        "expectedSizeMatched": size_matched,
        "expectedDigestMatched": False,
        "reasonCodes": [reason],
        "result": "BLOCKED_DURING_READ" if during_read else "BLOCKED_PRE_READ",
    }


def simulated_artifact(artifact_id: str) -> dict[str, Any]:
    return {"artifactId": artifact_id, **SIMULATED_ARTIFACT}


def restricted_path_state(path: Path, restricted_root: Path) -> str | None:
    root = Path(os.path.abspath(restricted_root))
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(root)
    except (OSError, ValueError):
        return "outside"
    directories = [root]
    current = root
    for component in relative.parts[:-1]:
        current /= component
        directories.append(current)
    for directory in directories:
        try:
            metadata = directory.lstat()
        except OSError:
            return "parent"
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o022
        ):
            return "parent"
    try:
        resolved_root = root.resolve(strict=True)
        candidate.parent.resolve(strict=True).relative_to(resolved_root)
        if candidate.exists() or candidate.is_symlink():
            candidate.resolve(strict=True).relative_to(resolved_root)
    except (OSError, ValueError):
        return "outside"
    return None


def open_restricted_parent(
    path: Path, restricted_root: Path
) -> tuple[int | None, str | None, str | None]:
    root = Path(os.path.abspath(restricted_root))
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(root)
    except (OSError, ValueError):
        return None, None, "outside"
    if not relative.parts:
        return None, None, "outside"
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return None, None, "unsupported"

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor: int | None = None
    try:
        descriptor = os.open(root, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
            os.close(descriptor)
            return None, None, "parent"
        for component in relative.parts[:-1]:
            child: int | None = None
            try:
                child = os.open(component, flags, dir_fd=descriptor)
                child_metadata = os.fstat(child)
            except OSError:
                if child is not None:
                    os.close(child)
                raise
            if (
                not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_mode & 0o022
            ):
                os.close(child)
                os.close(descriptor)
                return None, None, "parent"
            os.close(descriptor)
            descriptor = child
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        return None, None, "changed"
    return descriptor, relative.parts[-1], None


def inside_restricted(path: Path, restricted_root: Path) -> bool:
    return restricted_path_state(path, restricted_root) is None


def inspect_artifact_file(
    path: Path,
    artifact: dict[str, Any],
    *,
    restricted_root: Path = RESTRICTED_ROOT,
) -> dict[str, Any]:
    artifact_id = artifact["artifactId"]
    try:
        metadata = path.lstat()
    except OSError:
        return blocked_artifact(artifact_id, "ARTIFACT_INPUT_MISSING")
    if stat.S_ISLNK(metadata.st_mode):
        return blocked_artifact(artifact_id, "ARTIFACT_SYMLINK")
    path_state = restricted_path_state(path, restricted_root)
    if path_state == "outside":
        return blocked_artifact(artifact_id, "ARTIFACT_OUTSIDE_RESTRICTED")
    if path_state == "parent":
        return blocked_artifact(artifact_id, "ARTIFACT_PARENT_UNSAFE")
    if not stat.S_ISREG(metadata.st_mode):
        return blocked_artifact(artifact_id, "ARTIFACT_NOT_REGULAR")
    if metadata.st_mode & 0o022:
        return blocked_artifact(
            artifact_id,
            "ARTIFACT_GROUP_OR_WORLD_WRITABLE",
            pre_size=metadata.st_size,
        )
    expected_size = artifact["sizeBytes"]
    if (
        metadata.st_size != expected_size
        or metadata.st_size > artifact["maximumAllowedBytes"]
    ):
        return blocked_artifact(
            artifact_id,
            "ARTIFACT_SIZE_MISMATCH",
            pre_size=metadata.st_size,
        )
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return blocked_artifact(
            artifact_id,
            "ARTIFACT_READ_FAILED",
            pre_size=metadata.st_size,
            pre_read_guard_passed=True,
            size_matched=True,
            during_read=True,
        )

    parent_descriptor, leaf_name, parent_error = open_restricted_parent(
        path, restricted_root
    )
    if parent_error == "parent":
        return blocked_artifact(
            artifact_id,
            "ARTIFACT_PARENT_UNSAFE",
            pre_size=metadata.st_size,
        )
    if parent_error is not None or parent_descriptor is None or leaf_name is None:
        return blocked_artifact(
            artifact_id,
            "ARTIFACT_DESCRIPTOR_CHANGED",
            pre_size=metadata.st_size,
            pre_read_guard_passed=True,
            size_matched=True,
            during_read=True,
        )

    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(leaf_name, flags, dir_fd=parent_descriptor)
    except OSError:
        return blocked_artifact(
            artifact_id,
            "ARTIFACT_DESCRIPTOR_CHANGED",
            pre_size=metadata.st_size,
            pre_read_guard_passed=True,
            size_matched=True,
            during_read=True,
        )
    finally:
        os.close(parent_descriptor)

    observed_digest: str | None = None
    total = 0
    try:
        before = os.fstat(descriptor)
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        if (
            identity != before_identity
            or not stat.S_ISREG(before.st_mode)
            or before.st_size != expected_size
        ):
            return blocked_artifact(
                artifact_id,
                "ARTIFACT_DESCRIPTOR_CHANGED",
                pre_size=metadata.st_size,
                post_size=before.st_size,
                pre_read_guard_passed=True,
                size_matched=before.st_size == expected_size,
                during_read=True,
            )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1048576)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size or total > artifact["maximumAllowedBytes"]:
                return blocked_artifact(
                    artifact_id,
                    "ARTIFACT_SIZE_MISMATCH",
                    pre_size=metadata.st_size,
                    post_size=total,
                    pre_read_guard_passed=True,
                    size_matched=False,
                    during_read=True,
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        observed_digest = f"sha256:{digest.hexdigest()}"
        descriptor_stable = before_identity == after_identity
        size_matched = total == expected_size and after.st_size == expected_size
        if not descriptor_stable:
            return blocked_artifact(
                artifact_id,
                "ARTIFACT_DESCRIPTOR_CHANGED",
                pre_size=metadata.st_size,
                post_size=after.st_size,
                observed_digest=observed_digest,
                pre_read_guard_passed=True,
                descriptor_stable=False,
                size_matched=size_matched,
                during_read=True,
            )
        if not size_matched:
            return blocked_artifact(
                artifact_id,
                "ARTIFACT_SIZE_MISMATCH",
                pre_size=metadata.st_size,
                post_size=after.st_size,
                observed_digest=observed_digest,
                pre_read_guard_passed=True,
                descriptor_stable=True,
                size_matched=False,
                during_read=True,
            )
    except OSError:
        return blocked_artifact(
            artifact_id,
            "ARTIFACT_READ_FAILED",
            pre_size=metadata.st_size,
            post_size=total,
            observed_digest=observed_digest,
            pre_read_guard_passed=True,
            size_matched=total == expected_size,
            during_read=True,
        )
    finally:
        os.close(descriptor)

    if observed_digest != artifact["digest"]:
        return blocked_artifact(
            artifact_id,
            "ARTIFACT_DIGEST_MISMATCH",
            pre_size=metadata.st_size,
            post_size=total,
            observed_digest=observed_digest,
            pre_read_guard_passed=True,
            descriptor_stable=True,
            size_matched=True,
            during_read=True,
        )
    return {
        "artifactId": artifact_id,
        "preReadSizeBytes": metadata.st_size,
        "postReadSizeBytes": total,
        "observedDigest": observed_digest,
        "preReadGuardPassed": True,
        "descriptorStable": True,
        "expectedSizeMatched": True,
        "expectedDigestMatched": True,
        "reasonCodes": [],
        "result": "VERIFIED",
    }


def expected_bindings(
    policy: dict[str, Any], candidate: dict[str, Any], schema: dict[str, Any]
) -> dict[str, Any]:
    return {
        "policyId": policy["policyId"],
        "policyDigest": policy["policyDigest"],
        "candidateId": candidate["candidateId"],
        "candidateDigest": candidate["candidateDigest"],
        "schemaDigest": canonical_digest(schema),
    }


def decision_for(
    artifacts: list[dict[str, Any]], execution_mode: str
) -> dict[str, Any]:
    if execution_mode == "simulated":
        return {"status": "SIMULATED", "reasonCodes": ["SIMULATED_INPUT"]}
    reasons = {reason for artifact in artifacts for reason in artifact["reasonCodes"]}
    ordered = [reason for reason in ARTIFACT_REASON_ORDER if reason in reasons]
    if all(artifact["result"] == "VERIFIED" for artifact in artifacts):
        return {"status": "SOURCE_BYTES_OBSERVED", "reasonCodes": []}
    return {"status": "BLOCKED", "reasonCodes": ordered}


def build_report(
    *,
    observation_id: str,
    execution_mode: str,
    observed_at: datetime,
    artifacts: list[dict[str, Any]],
    policy: dict[str, Any],
    candidate: dict[str, Any],
    schema: dict[str, Any],
) -> dict[str, Any]:
    report = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "observationId": observation_id,
        "profileId": PROFILE_ID,
        "targetClass": "source-intake",
        "executionMode": execution_mode,
        "bindings": expected_bindings(policy, candidate, schema),
        "observedAt": utc_text(observed_at),
        "expiresAt": utc_text(observed_at + timedelta(seconds=86400)),
        "artifacts": artifacts,
        "decision": decision_for(artifacts, execution_mode),
        "controls": CONTROLS,
        "claims": CLAIMS,
    }
    report["reportDigest"] = canonical_digest(report)
    return report


def validate_artifact_observation(
    value: Any,
    expected: dict[str, Any],
    execution_mode: str,
) -> None:
    artifact = exact_keys(
        value,
        {
            "artifactId",
            "preReadSizeBytes",
            "postReadSizeBytes",
            "observedDigest",
            "preReadGuardPassed",
            "descriptorStable",
            "expectedSizeMatched",
            "expectedDigestMatched",
            "reasonCodes",
            "result",
        },
        "production_model_intake_artifact_observation_invalid",
    )
    if artifact["artifactId"] != expected["artifactId"]:
        fail("production_model_intake_artifact_identity_invalid")
    if execution_mode == "simulated":
        if artifact != simulated_artifact(expected["artifactId"]):
            fail("production_model_intake_simulated_artifact_invalid")
        return
    if artifact["result"] not in {
        "VERIFIED",
        "BLOCKED_PRE_READ",
        "BLOCKED_DURING_READ",
    }:
        fail("production_model_intake_artifact_result_invalid")
    for key in ("preReadSizeBytes", "postReadSizeBytes"):
        if artifact[key] is not None and (
            not isinstance(artifact[key], int) or artifact[key] < 0
        ):
            fail("production_model_intake_artifact_size_invalid")
    if artifact["observedDigest"] is not None and (
        not isinstance(artifact["observedDigest"], str)
        or not DIGEST.fullmatch(artifact["observedDigest"])
    ):
        fail("production_model_intake_artifact_digest_invalid")
    for key in (
        "preReadGuardPassed",
        "descriptorStable",
        "expectedSizeMatched",
        "expectedDigestMatched",
    ):
        if not isinstance(artifact[key], bool):
            fail("production_model_intake_artifact_boolean_invalid")
    reasons = artifact["reasonCodes"]
    if (
        not isinstance(reasons, list)
        or len(reasons) != len(set(reasons))
        or any(reason not in ARTIFACT_REASON_ORDER for reason in reasons)
        or reasons
        != [reason for reason in ARTIFACT_REASON_ORDER if reason in set(reasons)]
    ):
        fail("production_model_intake_artifact_reasons_invalid")
    if artifact["result"] == "VERIFIED":
        if artifact != {
            "artifactId": expected["artifactId"],
            "preReadSizeBytes": expected["sizeBytes"],
            "postReadSizeBytes": expected["sizeBytes"],
            "observedDigest": expected["digest"],
            "preReadGuardPassed": True,
            "descriptorStable": True,
            "expectedSizeMatched": True,
            "expectedDigestMatched": True,
            "reasonCodes": [],
            "result": "VERIFIED",
        }:
            fail("production_model_intake_verified_artifact_invalid")
        return
    if len(reasons) != 1:
        fail("production_model_intake_blocked_artifact_reason_invalid")
    reason = reasons[0]
    if artifact["expectedDigestMatched"]:
        fail("production_model_intake_blocked_artifact_digest_claim_invalid")
    if (
        reason
        in {
            "ARTIFACT_INPUT_MISSING",
            "ARTIFACT_OUTSIDE_RESTRICTED",
            "ARTIFACT_PARENT_UNSAFE",
            "ARTIFACT_SYMLINK",
            "ARTIFACT_NOT_REGULAR",
            "ARTIFACT_GROUP_OR_WORLD_WRITABLE",
            "ARTIFACT_SIZE_MISMATCH",
        }
        and artifact["result"] != "BLOCKED_PRE_READ"
    ):
        fail("production_model_intake_pre_read_boundary_invalid")
    if (
        reason
        in {
            "ARTIFACT_DESCRIPTOR_CHANGED",
            "ARTIFACT_READ_FAILED",
            "ARTIFACT_DIGEST_MISMATCH",
        }
        and artifact["result"] != "BLOCKED_DURING_READ"
    ):
        fail("production_model_intake_during_read_boundary_invalid")


def validate_report(
    value: dict[str, Any],
    policy: dict[str, Any],
    candidate: dict[str, Any],
    schema: dict[str, Any],
    *,
    now: datetime | None = None,
) -> str:
    reject_forbidden_keys(value)
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "observationId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "observedAt",
            "expiresAt",
            "artifacts",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "production_model_intake_report_keys_invalid",
    )
    validate_policy(policy, candidate, schema)
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not isinstance(value["observationId"], str)
        or not OBSERVATION_ID.fullmatch(value["observationId"])
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "source-intake"
        or value["executionMode"] not in {"simulated", "local-file-inspection"}
        or value["bindings"] != expected_bindings(policy, candidate, schema)
    ):
        fail("production_model_intake_report_identity_invalid")
    observed_at = parse_utc(
        value["observedAt"], "production_model_intake_observed_at_invalid"
    )
    expires_at = parse_utc(
        value["expiresAt"], "production_model_intake_expires_at_invalid"
    )
    if expires_at - observed_at != timedelta(seconds=86400):
        fail("production_model_intake_report_window_invalid")
    reference_now = now or datetime.now(timezone.utc)
    if value["executionMode"] == "local-file-inspection" and (
        observed_at > reference_now + timedelta(minutes=5)
        or reference_now >= expires_at
    ):
        fail("production_model_intake_report_stale")
    artifacts = value["artifacts"]
    expected = expected_artifacts(candidate)
    if not isinstance(artifacts, list) or len(artifacts) != len(expected):
        fail("production_model_intake_report_artifacts_invalid")
    for artifact, expected_artifact in zip(artifacts, expected, strict=True):
        validate_artifact_observation(
            artifact, expected_artifact, value["executionMode"]
        )
    expected_decision = decision_for(artifacts, value["executionMode"])
    if value["decision"] != expected_decision:
        fail("production_model_intake_report_decision_invalid")
    if value["controls"] != CONTROLS:
        fail("production_model_intake_report_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("production_model_intake_report_claims_invalid")
    digest = digest_without_field(value, "reportDigest")
    if value["reportDigest"] != digest:
        fail(f"production_model_intake_report_digest_invalid:{digest}")
    return digest


def validate_snapshot(
    value: dict[str, Any], candidate: dict[str, Any]
) -> tuple[str, datetime]:
    reject_forbidden_keys(value)
    exact_keys(
        value,
        {"schemaVersion", "kind", "executionMode", "observedAt", "artifactIds"},
        "production_model_intake_snapshot_invalid",
    )
    expected_ids = [
        artifact["artifactId"] for artifact in expected_artifacts(candidate)
    ]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] != "simulated"
        or value["artifactIds"] != expected_ids
    ):
        fail("production_model_intake_snapshot_identity_invalid")
    return value["executionMode"], parse_utc(
        value["observedAt"], "production_model_intake_snapshot_time_invalid"
    )


def restricted_output(path: Path) -> None:
    try:
        root = RESTRICTED_ROOT.resolve(strict=True)
        parent = path.parent.resolve(strict=True)
        parent.relative_to(root)
    except (OSError, ValueError):
        fail("production_model_intake_output_not_restricted")
    if restricted_path_state(path, RESTRICTED_ROOT) == "parent":
        fail("production_model_intake_output_parent_unsafe")
    if path.exists() or path.is_symlink():
        fail("production_model_intake_output_exists")


def write_create_only(path: Path, value: dict[str, Any]) -> None:
    restricted_output(path)
    data = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    if not data or len(data) > MAX_REPORT_BYTES:
        fail("production_model_intake_output_size_invalid")
    parent_descriptor, leaf_name, parent_error = open_restricted_parent(
        path, RESTRICTED_ROOT
    )
    if parent_error is not None or parent_descriptor is None or leaf_name is None:
        fail("production_model_intake_output_create_failed")
    try:
        descriptor = os.open(
            leaf_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
    except OSError:
        fail("production_model_intake_output_create_failed")
    finally:
        os.close(parent_descriptor)
    try:
        total = 0
        while total < len(data):
            written = os.write(descriptor, data[total:])
            if written <= 0:
                fail("production_model_intake_output_write_failed")
            total += written
        os.fsync(descriptor)
    except OSError:
        fail("production_model_intake_output_write_failed")
    finally:
        os.close(descriptor)


def restricted_report(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError:
        fail("production_model_intake_report_missing")
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o077
        or metadata.st_size <= 0
        or metadata.st_size > MAX_REPORT_BYTES
        or not inside_restricted(path, RESTRICTED_ROOT)
    ):
        fail("production_model_intake_report_file_unsafe")
    parent_descriptor, leaf_name, parent_error = open_restricted_parent(
        path, RESTRICTED_ROOT
    )
    if parent_error is not None or parent_descriptor is None or leaf_name is None:
        fail("production_model_intake_report_file_changed")
    try:
        descriptor = os.open(
            leaf_name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except OSError:
        fail("production_model_intake_report_file_changed")
    finally:
        os.close(parent_descriptor)

    data = bytearray()
    try:
        before = os.fstat(descriptor)
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        if (
            identity != before_identity
            or not stat.S_ISREG(before.st_mode)
            or before.st_mode & 0o077
            or before.st_size <= 0
            or before.st_size > MAX_REPORT_BYTES
        ):
            fail("production_model_intake_report_file_changed")
        while len(data) <= MAX_REPORT_BYTES:
            chunk = os.read(descriptor, min(8192, MAX_REPORT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if (
            len(data) > MAX_REPORT_BYTES
            or len(data) != before.st_size
            or before_identity != after_identity
        ):
            fail("production_model_intake_report_file_changed")
    except OSError:
        fail("production_model_intake_report_read_failed")
    finally:
        os.close(descriptor)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                fail("production_model_intake_report_json_duplicate")
            value[key] = child
        return value

    try:
        value = json.loads(
            bytes(data).decode("ascii"),
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("production_model_intake_report_json_invalid")
    if not isinstance(value, dict):
        fail("production_model_intake_report_json_object_required")
    expected = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    if bytes(data) != expected:
        fail("production_model_intake_report_json_noncanonical")
    return value


def load_contracts() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    candidate = load_validated_candidate()
    schema = load_json(SCHEMA_PATH)
    policy = load_json(POLICY_PATH)
    validate_policy(policy, candidate, schema)
    return policy, candidate, schema


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-policy")

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--observation-id", required=True)
    inspect.add_argument("--chat-model", type=Path, required=True)
    inspect.add_argument("--embedding-model", type=Path, required=True)
    inspect.add_argument("--output", type=Path, required=True)

    assess = subparsers.add_parser("assess")
    assess.add_argument("--snapshot", type=Path, required=True)
    assess.add_argument("--observation-id", required=True)
    assess.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    policy, candidate, schema = load_contracts()
    if args.command == "validate-policy":
        print(
            "production_model_artifact_intake_policy_valid "
            f"digest={policy['policyDigest']} artifacts=2 "
            "networkDownload=false artifactCopy=false sourceAdmission=false"
        )
        return 0
    if args.command == "inspect":
        artifacts = [
            inspect_artifact_file(args.chat_model, policy["artifacts"][0]),
            inspect_artifact_file(args.embedding_model, policy["artifacts"][1]),
        ]
        report = build_report(
            observation_id=args.observation_id,
            execution_mode="local-file-inspection",
            observed_at=datetime.now(timezone.utc),
            artifacts=artifacts,
            policy=policy,
            candidate=candidate,
            schema=schema,
        )
        validate_report(report, policy, candidate, schema)
        write_create_only(args.output, report)
        print(
            "production_model_artifact_intake_observed "
            f"status={report['decision']['status']} "
            f"digest={report['reportDigest']} "
            "artifactCustodyVerified=false sourceAdmission=false"
        )
        return 0 if report["decision"]["status"] == "SOURCE_BYTES_OBSERVED" else 2
    if args.command == "assess":
        snapshot = load_json(args.snapshot)
        execution_mode, observed_at = validate_snapshot(snapshot, candidate)
        artifacts = [
            simulated_artifact(artifact["artifactId"])
            for artifact in policy["artifacts"]
        ]
        report = build_report(
            observation_id=args.observation_id,
            execution_mode=execution_mode,
            observed_at=observed_at,
            artifacts=artifacts,
            policy=policy,
            candidate=candidate,
            schema=schema,
        )
        validate_report(report, policy, candidate, schema)
        write_create_only(args.output, report)
        print(
            "production_model_artifact_intake_assessed status=SIMULATED "
            f"digest={report['reportDigest']} "
            "artifactCustodyVerified=false sourceAdmission=false"
        )
        return 0
    report = restricted_report(args.report)
    digest = validate_report(report, policy, candidate, schema)
    print(
        "production_model_artifact_intake_valid "
        f"status={report['decision']['status']} digest={digest} "
        "artifactCustodyVerified=false sourceAdmission=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
