#!/usr/bin/env python3
"""Observe SNO dependency inputs without reading Secret values."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_repository import canonical_digest
    from scripts.validate_sno_trial_dependency_manifests import (
        CLAIMS,
        load_validated_candidate,
    )
except ModuleNotFoundError:
    from validate_repository import canonical_digest
    from validate_sno_trial_dependency_manifests import (
        CLAIMS,
        load_validated_candidate,
    )


SNAPSHOT_KIND = "orchestra.openshift.sno-trial-dependency-input-snapshot.v1"
REPORT_KIND = "orchestra.openshift.sno-trial-dependency-input-observation.v1"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
ASSESSMENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
KUBE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
KEY_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
EXPECTED_TYPES = {
    "valkey-auth": "Opaque",
    "valkey-server-tls": "kubernetes.io/tls",
    "model-auth": "Opaque",
    "model-server-tls": "kubernetes.io/tls",
}
INPUT_REASON_ORDER = [
    "INPUT_OBJECT_MISSING",
    "INPUT_KEY_MISSING",
    "INPUT_TYPE_MISMATCH",
    "STORAGE_CLASS_INCOMPATIBLE",
    "MODEL_PVC_INCOMPATIBLE",
]
DECISION_REASON_ORDER = [
    "LIVE_OBSERVATION_REQUIRED",
    *INPUT_REASON_ORDER,
]
CONTROLS = {
    "secretValuesObserved": False,
    "secretValuesStored": False,
    "certificateValidityVerified": False,
    "modelArtifactBytesVerified": False,
    "modelArtifactDigestVerified": False,
    "serverSideDryRunExecuted": False,
    "connectivityVerified": False,
    "manifestsMaterialized": False,
    "cloudMutationAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
}
CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def list_value(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list):
        fail(code)
    return value


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("sno_dependency_inputs_json_duplicate_key")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError) as error:
        fail(f"sno_dependency_inputs_json_invalid:{error}")
    return object_value(value, "sno_dependency_inputs_json_object_required")


def utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        fail("sno_dependency_inputs_time_invalid")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None:
        fail(code)
    return parsed.astimezone(timezone.utc)


def reference_digest(item: dict[str, Any]) -> str:
    return canonical_digest(item)


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )


def command_output(
    client: Path,
    kubeconfig: Path,
    arguments: list[str],
    run: CommandRunner,
) -> list[str]:
    command = [
        str(client.resolve()),
        "--kubeconfig",
        str(kubeconfig.resolve()),
        *arguments,
    ]
    try:
        completed = run(command)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        fail("sno_dependency_inputs_observation_failed")
    if completed.stderr.strip():
        fail("sno_dependency_inputs_observation_stderr")
    if not completed.stdout:
        return []
    return completed.stdout.rstrip("\n").split("\n")


def base_observation(
    item: dict[str, Any],
    *,
    observed: bool,
    resolved_name_digest: str | None,
    required_key_count: int,
    observed_required_key_count: int,
    missing_required_keys: list[str],
    properties_valid: bool,
    property_set: dict[str, Any],
    reason_codes: list[str],
) -> dict[str, Any]:
    return {
        "inputId": item["id"],
        "referenceDigest": reference_digest(item),
        "kind": item["kind"],
        "observed": observed,
        "resolvedNameDigest": resolved_name_digest,
        "requiredKeyCount": required_key_count,
        "observedRequiredKeyCount": observed_required_key_count,
        "missingRequiredKeyCount": len(missing_required_keys),
        "missingRequiredKeySetDigest": canonical_digest(missing_required_keys),
        "propertiesValid": properties_valid,
        "propertySetDigest": canonical_digest(property_set),
        "reasonCodes": reason_codes,
    }


def observe_secret(
    client: Path,
    kubeconfig: Path,
    item: dict[str, Any],
    run: CommandRunner,
) -> dict[str, Any]:
    lines = command_output(
        client,
        kubeconfig,
        [
            "get",
            "secret",
            item["name"],
            "--namespace",
            item["namespace"],
            "--ignore-not-found",
            "--output",
            (
                'go-template={{.metadata.name}}{{"\\n"}}{{.type}}{{"\\n"}}'
                '{{range $k,$v := .data}}{{$k}}{{"\\n"}}{{end}}'
            ),
        ],
        run,
    )
    observed = bool(lines)
    if observed and len(lines) < 2:
        fail("sno_dependency_inputs_secret_output_invalid")
    actual_name = lines[0] if observed else ""
    observed_type = lines[1] if observed else ""
    observed_keys = sorted(set(lines[2:])) if observed else []
    if observed and (
        actual_name != item["name"]
        or not KUBE_NAME.fullmatch(actual_name)
        or any(not KEY_NAME.fullmatch(key) for key in observed_keys)
    ):
        fail("sno_dependency_inputs_secret_output_invalid")
    required = sorted(item["requiredKeys"])
    missing = sorted(set(required) - set(observed_keys))
    type_matches = observed and observed_type == EXPECTED_TYPES[item["id"]]
    reasons: list[str] = []
    if not observed:
        reasons.append("INPUT_OBJECT_MISSING")
    if observed and missing:
        reasons.append("INPUT_KEY_MISSING")
    if observed and not type_matches:
        reasons.append("INPUT_TYPE_MISMATCH")
    return base_observation(
        item,
        observed=observed,
        resolved_name_digest=canonical_digest(actual_name) if observed else None,
        required_key_count=len(required),
        observed_required_key_count=len(set(required) & set(observed_keys)),
        missing_required_keys=missing,
        properties_valid=observed and not missing and type_matches,
        property_set={
            "type": observed_type if observed else None,
            "requiredKeySetDigest": canonical_digest(
                sorted(set(required) & set(observed_keys))
            ),
        },
        reason_codes=reasons,
    )


def observe_storage_class(
    client: Path,
    kubeconfig: Path,
    item: dict[str, Any],
    storage_class_name: str,
    run: CommandRunner,
) -> dict[str, Any]:
    if not KUBE_NAME.fullmatch(storage_class_name):
        fail("sno_dependency_inputs_storage_class_name_invalid")
    lines = command_output(
        client,
        kubeconfig,
        [
            "get",
            "storageclass",
            storage_class_name,
            "--ignore-not-found",
            "--output",
            (
                'go-template={{.metadata.name}}{{"\\n"}}'
                '{{.provisioner}}{{"\\n"}}'
                '{{.volumeBindingMode}}{{"\\n"}}'
                '{{.allowVolumeExpansion}}{{"\\n"}}'
            ),
        ],
        run,
    )
    observed = bool(lines)
    if observed and len(lines) != 4:
        fail("sno_dependency_inputs_storage_class_output_invalid")
    actual_name = lines[0] if observed else ""
    provisioner = lines[1] if observed else ""
    binding_mode = lines[2] if observed else ""
    expansion = lines[3].lower() == "true" if observed else False
    if observed and actual_name != storage_class_name:
        fail("sno_dependency_inputs_storage_class_output_invalid")
    valid = (
        observed
        and provisioner == "pd.csi.storage.gke.io"
        and binding_mode == "WaitForFirstConsumer"
        and expansion
    )
    reasons = []
    if not observed:
        reasons.append("INPUT_OBJECT_MISSING")
    elif not valid:
        reasons.append("STORAGE_CLASS_INCOMPATIBLE")
    return base_observation(
        item,
        observed=observed,
        resolved_name_digest=canonical_digest(actual_name) if observed else None,
        required_key_count=0,
        observed_required_key_count=0,
        missing_required_keys=[],
        properties_valid=valid,
        property_set={
            "provisioner": provisioner if observed else None,
            "volumeBindingMode": binding_mode if observed else None,
            "allowVolumeExpansion": expansion if observed else False,
        },
        reason_codes=reasons,
    )


def storage_gib(value: str) -> int | None:
    match = re.fullmatch(r"([1-9][0-9]*)Gi", value)
    return int(match.group(1)) if match else None


def observe_model_pvc(
    client: Path,
    kubeconfig: Path,
    item: dict[str, Any],
    storage_class_name_digest: str | None,
    run: CommandRunner,
) -> dict[str, Any]:
    lines = command_output(
        client,
        kubeconfig,
        [
            "get",
            "persistentvolumeclaim",
            item["name"],
            "--namespace",
            item["namespace"],
            "--ignore-not-found",
            "--output",
            (
                'go-template={{.metadata.name}}{{"\\n"}}'
                '{{.status.phase}}{{"\\n"}}'
                '{{range .spec.accessModes}}{{.}}{{"\\n"}}{{end}}'
                '{{.spec.volumeMode}}{{"\\n"}}'
                '{{.spec.storageClassName}}{{"\\n"}}'
                '{{.status.capacity.storage}}{{"\\n"}}'
            ),
        ],
        run,
    )
    observed = bool(lines)
    if observed and len(lines) != 6:
        fail("sno_dependency_inputs_model_pvc_output_invalid")
    actual_name = lines[0] if observed else ""
    phase = lines[1] if observed else ""
    access_mode = lines[2] if observed else ""
    volume_mode = lines[3] if observed else ""
    storage_class_name = lines[4] if observed else ""
    capacity = lines[5] if observed else ""
    if observed and actual_name != item["name"]:
        fail("sno_dependency_inputs_model_pvc_output_invalid")
    capacity_gib = storage_gib(capacity) if observed else None
    actual_storage_digest = (
        canonical_digest(storage_class_name)
        if observed and storage_class_name
        else None
    )
    valid = (
        observed
        and phase == "Bound"
        and access_mode == "ReadWriteOnce"
        and volume_mode == "Filesystem"
        and capacity_gib is not None
        and capacity_gib >= 10
        and actual_storage_digest == storage_class_name_digest
    )
    reasons = []
    if not observed:
        reasons.append("INPUT_OBJECT_MISSING")
    elif not valid:
        reasons.append("MODEL_PVC_INCOMPATIBLE")
    return base_observation(
        item,
        observed=observed,
        resolved_name_digest=canonical_digest(actual_name) if observed else None,
        required_key_count=0,
        observed_required_key_count=0,
        missing_required_keys=[],
        properties_valid=valid,
        property_set={
            "phase": phase if observed else None,
            "accessMode": access_mode if observed else None,
            "volumeMode": volume_mode if observed else None,
            "storageClassNameDigest": actual_storage_digest,
            "capacityGiB": capacity_gib,
        },
        reason_codes=reasons,
    )


def validate_tooling(client: Path, kubeconfig: Path) -> None:
    try:
        client_metadata = client.lstat()
        kubeconfig_metadata = kubeconfig.lstat()
    except OSError:
        fail("sno_dependency_inputs_tooling_invalid")
    if (
        not stat.S_ISREG(client_metadata.st_mode)
        or not client_metadata.st_mode & 0o100
        or client_metadata.st_mode & 0o022
        or not stat.S_ISREG(kubeconfig_metadata.st_mode)
        or kubeconfig_metadata.st_mode & 0o077
        or client.is_symlink()
        or kubeconfig.is_symlink()
    ):
        fail("sno_dependency_inputs_tooling_invalid")


def collect_snapshot(
    client: Path,
    kubeconfig: Path,
    storage_class_name: str,
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    validate_tooling(client, kubeconfig)
    candidate = load_validated_candidate()
    observations: list[dict[str, Any]] = []
    storage_class_digest: str | None = None
    for item in candidate["requiredInputs"]:
        if item["kind"] == "StorageClass":
            observation = observe_storage_class(
                client, kubeconfig, item, storage_class_name, run
            )
            storage_class_digest = observation["resolvedNameDigest"]
        elif item["kind"] == "Secret":
            observation = observe_secret(client, kubeconfig, item, run)
        elif item["kind"] == "PersistentVolumeClaim":
            observation = observe_model_pvc(
                client, kubeconfig, item, storage_class_digest, run
            )
        else:
            fail("sno_dependency_inputs_kind_invalid")
        observations.append(observation)
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-read-only",
        "observedAt": utc_text(observed_at),
        "bindings": {
            "candidateId": candidate["candidateId"],
            "candidateDigest": candidate["candidateDigest"],
            "manifestSetDigest": candidate["manifestSetDigest"],
        },
        "observations": observations,
    }
    validate_snapshot(snapshot)
    return snapshot


def validate_observation(value: Any) -> dict[str, Any]:
    item = object_value(value, "sno_dependency_inputs_observation_invalid")
    exact_keys(
        item,
        {
            "inputId",
            "referenceDigest",
            "kind",
            "observed",
            "resolvedNameDigest",
            "requiredKeyCount",
            "observedRequiredKeyCount",
            "missingRequiredKeyCount",
            "missingRequiredKeySetDigest",
            "propertiesValid",
            "propertySetDigest",
            "reasonCodes",
        },
        "sno_dependency_inputs_observation_invalid",
    )
    if (
        not isinstance(item["inputId"], str)
        or not DIGEST.fullmatch(str(item["referenceDigest"]))
        or item["kind"] not in {"StorageClass", "Secret", "PersistentVolumeClaim"}
        or type(item["observed"]) is not bool
        or item["resolvedNameDigest"] is not None
        and not DIGEST.fullmatch(str(item["resolvedNameDigest"]))
        or type(item["requiredKeyCount"]) is not int
        or type(item["observedRequiredKeyCount"]) is not int
        or type(item["missingRequiredKeyCount"]) is not int
        or min(
            item["requiredKeyCount"],
            item["observedRequiredKeyCount"],
            item["missingRequiredKeyCount"],
        )
        < 0
        or item["observedRequiredKeyCount"] + item["missingRequiredKeyCount"]
        != item["requiredKeyCount"]
        or not DIGEST.fullmatch(str(item["missingRequiredKeySetDigest"]))
        or type(item["propertiesValid"]) is not bool
        or not DIGEST.fullmatch(str(item["propertySetDigest"]))
        or not isinstance(item["reasonCodes"], list)
        or item["reasonCodes"]
        != [reason for reason in INPUT_REASON_ORDER if reason in item["reasonCodes"]]
        or len(item["reasonCodes"]) != len(set(item["reasonCodes"]))
        or any(reason not in INPUT_REASON_ORDER for reason in item["reasonCodes"])
        or not item["observed"]
        and item["resolvedNameDigest"] is not None
        or item["propertiesValid"]
        and (not item["observed"] or item["reasonCodes"])
    ):
        fail("sno_dependency_inputs_observation_invalid")
    reasons = item["reasonCodes"]
    if not item["observed"]:
        if (
            reasons != ["INPUT_OBJECT_MISSING"]
            or item["observedRequiredKeyCount"] != 0
            or item["missingRequiredKeyCount"] != item["requiredKeyCount"]
        ):
            fail("sno_dependency_inputs_observation_semantics_invalid")
    elif item["propertiesValid"]:
        if item["missingRequiredKeyCount"] != 0:
            fail("sno_dependency_inputs_observation_semantics_invalid")
    elif not reasons or "INPUT_OBJECT_MISSING" in reasons:
        fail("sno_dependency_inputs_observation_semantics_invalid")
    if item["kind"] == "Secret":
        if item["observed"] and (
            ("INPUT_KEY_MISSING" in reasons) != (item["missingRequiredKeyCount"] > 0)
            or any(
                reason in {"STORAGE_CLASS_INCOMPATIBLE", "MODEL_PVC_INCOMPATIBLE"}
                for reason in reasons
            )
        ):
            fail("sno_dependency_inputs_observation_semantics_invalid")
    elif item["kind"] == "StorageClass":
        expected = [] if item["propertiesValid"] else ["STORAGE_CLASS_INCOMPATIBLE"]
        if item["observed"] and reasons != expected:
            fail("sno_dependency_inputs_observation_semantics_invalid")
    else:
        expected = [] if item["propertiesValid"] else ["MODEL_PVC_INCOMPATIBLE"]
        if item["observed"] and reasons != expected:
            fail("sno_dependency_inputs_observation_semantics_invalid")
    return item


def validate_snapshot(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "executionMode",
            "observedAt",
            "bindings",
            "observations",
        },
        "sno_dependency_inputs_snapshot_invalid",
    )
    candidate = load_validated_candidate()
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in {"simulated", "live-read-only"}
    ):
        fail("sno_dependency_inputs_snapshot_invalid")
    parse_utc(value["observedAt"], "sno_dependency_inputs_snapshot_time_invalid")
    if value["bindings"] != {
        "candidateId": candidate["candidateId"],
        "candidateDigest": candidate["candidateDigest"],
        "manifestSetDigest": candidate["manifestSetDigest"],
    }:
        fail("sno_dependency_inputs_snapshot_bindings_invalid")
    observations = [
        validate_observation(item)
        for item in list_value(
            value["observations"], "sno_dependency_inputs_observations_invalid"
        )
    ]
    if len(observations) != len(candidate["requiredInputs"]):
        fail("sno_dependency_inputs_observations_invalid")
    for locked, observed in zip(candidate["requiredInputs"], observations, strict=True):
        if (
            observed["inputId"] != locked["id"]
            or observed["referenceDigest"] != reference_digest(locked)
            or observed["kind"] != locked["kind"]
            or observed["requiredKeyCount"] != len(locked["requiredKeys"])
        ):
            fail("sno_dependency_inputs_observations_invalid")


def aggregate(snapshot: dict[str, Any]) -> dict[str, Any]:
    observations = snapshot["observations"]
    storage = next(item for item in observations if item["inputId"] == "storage-class")
    return {
        "inputCount": len(observations),
        "observedCount": sum(1 for item in observations if item["observed"]),
        "validCount": sum(1 for item in observations if item["propertiesValid"]),
        "unresolvedCount": sum(
            1 for item in observations if not item["propertiesValid"]
        ),
        "referenceSetDigest": canonical_digest(
            [item["referenceDigest"] for item in observations]
        ),
        "storageClassNameDigest": storage["resolvedNameDigest"],
    }


def decision_for(
    execution_mode: str, observations: list[dict[str, Any]]
) -> dict[str, Any]:
    reasons: list[str] = []
    if execution_mode != "live-read-only":
        reasons.append("LIVE_OBSERVATION_REQUIRED")
    for reason in INPUT_REASON_ORDER:
        if any(reason in item["reasonCodes"] for item in observations):
            reasons.append(reason)
    return {
        "status": (
            "DEPENDENCY_INPUTS_OBSERVED"
            if execution_mode == "live-read-only" and not reasons
            else "DEPENDENCY_INPUTS_UNRESOLVED"
        ),
        "reasonCodes": [
            reason for reason in DECISION_REASON_ORDER if reason in reasons
        ],
    }


def build_assessment(
    snapshot: dict[str, Any],
    assessment_id: str,
    assessed_at: datetime | None = None,
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_dependency_inputs_assessment_id_invalid")
    assessed = assessed_at or datetime.now(timezone.utc)
    observed_at = parse_utc(
        snapshot["observedAt"], "sno_dependency_inputs_snapshot_time_invalid"
    )
    if assessed.tzinfo is None or observed_at > assessed.astimezone(timezone.utc):
        fail("sno_dependency_inputs_assessment_time_invalid")
    report = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "assessmentId": assessment_id,
        "profileId": PROFILE_ID,
        "targetClass": "engineering-trial",
        "executionMode": snapshot["executionMode"],
        "observedAt": snapshot["observedAt"],
        "assessedAt": utc_text(assessed),
        "bindings": copy.deepcopy(snapshot["bindings"]),
        "aggregate": aggregate(snapshot),
        "observations": copy.deepcopy(snapshot["observations"]),
        "decision": decision_for(snapshot["executionMode"], snapshot["observations"]),
        "controls": copy.deepcopy(CONTROLS),
        "claims": copy.deepcopy(CLAIMS),
    }
    report["reportDigest"] = canonical_digest(report)
    validate_assessment(report)
    return report


def validate_assessment(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "assessmentId",
            "profileId",
            "targetClass",
            "executionMode",
            "observedAt",
            "assessedAt",
            "bindings",
            "aggregate",
            "observations",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_dependency_inputs_report_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in {"simulated", "live-read-only"}
    ):
        fail("sno_dependency_inputs_report_invalid")
    observed_at = parse_utc(
        value["observedAt"], "sno_dependency_inputs_report_time_invalid"
    )
    assessed_at = parse_utc(
        value["assessedAt"], "sno_dependency_inputs_report_time_invalid"
    )
    if observed_at > assessed_at:
        fail("sno_dependency_inputs_report_time_invalid")
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": value["executionMode"],
        "observedAt": value["observedAt"],
        "bindings": value["bindings"],
        "observations": value["observations"],
    }
    validate_snapshot(snapshot)
    if value["aggregate"] != aggregate(snapshot):
        fail("sno_dependency_inputs_report_aggregate_invalid")
    if value["decision"] != decision_for(value["executionMode"], value["observations"]):
        fail("sno_dependency_inputs_report_decision_invalid")
    if value["controls"] != CONTROLS or value["claims"] != CLAIMS:
        fail("sno_dependency_inputs_report_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_dependency_inputs_report_digest_invalid")


def simulated_snapshot(observed_at: datetime) -> dict[str, Any]:
    candidate = load_validated_candidate()
    observations = [
        base_observation(
            item,
            observed=False,
            resolved_name_digest=None,
            required_key_count=len(item["requiredKeys"]),
            observed_required_key_count=0,
            missing_required_keys=sorted(item["requiredKeys"]),
            properties_valid=False,
            property_set={},
            reason_codes=["INPUT_OBJECT_MISSING"],
        )
        for item in candidate["requiredInputs"]
    ]
    value = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "simulated",
        "observedAt": utc_text(observed_at),
        "bindings": {
            "candidateId": candidate["candidateId"],
            "candidateDigest": candidate["candidateDigest"],
            "manifestSetDigest": candidate["manifestSetDigest"],
        },
        "observations": observations,
    }
    validate_snapshot(value)
    return value


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except OSError:
        fail("sno_dependency_inputs_output_write_failed")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--client", type=Path, required=True)
    collect.add_argument("--kubeconfig", type=Path, required=True)
    collect.add_argument("--storage-class", required=True)
    collect.add_argument("--assessment-id", required=True)
    collect.add_argument("--output", type=Path, required=True)
    assess = commands.add_parser("assess")
    assess.add_argument("--snapshot", type=Path, required=True)
    assess.add_argument("--assessment-id", required=True)
    assess.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "collect":
        snapshot = collect_snapshot(
            args.client,
            args.kubeconfig,
            args.storage_class,
            datetime.now(timezone.utc),
        )
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
    elif args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_dependency_inputs_live_snapshot_requires_collect")
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
    else:
        report = load_json(args.report)
        validate_assessment(report)
    print(
        "sno_dependency_inputs_valid "
        f"digest={report['reportDigest']} "
        f"status={report['decision']['status']} "
        "secretValuesStored=false deploymentAuthorized=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
