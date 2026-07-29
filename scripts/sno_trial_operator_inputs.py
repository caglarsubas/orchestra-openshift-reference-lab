#!/usr/bin/env python3
"""Validate and observe value-free SNO operator Secret and CA inputs."""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.sno_trial_product_dry_run import (
        DOCUMENT,
        METADATA_NAME,
        NAME_LINE,
        PLANES,
        PLANE_NAMESPACES,
        RESOURCE_KIND,
        file_digest,
        local_contracts,
        read_text,
    )
    from scripts.validate_sno_trial_profile import (
        ROOT,
        TRIAL_PROFILE_ID,
        canonical_digest,
    )
except ModuleNotFoundError:
    from sno_trial_product_dry_run import (  # type: ignore[no-redef]
        DOCUMENT,
        METADATA_NAME,
        NAME_LINE,
        PLANES,
        PLANE_NAMESPACES,
        RESOURCE_KIND,
        file_digest,
        local_contracts,
        read_text,
    )
    from validate_sno_trial_profile import (  # type: ignore[no-redef]
        ROOT,
        TRIAL_PROFILE_ID,
        canonical_digest,
    )


LOCK_PATH = ROOT / "config" / "sno-trial-operator-inputs.lock.json"
EXPECTED_CONTRACT_DIGEST = (
    "sha256:e98788368f1fd519b27ff3d692e87927c04508942d0fe6d9bfeec0eee4cca618"
)
REPORT_KIND = "orchestra.openshift.sno-trial-operator-inputs.v1"
SNAPSHOT_KIND = "orchestra.openshift.sno-trial-operator-inputs-snapshot.v1"
CONTRACT_KIND = "orchestra.openshift.sno-trial-operator-input-contract.v1"
ASSESSMENT_ID = re.compile(r"^sno-operator-inputs-[a-z0-9][a-z0-9.-]{5,79}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
KUBE_NAME = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\." r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$"
)
KEY_NAME = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
EXECUTION_MODES = {"simulated", "live-read-only"}
KINDS = {"Secret", "ConfigMap"}
PLANE_ORDER = {plane: index for index, plane in enumerate(PLANES)}
REFERENCE_BLOCKS = {
    "secret": ("Secret", "secretName", False),
    "secretKeyRef": ("Secret", "name", False),
    "secretRef": ("Secret", "name", True),
    "configMap": ("ConfigMap", "name", False),
    "configMapKeyRef": ("ConfigMap", "name", False),
    "configMapRef": ("ConfigMap", "name", True),
}
REASON_CODES = (
    "LIVE_OBSERVATION_REQUIRED",
    "MANIFEST_REFERENCE_CONTRACT_MISMATCH",
    "INPUT_OBJECT_MISSING",
    "INPUT_KEY_MISSING",
    "INPUT_TYPE_MISMATCH",
)
CONTROLS = {
    "commandPolicy": "read-only-secret-and-configmap-key-metadata",
    "secretValuesEmittedByClient": False,
    "secretValuesStored": False,
    "rawCommandOutputStored": False,
    "objectNamesStored": False,
    "kubeconfigStored": False,
    "dependencyConnectivityTested": False,
    "certificateValidityTested": False,
    "cloudMutationAuthorized": False,
    "workloadActivationAuthorized": False,
    "deploymentAuthorized": False,
    "teardownAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
}
CLAIMS = {
    "campaignEvidence": False,
    "referenceProfileVerified": False,
    "customerCertified": False,
    "redHatCertified": False,
    "contractualSla": False,
    "productionSupported": False,
    "highAvailability": False,
    "rpoRtoVerified": False,
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


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        fail("sno_operator_inputs_json_invalid")
    return object_value(value, "sno_operator_inputs_json_invalid")


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(code)
    return parsed


def scalar(value: str) -> str:
    result = value.strip()
    if len(result) >= 2 and result[0] == result[-1] and result[0] in {'"', "'"}:
        result = result[1:-1]
    return result


def yaml_lines(content: str) -> list[tuple[int, str, str]]:
    result: list[tuple[int, str, str]] = []
    for raw in content.splitlines():
        stripped = raw.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(stripped)
        if stripped.startswith("- "):
            stripped = stripped[2:].lstrip()
            indent += 2
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
            continue
        result.append((indent, key, scalar(value)))
    return result


def metadata_name(document: str) -> str:
    metadata = METADATA_NAME.search(document)
    if not metadata:
        fail("sno_operator_inputs_manifest_identity_invalid")
    name = NAME_LINE.search(metadata.group("body"))
    if not name:
        fail("sno_operator_inputs_manifest_identity_invalid")
    return name.group(1)


def defined_inputs(content: str) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for document in (item for item in DOCUMENT.split(content) if item.strip()):
        kind = RESOURCE_KIND.search(document)
        if not kind:
            fail("sno_operator_inputs_manifest_identity_invalid")
        if kind.group(1) in KINDS:
            result.add((kind.group(1), metadata_name(document)))
    return result


def manifest_input_inventory(plane: str, path: Path) -> list[dict[str, Any]]:
    if plane not in PLANES:
        fail("sno_operator_inputs_plane_invalid")
    content = read_text(path)
    defined = defined_inputs(content)
    lines = yaml_lines(content)
    references: dict[tuple[str, str], dict[str, Any]] = {}
    for index, (indent, key, _) in enumerate(lines):
        contract = REFERENCE_BLOCKS.get(key)
        if contract is None:
            continue
        kind, name_key, whole_import = contract
        descendants: list[tuple[int, str, str]] = []
        for candidate in lines[index + 1 :]:
            if candidate[0] <= indent:
                break
            descendants.append(candidate)
        names = [
            value
            for _, child_key, value in descendants
            if child_key == name_key and value
        ]
        if not names:
            continue
        name = names[0]
        if not KUBE_NAME.fullmatch(name):
            fail("sno_operator_inputs_manifest_reference_invalid")
        if (kind, name) in defined:
            continue
        required: set[str] = set()
        optional: set[str] = set()
        if key in {"secretKeyRef", "configMapKeyRef"}:
            keys = [
                value
                for _, child_key, value in descendants
                if child_key == "key" and value
            ]
            if len(keys) != 1 or not KEY_NAME.fullmatch(keys[0]):
                fail("sno_operator_inputs_manifest_reference_invalid")
            is_optional = any(
                child_key == "optional" and value.lower() == "true"
                for _, child_key, value in descendants
            )
            (optional if is_optional else required).add(keys[0])
        elif key in {"secret", "configMap"}:
            for _, child_key, value in descendants:
                if child_key == "key" and value:
                    if not KEY_NAME.fullmatch(value):
                        fail("sno_operator_inputs_manifest_reference_invalid")
                    required.add(value)
        identity = (kind, name)
        current = references.setdefault(
            identity,
            {
                "plane": plane,
                "namespace": PLANE_NAMESPACES[plane],
                "kind": kind,
                "name": name,
                "requiredKeys": set(),
                "optionalKeys": set(),
                "wholeObjectImport": False,
            },
        )
        current["requiredKeys"].update(required)
        current["optionalKeys"].update(optional)
        current["wholeObjectImport"] = current["wholeObjectImport"] or whole_import
    result: list[dict[str, Any]] = []
    for item in references.values():
        item["optionalKeys"] -= item["requiredKeys"]
        result.append(
            {
                **item,
                "requiredKeys": sorted(item["requiredKeys"]),
                "optionalKeys": sorted(item["optionalKeys"]),
            }
        )
    return sorted(result, key=reference_sort_key)


def reference_sort_key(value: dict[str, Any]) -> tuple[int, str, str]:
    return (
        PLANE_ORDER.get(str(value.get("plane")), len(PLANES)),
        str(value.get("kind")),
        str(value.get("name")),
    )


def reference_digest(value: dict[str, Any]) -> str:
    return canonical_digest(
        {
            "plane": value["plane"],
            "namespace": value["namespace"],
            "kind": value["kind"],
            "name": value["name"],
        }
    )


def validate_string_list(value: Any, code: str) -> list[str]:
    items = list_value(value, code)
    if any(
        not isinstance(item, str) or not KEY_NAME.fullmatch(item) for item in items
    ) or items != sorted(set(items)):
        fail(code)
    return items


def validate_contract(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "contractId",
            "profileId",
            "targetClass",
            "bindings",
            "inputs",
            "controls",
            "claims",
            "contractDigest",
        },
        "sno_operator_inputs_contract_keys_invalid",
    )
    profile, candidate, artifact_lock = local_contracts()
    if (
        value["schemaVersion"] != 1
        or value["kind"] != CONTRACT_KIND
        or value["contractId"] != "orchestra-sno-trial-operator-inputs-2026-07-28.2"
        or value["profileId"] != TRIAL_PROFILE_ID
        or value["targetClass"] != "engineering-trial"
    ):
        fail("sno_operator_inputs_contract_identity_invalid")
    bindings = object_value(
        value["bindings"], "sno_operator_inputs_contract_bindings_invalid"
    )
    exact_keys(
        bindings,
        {
            "profileDigest",
            "workloadCandidateId",
            "workloadCandidateDigest",
            "artifactSetId",
            "artifactSetDigest",
        },
        "sno_operator_inputs_contract_bindings_invalid",
    )
    if bindings != {
        "profileDigest": canonical_digest(profile),
        "workloadCandidateId": candidate["candidateId"],
        "workloadCandidateDigest": candidate["candidateDigest"],
        "artifactSetId": artifact_lock["artifactSetId"],
        "artifactSetDigest": artifact_lock["artifactSetDigest"],
    }:
        fail("sno_operator_inputs_contract_bindings_invalid")
    inputs = list_value(
        value["inputs"], "sno_operator_inputs_contract_inventory_invalid"
    )
    if len(inputs) != 17:
        fail("sno_operator_inputs_contract_inventory_invalid")
    identities: set[tuple[str, str, str, str]] = set()
    for item_value in inputs:
        item = object_value(item_value, "sno_operator_inputs_contract_item_invalid")
        exact_keys(
            item,
            {
                "plane",
                "namespace",
                "kind",
                "name",
                "expectedType",
                "requiredKeys",
                "optionalKeys",
                "wholeObjectImport",
            },
            "sno_operator_inputs_contract_item_invalid",
        )
        required = validate_string_list(
            item["requiredKeys"], "sno_operator_inputs_contract_item_invalid"
        )
        optional = validate_string_list(
            item["optionalKeys"], "sno_operator_inputs_contract_item_invalid"
        )
        identity = (
            str(item["plane"]),
            str(item["namespace"]),
            str(item["kind"]),
            str(item["name"]),
        )
        if (
            item["plane"] not in PLANES
            or item["namespace"] != PLANE_NAMESPACES[item["plane"]]
            or item["kind"] not in KINDS
            or not isinstance(item["name"], str)
            or not KUBE_NAME.fullmatch(item["name"])
            or item["expectedType"] not in {None, "Opaque", "kubernetes.io/tls"}
            or item["kind"] == "ConfigMap"
            and item["expectedType"] is not None
            or not required
            or set(required) & set(optional)
            or type(item["wholeObjectImport"]) is not bool
            or identity in identities
        ):
            fail("sno_operator_inputs_contract_item_invalid")
        identities.add(identity)
    if inputs != sorted(inputs, key=reference_sort_key):
        fail("sno_operator_inputs_contract_inventory_invalid")
    if value["controls"] != {
        "secretValuesStored": False,
        "operatorCreatesValuesOutOfBand": True,
        "additionalSecretKeysAllowed": True,
        "liveObservationRequiredForResolution": True,
        "dependencyConnectivitySeparate": True,
        "certificateValiditySeparate": True,
        "deploymentAuthorized": False,
        "campaignEligible": False,
        "allowedCertificationSlots": [],
    }:
        fail("sno_operator_inputs_contract_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_operator_inputs_contract_claims_invalid")
    digest = value["contractDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("contractDigest")
    if (
        not isinstance(digest, str)
        or digest != EXPECTED_CONTRACT_DIGEST
        or digest != canonical_digest(unsigned)
    ):
        fail("sno_operator_inputs_contract_digest_invalid")


def load_contract() -> dict[str, Any]:
    value = load_json(LOCK_PATH)
    validate_contract(value)
    return value


def validate_manifest_contract(
    manifests: dict[str, Path], contract: dict[str, Any]
) -> list[dict[str, Any]]:
    if set(manifests) != set(PLANES):
        fail("sno_operator_inputs_manifest_set_invalid")
    expected = {
        (item["plane"], item["kind"], item["name"]): item for item in contract["inputs"]
    }
    discovered: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for plane in PLANES:
        inventory = manifest_input_inventory(plane, manifests[plane])
        discovered.extend(inventory)
        records.append(
            {
                "plane": plane,
                "manifestDigest": file_digest(manifests[plane]),
                "externalReferenceCount": len(inventory),
                "externalReferenceSetDigest": canonical_digest(
                    [
                        {
                            "kind": item["kind"],
                            "name": item["name"],
                            "requiredKeys": item["requiredKeys"],
                            "optionalKeys": item["optionalKeys"],
                            "wholeObjectImport": item["wholeObjectImport"],
                        }
                        for item in inventory
                    ]
                ),
            }
        )
    observed = {
        (item["plane"], item["kind"], item["name"]): item for item in discovered
    }
    if set(observed) != set(expected):
        fail("sno_operator_inputs_manifest_contract_mismatch")
    for identity, actual in observed.items():
        locked = expected[identity]
        if (
            actual["namespace"] != locked["namespace"]
            or actual["wholeObjectImport"] != locked["wholeObjectImport"]
            or not set(actual["requiredKeys"]).issubset(locked["requiredKeys"])
            or not set(actual["optionalKeys"]).issubset(locked["optionalKeys"])
            or not actual["wholeObjectImport"]
            and (
                actual["requiredKeys"] != locked["requiredKeys"]
                or actual["optionalKeys"] != locked["optionalKeys"]
            )
        ):
            fail("sno_operator_inputs_manifest_contract_mismatch")
    return records


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )


def observe_input(
    client: Path,
    kubeconfig: Path,
    item: dict[str, Any],
    run: CommandRunner,
) -> dict[str, Any]:
    if item["kind"] == "Secret":
        resource = "secret"
        template = (
            'go-template={{.type}}{{"\\n"}}'
            '{{range $k,$v := .data}}{{$k}}{{"\\n"}}{{end}}'
        )
    else:
        resource = "configmap"
        template = (
            'go-template=ConfigMap{{"\\n"}}'
            '{{range $k,$v := .data}}{{$k}}{{"\\n"}}{{end}}'
        )
    command = [
        str(client.resolve()),
        "--kubeconfig",
        str(kubeconfig.resolve()),
        "get",
        resource,
        item["name"],
        "--namespace",
        item["namespace"],
        "--ignore-not-found",
        "--output",
        template,
    ]
    try:
        completed = run(command)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        fail("sno_operator_inputs_observation_failed")
    lines = [line for line in completed.stdout.splitlines() if line]
    observed = bool(lines)
    observed_type = lines[0] if observed else ""
    observed_keys = set(lines[1:]) if observed else set()
    if any(not KEY_NAME.fullmatch(key) for key in observed_keys):
        fail("sno_operator_inputs_observation_invalid")
    required = set(item["requiredKeys"])
    missing = sorted(required - observed_keys)
    expected_type = item["expectedType"]
    type_matches = observed and (
        expected_type is None or observed_type == expected_type
    )
    return {
        "referenceDigest": reference_digest(item),
        "plane": item["plane"],
        "kind": item["kind"],
        "observed": observed,
        "typeMatches": type_matches,
        "requiredKeyCount": len(required),
        "observedRequiredKeyCount": len(required & observed_keys),
        "missingRequiredKeyCount": len(missing),
        "missingRequiredKeySetDigest": canonical_digest(missing),
    }


def collect_snapshot(
    client: Path,
    kubeconfig: Path,
    manifests: dict[str, Path],
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    if (
        not client.is_file()
        or not client.stat().st_mode & 0o100
        or not kubeconfig.is_file()
    ):
        fail("sno_operator_inputs_tooling_invalid")
    contract = load_contract()
    manifest_records = validate_manifest_contract(manifests, contract)
    observations = [
        observe_input(client, kubeconfig, item, run) for item in contract["inputs"]
    ]
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-read-only",
        "observedAt": utc_text(observed_at),
        "manifests": manifest_records,
        "observations": observations,
        "manifestReferencesContractBound": True,
        "allObjectsObserved": all(item["observed"] for item in observations),
        "allRequiredKeysPresent": all(
            item["missingRequiredKeyCount"] == 0 for item in observations
        ),
        "allTypesMatch": all(item["typeMatches"] for item in observations),
    }
    validate_snapshot(snapshot)
    return snapshot


def validate_manifest_record(value: Any) -> None:
    item = object_value(value, "sno_operator_inputs_manifest_record_invalid")
    exact_keys(
        item,
        {
            "plane",
            "manifestDigest",
            "externalReferenceCount",
            "externalReferenceSetDigest",
        },
        "sno_operator_inputs_manifest_record_invalid",
    )
    if (
        item["plane"] not in PLANES
        or not DIGEST.fullmatch(str(item["manifestDigest"]))
        or type(item["externalReferenceCount"]) is not int
        or item["externalReferenceCount"] <= 0
        or not DIGEST.fullmatch(str(item["externalReferenceSetDigest"]))
    ):
        fail("sno_operator_inputs_manifest_record_invalid")


def validate_observation(value: Any) -> None:
    item = object_value(value, "sno_operator_inputs_observation_invalid")
    exact_keys(
        item,
        {
            "referenceDigest",
            "plane",
            "kind",
            "observed",
            "typeMatches",
            "requiredKeyCount",
            "observedRequiredKeyCount",
            "missingRequiredKeyCount",
            "missingRequiredKeySetDigest",
        },
        "sno_operator_inputs_observation_invalid",
    )
    counts = (
        item["requiredKeyCount"],
        item["observedRequiredKeyCount"],
        item["missingRequiredKeyCount"],
    )
    if (
        not DIGEST.fullmatch(str(item["referenceDigest"]))
        or item["plane"] not in PLANES
        or item["kind"] not in KINDS
        or type(item["observed"]) is not bool
        or type(item["typeMatches"]) is not bool
        or any(type(count) is not int or count < 0 for count in counts)
        or item["requiredKeyCount"]
        != item["observedRequiredKeyCount"] + item["missingRequiredKeyCount"]
        or item["typeMatches"]
        and not item["observed"]
        or not DIGEST.fullmatch(str(item["missingRequiredKeySetDigest"]))
    ):
        fail("sno_operator_inputs_observation_invalid")


def validate_snapshot(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "executionMode",
            "observedAt",
            "manifests",
            "observations",
            "manifestReferencesContractBound",
            "allObjectsObserved",
            "allRequiredKeysPresent",
            "allTypesMatch",
        },
        "sno_operator_inputs_snapshot_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_operator_inputs_snapshot_identity_invalid")
    parse_utc(value["observedAt"], "sno_operator_inputs_snapshot_time_invalid")
    manifests = list_value(value["manifests"], "sno_operator_inputs_manifests_invalid")
    for item in manifests:
        validate_manifest_record(item)
    if [item["plane"] for item in manifests] != list(PLANES):
        fail("sno_operator_inputs_manifests_invalid")
    contract = load_contract()
    observations = list_value(
        value["observations"], "sno_operator_inputs_observations_invalid"
    )
    if len(observations) != len(contract["inputs"]):
        fail("sno_operator_inputs_observations_invalid")
    for item in observations:
        validate_observation(item)
    if [item["referenceDigest"] for item in observations] != [
        reference_digest(item) for item in contract["inputs"]
    ]:
        fail("sno_operator_inputs_observations_invalid")
    expected = {
        "allObjectsObserved": all(item["observed"] for item in observations),
        "allRequiredKeysPresent": all(
            item["missingRequiredKeyCount"] == 0 for item in observations
        ),
        "allTypesMatch": all(item["typeMatches"] for item in observations),
    }
    if type(value["manifestReferencesContractBound"]) is not bool or any(
        value[key] != expected[key] for key in expected
    ):
        fail("sno_operator_inputs_snapshot_aggregate_invalid")


def aggregate(snapshot: dict[str, Any]) -> dict[str, Any]:
    observations = snapshot["observations"]
    return {
        "manifestCount": len(snapshot["manifests"]),
        "externalReferenceCount": len(observations),
        "observedObjectCount": sum(item["observed"] for item in observations),
        "requiredKeyCount": sum(item["requiredKeyCount"] for item in observations),
        "observedRequiredKeyCount": sum(
            item["observedRequiredKeyCount"] for item in observations
        ),
        "missingRequiredKeyCount": sum(
            item["missingRequiredKeyCount"] for item in observations
        ),
        "manifestReferencesContractBound": snapshot["manifestReferencesContractBound"],
        "allObjectsObserved": snapshot["allObjectsObserved"],
        "allRequiredKeysPresent": snapshot["allRequiredKeysPresent"],
        "allTypesMatch": snapshot["allTypesMatch"],
        "externalReferencesResolved": (
            snapshot["executionMode"] == "live-read-only"
            and snapshot["manifestReferencesContractBound"]
            and snapshot["allObjectsObserved"]
            and snapshot["allRequiredKeysPresent"]
            and snapshot["allTypesMatch"]
        ),
    }


def decision_for(execution_mode: str, result: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if execution_mode != "live-read-only":
        reasons.append("LIVE_OBSERVATION_REQUIRED")
    if not result["manifestReferencesContractBound"]:
        reasons.append("MANIFEST_REFERENCE_CONTRACT_MISMATCH")
    if not result["allObjectsObserved"]:
        reasons.append("INPUT_OBJECT_MISSING")
    if not result["allRequiredKeysPresent"]:
        reasons.append("INPUT_KEY_MISSING")
    if not result["allTypesMatch"]:
        reasons.append("INPUT_TYPE_MISMATCH")
    if reasons:
        return {
            "status": "OPERATOR_INPUTS_UNRESOLVED",
            "reasonCodes": reasons,
            "nextAction": "reconcile-operator-inputs",
        }
    return {
        "status": "OPERATOR_INPUTS_OBSERVED",
        "reasonCodes": [],
        "nextAction": "bind-observation-to-product-dry-run",
    }


def build_assessment(snapshot: dict[str, Any], assessment_id: str) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_operator_inputs_assessment_id_invalid")
    profile, candidate, artifact_lock = local_contracts()
    contract = load_contract()
    result = aggregate(snapshot)
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "assessmentId": assessment_id,
        "generatedAt": snapshot["observedAt"],
        "targetClass": "engineering-trial",
        "executionMode": snapshot["executionMode"],
        "bindings": {
            "profileId": TRIAL_PROFILE_ID,
            "profileDigest": canonical_digest(profile),
            "workloadCandidateId": candidate["candidateId"],
            "workloadCandidateDigest": candidate["candidateDigest"],
            "artifactSetId": artifact_lock["artifactSetId"],
            "artifactSetDigest": artifact_lock["artifactSetDigest"],
            "operatorInputContractId": contract["contractId"],
            "operatorInputContractDigest": contract["contractDigest"],
        },
        "manifests": copy.deepcopy(snapshot["manifests"]),
        "observations": copy.deepcopy(snapshot["observations"]),
        "aggregate": result,
        "decision": decision_for(snapshot["executionMode"], result),
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
            "generatedAt",
            "targetClass",
            "executionMode",
            "bindings",
            "manifests",
            "observations",
            "aggregate",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_operator_inputs_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_operator_inputs_report_identity_invalid")
    parse_utc(value["generatedAt"], "sno_operator_inputs_report_time_invalid")
    profile, candidate, artifact_lock = local_contracts()
    contract = load_contract()
    bindings = object_value(value["bindings"], "sno_operator_inputs_bindings_invalid")
    if bindings != {
        "profileId": TRIAL_PROFILE_ID,
        "profileDigest": canonical_digest(profile),
        "workloadCandidateId": candidate["candidateId"],
        "workloadCandidateDigest": candidate["candidateDigest"],
        "artifactSetId": artifact_lock["artifactSetId"],
        "artifactSetDigest": artifact_lock["artifactSetDigest"],
        "operatorInputContractId": contract["contractId"],
        "operatorInputContractDigest": contract["contractDigest"],
    }:
        fail("sno_operator_inputs_bindings_invalid")
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": value["executionMode"],
        "observedAt": value["generatedAt"],
        "manifests": value["manifests"],
        "observations": value["observations"],
        "manifestReferencesContractBound": value["aggregate"].get(
            "manifestReferencesContractBound"
        ),
        "allObjectsObserved": value["aggregate"].get("allObjectsObserved"),
        "allRequiredKeysPresent": value["aggregate"].get("allRequiredKeysPresent"),
        "allTypesMatch": value["aggregate"].get("allTypesMatch"),
    }
    validate_snapshot(snapshot)
    expected_aggregate = aggregate(snapshot)
    if value["aggregate"] != expected_aggregate:
        fail("sno_operator_inputs_aggregate_invalid")
    expected_decision = decision_for(value["executionMode"], expected_aggregate)
    if value["decision"] != expected_decision or any(
        reason not in REASON_CODES
        for reason in value["decision"].get("reasonCodes", [])
    ):
        fail("sno_operator_inputs_decision_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_operator_inputs_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_operator_inputs_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_operator_inputs_report_digest_invalid")


def report_resolves_manifests(
    report: dict[str, Any], manifests: dict[str, Path]
) -> bool:
    validate_assessment(report)
    contract = load_contract()
    records = validate_manifest_contract(manifests, contract)
    return (
        report["executionMode"] == "live-read-only"
        and report["decision"]["status"] == "OPERATOR_INPUTS_OBSERVED"
        and report["aggregate"]["externalReferencesResolved"] is True
        and report["manifests"] == records
    )


def simulated_snapshot(
    observed: bool, observed_at: datetime | None = None
) -> dict[str, Any]:
    contract = load_contract()
    observations = []
    for item in contract["inputs"]:
        required_count = len(item["requiredKeys"])
        missing_count = 0 if observed else required_count
        observations.append(
            {
                "referenceDigest": reference_digest(item),
                "plane": item["plane"],
                "kind": item["kind"],
                "observed": observed,
                "typeMatches": observed,
                "requiredKeyCount": required_count,
                "observedRequiredKeyCount": required_count if observed else 0,
                "missingRequiredKeyCount": missing_count,
                "missingRequiredKeySetDigest": canonical_digest(
                    [] if observed else item["requiredKeys"]
                ),
            }
        )
    timestamp = observed_at or datetime(2026, 7, 28, 0, 0, tzinfo=timezone.utc)
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "simulated",
        "observedAt": utc_text(timestamp),
        "manifests": [
            {
                "plane": plane,
                "manifestDigest": canonical_digest(f"{plane}-fixture"),
                "externalReferenceCount": sum(
                    item["plane"] == plane for item in contract["inputs"]
                ),
                "externalReferenceSetDigest": canonical_digest(
                    f"{plane}-fixture-inputs"
                ),
            }
            for plane in PLANES
        ],
        "observations": observations,
        "manifestReferencesContractBound": True,
        "allObjectsObserved": observed,
        "allRequiredKeysPresent": observed,
        "allTypesMatch": observed,
    }
    validate_snapshot(snapshot)
    return snapshot


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except FileExistsError:
        fail("sno_operator_inputs_output_exists")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-lock")
    collect = commands.add_parser("collect")
    collect.add_argument("--client", type=Path, required=True)
    collect.add_argument("--kubeconfig", type=Path, required=True)
    collect.add_argument("--platform-manifest", type=Path, required=True)
    collect.add_argument("--runtime-manifest", type=Path, required=True)
    collect.add_argument("--model-manifest", type=Path, required=True)
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
    if args.command == "validate-lock":
        contract = load_contract()
        print(
            "sno_operator_input_contract_valid "
            f"digest={contract['contractDigest']} "
            f"inputs={len(contract['inputs'])} "
            "secretValuesStored=false deploymentAuthorized=false"
        )
        return 0
    if args.command == "collect":
        snapshot = collect_snapshot(
            args.client,
            args.kubeconfig,
            {
                "platform": args.platform_manifest,
                "runtimeHost": args.runtime_manifest,
                "modelPlane": args.model_manifest,
            },
            datetime.now(timezone.utc),
        )
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
    elif args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_operator_inputs_live_snapshot_requires_collect")
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
    else:
        report = load_json(args.report)
        validate_assessment(report)
    print(
        "sno_operator_inputs_valid "
        f"digest={report['reportDigest']} "
        f"status={report['decision']['status']} "
        f"objects={report['aggregate']['observedObjectCount']}/"
        f"{report['aggregate']['externalReferenceCount']} "
        f"keys={report['aggregate']['observedRequiredKeyCount']}/"
        f"{report['aggregate']['requiredKeyCount']} "
        "deploymentAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
