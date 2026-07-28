#!/usr/bin/env python3
"""Validate source-only runtime contracts for the SNO trial dependencies."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_repository import canonical_digest, load_json
except ModuleNotFoundError:
    from validate_repository import canonical_digest, load_json


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "sno-trial-dependency-runtime-contracts.lock.json"
CANDIDATE_PATH = ROOT / "config" / "sno-trial-workload-candidate.lock.json"
DEPENDENCY_PATH = ROOT / "config" / "dependency-admission.lock.json"
OPERATOR_INPUT_PATH = ROOT / "config" / "sno-trial-operator-inputs.lock.json"
DEPENDENCY_ARTIFACT_PATH = (
    ROOT / "config" / "sno-trial-dependency-artifacts.lock.json"
)
KIND = "orchestra.openshift.sno-trial-dependency-runtime-contract-set.v1"
CONTRACT_SET_ID = "orchestra-sno-trial-dependency-runtime-2026-07-28.2"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
SERVICE_IDS = (
    "postgresql",
    "clickhouse",
    "jetstream",
    "valkey",
    "model-backend",
)
TOP_KEYS = {
    "schemaVersion",
    "kind",
    "contractSetId",
    "profileId",
    "targetClass",
    "executionMode",
    "architecture",
    "bindings",
    "runtimeDefaults",
    "contracts",
    "activation",
    "controls",
    "claims",
    "contractSetDigest",
}
CONTRACT_KEYS = {
    "id",
    "sourceId",
    "workloadKind",
    "artifact",
    "resources",
    "persistence",
    "network",
    "protocol",
    "behavior",
}
FORBIDDEN_KEYS = {
    "apiVersion",
    "data",
    "stringData",
    "secretValue",
    "secretData",
    "manifest",
    "manifests",
    "application",
    "applications",
    "values",
    "valuesObject",
}
RUNTIME_DEFAULTS = {
    "replicas": 1,
    "highAvailability": False,
    "autoscalingEnabled": False,
    "podDisruptionBudgetEnabled": False,
    "topologySpreadEnabled": False,
    "serviceAccountTokenAutomount": False,
    "security": {
        "scc": "restricted-v2",
        "runAsNonRoot": True,
        "arbitraryUidRequired": True,
        "fixedUid": None,
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilitiesDropAll": True,
        "seccompProfile": "RuntimeDefault",
    },
}
SERVICE_SPECS = {
    "postgresql": {
        "sourceId": "cloudnative-pg-postgresql-16",
        "workloadKind": "StatefulSet",
        "persistence": {
            "enabled": True,
            "purpose": "relational-state",
            "sizeGiB": 10,
            "accessMode": "ReadWriteOnce",
            "storageClassRef": None,
            "storageClassResolved": False,
            "backupEnabled": False,
        },
        "network": {
            "serviceType": "ClusterIP",
            "defaultDeny": True,
            "allowedClients": ["platform", "runtime-host"],
            "egressRequired": False,
        },
        "protocol": {
            "name": "postgresql",
            "port": 5432,
            "tlsRequired": True,
            "authenticationRequired": True,
            "credentialSecretRef": None,
            "certificateSecretRef": None,
            "trustedCaConfigMapRef": None,
            "referencesResolved": False,
        },
        "behavior": {
            "durability": "fsync-required",
            "readiness": "pg-isready-authenticated",
            "degradation": "fail-closed-no-local-database",
            "runtimeDownloadAllowed": False,
        },
    },
    "clickhouse": {
        "sourceId": "clickhouse-server-lts",
        "workloadKind": "StatefulSet",
        "persistence": {
            "enabled": True,
            "purpose": "telemetry-state",
            "sizeGiB": 20,
            "accessMode": "ReadWriteOnce",
            "storageClassRef": None,
            "storageClassResolved": False,
            "backupEnabled": False,
        },
        "network": {
            "serviceType": "ClusterIP",
            "defaultDeny": True,
            "allowedClients": ["platform"],
            "egressRequired": False,
        },
        "protocol": {
            "name": "clickhouse-https",
            "port": 8443,
            "tlsRequired": True,
            "authenticationRequired": True,
            "credentialSecretRef": None,
            "certificateSecretRef": None,
            "trustedCaConfigMapRef": None,
            "referencesResolved": False,
        },
        "behavior": {
            "durability": "single-replica-persistent",
            "readiness": "https-ping-authenticated",
            "degradation": "typed-telemetry-storage-unavailable",
            "runtimeDownloadAllowed": False,
        },
    },
    "jetstream": {
        "sourceId": "nats-server",
        "workloadKind": "StatefulSet",
        "persistence": {
            "enabled": True,
            "purpose": "durable-event-stream",
            "sizeGiB": 5,
            "accessMode": "ReadWriteOnce",
            "storageClassRef": None,
            "storageClassResolved": False,
            "backupEnabled": False,
        },
        "network": {
            "serviceType": "ClusterIP",
            "defaultDeny": True,
            "allowedClients": ["platform"],
            "egressRequired": False,
        },
        "protocol": {
            "name": "nats-tls",
            "port": 4222,
            "tlsRequired": True,
            "authenticationRequired": True,
            "credentialSecretRef": None,
            "certificateSecretRef": None,
            "trustedCaConfigMapRef": None,
            "referencesResolved": False,
        },
        "behavior": {
            "durability": "jetstream-file-store-replicas-one",
            "readiness": "nats-server-ready",
            "degradation": "buffer-or-reject-without-in-process-downgrade",
            "runtimeDownloadAllowed": False,
        },
    },
    "valkey": {
        "sourceId": "valkey",
        "workloadKind": "StatefulSet",
        "persistence": {
            "enabled": True,
            "purpose": "shared-rate-limit-and-budget-state",
            "sizeGiB": 2,
            "accessMode": "ReadWriteOnce",
            "storageClassRef": None,
            "storageClassResolved": False,
            "backupEnabled": False,
        },
        "network": {
            "serviceType": "ClusterIP",
            "defaultDeny": True,
            "allowedClients": ["platform", "model-plane"],
            "egressRequired": False,
        },
        "protocol": {
            "name": "valkey-tls",
            "port": 6379,
            "tlsRequired": True,
            "authenticationRequired": True,
            "credentialSecretRef": None,
            "certificateSecretRef": None,
            "trustedCaConfigMapRef": None,
            "referencesResolved": False,
        },
        "behavior": {
            "durability": "aof-appendfsync-everysec",
            "readiness": "valkey-ping-authenticated",
            "degradation": "conservative-deny-no-local-rate-limit",
            "runtimeDownloadAllowed": False,
        },
    },
    "model-backend": {
        "sourceId": "model-backend",
        "workloadKind": "StatefulSet",
        "persistence": {
            "enabled": True,
            "purpose": "immutable-model-artifact-cache",
            "sizeGiB": 10,
            "accessMode": "ReadWriteOnce",
            "storageClassRef": None,
            "storageClassResolved": False,
            "backupEnabled": False,
        },
        "network": {
            "serviceType": "ClusterIP",
            "defaultDeny": True,
            "allowedClients": ["model-plane"],
            "egressRequired": False,
        },
        "protocol": {
            "name": "openai-compatible-https",
            "port": 8000,
            "tlsRequired": True,
            "authenticationRequired": True,
            "credentialSecretRef": None,
            "certificateSecretRef": None,
            "trustedCaConfigMapRef": None,
            "referencesResolved": False,
        },
        "behavior": {
            "durability": "model-artifact-prestaged-read-only",
            "readiness": "health-and-v1-models",
            "degradation": "typed-model-backend-unavailable",
            "runtimeDownloadAllowed": False,
        },
    },
}
ACTIVATION_REASONS = [
    "DEPENDENCY_SOURCE_ADMISSION_INCOMPLETE",
    "DEPENDENCY_SECRET_REFERENCES_UNRESOLVED",
    "DEPENDENCY_TLS_REFERENCES_UNRESOLVED",
    "STORAGE_CLASS_REFERENCE_UNRESOLVED",
    "DESTINATION_MIRROR_PROOF_MISSING",
    "OPENSHIFT_SERVER_SIDE_DRY_RUN_MISSING",
    "LIVE_DEPENDENCY_CONNECTIVITY_MISSING",
]
CONTROLS = {
    "scope": "sno-engineering-trial-dependencies-only",
    "sourceOnly": True,
    "productionDependencyProfileMutated": False,
    "manifestsEmitted": False,
    "argocdApplicationsEmitted": False,
    "kustomizationReferenced": False,
    "secretValuesStored": False,
    "runtimeModelDownloadAllowed": False,
    "cloudMutationAuthorized": False,
    "deploymentAuthorized": False,
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


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def find_workload(candidate: dict[str, Any], identifier: str) -> dict[str, Any]:
    matches = [
        item
        for item in candidate.get("workloads", [])
        if isinstance(item, dict) and item.get("id") == identifier
    ]
    if len(matches) != 1:
        fail(f"sno_dependency_runtime_candidate_workload_invalid:{identifier}")
    return matches[0]


def reject_inline_deployment(value: Any) -> None:
    if isinstance(value, dict):
        overlap = set(value) & FORBIDDEN_KEYS
        if overlap:
            fail(
                "sno_dependency_runtime_inline_deployment_forbidden:"
                f"{sorted(overlap)[0]}"
            )
        for child in value.values():
            reject_inline_deployment(child)
    elif isinstance(value, list):
        for child in value:
            reject_inline_deployment(child)


def unsigned_digest(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("contractSetDigest", None)
    return canonical_digest(unsigned)


def validate_contract_set(
    value: dict[str, Any],
    candidate: dict[str, Any],
    dependency_admission: dict[str, Any],
    operator_inputs: dict[str, Any],
    dependency_artifacts: dict[str, Any],
) -> str:
    reject_inline_deployment(value)
    exact_keys(value, TOP_KEYS, "sno_dependency_runtime_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or value["contractSetId"] != CONTRACT_SET_ID
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "source-only"
        or value["architecture"] != "linux/amd64"
    ):
        fail("sno_dependency_runtime_identity_invalid")

    expected_bindings = {
        "workloadCandidateId": candidate.get("candidateId"),
        "workloadCandidateDigest": candidate.get("candidateDigest"),
        "dependencyAdmissionDigest": canonical_digest(dependency_admission),
        "operatorInputContractDigest": operator_inputs.get("contractDigest"),
        "dependencyArtifactSetDigest": dependency_artifacts.get(
            "artifactSetDigest"
        ),
    }
    bindings = exact_keys(
        value["bindings"],
        set(expected_bindings),
        "sno_dependency_runtime_bindings_invalid",
    )
    if bindings != expected_bindings or not all(
        isinstance(item, str) and DIGEST.fullmatch(item)
        for name, item in bindings.items()
        if name.endswith("Digest")
    ):
        fail("sno_dependency_runtime_bindings_invalid")

    if value["runtimeDefaults"] != RUNTIME_DEFAULTS:
        fail("sno_dependency_runtime_defaults_invalid")
    contracts = value["contracts"]
    if (
        not isinstance(contracts, list)
        or len(contracts) != len(SERVICE_IDS)
        or [item.get("id") for item in contracts if isinstance(item, dict)]
        != list(SERVICE_IDS)
    ):
        fail("sno_dependency_runtime_inventory_invalid")
    for contract in contracts:
        contract = exact_keys(
            contract,
            CONTRACT_KEYS,
            "sno_dependency_runtime_contract_keys_invalid",
        )
        identifier = contract["id"]
        expected = SERVICE_SPECS[identifier]
        workload = find_workload(candidate, identifier)
        if (
            contract["sourceId"] != expected["sourceId"]
            or contract["workloadKind"] != expected["workloadKind"]
            or contract["artifact"] != workload["artifact"]
            or contract["resources"] != workload["resources"]
            or contract["persistence"] != expected["persistence"]
            or contract["network"] != expected["network"]
            or contract["protocol"] != expected["protocol"]
            or contract["behavior"] != expected["behavior"]
        ):
            fail(f"sno_dependency_runtime_contract_invalid:{identifier}")

    unresolved = {
        item["id"]
        for item in contracts
        if item["artifact"]["admissionState"] == "unresolved"
    }
    if unresolved:
        fail("sno_dependency_runtime_unresolved_artifacts_invalid")
    if value["activation"] != {
        "state": "blocked",
        "reasonCodes": ACTIVATION_REASONS,
    }:
        fail("sno_dependency_runtime_activation_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_dependency_runtime_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_dependency_runtime_claims_invalid")
    digest = value["contractSetDigest"]
    if (
        not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
        or digest != unsigned_digest(value)
    ):
        fail("sno_dependency_runtime_digest_invalid")
    return digest


def main() -> int:
    value = load_json(CONTRACT_PATH)
    candidate = load_json(CANDIDATE_PATH)
    dependency_admission = load_json(DEPENDENCY_PATH)
    operator_inputs = load_json(OPERATOR_INPUT_PATH)
    dependency_artifacts = load_json(DEPENDENCY_ARTIFACT_PATH)
    digest = validate_contract_set(
        value,
        candidate,
        dependency_admission,
        operator_inputs,
        dependency_artifacts,
    )
    print(
        "sno_trial_dependency_runtime_contracts_valid "
        f"digest={digest} contracts={len(SERVICE_IDS)} "
        "activation=blocked manifests=0 campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
