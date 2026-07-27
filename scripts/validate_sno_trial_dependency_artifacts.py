#!/usr/bin/env python3
"""Validate immutable source artifacts for SNO trial dependencies."""

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
ARTIFACT_SET_PATH = ROOT / "config" / "sno-trial-dependency-artifacts.lock.json"
BOM_PATH = ROOT / "config" / "dependency-bom.lock.json"
ADMISSION_PATH = ROOT / "config" / "dependency-admission.lock.json"
RUNTIME_CONTRACT_PATH = (
    ROOT / "config" / "sno-trial-dependency-runtime-contracts.lock.json"
)
KIND = "orchestra.openshift.sno-trial-dependency-artifact-set.v1"
ARTIFACT_SET_ID = "orchestra-sno-trial-dependency-artifacts-2026-07-28.1"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMMUTABLE_REF = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
EXPECTED_ARTIFACT_SET_DIGEST = (
    "sha256:5b60283c1e02f20f4a224b55a218d62b308315adf6d58c8120f021e1f8333073"
)
EXPECTED_CONTAINERS = {
    "valkey-image": {
        "serviceId": "valkey",
        "sourceReference": "docker.io/valkey/valkey:9.1.0",
        "resolvedReference": (
            "docker.io/valkey/valkey@"
            "sha256:64f6e8025b9a798061c8c79e73a7a79dbc8cca437e6af682e9f7605ff334615d"
        ),
        "indexDigest": (
            "sha256:8e8d64b405ce18f41b8e5ee20aa4687a8ed0022d1298f2ce31cdcf3a76e09411"
        ),
        "platformDigest": (
            "sha256:64f6e8025b9a798061c8c79e73a7a79dbc8cca437e6af682e9f7605ff334615d"
        ),
        "platform": "linux/amd64",
        "version": "9.1.0",
        "sourceRevision": None,
        "sourceUrl": "https://github.com/valkey-io/valkey",
        "license": "BSD-3-Clause",
        "upstreamVerification": {
            "status": "pending",
            "method": "reviewed-exception",
            "identityPolicy": None,
        },
        "runtimeCompatibility": {
            "arbitraryUidRequired": True,
            "fixedUidAllowed": False,
            "readOnlyRootFilesystemRequired": True,
            "serviceAccountTokenAutomount": False,
            "requiredWritablePaths": ["/data"],
        },
    },
    "model-backend-image": {
        "serviceId": "model-backend",
        "sourceReference": "ghcr.io/ggml-org/llama.cpp:server",
        "resolvedReference": (
            "ghcr.io/ggml-org/llama.cpp@"
            "sha256:7a670b0633a2b33d915ca958fc1e4977334924590c9bd5ffc9d4813dd168d77b"
        ),
        "indexDigest": (
            "sha256:a576442ad3649c0b5ea74e20ad29a17c121117f32607cfe59ff27cc38066f874"
        ),
        "platformDigest": (
            "sha256:7a670b0633a2b33d915ca958fc1e4977334924590c9bd5ffc9d4813dd168d77b"
        ),
        "platform": "linux/amd64",
        "version": "b10143",
        "sourceRevision": "88b47a755c72fed4b22fba0fd262e2d7b7d01583",
        "sourceUrl": "https://github.com/ggml-org/llama.cpp",
        "license": "MIT",
        "upstreamVerification": {
            "status": "pending",
            "method": "reviewed-exception",
            "identityPolicy": None,
        },
        "runtimeCompatibility": {
            "arbitraryUidRequired": True,
            "fixedUidAllowed": False,
            "readOnlyRootFilesystemRequired": True,
            "serviceAccountTokenAutomount": False,
            "requiredWritablePaths": [],
        },
    },
}
EXPECTED_MODEL = {
    "id": "orchestra-reference-cpu-model",
    "serviceId": "model-backend",
    "provider": "Qwen",
    "repository": "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
    "revision": "9217f5db79a29953eb74d5343926648285ec7e67",
    "filename": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
    "immutableUrl": (
        "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/"
        "9217f5db79a29953eb74d5343926648285ec7e67/"
        "qwen2.5-0.5b-instruct-q4_k_m.gguf"
    ),
    "digest": (
        "sha256:74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
    ),
    "sizeBytes": 491400032,
    "format": "gguf",
    "quantization": "Q4_K_M",
    "license": "Apache-2.0",
    "servedModelId": "orchestra-reference-cpu",
    "mountPath": "/models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
    "materialization": "operator-prestaged-read-only-pvc",
    "runtimeDownloadAllowed": False,
    "maximumAllowedBytes": 4294967296,
    "chatRequired": True,
    "embeddingQualityCertifying": False,
}
EXPECTED_RUNTIME_BINDING = {
    "containerId": "model-backend-image",
    "modelId": "orchestra-reference-cpu-model",
    "protocol": "openai-compatible-https",
    "port": 8000,
    "authentication": "api-key-file",
    "tls": "operator-secret-files",
    "healthPath": "/health",
    "modelInventoryPath": "/v1/models",
    "startupArguments": [
        "--model",
        "/models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
        "--alias",
        "orchestra-reference-cpu",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        "--ctx-size",
        "2048",
        "--parallel",
        "1",
        "--api-key-file",
        "/var/run/secrets/orchestra-model/api-keys",
        "--ssl-key-file",
        "/var/run/secrets/orchestra-model/tls.key",
        "--ssl-cert-file",
        "/var/run/secrets/orchestra-model/tls.crt",
    ],
}
ACTIVATION_REASONS = [
    "UPSTREAM_VERIFICATION_PENDING",
    "DESTINATION_MIRROR_PROOF_MISSING",
    "LAB_SIGNATURE_MISSING",
    "MODEL_PVC_MATERIALIZATION_PROOF_MISSING",
    "DEPENDENCY_SECRET_REFERENCES_UNRESOLVED",
    "DEPENDENCY_TLS_REFERENCES_UNRESOLVED",
    "STORAGE_CLASS_REFERENCE_UNRESOLVED",
    "OPENSHIFT_SERVER_SIDE_DRY_RUN_MISSING",
    "LIVE_DEPENDENCY_CONNECTIVITY_MISSING",
]
CONTROLS = {
    "scope": "sno-engineering-trial-dependency-artifacts-only",
    "sourceOnly": True,
    "artifactBytesStored": False,
    "productionDependencyProfileMutated": False,
    "workloadCandidateMutated": False,
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


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def find_by_id(values: Any, identifier: str, code: str) -> dict[str, Any]:
    if not isinstance(values, list):
        fail(code)
    matches = [
        item
        for item in values
        if isinstance(item, dict) and item.get("id") == identifier
    ]
    if len(matches) != 1:
        fail(code)
    return matches[0]


def reject_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_KEYS.intersection(value)
        if forbidden:
            fail(f"dependency_artifact_forbidden_key:{sorted(forbidden)[0]}")
        for child in value.values():
            reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            reject_forbidden_keys(child)


def digest_without_self(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("artifactSetDigest", None)
    return canonical_digest(unsigned)


def validate_bindings(
    value: dict[str, Any],
    bom: dict[str, Any],
    admission: dict[str, Any],
    runtime_contracts: dict[str, Any],
) -> None:
    expected = {
        "dependencyBomDigest": canonical_digest(bom),
        "dependencyAdmissionDigest": canonical_digest(admission),
        "runtimeContractSetDigest": runtime_contracts.get("contractSetDigest"),
    }
    if value.get("bindings") != expected:
        fail("dependency_artifact_bindings_invalid")


def validate_valkey_derivation(
    container: dict[str, Any],
    bom: dict[str, Any],
    runtime_contracts: dict[str, Any],
) -> None:
    chart = find_by_id(
        bom.get("chartPackages"), "valkey", "dependency_artifact_valkey_chart_missing"
    )
    runtime = find_by_id(
        runtime_contracts.get("contracts"),
        "valkey",
        "dependency_artifact_valkey_runtime_missing",
    )
    if (
        chart.get("chart") != "valkey"
        or chart.get("chartVersion") != "0.10.0"
        or chart.get("appVersion") != container["version"]
        or chart.get("packageDigest")
        != "sha256:6497e784e1b707c303e358f6f9d6f82f931618f4b1e5a7aeb0946df51a081fe6"
        or runtime.get("artifact", {}).get("sourceClass") != "unresolved"
    ):
        fail("dependency_artifact_valkey_derivation_invalid")


def validate_model_derivation(
    container: dict[str, Any],
    model: dict[str, Any],
    runtime_contracts: dict[str, Any],
) -> None:
    runtime = find_by_id(
        runtime_contracts.get("contracts"),
        "model-backend",
        "dependency_artifact_model_runtime_missing",
    )
    if (
        runtime.get("artifact", {}).get("sourceClass") != "unresolved"
        or model["serviceId"] != container["serviceId"]
        or model["sizeBytes"] > model["maximumAllowedBytes"]
        or model["runtimeDownloadAllowed"]
        or not model["immutableUrl"].endswith(model["filename"])
    ):
        fail("dependency_artifact_model_derivation_invalid")


def validate_artifact_set(
    value: dict[str, Any],
    bom: dict[str, Any],
    admission: dict[str, Any],
    runtime_contracts: dict[str, Any],
) -> str:
    reject_forbidden_keys(value)
    if (
        value.get("schemaVersion") != 1
        or value.get("kind") != KIND
        or value.get("artifactSetId") != ARTIFACT_SET_ID
        or value.get("profileId") != PROFILE_ID
        or value.get("targetClass") != "engineering-trial"
        or value.get("executionMode") != "source-only"
        or value.get("architecture") != "linux/amd64"
    ):
        fail("dependency_artifact_identity_invalid")
    validate_bindings(value, bom, admission, runtime_contracts)

    containers = value.get("containers")
    if not isinstance(containers, list) or [
        item.get("id") for item in containers if isinstance(item, dict)
    ] != list(EXPECTED_CONTAINERS):
        fail("dependency_artifact_container_order_invalid")
    for container in containers:
        identifier = container["id"]
        expected = {"id": identifier, **EXPECTED_CONTAINERS[identifier]}
        if container != expected:
            fail(f"dependency_artifact_container_invalid:{identifier}")
        if (
            not IMMUTABLE_REF.fullmatch(container["resolvedReference"])
            or not DIGEST.fullmatch(container["indexDigest"])
            or not DIGEST.fullmatch(container["platformDigest"])
            or not container["resolvedReference"].endswith(container["platformDigest"])
        ):
            fail(f"dependency_artifact_container_digest_invalid:{identifier}")

    models = value.get("models")
    if models != [EXPECTED_MODEL]:
        fail("dependency_artifact_model_invalid")
    if value.get("runtimeBinding") != EXPECTED_RUNTIME_BINDING:
        fail("dependency_artifact_runtime_binding_invalid")
    validate_valkey_derivation(containers[0], bom, runtime_contracts)
    validate_model_derivation(containers[1], models[0], runtime_contracts)

    if value.get("activation") != {
        "state": "blocked",
        "reasonCodes": ACTIVATION_REASONS,
    }:
        fail("dependency_artifact_activation_invalid")
    if value.get("controls") != CONTROLS:
        fail("dependency_artifact_controls_invalid")
    if value.get("claims") != CLAIMS:
        fail("dependency_artifact_claims_invalid")

    digest = digest_without_self(value)
    if value.get("artifactSetDigest") != digest:
        fail(f"dependency_artifact_digest_invalid:{digest}")
    if digest != EXPECTED_ARTIFACT_SET_DIGEST:
        fail(f"dependency_artifact_digest_changed:{digest}")
    return digest


def main() -> int:
    value = load_json(ARTIFACT_SET_PATH)
    digest = validate_artifact_set(
        value,
        load_json(BOM_PATH),
        load_json(ADMISSION_PATH),
        load_json(RUNTIME_CONTRACT_PATH),
    )
    print(
        "sno_trial_dependency_artifacts_valid "
        f"digest={digest} containers=2 models=1 activation=blocked"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
