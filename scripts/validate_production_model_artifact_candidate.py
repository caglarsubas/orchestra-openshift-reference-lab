#!/usr/bin/env python3
"""Validate the inert production model-artifact candidate."""

from __future__ import annotations

import re
import sys
from typing import Any, NoReturn

try:
    from scripts.validate_dependency_admission import validate_admission
    from scripts.validate_dependency_bom import validate_dependency_bom
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_dependency_admission import validate_admission
    from validate_dependency_bom import validate_dependency_bom
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, canonical_digest, load_json


CANDIDATE_PATH = ROOT / "config" / "production-model-artifact-candidate.lock.json"
SCHEMA_PATH = ROOT / "schemas" / "production-model-artifact-candidate-v1.schema.json"
BOM_PATH = ROOT / "config" / "dependency-bom.lock.json"
ADMISSION_PATH = ROOT / "config" / "dependency-admission.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
TOPOLOGY_PATH = ROOT / "config" / "lab.lock.json"
KIND = "orchestra.openshift.production-model-artifact-candidate.v1"
CANDIDATE_ID = "orchestra-production-model-artifacts-2026-07-28.1"
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMMUTABLE_REF = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
EXPECTED_CANDIDATE_DIGEST = (
    "sha256:cae278d46301c9777265df6b8a093e577472e7ee90ba26ad92eef233c90589dc"
)
EXPECTED_CONTAINER = {
    "id": "llama-cpp-cpu-server",
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
}
EXPECTED_MODELS = [
    {
        "id": "orchestra-reference-chat-model",
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
        "licenseReviewStatus": "pending-independent-review",
        "servedModelId": "orchestra-reference-chat",
        "mountPath": "/models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
        "materialization": "operator-prestaged-read-only-pvc",
        "runtimeDownloadAllowed": False,
        "maximumAllowedBytes": 1073741824,
        "qualityStatus": "pending-live-inference",
        "capabilities": {"chat": True, "embeddings": False},
    },
    {
        "id": "orchestra-reference-embedding-model",
        "serviceId": "embedding-model",
        "provider": "Nomic",
        "repository": "nomic-ai/nomic-embed-text-v1.5-GGUF",
        "revision": "f750a25aba2d24830d874eb4e1af468f37248a37",
        "filename": "nomic-embed-text-v1.5.Q4_K_M.gguf",
        "immutableUrl": (
            "https://huggingface.co/nomic-ai/"
            "nomic-embed-text-v1.5-GGUF/resolve/"
            "f750a25aba2d24830d874eb4e1af468f37248a37/"
            "nomic-embed-text-v1.5.Q4_K_M.gguf"
        ),
        "digest": (
            "sha256:d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac"
        ),
        "sizeBytes": 84106624,
        "format": "gguf",
        "quantization": "Q4_K_M",
        "license": "Apache-2.0",
        "licenseReviewStatus": "pending-independent-review",
        "servedModelId": "orchestra-reference-embedding",
        "mountPath": "/models/nomic-embed-text-v1.5.Q4_K_M.gguf",
        "materialization": "operator-prestaged-read-only-pvc",
        "runtimeDownloadAllowed": False,
        "maximumAllowedBytes": 268435456,
        "qualityStatus": "pending-live-inference",
        "capabilities": {"chat": False, "embeddings": True},
    },
]
EXPECTED_RUNTIME_BINDINGS = [
    {
        "serviceId": "model-backend",
        "replicas": 2,
        "containerId": "llama-cpp-cpu-server",
        "modelId": "orchestra-reference-chat-model",
        "protocol": "openai-compatible-https",
        "port": 8000,
        "authentication": "api-key-file",
        "tls": "operator-secret-files",
        "networkIngress": "model-plane-only",
        "healthPath": "/health",
        "modelInventoryPath": "/v1/models",
        "openAiPath": "/v1/chat/completions",
        "startupArguments": [
            "--model",
            "/models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
            "--alias",
            "orchestra-reference-chat",
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
    },
    {
        "serviceId": "embedding-model",
        "replicas": 1,
        "containerId": "llama-cpp-cpu-server",
        "modelId": "orchestra-reference-embedding-model",
        "protocol": "openai-compatible-https",
        "port": 8000,
        "authentication": "api-key-file",
        "tls": "operator-secret-files",
        "networkIngress": "model-plane-only",
        "healthPath": "/health",
        "modelInventoryPath": "/v1/models",
        "openAiPath": "/v1/embeddings",
        "startupArguments": [
            "--model",
            "/models/nomic-embed-text-v1.5.Q4_K_M.gguf",
            "--alias",
            "orchestra-reference-embedding",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--embedding",
            "--pooling",
            "mean",
            "--api-key-file",
            "/var/run/secrets/orchestra-model/api-keys",
            "--ssl-key-file",
            "/var/run/secrets/orchestra-model/tls.key",
            "--ssl-cert-file",
            "/var/run/secrets/orchestra-model/tls.crt",
        ],
    },
]
ACTIVATION_REASONS = [
    "DEPENDENCY_BOM_REISSUE_REQUIRED",
    "DEPENDENCY_ADMISSION_REISSUE_REQUIRED",
    "UPSTREAM_IMAGE_EXCEPTION_REVIEW_PENDING",
    "DESTINATION_MIRROR_PROOF_MISSING",
    "LAB_SIGNATURE_MISSING",
    "MODEL_BYTE_CUSTODY_MISSING",
    "MODEL_LICENSE_REVIEW_PENDING",
    "MODEL_PVC_MATERIALIZATION_PROOF_MISSING",
    "SECRET_AND_TLS_BINDINGS_UNRESOLVED",
    "OPENSHIFT_SERVER_SIDE_DRY_RUN_MISSING",
    "LIVE_CHAT_AND_EMBEDDING_QUALITY_PROOF_MISSING",
    "LIVE_DEPENDENCY_CONNECTIVITY_MISSING",
]
CONTROLS = {
    "scope": "production-model-artifact-candidate-only",
    "sourceOnly": True,
    "artifactBytesStored": False,
    "productionDependencyBomMutated": False,
    "dependencyAdmissionMutated": False,
    "manifestsEmitted": False,
    "argocdApplicationsEmitted": False,
    "activeKustomizationReferenced": False,
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
    "chatQualityVerified": False,
    "embeddingQualityVerified": False,
}
FORBIDDEN_KEYS = {
    "apiVersion",
    "application",
    "applications",
    "data",
    "imagePullSecret",
    "manifest",
    "manifests",
    "metadata",
    "secretData",
    "secretValue",
    "spec",
    "stringData",
    "values",
    "valuesObject",
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def find_service(bom: dict[str, Any], service_id: str) -> dict[str, Any]:
    matches = [
        value
        for value in bom.get("serviceContracts", [])
        if isinstance(value, dict) and value.get("id") == service_id
    ]
    if len(matches) != 1:
        fail(f"production_model_bom_service_missing:{service_id}")
    return matches[0]


def reject_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_KEYS.intersection(value)
        if forbidden:
            fail(f"production_model_forbidden_key:{sorted(forbidden)[0]}")
        for child in value.values():
            reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            reject_forbidden_keys(child)


def digest_without_self(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("candidateDigest", None)
    return canonical_digest(unsigned)


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
            fail(f"production_model_schema_not_strict:{path}")
        for key, child in value.items():
            visit(child, f"{path}/{key}")

    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id")
        != (
            "https://schemas.prometa.ai/orchestra/reference-lab/"
            "production-model-artifact-candidate-v1.schema.json"
        )
        or schema.get("additionalProperties") is not False
    ):
        fail("production_model_schema_identity_invalid")
    visit(schema, "$")


def validate_bindings(
    value: dict[str, Any],
    bom: dict[str, Any],
    admission: dict[str, Any],
    release_set: dict[str, Any],
    schema: dict[str, Any],
) -> None:
    expected = {
        "dependencyBomId": bom["bomId"],
        "dependencyBomDigest": canonical_digest(bom),
        "dependencyAdmissionDigest": canonical_digest(admission),
        "releaseSetId": release_set["releaseSetId"],
        "releaseSetDigest": canonical_digest(release_set),
        "schemaDigest": canonical_digest(schema),
    }
    if value.get("bindings") != expected:
        fail("production_model_bindings_invalid")


def validate_frozen_bom_gap(bom: dict[str, Any]) -> None:
    for service_id in ("model-backend", "embedding-model"):
        service = find_service(bom, service_id)
        if (
            service.get("provider") != "unselected"
            or service.get("activationState") != "blocked"
            or service.get("reasonCodes") != ["MODEL_ARTIFACT_CONTRACT_MISSING"]
        ):
            fail(f"production_model_bom_reissue_boundary_invalid:{service_id}")


def validate_models(models: Any) -> None:
    if models != EXPECTED_MODELS:
        fail("production_model_artifacts_invalid")
    for model in models:
        if (
            not REVISION.fullmatch(model["revision"])
            or not DIGEST.fullmatch(model["digest"])
            or f"/resolve/{model['revision']}/" not in model["immutableUrl"]
            or not model["immutableUrl"].endswith(model["filename"])
            or model["mountPath"] != f"/models/{model['filename']}"
            or model["sizeBytes"] > model["maximumAllowedBytes"]
            or model["runtimeDownloadAllowed"]
        ):
            fail(f"production_model_artifact_derivation_invalid:{model['id']}")


def validate_candidate(
    value: dict[str, Any],
    bom: dict[str, Any],
    admission: dict[str, Any],
    release_set: dict[str, Any],
    topology: dict[str, Any],
    schema: dict[str, Any],
) -> str:
    reject_forbidden_keys(value)
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "candidateId",
            "profileId",
            "targetClass",
            "executionMode",
            "architecture",
            "bindings",
            "container",
            "models",
            "runtimeBindings",
            "activation",
            "controls",
            "claims",
            "candidateDigest",
        },
        "production_model_candidate_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or value["candidateId"] != CANDIDATE_ID
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "source-only"
        or value["architecture"] != "linux/amd64"
    ):
        fail("production_model_candidate_identity_invalid")

    validate_schema_strictness(schema)
    validate_dependency_bom(bom, topology)
    validate_admission(admission, bom, topology)
    validate_release_set(release_set)
    validate_bindings(value, bom, admission, release_set, schema)
    validate_frozen_bom_gap(bom)

    if value["container"] != EXPECTED_CONTAINER:
        fail("production_model_container_invalid")
    container = value["container"]
    if (
        not IMMUTABLE_REF.fullmatch(container["resolvedReference"])
        or not DIGEST.fullmatch(container["indexDigest"])
        or not DIGEST.fullmatch(container["platformDigest"])
        or not container["resolvedReference"].endswith(container["platformDigest"])
    ):
        fail("production_model_container_digest_invalid")

    validate_models(value["models"])
    if value["runtimeBindings"] != EXPECTED_RUNTIME_BINDINGS:
        fail("production_model_runtime_bindings_invalid")
    if value["activation"] != {
        "state": "blocked",
        "reasonCodes": ACTIVATION_REASONS,
    }:
        fail("production_model_activation_invalid")
    if value["controls"] != CONTROLS:
        fail("production_model_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("production_model_claims_invalid")

    digest = digest_without_self(value)
    if value["candidateDigest"] != digest:
        fail(f"production_model_candidate_digest_invalid:{digest}")
    if digest != EXPECTED_CANDIDATE_DIGEST:
        fail(f"production_model_candidate_digest_changed:{digest}")
    return digest


def main() -> int:
    value = load_json(CANDIDATE_PATH)
    digest = validate_candidate(
        value,
        load_json(BOM_PATH),
        load_json(ADMISSION_PATH),
        load_json(RELEASE_SET_PATH),
        load_json(TOPOLOGY_PATH),
        load_json(SCHEMA_PATH),
    )
    print(
        "production_model_artifact_candidate_valid "
        f"digest={digest} models=2 chatReplicas=2 embeddingReplicas=1 "
        "sourceOnly=true deploymentAuthorized=false campaignEligible=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
