#!/usr/bin/env python3
"""Validate the inactive SNO Valkey and model-backend manifest candidate."""

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
CANDIDATE_PATH = ROOT / "config" / "sno-trial-dependency-manifest-candidate.lock.json"
WORKLOAD_PATH = ROOT / "config" / "sno-trial-workload-candidate.lock.json"
RUNTIME_PATH = ROOT / "config" / "sno-trial-dependency-runtime-contracts.lock.json"
ARTIFACT_PATH = ROOT / "config" / "sno-trial-dependency-artifacts.lock.json"
ACTIVE_DEPENDENCY_KUSTOMIZATION = (
    ROOT / "gitops" / "dependencies" / "reference-lab" / "kustomization.yaml"
)
KIND = "orchestra.openshift.sno-trial-dependency-manifest-candidate.v1"
CANDIDATE_ID = "orchestra-sno-trial-dependency-manifests-2026-07-28.3"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
MANIFEST_ROOT = ROOT / "gitops" / "dependencies" / "candidates" / "sno-trial"
KUSTOMIZATION_PATH = MANIFEST_ROOT / "kustomization.yaml"
STORAGE_CLASS_PLACEHOLDER = "ORCHESTRA_SNO_STORAGE_CLASS_REQUIRED"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMMUTABLE_IMAGE = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
EXPECTED_CANDIDATE_DIGEST = (
    "sha256:1af48913dfc27d16095b6024d7db59432102c9802db7950a77fc1b166deca1e9"
)
EXPECTED_MANIFEST_SET_DIGEST = (
    "sha256:e5255df5ccebaa1fb25347be194770a92a080dca9ef23c94b082cf1ac9bff728"
)
RESOURCE_FILES = [
    "namespace-valkey.json",
    "namespace-model-backend.json",
    "valkey-service-account.json",
    "valkey-service.json",
    "valkey-stateful-set.json",
    "valkey-default-deny.json",
    "valkey-allow-clients.json",
    "model-backend-service-account.json",
    "model-backend-service.json",
    "model-backend-stateful-set.json",
    "model-backend-default-deny.json",
    "model-backend-allow-model-plane.json",
]
EXPECTED_INPUTS = [
    {
        "id": "storage-class",
        "kind": "StorageClass",
        "namespace": None,
        "name": STORAGE_CLASS_PLACEHOLDER,
        "requiredKeys": [],
        "usage": "valkey-volume-claim-template",
        "materialization": "replace-with-live-observed-name",
    },
    {
        "id": "valkey-auth",
        "kind": "Secret",
        "namespace": "orchestra-sno-valkey",
        "name": "orchestra-sno-valkey-auth",
        "requiredKeys": ["password"],
        "usage": "valkey-server-and-probe-authentication",
        "materialization": "operator-created-out-of-band",
    },
    {
        "id": "valkey-server-tls",
        "kind": "Secret",
        "namespace": "orchestra-sno-valkey",
        "name": "orchestra-sno-valkey-server-tls",
        "requiredKeys": ["ca.crt", "tls.crt", "tls.key"],
        "usage": "valkey-server-tls",
        "materialization": "operator-created-out-of-band",
    },
    {
        "id": "model-artifact-pvc",
        "kind": "PersistentVolumeClaim",
        "namespace": "orchestra-sno-model-backend",
        "name": "orchestra-sno-model-artifact",
        "requiredKeys": [],
        "usage": "read-only-pinned-gguf",
        "materialization": "operator-prestaged-and-digest-verified",
    },
    {
        "id": "model-auth",
        "kind": "Secret",
        "namespace": "orchestra-sno-model-backend",
        "name": "orchestra-sno-model-auth",
        "requiredKeys": ["api-keys"],
        "usage": "llama-server-api-key-file",
        "materialization": "operator-created-out-of-band",
    },
    {
        "id": "model-server-tls",
        "kind": "Secret",
        "namespace": "orchestra-sno-model-backend",
        "name": "orchestra-sno-model-server-tls",
        "requiredKeys": ["ca.crt", "tls.crt", "tls.key"],
        "usage": "llama-server-tls",
        "materialization": "operator-created-out-of-band",
    },
]
ACTIVATION_REASONS = [
    "UPSTREAM_VERIFICATION_PENDING",
    "DESTINATION_MIRROR_PROOF_MISSING",
    "LAB_SIGNATURE_MISSING",
    "STORAGE_CLASS_REFERENCE_UNRESOLVED",
    "DEPENDENCY_SECRET_REFERENCES_UNRESOLVED",
    "DEPENDENCY_TLS_REFERENCES_UNRESOLVED",
    "MODEL_PVC_MATERIALIZATION_PROOF_MISSING",
    "LIVE_ALLOCATABLE_NOT_OBSERVED",
    "OPENSHIFT_SERVER_SIDE_DRY_RUN_MISSING",
    "LIVE_DEPENDENCY_CONNECTIVITY_MISSING",
]
CONTROLS = {
    "scope": "sno-engineering-trial-valkey-and-model-backend-only",
    "sourceOnly": True,
    "renderable": True,
    "operatorMaterializationRequired": True,
    "productionDependencyProfileMutated": False,
    "workloadCandidateMutated": False,
    "manifestsEmitted": True,
    "argocdApplicationsEmitted": False,
    "activeKustomizationReferenced": False,
    "secretObjectsEmitted": False,
    "secretValuesStored": False,
    "modelBytesStored": False,
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
FORBIDDEN_POD_KEYS = {
    "hostAliases",
    "hostIPC",
    "hostNetwork",
    "hostPID",
    "hostUsers",
    "nodeName",
    "priorityClassName",
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


def digest_without_self(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("candidateDigest", None)
    return canonical_digest(unsigned)


def resource_identity(resource: dict[str, Any]) -> dict[str, Any]:
    metadata = resource.get("metadata")
    if not isinstance(metadata, dict):
        fail("dependency_manifest_metadata_invalid")
    return {
        "apiVersion": resource.get("apiVersion"),
        "kind": resource.get("kind"),
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
    }


def manifest_set_digest(resources: list[dict[str, Any]]) -> str:
    return canonical_digest(
        [
            {
                "identity": resource_identity(resource),
                "document": resource,
            }
            for resource in resources
        ]
    )


def load_resources(
    manifest_root: Path = MANIFEST_ROOT,
    resource_files: list[str] = RESOURCE_FILES,
) -> list[dict[str, Any]]:
    return [load_json(manifest_root / name) for name in resource_files]


def kustomization_resources(path: Path = KUSTOMIZATION_PATH) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"dependency_manifest_kustomization_missing:{error}")
    if lines[:3] != [
        "apiVersion: kustomize.config.k8s.io/v1beta1",
        "kind: Kustomization",
        "resources:",
    ]:
        fail("dependency_manifest_kustomization_header_invalid")
    values = [line.removeprefix("  - ") for line in lines[3:] if line]
    if any(not line.startswith("  - ") for line in lines[3:] if line):
        fail("dependency_manifest_kustomization_directive_forbidden")
    return values


def walk(value: Any) -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.append((key, child))
            found.extend(walk(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(walk(child))
    return found


def validate_resource_floor(resources: list[dict[str, Any]]) -> None:
    for resource in resources:
        identity = resource_identity(resource)
        if not all(
            identity[key] for key in ("apiVersion", "kind", "name")
        ) or resource.get("kind") in {"Secret", "Application", "ApplicationSet"}:
            fail("dependency_manifest_resource_kind_forbidden")
        labels = resource["metadata"].get("labels")
        if (
            not isinstance(labels, dict)
            or labels.get("app.kubernetes.io/part-of") != "orchestra-sno-trial"
            or labels.get("orchestra.prometa.ai/activation") != "blocked"
        ):
            fail("dependency_manifest_blocked_label_missing")
        for key, child in walk(resource):
            if key in {"data", "stringData"}:
                fail("dependency_manifest_secret_material_forbidden")
            if key in {"runAsUser", "runAsGroup", "fsGroup", "supplementalGroups"}:
                fail("dependency_manifest_fixed_identity_forbidden")
            if key == "privileged" and child is not False:
                fail("dependency_manifest_privileged_forbidden")
            if key == "hostPath":
                fail("dependency_manifest_host_path_forbidden")


def validate_namespaces(
    resources_by_identity: dict[tuple[str, str, str | None], Any],
) -> None:
    for namespace in ("orchestra-sno-valkey", "orchestra-sno-model-backend"):
        resource = resources_by_identity.get(("Namespace", namespace, None))
        if not resource:
            fail(f"dependency_manifest_namespace_missing:{namespace}")
        labels = resource["metadata"]["labels"]
        for mode in ("audit", "enforce", "warn"):
            if (
                labels.get(f"pod-security.kubernetes.io/{mode}") != "restricted"
                or labels.get(f"pod-security.kubernetes.io/{mode}-version") != "latest"
            ):
                fail(f"dependency_manifest_namespace_psa_invalid:{namespace}:{mode}")


def expected_resources(runtime: dict[str, Any], identifier: str) -> dict[str, Any]:
    contract = find_by_id(
        runtime.get("contracts"),
        identifier,
        f"dependency_manifest_runtime_missing:{identifier}",
    )
    resources = contract.get("resources")
    if not isinstance(resources, dict):
        fail(f"dependency_manifest_runtime_resources_invalid:{identifier}")
    return {
        "requests": {
            "cpu": f"{resources['requests']['cpuMillicores']}m",
            "memory": f"{resources['requests']['memoryMiB']}Mi",
        },
        "limits": {
            "cpu": f"{resources['limits']['cpuMillicores']}m",
            "memory": f"{resources['limits']['memoryMiB']}Mi",
        },
    }


def validate_pod_security(pod_spec: dict[str, Any], identifier: str) -> None:
    if (
        pod_spec.get("automountServiceAccountToken") is not False
        or pod_spec.get("securityContext")
        != {
            "runAsNonRoot": True,
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        or FORBIDDEN_POD_KEYS.intersection(pod_spec)
    ):
        fail(f"dependency_manifest_pod_security_invalid:{identifier}")
    containers = pod_spec.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        fail(f"dependency_manifest_container_count_invalid:{identifier}")
    container_security = containers[0].get("securityContext")
    if container_security != {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
    }:
        fail(f"dependency_manifest_container_security_invalid:{identifier}")
    if pod_spec.get("initContainers"):
        fail(f"dependency_manifest_init_container_forbidden:{identifier}")


def collect_secret_refs(value: Any) -> set[tuple[str, str | None]]:
    references: set[tuple[str, str | None]] = set()
    if isinstance(value, dict):
        secret_key_ref = value.get("secretKeyRef")
        if isinstance(secret_key_ref, dict):
            references.add((secret_key_ref.get("name"), secret_key_ref.get("key")))
        secret = value.get("secret")
        if isinstance(secret, dict):
            name = secret.get("secretName")
            items = secret.get("items", [])
            if not isinstance(items, list):
                fail("dependency_manifest_secret_items_invalid")
            for item in items:
                if not isinstance(item, dict):
                    fail("dependency_manifest_secret_items_invalid")
                references.add((name, item.get("key")))
        for child in value.values():
            references.update(collect_secret_refs(child))
    elif isinstance(value, list):
        for child in value:
            references.update(collect_secret_refs(child))
    return references


def validate_valkey(
    resources_by_identity: dict[tuple[str, str, str | None], dict[str, Any]],
    runtime: dict[str, Any],
    artifact: dict[str, Any],
) -> None:
    namespace = "orchestra-sno-valkey"
    stateful_set = resources_by_identity[
        ("StatefulSet", "orchestra-sno-valkey", namespace)
    ]
    service = resources_by_identity[("Service", "orchestra-sno-valkey", namespace)]
    service_account = resources_by_identity[
        ("ServiceAccount", "orchestra-sno-valkey", namespace)
    ]
    spec = stateful_set.get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {})
    validate_pod_security(pod_spec, "valkey")
    container = pod_spec["containers"][0]
    artifact_container = find_by_id(
        artifact.get("containers"),
        "valkey-image",
        "dependency_manifest_valkey_artifact_missing",
    )
    if (
        spec.get("replicas") != 1
        or spec.get("serviceName") != "orchestra-sno-valkey"
        or pod_spec.get("serviceAccountName") != "orchestra-sno-valkey"
        or service_account.get("automountServiceAccountToken") is not False
        or container.get("name") != "valkey"
        or container.get("image") != artifact_container.get("resolvedReference")
        or not IMMUTABLE_IMAGE.fullmatch(str(container.get("image")))
        or container.get("resources") != expected_resources(runtime, "valkey")
    ):
        fail("dependency_manifest_valkey_workload_invalid")
    command_text = " ".join(container.get("command", []) + container.get("args", []))
    required_command = (
        "--port 0",
        "--tls-port 6379",
        "--tls-auth-clients no",
        '--requirepass "$VALKEYCLI_AUTH"',
        "--appendonly yes",
        "--appendfsync everysec",
        "--dir /data",
    )
    if any(item not in command_text for item in required_command):
        fail("dependency_manifest_valkey_command_invalid")
    probes = [
        container.get("startupProbe"),
        container.get("readinessProbe"),
        container.get("livenessProbe"),
    ]
    if any(
        not isinstance(probe, dict)
        or probe.get("exec", {}).get("command")
        != [
            "valkey-cli",
            "--tls",
            "--cacert",
            "/var/run/secrets/orchestra-valkey/ca.crt",
            "ping",
        ]
        for probe in probes
    ):
        fail("dependency_manifest_valkey_probe_invalid")
    claims = spec.get("volumeClaimTemplates")
    if (
        not isinstance(claims, list)
        or len(claims) != 1
        or claims[0].get("metadata", {}).get("name") != "data"
        or claims[0].get("spec")
        != {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": STORAGE_CLASS_PLACEHOLDER,
            "resources": {"requests": {"storage": "2Gi"}},
        }
    ):
        fail("dependency_manifest_valkey_storage_invalid")
    if collect_secret_refs(stateful_set) != {
        ("orchestra-sno-valkey-auth", "password"),
        ("orchestra-sno-valkey-server-tls", "ca.crt"),
        ("orchestra-sno-valkey-server-tls", "tls.crt"),
        ("orchestra-sno-valkey-server-tls", "tls.key"),
    }:
        fail("dependency_manifest_valkey_secret_refs_invalid")
    if service.get("spec", {}).get("type") != "ClusterIP" or service.get(
        "spec", {}
    ).get("ports") != [
        {
            "name": "valkey-tls",
            "port": 6379,
            "protocol": "TCP",
            "targetPort": "valkey-tls",
        }
    ]:
        fail("dependency_manifest_valkey_service_invalid")


def validate_model_backend(
    resources_by_identity: dict[tuple[str, str, str | None], dict[str, Any]],
    runtime: dict[str, Any],
    artifact: dict[str, Any],
) -> None:
    namespace = "orchestra-sno-model-backend"
    stateful_set = resources_by_identity[
        ("StatefulSet", "orchestra-sno-model-backend", namespace)
    ]
    service = resources_by_identity[
        ("Service", "orchestra-sno-model-backend", namespace)
    ]
    service_account = resources_by_identity[
        ("ServiceAccount", "orchestra-sno-model-backend", namespace)
    ]
    spec = stateful_set.get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {})
    validate_pod_security(pod_spec, "model-backend")
    container = pod_spec["containers"][0]
    artifact_container = find_by_id(
        artifact.get("containers"),
        "model-backend-image",
        "dependency_manifest_model_artifact_missing",
    )
    if (
        spec.get("replicas") != 1
        or spec.get("serviceName") != "orchestra-sno-model-backend"
        or pod_spec.get("serviceAccountName") != "orchestra-sno-model-backend"
        or service_account.get("automountServiceAccountToken") is not False
        or container.get("name") != "model-backend"
        or container.get("image") != artifact_container.get("resolvedReference")
        or not IMMUTABLE_IMAGE.fullmatch(str(container.get("image")))
        or container.get("resources") != expected_resources(runtime, "model-backend")
        or container.get("args")
        != artifact.get("runtimeBinding", {}).get("startupArguments")
    ):
        fail("dependency_manifest_model_workload_invalid")
    command_text = " ".join(container.get("command", []) + container.get("args", []))
    if any(
        item in command_text.lower()
        for item in ("http://", "https://", "curl ", "wget ", "huggingface")
    ):
        fail("dependency_manifest_model_runtime_download_forbidden")
    for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
        probe = container.get(probe_name)
        if (
            not isinstance(probe, dict)
            or probe.get("httpGet", {}).get("path") != "/health"
            or probe.get("httpGet", {}).get("port") != "https"
            or probe.get("httpGet", {}).get("scheme") != "HTTPS"
        ):
            fail(f"dependency_manifest_model_probe_invalid:{probe_name}")
    model_volume = next(
        (
            item.get("persistentVolumeClaim")
            for item in pod_spec.get("volumes", [])
            if item.get("name") == "model-artifact"
        ),
        None,
    )
    model_mount = next(
        (
            item
            for item in container.get("volumeMounts", [])
            if item.get("name") == "model-artifact"
        ),
        None,
    )
    if (
        model_volume
        != {
            "claimName": "orchestra-sno-model-artifact",
            "readOnly": True,
        }
        or not isinstance(model_mount, dict)
        or model_mount.get("mountPath") != "/models"
        or model_mount.get("readOnly") is not True
        or spec.get("volumeClaimTemplates")
    ):
        fail("dependency_manifest_model_pvc_invalid")
    if collect_secret_refs(stateful_set) != {
        ("orchestra-sno-model-auth", "api-keys"),
        ("orchestra-sno-model-server-tls", "ca.crt"),
        ("orchestra-sno-model-server-tls", "tls.crt"),
        ("orchestra-sno-model-server-tls", "tls.key"),
    }:
        fail("dependency_manifest_model_secret_refs_invalid")
    tls_mounts = {
        (item.get("mountPath"), item.get("subPath"), item.get("readOnly"))
        for item in container.get("volumeMounts", [])
        if item.get("name") == "tls"
    }
    if tls_mounts != {
        ("/var/run/secrets/orchestra-model/ca.crt", "ca.crt", True),
        ("/var/run/secrets/orchestra-model/tls.crt", "tls.crt", True),
        ("/var/run/secrets/orchestra-model/tls.key", "tls.key", True),
    }:
        fail("dependency_manifest_model_tls_mounts_invalid")
    if service.get("spec", {}).get("type") != "ClusterIP" or service.get(
        "spec", {}
    ).get("ports") != [
        {
            "name": "https",
            "port": 8000,
            "protocol": "TCP",
            "targetPort": "https",
        }
    ]:
        fail("dependency_manifest_model_service_invalid")


def validate_network(
    resources_by_identity: dict[tuple[str, str, str | None], dict[str, Any]],
) -> None:
    expected = {
        "orchestra-sno-valkey": {
            "policy": "allow-valkey-clients",
            "clients": ["orchestra-platform", "orchestra-model"],
            "port": 6379,
            "selector": "orchestra-sno-valkey",
        },
        "orchestra-sno-model-backend": {
            "policy": "allow-model-plane",
            "clients": ["orchestra-model"],
            "port": 8000,
            "selector": "orchestra-sno-model-backend",
        },
    }
    for namespace, policy in expected.items():
        default_deny = resources_by_identity.get(
            ("NetworkPolicy", "default-deny", namespace)
        )
        allow = resources_by_identity.get(
            ("NetworkPolicy", policy["policy"], namespace)
        )
        if (
            not default_deny
            or default_deny.get("spec")
            != {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
            or not allow
        ):
            fail(f"dependency_manifest_default_deny_invalid:{namespace}")
        spec = allow.get("spec", {})
        ingress = spec.get("ingress")
        if (
            spec.get("policyTypes") != ["Ingress"]
            or spec.get("podSelector")
            != {"matchLabels": {"app.kubernetes.io/name": policy["selector"]}}
            or not isinstance(ingress, list)
            or len(ingress) != 1
        ):
            fail(f"dependency_manifest_ingress_invalid:{namespace}")
        source_names = [
            item.get("namespaceSelector", {})
            .get("matchLabels", {})
            .get("kubernetes.io/metadata.name")
            for item in ingress[0].get("from", [])
        ]
        if source_names != policy["clients"] or ingress[0].get("ports") != [
            {"port": policy["port"], "protocol": "TCP"}
        ]:
            fail(f"dependency_manifest_ingress_scope_invalid:{namespace}")


def expected_workloads(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    valkey = find_by_id(
        artifact.get("containers"),
        "valkey-image",
        "dependency_manifest_valkey_artifact_missing",
    )
    model = find_by_id(
        artifact.get("containers"),
        "model-backend-image",
        "dependency_manifest_model_artifact_missing",
    )
    return [
        {
            "id": "valkey",
            "namespace": "orchestra-sno-valkey",
            "statefulSet": "orchestra-sno-valkey",
            "service": "orchestra-sno-valkey",
            "serviceAccount": "orchestra-sno-valkey",
            "container": "valkey",
            "image": valkey["resolvedReference"],
            "replicas": 1,
            "port": 6379,
            "protocol": "valkey-tls",
            "allowedClientNamespaces": ["orchestra-platform", "orchestra-model"],
            "persistentVolumeGiB": 2,
            "modelArtifactReadOnly": None,
        },
        {
            "id": "model-backend",
            "namespace": "orchestra-sno-model-backend",
            "statefulSet": "orchestra-sno-model-backend",
            "service": "orchestra-sno-model-backend",
            "serviceAccount": "orchestra-sno-model-backend",
            "container": "model-backend",
            "image": model["resolvedReference"],
            "replicas": 1,
            "port": 8000,
            "protocol": "openai-compatible-https",
            "allowedClientNamespaces": ["orchestra-model"],
            "persistentVolumeGiB": 10,
            "modelArtifactReadOnly": True,
        },
    ]


def validate_candidate(
    value: dict[str, Any],
    resources: list[dict[str, Any]],
    workload: dict[str, Any],
    runtime: dict[str, Any],
    artifact: dict[str, Any],
    *,
    active_kustomization_text: str,
    kustomization_file_list: list[str],
    enforce_expected_digests: bool = True,
) -> tuple[str, str]:
    if (
        value.get("schemaVersion") != 1
        or value.get("kind") != KIND
        or value.get("candidateId") != CANDIDATE_ID
        or value.get("profileId") != PROFILE_ID
        or value.get("targetClass") != "engineering-trial"
        or value.get("executionMode") != "source-only"
        or value.get("architecture") != "linux/amd64"
        or value.get("manifestRoot") != "gitops/dependencies/candidates/sno-trial"
        or value.get("kustomization")
        != "gitops/dependencies/candidates/sno-trial/kustomization.yaml"
    ):
        fail("dependency_manifest_candidate_identity_invalid")
    if value.get("bindings") != {
        "workloadCandidateDigest": workload.get("candidateDigest"),
        "runtimeContractSetDigest": runtime.get("contractSetDigest"),
        "dependencyArtifactSetDigest": artifact.get("artifactSetDigest"),
    }:
        fail("dependency_manifest_candidate_bindings_invalid")
    if value.get("resourceFiles") != RESOURCE_FILES:
        fail("dependency_manifest_resource_files_invalid")
    if kustomization_file_list != RESOURCE_FILES:
        fail("dependency_manifest_kustomization_resources_invalid")
    if len(resources) != len(RESOURCE_FILES):
        fail("dependency_manifest_resource_count_invalid")
    validate_resource_floor(resources)
    inventory = [resource_identity(resource) for resource in resources]
    if value.get("resourceInventory") != inventory or len(
        {(item["kind"], item["name"], item["namespace"]) for item in inventory}
    ) != len(inventory):
        fail("dependency_manifest_inventory_invalid")
    if value.get("requiredInputs") != EXPECTED_INPUTS:
        fail("dependency_manifest_required_inputs_invalid")
    if value.get("workloads") != expected_workloads(artifact):
        fail("dependency_manifest_workloads_invalid")

    resources_by_identity = {
        (item["kind"], item["name"], item["namespace"]): resource
        for item, resource in zip(inventory, resources, strict=True)
    }
    validate_namespaces(resources_by_identity)
    validate_valkey(resources_by_identity, runtime, artifact)
    validate_model_backend(resources_by_identity, runtime, artifact)
    validate_network(resources_by_identity)

    active_path = "gitops/dependencies/candidates/sno-trial"
    if (
        active_path in active_kustomization_text
        or "candidates/sno-trial" in active_kustomization_text
    ):
        fail("dependency_manifest_active_kustomization_reference_forbidden")
    if value.get("activation") != {
        "state": "blocked",
        "reasonCodes": ACTIVATION_REASONS,
    }:
        fail("dependency_manifest_activation_invalid")
    if value.get("controls") != CONTROLS:
        fail("dependency_manifest_controls_invalid")
    if value.get("claims") != CLAIMS:
        fail("dependency_manifest_claims_invalid")

    manifests_digest = manifest_set_digest(resources)
    if value.get("manifestSetDigest") != manifests_digest:
        fail(f"dependency_manifest_set_digest_invalid:{manifests_digest}")
    candidate_digest = digest_without_self(value)
    if value.get("candidateDigest") != candidate_digest:
        fail(f"dependency_manifest_candidate_digest_invalid:{candidate_digest}")
    if enforce_expected_digests and (
        manifests_digest != EXPECTED_MANIFEST_SET_DIGEST
        or candidate_digest != EXPECTED_CANDIDATE_DIGEST
    ):
        fail(
            "dependency_manifest_expected_digest_changed:"
            f"{manifests_digest}:{candidate_digest}"
        )
    if not DIGEST.fullmatch(manifests_digest) or not DIGEST.fullmatch(candidate_digest):
        fail("dependency_manifest_digest_format_invalid")
    return manifests_digest, candidate_digest


def load_validated_candidate() -> dict[str, Any]:
    value = load_json(CANDIDATE_PATH)
    validate_candidate(
        value,
        load_resources(),
        load_json(WORKLOAD_PATH),
        load_json(RUNTIME_PATH),
        load_json(ARTIFACT_PATH),
        active_kustomization_text=ACTIVE_DEPENDENCY_KUSTOMIZATION.read_text(
            encoding="utf-8"
        ),
        kustomization_file_list=kustomization_resources(),
    )
    return value


def main() -> int:
    resources = load_resources()
    manifests_digest, candidate_digest = validate_candidate(
        load_json(CANDIDATE_PATH),
        resources,
        load_json(WORKLOAD_PATH),
        load_json(RUNTIME_PATH),
        load_json(ARTIFACT_PATH),
        active_kustomization_text=ACTIVE_DEPENDENCY_KUSTOMIZATION.read_text(
            encoding="utf-8"
        ),
        kustomization_file_list=kustomization_resources(),
    )
    print(
        "sno_trial_dependency_manifests_valid "
        f"candidateDigest={candidate_digest} manifestSetDigest={manifests_digest} "
        "resources=12 workloads=2 activation=blocked"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
