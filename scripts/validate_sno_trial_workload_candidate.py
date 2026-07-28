#!/usr/bin/env python3
"""Validate the inert, cost-bounded SNO trial workload candidate."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_dependency_admission import validate_admission
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import validate_lab_services
    from scripts.validate_sno_trial_profile import (
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_production_isolation,
        validate_profile,
    )
except ModuleNotFoundError:
    from validate_dependency_admission import validate_admission
    from validate_release_set import validate_release_set
    from validate_repository import validate_lab_services
    from validate_sno_trial_profile import (
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_production_isolation,
        validate_profile,
    )


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = ROOT / "config" / "sno-trial-workload-candidate.lock.json"
TOOLCHAIN_PATH = ROOT / "config" / "sno-trial-openshift-toolchain.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
DEPENDENCY_PATH = ROOT / "config" / "dependency-admission.lock.json"
DEPENDENCY_BOM_PATH = ROOT / "config" / "dependency-bom.lock.json"
LAB_SERVICES_PATH = ROOT / "config" / "lab-services.lock.json"
DEPENDENCY_ARTIFACT_PATH = (
    ROOT / "config" / "sno-trial-dependency-artifacts.lock.json"
)
TOPOLOGY_PATH = ROOT / "config" / "lab.lock.json"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMMUTABLE_REF = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
TOP_KEYS = {
    "schemaVersion",
    "kind",
    "candidateId",
    "profileId",
    "targetClass",
    "executionMode",
    "architecture",
    "bindings",
    "nodeEnvelope",
    "workloads",
    "activation",
    "controls",
    "claims",
    "candidateDigest",
}
WORKLOAD_KEYS = {
    "id",
    "category",
    "replicas",
    "resources",
    "persistentVolumeGiB",
    "artifact",
    "mode",
}
ARTIFACT_KEYS = {
    "sourceClass",
    "sourceId",
    "reference",
    "platformDigest",
    "admissionState",
    "usableForCapacityOnly",
}
RESOURCE_KEYS = {"requests", "limits"}
QUANTITY_KEYS = {"cpuMillicores", "memoryMiB"}
FORBIDDEN_INLINE_KEYS = {
    "apiVersion",
    "metadata",
    "spec",
    "data",
    "stringData",
    "manifest",
    "manifests",
    "application",
    "applications",
    "values",
    "valuesObject",
    "secretValue",
    "secretData",
}
PRODUCTION_PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"

RESOURCE_PLAN = {
    "platform": ("product", 250, 512, 1000, 1024, 0),
    "runtime-host": ("product", 100, 128, 500, 512, 0),
    "model-plane": ("product", 500, 4096, 1500, 8192, 1),
    "postgresql": ("dependency", 250, 1024, 500, 2048, 10),
    "clickhouse": ("dependency", 500, 2048, 1000, 4096, 20),
    "jetstream": ("dependency", 100, 256, 250, 512, 5),
    "valkey": ("dependency", 100, 256, 250, 512, 2),
    "model-backend": ("dependency", 1500, 6144, 2000, 8192, 10),
    "synthetic-tenant-kit": ("synthetic-surface", 100, 256, 250, 512, 0),
}
MODES = {
    "platform": {
        "observeFirst": True,
        "agentQuerying": False,
        "toolExecution": False,
        "orchestrationRun": False,
    },
    "runtime-host": {
        "modelCalls": True,
        "mcp": "read-only",
        "writeTools": False,
        "productionHostedByPlatform": False,
    },
    "model-plane": {
        "backend": "remote-in-cluster",
        "routingPolicyRequired": True,
        "rateLimitScope": "deployment-shared",
        "fallbackRequired": True,
    },
    "postgresql": {
        "implementation": "trial-direct-single-instance",
        "logicalDatabases": 2,
        "backup": False,
        "highAvailability": False,
    },
    "clickhouse": {
        "implementation": "trial-direct-single-instance",
        "keeper": False,
        "backup": False,
        "highAvailability": False,
    },
    "jetstream": {
        "implementation": "trial-direct-single-instance",
        "streamReplicas": 1,
        "durableTelemetry": True,
        "highAvailability": False,
    },
    "valkey": {
        "implementation": "trial-direct-single-instance",
        "sentinel": False,
        "aof": True,
        "highAvailability": False,
    },
    "model-backend": {
        "implementation": "cpu-only-single-backend",
        "quantizationRequired": True,
        "maximumModelBytes": 4294967296,
        "chatRequired": True,
        "embeddingQualityCertifying": False,
    },
    "synthetic-tenant-kit": {
        "tenantGateway": True,
        "mcp": "read-only",
        "faultSurfaces": True,
        "customerData": False,
    },
}
ACTIVATION_REASONS = [
    "BILLING_ASSOCIATION_PENDING",
    "FOUNDATION_NOT_APPLIED",
    "OPERATOR_LEASE_MISSING",
    "PULL_SECRET_MISSING",
    "ENTITLEMENT_OBSERVATION_MISSING",
    "LINUX_INSTALLER_EXECUTION_MISSING",
    "SOURCE_ADMISSION_INCOMPLETE",
    "TRIAL_CHART_PROFILES_MISSING",
    "TRIAL_DEPENDENCY_RUNTIME_CONTRACT_REFRESH_PENDING",
    "TRIAL_DEPENDENCY_MANIFEST_REFRESH_PENDING",
    "DESTINATION_PULL_PROOF_MISSING",
    "SECRET_REFERENCES_UNRESOLVED",
    "TLS_REFERENCES_UNRESOLVED",
    "LIVE_ALLOCATABLE_NOT_OBSERVED",
    "CAPACITY_CALIBRATION_PENDING",
    "SERVER_SIDE_DRY_RUN_MISSING",
]
CONTROLS = {
    "profileScope": "sno-engineering-trial-only",
    "registryMode": "direct-source-by-digest-after-review",
    "secretStrategy": "operator-created-existing-secret-references",
    "tlsStrategy": "operator-provided-trial-secret-references",
    "backupMode": "none-ephemeral-trial",
    "replicaPolicy": "single-replica-no-ha",
    "autoscalingEnabled": False,
    "podDisruptionBudgetsEnabled": False,
    "topologySpreadEnabled": False,
    "platformInSynchronousRuntimePath": False,
    "platformProductionToolExecution": False,
    "runtimeMcpMode": "read-only",
    "manifestsEmitted": False,
    "argocdApplicationsEmitted": False,
    "kustomizationReferenced": False,
    "secretValuesStored": False,
    "cloudMutationAuthorized": False,
    "installAuthorized": False,
    "activationAuthorized": False,
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


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def digest_without_candidate(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("candidateDigest", None)
    return canonical_digest(unsigned)


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


def find_plane(release_set: dict[str, Any], plane: str) -> dict[str, Any]:
    values = release_set.get("planes")
    if not isinstance(values, list):
        fail("sno_candidate_release_planes_invalid")
    matches = [
        item for item in values if isinstance(item, dict) and item.get("plane") == plane
    ]
    if len(matches) != 1:
        fail("sno_candidate_release_plane_invalid")
    return matches[0]


def release_artifact(
    release_set: dict[str, Any],
    plane: str,
    source_id: str,
) -> dict[str, Any]:
    item = find_plane(release_set, plane)
    reference = item.get("deploymentImage")
    if not isinstance(reference, str) or not IMMUTABLE_REF.fullmatch(reference):
        fail("sno_candidate_release_artifact_invalid")
    return {
        "sourceClass": "cross-plane-release",
        "sourceId": source_id,
        "reference": reference,
        "platformDigest": f"sha256:{reference.rsplit('@sha256:', 1)[1]}",
        "admissionState": "published-not-trial-admitted",
        "usableForCapacityOnly": True,
    }


def dependency_artifact(
    admission: dict[str, Any],
    source_id: str,
) -> dict[str, Any]:
    item = find_by_id(
        admission.get("images"),
        source_id,
        "sno_candidate_dependency_artifact_missing",
    )
    source = object_value(
        item.get("source"), "sno_candidate_dependency_artifact_invalid"
    )
    reference = source.get("reference")
    digest = source.get("platformDigest")
    if (
        not isinstance(reference, str)
        or not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
        or source.get("platform") != "linux/amd64"
    ):
        fail("sno_candidate_dependency_artifact_invalid")
    return {
        "sourceClass": "dependency-source",
        "sourceId": source_id,
        "reference": reference,
        "platformDigest": digest,
        "admissionState": "source-resolved-not-mirrored",
        "usableForCapacityOnly": True,
    }


def lab_service_artifact(
    lab_services: dict[str, Any],
    source_id: str,
) -> dict[str, Any]:
    service = find_by_id(
        lab_services.get("services"),
        source_id,
        "sno_candidate_lab_service_missing",
    )
    image = object_value(
        service.get("image"), "sno_candidate_lab_service_artifact_invalid"
    )
    reference = image.get("signatureSubject")
    digest = image.get("digest")
    if (
        service.get("activation") != "published"
        or not isinstance(reference, str)
        or not IMMUTABLE_REF.fullmatch(reference)
        or not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
        or not reference.endswith(digest)
    ):
        fail("sno_candidate_lab_service_artifact_invalid")
    return {
        "sourceClass": "lab-service-publication",
        "sourceId": source_id,
        "reference": reference,
        "platformDigest": digest,
        "admissionState": "published-not-trial-admitted",
        "usableForCapacityOnly": True,
    }


def expected_artifacts(
    release_set: dict[str, Any],
    admission: dict[str, Any],
    lab_services: dict[str, Any],
    dependency_artifacts: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    def selected(source_id: str) -> dict[str, Any]:
        item = find_by_id(
            dependency_artifacts.get("containers"),
            source_id,
            "sno_candidate_selected_dependency_artifact_missing",
        )
        reference = item.get("resolvedReference")
        digest = item.get("platformDigest")
        if (
            not isinstance(reference, str)
            or not IMMUTABLE_REF.fullmatch(reference)
            or not isinstance(digest, str)
            or not DIGEST.fullmatch(digest)
            or not reference.endswith(digest)
            or item.get("platform") != "linux/amd64"
        ):
            fail("sno_candidate_selected_dependency_artifact_invalid")
        return {
            "sourceClass": "trial-dependency-artifact",
            "sourceId": source_id,
            "reference": reference,
            "platformDigest": digest,
            "admissionState": "source-resolved-not-mirrored",
            "usableForCapacityOnly": True,
        }

    return {
        "platform": release_artifact(release_set, "platform", "platform"),
        "runtime-host": release_artifact(release_set, "runtimeHost", "runtimeHost"),
        "model-plane": release_artifact(release_set, "modelPlane", "modelPlane"),
        "postgresql": dependency_artifact(admission, "cloudnative-pg-postgresql-16"),
        "clickhouse": dependency_artifact(admission, "clickhouse-server-lts"),
        "jetstream": dependency_artifact(admission, "nats-server"),
        "valkey": selected("valkey-image"),
        "model-backend": selected("model-backend-image"),
        "synthetic-tenant-kit": lab_service_artifact(
            lab_services, "synthetic-tenant-kit"
        ),
    }


def validate_no_inline_deployment(value: Any) -> None:
    if isinstance(value, dict):
        overlap = set(value) & FORBIDDEN_INLINE_KEYS
        if overlap:
            fail(f"sno_candidate_inline_deployment_forbidden:{sorted(overlap)[0]}")
        for child in value.values():
            validate_no_inline_deployment(child)
    elif isinstance(value, list):
        for child in value:
            validate_no_inline_deployment(child)
    elif isinstance(value, str) and PRODUCTION_PROFILE_ID in value:
        fail("sno_candidate_production_profile_reference_forbidden")


def validate_bindings(
    value: dict[str, Any],
    trial: dict[str, Any],
    toolchain: dict[str, Any],
    release_set: dict[str, Any],
    admission: dict[str, Any],
    lab_services: dict[str, Any],
    dependency_artifacts: dict[str, Any],
) -> None:
    expected = {
        "trialProfileDigest": canonical_digest(trial),
        "toolchainLockDigest": canonical_digest(toolchain),
        "artifactReleaseSetDigest": canonical_digest(release_set),
        "dependencySourceDigest": canonical_digest(admission),
        "labServicesDigest": canonical_digest(lab_services),
        "dependencyArtifactSetDigest": dependency_artifacts.get(
            "artifactSetDigest"
        ),
    }
    if value != expected or not all(DIGEST.fullmatch(item) for item in value.values()):
        fail("sno_candidate_bindings_invalid")


def validate_resources(
    workloads: list[dict[str, Any]],
    envelope: dict[str, Any],
) -> None:
    physical = {"cpuMillicores": 8000, "memoryMiB": 32768}
    reserve = {"cpuMillicores": 3000, "memoryMiB": 12288}
    budget = {key: physical[key] - reserve[key] for key in QUANTITY_KEYS}
    request_totals = {key: 0 for key in QUANTITY_KEYS}
    limit_totals = {key: 0 for key in QUANTITY_KEYS}
    storage_total = 0
    for workload in workloads:
        resources = object_value(
            workload.get("resources"), "sno_candidate_resources_invalid"
        )
        exact_keys(resources, RESOURCE_KEYS, "sno_candidate_resources_keys_invalid")
        for class_name, totals in (
            ("requests", request_totals),
            ("limits", limit_totals),
        ):
            quantities = object_value(
                resources.get(class_name), "sno_candidate_quantities_invalid"
            )
            exact_keys(quantities, QUANTITY_KEYS, "sno_candidate_quantity_keys_invalid")
            for key, quantity in quantities.items():
                if type(quantity) is not int or quantity <= 0:
                    fail("sno_candidate_quantity_invalid")
                totals[key] += quantity
        for key in QUANTITY_KEYS:
            if resources["requests"][key] > resources["limits"][key]:
                fail("sno_candidate_request_exceeds_limit")
        storage = workload.get("persistentVolumeGiB")
        if type(storage) is not int or storage < 0:
            fail("sno_candidate_storage_invalid")
        storage_total += storage

    transient = {"cpuMillicores": 250, "memoryMiB": 256}
    peak = {key: request_totals[key] + transient[key] for key in QUANTITY_KEYS}
    headroom = {key: budget[key] - peak[key] for key in QUANTITY_KEYS}
    if any(headroom[key] <= 0 for key in QUANTITY_KEYS):
        fail("sno_candidate_request_budget_exceeded")
    if any(limit_totals[key] > physical[key] for key in QUANTITY_KEYS):
        fail("sno_candidate_physical_limit_exceeded")
    expected = {
        "machineType": "n2-standard-8",
        "physical": physical,
        "systemReserve": reserve,
        "workloadRequestBudget": budget,
        "steadyRequests": request_totals,
        "transientPeakAllowance": {
            **transient,
            "scheduling": "serial-only",
        },
        "peakRequests": peak,
        "requestHeadroom": headroom,
        "aggregateLimits": limit_totals,
        "persistentVolumeGiB": storage_total,
    }
    if envelope != expected:
        fail("sno_candidate_node_envelope_invalid")


def validate_candidate(
    value: dict[str, Any],
    trial: dict[str, Any],
    production: dict[str, Any],
    toolchain: dict[str, Any],
    release_set: dict[str, Any],
    admission: dict[str, Any],
    lab_services: dict[str, Any],
    dependency_artifacts: dict[str, Any],
) -> str:
    validate_profile(trial, production)
    validate_release_set(release_set)
    validate_lab_services(lab_services)
    validate_no_inline_deployment(value)
    exact_keys(value, TOP_KEYS, "sno_candidate_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "orchestra.openshift.sno-trial-workload-candidate.v1"
        or value["candidateId"] != "orchestra-sno-trial-workload-candidate-2026-07-28.2"
        or value["profileId"] != TRIAL_PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "source-only"
        or value["architecture"] != "linux/amd64"
    ):
        fail("sno_candidate_identity_invalid")
    validate_bindings(
        object_value(value["bindings"], "sno_candidate_bindings_invalid"),
        trial,
        toolchain,
        release_set,
        admission,
        lab_services,
        dependency_artifacts,
    )
    workloads = value["workloads"]
    if not isinstance(workloads, list) or len(workloads) != len(RESOURCE_PLAN):
        fail("sno_candidate_workloads_invalid")
    expected_ids = list(RESOURCE_PLAN)
    if [item.get("id") for item in workloads if isinstance(item, dict)] != expected_ids:
        fail("sno_candidate_workload_order_invalid")
    artifacts = expected_artifacts(
        release_set, admission, lab_services, dependency_artifacts
    )
    for workload in workloads:
        if not isinstance(workload, dict):
            fail("sno_candidate_workload_invalid")
        exact_keys(workload, WORKLOAD_KEYS, "sno_candidate_workload_keys_invalid")
        identifier = workload["id"]
        category, req_cpu, req_memory, limit_cpu, limit_memory, storage = RESOURCE_PLAN[
            identifier
        ]
        if (
            workload["category"] != category
            or workload["replicas"] != 1
            or workload["resources"]
            != {
                "requests": {
                    "cpuMillicores": req_cpu,
                    "memoryMiB": req_memory,
                },
                "limits": {
                    "cpuMillicores": limit_cpu,
                    "memoryMiB": limit_memory,
                },
            }
            or workload["persistentVolumeGiB"] != storage
            or workload["mode"] != MODES[identifier]
        ):
            fail(f"sno_candidate_workload_contract_invalid:{identifier}")
        artifact = object_value(workload["artifact"], "sno_candidate_artifact_invalid")
        exact_keys(artifact, ARTIFACT_KEYS, "sno_candidate_artifact_keys_invalid")
        if artifact != artifacts[identifier]:
            fail(f"sno_candidate_artifact_invalid:{identifier}")
    validate_resources(
        workloads,
        object_value(value["nodeEnvelope"], "sno_candidate_node_envelope_invalid"),
    )
    if value["activation"] != {
        "state": "blocked",
        "reasonCodes": ACTIVATION_REASONS,
    }:
        fail("sno_candidate_activation_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_candidate_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_candidate_claims_invalid")
    candidate_digest = value["candidateDigest"]
    if (
        not isinstance(candidate_digest, str)
        or not DIGEST.fullmatch(candidate_digest)
        or candidate_digest != digest_without_candidate(value)
    ):
        fail("sno_candidate_digest_invalid")
    return candidate_digest


def main() -> int:
    candidate = load_json(CANDIDATE_PATH)
    trial = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    toolchain = load_json(TOOLCHAIN_PATH)
    release_set = load_json(RELEASE_SET_PATH)
    admission = load_json(DEPENDENCY_PATH)
    dependency_bom = load_json(DEPENDENCY_BOM_PATH)
    topology = load_json(TOPOLOGY_PATH)
    lab_services = load_json(LAB_SERVICES_PATH)
    dependency_artifacts = load_json(DEPENDENCY_ARTIFACT_PATH)
    validate_admission(admission, dependency_bom, topology)
    digest = validate_candidate(
        candidate,
        trial,
        production,
        toolchain,
        release_set,
        admission,
        lab_services,
        dependency_artifacts,
    )
    validate_production_isolation()
    print(
        "sno_trial_workload_candidate_valid "
        f"digest={digest} workloads={len(RESOURCE_PLAN)} "
        "activation=blocked manifests=0 campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
