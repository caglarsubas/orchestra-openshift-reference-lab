#!/usr/bin/env python3
"""Validate the immutable, deliberately non-activatable dependency catalog."""

from __future__ import annotations

import re
import sys
from typing import Any, NoReturn

try:
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_repository import ROOT, canonical_digest, load_json


DEPENDENCY_BOM = ROOT / "config" / "dependency-bom.lock.json"
EXPECTED_BOM_DIGEST = "sha256:fabec47064381d067ca759ba99c47470cc66628ecaacd2e0521f50bb29aad5dc"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]+$")
EXPECTED_CHARTS = {
    "argocd": ("argo-cd", "10.1.4", "v3.4.5", "142d2eaaa2adf9051c109c396c5fe3af742674011a5837df262bd6f8f2991d2c"),
    "cert-manager": ("cert-manager", "v1.21.0", "v1.21.0", "9c2c6fabf3cf8fe14dacb016f37c819b66bc2c79e8b7acde4573d45ec141fb97"),
    "cloudnative-pg": ("cloudnative-pg", "0.29.0", "1.30.0", "668e065ff53508d58238788fd35b355a925060843629a951df0e6a9362e6d32f"),
    "clickhouse-operator": ("altinity-clickhouse-operator", "0.27.1", "0.27.1", "716fd37d87bce19e15b42b207db5b0363f61d4f7b546413935d9a2ed9144401e"),
    "nats": ("nats", "2.14.2", "2.14.2", "86e0fbfe000b6d7fe70a3032ad3a667252f2d3dd2022e95f7330704d947d0f84"),
    "vault": ("vault", "0.34.0", "2.0.3", "a716f4fa8bb80e450ce7c0f9de7b475183c47437a162eee744cd40bf991244e9"),
    "external-secrets": ("external-secrets", "2.8.0", "v2.8.0", "251e4615013c6d2f9ade5cedf1cd8615613f286bfc381e44fb005f197e611ecd"),
    "harbor": ("harbor", "1.19.1", "2.15.1", "593f47e1ff6cdb58bd571708535ccef436f44ccf842c5f7925cd7b03e827edc1"),
    "kube-prometheus-stack": ("kube-prometheus-stack", "87.17.0", "v0.92.1", "e9d625daece8804bfa82959296e59cf146756d9aa638f207ebe20e01d6d75514"),
    "blackbox-exporter": ("prometheus-blackbox-exporter", "11.15.1", "v0.28.0", "4e8e45b8a6fbec4168d9b3e772a0219afec09b61c545af5f01395de363e30b5e"),
    "valkey": ("valkey", "0.10.0", "9.1.0", "6497e784e1b707c303e358f6f9d6f82f931618f4b1e5a7aeb0946df51a081fe6"),
}
EXPECTED_SERVICE_IDS = {
    "services-gitops",
    "cert-manager",
    "postgresql-platform",
    "postgresql-infrastructure",
    "clickhouse",
    "clickhouse-keeper",
    "jetstream",
    "valkey",
    "vault",
    "external-secrets",
    "harbor",
    "keycloak",
    "prometheus-thanos",
    "blackbox-probes",
    "model-backend",
    "embedding-model",
    "synthetic-mcp",
}
TOPOLOGY_SERVICE_IDS = {
    "postgresql-platform",
    "postgresql-infrastructure",
    "clickhouse",
    "clickhouse-keeper",
    "jetstream",
    "valkey",
    "vault",
    "harbor",
    "keycloak",
    "model-backend",
    "embedding-model",
    "synthetic-mcp",
}
EXPECTED_UNRESOLVED = {
    "VALKEY_SENTINEL_PROVIDER_UNRESOLVED",
    "THANOS_DEPLOYMENT_CONTRACT_UNRESOLVED",
    "KEYCLOAK_OPERATOR_SOURCE_NOT_LOCKED",
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def validate_chart_packages(packages: Any) -> None:
    if not isinstance(packages, list) or len(packages) != len(EXPECTED_CHARTS):
        fail("dependency_bom_chart_inventory_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for package in packages:
        package = object_value(package, "dependency_bom_chart_invalid")
        if set(package) != {
            "id",
            "repository",
            "chart",
            "chartVersion",
            "appVersion",
            "packageDigest",
            "upstreamSignatureStatus",
            "mirrorPath",
        }:
            fail("dependency_bom_chart_keys_invalid")
        package_id = package.get("id")
        if not isinstance(package_id, str) or package_id in by_id:
            fail("dependency_bom_chart_id_invalid")
        by_id[package_id] = package
    if set(by_id) != set(EXPECTED_CHARTS):
        fail("dependency_bom_chart_inventory_invalid")
    for package_id, expected in EXPECTED_CHARTS.items():
        package = by_id[package_id]
        chart, chart_version, app_version, digest = expected
        if (
            package["chart"] != chart
            or package["chartVersion"] != chart_version
            or package["appVersion"] != app_version
            or package["packageDigest"] != f"sha256:{digest}"
            or not DIGEST.fullmatch(package["packageDigest"])
            or not str(package["repository"]).startswith("https://")
            or package["upstreamSignatureStatus"] != "unverified"
            or package["mirrorPath"] != f"charts/{chart}"
        ):
            fail(f"dependency_bom_chart_lock_invalid:{package_id}")


def validate_service_contracts(services: Any, topology: dict[str, Any]) -> None:
    if not isinstance(services, list) or len(services) != len(EXPECTED_SERVICE_IDS):
        fail("dependency_bom_service_inventory_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for service in services:
        service = object_value(service, "dependency_bom_service_invalid")
        if set(service) != {
            "id",
            "provider",
            "stage",
            "desired",
            "activationState",
            "reasonCodes",
        }:
            fail("dependency_bom_service_keys_invalid")
        service_id = service.get("id")
        reasons = service.get("reasonCodes")
        if (
            not isinstance(service_id, str)
            or service_id in by_id
            or service.get("activationState") != "blocked"
            or not isinstance(reasons, list)
            or not reasons
            or any(not isinstance(reason, str) or not REASON_CODE.fullmatch(reason) for reason in reasons)
            or not isinstance(service.get("desired"), dict)
        ):
            fail(f"dependency_bom_service_contract_invalid:{service_id}")
        by_id[service_id] = service
    if set(by_id) != EXPECTED_SERVICE_IDS:
        fail("dependency_bom_service_inventory_invalid")

    topology_dependencies = topology["dependencyPlane"]["dependencies"]
    topology_by_id = {item["kind"]: item for item in topology_dependencies}
    if set(topology_by_id) != TOPOLOGY_SERVICE_IDS:
        fail("dependency_bom_topology_inventory_invalid")
    for service_id, topology_contract in topology_by_id.items():
        desired = by_id[service_id]["desired"]
        for key, value in topology_contract.items():
            if key != "kind" and desired.get(key) != value:
                fail(f"dependency_bom_topology_contract_invalid:{service_id}:{key}")

    all_reasons = {
        reason
        for service in services
        for reason in service["reasonCodes"]
    }
    if not EXPECTED_UNRESOLVED.issubset(all_reasons):
        fail("dependency_bom_unresolved_reason_not_bound")


def validate_dependency_bom(value: dict[str, Any], topology: dict[str, Any]) -> str:
    if set(value) != {
        "schemaVersion",
        "profileId",
        "bomId",
        "claim",
        "target",
        "bootstrapRegistry",
        "chartPackages",
        "serviceContracts",
        "admission",
    }:
        fail("dependency_bom_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != topology["profileId"]
        or value["bomId"] != "orchestra-dependencies-2026-07-21.1"
        or value["claim"]
        != {
            "declared": True,
            "applied": False,
            "liveTested": False,
            "campaignEvidence": False,
        }
        or value["target"]
        != {
            "projectRole": "services-evidence",
            "cluster": "orchestra-dependencies",
            "platform": "gke",
            "mode": "private-regional",
            "gitOpsController": "argocd",
        }
        or value["bootstrapRegistry"]
        != {
            "provider": "gcp-artifact-registry",
            "repositoryId": "orchestra-bootstrap",
            "format": "oci-over-docker",
            "immutableTags": True,
            "purpose": "pre-harbor-seed",
            "retirementCondition": "harbor-mirror-rollback-proven",
        }
    ):
        fail("dependency_bom_identity_invalid")
    validate_chart_packages(value["chartPackages"])
    validate_service_contracts(value["serviceContracts"], topology)
    admission = object_value(value["admission"], "dependency_bom_admission_invalid")
    if (
        set(admission) != {
            "activation",
            "requiredForActivation",
            "unresolvedDecisions",
        }
        or admission["activation"] != "blocked"
        or set(admission["unresolvedDecisions"]) != EXPECTED_UNRESOLVED
        or len(admission["requiredForActivation"]) != 9
        or len(set(admission["requiredForActivation"])) != 9
    ):
        fail("dependency_bom_admission_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_BOM_DIGEST:
        fail(f"dependency_bom_digest_changed:{digest}")
    return digest


def main() -> int:
    bom = load_json(DEPENDENCY_BOM)
    topology = load_json(ROOT / "config" / "lab.lock.json")
    digest = validate_dependency_bom(bom, topology)
    print(
        "dependency_bom_valid "
        f"digest={digest} charts={len(EXPECTED_CHARTS)} services={len(EXPECTED_SERVICE_IDS)} activation=blocked"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
