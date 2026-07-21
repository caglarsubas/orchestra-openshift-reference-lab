#!/usr/bin/env python3
"""Validate digest-bound, secret-free product GitOps declarations."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import ROOT, load_json
except ModuleNotFoundError:
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, load_json


PRODUCT_ROOT = ROOT / "gitops" / "products" / "reference-lab"
MIRROR_CHART_REPOSITORY = "harbor.services.ocp-lab.prometa.ai/orchestra/charts"
DEPENDENCY_BOM_DIGEST = "sha256:fabec47064381d067ca759ba99c47470cc66628ecaacd2e0521f50bb29aad5dc"
APPLICATION_CONTRACTS = {
    "platform": {
        "file": "platform-application.json",
        "name": "orchestra-platform",
        "namespace": "orchestra-platform",
        "chart": "prometa",
        "chartVersion": "0.3.0-rc.7",
        "chartRole": "helm-chart",
        "imageRole": "platform-image-ubi9",
        "imageRepository": "harbor.services.ocp-lab.prometa.ai/orchestra/platform/prometa-ubi",
    },
    "runtimeHost": {
        "file": "runtime-application.json",
        "name": "orchestra-runtime",
        "namespace": "orchestra-runtime",
        "chart": "prometa-runtime",
        "chartVersion": "0.3.4",
        "chartRole": "helm-chart",
        "imageRole": "runtime-host-image-ubi9",
        "imageRepository": "harbor.services.ocp-lab.prometa.ai/orchestra/runtime/prometa-runtime-host-ubi9",
    },
    "modelPlane": {
        "file": "model-application.json",
        "name": "orchestra-model-plane",
        "namespace": "orchestra-model",
        "chart": "orchestra-inference-engine",
        "chartVersion": "0.1.2",
        "chartRole": "helm-chart",
        "imageRole": "inference-engine-image-ubi9",
        "imageRepository": "harbor.services.ocp-lab.prometa.ai/orchestra/model/inference-engine-ubi",
    },
}
EXPECTED_RENDERED_COUNTS = {
    "AppProject": 1,
    "Application": 3,
    "Certificate": 2,
    "ConfigMap": 3,
    "ExternalSecret": 13,
    "NetworkPolicy": 1,
    "ServiceAccount": 1,
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def digest_from_ref(reference: str) -> str:
    if "@sha256:" not in reference:
        fail("product_gitops_release_ref_not_immutable")
    return reference.split("@", 1)[1]


def plane_by_name(release_set: dict[str, Any], name: str) -> dict[str, Any]:
    for plane in release_set["planes"]:
        if plane["plane"] == name:
            return plane
    fail(f"product_gitops_release_plane_missing:{name}")


def subject_ref(plane: dict[str, Any], role: str) -> str:
    for subject in plane["subjects"]:
        if subject["role"] == role:
            return subject["ref"]
    fail(f"product_gitops_release_subject_missing:{plane['plane']}:{role}")


def validate_common_application(
    application: dict[str, Any],
    release_set: dict[str, Any],
    release_set_digest: str,
    plane_name: str,
    contract: dict[str, str],
) -> dict[str, Any]:
    if (
        application.get("apiVersion") != "argoproj.io/v1alpha1"
        or application.get("kind") != "Application"
    ):
        fail(f"product_gitops_application_identity_invalid:{plane_name}")
    metadata = object_value(
        application.get("metadata"), "product_gitops_metadata_invalid"
    )
    annotations = object_value(
        metadata.get("annotations"), "product_gitops_annotations_invalid"
    )
    spec = object_value(application.get("spec"), "product_gitops_spec_invalid")
    source = object_value(spec.get("source"), "product_gitops_source_invalid")
    helm = object_value(source.get("helm"), "product_gitops_helm_invalid")
    values = object_value(
        helm.get("valuesObject"), "product_gitops_values_invalid"
    )
    destination = object_value(
        spec.get("destination"), "product_gitops_destination_invalid"
    )
    sync = object_value(
        spec.get("syncPolicy"), "product_gitops_sync_policy_invalid"
    )
    automated = object_value(
        sync.get("automated"), "product_gitops_automated_sync_invalid"
    )
    plane = plane_by_name(release_set, plane_name)
    chart_ref = subject_ref(plane, contract["chartRole"])
    image_ref = subject_ref(plane, contract["imageRole"])
    image = object_value(values.get("image"), "product_gitops_image_invalid")
    profile = object_value(
        values.get("productionProfile"), "product_gitops_profile_invalid"
    )
    if (
        metadata.get("name") != contract["name"]
        or metadata.get("namespace") != "openshift-gitops"
        or annotations.get("orchestra.prometa.ai/release-set-digest")
        != release_set_digest
        or annotations.get("orchestra.prometa.ai/dependency-bom-digest")
        != DEPENDENCY_BOM_DIGEST
        or annotations.get("orchestra.prometa.ai/source-revision")
        != plane["source"]["revision"]
        or annotations.get("orchestra.prometa.ai/source-chart-digest")
        != digest_from_ref(chart_ref)
        or spec.get("project") != "orchestra-reference-lab"
        or source.get("repoURL") != MIRROR_CHART_REPOSITORY
        or source.get("chart") != contract["chart"]
        or source.get("targetRevision") != contract["chartVersion"]
        or helm.get("releaseName") != contract["name"]
        or destination
        != {
            "server": "https://kubernetes.default.svc",
            "namespace": contract["namespace"],
        }
        or automated != {"prune": True, "selfHeal": True}
        or "CreateNamespace=false" not in sync.get("syncOptions", [])
        or image.get("repository") != contract["imageRepository"]
        or image.get("digest") != digest_from_ref(image_ref)
        or image.get("tag") != ""
        or profile.get("enabled") is not True
        or profile.get("profileId") != "orchestra-ocp-4.20-amd64-v1"
    ):
        fail(f"product_gitops_application_contract_invalid:{plane_name}")
    return values


def validate_project(release_set_digest: str) -> None:
    project = load_json(PRODUCT_ROOT / "project.json")
    metadata = object_value(
        project.get("metadata"), "product_gitops_project_metadata_invalid"
    )
    annotations = object_value(
        metadata.get("annotations"), "product_gitops_project_annotations_invalid"
    )
    if (
        project.get("apiVersion") != "argoproj.io/v1alpha1"
        or project.get("kind") != "AppProject"
        or metadata.get("name") != "orchestra-reference-lab"
        or annotations.get("orchestra.prometa.ai/release-set-digest")
        != release_set_digest
        or annotations.get("orchestra.prometa.ai/dependency-bom-digest")
        != DEPENDENCY_BOM_DIGEST
        or annotations.get("orchestra.prometa.ai/activation")
        != "blocked-until-live-prerequisites-and-mirror-intake-pass"
    ):
        fail("product_gitops_project_contract_invalid")


def validate_platform(values: dict[str, Any]) -> None:
    backend_tls = object_value(
        values.get("backendTls"), "product_gitops_platform_backend_tls_invalid"
    )
    service_certificate = object_value(
        backend_tls.get("serviceServingCertificate"),
        "product_gitops_platform_service_certificate_invalid",
    )
    route = object_value(
        values.get("route"), "product_gitops_platform_route_invalid"
    )
    if (
        values.get("agentQuerying") != {"enabled": False}
        or values.get("toolExecution") != {"enabled": False}
        or values.get("modelPlane") != {"enabled": False}
        or values.get("evalModel") != {"enabled": False}
        or values.get("releaseValidation") != {"enabled": False}
        or values.get("postgresql") != {"enabled": False}
        or values.get("clickhouse") != {"enabled": False}
        or values.get("nats") != {"enabled": False}
        or values.get("eventBus", {}).get("externalJetStream", {}).get("enabled")
        is not True
        or values.get("controlPlaneEvents", {}).get("mode") != "postgres"
        or values.get("ingest", {}).get("rateLimit", {}).get("scope")
        != "deployment-shared"
        or values.get("secret", {}).get("create") is not False
        or backend_tls.get("enabled") is not True
        or backend_tls.get("port") != 3443
        or backend_tls.get("existingSecret")
        != "orchestra-platform-backend-tls"
        or backend_tls.get("rolloutId") != "release-set-ec705bcc"
        or backend_tls.get("serverName")
        != "orchestra-platform.orchestra-platform.svc"
        or service_certificate
        != {
            "enabled": True,
            "caBundleConfigMapName": "orchestra-platform-service-ca",
        }
        or route.get("tls")
        != {
            "termination": "reencrypt",
            "insecureEdgeTerminationPolicy": "Redirect",
        }
    ):
        fail("product_gitops_platform_boundary_invalid")


def validate_runtime(values: dict[str, Any]) -> None:
    tls = object_value(values.get("serverTls"), "product_gitops_runtime_tls_invalid")
    credentials = object_value(
        values.get("credentials"), "product_gitops_runtime_credentials_invalid"
    )
    if (
        values.get("runtimeEdge", {}).get("overloadContract")
        != "orchestra-runtime-edge-overload-v1"
        or not values.get("runtimeConfig", {}).get("existingSecret")
        or not credentials.get("existingSecret")
        or credentials.get("modelGatewayApiKeyOptional") is not False
        or credentials.get("receiptApiKeyOptional") is not False
        or tls.get("enabled") is not True
        or not tls.get("existingSecret")
        or not tls.get("rolloutId")
        or values.get("backup") != {"enabled": False}
    ):
        fail("product_gitops_runtime_boundary_invalid")


def validate_model(values: dict[str, Any]) -> None:
    tls = object_value(values.get("serverTls"), "product_gitops_model_tls_invalid")
    routing = object_value(values.get("routing"), "product_gitops_model_routing_invalid")
    if (
        values.get("workloadSurface", {}).get("profileId")
        != "orchestra-model-plane-workload-v1"
        or values.get("targetEnvironment") != "prod"
        or values.get("auth", {}).get("enabled") is not True
        or routing.get("policyRequired") is not True
        or routing.get("expectedOrgId") != "tenant-alpha"
        or routing.get("rateLimitScope") != "deployment-shared"
        or tls.get("enabled") is not True
        or not tls.get("existingSecret")
        or not tls.get("rolloutId")
        or values.get("modelBackends", {}).get("mode") != "remote"
        or values.get("otel", {}).get("enabled") is not True
        or values.get("persistence", {}).get("externalBackupAcknowledged")
        is not True
    ):
        fail("product_gitops_model_boundary_invalid")


def validate_applications(release_set: dict[str, Any]) -> str:
    release_set_digest = validate_release_set(release_set)
    validate_project(release_set_digest)
    for plane_name, contract in APPLICATION_CONTRACTS.items():
        application = load_json(PRODUCT_ROOT / contract["file"])
        values = validate_common_application(
            application, release_set, release_set_digest, plane_name, contract
        )
        if plane_name == "platform":
            validate_platform(values)
        elif plane_name == "runtimeHost":
            validate_runtime(values)
        else:
            validate_model(values)
    return release_set_digest


def field(document: str, name: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(name)}:\s*([^\n]+)$", document)
    return match.group(1).strip() if match else None


def validate_rendered(content: str) -> None:
    documents = [
        item.strip()
        for item in re.split(r"(?m)^---\s*$", content)
        if item.strip()
    ]
    counts: dict[str, int] = {}
    for document in documents:
        kind = field(document, "kind")
        if not kind:
            fail("product_gitops_rendered_identity_invalid")
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "Secret":
            fail("product_gitops_secret_object_forbidden")
        if re.search(
            r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", document
        ):
            fail("product_gitops_private_key_forbidden")
    if counts != EXPECTED_RENDERED_COUNTS:
        fail("product_gitops_rendered_inventory_invalid")
    if (
        content.count("kind: ClusterSecretStore") != 13
        or len(re.findall(r"(?m)^\s+name: orchestra-vault$", content)) != 13
    ):
        fail("product_gitops_external_secret_store_invalid")
    if content.count('config.openshift.io/inject-trusted-cabundle: "true"') != 3:
        fail("product_gitops_trusted_ca_invalid")


def main() -> int:
    release_set = load_json(ROOT / "config" / "cross-plane-release-set.lock.json")
    release_set_digest = validate_applications(release_set)
    rendered = sys.stdin.read()
    if not rendered.strip():
        fail("product_gitops_rendered_input_required")
    validate_rendered(rendered)
    print(
        "product_gitops_valid "
        f"releaseSetDigest={release_set_digest} applications=3 secrets=external-only"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
