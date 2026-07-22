#!/usr/bin/env python3
"""Validate the source-only dependency GitOps candidate remains non-activatable."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_repository import ROOT, canonical_digest, load_json


CANDIDATE_LOCK = ROOT / "config" / "dependency-gitops-candidate.lock.json"
CANDIDATE_ROOT = ROOT / "gitops" / "dependencies" / "candidates" / "reference-lab"
ACTIVE_KUSTOMIZATION = (
    ROOT / "gitops" / "dependencies" / "reference-lab" / "kustomization.yaml"
)
TOPOLOGY_LOCK = ROOT / "config" / "lab.lock.json"
RELEASE_SET_LOCK = ROOT / "config" / "cross-plane-release-set.lock.json"
DEPENDENCY_BOM_LOCK = ROOT / "config" / "dependency-bom.lock.json"
DEPENDENCY_ADMISSION_LOCK = ROOT / "config" / "dependency-admission.lock.json"
SOURCE_VERIFICATION_LOCK = ROOT / "config" / "dependency-source-verification.lock.json"
RISK_POLICY_LOCK = ROOT / "config" / "dependency-risk-policy.lock.json"
MIRROR_INTAKE = ROOT / "config" / "dependency-mirror-intake.example.json"

EXPECTED_CANDIDATE_DIGEST = (
    "sha256:6f7a051f0dcf3c46ecbde68efb5e21369d42035ec72cca2f334c652c37600790"
)
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
ARCHITECTURE = "linux/amd64"
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]+$")

EXPECTED_APPLICATIONS = {
    "cloudnative-pg-operator": {
        "controller": "services-gitops",
        "targetCluster": "services-gke",
        "namespace": "orchestra-postgres",
        "stage": "data-foundation",
        "chartId": "cloudnative-pg",
        "images": ["cloudnative-pg-operator"],
        "valuesPath": (
            "gitops/dependencies/candidates/reference-lab/cloudnative-pg.values.json"
        ),
        "valuesDigest": (
            "sha256:81ddf5a16e19dc0523aafcbf0f337757ca0b8bb8ac94c35a6485e1ee819d1a65"
        ),
        "reasonCodes": [
            "SOURCE_ADMISSION_INCOMPLETE",
            "DESTINATION_MIRROR_MISSING",
            "LAB_SIGNATURE_MISSING",
            "LIVE_BACKUP_TARGET_MISSING",
            "SERVER_SIDE_DRY_RUN_MISSING",
            "TWO_PERSON_APPROVAL_MISSING",
        ],
    },
    "clickhouse-operator": {
        "controller": "services-gitops",
        "targetCluster": "services-gke",
        "namespace": "orchestra-clickhouse",
        "stage": "data-foundation",
        "chartId": "clickhouse-operator",
        "images": ["clickhouse-operator", "clickhouse-metrics-exporter"],
        "valuesPath": (
            "gitops/dependencies/candidates/reference-lab/"
            "clickhouse-operator.values.json"
        ),
        "valuesDigest": (
            "sha256:cfb1b2bca2cda9f59956cbccba68afb3721853691833cb454b6f5d77178ced7a"
        ),
        "reasonCodes": [
            "SOURCE_ADMISSION_INCOMPLETE",
            "DESTINATION_MIRROR_MISSING",
            "LAB_SIGNATURE_MISSING",
            "CLICKHOUSE_BACKUP_CONTRACT_PENDING",
            "SERVER_SIDE_DRY_RUN_MISSING",
            "TWO_PERSON_APPROVAL_MISSING",
        ],
    },
    "jetstream": {
        "controller": "services-gitops",
        "targetCluster": "services-gke",
        "namespace": "orchestra-jetstream",
        "stage": "data-foundation",
        "chartId": "nats",
        "images": ["nats-server", "nats-config-reloader"],
        "valuesPath": (
            "gitops/dependencies/candidates/reference-lab/jetstream.values.json"
        ),
        "valuesDigest": (
            "sha256:b838b3041b55491dd5bc6b7de9242c61bad3a5249e1e71d3da22e0f97e2dcdd1"
        ),
        "reasonCodes": [
            "SOURCE_ADMISSION_INCOMPLETE",
            "DESTINATION_MIRROR_MISSING",
            "LAB_SIGNATURE_MISSING",
            "LIVE_BACKUP_TARGET_MISSING",
            "SERVER_SIDE_DRY_RUN_MISSING",
            "TWO_PERSON_APPROVAL_MISSING",
        ],
    },
    "vault": {
        "controller": "services-gitops",
        "targetCluster": "services-gke",
        "namespace": "orchestra-vault",
        "stage": "security-foundation",
        "chartId": "vault",
        "images": ["vault-server"],
        "valuesPath": "gitops/dependencies/candidates/reference-lab/vault.values.json",
        "valuesDigest": (
            "sha256:873993d24263ebf0724ef0f748c26603b00a5d2967cb861ec0743dc83d673b39"
        ),
        "reasonCodes": [
            "SOURCE_ADMISSION_INCOMPLETE",
            "DESTINATION_MIRROR_MISSING",
            "LAB_SIGNATURE_MISSING",
            "LIVE_KMS_BINDING_MISSING",
            "LIVE_PKI_BINDING_MISSING",
            "SERVER_SIDE_DRY_RUN_MISSING",
            "TWO_PERSON_APPROVAL_MISSING",
        ],
    },
    "external-secrets": {
        "controller": "openshift-gitops",
        "targetCluster": "openshift",
        "namespace": "orchestra-external-secrets",
        "stage": "security-foundation",
        "chartId": "external-secrets",
        "images": ["external-secrets-controller"],
        "valuesPath": (
            "gitops/dependencies/candidates/reference-lab/external-secrets.values.json"
        ),
        "valuesDigest": (
            "sha256:a351eca3a1147b1dd4e419ec211d0ce5ac7e131d7947ae161bec4d76c46bb566"
        ),
        "reasonCodes": [
            "SOURCE_ADMISSION_INCOMPLETE",
            "DESTINATION_MIRROR_MISSING",
            "LAB_SIGNATURE_MISSING",
            "VAULT_NOT_READY",
            "CERT_MANAGER_NOT_READY",
            "LIVE_PKI_BINDING_MISSING",
            "OPENSHIFT_SERVER_DRY_RUN_MISSING",
            "TWO_PERSON_APPROVAL_MISSING",
        ],
    },
}

EXPECTED_SERVICE_APPLICATIONS = {
    "postgresql-platform": "cloudnative-pg-operator",
    "postgresql-infrastructure": "cloudnative-pg-operator",
    "clickhouse-and-keeper": "clickhouse-operator",
    "jetstream": "jetstream",
    "vault": "vault",
    "external-secrets": "external-secrets",
}

BOM_SERVICES_COVERED = {
    "postgresql-platform",
    "postgresql-infrastructure",
    "clickhouse",
    "clickhouse-keeper",
    "jetstream",
    "vault",
    "external-secrets",
}

EXPECTED_RENDER_POLICY = {
    "candidateRoot": "gitops/dependencies/candidates/reference-lab",
    "outputRoot": "restricted/dependency-gitops-candidate",
    "offlineHelmTemplateAllowed": True,
    "applicationEmissionAllowed": False,
    "serverDryRunAllowed": False,
    "imperativeSyncAllowed": False,
    "activeKustomizationReferenceAllowed": False,
}

EXPECTED_CLAIM = {
    "sourceCandidateDeclared": True,
    "destinationMirrorsBound": False,
    "labSignaturesVerified": False,
    "applicationsEmitted": False,
    "serverDryRunPassed": False,
    "twoPersonApproved": False,
    "activated": False,
    "applied": False,
    "liveTested": False,
    "campaignEvidence": False,
}

EXPECTED_OVERLAY_CLAIM = {
    "rendered": False,
    "serverDryRunPassed": False,
    "applicationsEmitted": False,
    "activated": False,
    "applied": False,
    "campaignEvidence": False,
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def list_by_id(value: Any, code: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        fail(code)
    result: dict[str, dict[str, Any]] = {}
    for item in value:
        item = object_value(item, code)
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id or item_id in result:
            fail(code)
        result[item_id] = item
    return result


def validate_reason_codes(value: Any, code: str) -> None:
    if (
        not isinstance(value, list)
        or not value
        or len(value) != len(set(value))
        or any(
            not isinstance(item, str) or not REASON_CODE.fullmatch(item)
            for item in value
        )
    ):
        fail(code)


def nested_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [item for child in value.values() for item in nested_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in nested_strings(child)]
    return [value] if isinstance(value, str) else []


def repo_path(value: Any, candidate_root: Path = CANDIDATE_ROOT) -> Path:
    if not isinstance(value, str) or not value:
        fail("dependency_gitops_candidate_path_invalid")
    resolved = (ROOT / value).resolve()
    try:
        resolved.relative_to(candidate_root.resolve())
    except ValueError:
        fail("dependency_gitops_candidate_path_escape")
    if not resolved.is_file():
        fail("dependency_gitops_candidate_file_missing")
    return resolved


def validate_application_values(
    application_id: str,
    values: dict[str, Any],
    image_sources: dict[str, dict[str, Any]],
) -> None:
    expected = EXPECTED_APPLICATIONS[application_id]
    serialized = json.dumps(values, sort_keys=True)
    strings = nested_strings(values)
    if (
        "ORCHESTRA_SERVICES_PROJECT_REQUIRED" not in serialized
        or "europe-west1-docker.pkg.dev" not in serialized
        or any(
            item.lower() == "latest" or re.search(r"(?i):latest(?:@|$)", item)
            for item in strings
        )
    ):
        fail(f"dependency_gitops_candidate_values_image_invalid:{application_id}")
    for image_id in expected["images"]:
        source = object_value(
            image_sources[image_id].get("source"),
            f"dependency_gitops_candidate_source_image_invalid:{image_id}",
        )
        platform_digest = source.get("platformDigest")
        index_digest = source.get("indexDigest")
        source_reference = source.get("reference")
        if (
            not isinstance(platform_digest, str)
            or platform_digest not in serialized
            or index_digest in serialized
            or not isinstance(source_reference, str)
            or source_reference in serialized
        ):
            fail(f"dependency_gitops_candidate_image_projection_invalid:{image_id}")
    if any(item.startswith(("docker.io/", "ghcr.io/", "quay.io/")) for item in strings):
        fail(f"dependency_gitops_candidate_upstream_image_leak:{application_id}")

    if application_id == "cloudnative-pg-operator":
        if (
            values.get("replicaCount") != 2
            or values.get("crds") != {"create": True}
            or object_value(values.get("config"), "cloudnative_pg_config_invalid").get(
                "secret"
            )
            is not False
            or object_value(
                values.get("containerSecurityContext"),
                "cloudnative_pg_security_invalid",
            ).get("readOnlyRootFilesystem")
            is not True
        ):
            fail("dependency_gitops_candidate_cloudnative_pg_values_invalid")
    elif application_id == "clickhouse-operator":
        if (
            values.get("crdHook") != {"enabled": False}
            or values.get("secret") != {"create": False}
            or object_value(values.get("metrics"), "clickhouse_metrics_invalid").get(
                "enabled"
            )
            is not True
        ):
            fail("dependency_gitops_candidate_clickhouse_values_invalid")
    elif application_id == "jetstream":
        config = object_value(values.get("config"), "jetstream_config_invalid")
        cluster = object_value(config.get("cluster"), "jetstream_cluster_invalid")
        jetstream = object_value(config.get("jetstream"), "jetstream_storage_invalid")
        file_store = object_value(
            jetstream.get("fileStore"), "jetstream_file_store_invalid"
        )
        pvc = object_value(file_store.get("pvc"), "jetstream_pvc_invalid")
        pdb = object_value(values.get("podDisruptionBudget"), "jetstream_pdb_invalid")
        if (
            cluster.get("replicas") != 3
            or object_value(cluster.get("tls"), "jetstream_route_tls_invalid").get(
                "enabled"
            )
            is not True
            or object_value(
                object_value(config.get("nats"), "jetstream_nats_invalid").get("tls"),
                "jetstream_client_tls_invalid",
            ).get("enabled")
            is not True
            or jetstream.get("enabled") is not True
            or pvc.get("storageClassName") != "orchestra-regional-rwo"
            or pdb.get("enabled") is not True
            or object_value(pdb.get("merge"), "jetstream_pdb_merge_invalid")
            .get("spec", {})
            .get("minAvailable")
            != 2
            or values.get("natsBox") != {"enabled": False}
        ):
            fail("dependency_gitops_candidate_jetstream_values_invalid")
    elif application_id == "vault":
        server = object_value(values.get("server"), "vault_server_invalid")
        ha = object_value(server.get("ha"), "vault_ha_invalid")
        raft = object_value(ha.get("raft"), "vault_raft_invalid")
        config = raft.get("config")
        stateful_set = object_value(
            server.get("statefulSet"), "vault_stateful_set_invalid"
        )
        security = object_value(
            stateful_set.get("securityContext"), "vault_security_invalid"
        )
        if (
            values.get("global") != {"enabled": True, "tlsDisable": False}
            or values.get("injector") != {"enabled": False}
            or values.get("csi") != {"enabled": False}
            or ha.get("enabled") is not True
            or ha.get("replicas") != 3
            or raft.get("enabled") is not True
            or raft.get("setNodeId") is not True
            or not isinstance(config, str)
            or 'seal "gcpckms"' not in config
            or "tls_disable = 0" not in config
            or "disable_mlock = true" not in config
            or "node_id" in config
            or security.get("pod")
            != {
                "runAsNonRoot": True,
                "seccompProfile": {"type": "RuntimeDefault"},
            }
            or security.get("container")
            != {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"},
            }
            or object_value(
                server.get("dataStorage"), "vault_data_storage_invalid"
            ).get("storageClass")
            != "orchestra-regional-rwo"
        ):
            fail("dependency_gitops_candidate_vault_values_invalid")
    elif application_id == "external-secrets":
        global_values = object_value(
            values.get("global"), "external_secrets_global_invalid"
        )
        compatibility = object_value(
            global_values.get("compatibility"),
            "external_secrets_compatibility_invalid",
        )
        openshift = object_value(
            compatibility.get("openshift"), "external_secrets_openshift_invalid"
        )
        if (
            values.get("replicaCount") != 2
            or values.get("installCRDs") is not True
            or openshift.get("adaptSecurityContext") != "force"
            or values.get("genericTargets") != {"enabled": False, "resources": []}
            or values.get("podDisruptionBudget") != {"enabled": True, "minAvailable": 1}
            or object_value(
                values.get("webhook"), "external_secrets_webhook_invalid"
            ).get("replicaCount")
            != 2
            or object_value(
                object_value(
                    values.get("webhook"), "external_secrets_webhook_invalid"
                ).get("certManager"),
                "external_secrets_cert_manager_invalid",
            )
            != {
                "enabled": True,
                "addInjectorAnnotations": True,
                "cert": {"create": False},
            }
            or object_value(
                values.get("certController"),
                "external_secrets_cert_controller_invalid",
            ).get("create")
            is not False
        ):
            fail("dependency_gitops_candidate_external_secrets_values_invalid")


def validate_service_overlays(
    value: dict[str, Any],
    admission_services: dict[str, dict[str, Any]],
) -> None:
    if set(value) != {
        "schemaVersion",
        "kind",
        "profileId",
        "overlays",
        "claim",
    }:
        fail("dependency_gitops_candidate_service_overlay_keys_invalid")
    if (
        value.get("schemaVersion") != 1
        or value.get("kind") != "orchestra.dependency-service-overlays.v1"
        or value.get("profileId") != PROFILE_ID
        or value.get("claim") != EXPECTED_OVERLAY_CLAIM
    ):
        fail("dependency_gitops_candidate_service_overlay_identity_invalid")
    overlays = list_by_id(
        value.get("overlays"), "dependency_gitops_candidate_service_overlays_invalid"
    )
    if set(overlays) != set(EXPECTED_SERVICE_APPLICATIONS):
        fail("dependency_gitops_candidate_service_overlay_inventory_invalid")
    for service_id, application_id in EXPECTED_SERVICE_APPLICATIONS.items():
        overlay = overlays[service_id]
        admitted = admission_services[service_id]
        if set(overlay) != {
            "id",
            "applicationId",
            "targetCluster",
            "namespace",
            "resourceKinds",
            "configurationState",
            "reasonCodes",
        }:
            fail(
                f"dependency_gitops_candidate_service_overlay_shape_invalid:{service_id}"
            )
        validate_reason_codes(
            overlay.get("reasonCodes"),
            f"dependency_gitops_candidate_service_reason_codes_invalid:{service_id}",
        )
        if (
            overlay.get("applicationId") != application_id
            or overlay.get("targetCluster") != admitted.get("targetCluster")
            or overlay.get("namespace") != admitted.get("namespace")
            or overlay.get("reasonCodes") != admitted.get("reasonCodes")
            or overlay.get("configurationState") != "blocked"
            or not isinstance(overlay.get("resourceKinds"), list)
            or not overlay["resourceKinds"]
            or len(overlay["resourceKinds"]) != len(set(overlay["resourceKinds"]))
        ):
            fail(f"dependency_gitops_candidate_service_overlay_invalid:{service_id}")


def validate_candidate_tree(
    candidate_root: Path = CANDIDATE_ROOT,
    active_kustomization_content: str | None = None,
) -> None:
    for path in candidate_root.rglob("*"):
        if not path.is_file():
            continue
        if path.name.lower().startswith("kustomization") or path.suffix in {
            ".yaml",
            ".yml",
        }:
            fail("dependency_gitops_candidate_manifest_forbidden")
        if path.suffix == ".json":
            value = load_json(path)
            stack: list[Any] = [value]
            while stack:
                current = stack.pop()
                if isinstance(current, dict):
                    if current.get("kind") in {
                        "Application",
                        "ApplicationSet",
                        "Secret",
                    }:
                        fail("dependency_gitops_candidate_object_forbidden")
                    stack.extend(current.values())
                elif isinstance(current, list):
                    stack.extend(current)
    content = (
        active_kustomization_content
        if active_kustomization_content is not None
        else ACTIVE_KUSTOMIZATION.read_text(encoding="utf-8")
    )
    if "candidates/reference-lab" in content or "../candidates" in content:
        fail("dependency_gitops_candidate_active_reference_forbidden")


def validate_candidate(
    value: dict[str, Any],
    topology: dict[str, Any],
    release_set: dict[str, Any],
    dependency_bom: dict[str, Any],
    admission: dict[str, Any],
    source_verification: dict[str, Any],
    risk_policy: dict[str, Any],
    mirror_intake: dict[str, Any],
    *,
    candidate_root: Path = CANDIDATE_ROOT,
    active_kustomization_content: str | None = None,
    enforce_expected_digest: bool = True,
) -> str:
    if set(value) != {
        "schemaVersion",
        "kind",
        "candidateId",
        "profileId",
        "architecture",
        "bindings",
        "applications",
        "serviceOverlays",
        "unresolvedServices",
        "renderPolicy",
        "claim",
    }:
        fail("dependency_gitops_candidate_keys_invalid")
    if (
        value.get("schemaVersion") != 1
        or value.get("kind") != "orchestra.dependency-gitops-candidate.v1"
        or value.get("candidateId")
        != "orchestra-dependency-gitops-source-candidate-2026-07-22.1"
        or value.get("profileId") != PROFILE_ID
        or value.get("architecture") != ARCHITECTURE
        or value.get("renderPolicy") != EXPECTED_RENDER_POLICY
        or value.get("claim") != EXPECTED_CLAIM
    ):
        fail("dependency_gitops_candidate_identity_invalid")

    expected_bindings = {
        "topologyDigest": canonical_digest(topology),
        "releaseSetDigest": canonical_digest(release_set),
        "dependencyBomDigest": canonical_digest(dependency_bom),
        "dependencyAdmissionDigest": canonical_digest(admission),
        "sourceVerificationDigest": canonical_digest(source_verification),
        "riskPolicyDigest": canonical_digest(risk_policy),
        "mirrorIntakeDigest": canonical_digest(mirror_intake),
    }
    if value.get("bindings") != expected_bindings:
        fail("dependency_gitops_candidate_bindings_invalid")
    if (
        source_verification.get("claim", {}).get("mirroringAuthorized") is not False
        or risk_policy.get("claim", {}).get("activationAuthorized") is not False
        or mirror_intake.get("claim", {}).get("activationAuthorized") is not False
    ):
        fail("dependency_gitops_candidate_upstream_gate_unexpected")

    chart_packages = list_by_id(
        dependency_bom.get("chartPackages"),
        "dependency_gitops_candidate_chart_inventory_invalid",
    )
    image_sources = list_by_id(
        admission.get("images"), "dependency_gitops_candidate_image_inventory_invalid"
    )
    admission_services = list_by_id(
        admission.get("serviceContracts"),
        "dependency_gitops_candidate_admission_services_invalid",
    )
    applications = list_by_id(
        value.get("applications"),
        "dependency_gitops_candidate_applications_invalid",
    )
    if set(applications) != set(EXPECTED_APPLICATIONS):
        fail("dependency_gitops_candidate_application_inventory_invalid")

    for application_id, expected in EXPECTED_APPLICATIONS.items():
        application = applications[application_id]
        if set(application) != {
            "id",
            "controller",
            "targetCluster",
            "namespace",
            "stage",
            "chart",
            "images",
            "values",
            "activationState",
            "reasonCodes",
        }:
            fail(
                f"dependency_gitops_candidate_application_shape_invalid:{application_id}"
            )
        for field in ("controller", "targetCluster", "namespace", "stage"):
            if application.get(field) != expected[field]:
                fail(
                    f"dependency_gitops_candidate_application_invalid:{application_id}"
                )
        if (
            application.get("activationState") != "blocked"
            or application.get("reasonCodes") != expected["reasonCodes"]
        ):
            fail(f"dependency_gitops_candidate_activation_invalid:{application_id}")
        validate_reason_codes(
            application.get("reasonCodes"),
            f"dependency_gitops_candidate_reason_codes_invalid:{application_id}",
        )

        chart = object_value(
            application.get("chart"),
            f"dependency_gitops_candidate_chart_invalid:{application_id}",
        )
        package = chart_packages[expected["chartId"]]
        expected_chart = {
            "id": expected["chartId"],
            "name": package["chart"],
            "version": package["chartVersion"],
            "packageDigest": package["packageDigest"],
            "mirrorPath": package["mirrorPath"],
            "destinationRepository": None,
        }
        if chart != expected_chart:
            fail(f"dependency_gitops_candidate_chart_lock_invalid:{application_id}")

        images = list_by_id(
            application.get("images"),
            f"dependency_gitops_candidate_images_invalid:{application_id}",
        )
        if list(images) != expected["images"]:
            fail(f"dependency_gitops_candidate_images_invalid:{application_id}")
        for image_id, image in images.items():
            source = object_value(
                image_sources[image_id].get("source"),
                f"dependency_gitops_candidate_source_image_invalid:{image_id}",
            )
            if image != {
                "id": image_id,
                "sourceIndexDigest": source["indexDigest"],
                "sourcePlatformDigest": source["platformDigest"],
                "destinationReference": None,
            }:
                fail(f"dependency_gitops_candidate_image_lock_invalid:{image_id}")

        values_lock = object_value(
            application.get("values"),
            f"dependency_gitops_candidate_values_lock_invalid:{application_id}",
        )
        if values_lock != {
            "path": expected["valuesPath"],
            "canonicalDigest": expected["valuesDigest"],
        }:
            fail(f"dependency_gitops_candidate_values_lock_invalid:{application_id}")
        values_path = repo_path(values_lock["path"], candidate_root)
        values = load_json(values_path)
        if canonical_digest(values) != values_lock["canonicalDigest"]:
            fail(f"dependency_gitops_candidate_values_digest_invalid:{application_id}")
        validate_application_values(application_id, values, image_sources)

    service_lock = object_value(
        value.get("serviceOverlays"),
        "dependency_gitops_candidate_service_lock_invalid",
    )
    expected_service_path = (
        "gitops/dependencies/candidates/reference-lab/service-overlays.json"
    )
    if service_lock != {
        "path": expected_service_path,
        "canonicalDigest": (
            "sha256:76d8efbd3c25be01ac58e5b54ec64fbdf711da2524e91615aa46c8013665f244"
        ),
    }:
        fail("dependency_gitops_candidate_service_lock_invalid")
    service_path = repo_path(service_lock["path"], candidate_root)
    service_overlays = load_json(service_path)
    if canonical_digest(service_overlays) != service_lock["canonicalDigest"]:
        fail("dependency_gitops_candidate_service_digest_invalid")
    validate_service_overlays(service_overlays, admission_services)

    bom_services = list_by_id(
        dependency_bom.get("serviceContracts"),
        "dependency_gitops_candidate_bom_services_invalid",
    )
    expected_unresolved = set(bom_services) - BOM_SERVICES_COVERED
    unresolved = list_by_id(
        value.get("unresolvedServices"),
        "dependency_gitops_candidate_unresolved_services_invalid",
    )
    if set(unresolved) != expected_unresolved:
        fail("dependency_gitops_candidate_unresolved_inventory_invalid")
    for service_id, item in unresolved.items():
        if set(item) != {"id", "reasonCodes"}:
            fail(f"dependency_gitops_candidate_unresolved_shape_invalid:{service_id}")
        validate_reason_codes(
            item.get("reasonCodes"),
            f"dependency_gitops_candidate_unresolved_reason_codes_invalid:{service_id}",
        )
        if item.get("reasonCodes") != bom_services[service_id].get("reasonCodes"):
            fail(f"dependency_gitops_candidate_unresolved_invalid:{service_id}")

    validate_candidate_tree(candidate_root, active_kustomization_content)
    digest = canonical_digest(value)
    if enforce_expected_digest and digest != EXPECTED_CANDIDATE_DIGEST:
        fail("dependency_gitops_candidate_digest_changed")
    return digest


def main() -> int:
    digest = validate_candidate(
        load_json(CANDIDATE_LOCK),
        load_json(TOPOLOGY_LOCK),
        load_json(RELEASE_SET_LOCK),
        load_json(DEPENDENCY_BOM_LOCK),
        load_json(DEPENDENCY_ADMISSION_LOCK),
        load_json(SOURCE_VERIFICATION_LOCK),
        load_json(RISK_POLICY_LOCK),
        load_json(MIRROR_INTAKE),
    )
    print(
        "dependency_gitops_candidate_valid "
        f"digest={digest} charts=5 service_overlays=6 applications=0 "
        "activation=blocked evidence=none"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error)
        raise SystemExit(1)
