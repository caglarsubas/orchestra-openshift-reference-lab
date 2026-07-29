#!/usr/bin/env python3
"""Validate the source-resolved but deliberately non-activatable dependency intake."""

from __future__ import annotations

import re
from typing import Any, NoReturn

try:
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_repository import ROOT, canonical_digest, load_json


ADMISSION_LOCK = ROOT / "config" / "dependency-admission.lock.json"
DEPENDENCY_BOM_DIGEST = (
    "sha256:fabec47064381d067ca759ba99c47470cc66628ecaacd2e0521f50bb29aad5dc"
)
TOPOLOGY_DIGEST = (
    "sha256:7c72982c74afd5d5ebdb1c5ea92054b477cd70cc604d7f14a1f4c348ec670fc5"
)
EXPECTED_ADMISSION_DIGEST = (
    "sha256:73282faf172793398120509087930691e362f2290d4b60cc7f13ef4f99bf4219"
)
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]+$")

EXPECTED_IMAGES = {
    "cloudnative-pg-operator": (
        "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.0",
        "sha256:a2701eb97cdd2a34b1fdb2cb51987f544b706e40bec72ae7146cd8580efefebb",
        "sha256:091d306935cfdf646debfe78010d59ebfb572150eb6eb922b0203873c0c68841",
    ),
    "cloudnative-pg-postgresql-16": (
        "ghcr.io/cloudnative-pg/postgresql:16.10-system-trixie",
        "sha256:26e146bc71ebfc2a3937f729a15161a7fb6cd7c8a0b0007ad60cb53d2371b3fc",
        "sha256:dea92d39d38abf4d87c0b0bd43cbf956dc2de03db3a78b5829ac629ef296b8e1",
    ),
    "barman-cloud-controller": (
        "ghcr.io/cloudnative-pg/plugin-barman-cloud:v0.13.0",
        "sha256:71589dbac582333442812b07b31f7ea4d00324a8358aac7ca507dabf9f4b6c96",
        "sha256:417449fe4f6f0a56acdeb30e4131930815f2b46b9afeb808059b57aa8b4c2ef5",
    ),
    "barman-cloud-sidecar": (
        "ghcr.io/cloudnative-pg/plugin-barman-cloud-sidecar:v0.13.0",
        "sha256:990361af3319f9e23aafa0f6d7981f99bf1f69b4e6a85cf1bc7d71d6f09bb288",
        "sha256:15cb1a01e7c5235eedac2061cab8208e5f7c39dbda292f9c2d4ddaa0c1f211e6",
    ),
    "clickhouse-operator": (
        "docker.io/altinity/clickhouse-operator:0.27.1",
        "sha256:a802b3a19d2011f672c32cea6733e573e004938ff463d1c3ab4ac0b16b9877dd",
        "sha256:678ea8ebc4f68eb6fef14e1461c2109cb8d9d135c0f2d4119a46141d54fa0930",
    ),
    "clickhouse-metrics-exporter": (
        "docker.io/altinity/metrics-exporter:0.27.1",
        "sha256:5523d83190ad1560051f19fe6daa00876436f12cf833a506731ed6226192193f",
        "sha256:ca56a26fda49da1a5938e5532b6f0ead71726af38d5dd88810fc0cd4123ef113",
    ),
    "clickhouse-server-lts": (
        "docker.io/clickhouse/clickhouse-server:25.8.28.1",
        "sha256:a9d328123ff8a61bf6b16448528b577d59deb85758172e13b09054b0727f8adf",
        "sha256:cb75da0e596b8115d10bea34cef1414eafebfbcb5f5136c03e022c7b525899b3",
    ),
    "nats-server": (
        "docker.io/library/nats:2.14.2-alpine",
        "sha256:952d157e28d5394a211229bd57a7b37ff9f184e58e2c8486a08fa909fd254e32",
        "sha256:8c0cf827d557b41c5973875a2618eb886aa26d20921471f03ed1185702ad1cf2",
    ),
    "nats-config-reloader": (
        "docker.io/natsio/nats-server-config-reloader:0.23.0",
        "sha256:64cb6c858e794906d3167378e02b7e0feb83c4e14c07b371eb8d921ef8c4a60b",
        "sha256:1418d42cea39ea729c1d34ca26ba33d967abdf040bad45ec1314c807bfacc56f",
    ),
    "vault-server": (
        "docker.io/hashicorp/vault:2.0.3",
        "sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54",
        "sha256:db6a5f78749204d0a8d002be1cc6e9a2a6de53dffce41a894c4a06d309dca360",
    ),
    "external-secrets-controller": (
        "ghcr.io/external-secrets/external-secrets:v2.8.0",
        "sha256:24c0dd3699e0988520afd2218612758cd97d1f702757b5b4fcf89adaa33ef679",
        "sha256:02259bfd212de0b563b1eb9065e85e816bfec13d1aec84ee4e1a48cfed228b40",
    ),
}

EXPECTED_SERVICES = {
    "postgresql-platform": {
        "target": "services-gke",
        "namespace": "orchestra-postgres",
        "provider": "cloudnative-pg",
        "images": {
            "cloudnative-pg-operator",
            "cloudnative-pg-postgresql-16",
            "barman-cloud-controller",
            "barman-cloud-sidecar",
        },
    },
    "postgresql-infrastructure": {
        "target": "services-gke",
        "namespace": "orchestra-postgres",
        "provider": "cloudnative-pg",
        "images": {
            "cloudnative-pg-operator",
            "cloudnative-pg-postgresql-16",
            "barman-cloud-controller",
            "barman-cloud-sidecar",
        },
    },
    "clickhouse-and-keeper": {
        "target": "services-gke",
        "namespace": "orchestra-clickhouse",
        "provider": "altinity-clickhouse-operator",
        "images": {
            "clickhouse-operator",
            "clickhouse-metrics-exporter",
            "clickhouse-server-lts",
        },
    },
    "jetstream": {
        "target": "services-gke",
        "namespace": "orchestra-jetstream",
        "provider": "nats-helm",
        "images": {"nats-server", "nats-config-reloader"},
    },
    "vault": {
        "target": "services-gke",
        "namespace": "orchestra-vault",
        "provider": "vault-helm",
        "images": {"vault-server"},
    },
    "external-secrets": {
        "target": "openshift",
        "namespace": "orchestra-external-secrets",
        "provider": "external-secrets-helm",
        "images": {"external-secrets-controller"},
    },
}

EXPECTED_CLAIM = {
    "sourceImagesResolved": True,
    "serviceContractsDeclared": True,
    "upstreamSignaturesVerified": False,
    "mirrored": False,
    "labSigned": False,
    "serverDryRunPassed": False,
    "twoPersonApproved": False,
    "activated": False,
    "applied": False,
    "liveTested": False,
    "campaignEvidence": False,
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


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


def validate_images(images: Any) -> set[str]:
    if not isinstance(images, list) or len(images) != len(EXPECTED_IMAGES):
        fail("dependency_admission_image_inventory_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    image_keys = {
        "id",
        "owners",
        "purpose",
        "source",
        "upstreamVerification",
        "mirrors",
        "labSignatureBundleDigest",
        "activationState",
        "reasonCodes",
    }
    for image in images:
        image = object_value(image, "dependency_admission_image_invalid")
        if set(image) != image_keys:
            fail("dependency_admission_image_keys_invalid")
        image_id = image.get("id")
        if not isinstance(image_id, str) or image_id in by_id:
            fail("dependency_admission_image_id_invalid")
        by_id[image_id] = image
    if set(by_id) != set(EXPECTED_IMAGES):
        fail("dependency_admission_image_inventory_invalid")

    for image_id, expected_source in EXPECTED_IMAGES.items():
        image = by_id[image_id]
        source = object_value(
            image.get("source"), f"dependency_admission_source_invalid:{image_id}"
        )
        verification = object_value(
            image.get("upstreamVerification"),
            f"dependency_admission_verification_invalid:{image_id}",
        )
        mirrors = object_value(
            image.get("mirrors"), f"dependency_admission_mirrors_invalid:{image_id}"
        )
        if (
            set(source) != {"reference", "indexDigest", "platformDigest", "platform"}
            or (source["reference"], source["indexDigest"], source["platformDigest"])
            != expected_source
            or source["platform"] != "linux/amd64"
            or ":latest" in source["reference"]
            or not DIGEST.fullmatch(source["indexDigest"])
            or not DIGEST.fullmatch(source["platformDigest"])
        ):
            fail(f"dependency_admission_source_lock_invalid:{image_id}")
        if (
            set(verification) != {"status", "method", "identityPolicy"}
            or verification["status"] != "pending"
            or verification["method"] not in {"sigstore-keyless", "reviewed-exception"}
            or (
                verification["method"] == "sigstore-keyless"
                and not isinstance(verification["identityPolicy"], str)
            )
            or (
                verification["method"] == "reviewed-exception"
                and verification["identityPolicy"] is not None
            )
        ):
            fail(f"dependency_admission_verification_invalid:{image_id}")
        if set(mirrors) != {"artifactRegistry", "harbor"}:
            fail(f"dependency_admission_mirrors_invalid:{image_id}")
        for target in mirrors.values():
            if target != {"reference": None, "digest": None}:
                fail(f"dependency_admission_mirror_must_be_empty:{image_id}")
        owners = image.get("owners")
        if (
            not isinstance(owners, list)
            or not owners
            or len(owners) != len(set(owners))
            or any(not isinstance(owner, str) or not owner for owner in owners)
            or not isinstance(image.get("purpose"), str)
            or image["activationState"] != "blocked"
            or image["labSignatureBundleDigest"] is not None
        ):
            fail(f"dependency_admission_image_state_invalid:{image_id}")
        validate_reason_codes(
            image["reasonCodes"],
            f"dependency_admission_reason_codes_invalid:{image_id}",
        )
    return set(by_id)


def validate_source_artifacts(artifacts: Any) -> None:
    if not isinstance(artifacts, list) or artifacts != [
        {
            "id": "barman-cloud-manifest",
            "type": "release-manifest",
            "sourceUrl": "https://github.com/cloudnative-pg/plugin-barman-cloud/releases/download/v0.13.0/manifest.yaml",
            "sourceDigest": "sha256:d2e71e7b06822448f1a421f05781846cfdb9cc621e7ef32eef5e20c5133213b0",
            "upstreamVerificationStatus": "pending",
            "artifactRegistryDigest": None,
            "harborDigest": None,
            "labSignatureBundleDigest": None,
            "activationState": "blocked",
            "reasonCodes": [
                "UPSTREAM_SIGNATURE_PENDING",
                "DESTINATION_MIRROR_MISSING",
                "LAB_SIGNATURE_MISSING",
                "MANIFEST_HARDENING_PATCH_REQUIRED",
            ],
        }
    ]:
        fail("dependency_admission_source_artifact_invalid")


def validate_service_contracts(
    services: Any, image_ids: set[str], topology: dict[str, Any]
) -> None:
    if not isinstance(services, list) or len(services) != len(EXPECTED_SERVICES):
        fail("dependency_admission_service_inventory_invalid")
    common_keys = {
        "id",
        "targetCluster",
        "namespace",
        "provider",
        "activationState",
        "reasonCodes",
        "images",
        "availability",
        "storage",
        "security",
        "backup",
        "network",
    }
    by_id: dict[str, dict[str, Any]] = {}
    for service in services:
        service = object_value(service, "dependency_admission_service_invalid")
        if set(service) != common_keys:
            fail("dependency_admission_service_keys_invalid")
        service_id = service.get("id")
        if not isinstance(service_id, str) or service_id in by_id:
            fail("dependency_admission_service_id_invalid")
        by_id[service_id] = service
    if set(by_id) != set(EXPECTED_SERVICES):
        fail("dependency_admission_service_inventory_invalid")

    for service_id, expected in EXPECTED_SERVICES.items():
        service = by_id[service_id]
        referenced_images = service.get("images")
        security = object_value(
            service.get("security"),
            f"dependency_admission_security_invalid:{service_id}",
        )
        network = object_value(
            service.get("network"), f"dependency_admission_network_invalid:{service_id}"
        )
        if (
            service["targetCluster"] != expected["target"]
            or service["namespace"] != expected["namespace"]
            or service["provider"] != expected["provider"]
            or service["activationState"] != "blocked"
            or not isinstance(referenced_images, list)
            or set(referenced_images) != expected["images"]
            or not set(referenced_images).issubset(image_ids)
        ):
            fail(f"dependency_admission_service_contract_invalid:{service_id}")
        validate_reason_codes(
            service["reasonCodes"],
            f"dependency_admission_service_reasons_invalid:{service_id}",
        )
        if (
            security.get("tls") not in {"required", "mutual-required"}
            or security.get("superuserAccess") is not False
            or not isinstance(security.get("tlsSecretRefs"), list)
            or not security["tlsSecretRefs"]
            or network
            != {
                "allowedClientIdentities": network.get("allowedClientIdentities"),
                "publicEndpoint": False,
                "defaultDeny": True,
            }
            or not isinstance(network["allowedClientIdentities"], list)
            or not network["allowedClientIdentities"]
        ):
            fail(f"dependency_admission_security_boundary_invalid:{service_id}")
        storage = service["storage"]
        if storage is not None:
            storage = object_value(
                storage, f"dependency_admission_storage_invalid:{service_id}"
            )
            if (
                storage.get("class") != "orchestra-regional-rwo"
                or storage.get("volumeMode") != "Filesystem"
                or storage.get("allowExpansion") is not True
            ):
                fail(f"dependency_admission_storage_invalid:{service_id}")

    topology_services = {
        item["kind"]: item for item in topology["dependencyPlane"]["dependencies"]
    }
    if (
        by_id["postgresql-platform"]["availability"]["instances"]
        != topology_services["postgresql-platform"]["instances"]
        or by_id["postgresql-infrastructure"]["availability"]["instances"]
        != topology_services["postgresql-infrastructure"]["instances"]
        or by_id["jetstream"]["availability"]["instances"]
        != topology_services["jetstream"]["instances"]
        or by_id["vault"]["availability"]["instances"]
        != topology_services["vault"]["instances"]
        or by_id["clickhouse-and-keeper"]["availability"]["replicas"]
        != topology_services["clickhouse"]["replicas"]
        or by_id["clickhouse-and-keeper"]["availability"]["shards"]
        != topology_services["clickhouse"]["shards"]
        or by_id["clickhouse-and-keeper"]["availability"]["keeperInstances"]
        != topology_services["clickhouse-keeper"]["instances"]
    ):
        fail("dependency_admission_topology_mismatch")
    if by_id["clickhouse-and-keeper"]["backup"]["provider"] != "decision-pending":
        fail("dependency_admission_clickhouse_backup_gap_hidden")
    if (
        by_id["external-secrets"]["storage"] is not None
        or by_id["external-secrets"]["backup"] is not None
    ):
        fail("dependency_admission_external_secrets_stateful_invalid")


def validate_admission(
    value: dict[str, Any], dependency_bom: dict[str, Any], topology: dict[str, Any]
) -> str:
    if set(value) != {
        "schemaVersion",
        "profileId",
        "admissionId",
        "bindings",
        "claim",
        "architecture",
        "images",
        "sourceArtifacts",
        "serviceContracts",
        "admission",
    }:
        fail("dependency_admission_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != topology["profileId"]
        or value["admissionId"] != "orchestra-dependency-admission-2026-07-21.1"
        or value["architecture"] != "linux/amd64"
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "dependencyBomDigest": DEPENDENCY_BOM_DIGEST,
        }
        or canonical_digest(dependency_bom) != DEPENDENCY_BOM_DIGEST
        or dependency_bom["admission"]["activation"] != "blocked"
        or value["claim"] != EXPECTED_CLAIM
    ):
        fail("dependency_admission_identity_invalid")
    image_ids = validate_images(value["images"])
    validate_source_artifacts(value["sourceArtifacts"])
    validate_service_contracts(value["serviceContracts"], image_ids, topology)
    admission = object_value(value["admission"], "dependency_admission_gate_invalid")
    if (
        set(admission)
        != {
            "activation",
            "requiredEvidence",
            "unresolvedReasonCodes",
        }
        or admission["activation"] != "blocked"
        or not isinstance(admission["requiredEvidence"], list)
        or len(admission["requiredEvidence"]) != 10
        or len(set(admission["requiredEvidence"])) != 10
        or not isinstance(admission["unresolvedReasonCodes"], list)
        or "CLICKHOUSE_BACKUP_CONTRACT_PENDING"
        not in admission["unresolvedReasonCodes"]
        or "SERVER_SIDE_DRY_RUNS_MISSING" not in admission["unresolvedReasonCodes"]
        or "TWO_PERSON_APPROVAL_MISSING" not in admission["unresolvedReasonCodes"]
    ):
        fail("dependency_admission_gate_invalid")
    validate_reason_codes(
        admission["unresolvedReasonCodes"],
        "dependency_admission_unresolved_reasons_invalid",
    )
    digest = canonical_digest(value)
    if digest != EXPECTED_ADMISSION_DIGEST:
        fail(f"dependency_admission_digest_changed:{digest}")
    return digest


def main() -> int:
    admission = load_json(ADMISSION_LOCK)
    dependency_bom = load_json(ROOT / "config" / "dependency-bom.lock.json")
    topology = load_json(ROOT / "config" / "lab.lock.json")
    digest = validate_admission(admission, dependency_bom, topology)
    print(
        "dependency_admission_valid "
        f"digest={digest} images={len(EXPECTED_IMAGES)} "
        f"services={len(EXPECTED_SERVICES)} activation=blocked"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error)
        raise SystemExit(1)
