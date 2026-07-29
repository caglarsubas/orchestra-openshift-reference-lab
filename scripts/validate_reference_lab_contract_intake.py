#!/usr/bin/env python3
"""Validate the platform-owned reference-lab certification contract intake."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_dependency_bom import validate_dependency_bom
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import ROOT, canonical_digest
except ModuleNotFoundError:
    from validate_dependency_bom import validate_dependency_bom
    from validate_release_set import validate_release_set
    from validate_repository import ROOT, canonical_digest


INTAKE_PATH = ROOT / "config" / "reference-lab-certification-contract.lock.json"
EXPECTED_INTAKE_DIGEST = (
    "sha256:bd2485b6cbcc35402bf8ed73929a13986ac44c132abac1d8d39e7745550fe6f5"
)
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
POLICY_ID = "orchestra-reference-lab-live-v2"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
ARTIFACT_PATHS = {
    "certification-policy": (
        "prometa-platform/deploy/helm/prometa/ci/"
        "reference-lab-certification-policy.v2.json",
        "contracts/platform/reference-lab-certification-policy.v2.json",
    ),
    "contract-schema-bundle": (
        "prometa-platform/deploy/helm/prometa/ci/"
        "reference-lab-contract-schemas.v2.json",
        "contracts/platform/reference-lab-contract-schemas.v2.json",
    ),
    "fixture-campaign": (
        "prometa-platform/deploy/helm/prometa/ci/reference-lab-campaign.example.json",
        "contracts/platform/reference-lab-campaign.fixture.json",
    ),
}
SCHEMA_CONTRACTS = (
    "campaign",
    "campaignClosure",
    "evidence",
    "evidenceIndex",
    "faultAttestation",
    "policy",
    "referenceProfileVerificationBom",
    "reviewAttestation",
)
FORBIDDEN_EVIDENCE_KEYS = (
    "apiKey",
    "arguments",
    "authorizationHeader",
    "body",
    "content",
    "credential",
    "inputPayload",
    "outputPayload",
    "password",
    "prompt",
    "requestPayload",
    "responsePayload",
    "secret",
    "token",
)
REQUIREMENTS = (
    (
        "openshift-preflight",
        "orchestra.openshift.production-preflight.v2",
        (),
        1488,
        None,
    ),
    (
        "openshift-target-intake",
        "orchestra.openshift.production-target-intake.v2",
        ("openshift-preflight",),
        1488,
        None,
    ),
    (
        "openshift-deployment-observation",
        "orchestra.openshift.production-deployment-observation.v2",
        ("openshift-preflight", "openshift-target-intake"),
        1488,
        None,
    ),
    (
        "single-pod-recovery",
        "orchestra.openshift.single-pod-recovery.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "single-worker-drain",
        "orchestra.openshift.single-worker-drain.v2",
        ("single-pod-recovery",),
        1488,
        None,
    ),
    (
        "external-worker-outage",
        "orchestra.openshift.external-worker-outage-observation.v2",
        ("single-worker-drain",),
        1488,
        None,
    ),
    (
        "external-dependency-partition",
        "orchestra.openshift.external-dependency-partition.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "tenant-isolation",
        "orchestra.openshift.tenant-isolation.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "graceful-drain-overload",
        "orchestra.openshift.graceful-drain-overload.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "published-artifact-upgrade",
        "orchestra.openshift.published-artifact-upgrade.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "published-artifact-rollback",
        "orchestra.openshift.published-artifact-rollback.v2",
        ("published-artifact-upgrade",),
        1488,
        None,
    ),
    (
        "credential-certificate-rotation",
        "orchestra.openshift.credential-certificate-rotation.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "postgres-backup-restore",
        "orchestra.openshift.postgres-backup-restore.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "clickhouse-backup-restore",
        "orchestra.openshift.clickhouse-backup-restore.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "jetstream-backup-restore",
        "orchestra.openshift.jetstream-backup-restore.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "valkey-backup-restore",
        "orchestra.openshift.valkey-backup-restore.v2",
        ("openshift-deployment-observation",),
        1488,
        None,
    ),
    (
        "rpo-rto",
        "orchestra.openshift.rpo-rto.v2",
        (
            "external-worker-outage",
            "external-dependency-partition",
            "postgres-backup-restore",
            "clickhouse-backup-restore",
            "jetstream-backup-restore",
            "valkey-backup-restore",
        ),
        1488,
        None,
    ),
    (
        "availability-soak-30d",
        "orchestra.openshift.availability-soak.v2",
        (
            "openshift-preflight",
            "openshift-target-intake",
            "openshift-deployment-observation",
            "single-pod-recovery",
            "single-worker-drain",
            "external-worker-outage",
            "external-dependency-partition",
            "tenant-isolation",
            "graceful-drain-overload",
            "published-artifact-upgrade",
            "published-artifact-rollback",
            "credential-certificate-rotation",
            "postgres-backup-restore",
            "clickhouse-backup-restore",
            "jetstream-backup-restore",
            "valkey-backup-restore",
            "rpo-rto",
        ),
        24,
        43200,
    ),
)


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def parse_json_bytes(raw: bytes, code: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                fail(f"{code}_duplicate_key")
            value[key] = child
        return value

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{code}_json_invalid") from error
    if not isinstance(value, dict):
        fail(f"{code}_object_required")
    return value


def read_json(path: Path, code: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"{code}_read_failed") from error
    return raw, parse_json_bytes(raw, code)


def raw_digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def expected_policy() -> dict[str, Any]:
    required_evidence: list[dict[str, Any]] = []
    for slot, evidence_type, dependencies, max_age, minimum_duration in REQUIREMENTS:
        requirement = {
            "dependencies": list(dependencies),
            "evidenceType": evidence_type,
            "maxAgeHours": max_age,
            "slot": slot,
        }
        if minimum_duration is not None:
            requirement["minimumDurationMinutes"] = minimum_duration
        required_evidence.append(requirement)
    return {
        "acceptedExecutionModes": ["live"],
        "acceptedTargetClasses": ["vendor-reference-lab"],
        "claimType": "reference-profile-verification",
        "forbiddenEvidenceKeys": list(FORBIDDEN_EVIDENCE_KEYS),
        "kind": "orchestra.cross-plane.certification-policy.v2",
        "policyId": POLICY_ID,
        "profileId": PROFILE_ID,
        "requiredEvidence": required_evidence,
        "schemaVersion": 2,
        "validityDays": 30,
    }


def validate_policy(policy: dict[str, Any]) -> None:
    if policy != expected_policy():
        fail("reference_lab_contract_policy_semantics_invalid")
    seen: set[str] = set()
    for requirement in policy["requiredEvidence"]:
        if any(dependency not in seen for dependency in requirement["dependencies"]):
            fail("reference_lab_contract_policy_dependency_order_invalid")
        seen.add(requirement["slot"])


def strict_schema_objects(value: Any, path: str = "$") -> None:
    if isinstance(value, list):
        for index, child in enumerate(value):
            strict_schema_objects(child, f"{path}/{index}")
        return
    if not isinstance(value, dict):
        return
    if value.get("type") == "object" and value.get("additionalProperties") is not False:
        fail(f"reference_lab_contract_schema_not_strict:{path}")
    for key, child in value.items():
        strict_schema_objects(child, f"{path}/{key}")


def validate_schema_bundle(bundle: dict[str, Any], policy: dict[str, Any]) -> None:
    strict_keys(
        bundle,
        {"schemaVersion", "kind", "contracts"},
        "reference_lab_contract_schema_bundle_keys_invalid",
    )
    if (
        bundle["schemaVersion"] != 1
        or bundle["kind"] != "orchestra.reference-lab.schema-bundle.v1"
    ):
        fail("reference_lab_contract_schema_bundle_identity_invalid")
    contracts = strict_keys(
        bundle["contracts"],
        set(SCHEMA_CONTRACTS),
        "reference_lab_contract_schema_inventory_invalid",
    )
    strict_schema_objects(contracts)

    evidence = strict_keys(
        contracts["evidence"],
        {requirement["slot"] for requirement in policy["requiredEvidence"]},
        "reference_lab_contract_evidence_schema_inventory_invalid",
    )
    for requirement in policy["requiredEvidence"]:
        schema = strict_keys(
            evidence[requirement["slot"]],
            {"type", "additionalProperties", "properties", "required"},
            "reference_lab_contract_evidence_schema_invalid",
        )
        evidence_type = schema.get("properties", {}).get("evidenceType", {})
        if evidence_type.get("const") != requirement["evidenceType"]:
            fail("reference_lab_contract_evidence_type_drift")

    campaign = contracts["campaign"]
    campaign_properties = campaign.get("properties", {})
    if campaign_properties.get("targetClass", {}).get("enum") != [
        "fixture",
        "vendor-reference-lab",
        "customer-production",
    ] or campaign_properties.get("executionMode", {}).get("enum") != [
        "simulated",
        "live",
    ]:
        fail("reference_lab_contract_campaign_origin_schema_invalid")

    bom_properties = contracts["referenceProfileVerificationBom"].get("properties", {})
    claims = bom_properties.get("claims", {}).get("properties", {})
    if (
        claims.get("referenceProfileVerified", {}).get("const") is not True
        or claims.get("customerCertified", {}).get("const") is not False
        or claims.get("redHatCertified", {}).get("const") is not False
        or claims.get("contractualSla", {}).get("const") is not False
        or bom_properties.get("verificationStatus", {}).get("const")
        != "reference-profile-verified"
        or bom_properties.get("publicWording", {}).get("const")
        != "Orchestra reference profile verified on the documented OpenShift 4.20.27 GCP topology."
    ):
        fail("reference_lab_contract_bom_claim_schema_invalid")


def forbidden_key(value: Any, forbidden: set[str]) -> str | None:
    if isinstance(value, list):
        for child in value:
            found = forbidden_key(child, forbidden)
            if found is not None:
                return found
        return None
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in forbidden:
                return key.lower()
            found = forbidden_key(child, forbidden)
            if found is not None:
                return found
    return None


def validate_fixture_campaign(
    campaign: dict[str, Any],
    campaign_schema: dict[str, Any],
    policy: dict[str, Any],
    topology: dict[str, Any],
) -> None:
    properties = campaign_schema.get("properties")
    required = campaign_schema.get("required")
    if (
        not isinstance(properties, dict)
        or not isinstance(required, list)
        or set(campaign) != set(properties)
        or set(campaign) != set(required)
    ):
        fail("reference_lab_contract_fixture_shape_invalid")
    if (
        campaign.get("schemaVersion") != 2
        or campaign.get("kind") != "orchestra.certification-campaign.v2"
        or campaign.get("targetClass") != "fixture"
        or campaign.get("executionMode") != "simulated"
        or campaign.get("profile", {}).get("id") != PROFILE_ID
        or campaign.get("policy", {}).get("id") != POLICY_ID
        or campaign.get("cluster")
        != {
            "architecture": topology["openshift"]["architecture"],
            "identityDigest": f"sha256:{'c' * 64}",
            "version": topology["openshift"]["version"],
        }
    ):
        fail("reference_lab_contract_fixture_identity_invalid")
    fixture_topology = campaign.get("topology")
    if not isinstance(fixture_topology, dict) or (
        fixture_topology.get("region") != topology["location"]["region"]
        or fixture_topology.get("zones") != topology["location"]["zones"]
        or fixture_topology.get("dnsZone") != topology["location"]["dnsZone"]
        or fixture_topology.get("cni") != topology["openshift"]["cni"]
        or fixture_topology.get("controlPlane")
        != {
            "count": topology["openshift"]["controlPlane"]["count"],
            "machineType": topology["openshift"]["controlPlane"]["machineType"],
        }
        or fixture_topology.get("workers")
        != {
            "count": topology["openshift"]["workers"]["count"],
            "machineType": topology["openshift"]["workers"]["machineType"],
            "preemptible": topology["openshift"]["workers"]["preemptible"],
        }
    ):
        fail("reference_lab_contract_fixture_topology_invalid")
    if (
        campaign["targetClass"] in policy["acceptedTargetClasses"]
        or campaign["executionMode"] in policy["acceptedExecutionModes"]
        or not str(campaign.get("runner", {}).get("image", "")).startswith(
            "registry.example.invalid/"
        )
        or not str(campaign.get("releaseSet", {}).get("id", "")).startswith("fixture-")
        or any(
            dependency.get("version") != "fixture"
            for dependency in campaign.get("dependencies", {}).get("inventory", [])
        )
    ):
        fail("reference_lab_contract_fixture_live_boundary_invalid")
    forbidden = {key.lower() for key in policy["forbiddenEvidenceKeys"]}
    if forbidden_key(campaign, forbidden) is not None:
        fail("reference_lab_contract_fixture_forbidden_key")
    try:
        created_at = datetime.fromisoformat(
            campaign["createdAt"].replace("Z", "+00:00")
        )
        starts_at = datetime.fromisoformat(
            campaign["window"]["startsAt"].replace("Z", "+00:00")
        )
        ends_at = datetime.fromisoformat(
            campaign["window"]["endsAt"].replace("Z", "+00:00")
        )
    except (AttributeError, KeyError, ValueError) as error:
        raise ValueError("reference_lab_contract_fixture_time_invalid") from error
    if any(value.tzinfo is None for value in (created_at, starts_at, ends_at)) or not (
        created_at <= starts_at < ends_at
    ):
        fail("reference_lab_contract_fixture_time_invalid")


def safe_vendored_path(root: Path, relative: str) -> Path:
    if Path(relative).is_absolute():
        fail("reference_lab_contract_artifact_path_invalid")
    base = (root / "contracts" / "platform").resolve()
    candidate = (root / relative).resolve()
    if candidate == base or base not in candidate.parents:
        fail("reference_lab_contract_artifact_path_invalid")
    return candidate


def validate_contract_intake(
    intake: dict[str, Any],
    *,
    root: Path = ROOT,
) -> str:
    strict_keys(
        intake,
        {
            "schemaVersion",
            "kind",
            "source",
            "bindings",
            "artifacts",
            "semantics",
            "claim",
        },
        "reference_lab_contract_intake_keys_invalid",
    )
    if (
        intake["schemaVersion"] != 1
        or intake["kind"] != "orchestra.reference-lab.certification-contract-intake.v1"
    ):
        fail("reference_lab_contract_intake_identity_invalid")

    _, topology = read_json(root / "config" / "lab.lock.json", "topology")
    _, release_set = read_json(
        root / "config" / "cross-plane-release-set.lock.json", "release_set"
    )
    _, dependency_bom = read_json(
        root / "config" / "dependency-bom.lock.json", "dependency_bom"
    )
    release_set_digest = validate_release_set(release_set)
    dependency_bom_digest = validate_dependency_bom(dependency_bom, topology)
    topology_digest = canonical_digest(topology)
    platform = next(
        plane for plane in release_set["planes"] if plane["plane"] == "platform"
    )
    runner = release_set["certificationRunner"]

    source = strict_keys(
        intake["source"],
        {
            "ownerPlane",
            "repository",
            "revision",
            "release",
            "certificationRunnerImage",
            "toolchainDigest",
        },
        "reference_lab_contract_source_invalid",
    )
    expected_source = {
        "ownerPlane": "platform",
        "repository": platform["source"]["repository"],
        "revision": platform["source"]["revision"],
        "release": platform["release"],
        "certificationRunnerImage": runner["image"],
        "toolchainDigest": runner["toolchainDigest"],
    }
    if source != expected_source or not REVISION.fullmatch(source["revision"]):
        fail("reference_lab_contract_source_invalid")

    bindings = strict_keys(
        intake["bindings"],
        {
            "profileId",
            "platformProfileDigest",
            "topologyDigest",
            "releaseSetId",
            "releaseSetDigest",
            "dependencyBomId",
            "dependencyBomDigest",
        },
        "reference_lab_contract_bindings_invalid",
    )
    expected_bindings = {
        "profileId": topology["profileId"],
        "platformProfileDigest": release_set["profile"]["digest"],
        "topologyDigest": topology_digest,
        "releaseSetId": release_set["releaseSetId"],
        "releaseSetDigest": release_set_digest,
        "dependencyBomId": dependency_bom["bomId"],
        "dependencyBomDigest": dependency_bom_digest,
    }
    if bindings != expected_bindings:
        fail("reference_lab_contract_bindings_invalid")

    artifacts = intake["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_PATHS):
        fail("reference_lab_contract_artifact_inventory_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    parsed: dict[str, dict[str, Any]] = {}
    for raw_artifact in artifacts:
        artifact = strict_keys(
            raw_artifact,
            {
                "id",
                "sourcePath",
                "vendoredPath",
                "rawDigest",
                "canonicalDigest",
            },
            "reference_lab_contract_artifact_invalid",
        )
        artifact_id = artifact.get("id")
        if not isinstance(artifact_id, str) or artifact_id in by_id:
            fail("reference_lab_contract_artifact_inventory_invalid")
        expected_paths = ARTIFACT_PATHS.get(artifact_id)
        if (
            expected_paths is None
            or (artifact["sourcePath"], artifact["vendoredPath"]) != expected_paths
            or not DIGEST.fullmatch(str(artifact["rawDigest"]))
            or not DIGEST.fullmatch(str(artifact["canonicalDigest"]))
        ):
            fail("reference_lab_contract_artifact_invalid")
        vendored_path = safe_vendored_path(root, artifact["vendoredPath"])
        artifact_bytes, artifact_value = read_json(
            vendored_path, f"reference_lab_contract_artifact_{artifact_id}"
        )
        if (
            raw_digest(artifact_bytes) != artifact["rawDigest"]
            or canonical_digest(artifact_value) != artifact["canonicalDigest"]
            or artifact_bytes != canonical_bytes(artifact_value)
        ):
            fail(f"reference_lab_contract_artifact_digest_invalid:{artifact_id}")
        by_id[artifact_id] = artifact
        parsed[artifact_id] = artifact_value
    if set(by_id) != set(ARTIFACT_PATHS):
        fail("reference_lab_contract_artifact_inventory_invalid")

    semantics = strict_keys(
        intake["semantics"],
        {
            "policyId",
            "acceptedTargetClasses",
            "acceptedExecutionModes",
            "evidenceSlots",
            "schemaContracts",
            "fixtureVector",
        },
        "reference_lab_contract_semantics_invalid",
    )
    expected_semantics = {
        "policyId": POLICY_ID,
        "acceptedTargetClasses": ["vendor-reference-lab"],
        "acceptedExecutionModes": ["live"],
        "evidenceSlots": [requirement[0] for requirement in REQUIREMENTS],
        "schemaContracts": list(SCHEMA_CONTRACTS),
        "fixtureVector": {
            "targetClass": "fixture",
            "executionMode": "simulated",
            "acceptedByLivePolicy": False,
        },
    }
    if semantics != expected_semantics:
        fail("reference_lab_contract_semantics_invalid")
    if intake["claim"] != {
        "contractSourceOnly": True,
        "liveCampaignStarted": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }:
        fail("reference_lab_contract_claim_invalid")

    policy = parsed["certification-policy"]
    schema_bundle = parsed["contract-schema-bundle"]
    fixture = parsed["fixture-campaign"]
    validate_policy(policy)
    validate_schema_bundle(schema_bundle, policy)
    validate_fixture_campaign(
        fixture,
        schema_bundle["contracts"]["campaign"],
        policy,
        topology,
    )
    digest = canonical_digest(intake)
    if root.resolve() == ROOT.resolve() and digest != EXPECTED_INTAKE_DIGEST:
        fail(f"reference_lab_contract_intake_digest_changed:{digest}")
    return digest


def verify_upstream_bytes(
    repository: Path,
    revision: str,
    artifacts: list[dict[str, Any]],
    *,
    root: Path = ROOT,
) -> None:
    if not repository.is_dir() or not REVISION.fullmatch(revision):
        fail("reference_lab_contract_upstream_repository_invalid")
    try:
        subprocess.run(
            ["git", "-C", str(repository), "cat-file", "-e", f"{revision}^{{commit}}"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        for artifact in artifacts:
            source_bytes = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "show",
                    f"{revision}:{artifact['sourcePath']}",
                ],
                check=True,
                capture_output=True,
                timeout=30,
            ).stdout
            vendored = safe_vendored_path(root, artifact["vendoredPath"]).read_bytes()
            if (
                source_bytes != vendored
                or raw_digest(source_bytes) != artifact["rawDigest"]
            ):
                fail(f"reference_lab_contract_upstream_bytes_mismatch:{artifact['id']}")
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("reference_lab_contract_upstream_read_failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform-repository", type=Path)
    args = parser.parse_args(argv)
    _, intake = read_json(INTAKE_PATH, "reference_lab_contract_intake")
    digest = validate_contract_intake(intake)
    upstream_verified = False
    if args.platform_repository is not None:
        verify_upstream_bytes(
            args.platform_repository.resolve(),
            intake["source"]["revision"],
            intake["artifacts"],
        )
        upstream_verified = True
    print(
        "reference_lab_contract_intake_valid "
        f"digest={digest} artifacts={len(intake['artifacts'])} "
        f"slots={len(REQUIREMENTS)} upstreamBytesVerified={str(upstream_verified).lower()} "
        "liveCampaignStarted=false campaignEvidence=false referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
