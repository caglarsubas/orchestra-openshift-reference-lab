#!/usr/bin/env python3
"""Validate the isolated, non-certifying OpenShift SNO trial profile."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
TRIAL_PROFILE = ROOT / "config" / "sno-trial.lock.json"
BILLING_EXECUTION_LOCK = (
    ROOT / "config" / "sno-trial-billing-execution.lock.json"
)
PRODUCTION_PROFILE = ROOT / "config" / "lab.lock.json"
TRIAL_PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
PRODUCTION_PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
ALLOWED_TRIAL_CONFIG_NAMES = {
    "sno-trial.lock.json",
    "sno-trial-billing-execution.lock.json",
    "sno-trial-cost-rate-card.lock.json",
    "sno-trial-openshift-toolchain.lock.json",
    "sno-trial-product-artifact-admission-policy.lock.json",
    "sno-trial-product-artifacts.lock.json",
    "sno-trial-workload-candidate.lock.json",
}
EXPECTED_PRODUCTION_DIGEST = (
    "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0"
)
EXPECTED_TRIAL_DIGEST = (
    "sha256:9a7dbdac36417b10ce15b74de4558502fc09cf1740153c5817b89df4c0ba738a"
)
EXPECTED_BILLING_EXECUTION_DIGEST = (
    "sha256:c36e8d30ac3f397d5ab0aabe562a2bb8ecece2e54dd4046ba4f22c24fea0a279"
)
PROTECTED_PRODUCTION_PATHS = (
    ROOT / ".github" / "workflows",
    ROOT / "contracts",
    ROOT / "policies",
    ROOT / "gitops" / "clusters" / "reference-lab",
    ROOT / "gitops" / "dependencies" / "reference-lab",
    ROOT / "gitops" / "products" / "reference-lab",
)


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"trial_json_invalid:{error}")
    if not isinstance(value, dict):
        fail("trial_json_object_required")
    return value


def canonical_digest(value: Any) -> str:
    encoded = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def validate_profile(
    value: dict[str, Any], production: dict[str, Any]
) -> None:
    if set(value) != {
        "schemaVersion",
        "profileId",
        "purpose",
        "targetClass",
        "executionMode",
        "certificationEligible",
        "claim",
        "location",
        "projects",
        "openshift",
        "dependencyPlane",
        "access",
        "storage",
        "guardrails",
        "evidence",
        "deploymentAuthority",
    }:
        fail("trial_profile_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != TRIAL_PROFILE_ID
        or value["purpose"] != "cost-bounded-live-engineering-trial"
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "live"
        or value["certificationEligible"] is not False
    ):
        fail("trial_profile_identity_invalid")
    if production.get("profileId") != PRODUCTION_PROFILE_ID:
        fail("production_profile_identity_changed")
    if canonical_digest(production) != EXPECTED_PRODUCTION_DIGEST:
        fail("production_profile_digest_changed")
    if value["profileId"] == production["profileId"]:
        fail("trial_profile_not_isolated")

    if value["claim"] != {
        "campaignEvidence": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
        "productionSupported": False,
        "highAvailability": False,
        "rpoRtoVerified": False,
    }:
        fail("trial_claim_invalid")
    if value["location"] != {
        "cloud": "gcp",
        "region": "europe-west1",
        "zones": ["europe-west1-b"],
        "dnsZone": "ocp-lab.planeon.ai",
    }:
        fail("trial_location_invalid")
    if value["projects"] != {
        "count": 1,
        "role": "trial",
        "mustBeEphemeral": True,
    }:
        fail("trial_projects_invalid")
    if value["openshift"] != {
        "distribution": "OpenShift Container Platform",
        "version": "4.20.27",
        "architecture": "linux/amd64",
        "installation": "installer-provisioned-single-node",
        "publish": "External",
        "cni": "OVN-Kubernetes",
        "controlPlane": {
            "count": 1,
            "machineType": "n2-standard-8",
            "diskType": "pd-balanced",
            "diskSizeGB": 150,
        },
        "workers": {"count": 0},
    }:
        fail("trial_openshift_invalid")

    dependency = value["dependencyPlane"]
    expected_dependencies = [
        {"kind": "postgresql", "instances": 1},
        {"kind": "clickhouse", "instances": 1},
        {"kind": "jetstream", "instances": 1},
        {"kind": "valkey", "instances": 1},
        {"kind": "model-backend", "instances": 1},
        {"kind": "synthetic-mcp", "mode": "read-only"},
    ]
    if (
        not isinstance(dependency, dict)
        or set(dependency)
        != {"platform", "mode", "nodeCount", "dependencies", "deferred"}
        or dependency["platform"] != "openshift-sno"
        or dependency["mode"] != "co-located-single-replica"
        or dependency["nodeCount"] != 0
        or dependency["dependencies"] != expected_dependencies
        or dependency["deferred"]
        != [
            "external-ha-postgresql",
            "clickhouse-keeper",
            "valkey-sentinel",
            "vault",
            "harbor",
            "keycloak",
            "thanos",
            "external-probes",
        ]
    ):
        fail("trial_dependency_plane_invalid")
    if value["access"] != {
        "api": "external-ip-allowlisted",
        "routes": "external",
        "administration": "short-lived-ip-allowlisted",
        "publicAdministrativeEndpoints": True,
        "allowedSourceCidrsRequired": True,
    }:
        fail("trial_access_invalid")
    if value["storage"] != {
        "applicationDiskType": "pd-balanced",
        "volumeBindingMode": "WaitForFirstConsumer",
        "allowExpansion": True,
        "encryptedAtRest": True,
    }:
        fail("trial_storage_invalid")
    if value["guardrails"] != {
        "budget": {
            "monthlyUsd": 75,
            "alertPercentages": [10, 25, 50, 75, 90, 100],
            "budgetIsHardCap": False,
            "maxActiveHoursPerMonth": 48,
        },
        "lease": {
            "requiredBeforeRender": True,
            "maximumHours": 12,
            "renewalRequiresOperatorAction": True,
            "expiredLeaseBlocksRender": True,
        },
        "teardown": {
            "required": True,
            "automaticProviderTeardown": False,
            "deleteClusterBeforeProject": True,
        },
    }:
        fail("trial_guardrails_invalid")
    if value["evidence"] != {
        "targetClass": "engineering-trial",
        "campaignEligible": False,
        "allowedCertificationSlots": [],
        "signedRetentionLocked": False,
        "retentionDays": 7,
        "cmekRequired": False,
        "externalProbeRunners": 0,
    }:
        fail("trial_evidence_invalid")
    if value["deploymentAuthority"] != {
        "owner": "trial-operator",
        "orchestraHasCredentials": False,
        "orchestraMayRecommend": False,
    }:
        fail("trial_deployment_authority_invalid")
    if canonical_digest(value) != EXPECTED_TRIAL_DIGEST:
        fail("trial_profile_digest_changed")


def validate_billing_execution(
    value: dict[str, Any], profile: dict[str, Any]
) -> None:
    expected = {
        "schemaVersion": 1,
        "kind": "orchestra.openshift.sno-trial-billing-execution.v1",
        "profileId": TRIAL_PROFILE_ID,
        "profileDigest": EXPECTED_TRIAL_DIGEST,
        "monthlyUsdCeiling": 75,
        "billingCurrencyCode": "TRY",
        "billingAmountUnits": 3500,
        "conversionRateTryPerUsd": "47.2497",
        "conversionRateDate": "2026-07-24",
        "conversionRateSource": "TCMB ForexSelling",
        "equivalentUsdAtLockedRate": "74.08",
        "budgetIsHardCap": False,
    }
    if value != expected:
        fail("trial_billing_execution_invalid")
    if (
        value["profileId"] != profile["profileId"]
        or value["profileDigest"] != canonical_digest(profile)
        or value["monthlyUsdCeiling"]
        != profile["guardrails"]["budget"]["monthlyUsd"]
        or value["budgetIsHardCap"]
        != profile["guardrails"]["budget"]["budgetIsHardCap"]
    ):
        fail("trial_billing_execution_profile_binding_invalid")
    if canonical_digest(value) != EXPECTED_BILLING_EXECUTION_DIGEST:
        fail("trial_billing_execution_digest_changed")


def validate_production_isolation(root: Path = ROOT) -> None:
    for protected in PROTECTED_PRODUCTION_PATHS:
        if not protected.exists():
            continue
        for path in protected.rglob("*"):
            if path.is_file() and TRIAL_PROFILE_ID in path.read_text(
                encoding="utf-8", errors="ignore"
            ):
                fail(f"trial_profile_referenced_by_production_path:{path.relative_to(root)}")
    for path in (root / "config").glob("*.json"):
        if path.name in ALLOWED_TRIAL_CONFIG_NAMES:
            continue
        if TRIAL_PROFILE_ID in path.read_text(encoding="utf-8", errors="ignore"):
            fail(f"trial_profile_referenced_by_production_config:{path.name}")


def main() -> int:
    trial = load_json(TRIAL_PROFILE)
    billing_execution = load_json(BILLING_EXECUTION_LOCK)
    production = load_json(PRODUCTION_PROFILE)
    validate_profile(trial, production)
    validate_billing_execution(billing_execution, trial)
    validate_production_isolation()
    print(
        "sno_trial_profile_valid "
        f"profileDigest={canonical_digest(trial)} "
        f"billingExecutionDigest={canonical_digest(billing_execution)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
