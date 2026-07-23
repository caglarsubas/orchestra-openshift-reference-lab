#!/usr/bin/env python3
"""Fail-closed validation for topology, prerequisites, and repository safety."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
ACTION_PIN = re.compile(r"^\s*-?\s*uses:\s*[^@\s]+@[a-f0-9]{40}(?:\s+#.*)?$")
EXPECTED_TOPOLOGY_DIGEST = (
    "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0"
)
MAX_PREREQUISITE_AGE = timedelta(days=30)
EXPECTED_GATES = {
    "redHatEntitlement",
    "openshiftPullSecret",
    "openshiftInstaller",
    "gcpBillingAndQuotas",
    "targetProject",
    "servicesEvidenceProject",
    "dnsDelegation",
    "shortLivedIdentityFederation",
    "certificationRunner",
    "crossPlaneReleaseSet",
}
PREREQUISITE_STAGE_GATES = {
    "bootstrap": {
        "redHatEntitlement",
        "openshiftPullSecret",
        "openshiftInstaller",
        "certificationRunner",
        "crossPlaneReleaseSet",
    },
    "foundation": EXPECTED_GATES - {"dnsDelegation"},
    "openshift-install": EXPECTED_GATES,
    "all": EXPECTED_GATES,
}
EXPECTED_RECEIVER_BLOCKERS = [
    "published-signed-image",
    "mirror-admission",
    "external-postgresql",
    "vault-external-secrets",
    "github-app-installation",
    "live-campaign",
]
EXPECTED_SYNTHETIC_BLOCKERS = [
    "published-signed-image",
    "mirror-admission",
    "vault-external-secrets",
    "keycloak-identity",
    "runtime-host-tls",
    "lab-pki",
    "live-campaign",
]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"json_invalid:{path.relative_to(ROOT)}:{error}")
    if not isinstance(value, dict):
        fail(f"json_object_required:{path.relative_to(ROOT)}")
    return value


def canonical_digest(value: Any) -> str:
    # Match prometa-platform's cross-plane canonical JSON exactly.
    encoded = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def validate_lock(value: dict[str, Any]) -> None:
    if set(value) != {
        "schemaVersion",
        "profileId",
        "claim",
        "location",
        "projects",
        "openshift",
        "dependencyPlane",
        "access",
        "storage",
        "evidence",
        "availability",
        "deploymentAuthority",
    }:
        fail("lab_lock_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != "orchestra-ocp-4.20-amd64-v1"
    ):
        fail("lab_lock_identity_invalid")
    if value["claim"] != {
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }:
        fail("lab_lock_claim_invalid")
    location = value["location"]
    if location != {
        "cloud": "gcp",
        "region": "europe-west1",
        "zones": ["europe-west1-b", "europe-west1-c", "europe-west1-d"],
        "dnsZone": "ocp-lab.prometa.ai",
    }:
        fail("lab_lock_location_invalid")
    openshift = value["openshift"]
    if (
        openshift.get("version") != "4.20.27"
        or openshift.get("architecture") != "linux/amd64"
        or openshift.get("publish") != "Internal"
        or openshift.get("cni") != "OVN-Kubernetes"
        or openshift.get("controlPlane")
        != {
            "count": 3,
            "machineType": "n2-standard-4",
            "diskType": "pd-ssd",
            "diskSizeGB": 256,
        }
        or openshift.get("workers")
        != {
            "count": 3,
            "machineType": "n2-standard-8",
            "diskType": "pd-ssd",
            "diskSizeGB": 256,
            "preemptible": False,
        }
    ):
        fail("lab_lock_openshift_invalid")
    dependency = value["dependencyPlane"]
    if (
        dependency.get("platform") != "gke"
        or dependency.get("mode") != "private-regional"
        or dependency.get("nodeCount") != 3
        or dependency.get("machineType") != "n2-standard-8"
        or dependency.get("preemptible") is not False
    ):
        fail("lab_lock_dependency_plane_invalid")
    evidence = value["evidence"]
    availability = value["availability"]
    if evidence != {
        "signedRetentionDays": 400,
        "signedRetentionLocked": True,
        "rawRetentionDays": 90,
        "cmekRequired": True,
        "externalProbeRunners": 2,
        "probeRunnerZonesMustDiffer": True,
    }:
        fail("lab_lock_evidence_invalid")
    if availability != {
        "soakMinutes": 43200,
        "minimumPerJourneyPercent": 99.9,
        "maximumDowntimeMinutes": 43.2,
        "maximumProbeGapMinutes": 5,
        "rpoMinutes": 15,
        "rtoMinutes": 60,
    }:
        fail("lab_lock_availability_invalid")
    authority = value["deploymentAuthority"]
    if authority != {
        "owner": "openshift-gitops",
        "orchestraHasCredentials": False,
        "orchestraMayRecommend": True,
    }:
        fail("lab_lock_deployment_authority_invalid")
    if canonical_digest(value) != EXPECTED_TOPOLOGY_DIGEST:
        fail("lab_lock_digest_changed")


def validate_prerequisites(
    value: dict[str, Any],
    require_ready: bool,
    now: datetime | None = None,
    readiness_stage: str = "all",
) -> None:
    assessed_at = now or datetime.now(timezone.utc)
    if readiness_stage not in PREREQUISITE_STAGE_GATES:
        fail("prerequisite_readiness_stage_invalid")
    required_gates = PREREQUISITE_STAGE_GATES[readiness_stage]
    if set(value) != {
        "schemaVersion",
        "profileId",
        "targetClass",
        "executionMode",
        "gates",
    }:
        fail("prerequisites_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != "orchestra-ocp-4.20-amd64-v1"
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
    ):
        fail("prerequisites_identity_invalid")
    gates = value["gates"]
    if not isinstance(gates, dict) or set(gates) != EXPECTED_GATES:
        fail("prerequisites_gates_invalid")
    for name, gate in gates.items():
        if not isinstance(gate, dict) or set(gate) != {
            "status",
            "evidenceDigest",
            "verifiedAt",
            "verifiedByIdentityDigest",
        }:
            fail(f"prerequisite_gate_shape_invalid:{name}")
        if gate["status"] not in {"missing", "verified"}:
            fail(f"prerequisite_gate_status_invalid:{name}")
        fields = (
            gate["evidenceDigest"],
            gate["verifiedAt"],
            gate["verifiedByIdentityDigest"],
        )
        if gate["status"] == "missing":
            if any(field is not None for field in fields):
                fail(f"prerequisite_missing_gate_has_evidence:{name}")
            if require_ready and name in required_gates:
                fail(f"prerequisite_gate_missing:{name}")
            continue
        if not DIGEST.fullmatch(str(gate["evidenceDigest"])) or not DIGEST.fullmatch(
            str(gate["verifiedByIdentityDigest"])
        ):
            fail(f"prerequisite_gate_digest_invalid:{name}")
        try:
            verified_at = datetime.fromisoformat(
                str(gate["verifiedAt"]).replace("Z", "+00:00")
            )
        except ValueError:
            fail(f"prerequisite_gate_time_invalid:{name}")
        if (
            verified_at.tzinfo is None
            or verified_at > assessed_at
            or assessed_at - verified_at > MAX_PREREQUISITE_AGE
        ):
            fail(f"prerequisite_gate_time_invalid:{name}")
    if all(gates[name]["status"] == "verified" for name in required_gates):
        verifier_identities = {
            gates[name]["verifiedByIdentityDigest"] for name in required_gates
        }
        if len(verifier_identities) < 2:
            fail("prerequisite_verifiers_not_independent")
        if {"targetProject", "servicesEvidenceProject"}.issubset(required_gates) and (
            gates["targetProject"]["evidenceDigest"]
            == gates["servicesEvidenceProject"]["evidenceDigest"]
        ):
            fail("prerequisite_projects_not_distinct")


def validate_lab_services(value: dict[str, Any]) -> None:
    if set(value) != {"schemaVersion", "services"} or value["schemaVersion"] != 1:
        fail("lab_services_shape_invalid")
    services = value["services"]
    if not isinstance(services, list) or len(services) != 2:
        fail("lab_services_inventory_invalid")
    expected = [
        {
            "id": "release-validation-receiver",
            "owner": "tenant-ci-cd-or-gitops",
            "sourcePath": "services/release-validation-receiver",
            "activation": "source-only",
            "release": None,
            "image": None,
            "gitOpsReferenced": False,
            "deploymentAuthority": "openshift-gitops",
            "platformHasDeploymentCredentials": False,
            "blockedOn": EXPECTED_RECEIVER_BLOCKERS,
        },
        {
            "id": "synthetic-tenant-kit",
            "owner": "reference-lab-operator",
            "sourcePath": "services/synthetic-tenant-kit",
            "activation": "source-only",
            "release": None,
            "image": None,
            "gitOpsReferenced": False,
            "deploymentAuthority": "openshift-gitops",
            "platformHasDeploymentCredentials": False,
            "blockedOn": EXPECTED_SYNTHETIC_BLOCKERS,
        },
    ]
    required_keys = set(expected[0])
    if any(
        not isinstance(service, dict) or set(service) != required_keys
        for service in services
    ):
        fail("lab_service_shape_invalid")
    if services != expected:
        fail("lab_service_activation_invalid")
    for service in services:
        if not (ROOT / service["sourcePath"] / "Containerfile").is_file():
            fail("lab_service_source_missing")
        for directory in (
            ROOT / "gitops" / "clusters",
            ROOT / "gitops" / "dependencies",
            ROOT / "gitops" / "products",
        ):
            for path in directory.rglob("*"):
                if path.is_file() and service["id"] in path.read_text(encoding="utf-8"):
                    fail(
                        "lab_service_unpublished_gitops_reference:"
                        f"{path.relative_to(ROOT)}"
                    )


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / line for line in result.stdout.splitlines() if line]


def validate_repository_safety(policy: dict[str, Any]) -> None:
    forbidden_names = set(policy["forbiddenTrackedNames"])
    forbidden_suffixes = tuple(policy["forbiddenTrackedSuffixes"])
    patterns = [re.compile(item) for item in policy["forbiddenContentPatterns"]]
    allowed_placeholders = set(policy["allowedSecretPlaceholders"])
    for path in tracked_files():
        relative = path.relative_to(ROOT)
        if path.name in forbidden_names or str(relative).endswith(forbidden_suffixes):
            fail(f"forbidden_tracked_file:{relative}")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if relative == Path("policies/repository-policy.json"):
            continue
        scrubbed = content
        for placeholder in allowed_placeholders:
            scrubbed = scrubbed.replace(placeholder, "")
        for pattern in patterns:
            if pattern.search(scrubbed):
                fail(f"forbidden_content:{relative}")


def validate_workflow_pins() -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if "uses:" in line and not ACTION_PIN.match(line):
                fail(f"workflow_action_not_pinned:{workflow.name}:{line_number}")


def validate_foundation_plan_workflow() -> None:
    path = ROOT / ".github" / "workflows" / "foundation-plan.yml"
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"foundation_plan_workflow_missing:{error}")
    required = (
        "workflow_dispatch:",
        "expected_main_sha:",
        "actions: read",
        "id-token: write",
        "if: github.ref == 'refs/heads/main'",
        "environment: reference-lab-foundation-plan",
        "persist-credentials: false",
        "FOUNDATION_PLAN_REVIEW_GATE_CONFIGURED",
        "GCP_FOUNDATION_PLAN_SERVICE_ACCOUNT",
        "GCP_FOUNDATION_PLAN_PACKAGER_SERVICE_ACCOUNT",
        "plan_kms_key_version:",
        "expected_plan_public_key_digest:",
        "github_environment_contract.py verify",
        "github-token",
        '--workflow-run-id "$GITHUB_RUN_ID"',
        '--workflow-run-attempt "$GITHUB_RUN_ATTEMPT"',
        '--workflow-actor-id "$GITHUB_ACTOR_ID"',
        "--readiness-stage foundation",
        "-lock=false",
        "--execution-mode live",
        "foundation-plan.log",
        "foundation-plan-summary.json",
        "publish_foundation_plan_package.sh",
        "ENVIRONMENT_APPROVAL_DIGEST",
    )
    if any(fragment not in content for fragment in required):
        fail("foundation_plan_workflow_contract_invalid")
    forbidden = (
        "terraform apply",
        "-lock=true",
        "GCP_FOUNDATION_SERVICE_ACCOUNT",
        "path: ${{ runner.temp }}/foundation.tfplan",
        "path: ${{ runner.temp }}/foundation-plan.json",
    )
    if any(fragment in content for fragment in forbidden):
        fail("foundation_plan_workflow_authority_invalid")


def validate_dependency_risk_preflight_workflow() -> None:
    try:
        from scripts.dependency_risk_execution import (
            load_contract,
            validate_authority,
            validate_declared_implementation,
        )
    except ModuleNotFoundError:
        from dependency_risk_execution import (
            load_contract,
            validate_authority,
            validate_declared_implementation,
        )

    authority, release_set, risk_policy = load_contract()
    validate_authority(authority, release_set, risk_policy)
    validate_declared_implementation()


def validate_foundation_apply_workflow() -> None:
    try:
        from scripts.foundation_apply_execution import (
            load_contract,
            validate_authority,
            validate_declared_implementation,
        )
    except ModuleNotFoundError:
        from foundation_apply_execution import (
            load_contract,
            validate_authority,
            validate_declared_implementation,
        )

    authority, release_set, policy = load_contract()
    validate_authority(authority, release_set, policy)
    validate_declared_implementation()


def validate_dependency_risk_collection_workflow() -> None:
    try:
        from scripts.dependency_risk_collection_execution import (
            load_contract,
            validate_authority,
            validate_declared_implementation,
        )
    except ModuleNotFoundError:
        from dependency_risk_collection_execution import (
            load_contract,
            validate_authority,
            validate_declared_implementation,
        )

    authority, release_set, risk_policy = load_contract()
    validate_authority(authority, release_set, risk_policy)
    validate_declared_implementation()


def validate_dependency_risk_custody_verification_workflow() -> None:
    try:
        from scripts.dependency_risk_custody_verification import (
            load_contract,
            validate_authority,
            validate_declared_implementation,
        )
    except ModuleNotFoundError:
        from dependency_risk_custody_verification import (
            load_contract,
            validate_authority,
            validate_declared_implementation,
        )

    authority, release_set, risk_policy = load_contract()
    validate_authority(authority, release_set, risk_policy)
    validate_declared_implementation()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prerequisites", type=Path)
    parser.add_argument("--require-ready", action="store_true")
    parser.add_argument(
        "--readiness-stage",
        choices=tuple(PREREQUISITE_STAGE_GATES),
        default="all",
    )
    args = parser.parse_args(argv)
    if args.require_ready and args.prerequisites is None:
        fail("prerequisites_required_for_ready_check")

    lock = load_json(ROOT / "config" / "lab.lock.json")
    services = load_json(ROOT / "config" / "lab-services.lock.json")
    policy = load_json(ROOT / "policies" / "repository-policy.json")
    validate_lock(lock)
    validate_lab_services(services)
    if policy.get("requiredClaim") != lock["claim"]:
        fail("repository_policy_claim_mismatch")
    validate_repository_safety(policy)
    validate_workflow_pins()
    validate_foundation_plan_workflow()
    validate_foundation_apply_workflow()
    validate_dependency_risk_preflight_workflow()
    validate_dependency_risk_collection_workflow()
    validate_dependency_risk_custody_verification_workflow()
    validate_prerequisites(
        load_json(args.prerequisites.resolve())
        if args.prerequisites
        else load_json(ROOT / "config" / "prerequisites.example.json"),
        args.require_ready,
        readiness_stage=args.readiness_stage,
    )
    print(f"repository_valid topologyDigest={canonical_digest(lock)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
