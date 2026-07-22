#!/usr/bin/env python3
"""Strict contracts for payload-free prerequisite observations."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, NoReturn

try:
    from scripts.validate_release_set import validate_release_set
    from scripts.validate_repository import DIGEST, ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_release_set import validate_release_set
    from validate_repository import DIGEST, ROOT, canonical_digest, load_json


POLICY_PATH = ROOT / "config" / "prerequisite-observation-policy.lock.json"
RELEASE_SET_PATH = ROOT / "config" / "cross-plane-release-set.lock.json"
COLLECTOR_PATH = ROOT / "scripts" / "collect_prerequisite_observation.py"
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
TOPOLOGY_DIGEST = (
    "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0"
)
EXPECTED_POLICY_DIGEST = (
    "sha256:c04c6038eba4facf57e2b6c7095be7a2e6fbfb9057695af4f6e05998ebfadafe"
)
OBSERVATION_ID = re.compile(r"^orchestra-prerequisite-observation-[a-z0-9][a-z0-9.-]+$")
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]+$")
GATE_ORDER = (
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
)
STAGE_GATES = {
    "bootstrap": (
        "redHatEntitlement",
        "openshiftPullSecret",
        "openshiftInstaller",
        "certificationRunner",
        "crossPlaneReleaseSet",
    ),
    "foundation": (
        "redHatEntitlement",
        "openshiftPullSecret",
        "openshiftInstaller",
        "gcpBillingAndQuotas",
        "targetProject",
        "servicesEvidenceProject",
        "shortLivedIdentityFederation",
        "certificationRunner",
        "crossPlaneReleaseSet",
    ),
    "openshift-install": GATE_ORDER,
    "all": GATE_ORDER,
}
GATE_CHECKS = {
    "redHatEntitlement": ("active-entitlement",),
    "openshiftPullSecret": ("required-registry-auths",),
    "openshiftInstaller": ("exact-installer",),
    "gcpBillingAndQuotas": ("billing-and-capacity",),
    "targetProject": ("dedicated-target-project",),
    "servicesEvidenceProject": ("dedicated-services-project",),
    "dnsDelegation": ("exact-public-delegation",),
    "shortLivedIdentityFederation": (
        "github-environment-protection",
        "restricted-wif-no-user-keys",
    ),
    "certificationRunner": ("signed-runner-provenance",),
    "crossPlaneReleaseSet": ("locked-release-set",),
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(code)
    return value


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None:
        fail(code)
    return parsed


def blob_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def payload_digest(value: Any) -> str:
    return blob_digest(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    )


def load_contract() -> tuple[dict[str, Any], dict[str, Any]]:
    return load_json(POLICY_PATH), load_json(RELEASE_SET_PATH)


def validate_policy(value: dict[str, Any], release_set: dict[str, Any]) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "profileId",
            "bindings",
            "observationPolicy",
            "runner",
            "stages",
            "gates",
            "gcp",
            "dns",
            "claim",
        },
        "prerequisite_observation_policy_keys_invalid",
    )
    release_set_digest = validate_release_set(release_set)
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "orchestra.reference-lab.prerequisite-observation-policy.v1"
        or value["policyId"] != "orchestra-reference-lab-prerequisite-observation-v1"
        or value["profileId"] != PROFILE_ID
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "releaseSetDigest": release_set_digest,
        }
    ):
        fail("prerequisite_observation_policy_identity_invalid")

    observation_policy = strict_keys(
        value["observationPolicy"],
        {
            "maximumAgeHours",
            "maximumCollectionMinutes",
            "liveExecutionClass",
            "diagnosticExecutionClass",
            "rawProviderOutputStored",
            "secretValuesStored",
            "collectorMayVerifyGates",
            "observationMayAuthorizeProvisioning",
        },
        "prerequisite_observation_policy_collection_invalid",
    )
    if observation_policy != {
        "maximumAgeHours": 24,
        "maximumCollectionMinutes": 30,
        "liveExecutionClass": "signed-certification-runner",
        "diagnosticExecutionClass": "developer-diagnostic",
        "rawProviderOutputStored": False,
        "secretValuesStored": False,
        "collectorMayVerifyGates": False,
        "observationMayAuthorizeProvisioning": False,
    }:
        fail("prerequisite_observation_policy_collection_invalid")

    runner = release_set["certificationRunner"]
    if value["runner"] != {
        "release": runner["release"],
        "repository": runner["source"]["repository"],
        "revision": runner["source"]["revision"],
        "image": runner["image"],
        "imageDigest": runner["image"].rsplit("@", 1)[1],
        "toolchainDigest": runner["toolchainDigest"],
    }:
        fail("prerequisite_observation_policy_runner_invalid")
    if value["stages"] != {name: list(gates) for name, gates in STAGE_GATES.items()}:
        fail("prerequisite_observation_policy_stages_invalid")

    gates = strict_keys(
        value["gates"], set(GATE_ORDER), "prerequisite_observation_policy_gates_invalid"
    )
    for name in GATE_ORDER:
        gate = strict_keys(
            gates[name],
            {
                "stage",
                "evidenceClass",
                "requiredChecks",
                "independentReviewRequired",
            },
            f"prerequisite_observation_policy_gate_invalid:{name}",
        )
        if (
            gate["stage"] not in {"bootstrap", "foundation", "openshift-install"}
            or not isinstance(gate["evidenceClass"], str)
            or not gate["evidenceClass"]
            or gate["requiredChecks"] != list(GATE_CHECKS[name])
            or gate["independentReviewRequired"] is not True
        ):
            fail(f"prerequisite_observation_policy_gate_invalid:{name}")

    gcp = strict_keys(
        value["gcp"],
        {
            "region",
            "targetLabels",
            "servicesLabels",
            "targetRequiredApis",
            "servicesRequiredApis",
            "quotaMinimumAvailable",
            "wif",
        },
        "prerequisite_observation_policy_gcp_invalid",
    )
    if (
        gcp["region"] != "europe-west1"
        or gcp["targetLabels"]
        != {
            "environment": "reference-lab",
            "plane": "target",
            "managed_by": "terraform",
        }
        or gcp["servicesLabels"]
        != {
            "environment": "reference-lab",
            "plane": "services-evidence",
            "managed_by": "terraform",
        }
    ):
        fail("prerequisite_observation_policy_gcp_invalid")
    for api_key in ("targetRequiredApis", "servicesRequiredApis"):
        apis = gcp[api_key]
        if (
            not isinstance(apis, list)
            or not apis
            or apis != sorted(set(apis))
            or not all(
                isinstance(item, str) and item.endswith(".googleapis.com")
                for item in apis
            )
        ):
            fail("prerequisite_observation_policy_gcp_apis_invalid")
    quotas = strict_keys(
        gcp["quotaMinimumAvailable"],
        {"target", "services"},
        "prerequisite_observation_policy_gcp_quotas_invalid",
    )
    for plane in ("target", "services"):
        scopes = strict_keys(
            quotas[plane],
            {"global", "regional"},
            "prerequisite_observation_policy_gcp_quotas_invalid",
        )
        for required in scopes.values():
            if (
                not isinstance(required, dict)
                or not required
                or any(
                    not isinstance(metric, str)
                    or not isinstance(minimum, (int, float))
                    or minimum <= 0
                    for metric, minimum in required.items()
                )
            ):
                fail("prerequisite_observation_policy_gcp_quotas_invalid")
    wif = strict_keys(
        gcp["wif"],
        {
            "poolId",
            "providerId",
            "serviceAccountId",
            "executorServiceAccountId",
            "executorFederated",
            "issuerUri",
            "repository",
            "repositoryId",
            "repositoryOwnerId",
            "repositoryVisibility",
            "workflowRef",
            "environment",
            "minimumIndependentReviewers",
            "reviewerType",
            "preventSelfReview",
            "deploymentBranch",
            "attributeCondition",
        },
        "prerequisite_observation_policy_wif_invalid",
    )
    if wif != {
        "poolId": "orchestra-lab-github",
        "providerId": "github",
        "serviceAccountId": "orchestra-lab-foundation-plan",
        "executorServiceAccountId": "orchestra-lab-foundation",
        "executorFederated": False,
        "issuerUri": "https://token.actions.githubusercontent.com",
        "repository": "caglarsubas/orchestra-openshift-reference-lab",
        "repositoryId": "1307302690",
        "repositoryOwnerId": "37515097",
        "repositoryVisibility": "private",
        "workflowRef": (
            "caglarsubas/orchestra-openshift-reference-lab/"
            ".github/workflows/foundation-plan.yml@refs/heads/main"
        ),
        "environment": "reference-lab-foundation-plan",
        "minimumIndependentReviewers": 1,
        "reviewerType": "User",
        "preventSelfReview": True,
        "deploymentBranch": "main",
        "attributeCondition": (
            "assertion.repository == "
            "'caglarsubas/orchestra-openshift-reference-lab' && "
            "assertion.repository_id == '1307302690' && "
            "assertion.repository_owner_id == '37515097' && "
            "assertion.repository_visibility == 'private' && "
            "assertion.ref == 'refs/heads/main' && "
            "assertion.event_name == 'workflow_dispatch' && "
            "assertion.workflow_ref == "
            "'caglarsubas/orchestra-openshift-reference-lab/"
            ".github/workflows/foundation-plan.yml@refs/heads/main' && "
            "assertion.environment == 'reference-lab-foundation-plan'"
        ),
    }:
        fail("prerequisite_observation_policy_wif_invalid")
    if value["dns"] != {
        "managedZoneName": "orchestra-ocp-lab-public",
        "managedZoneProjectPlane": "services-evidence",
        "dnsName": "ocp-lab.prometa.ai.",
        "visibility": "public",
        "clusterDnsName": "orchestra.ocp-lab.prometa.ai.",
        "privateZoneAuthority": "openshift-installer",
        "servicesPeeringZoneName": "orchestra-services-to-ocp-private",
    }:
        fail("prerequisite_observation_policy_dns_invalid")
    if value["claim"] != {
        "independentReviewRequired": True,
        "provisioningReady": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("prerequisite_observation_policy_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_POLICY_DIGEST:
        fail(f"prerequisite_observation_policy_digest_changed:{digest}")
    return digest


def expected_bindings() -> dict[str, str]:
    policy, release_set = load_contract()
    return {
        "topologyDigest": TOPOLOGY_DIGEST,
        "releaseSetDigest": validate_release_set(release_set),
        "policyDigest": validate_policy(policy, release_set),
    }


def validate_observation(
    value: dict[str, Any],
    *,
    now: datetime | None = None,
    require_fresh: bool = True,
) -> str:
    policy, release_set = load_contract()
    policy_digest = validate_policy(policy, release_set)
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "targetClass",
            "executionMode",
            "observationId",
            "bindings",
            "collection",
            "gates",
            "summary",
            "claims",
        },
        "prerequisite_observation_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "orchestra.reference-lab.prerequisite-observation.v1"
        or value["profileId"] != PROFILE_ID
        or not isinstance(value["observationId"], str)
        or not OBSERVATION_ID.fullmatch(value["observationId"])
        or value["bindings"]
        != {
            "topologyDigest": TOPOLOGY_DIGEST,
            "releaseSetDigest": validate_release_set(release_set),
            "policyDigest": policy_digest,
        }
    ):
        fail("prerequisite_observation_identity_invalid")
    pair = (value["targetClass"], value["executionMode"])
    if pair not in {
        ("fixture", "simulated"),
        ("vendor-reference-lab", "live"),
    }:
        fail("prerequisite_observation_origin_invalid")

    collection = strict_keys(
        value["collection"],
        {
            "executionClass",
            "runnerRelease",
            "runnerImageDigest",
            "runnerToolchainDigest",
            "collectorScriptDigest",
            "actorIdentityDigest",
            "startedAt",
            "completedAt",
            "commandPolicy",
            "rawProviderOutputStored",
            "secretValuesStored",
        },
        "prerequisite_observation_collection_invalid",
    )
    require_digest(
        collection["collectorScriptDigest"],
        "prerequisite_observation_collector_digest_invalid",
    )
    require_digest(
        collection["actorIdentityDigest"],
        "prerequisite_observation_actor_digest_invalid",
    )
    if collection["collectorScriptDigest"] != blob_digest(COLLECTOR_PATH.read_bytes()):
        fail("prerequisite_observation_collector_digest_mismatch")
    if (
        collection["commandPolicy"] != "read-only"
        or collection["rawProviderOutputStored"] is not False
        or collection["secretValuesStored"] is not False
    ):
        fail("prerequisite_observation_collection_policy_invalid")
    if value["executionMode"] == "live":
        if collection != {
            **collection,
            "executionClass": policy["observationPolicy"]["liveExecutionClass"],
            "runnerRelease": policy["runner"]["release"],
            "runnerImageDigest": policy["runner"]["imageDigest"],
            "runnerToolchainDigest": policy["runner"]["toolchainDigest"],
        }:
            fail("prerequisite_observation_live_runner_invalid")
    elif (
        collection["executionClass"]
        != policy["observationPolicy"]["diagnosticExecutionClass"]
        or collection["runnerRelease"] is not None
        or collection["runnerImageDigest"] is not None
        or collection["runnerToolchainDigest"] is not None
    ):
        fail("prerequisite_observation_diagnostic_runner_invalid")

    started_at = parse_utc(
        collection["startedAt"], "prerequisite_observation_collection_time_invalid"
    )
    completed_at = parse_utc(
        collection["completedAt"], "prerequisite_observation_collection_time_invalid"
    )
    assessed_at = now or datetime.now(timezone.utc)
    if (
        completed_at < started_at
        or completed_at - started_at
        > timedelta(minutes=policy["observationPolicy"]["maximumCollectionMinutes"])
        or completed_at > assessed_at
    ):
        fail("prerequisite_observation_collection_time_invalid")
    if require_fresh and assessed_at - completed_at > timedelta(
        hours=policy["observationPolicy"]["maximumAgeHours"]
    ):
        fail("prerequisite_observation_stale")

    gates = strict_keys(
        value["gates"], set(GATE_ORDER), "prerequisite_observation_gates_invalid"
    )
    passed_gates = 0
    for gate_name in GATE_ORDER:
        gate = strict_keys(
            gates[gate_name],
            {"status", "checks", "reasonCodes"},
            f"prerequisite_observation_gate_invalid:{gate_name}",
        )
        checks = gate["checks"]
        if not isinstance(checks, list) or [
            item.get("id") for item in checks if isinstance(item, dict)
        ] != list(GATE_CHECKS[gate_name]):
            fail(f"prerequisite_observation_checks_invalid:{gate_name}")
        observed_statuses: list[str] = []
        blocked_reasons: list[str] = []
        for check in checks:
            strict_keys(
                check,
                {"id", "status", "evidenceDigest", "observedAt", "reasonCode"},
                f"prerequisite_observation_check_invalid:{gate_name}",
            )
            status = check["status"]
            reason = check["reasonCode"]
            if (
                status not in {"passed", "failed", "not-run"}
                or not isinstance(reason, str)
                or not REASON_CODE.fullmatch(reason)
            ):
                fail(f"prerequisite_observation_check_invalid:{gate_name}")
            if status == "not-run":
                if (
                    check["evidenceDigest"] is not None
                    or check["observedAt"] is not None
                ):
                    fail(f"prerequisite_observation_check_invalid:{gate_name}")
            else:
                require_digest(
                    check["evidenceDigest"],
                    f"prerequisite_observation_check_digest_invalid:{gate_name}",
                )
                observed_at = parse_utc(
                    check["observedAt"],
                    f"prerequisite_observation_check_time_invalid:{gate_name}",
                )
                if not started_at <= observed_at <= completed_at:
                    fail(f"prerequisite_observation_check_time_invalid:{gate_name}")
            if status == "passed" and reason != "OBSERVED":
                fail(f"prerequisite_observation_check_reason_invalid:{gate_name}")
            if status != "passed":
                blocked_reasons.append(reason)
            observed_statuses.append(status)
        expected_status = (
            "passed"
            if all(status == "passed" for status in observed_statuses)
            else "blocked"
        )
        expected_reasons = (
            ["OBSERVATIONS_COMPLETE_REVIEW_REQUIRED"]
            if expected_status == "passed"
            else sorted(set(blocked_reasons))
        )
        if gate["status"] != expected_status or gate["reasonCodes"] != expected_reasons:
            fail(f"prerequisite_observation_gate_summary_invalid:{gate_name}")
        if expected_status == "passed":
            passed_gates += 1

    summary = {
        "passedGates": passed_gates,
        "blockedGates": len(GATE_ORDER) - passed_gates,
        "totalGates": len(GATE_ORDER),
    }
    if value["summary"] != summary:
        fail("prerequisite_observation_summary_invalid")
    all_passed = passed_gates == len(GATE_ORDER)
    expected_claims = {
        "allRequiredObservationsPassed": all_passed,
        "eligibleForIndependentReview": all_passed and value["executionMode"] == "live",
        "verifiedPrerequisiteGates": 0,
        "provisioningReady": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }
    if value["claims"] != expected_claims:
        fail("prerequisite_observation_claims_invalid")
    return canonical_digest(value)
