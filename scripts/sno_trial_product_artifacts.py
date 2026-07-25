#!/usr/bin/env python3
"""Validate and replay locked SNO product artifacts without deployment authority."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_sno_trial_profile import canonical_digest
except ModuleNotFoundError:
    from validate_sno_trial_profile import canonical_digest


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config" / "sno-trial-product-artifacts.lock.json"
CANDIDATE_PATH = ROOT / "config" / "sno-trial-workload-candidate.lock.json"
LOCK_KIND = "orchestra.openshift.sno-trial-product-artifact-set.v2"
REPORT_KIND = "orchestra.openshift.sno-trial-product-artifact-replay.v2"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
ARTIFACT_SET_ID = "orchestra-sno-trial-products-2026-07-25.3"
TARGET_CLASS = "engineering-trial"
LOCK_EXECUTION_MODE = "source-observation"
REPORT_EXECUTION_MODE = "live-registry-artifact-replay"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
VERIFICATION_ID = re.compile(r"^sno-product-replay-[a-z0-9][a-z0-9.-]{5,79}$")
EXPECTED_PLANES = ("platform", "runtimeHost", "modelPlane")
EXPECTED_ARTIFACTS: dict[str, dict[str, Any]] = {
    "platform": {
        "release": "platform-v0.1.0-rc.11",
        "source": {
            "repository": "caglarsubas/agent-hook-v2",
            "revision": "13fcacafedd16eb88a0bf0f3b49e176625e15e02",
        },
        "image": {
            "repository": "ghcr.io/caglarsubas/agent-hook-v2/prometa-ubi",
            "digest": "sha256:f2444f162328d0716338d0c3d151310a908e2f022c1f32d2d01e08f320e9e56d",
            "platformManifestDigest": "sha256:998db0c5a1110bbaf551e44d362af63e4d844db8d115380ec7215680ad564a14",
            "variant": "ubi9",
        },
        "chart": {
            "repository": "ghcr.io/caglarsubas/agent-hook-v2/charts/prometa",
            "digest": "sha256:b82fe64341de376819e0012dd184f12ff68bf33581f927ed66b839ce06959a2d",
            "name": "prometa",
            "version": "0.3.0-rc.11",
            "appVersion": "0.1.0",
            "packageDigest": "sha256:baed4c981742e8179edc752da261c0bb811736372bdfa46d72dbcc9487ee3d84",
            "trialValuesPath": "prometa/values.openshift-sno-trial.yaml",
            "trialValuesDigest": "sha256:3b5e5150afc64141a4a0487241b041111712983cdb5b0dc89e9bd3e3d1e44d2b",
        },
        "publication": {
            "workflow": ".github/workflows/publish-platform-release.yml",
            "workflowName": "publish-platform-release",
            "runId": 30157474312,
            "runAttempt": 1,
            "signatureIdentity": (
                "https://github.com/caglarsubas/agent-hook-v2/"
                ".github/workflows/publish-platform-release.yml"
                "@refs/tags/platform-v0.1.0-rc.11"
            ),
        },
    },
    "runtimeHost": {
        "release": "v0.18.7",
        "source": {
            "repository": "prometa-ai/orchestra-python-sdk",
            "revision": "2dbbbe13bc1764ed8bd5225dc8214906acd3310b",
        },
        "image": {
            "repository": (
                "ghcr.io/prometa-ai/orchestra-python-sdk/"
                "prometa-runtime-host-ubi9"
            ),
            "digest": "sha256:0ad1cc268da818d1b0c6ed850d50fdd937df79f1ab5e29cb6f7c3740b380029b",
            "platformManifestDigest": "sha256:5f397db663f26d7e33a01faf656a8fa3eebee73ccdb348e4dfae84d7f2ec713f",
            "variant": "ubi9",
        },
        "chart": {
            "repository": (
                "ghcr.io/prometa-ai/orchestra-python-sdk/charts/prometa-runtime"
            ),
            "name": "prometa-runtime",
            "version": "0.3.8",
            "appVersion": "0.18.7",
            "digest": "sha256:1e6b346b096ae9aeba799ab5461b6bd3e206fd319457d43be53f6fa627bbb5a6",
            "packageDigest": "sha256:dc77a8e181729ac91e6453a48e1f9b78c1fbae561f43d9e0717d72ff4c16f6b6",
            "trialValuesPath": (
                "prometa-runtime/values.openshift-sno-trial.yaml"
            ),
            "trialValuesDigest": "sha256:11fe28f037b111fee2723a09999f913a220dbd5c07b28458f340b6d883027b63",
        },
        "publication": {
            "workflow": ".github/workflows/publish-runtime-artifacts.yml",
            "workflowName": "Publish runtime artifacts",
            "runId": 30171938726,
            "runAttempt": 1,
            "signatureIdentity": (
                "https://github.com/prometa-ai/orchestra-python-sdk/"
                ".github/workflows/publish-runtime-artifacts.yml"
                "@refs/heads/main"
            ),
        },
    },
    "modelPlane": {
        "release": "v0.1.11",
        "source": {
            "repository": "caglarsubas/llm_inference_engine",
            "revision": "6c3f2a0cb34ca5110760b53d9cc8d65a3a5c2df2",
        },
        "image": {
            "repository": (
                "ghcr.io/caglarsubas/llm_inference_engine/inference-engine-ubi"
            ),
            "digest": "sha256:6eb6052cfc38fa6304021a2887536b5d7c77dc9f0ca4331491324021a0732549",
            "platformManifestDigest": "sha256:52e9da1065dfa539c70aae79beccafc58a47db17f5422bc500e3ab9b3c394c7a",
            "variant": "ubi9",
        },
        "chart": {
            "repository": (
                "ghcr.io/caglarsubas/llm_inference_engine/"
                "charts/orchestra-inference-engine"
            ),
            "digest": "sha256:a8acbe5d54efba912547e1ca6b783344d5821b7b7ab19d4c262948d015974637",
            "name": "orchestra-inference-engine",
            "version": "0.1.3",
            "appVersion": "0.1.11",
            "packageDigest": "sha256:bde3db9f6849e3a25a19d5671b0db4e8f14e14f96218b0552920f182fe8467b3",
            "trialValuesPath": (
                "orchestra-inference-engine/values.openshift-sno-trial.yaml"
            ),
            "trialValuesDigest": "sha256:21affdee56d51be89396a209819d6a5b0a6d74fe6aa4210b1bd0096384023c1c",
        },
        "publication": {
            "workflow": ".github/workflows/publish-images.yml",
            "workflowName": "publish-release-artifacts",
            "runId": 30151836099,
            "runAttempt": 1,
            "signatureIdentity": (
                "https://github.com/caglarsubas/llm_inference_engine/"
                ".github/workflows/publish-images.yml@refs/tags/v0.1.11"
            ),
        },
    },
}

LOCK_KEYS = {
    "schemaVersion",
    "kind",
    "artifactSetId",
    "profileId",
    "targetClass",
    "executionMode",
    "completeness",
    "bindings",
    "artifacts",
    "activation",
    "controls",
    "claims",
    "artifactSetDigest",
}
ARTIFACT_KEYS = {
    "plane",
    "release",
    "source",
    "image",
    "chart",
    "publication",
    "admission",
}
SOURCE_KEYS = {"repository", "revision"}
IMAGE_KEYS = {
    "repository",
    "digest",
    "reference",
    "platform",
    "platformManifestDigest",
    "variant",
}
CHART_KEYS = {
    "repository",
    "digest",
    "reference",
    "name",
    "version",
    "appVersion",
    "packageDigest",
    "trialValuesPath",
    "trialValuesDigest",
}
PUBLICATION_KEYS = {
    "workflow",
    "workflowName",
    "runId",
    "runAttempt",
    "runUrl",
    "tag",
    "signatureIdentity",
    "oidcIssuer",
}
ADMISSION_KEYS = {
    "state",
    "sourceOnly",
    "publicReplayRequired",
    "destinationMirrorVerified",
    "liveClusterPullVerified",
    "secretReferencesResolved",
    "serverSideDryRunVerified",
    "activationAuthorized",
}
ACTIVATION_REASONS = [
    "product-artifact-replay-review-missing",
    "destination-mirror-verification-missing",
    "live-cluster-pull-verification-missing",
    "operator-secret-and-ca-inputs-missing",
    "openshift-server-side-dry-run-missing",
    "provider-readiness-not-approved",
]
CONTROLS = {
    "productionReleaseSetMutated": False,
    "manifestsEmitted": False,
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
}
REPORT_CONTROLS = {
    "registryReadOnly": True,
    "registryCredentialsRequired": True,
    "githubApiTokenUsed": True,
    "providerCredentialsUsed": False,
    "payloadsCollected": False,
    "secretsCollected": False,
    "manifestsEmitted": False,
    "cloudMutationAuthorized": False,
    "deploymentAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
}

CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def require_expected_subset(
    value: dict[str, Any],
    expected: dict[str, Any],
    code: str,
) -> None:
    for key, expected_value in expected.items():
        actual_value = value.get(key)
        if isinstance(expected_value, dict):
            if not isinstance(actual_value, dict):
                fail(code)
            require_expected_subset(actual_value, expected_value, code)
        elif actual_value != expected_value:
            fail(code)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("sno_product_artifact_json_invalid")
    if not isinstance(value, dict):
        fail("sno_product_artifact_json_object_required")
    return value


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        fail("sno_product_artifact_file_unreadable")
    return f"sha256:{digest.hexdigest()}"


def bytes_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def unsigned_digest(value: dict[str, Any], field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(field, None)
    return canonical_digest(unsigned)


def validate_digest(value: Any, code: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(code)


def validate_utc(value: Any) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail("sno_product_artifact_report_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail("sno_product_artifact_report_time_invalid")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        fail("sno_product_artifact_report_time_invalid")


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_lock(
    value: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    exact_keys(value, LOCK_KEYS, "sno_product_artifact_lock_keys_invalid")
    if (
        value["schemaVersion"] != 2
        or value["kind"] != LOCK_KIND
        or value["artifactSetId"] != ARTIFACT_SET_ID
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != TARGET_CLASS
        or value["executionMode"] != LOCK_EXECUTION_MODE
        or value["completeness"] != "published-three-plane-not-trial-admitted"
    ):
        fail("sno_product_artifact_lock_identity_invalid")
    if value["bindings"] != {
        "workloadCandidateDigest": candidate.get("candidateDigest")
    }:
        fail("sno_product_artifact_lock_bindings_invalid")
    validate_digest(
        value["bindings"]["workloadCandidateDigest"],
        "sno_product_artifact_lock_bindings_invalid",
    )

    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(EXPECTED_PLANES):
        fail("sno_product_artifact_lock_artifacts_invalid")
    planes = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            fail("sno_product_artifact_lock_artifacts_invalid")
        exact_keys(
            artifact,
            ARTIFACT_KEYS,
            "sno_product_artifact_lock_artifact_keys_invalid",
        )
        plane = artifact["plane"]
        if not isinstance(plane, str):
            fail("sno_product_artifact_lock_release_invalid")
        planes.append(plane)
        expected_artifact = EXPECTED_ARTIFACTS.get(plane)
        if (
            expected_artifact is None
            or artifact["release"] != expected_artifact["release"]
        ):
            fail("sno_product_artifact_lock_release_invalid")

        source = artifact["source"]
        if not isinstance(source, dict):
            fail("sno_product_artifact_lock_source_invalid")
        exact_keys(
            source,
            SOURCE_KEYS,
            "sno_product_artifact_lock_source_keys_invalid",
        )
        if (
            not isinstance(source["repository"], str)
            or not isinstance(source["revision"], str)
            or not REVISION.fullmatch(source["revision"])
        ):
            fail("sno_product_artifact_lock_source_invalid")
        require_expected_subset(
            source,
            expected_artifact["source"],
            "sno_product_artifact_lock_source_invalid",
        )

        image = artifact["image"]
        if not isinstance(image, dict):
            fail("sno_product_artifact_lock_image_invalid")
        exact_keys(image, IMAGE_KEYS, "sno_product_artifact_lock_image_keys_invalid")
        for field in ("digest", "platformManifestDigest"):
            validate_digest(image[field], "sno_product_artifact_lock_image_invalid")
        if (
            not isinstance(image["repository"], str)
            or image["reference"] != f"{image['repository']}@{image['digest']}"
            or image["platform"] != "linux/amd64"
            or image["variant"] != "ubi9"
        ):
            fail("sno_product_artifact_lock_image_invalid")
        require_expected_subset(
            image,
            expected_artifact["image"],
            "sno_product_artifact_lock_image_invalid",
        )

        chart = artifact["chart"]
        if not isinstance(chart, dict):
            fail("sno_product_artifact_lock_chart_invalid")
        exact_keys(chart, CHART_KEYS, "sno_product_artifact_lock_chart_keys_invalid")
        for field in ("digest", "packageDigest", "trialValuesDigest"):
            validate_digest(chart[field], "sno_product_artifact_lock_chart_invalid")
        if (
            not isinstance(chart["repository"], str)
            or chart["reference"] != f"{chart['repository']}@{chart['digest']}"
            or not all(
                isinstance(chart[field], str)
                for field in (
                    "name",
                    "version",
                    "appVersion",
                    "trialValuesPath",
                )
            )
        ):
            fail("sno_product_artifact_lock_chart_invalid")
        require_expected_subset(
            chart,
            expected_artifact["chart"],
            "sno_product_artifact_lock_chart_invalid",
        )

        publication = artifact["publication"]
        if not isinstance(publication, dict):
            fail("sno_product_artifact_lock_publication_invalid")
        exact_keys(
            publication,
            PUBLICATION_KEYS,
            "sno_product_artifact_lock_publication_keys_invalid",
        )
        expected_identity = expected_artifact["publication"][
            "signatureIdentity"
        ]
        expected_url = (
            f"https://github.com/{source['repository']}/"
            f"actions/runs/{publication['runId']}"
        )
        if (
            publication["tag"] != artifact["release"]
            or not isinstance(publication["runAttempt"], int)
            or publication["runAttempt"] <= 0
            or not isinstance(publication["runId"], int)
            or publication["runId"] <= 0
            or publication["runUrl"] != expected_url
            or publication["signatureIdentity"] != expected_identity
            or publication["oidcIssuer"]
            != "https://token.actions.githubusercontent.com"
            or not isinstance(publication["workflowName"], str)
        ):
            fail("sno_product_artifact_lock_publication_invalid")
        require_expected_subset(
            publication,
            expected_artifact["publication"],
            "sno_product_artifact_lock_publication_invalid",
        )

        admission = artifact["admission"]
        if not isinstance(admission, dict):
            fail("sno_product_artifact_lock_admission_invalid")
        exact_keys(
            admission,
            ADMISSION_KEYS,
            "sno_product_artifact_lock_admission_keys_invalid",
        )
        if admission != {
            "state": "published-not-trial-admitted",
            "sourceOnly": True,
            "publicReplayRequired": True,
            "destinationMirrorVerified": False,
            "liveClusterPullVerified": False,
            "secretReferencesResolved": False,
            "serverSideDryRunVerified": False,
            "activationAuthorized": False,
        }:
            fail("sno_product_artifact_lock_admission_invalid")

    if tuple(planes) != EXPECTED_PLANES:
        fail("sno_product_artifact_lock_release_invalid")
    if len(set(planes)) != len(planes):
        fail("sno_product_artifact_lock_artifacts_invalid")
    if value["activation"] != {
        "state": "blocked",
        "reasonCodes": ACTIVATION_REASONS,
    }:
        fail("sno_product_artifact_lock_activation_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_product_artifact_lock_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_product_artifact_lock_claims_invalid")
    validate_digest(
        value["artifactSetDigest"],
        "sno_product_artifact_lock_digest_invalid",
    )
    if value["artifactSetDigest"] != unsigned_digest(value, "artifactSetDigest"):
        fail("sno_product_artifact_lock_digest_mismatch")


def default_runner(
    command: list[str],
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )


def run_checked(
    run: CommandRunner,
    command: list[str],
    code: str,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return run(command, cwd)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        fail(code)


def parse_json(value: str, code: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        fail(code)


def verify_publication_run(
    artifact: dict[str, Any],
    run: CommandRunner,
) -> dict[str, Any]:
    publication = artifact["publication"]
    source = artifact["source"]
    result = run_checked(
        run,
        [
            "gh",
            "api",
            f"repos/{source['repository']}/actions/runs/{publication['runId']}",
        ],
        "sno_product_artifact_publication_query_failed",
    )
    value = parse_json(result.stdout, "sno_product_artifact_publication_json_invalid")
    if not isinstance(value, dict):
        fail("sno_product_artifact_publication_json_invalid")
    identity_ref = publication["signatureIdentity"].rsplit("@", 1)[-1]
    if identity_ref == f"refs/tags/{publication['tag']}":
        expected_event = "push"
        expected_branch = publication["tag"]
    elif identity_ref == "refs/heads/main":
        expected_event = "workflow_dispatch"
        expected_branch = "main"
    else:
        fail("sno_product_artifact_publication_origin_invalid")
    expected = {
        "id": publication["runId"],
        "run_attempt": publication["runAttempt"],
        "event": expected_event,
        "status": "completed",
        "conclusion": "success",
        "head_branch": expected_branch,
        "head_sha": source["revision"],
        "path": publication["workflow"],
        "html_url": publication["runUrl"],
    }
    if any(
        value.get(key) != expected_value for key, expected_value in expected.items()
    ):
        fail("sno_product_artifact_publication_origin_invalid")
    return {
        "runId": publication["runId"],
        "runAttempt": publication["runAttempt"],
        "runUrl": publication["runUrl"],
        "tag": publication["tag"],
        "sourceRevision": source["revision"],
        "workflow": publication["workflow"],
        "workflowName": publication["workflowName"],
        "conclusion": "success",
    }


def signature_command(
    reference: str,
    publication: dict[str, Any],
) -> list[str]:
    return [
        "cosign",
        "verify",
        reference,
        "--certificate-identity",
        publication["signatureIdentity"],
        "--certificate-oidc-issuer",
        publication["oidcIssuer"],
    ]


def attestation_command(
    reference: str,
    publication: dict[str, Any],
) -> list[str]:
    return [
        "cosign",
        "verify-attestation",
        reference,
        "--type",
        "cyclonedx",
        "--certificate-identity",
        publication["signatureIdentity"],
        "--certificate-oidc-issuer",
        publication["oidcIssuer"],
    ]


def verify_signature(
    reference: str,
    repository: str,
    digest: str,
    source: dict[str, Any],
    publication: dict[str, Any],
    run: CommandRunner,
) -> None:
    result = run_checked(
        run,
        signature_command(reference, publication),
        "sno_product_artifact_signature_failed",
    )
    value = parse_json(result.stdout, "sno_product_artifact_signature_json_invalid")
    if not isinstance(value, list) or not value:
        fail("sno_product_artifact_signature_json_invalid")
    for signature in value:
        if not isinstance(signature, dict):
            continue
        critical = signature.get("critical")
        optional = signature.get("optional")
        if not isinstance(critical, dict) or not isinstance(optional, dict):
            continue
        identity = critical.get("identity")
        image = critical.get("image")
        workflow_claims = {
            "githubWorkflowSha": source["revision"],
            "githubWorkflowRef": f"refs/tags/{publication['tag']}",
            "githubWorkflowRepository": source["repository"],
            "githubWorkflowName": publication["workflowName"],
        }
        claims_match = not optional or all(
            optional.get(key) == expected
            for key, expected in workflow_claims.items()
        )
        if (
            isinstance(identity, dict)
            and isinstance(image, dict)
            and identity.get("docker-reference") in {repository, reference}
            and image.get("docker-manifest-digest") == digest
            and claims_match
        ):
            return
    fail("sno_product_artifact_signature_claims_invalid")


def decode_attestation_payload(value: str) -> dict[str, Any]:
    envelope = parse_json(value, "sno_product_artifact_attestation_json_invalid")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
        fail("sno_product_artifact_attestation_json_invalid")
    try:
        decoded = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        fail("sno_product_artifact_attestation_payload_invalid")
    if not isinstance(statement, dict):
        fail("sno_product_artifact_attestation_payload_invalid")
    return statement


def verify_attestation(
    reference: str,
    repository: str,
    digest: str,
    publication: dict[str, Any],
    run: CommandRunner,
) -> None:
    result = run_checked(
        run,
        attestation_command(reference, publication),
        "sno_product_artifact_attestation_failed",
    )
    statements = [
        decode_attestation_payload(line)
        for line in result.stdout.splitlines()
        if line.strip()
    ]
    expected_digest = digest.removeprefix("sha256:")
    for statement in statements:
        if statement.get("predicateType") != "https://cyclonedx.org/bom":
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue
        for subject in subjects:
            if not isinstance(subject, dict):
                continue
            subject_digest = subject.get("digest")
            if (
                subject.get("name") == repository
                and isinstance(subject_digest, dict)
                and subject_digest.get("sha256") == expected_digest
            ):
                return
    fail("sno_product_artifact_attestation_subject_invalid")


def chart_metadata(stdout: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for line in stdout.splitlines():
        match = re.fullmatch(
            r"(name|version|appVersion):[ ]*['\"]?([^'\"]+)['\"]?", line
        )
        if match:
            metadata[match.group(1)] = match.group(2)
    if set(metadata) != {"name", "version", "appVersion"}:
        fail("sno_product_artifact_chart_metadata_invalid")
    return metadata


def inspect_chart_package(
    package: Path,
    chart: dict[str, Any],
    run: CommandRunner,
) -> dict[str, Any]:
    if not package.is_file() or package.is_symlink():
        fail("sno_product_artifact_chart_package_missing")
    if file_digest(package) != chart["packageDigest"]:
        fail("sno_product_artifact_chart_package_digest_invalid")
    shown = run_checked(
        run,
        ["helm", "show", "chart", str(package)],
        "sno_product_artifact_chart_metadata_failed",
    )
    if chart_metadata(shown.stdout) != {
        "name": chart["name"],
        "version": chart["version"],
        "appVersion": chart["appVersion"],
    }:
        fail("sno_product_artifact_chart_metadata_invalid")
    try:
        with tarfile.open(package, mode="r:gz") as archive:
            members = archive.getmembers()
            matches = [
                member for member in members if member.name == chart["trialValuesPath"]
            ]
            if len(matches) != 1 or not matches[0].isreg():
                fail("sno_product_artifact_trial_values_missing")
            extracted = archive.extractfile(matches[0])
            if extracted is None:
                fail("sno_product_artifact_trial_values_missing")
            trial_values = extracted.read()
    except (OSError, tarfile.TarError):
        fail("sno_product_artifact_chart_package_invalid")
    if bytes_digest(trial_values) != chart["trialValuesDigest"]:
        fail("sno_product_artifact_trial_values_digest_invalid")
    try:
        text = trial_values.decode("utf-8")
    except UnicodeDecodeError:
        fail("sno_product_artifact_trial_values_invalid")
    required_lines = {
        "  enabled: true",
        f"  profileId: {PROFILE_ID}",
        "  sourceOnlyAcknowledged: true",
    }
    if not required_lines.issubset(set(text.splitlines())):
        fail("sno_product_artifact_trial_values_invalid")
    return {
        "reference": chart["reference"],
        "digest": chart["digest"],
        "name": chart["name"],
        "version": chart["version"],
        "appVersion": chart["appVersion"],
        "packageDigest": chart["packageDigest"],
        "trialValuesPath": chart["trialValuesPath"],
        "trialValuesDigest": chart["trialValuesDigest"],
        "signatureVerified": True,
        "cycloneDxAttestationVerified": True,
        "packagePulled": True,
        "trialValuesVerified": True,
    }


def verify_chart(
    artifact: dict[str, Any],
    run: CommandRunner,
) -> dict[str, Any]:
    source = artifact["source"]
    chart = artifact["chart"]
    publication = artifact["publication"]
    verify_signature(
        chart["reference"],
        chart["repository"],
        chart["digest"],
        source,
        publication,
        run,
    )
    verify_attestation(
        chart["reference"],
        chart["repository"],
        chart["digest"],
        publication,
        run,
    )
    with tempfile.TemporaryDirectory(prefix="orchestra-sno-chart.") as directory:
        root = Path(directory)
        run_checked(
            run,
            [
                "helm",
                "pull",
                f"oci://{chart['repository']}",
                "--version",
                chart["version"],
                "--destination",
                str(root),
            ],
            "sno_product_artifact_chart_pull_failed",
        )
        package = root / f"{chart['name']}-{chart['version']}.tgz"
        return inspect_chart_package(package, chart, run)


def verify_image_index(
    image: dict[str, Any],
    run: CommandRunner,
) -> None:
    result = run_checked(
        run,
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            "--raw",
            image["reference"],
        ],
        "sno_product_artifact_image_index_failed",
    )
    value = parse_json(result.stdout, "sno_product_artifact_image_index_json_invalid")
    if not isinstance(value, dict) or not isinstance(value.get("manifests"), list):
        fail("sno_product_artifact_image_index_json_invalid")
    matches = []
    for manifest in value["manifests"]:
        if not isinstance(manifest, dict):
            continue
        platform = manifest.get("platform")
        if (
            isinstance(platform, dict)
            and platform.get("os") == "linux"
            and platform.get("architecture") == "amd64"
        ):
            matches.append(manifest)
    if len(matches) != 1 or matches[0].get("digest") != image["platformManifestDigest"]:
        fail("sno_product_artifact_image_platform_invalid")


def verify_image(
    artifact: dict[str, Any],
    run: CommandRunner,
) -> dict[str, Any]:
    source = artifact["source"]
    image = artifact["image"]
    publication = artifact["publication"]
    verify_image_index(image, run)
    verify_signature(
        image["reference"],
        image["repository"],
        image["digest"],
        source,
        publication,
        run,
    )
    verify_attestation(
        image["reference"],
        image["repository"],
        image["digest"],
        publication,
        run,
    )
    return {
        **image,
        "platformManifestVerified": True,
        "signatureVerified": True,
        "cycloneDxAttestationVerified": True,
    }


def report_digest(value: dict[str, Any]) -> str:
    return unsigned_digest(value, "reportDigest")


def build_report(
    lock: dict[str, Any],
    candidate: dict[str, Any],
    verification_id: str,
    generated_at: datetime,
    verifier_revision: str,
    verifier_run_id: int,
    verifier_run_attempt: int,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    validate_lock(lock, candidate)
    if not VERIFICATION_ID.fullmatch(verification_id):
        fail("sno_product_artifact_verification_id_invalid")
    if not REVISION.fullmatch(verifier_revision):
        fail("sno_product_artifact_verifier_revision_invalid")
    if verifier_run_id <= 0 or verifier_run_attempt != 1:
        fail("sno_product_artifact_verifier_run_invalid")
    artifacts = []
    for artifact in lock["artifacts"]:
        artifacts.append(
            {
                "plane": artifact["plane"],
                "publication": verify_publication_run(artifact, run),
                "image": verify_image(artifact, run),
                "chart": verify_chart(artifact, run),
                "admission": dict(artifact["admission"]),
            }
        )
    report = {
        "schemaVersion": 2,
        "kind": REPORT_KIND,
        "verificationId": verification_id,
        "generatedAt": utc_text(generated_at),
        "targetClass": TARGET_CLASS,
        "executionMode": REPORT_EXECUTION_MODE,
        "bindings": {
            "profileId": PROFILE_ID,
            "artifactSetId": ARTIFACT_SET_ID,
            "artifactSetDigest": lock["artifactSetDigest"],
            "workloadCandidateDigest": candidate["candidateDigest"],
            "verifierRevision": verifier_revision,
            "verifierRunId": verifier_run_id,
            "verifierRunAttempt": verifier_run_attempt,
        },
        "artifacts": artifacts,
        "activation": dict(lock["activation"]),
        "controls": dict(REPORT_CONTROLS),
        "claims": dict(CLAIMS),
    }
    report["reportDigest"] = report_digest(report)
    validate_report(report, lock, candidate)
    return report


def validate_report(
    value: dict[str, Any],
    lock: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    validate_lock(lock, candidate)
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "verificationId",
            "generatedAt",
            "targetClass",
            "executionMode",
            "bindings",
            "artifacts",
            "activation",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_product_artifact_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 2
        or value["kind"] != REPORT_KIND
        or not isinstance(value["verificationId"], str)
        or not VERIFICATION_ID.fullmatch(value["verificationId"])
        or value["targetClass"] != TARGET_CLASS
        or value["executionMode"] != REPORT_EXECUTION_MODE
    ):
        fail("sno_product_artifact_report_identity_invalid")
    validate_utc(value["generatedAt"])
    bindings = value["bindings"]
    if not isinstance(bindings, dict):
        fail("sno_product_artifact_report_bindings_invalid")
    exact_keys(
        bindings,
        {
            "profileId",
            "artifactSetId",
            "artifactSetDigest",
            "workloadCandidateDigest",
            "verifierRevision",
            "verifierRunId",
            "verifierRunAttempt",
        },
        "sno_product_artifact_report_bindings_invalid",
    )
    if (
        bindings["profileId"] != PROFILE_ID
        or bindings["artifactSetId"] != ARTIFACT_SET_ID
        or bindings["artifactSetDigest"] != lock["artifactSetDigest"]
        or bindings["workloadCandidateDigest"] != candidate["candidateDigest"]
        or not isinstance(bindings["verifierRevision"], str)
        or not REVISION.fullmatch(bindings["verifierRevision"])
        or not isinstance(bindings["verifierRunId"], int)
        or bindings["verifierRunId"] <= 0
        or bindings["verifierRunAttempt"] != 1
    ):
        fail("sno_product_artifact_report_bindings_invalid")
    report_artifacts = value["artifacts"]
    if not isinstance(report_artifacts, list) or len(report_artifacts) != len(
        lock["artifacts"]
    ):
        fail("sno_product_artifact_report_artifacts_invalid")
    for artifact, report_artifact in zip(
        lock["artifacts"], report_artifacts, strict=True
    ):
        if not isinstance(report_artifact, dict):
            fail("sno_product_artifact_report_artifacts_invalid")
        exact_keys(
            report_artifact,
            {"plane", "publication", "image", "chart", "admission"},
            "sno_product_artifact_report_artifact_keys_invalid",
        )
        if report_artifact["plane"] != artifact["plane"]:
            fail("sno_product_artifact_report_artifacts_invalid")
        publication = artifact["publication"]
        source = artifact["source"]
        if report_artifact["publication"] != {
            "runId": publication["runId"],
            "runAttempt": publication["runAttempt"],
            "runUrl": publication["runUrl"],
            "tag": publication["tag"],
            "sourceRevision": source["revision"],
            "workflow": publication["workflow"],
            "workflowName": publication["workflowName"],
            "conclusion": "success",
        }:
            fail("sno_product_artifact_report_publication_invalid")
        image = artifact["image"]
        if report_artifact["image"] != {
            **image,
            "platformManifestVerified": True,
            "signatureVerified": True,
            "cycloneDxAttestationVerified": True,
        }:
            fail("sno_product_artifact_report_image_invalid")
        chart = artifact["chart"]
        if report_artifact["chart"] != {
            "reference": chart["reference"],
            "digest": chart["digest"],
            "name": chart["name"],
            "version": chart["version"],
            "appVersion": chart["appVersion"],
            "packageDigest": chart["packageDigest"],
            "trialValuesPath": chart["trialValuesPath"],
            "trialValuesDigest": chart["trialValuesDigest"],
            "signatureVerified": True,
            "cycloneDxAttestationVerified": True,
            "packagePulled": True,
            "trialValuesVerified": True,
        }:
            fail("sno_product_artifact_report_chart_invalid")
        if report_artifact["admission"] != artifact["admission"]:
            fail("sno_product_artifact_report_admission_invalid")
    if value["activation"] != lock["activation"]:
        fail("sno_product_artifact_report_activation_invalid")
    if value["controls"] != REPORT_CONTROLS:
        fail("sno_product_artifact_report_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_product_artifact_report_claims_invalid")
    validate_digest(
        value["reportDigest"],
        "sno_product_artifact_report_digest_invalid",
    )
    if value["reportDigest"] != report_digest(value):
        fail("sno_product_artifact_report_digest_mismatch")


def write_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError:
        fail("sno_product_artifact_output_exists")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-lock")

    replay = subparsers.add_parser("replay")
    replay.add_argument("--verification-id", required=True)
    replay.add_argument("--generated-at", required=True)
    replay.add_argument("--verifier-revision", required=True)
    replay.add_argument("--verifier-run-id", type=int, required=True)
    replay.add_argument("--verifier-run-attempt", type=int, required=True)
    replay.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)

    args = parser.parse_args(argv)
    lock = load_json(LOCK_PATH)
    candidate = load_json(CANDIDATE_PATH)
    if args.command == "validate-lock":
        validate_lock(lock, candidate)
        print(
            f"sno_product_artifacts_valid artifactSetDigest={lock['artifactSetDigest']}"
        )
        return 0
    if args.command == "replay":
        try:
            generated_at = datetime.fromisoformat(
                args.generated_at.replace("Z", "+00:00")
            )
        except ValueError:
            fail("sno_product_artifact_report_time_invalid")
        report = build_report(
            lock,
            candidate,
            args.verification_id,
            generated_at,
            args.verifier_revision,
            args.verifier_run_id,
            args.verifier_run_attempt,
        )
        write_create_only(args.output.resolve(), report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    report = load_json(args.report.resolve())
    validate_report(report, lock, candidate)
    print(f"verified {args.report}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
