#!/usr/bin/env python3
"""Validate and replay public SNO product artifacts without deployment authority."""

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
LOCK_KIND = "orchestra.openshift.sno-trial-product-artifact-set.v1"
REPORT_KIND = "orchestra.openshift.sno-trial-product-artifact-replay.v1"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
ARTIFACT_SET_ID = "orchestra-sno-trial-products-2026-07-25.1"
TARGET_CLASS = "engineering-trial"
LOCK_EXECUTION_MODE = "source-observation"
REPORT_EXECUTION_MODE = "live-public-artifact-replay"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
VERIFICATION_ID = re.compile(r"^sno-product-replay-[a-z0-9][a-z0-9.-]{5,79}$")
REPOSITORY = "caglarsubas/llm_inference_engine"
SOURCE_REVISION = "6c3f2a0cb34ca5110760b53d9cc8d65a3a5c2df2"
IMAGE_DIGEST = "sha256:6eb6052cfc38fa6304021a2887536b5d7c77dc9f0ca4331491324021a0732549"
IMAGE_PLATFORM_DIGEST = (
    "sha256:52e9da1065dfa539c70aae79beccafc58a47db17f5422bc500e3ab9b3c394c7a"
)
CHART_DIGEST = "sha256:a8acbe5d54efba912547e1ca6b783344d5821b7b7ab19d4c262948d015974637"
CHART_PACKAGE_DIGEST = (
    "sha256:bde3db9f6849e3a25a19d5671b0db4e8f14e14f96218b0552920f182fe8467b3"
)
TRIAL_VALUES_DIGEST = (
    "sha256:21affdee56d51be89396a209819d6a5b0a6d74fe6aa4210b1bd0096384023c1c"
)

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
    "platform-sno-profile-missing",
    "runtime-sno-profile-missing",
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
    "registryCredentialsRequired": False,
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
        value["schemaVersion"] != 1
        or value["kind"] != LOCK_KIND
        or value["artifactSetId"] != ARTIFACT_SET_ID
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != TARGET_CLASS
        or value["executionMode"] != LOCK_EXECUTION_MODE
        or value["completeness"] != "partial"
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
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        fail("sno_product_artifact_lock_artifacts_invalid")
    artifact = artifacts[0]
    if not isinstance(artifact, dict):
        fail("sno_product_artifact_lock_artifacts_invalid")
    exact_keys(
        artifact,
        ARTIFACT_KEYS,
        "sno_product_artifact_lock_artifact_keys_invalid",
    )
    if artifact["plane"] != "modelPlane" or artifact["release"] != "v0.1.11":
        fail("sno_product_artifact_lock_release_invalid")

    source = artifact["source"]
    if not isinstance(source, dict):
        fail("sno_product_artifact_lock_source_invalid")
    exact_keys(source, SOURCE_KEYS, "sno_product_artifact_lock_source_keys_invalid")
    if source["repository"] != REPOSITORY or source["revision"] != SOURCE_REVISION:
        fail("sno_product_artifact_lock_source_invalid")

    image = artifact["image"]
    if not isinstance(image, dict):
        fail("sno_product_artifact_lock_image_invalid")
    exact_keys(image, IMAGE_KEYS, "sno_product_artifact_lock_image_keys_invalid")
    for field in ("digest", "platformManifestDigest"):
        validate_digest(image[field], "sno_product_artifact_lock_image_invalid")
    if (
        image["repository"]
        != "ghcr.io/caglarsubas/llm_inference_engine/inference-engine-ubi"
        or image["digest"] != IMAGE_DIGEST
        or image["reference"] != f"{image['repository']}@{image['digest']}"
        or image["platform"] != "linux/amd64"
        or image["platformManifestDigest"] != IMAGE_PLATFORM_DIGEST
        or image["variant"] != "ubi9"
    ):
        fail("sno_product_artifact_lock_image_invalid")

    chart = artifact["chart"]
    if not isinstance(chart, dict):
        fail("sno_product_artifact_lock_chart_invalid")
    exact_keys(chart, CHART_KEYS, "sno_product_artifact_lock_chart_keys_invalid")
    for field in ("digest", "packageDigest", "trialValuesDigest"):
        validate_digest(chart[field], "sno_product_artifact_lock_chart_invalid")
    if (
        chart["repository"]
        != "ghcr.io/caglarsubas/llm_inference_engine/charts/orchestra-inference-engine"
        or chart["digest"] != CHART_DIGEST
        or chart["reference"] != f"{chart['repository']}@{chart['digest']}"
        or chart["name"] != "orchestra-inference-engine"
        or chart["version"] != "0.1.3"
        or chart["appVersion"] != "0.1.11"
        or chart["packageDigest"] != CHART_PACKAGE_DIGEST
        or chart["trialValuesPath"]
        != "orchestra-inference-engine/values.openshift-sno-trial.yaml"
        or chart["trialValuesDigest"] != TRIAL_VALUES_DIGEST
    ):
        fail("sno_product_artifact_lock_chart_invalid")

    publication = artifact["publication"]
    if not isinstance(publication, dict):
        fail("sno_product_artifact_lock_publication_invalid")
    exact_keys(
        publication,
        PUBLICATION_KEYS,
        "sno_product_artifact_lock_publication_keys_invalid",
    )
    expected_identity = (
        "https://github.com/caglarsubas/llm_inference_engine/"
        ".github/workflows/publish-images.yml@refs/tags/v0.1.11"
    )
    if publication != {
        "workflow": ".github/workflows/publish-images.yml",
        "workflowName": "publish-release-artifacts",
        "runId": 30151836099,
        "runAttempt": 1,
        "runUrl": (
            "https://github.com/caglarsubas/llm_inference_engine/"
            "actions/runs/30151836099"
        ),
        "tag": artifact["release"],
        "signatureIdentity": expected_identity,
        "oidcIssuer": "https://token.actions.githubusercontent.com",
    }:
        fail("sno_product_artifact_lock_publication_invalid")

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
            f"repos/{REPOSITORY}/actions/runs/{publication['runId']}",
        ],
        "sno_product_artifact_publication_query_failed",
    )
    value = parse_json(result.stdout, "sno_product_artifact_publication_json_invalid")
    if not isinstance(value, dict):
        fail("sno_product_artifact_publication_json_invalid")
    expected = {
        "id": publication["runId"],
        "run_attempt": publication["runAttempt"],
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": publication["tag"],
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
        if (
            isinstance(identity, dict)
            and isinstance(image, dict)
            and identity.get("docker-reference") == repository
            and image.get("docker-manifest-digest") == digest
            and optional.get("githubWorkflowSha") == source["revision"]
            and optional.get("githubWorkflowRef") == f"refs/tags/{publication['tag']}"
            and optional.get("githubWorkflowRepository") == REPOSITORY
            and optional.get("githubWorkflowName") == publication["workflowName"]
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
        "  protocol: http/protobuf",
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
    artifact = lock["artifacts"][0]
    report = {
        "schemaVersion": 1,
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
        "publication": verify_publication_run(artifact, run),
        "image": verify_image(artifact, run),
        "chart": verify_chart(artifact, run),
        "admission": dict(artifact["admission"]),
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
            "publication",
            "image",
            "chart",
            "admission",
            "activation",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_product_artifact_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
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
    artifact = lock["artifacts"][0]
    publication = artifact["publication"]
    source = artifact["source"]
    if value["publication"] != {
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
    if value["image"] != {
        **image,
        "platformManifestVerified": True,
        "signatureVerified": True,
        "cycloneDxAttestationVerified": True,
    }:
        fail("sno_product_artifact_report_image_invalid")
    chart = artifact["chart"]
    if value["chart"] != {
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
    if value["admission"] != artifact["admission"]:
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
