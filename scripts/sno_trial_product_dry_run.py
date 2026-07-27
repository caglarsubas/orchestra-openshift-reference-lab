#!/usr/bin/env python3
"""Observe SNO product API acceptance and capacity without deployment authority."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.sno_trial_cluster_observation import (
        validate_assessment as validate_cluster_assessment,
    )
    from scripts.sno_trial_product_artifacts import (
        LOCK_PATH,
        load_json,
        validate_lock,
    )
    from scripts.validate_sno_trial_profile import (
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        validate_production_isolation,
        validate_profile,
    )
    from scripts.validate_sno_trial_workload_candidate import CANDIDATE_PATH
except ModuleNotFoundError:
    from sno_trial_cluster_observation import (  # type: ignore[no-redef]
        validate_assessment as validate_cluster_assessment,
    )
    from sno_trial_product_artifacts import (  # type: ignore[no-redef]
        LOCK_PATH,
        load_json,
        validate_lock,
    )
    from validate_sno_trial_profile import (  # type: ignore[no-redef]
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        validate_production_isolation,
        validate_profile,
    )
    from validate_sno_trial_workload_candidate import (  # type: ignore[no-redef]
        CANDIDATE_PATH,
    )


REPORT_KIND = "orchestra.openshift.sno-trial-product-dry-run.v1"
SNAPSHOT_KIND = "orchestra.openshift.sno-trial-product-dry-run-snapshot.v1"
ASSESSMENT_ID = re.compile(r"^sno-product-dry-run-[a-z0-9][a-z0-9.-]{5,79}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMAGE = re.compile(r"^\s*image:\s*[\"']?([^\"'\s#]+)", re.MULTILINE)
SECRET_NAME = re.compile(
    r"^\s*secretName:\s*[\"']?([^\"'\s#]+)", re.MULTILINE
)
DOCUMENT = re.compile(r"(?m)^---\s*$")
RESOURCE_KIND = re.compile(r"(?m)^kind:\s*([A-Za-z][A-Za-z0-9]+)\s*$")
METADATA_NAME = re.compile(
    r"(?ms)^metadata:\s*\n(?P<body>(?:^[ \t]+.*\n?)*)"
)
NAME_LINE = re.compile(r"(?m)^  name:\s*[\"']?([^\"'\s#]+)")
EXECUTION_MODES = {"simulated", "live-diagnostic"}
PLANES = ("platform", "runtimeHost", "modelPlane")
PLANE_NAMESPACES = {
    "platform": "default",
    "runtimeHost": "default",
    "modelPlane": "default",
}
MIB = 1024 * 1024
GIB = 1024 * MIB
TIGHT_CPU_MILLICORES = 1000
TIGHT_MEMORY_BYTES = 4 * GIB
REASON_CODES = (
    "CLUSTER_BASELINE_INVALID",
    "SERVER_DRY_RUN_FAILED",
    "DRY_RUN_OBJECT_PERSISTED",
    "CAPACITY_HEADROOM_NEGATIVE",
    "CAPACITY_MARGIN_TIGHT",
    "MIGRATION_IMAGE_NOT_ARTIFACT_BOUND",
    "EXTERNAL_REFERENCES_UNRESOLVED",
    "LIVE_PULL_NOT_VERIFIED",
    "DESTINATION_MIRROR_NOT_VERIFIED",
)
CONTROLS = {
    "commandPolicy": "server-side-dry-run-only",
    "rawManifestContentStored": False,
    "rawCommandOutputStored": False,
    "objectNamesStored": False,
    "secretValuesStored": False,
    "kubeconfigStored": False,
    "liveImagePullAttempted": False,
    "artifactAdmissionStateAdvanced": False,
    "cloudMutationAuthorized": False,
    "workloadActivationAuthorized": False,
    "deploymentAuthorized": False,
    "teardownAuthorized": False,
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
    "highAvailability": False,
    "rpoRtoVerified": False,
}
CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def list_value(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list):
        fail(code)
    return value


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_utc(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(code)
    return parsed


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        fail("sno_product_dry_run_file_unreadable")
    return f"sha256:{digest.hexdigest()}"


def read_text(path: Path, maximum_bytes: int = 2 * 1024 * 1024) -> str:
    try:
        if not path.is_file() or path.stat().st_size > maximum_bytes:
            fail("sno_product_dry_run_manifest_invalid")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        fail("sno_product_dry_run_manifest_invalid")


def candidate_digest(candidate: dict[str, Any]) -> str:
    digest = candidate.get("candidateDigest")
    unsigned = copy.deepcopy(candidate)
    unsigned.pop("candidateDigest", None)
    if (
        not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
        or digest != canonical_digest(unsigned)
    ):
        fail("sno_product_dry_run_candidate_invalid")
    envelope = object_value(
        candidate.get("nodeEnvelope"),
        "sno_product_dry_run_candidate_invalid",
    )
    peak = object_value(
        envelope.get("peakRequests"),
        "sno_product_dry_run_candidate_invalid",
    )
    if (
        candidate.get("profileId") != TRIAL_PROFILE_ID
        or candidate.get("targetClass") != "engineering-trial"
        or candidate.get("executionMode") != "source-only"
        or candidate.get("architecture") != "linux/amd64"
        or type(peak.get("cpuMillicores")) is not int
        or peak["cpuMillicores"] <= 0
        or type(peak.get("memoryMiB")) is not int
        or peak["memoryMiB"] <= 0
    ):
        fail("sno_product_dry_run_candidate_invalid")
    return digest


def local_contracts() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    candidate = load_json(CANDIDATE_PATH)
    lock = load_json(LOCK_PATH)
    validate_profile(profile, production)
    validate_production_isolation()
    candidate_digest(candidate)
    validate_lock(lock, candidate)
    return profile, candidate, lock


def decimal(value: str, code: str) -> Decimal:
    try:
        result = Decimal(value)
    except InvalidOperation:
        fail(code)
    if not result.is_finite() or result < 0:
        fail(code)
    return result


def cpu_millicores(value: Any) -> int:
    if value in (None, ""):
        return 0
    if not isinstance(value, str):
        fail("sno_product_dry_run_cpu_quantity_invalid")
    units = {
        "n": Decimal("0.000001"),
        "u": Decimal("0.001"),
        "m": Decimal(1),
    }
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([num]?)", value)
    if not match:
        fail("sno_product_dry_run_cpu_quantity_invalid")
    factor = units.get(match.group(2), Decimal(1000))
    return int(
        (decimal(match.group(1), "sno_product_dry_run_cpu_quantity_invalid") * factor)
        .to_integral_value(rounding=ROUND_CEILING)
    )


def memory_bytes(value: Any) -> int:
    if value in (None, ""):
        return 0
    if not isinstance(value, str):
        fail("sno_product_dry_run_memory_quantity_invalid")
    factors = {
        "": Decimal(1),
        "K": Decimal(1000),
        "M": Decimal(1000**2),
        "G": Decimal(1000**3),
        "T": Decimal(1000**4),
        "Ki": Decimal(1024),
        "Mi": Decimal(1024**2),
        "Gi": Decimal(1024**3),
        "Ti": Decimal(1024**4),
    }
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(Ki|Mi|Gi|Ti|K|M|G|T)?", value)
    if not match:
        fail("sno_product_dry_run_memory_quantity_invalid")
    return int(
        (
            decimal(
                match.group(1),
                "sno_product_dry_run_memory_quantity_invalid",
            )
            * factors[match.group(2) or ""]
        ).to_integral_value(rounding=ROUND_CEILING)
    )


def resource_pair(resources: Any) -> tuple[int, int]:
    if not isinstance(resources, dict):
        return 0, 0
    requests = resources.get("requests", {})
    if not isinstance(requests, dict):
        return 0, 0
    return cpu_millicores(requests.get("cpu")), memory_bytes(
        requests.get("memory")
    )


def pod_request(pod: dict[str, Any]) -> tuple[int, int]:
    spec = object_value(pod.get("spec"), "sno_product_dry_run_pod_invalid")
    app_cpu = 0
    app_memory = 0
    for container in list_value(
        spec.get("containers"), "sno_product_dry_run_pod_invalid"
    ):
        if not isinstance(container, dict):
            fail("sno_product_dry_run_pod_invalid")
        cpu, memory = resource_pair(container.get("resources"))
        app_cpu += cpu
        app_memory += memory
    init_cpu = 0
    init_memory = 0
    for container in spec.get("initContainers", []):
        if not isinstance(container, dict):
            fail("sno_product_dry_run_pod_invalid")
        cpu, memory = resource_pair(container.get("resources"))
        init_cpu = max(init_cpu, cpu)
        init_memory = max(init_memory, memory)
    overhead_cpu, overhead_memory = resource_pair(
        {"requests": spec.get("overhead", {})}
    )
    return (
        max(app_cpu, init_cpu) + overhead_cpu,
        max(app_memory, init_memory) + overhead_memory,
    )


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )


def run_checked(
    run: CommandRunner, command: list[str], code: str
) -> subprocess.CompletedProcess[str]:
    try:
        return run(command)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        fail(code)


def run_json(run: CommandRunner, command: list[str], code: str) -> Any:
    try:
        return json.loads(run_checked(run, command, code).stdout)
    except json.JSONDecodeError:
        fail(code)


def metadata_name(document: str) -> str:
    metadata = METADATA_NAME.search(document)
    if not metadata:
        fail("sno_product_dry_run_manifest_identity_invalid")
    name = NAME_LINE.search(metadata.group("body"))
    if not name:
        fail("sno_product_dry_run_manifest_identity_invalid")
    return name.group(1)


def secret_references(content: str) -> list[str]:
    names = set(SECRET_NAME.findall(content))
    lines = content.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("- "):
            stripped = stripped[2:].lstrip()
        if stripped not in {"secretKeyRef:", "secretRef:"}:
            continue
        parent_indent = len(line) - len(line.lstrip())
        for child in lines[index + 1 :]:
            if not child.strip():
                continue
            indent = len(child) - len(child.lstrip())
            if indent <= parent_indent:
                break
            match = re.match(r"\s*name:\s*[\"']?([^\"'\s#]+)", child)
            if match:
                names.add(match.group(1))
                break
    return sorted(names)


def analyze_manifest(
    plane: str,
    path: Path,
    locked_images: set[str],
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    content = read_text(path)
    documents = [item for item in DOCUMENT.split(content) if item.strip()]
    identities: list[tuple[str, str]] = []
    for document in documents:
        kind = RESOURCE_KIND.search(document)
        if not kind:
            fail("sno_product_dry_run_manifest_identity_invalid")
        identities.append((kind.group(1), metadata_name(document)))
    if len(identities) != len(set(identities)) or not identities:
        fail("sno_product_dry_run_manifest_identity_invalid")
    images = sorted(set(IMAGE.findall(content)))
    if not images or any(
        not re.fullmatch(r".+@sha256:[a-f0-9]{64}", image) for image in images
    ):
        fail("sno_product_dry_run_manifest_image_invalid")
    bound = sorted(set(images) & locked_images)
    unbound = sorted(set(images) - locked_images)
    secrets = secret_references(content)
    result = {
        "plane": plane,
        "namespaceDigest": canonical_digest(PLANE_NAMESPACES[plane]),
        "manifestDigest": file_digest(path),
        "objectCount": len(identities),
        "objectSetDigest": canonical_digest(sorted(identities)),
        "imageReferenceCount": len(images),
        "imageSetDigest": canonical_digest(images),
        "boundImageReferenceCount": len(bound),
        "unboundImageReferenceCount": len(unbound),
        "unboundImageSetDigest": canonical_digest(unbound),
        "secretReferenceCount": len(secrets),
        "secretReferenceSetDigest": canonical_digest(secrets),
        "serverDryRunAccepted": False,
        "acceptedObjectCount": 0,
        "noPersistenceObserved": False,
    }
    return result, identities


def capacity_snapshot(
    nodes: Any,
    pods: Any,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    node_items = object_value(
        nodes, "sno_product_dry_run_nodes_invalid"
    ).get("items")
    pod_items = object_value(pods, "sno_product_dry_run_pods_invalid").get(
        "items"
    )
    if not isinstance(node_items, list) or not isinstance(pod_items, list):
        fail("sno_product_dry_run_inventory_invalid")
    eligible: list[dict[str, Any]] = []
    for node in node_items:
        if not isinstance(node, dict):
            fail("sno_product_dry_run_nodes_invalid")
        status = object_value(
            node.get("status"), "sno_product_dry_run_nodes_invalid"
        )
        spec = node.get("spec", {})
        conditions = status.get("conditions", [])
        ready = any(
            isinstance(item, dict)
            and item.get("type") == "Ready"
            and item.get("status") == "True"
            for item in conditions
        )
        if (
            ready
            and isinstance(spec, dict)
            and spec.get("unschedulable") is not True
            and status.get("nodeInfo", {}).get("architecture") == "amd64"
        ):
            eligible.append(node)
    if not eligible:
        fail("sno_product_dry_run_no_eligible_node")
    node_names = {
        item.get("metadata", {}).get("name") for item in eligible
    }
    if None in node_names or len(node_names) != len(eligible):
        fail("sno_product_dry_run_nodes_invalid")
    allocatable_cpu = 0
    allocatable_memory = 0
    for node in eligible:
        allocatable = node["status"].get("allocatable", {})
        allocatable_cpu += cpu_millicores(allocatable.get("cpu"))
        allocatable_memory += memory_bytes(allocatable.get("memory"))
    existing_cpu = 0
    existing_memory = 0
    pod_identities: list[tuple[str, str]] = []
    for pod in pod_items:
        if not isinstance(pod, dict):
            fail("sno_product_dry_run_pods_invalid")
        spec = pod.get("spec", {})
        status = pod.get("status", {})
        if (
            not isinstance(spec, dict)
            or not isinstance(status, dict)
            or spec.get("nodeName") not in node_names
            or status.get("phase") in {"Succeeded", "Failed"}
        ):
            continue
        metadata = object_value(
            pod.get("metadata"), "sno_product_dry_run_pods_invalid"
        )
        namespace = metadata.get("namespace")
        name = metadata.get("name")
        if not isinstance(namespace, str) or not isinstance(name, str):
            fail("sno_product_dry_run_pods_invalid")
        pod_identities.append((namespace, name))
        cpu, memory = pod_request(pod)
        existing_cpu += cpu
        existing_memory += memory
    peak = candidate["nodeEnvelope"]["peakRequests"]
    candidate_cpu = peak["cpuMillicores"]
    candidate_memory = peak["memoryMiB"] * MIB
    headroom_cpu = allocatable_cpu - existing_cpu - candidate_cpu
    headroom_memory = allocatable_memory - existing_memory - candidate_memory
    positive = headroom_cpu >= 0 and headroom_memory >= 0
    tight = positive and (
        headroom_cpu < TIGHT_CPU_MILLICORES
        or headroom_memory < TIGHT_MEMORY_BYTES
    )
    return {
        "eligibleNodeCount": len(eligible),
        "nodeSetDigest": canonical_digest(sorted(node_names)),
        "observedPodCount": len(pod_identities),
        "podSetDigest": canonical_digest(sorted(pod_identities)),
        "allocatableCpuMillicores": allocatable_cpu,
        "allocatableMemoryBytes": allocatable_memory,
        "existingRequestedCpuMillicores": existing_cpu,
        "existingRequestedMemoryBytes": existing_memory,
        "candidatePeakCpuMillicores": candidate_cpu,
        "candidatePeakMemoryBytes": candidate_memory,
        "projectedHeadroomCpuMillicores": headroom_cpu,
        "projectedHeadroomMemoryBytes": headroom_memory,
        "projectedHeadroomMemoryMiB": int(
            (Decimal(headroom_memory) / Decimal(MIB)).to_integral_value(
                rounding=ROUND_FLOOR
            )
        ),
        "positiveProjectedHeadroom": positive,
        "capacityMarginTight": tight,
    }


def collect_snapshot(
    cluster_report: dict[str, Any],
    client: Path,
    kubeconfig: Path,
    manifests: dict[str, Path],
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    validate_cluster_assessment(cluster_report)
    if cluster_report["decision"]["status"] != "TRIAL_CLUSTER_OBSERVED":
        fail("sno_product_dry_run_cluster_not_observed")
    if (
        not client.is_file()
        or not client.stat().st_mode & 0o100
        or not kubeconfig.is_file()
    ):
        fail("sno_product_dry_run_tooling_invalid")
    _, candidate, lock = local_contracts()
    if set(manifests) != set(PLANES):
        fail("sno_product_dry_run_manifest_set_invalid")
    base = [str(client.resolve()), "--kubeconfig", str(kubeconfig.resolve())]
    nodes = run_json(
        run,
        [*base, "get", "nodes", "-o", "json"],
        "sno_product_dry_run_node_observation_failed",
    )
    pods = run_json(
        run,
        [*base, "get", "pods", "-A", "-o", "json"],
        "sno_product_dry_run_pod_observation_failed",
    )
    locked_images = {
        image["reference"]
        for artifact in lock["artifacts"]
        for image in [artifact["image"], *artifact["auxiliaryImages"]]
    }
    results: list[dict[str, Any]] = []
    for plane in PLANES:
        path = manifests[plane]
        result, identities = analyze_manifest(plane, path, locked_images)
        namespace = PLANE_NAMESPACES[plane]
        dry_run = run_checked(
            run,
            [
                *base,
                "apply",
                "--dry-run=server",
                "--validate=strict",
                "--namespace",
                namespace,
                "-f",
                str(path.resolve()),
            ],
            "sno_product_dry_run_apply_failed",
        )
        accepted_lines = [
            line.strip()
            for line in dry_run.stdout.splitlines()
            if line.strip().endswith("(server dry run)")
        ]
        result["acceptedObjectCount"] = len(accepted_lines)
        result["serverDryRunAccepted"] = (
            len(accepted_lines) == result["objectCount"]
        )
        persisted = False
        for kind, name in identities:
            observation = run_checked(
                run,
                [
                    *base,
                    "get",
                    kind,
                    name,
                    "--namespace",
                    namespace,
                    "--ignore-not-found",
                    "-o",
                    "name",
                ],
                "sno_product_dry_run_persistence_check_failed",
            )
            if observation.stdout.strip():
                persisted = True
        result["noPersistenceObserved"] = not persisted
        results.append(result)
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-diagnostic",
        "observedAt": utc_text(observed_at),
        "capacity": capacity_snapshot(nodes, pods, candidate),
        "manifests": results,
        "externalReferencesResolved": False,
        "liveImagePullVerified": False,
        "destinationMirrorVerified": False,
    }
    validate_snapshot(snapshot)
    return snapshot


def validate_manifest_result(value: Any) -> None:
    item = object_value(value, "sno_product_dry_run_manifest_result_invalid")
    exact_keys(
        item,
        {
            "plane",
            "namespaceDigest",
            "manifestDigest",
            "objectCount",
            "objectSetDigest",
            "imageReferenceCount",
            "imageSetDigest",
            "boundImageReferenceCount",
            "unboundImageReferenceCount",
            "unboundImageSetDigest",
            "secretReferenceCount",
            "secretReferenceSetDigest",
            "serverDryRunAccepted",
            "acceptedObjectCount",
            "noPersistenceObserved",
        },
        "sno_product_dry_run_manifest_result_keys_invalid",
    )
    count_keys = (
        "objectCount",
        "imageReferenceCount",
        "boundImageReferenceCount",
        "unboundImageReferenceCount",
        "secretReferenceCount",
        "acceptedObjectCount",
    )
    digest_keys = (
        "namespaceDigest",
        "manifestDigest",
        "objectSetDigest",
        "imageSetDigest",
        "unboundImageSetDigest",
        "secretReferenceSetDigest",
    )
    if (
        item["plane"] not in PLANES
        or any(type(item[key]) is not int or item[key] < 0 for key in count_keys)
        or item["objectCount"] <= 0
        or item["imageReferenceCount"] <= 0
        or any(not DIGEST.fullmatch(str(item[key])) for key in digest_keys)
        or item["imageReferenceCount"]
        != item["boundImageReferenceCount"]
        + item["unboundImageReferenceCount"]
        or type(item["serverDryRunAccepted"]) is not bool
        or type(item["noPersistenceObserved"]) is not bool
        or item["serverDryRunAccepted"]
        != (item["acceptedObjectCount"] == item["objectCount"])
    ):
        fail("sno_product_dry_run_manifest_result_invalid")


def validate_capacity(value: Any) -> None:
    capacity = object_value(value, "sno_product_dry_run_capacity_invalid")
    exact_keys(
        capacity,
        {
            "eligibleNodeCount",
            "nodeSetDigest",
            "observedPodCount",
            "podSetDigest",
            "allocatableCpuMillicores",
            "allocatableMemoryBytes",
            "existingRequestedCpuMillicores",
            "existingRequestedMemoryBytes",
            "candidatePeakCpuMillicores",
            "candidatePeakMemoryBytes",
            "projectedHeadroomCpuMillicores",
            "projectedHeadroomMemoryBytes",
            "projectedHeadroomMemoryMiB",
            "positiveProjectedHeadroom",
            "capacityMarginTight",
        },
        "sno_product_dry_run_capacity_keys_invalid",
    )
    nonnegative = (
        "eligibleNodeCount",
        "observedPodCount",
        "allocatableCpuMillicores",
        "allocatableMemoryBytes",
        "existingRequestedCpuMillicores",
        "existingRequestedMemoryBytes",
        "candidatePeakCpuMillicores",
        "candidatePeakMemoryBytes",
    )
    if (
        any(type(capacity[key]) is not int or capacity[key] < 0 for key in nonnegative)
        or any(
            type(capacity[key]) is not int
            for key in (
                "projectedHeadroomCpuMillicores",
                "projectedHeadroomMemoryBytes",
                "projectedHeadroomMemoryMiB",
            )
        )
        or any(
            not DIGEST.fullmatch(str(capacity[key]))
            for key in ("nodeSetDigest", "podSetDigest")
        )
        or capacity["eligibleNodeCount"] <= 0
        or type(capacity["positiveProjectedHeadroom"]) is not bool
        or type(capacity["capacityMarginTight"]) is not bool
        or capacity["projectedHeadroomCpuMillicores"]
        != capacity["allocatableCpuMillicores"]
        - capacity["existingRequestedCpuMillicores"]
        - capacity["candidatePeakCpuMillicores"]
        or capacity["projectedHeadroomMemoryBytes"]
        != capacity["allocatableMemoryBytes"]
        - capacity["existingRequestedMemoryBytes"]
        - capacity["candidatePeakMemoryBytes"]
        or capacity["positiveProjectedHeadroom"]
        != (
            capacity["projectedHeadroomCpuMillicores"] >= 0
            and capacity["projectedHeadroomMemoryBytes"] >= 0
        )
        or capacity["capacityMarginTight"]
        != (
            capacity["positiveProjectedHeadroom"]
            and (
                capacity["projectedHeadroomCpuMillicores"]
                < TIGHT_CPU_MILLICORES
                or capacity["projectedHeadroomMemoryBytes"] < TIGHT_MEMORY_BYTES
            )
        )
    ):
        fail("sno_product_dry_run_capacity_invalid")


def validate_snapshot(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "executionMode",
            "observedAt",
            "capacity",
            "manifests",
            "externalReferencesResolved",
            "liveImagePullVerified",
            "destinationMirrorVerified",
        },
        "sno_product_dry_run_snapshot_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_product_dry_run_snapshot_identity_invalid")
    parse_utc(value["observedAt"], "sno_product_dry_run_snapshot_time_invalid")
    validate_capacity(value["capacity"])
    manifests = list_value(
        value["manifests"], "sno_product_dry_run_manifest_results_invalid"
    )
    for result in manifests:
        validate_manifest_result(result)
    if [item["plane"] for item in manifests] != list(PLANES):
        fail("sno_product_dry_run_manifest_results_invalid")
    if any(
        value[key] is not False
        for key in (
            "externalReferencesResolved",
            "liveImagePullVerified",
            "destinationMirrorVerified",
        )
    ):
        fail("sno_product_dry_run_snapshot_invalid")


def aggregate(snapshot: dict[str, Any]) -> dict[str, Any]:
    manifests = snapshot["manifests"]
    return {
        "manifestCount": len(manifests),
        "objectCount": sum(item["objectCount"] for item in manifests),
        "acceptedObjectCount": sum(
            item["acceptedObjectCount"] for item in manifests
        ),
        "allServerDryRunsAccepted": all(
            item["serverDryRunAccepted"] for item in manifests
        ),
        "allNonPersistent": all(
            item["noPersistenceObserved"] for item in manifests
        ),
        "imageReferenceCount": sum(
            item["imageReferenceCount"] for item in manifests
        ),
        "boundImageReferenceCount": sum(
            item["boundImageReferenceCount"] for item in manifests
        ),
        "unboundImageReferenceCount": sum(
            item["unboundImageReferenceCount"] for item in manifests
        ),
        "allImagesArtifactBound": all(
            item["unboundImageReferenceCount"] == 0 for item in manifests
        ),
        "secretReferenceCount": sum(
            item["secretReferenceCount"] for item in manifests
        ),
        "externalReferencesResolved": snapshot["externalReferencesResolved"],
        "liveImagePullVerified": snapshot["liveImagePullVerified"],
        "destinationMirrorVerified": snapshot["destinationMirrorVerified"],
    }


def decision_for(
    cluster_status: str,
    capacity: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    blocking: list[str] = []
    if cluster_status != "TRIAL_CLUSTER_OBSERVED":
        blocking.append("CLUSTER_BASELINE_INVALID")
    if not result["allServerDryRunsAccepted"]:
        blocking.append("SERVER_DRY_RUN_FAILED")
    if not result["allNonPersistent"]:
        blocking.append("DRY_RUN_OBJECT_PERSISTED")
    if not capacity["positiveProjectedHeadroom"]:
        blocking.append("CAPACITY_HEADROOM_NEGATIVE")
    gaps: list[str] = []
    if capacity["capacityMarginTight"]:
        gaps.append("CAPACITY_MARGIN_TIGHT")
    if not result["allImagesArtifactBound"]:
        gaps.append("MIGRATION_IMAGE_NOT_ARTIFACT_BOUND")
    if not result["externalReferencesResolved"]:
        gaps.append("EXTERNAL_REFERENCES_UNRESOLVED")
    if not result["liveImagePullVerified"]:
        gaps.append("LIVE_PULL_NOT_VERIFIED")
    if not result["destinationMirrorVerified"]:
        gaps.append("DESTINATION_MIRROR_NOT_VERIFIED")
    reasons = blocking + gaps
    if blocking:
        return {
            "status": "BLOCKED",
            "reasonCodes": reasons,
            "nextAction": "reconcile-dry-run-or-capacity",
        }
    return {
        "status": "SERVER_DRY_RUN_OBSERVED_WITH_GAPS",
        "reasonCodes": reasons,
        "nextAction": "bind-images-and-resolve-external-references",
    }


def build_assessment(
    snapshot: dict[str, Any],
    cluster_report: dict[str, Any],
    assessment_id: str,
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    validate_cluster_assessment(cluster_report)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_product_dry_run_assessment_id_invalid")
    profile, candidate, lock = local_contracts()
    result = aggregate(snapshot)
    cluster_status = cluster_report["decision"]["status"]
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "assessmentId": assessment_id,
        "generatedAt": snapshot["observedAt"],
        "targetClass": "engineering-trial",
        "executionMode": snapshot["executionMode"],
        "bindings": {
            "profileId": TRIAL_PROFILE_ID,
            "profileDigest": canonical_digest(profile),
            "clusterAssessmentId": cluster_report["assessmentId"],
            "clusterReportDigest": cluster_report["reportDigest"],
            "clusterDecisionStatus": cluster_status,
            "artifactSetId": lock["artifactSetId"],
            "artifactSetDigest": lock["artifactSetDigest"],
            "workloadCandidateId": candidate["candidateId"],
            "workloadCandidateDigest": candidate["candidateDigest"],
        },
        "capacity": copy.deepcopy(snapshot["capacity"]),
        "manifests": copy.deepcopy(snapshot["manifests"]),
        "aggregate": result,
        "decision": decision_for(
            cluster_status, snapshot["capacity"], result
        ),
        "controls": copy.deepcopy(CONTROLS),
        "claims": copy.deepcopy(CLAIMS),
    }
    report["reportDigest"] = canonical_digest(report)
    validate_assessment(report)
    return report


def validate_aggregate(value: Any, manifests: list[dict[str, Any]]) -> None:
    result = object_value(value, "sno_product_dry_run_aggregate_invalid")
    count_keys = (
        "manifestCount",
        "objectCount",
        "acceptedObjectCount",
        "imageReferenceCount",
        "boundImageReferenceCount",
        "unboundImageReferenceCount",
        "secretReferenceCount",
    )
    bool_keys = (
        "allServerDryRunsAccepted",
        "allNonPersistent",
        "allImagesArtifactBound",
        "externalReferencesResolved",
        "liveImagePullVerified",
        "destinationMirrorVerified",
    )
    if (
        any(type(result.get(key)) is not int or result[key] < 0 for key in count_keys)
        or any(type(result.get(key)) is not bool for key in bool_keys)
        or result["externalReferencesResolved"]
        or result["liveImagePullVerified"]
        or result["destinationMirrorVerified"]
    ):
        fail("sno_product_dry_run_aggregate_invalid")
    expected = aggregate(
        {
            "manifests": manifests,
            "externalReferencesResolved": result.get(
                "externalReferencesResolved"
            ),
            "liveImagePullVerified": result.get("liveImagePullVerified"),
            "destinationMirrorVerified": result.get(
                "destinationMirrorVerified"
            ),
        }
    )
    if result != expected:
        fail("sno_product_dry_run_aggregate_invalid")


def validate_assessment(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "assessmentId",
            "generatedAt",
            "targetClass",
            "executionMode",
            "bindings",
            "capacity",
            "manifests",
            "aggregate",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_product_dry_run_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_product_dry_run_report_identity_invalid")
    parse_utc(value["generatedAt"], "sno_product_dry_run_report_time_invalid")
    profile, candidate, lock = local_contracts()
    bindings = object_value(
        value["bindings"], "sno_product_dry_run_bindings_invalid"
    )
    exact_keys(
        bindings,
        {
            "profileId",
            "profileDigest",
            "clusterAssessmentId",
            "clusterReportDigest",
            "clusterDecisionStatus",
            "artifactSetId",
            "artifactSetDigest",
            "workloadCandidateId",
            "workloadCandidateDigest",
        },
        "sno_product_dry_run_bindings_keys_invalid",
    )
    if (
        bindings["profileId"] != TRIAL_PROFILE_ID
        or bindings["profileDigest"] != canonical_digest(profile)
        or not isinstance(bindings["clusterAssessmentId"], str)
        or not DIGEST.fullmatch(str(bindings["clusterReportDigest"]))
        or bindings["clusterDecisionStatus"] != "TRIAL_CLUSTER_OBSERVED"
        or bindings["artifactSetId"] != lock["artifactSetId"]
        or bindings["artifactSetDigest"] != lock["artifactSetDigest"]
        or bindings["workloadCandidateId"] != candidate["candidateId"]
        or bindings["workloadCandidateDigest"] != candidate["candidateDigest"]
    ):
        fail("sno_product_dry_run_bindings_invalid")
    validate_capacity(value["capacity"])
    manifests = list_value(
        value["manifests"], "sno_product_dry_run_manifests_invalid"
    )
    for manifest in manifests:
        validate_manifest_result(manifest)
    if [item["plane"] for item in manifests] != list(PLANES):
        fail("sno_product_dry_run_manifests_invalid")
    validate_aggregate(value["aggregate"], manifests)
    decision = object_value(
        value["decision"], "sno_product_dry_run_decision_invalid"
    )
    if (
        decision
        != decision_for(
            bindings["clusterDecisionStatus"],
            value["capacity"],
            value["aggregate"],
        )
        or any(reason not in REASON_CODES for reason in decision["reasonCodes"])
    ):
        fail("sno_product_dry_run_decision_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_product_dry_run_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_product_dry_run_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_product_dry_run_report_digest_invalid")


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except FileExistsError:
        fail("sno_product_dry_run_output_exists")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--cluster-report", type=Path, required=True)
    collect.add_argument("--client", type=Path, required=True)
    collect.add_argument("--kubeconfig", type=Path, required=True)
    collect.add_argument("--platform-manifest", type=Path, required=True)
    collect.add_argument("--runtime-manifest", type=Path, required=True)
    collect.add_argument("--model-manifest", type=Path, required=True)
    collect.add_argument("--assessment-id", required=True)
    collect.add_argument("--output", type=Path, required=True)
    assess = commands.add_parser("assess")
    assess.add_argument("--snapshot", type=Path, required=True)
    assess.add_argument("--cluster-report", type=Path, required=True)
    assess.add_argument("--assessment-id", required=True)
    assess.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "collect":
        cluster = load_json(args.cluster_report)
        snapshot = collect_snapshot(
            cluster,
            args.client,
            args.kubeconfig,
            {
                "platform": args.platform_manifest,
                "runtimeHost": args.runtime_manifest,
                "modelPlane": args.model_manifest,
            },
            datetime.now(timezone.utc),
        )
        report = build_assessment(snapshot, cluster, args.assessment_id)
        write_json_create_only(args.output, report)
    elif args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_product_dry_run_live_snapshot_requires_collect")
        cluster = load_json(args.cluster_report)
        report = build_assessment(snapshot, cluster, args.assessment_id)
        write_json_create_only(args.output, report)
    else:
        report = load_json(args.report)
        validate_assessment(report)
    print(
        "sno_product_dry_run_valid "
        f"digest={report['reportDigest']} "
        f"status={report['decision']['status']} "
        f"objects={report['aggregate']['acceptedObjectCount']}/"
        f"{report['aggregate']['objectCount']} "
        f"headroomCpuMillicores="
        f"{report['capacity']['projectedHeadroomCpuMillicores']} "
        f"headroomMemoryMiB="
        f"{report['capacity']['projectedHeadroomMemoryMiB']} "
        "deploymentAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
