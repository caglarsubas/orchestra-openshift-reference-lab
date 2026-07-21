#!/usr/bin/env python3
"""Validate the immutable three-plane release intake used by the lab."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:  # Direct `python scripts/...` execution.
    from validate_repository import ROOT, canonical_digest, load_json


DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMMUTABLE_REF = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
RELEASE_SET_ID = re.compile(r"^orchestra-reference-lab-[a-z0-9][a-z0-9.-]*$")
PROFILE_ID = "orchestra-ocp-4.20-amd64-v1"
PROFILE_DIGEST = "sha256:6778ce06451fdde0f3c49bce15fb610919b3fc2f3d9f7a4854640d64d448b6c4"
CONTRACTS = {
    "modelWorkloadSurface": "orchestra-model-plane-workload-v1",
    "runtimeEdgeOverload": "orchestra-runtime-edge-overload-v1",
}
PLANE_CONTRACTS = {
    "platform": {
        "repository": "caglarsubas/agent-hook-v2",
        "release": re.compile(r"^platform-v\d+\.\d+\.\d+-rc\.\d+$"),
        "roles": {
            "platform-image-ubi9",
            "tools-image-ubi9",
            "certification-runner-image-ubi9",
            "helm-chart",
        },
        "deploymentRole": "platform-image-ubi9",
    },
    "runtimeHost": {
        "repository": "prometa-ai/orchestra-python-sdk",
        "release": re.compile(r"^v\d+\.\d+\.\d+$"),
        "roles": {"runtime-host-image-ubi9", "helm-chart"},
        "deploymentRole": "runtime-host-image-ubi9",
    },
    "modelPlane": {
        "repository": "caglarsubas/llm_inference_engine",
        "release": re.compile(r"^v\d+\.\d+\.\d+$"),
        "roles": {"inference-engine-image-ubi9", "helm-chart"},
        "deploymentRole": "inference-engine-image-ubi9",
    },
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def object_value(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(code)
    return value


def nonempty_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(code)
    return value


def validate_release_set(value: dict[str, Any]) -> str:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "releaseSetId",
            "createdAt",
            "profile",
            "contracts",
            "planes",
            "certificationRunner",
        },
        "release_set_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "orchestra.cross-plane.release-set.v1"
        or not RELEASE_SET_ID.fullmatch(str(value["releaseSetId"]))
    ):
        fail("release_set_identity_invalid")
    try:
        created_at = datetime.fromisoformat(
            nonempty_string(value["createdAt"], "release_set_created_at_invalid").replace(
                "Z", "+00:00"
            )
        )
    except ValueError:
        fail("release_set_created_at_invalid")
    if created_at.tzinfo is None:
        fail("release_set_created_at_invalid")

    profile = object_value(value["profile"], "release_set_profile_invalid")
    exact_keys(profile, {"id", "digest"}, "release_set_profile_keys_invalid")
    if profile != {"id": PROFILE_ID, "digest": PROFILE_DIGEST}:
        fail("release_set_profile_invalid")
    if value["contracts"] != CONTRACTS:
        fail("release_set_contracts_invalid")

    raw_planes = value["planes"]
    if not isinstance(raw_planes, list) or len(raw_planes) != len(PLANE_CONTRACTS):
        fail("release_set_planes_incomplete")
    planes: dict[str, dict[str, Any]] = {}
    for raw_plane in raw_planes:
        plane = object_value(raw_plane, "release_set_plane_invalid")
        exact_keys(
            plane,
            {"plane", "release", "source", "deploymentImage", "subjects"},
            "release_set_plane_keys_invalid",
        )
        name = nonempty_string(plane["plane"], "release_set_plane_name_invalid")
        contract = PLANE_CONTRACTS.get(name)
        if contract is None or name in planes:
            fail("release_set_plane_name_invalid")
        release = nonempty_string(plane["release"], "release_set_release_invalid")
        if not contract["release"].fullmatch(release):
            fail(f"release_set_release_invalid:{name}")
        source = object_value(plane["source"], "release_set_source_invalid")
        exact_keys(source, {"repository", "revision"}, "release_set_source_keys_invalid")
        if (
            source["repository"] != contract["repository"]
            or not REVISION.fullmatch(str(source["revision"]))
        ):
            fail(f"release_set_source_invalid:{name}")

        subjects = plane["subjects"]
        if not isinstance(subjects, list) or not subjects:
            fail(f"release_set_subjects_invalid:{name}")
        by_role: dict[str, str] = {}
        for raw_subject in subjects:
            subject = object_value(raw_subject, "release_set_subject_invalid")
            exact_keys(subject, {"role", "ref"}, "release_set_subject_keys_invalid")
            role = nonempty_string(subject["role"], "release_set_subject_role_invalid")
            ref = nonempty_string(subject["ref"], "release_set_subject_ref_invalid")
            if role in by_role or not IMMUTABLE_REF.fullmatch(ref):
                fail(f"release_set_subject_invalid:{name}")
            by_role[role] = ref
        if set(by_role) != contract["roles"] or len(set(by_role.values())) != len(
            by_role
        ):
            fail(f"release_set_subject_roles_invalid:{name}")
        deployment_image = nonempty_string(
            plane["deploymentImage"], "release_set_deployment_image_invalid"
        )
        if (
            not IMMUTABLE_REF.fullmatch(deployment_image)
            or deployment_image != by_role[contract["deploymentRole"]]
        ):
            fail(f"release_set_deployment_image_invalid:{name}")
        planes[name] = plane
    if set(planes) != set(PLANE_CONTRACTS):
        fail("release_set_planes_incomplete")

    runner = object_value(
        value["certificationRunner"], "release_set_runner_invalid"
    )
    exact_keys(
        runner,
        {
            "release",
            "source",
            "image",
            "toolchainDigest",
            "baseImage",
            "architecture",
        },
        "release_set_runner_keys_invalid",
    )
    runner_source = object_value(
        runner["source"], "release_set_runner_source_invalid"
    )
    exact_keys(
        runner_source,
        {"repository", "revision"},
        "release_set_runner_source_keys_invalid",
    )
    platform = planes["platform"]
    platform_runner = next(
        subject["ref"]
        for subject in platform["subjects"]
        if subject["role"] == "certification-runner-image-ubi9"
    )
    if (
        runner["release"] != platform["release"]
        or runner_source != platform["source"]
        or runner["image"] != platform_runner
        or not IMMUTABLE_REF.fullmatch(str(runner["image"]))
        or not DIGEST.fullmatch(str(runner["toolchainDigest"]))
        or runner["baseImage"] != "ubi9"
        or runner["architecture"] != "linux/amd64"
    ):
        fail("release_set_runner_invalid")
    return canonical_digest(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=ROOT / "config" / "cross-plane-release-set.lock.json",
    )
    args = parser.parse_args(argv)
    value = load_json(args.path.resolve())
    print(f"release_set_valid digest={validate_release_set(value)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
