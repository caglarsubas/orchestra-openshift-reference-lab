#!/usr/bin/env python3
"""Observe strict OpenShift admission of materialized SNO dependencies."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.materialize_sno_trial_dependency_manifests import (
        load_json,
        parse_utc,
        restricted_path,
        validate_materialized_directory,
    )
    from scripts.sno_trial_cluster_observation import (
        validate_assessment as validate_cluster_assessment,
    )
    from scripts.validate_repository import ROOT, canonical_digest
    from scripts.validate_sno_trial_dependency_manifests import (
        RESOURCE_FILES,
        load_validated_candidate,
    )
except ModuleNotFoundError:
    from materialize_sno_trial_dependency_manifests import (
        load_json,
        parse_utc,
        restricted_path,
        validate_materialized_directory,
    )
    from sno_trial_cluster_observation import (
        validate_assessment as validate_cluster_assessment,
    )
    from validate_repository import ROOT, canonical_digest
    from validate_sno_trial_dependency_manifests import (
        RESOURCE_FILES,
        load_validated_candidate,
    )


KIND = "orchestra.openshift.sno-trial-dependency-server-dry-run.v1"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
MAX_AGE = timedelta(hours=1)
REASON_ORDER = (
    "SERVER_DRY_RUN_REJECTED",
    "DRY_RUN_OBJECT_STATE_CHANGED",
    "LIVE_IMAGE_PULL_NOT_VERIFIED",
    "LIVE_DEPENDENCY_CONNECTIVITY_MISSING",
    "ACTIVATION_REVIEW_MISSING",
)
CONTROLS = {
    "scope": "sno-engineering-trial-dependency-api-admission-only",
    "commandPolicy": "get-and-server-side-dry-run-only",
    "strictFieldValidation": True,
    "rawManifestContentStored": False,
    "rawCommandOutputStored": False,
    "objectNamesStored": False,
    "secretValuesObserved": False,
    "secretValuesStored": False,
    "serverSideDryRunExecuted": True,
    "objectPersistenceObserved": False,
    "liveImagePullAttempted": False,
    "connectivityVerified": False,
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
    "highAvailability": False,
    "rpoRtoVerified": False,
}
CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def private_regular_file(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        fail(code)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o077
    ):
        fail(code)


def restricted_report(path: Path, code: str) -> dict[str, Any]:
    private_regular_file(path, code)
    try:
        path.resolve(strict=True).relative_to((ROOT / "restricted").resolve())
    except (OSError, ValueError):
        fail(code)
    return load_json(path)


def executable_file(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        fail(code)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & 0o100
        or metadata.st_mode & 0o022
    ):
        fail(code)


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def run_checked(run: CommandRunner, command: list[str], code: str) -> str:
    try:
        completed = run(command)
    except (OSError, subprocess.SubprocessError):
        fail(code)
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout.encode("utf-8")) > 2 * 1024 * 1024
    ):
        fail(code)
    return completed.stdout


def resource_identity(resource: dict[str, Any]) -> tuple[str, str, str | None, str]:
    metadata = resource.get("metadata")
    if (
        not isinstance(resource.get("apiVersion"), str)
        or not isinstance(resource.get("kind"), str)
        or not isinstance(metadata, dict)
        or not isinstance(metadata.get("name"), str)
    ):
        fail("sno_dependency_dry_run_resource_invalid")
    namespace = metadata.get("namespace")
    if namespace is not None and not isinstance(namespace, str):
        fail("sno_dependency_dry_run_resource_invalid")
    if resource["kind"] == "Secret":
        fail("sno_dependency_dry_run_secret_forbidden")
    return resource["apiVersion"], resource["kind"], namespace, metadata["name"]


def state_projection(
    raw: str, expected: tuple[str, str, str | None, str]
) -> dict[str, Any]:
    if not raw.strip():
        return {"exists": False, "identityDigest": None, "versionDigest": None}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        fail("sno_dependency_dry_run_state_invalid")
    api_version, kind, namespace, name = resource_identity(value)
    if (api_version, kind, namespace, name) != expected:
        fail("sno_dependency_dry_run_state_invalid")
    metadata = value["metadata"]
    version = {
        "uid": metadata.get("uid"),
        "resourceVersion": metadata.get("resourceVersion"),
        "generation": metadata.get("generation"),
        "deletionTimestamp": metadata.get("deletionTimestamp"),
    }
    if (
        not isinstance(version["uid"], str)
        or not isinstance(version["resourceVersion"], str)
        or version["generation"] is not None
        and type(version["generation"]) is not int
        or version["deletionTimestamp"] is not None
        and not isinstance(version["deletionTimestamp"], str)
    ):
        fail("sno_dependency_dry_run_state_invalid")
    return {
        "exists": True,
        "identityDigest": canonical_digest(
            {
                "apiVersion": api_version,
                "kind": kind,
                "namespace": namespace,
                "name": name,
            }
        ),
        "versionDigest": canonical_digest(version),
    }


def get_command(
    base: list[str], identity: tuple[str, str, str | None, str]
) -> list[str]:
    _, kind, namespace, name = identity
    command = [*base, "get", kind, name]
    if namespace is not None:
        command.extend(["--namespace", namespace])
    command.extend(["--ignore-not-found", "--output", "json"])
    return command


def validate_prerequisites(
    cluster_report: dict[str, Any],
    receipt: dict[str, Any],
    observed_at: datetime,
) -> None:
    validate_cluster_assessment(cluster_report)
    if observed_at.tzinfo is None:
        fail("sno_dependency_dry_run_time_invalid")
    current = observed_at.astimezone(timezone.utc)
    cluster_at = parse_utc(
        cluster_report["generatedAt"], "sno_dependency_dry_run_cluster_time_invalid"
    )
    materialized_at = parse_utc(
        receipt["materializedAt"],
        "sno_dependency_dry_run_materialization_time_invalid",
    )
    if (
        cluster_report["executionMode"] != "live-diagnostic"
        or cluster_report["decision"]["status"] != "TRIAL_CLUSTER_OBSERVED"
        or current < cluster_at
        or current < materialized_at
        or current - cluster_at > MAX_AGE
        or current - materialized_at > MAX_AGE
    ):
        fail("sno_dependency_dry_run_prerequisite_not_ready")


def collect_snapshot(
    cluster_report: dict[str, Any],
    client: Path,
    kubeconfig: Path,
    directory: Path,
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    executable_file(client, "sno_dependency_dry_run_tooling_invalid")
    private_regular_file(kubeconfig, "sno_dependency_dry_run_tooling_invalid")
    resolved = restricted_path(
        directory, existing=True, code="sno_dependency_dry_run_directory_invalid"
    )
    receipt = validate_materialized_directory(resolved)
    validate_prerequisites(cluster_report, receipt, observed_at)
    base = [str(client.resolve()), "--kubeconfig", str(kubeconfig.resolve())]
    results: list[dict[str, Any]] = []
    for filename in RESOURCE_FILES:
        path = resolved / filename
        resource = load_json(path)
        identity = resource_identity(resource)
        before = state_projection(
            run_checked(
                run,
                get_command(base, identity),
                "sno_dependency_dry_run_state_observation_failed",
            ),
            identity,
        )
        output = run_checked(
            run,
            [
                *base,
                "apply",
                "--dry-run=server",
                "--validate=strict",
                "--output",
                "json",
                "--filename",
                str(path.resolve()),
            ],
            "sno_dependency_dry_run_apply_failed",
        )
        try:
            accepted = json.loads(output)
        except json.JSONDecodeError:
            fail("sno_dependency_dry_run_apply_output_invalid")
        accepted_identity = resource_identity(accepted)
        after = state_projection(
            run_checked(
                run,
                get_command(base, identity),
                "sno_dependency_dry_run_state_observation_failed",
            ),
            identity,
        )
        results.append(
            {
                "file": filename,
                "apiVersionDigest": canonical_digest(identity[0]),
                "kindDigest": canonical_digest(identity[1]),
                "namespaceDigest": (
                    canonical_digest(identity[2]) if identity[2] is not None else None
                ),
                "nameDigest": canonical_digest(identity[3]),
                "manifestDigest": canonical_digest(resource),
                "acceptedObjectDigest": canonical_digest(accepted),
                "preexisting": before["exists"],
                "serverDryRunAccepted": accepted_identity == identity,
                "objectStateUnchanged": before == after,
            }
        )
    return {
        "executionMode": "live-server-dry-run",
        "observedAt": utc_text(observed_at),
        "bindings": {
            "clusterObservationId": cluster_report["assessmentId"],
            "clusterObservationDigest": cluster_report["reportDigest"],
            "materializationId": receipt["materializationId"],
            "materializationDigest": receipt["receiptDigest"],
            "candidateId": receipt["bindings"]["candidateId"],
            "candidateDigest": receipt["bindings"]["candidateDigest"],
            "materializedManifestSetDigest": receipt["outputs"][
                "materializedManifestSetDigest"
            ],
        },
        "resources": results,
    }


def decision_for(resources: list[dict[str, Any]]) -> dict[str, Any]:
    blocking: list[str] = []
    if not all(item["serverDryRunAccepted"] for item in resources):
        blocking.append("SERVER_DRY_RUN_REJECTED")
    if not all(item["objectStateUnchanged"] for item in resources):
        blocking.append("DRY_RUN_OBJECT_STATE_CHANGED")
    reasons = [
        *blocking,
        *(
            [
                "LIVE_IMAGE_PULL_NOT_VERIFIED",
                "LIVE_DEPENDENCY_CONNECTIVITY_MISSING",
                "ACTIVATION_REVIEW_MISSING",
            ]
        ),
    ]
    return {
        "status": ("SERVER_DRY_RUN_OBSERVED_WITH_GAPS" if not blocking else "BLOCKED"),
        "reasonCodes": reasons,
    }


def validate_resource(value: Any, filename: str) -> dict[str, Any]:
    item = exact_keys(
        value,
        {
            "file",
            "apiVersionDigest",
            "kindDigest",
            "namespaceDigest",
            "nameDigest",
            "manifestDigest",
            "acceptedObjectDigest",
            "preexisting",
            "serverDryRunAccepted",
            "objectStateUnchanged",
        },
        "sno_dependency_dry_run_resource_result_invalid",
    )
    if (
        item["file"] != filename
        or any(
            not DIGEST.fullmatch(str(item[key]))
            for key in (
                "apiVersionDigest",
                "kindDigest",
                "nameDigest",
                "manifestDigest",
                "acceptedObjectDigest",
            )
        )
        or item["namespaceDigest"] is not None
        and not DIGEST.fullmatch(str(item["namespaceDigest"]))
        or any(
            type(item[key]) is not bool
            for key in (
                "preexisting",
                "serverDryRunAccepted",
                "objectStateUnchanged",
            )
        )
    ):
        fail("sno_dependency_dry_run_resource_result_invalid")
    return item


def validate_bindings(value: Any) -> dict[str, Any]:
    bindings = exact_keys(
        value,
        {
            "clusterObservationId",
            "clusterObservationDigest",
            "materializationId",
            "materializationDigest",
            "candidateId",
            "candidateDigest",
            "materializedManifestSetDigest",
        },
        "sno_dependency_dry_run_bindings_invalid",
    )
    candidate = load_validated_candidate()
    if (
        any(
            not IDENTIFIER.fullmatch(str(bindings[key]))
            for key in (
                "clusterObservationId",
                "materializationId",
                "candidateId",
            )
        )
        or bindings["candidateId"] != candidate["candidateId"]
        or bindings["candidateDigest"] != candidate["candidateDigest"]
        or any(
            not DIGEST.fullmatch(str(bindings[key]))
            for key in (
                "clusterObservationDigest",
                "materializationDigest",
                "candidateDigest",
                "materializedManifestSetDigest",
            )
        )
    ):
        fail("sno_dependency_dry_run_bindings_invalid")
    return bindings


def build_assessment(
    snapshot: dict[str, Any], assessment_id: str, assessed_at: datetime
) -> dict[str, Any]:
    if not IDENTIFIER.fullmatch(assessment_id) or assessed_at.tzinfo is None:
        fail("sno_dependency_dry_run_assessment_invalid")
    bindings = validate_bindings(snapshot.get("bindings"))
    resources = snapshot.get("resources")
    if (
        snapshot.get("executionMode") != "live-server-dry-run"
        or not isinstance(resources, list)
        or len(resources) != len(RESOURCE_FILES)
    ):
        fail("sno_dependency_dry_run_snapshot_invalid")
    validated = [
        validate_resource(item, filename)
        for item, filename in zip(resources, RESOURCE_FILES, strict=True)
    ]
    observed_at = parse_utc(
        snapshot["observedAt"], "sno_dependency_dry_run_time_invalid"
    )
    if assessed_at.astimezone(timezone.utc) < observed_at:
        fail("sno_dependency_dry_run_time_invalid")
    report = {
        "schemaVersion": 1,
        "kind": KIND,
        "assessmentId": assessment_id,
        "profileId": PROFILE_ID,
        "targetClass": "engineering-trial",
        "executionMode": "live-server-dry-run",
        "observedAt": utc_text(observed_at),
        "assessedAt": utc_text(assessed_at),
        "bindings": copy.deepcopy(bindings),
        "aggregate": {
            "resourceCount": len(validated),
            "acceptedCount": sum(item["serverDryRunAccepted"] for item in validated),
            "unchangedCount": sum(item["objectStateUnchanged"] for item in validated),
            "resourceResultSetDigest": canonical_digest(validated),
        },
        "resources": copy.deepcopy(validated),
        "decision": decision_for(validated),
        "controls": copy.deepcopy(CONTROLS),
        "claims": copy.deepcopy(CLAIMS),
    }
    report["reportDigest"] = canonical_digest(report)
    validate_assessment(report)
    return report


def validate_assessment(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "assessmentId",
            "profileId",
            "targetClass",
            "executionMode",
            "observedAt",
            "assessedAt",
            "bindings",
            "aggregate",
            "resources",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_dependency_dry_run_report_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or not IDENTIFIER.fullmatch(str(value["assessmentId"]))
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "live-server-dry-run"
    ):
        fail("sno_dependency_dry_run_report_invalid")
    resources = value["resources"]
    if not isinstance(resources, list) or len(resources) != len(RESOURCE_FILES):
        fail("sno_dependency_dry_run_report_invalid")
    validate_bindings(value["bindings"])
    validated = [
        validate_resource(item, filename)
        for item, filename in zip(resources, RESOURCE_FILES, strict=True)
    ]
    observed = parse_utc(value["observedAt"], "sno_dependency_dry_run_time_invalid")
    assessed = parse_utc(value["assessedAt"], "sno_dependency_dry_run_time_invalid")
    aggregate = value["aggregate"]
    expected_aggregate = {
        "resourceCount": len(validated),
        "acceptedCount": sum(item["serverDryRunAccepted"] for item in validated),
        "unchangedCount": sum(item["objectStateUnchanged"] for item in validated),
        "resourceResultSetDigest": canonical_digest(validated),
    }
    if (
        assessed < observed
        or aggregate != expected_aggregate
        or value["decision"] != decision_for(validated)
        or value["controls"] != CONTROLS
        or value["claims"] != CLAIMS
        or value["reportDigest"]
        != canonical_digest({k: v for k, v in value.items() if k != "reportDigest"})
    ):
        fail("sno_dependency_dry_run_report_semantics_invalid")


def write_create_only(path: Path, value: dict[str, Any]) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except OSError:
        fail("sno_dependency_dry_run_output_invalid")


def validate_contract() -> None:
    if len(RESOURCE_FILES) != 12 or len(set(RESOURCE_FILES)) != 12:
        fail("sno_dependency_dry_run_contract_invalid")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-contract")
    collect = commands.add_parser("collect")
    collect.add_argument("--cluster-report", type=Path, required=True)
    collect.add_argument("--client", type=Path, required=True)
    collect.add_argument("--kubeconfig", type=Path, required=True)
    collect.add_argument("--directory", type=Path, required=True)
    collect.add_argument("--assessment-id", required=True)
    collect.add_argument("--observed-at", required=True)
    collect.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    validate_contract()
    if args.command == "validate-contract":
        print("sno_dependency_server_dry_run_contract_valid resources=12")
        return 0
    if args.command == "verify":
        validate_assessment(
            restricted_report(args.report, "sno_dependency_dry_run_report_invalid")
        )
        return 0
    cluster_report = restricted_report(
        args.cluster_report, "sno_dependency_dry_run_cluster_report_invalid"
    )
    observed_at = parse_utc(args.observed_at, "sno_dependency_dry_run_time_invalid")
    snapshot = collect_snapshot(
        cluster_report,
        args.client,
        args.kubeconfig,
        args.directory,
        observed_at,
    )
    report = build_assessment(snapshot, args.assessment_id, observed_at)
    output = restricted_path(
        args.output, existing=False, code="sno_dependency_dry_run_output_invalid"
    )
    if (
        not output.parent.is_dir()
        or output.parent.is_symlink()
        or output.parent.stat().st_mode & 0o077
    ):
        fail("sno_dependency_dry_run_output_invalid")
    write_create_only(output, report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
