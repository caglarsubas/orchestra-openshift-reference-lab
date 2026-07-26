#!/usr/bin/env python3
"""Observe the SNO trial operator path without install authority."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
import platform
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_sno_trial_profile import (
        PRODUCTION_PROFILE,
        ROOT,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_production_isolation,
        validate_profile,
    )
except ModuleNotFoundError:
    from validate_sno_trial_profile import (  # type: ignore[no-redef]
        PRODUCTION_PROFILE,
        ROOT,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_production_isolation,
        validate_profile,
    )


REPORT_KIND = "orchestra.openshift.sno-trial-operator-path.v1"
SNAPSHOT_KIND = "orchestra.host.sno-trial-operator-path-snapshot.v1"
EXPECTED_VERSION = "4.20.27"
ASSESSMENT_ID = re.compile(r"^sno-operator-[a-z0-9][a-z0-9.-]{5,79}$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
INSTALLER_VERSION = re.compile(
    r"(?m)^openshift-install\s+v?(\d+\.\d+\.\d+)\s*$"
)
CLIENT_VERSION = re.compile(
    r"(?m)^Client Version:\s+v?(\d+\.\d+\.\d+)\s*$"
)
EXECUTION_MODES = {"simulated", "live-diagnostic"}
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
CONTROLS = {
    "commandPolicy": "read-only",
    "rawCommandOutputStored": False,
    "credentialValuesStored": False,
    "sourceCidrStored": False,
    "cloudMutationAuthorized": False,
    "firewallMutationAuthorized": False,
    "installAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
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


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def run_command(
    run: CommandRunner, command: list[str], code: str
) -> subprocess.CompletedProcess[str]:
    try:
        return run(command)
    except (
        OSError,
        subprocess.SubprocessError,
        subprocess.TimeoutExpired,
    ):
        fail(code)


def normalize_operating_system(value: str) -> str:
    normalized = value.strip().lower()
    if normalized == "linux":
        return "linux"
    if normalized == "darwin":
        return "darwin"
    if normalized.startswith("win"):
        return "windows"
    return "other"


def normalize_architecture(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"x86_64", "amd64"}:
        return "amd64"
    if normalized in {"aarch64", "arm64"}:
        return "arm64"
    return "other"


def private_regular_file(path: Path, code: str) -> Path:
    try:
        lexical = path.expanduser().absolute()
        resolved = lexical.resolve(strict=True)
        details = lexical.lstat()
    except OSError:
        fail(code)
    if (
        lexical.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or details.st_mode & 0o077
    ):
        fail(code)
    restricted = (ROOT / "restricted").resolve()
    if restricted not in resolved.parents:
        fail(code)
    return resolved


def read_source_network(path: Path) -> dict[str, Any]:
    source = private_regular_file(
        path, "sno_operator_path_source_cidr_file_invalid"
    )
    try:
        text = source.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        fail("sno_operator_path_source_cidr_file_invalid")
    if not text or len(text) > 64 or "\n" in text or "\r" in text:
        fail("sno_operator_path_source_cidr_invalid")
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        fail("sno_operator_path_source_cidr_invalid")
    required_prefix = 32 if network.version == 4 else 128
    if not network.is_global or network.prefixlen != required_prefix:
        fail("sno_operator_path_source_cidr_invalid")
    return {
        "family": "ipv4" if network.version == 4 else "ipv6",
        "prefixLength": network.prefixlen,
        "hostNetwork": True,
        "cidrDigest": canonical_digest(network.with_prefixlen),
    }


def executable_path(path: Path, code: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
        details = resolved.stat()
    except OSError:
        fail(code)
    if not stat.S_ISREG(details.st_mode) or not os.access(resolved, os.X_OK):
        fail(code)
    return resolved


def active_identity_digests(value: Any) -> list[str]:
    if not isinstance(value, list):
        fail("sno_operator_path_gcp_identity_invalid")
    result: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            fail("sno_operator_path_gcp_identity_invalid")
        account = item.get("account")
        if (
            not isinstance(account, str)
            or len(account) > 320
            or "@" not in account
        ):
            fail("sno_operator_path_gcp_identity_invalid")
        result.append(canonical_digest(account.strip().lower()))
    result.sort()
    if len(result) != len(set(result)):
        fail("sno_operator_path_gcp_identity_invalid")
    return result


def exact_version(output: str, pattern: re.Pattern[str], code: str) -> str:
    matched = pattern.search(output)
    if matched is None:
        fail(code)
    return matched.group(1)


def collect_snapshot(
    project_id: str,
    source_cidr_file: Path,
    installer_path: Path,
    client_path: Path,
    observed_at: datetime,
    run: CommandRunner = default_runner,
    system: Callable[[], str] = platform.system,
    machine: Callable[[], str] = platform.machine,
) -> dict[str, Any]:
    if not PROJECT_ID.fullmatch(project_id):
        fail("sno_operator_path_project_id_invalid")
    installer = executable_path(
        installer_path, "sno_operator_path_installer_invalid"
    )
    client = executable_path(client_path, "sno_operator_path_client_invalid")
    identities_output = run_command(
        run,
        [
            "gcloud",
            "auth",
            "list",
            "--filter=status:ACTIVE",
            "--format=json(account)",
        ],
        "sno_operator_path_gcp_identity_observation_failed",
    ).stdout
    try:
        identities = active_identity_digests(json.loads(identities_output))
    except json.JSONDecodeError:
        fail("sno_operator_path_gcp_identity_observation_failed")
    configured_project = run_command(
        run,
        ["gcloud", "config", "get-value", "project", "--quiet"],
        "sno_operator_path_gcp_project_observation_failed",
    ).stdout.strip()
    if not PROJECT_ID.fullmatch(configured_project):
        fail("sno_operator_path_gcp_project_observation_failed")
    installer_version = exact_version(
        run_command(
            run,
            [str(installer), "version"],
            "sno_operator_path_installer_observation_failed",
        ).stdout,
        INSTALLER_VERSION,
        "sno_operator_path_installer_version_invalid",
    )
    client_version = exact_version(
        run_command(
            run,
            [str(client), "version", "--client"],
            "sno_operator_path_client_observation_failed",
        ).stdout,
        CLIENT_VERSION,
        "sno_operator_path_client_version_invalid",
    )
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-diagnostic",
        "observedAt": utc_text(observed_at),
        "projectId": project_id,
        "operatingSystem": normalize_operating_system(system()),
        "architecture": normalize_architecture(machine()),
        "activeIdentityDigests": identities,
        "configuredProjectId": configured_project,
        "sourceNetwork": read_source_network(source_cidr_file),
        "toolchain": {
            "installerVersion": installer_version,
            "clientVersion": client_version,
        },
    }
    validate_snapshot(snapshot)
    return snapshot


def validate_snapshot(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "executionMode",
            "observedAt",
            "projectId",
            "operatingSystem",
            "architecture",
            "activeIdentityDigests",
            "configuredProjectId",
            "sourceNetwork",
            "toolchain",
        },
        "sno_operator_path_snapshot_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in EXECUTION_MODES
        or not PROJECT_ID.fullmatch(str(value["projectId"]))
        or value["operatingSystem"]
        not in {"linux", "darwin", "windows", "other"}
        or value["architecture"] not in {"amd64", "arm64", "other"}
        or not PROJECT_ID.fullmatch(str(value["configuredProjectId"]))
    ):
        fail("sno_operator_path_snapshot_identity_invalid")
    parse_utc(value["observedAt"], "sno_operator_path_snapshot_time_invalid")
    identities = value["activeIdentityDigests"]
    if (
        not isinstance(identities, list)
        or identities != sorted(set(identities))
        or any(not DIGEST.fullmatch(str(item)) for item in identities)
    ):
        fail("sno_operator_path_identity_digests_invalid")
    source = object_value(
        value["sourceNetwork"], "sno_operator_path_source_network_invalid"
    )
    exact_keys(
        source,
        {"family", "prefixLength", "hostNetwork", "cidrDigest"},
        "sno_operator_path_source_network_keys_invalid",
    )
    expected_prefix = 32 if source.get("family") == "ipv4" else 128
    if (
        source.get("family") not in {"ipv4", "ipv6"}
        or source.get("prefixLength") != expected_prefix
        or source.get("hostNetwork") is not True
        or not DIGEST.fullmatch(str(source.get("cidrDigest")))
    ):
        fail("sno_operator_path_source_network_invalid")
    toolchain = object_value(
        value["toolchain"], "sno_operator_path_toolchain_invalid"
    )
    exact_keys(
        toolchain,
        {"installerVersion", "clientVersion"},
        "sno_operator_path_toolchain_keys_invalid",
    )
    for key in ("installerVersion", "clientVersion"):
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(toolchain[key])):
            fail("sno_operator_path_toolchain_invalid")


def operator_state(snapshot: dict[str, Any]) -> dict[str, Any]:
    identities = snapshot["activeIdentityDigests"]
    source = snapshot["sourceNetwork"]
    toolchain = snapshot["toolchain"]
    return {
        "observedAt": snapshot["observedAt"],
        "projectId": snapshot["projectId"],
        "projectIdentityDigest": canonical_digest(snapshot["projectId"]),
        "operatingSystem": snapshot["operatingSystem"],
        "architecture": snapshot["architecture"],
        "activeIdentityCount": len(identities),
        "activeIdentityDigests": identities,
        "activeIdentitySetDigest": canonical_digest(identities),
        "configuredProjectMatches": (
            snapshot["configuredProjectId"] == snapshot["projectId"]
        ),
        "configuredProjectIdentityDigest": canonical_digest(
            snapshot["configuredProjectId"]
        ),
        "sourceAddressFamily": source["family"],
        "sourcePrefixLength": source["prefixLength"],
        "sourceHostNetwork": source["hostNetwork"],
        "sourceCidrDigest": source["cidrDigest"],
        "installerVersion": toolchain["installerVersion"],
        "clientVersion": toolchain["clientVersion"],
    }


def decision_for(state: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if state["operatingSystem"] != "linux":
        reasons.append("ADMIN_HOST_OS_UNSUPPORTED")
    if state["architecture"] != "amd64":
        reasons.append("ADMIN_HOST_ARCHITECTURE_UNSUPPORTED")
    if state["activeIdentityCount"] != 1:
        reasons.append("ACTIVE_GCP_IDENTITY_INVALID")
    if not state["configuredProjectMatches"]:
        reasons.append("GCP_PROJECT_MISMATCH")
    if not state["sourceHostNetwork"]:
        reasons.append("SOURCE_CIDR_NOT_HOST_SCOPED")
    if state["installerVersion"] != EXPECTED_VERSION:
        reasons.append("INSTALLER_VERSION_MISMATCH")
    if state["clientVersion"] != EXPECTED_VERSION:
        reasons.append("CLIENT_VERSION_MISMATCH")
    observed = not reasons
    return {
        "status": "OPERATOR_PATH_OBSERVED" if observed else "BLOCKED",
        "reasonCodes": reasons,
        "nextAction": (
            "create-short-lived-lease-and-build-install-admission"
            if observed
            else "reconcile-operator-path"
        ),
    }


def build_assessment(
    snapshot: dict[str, Any], assessment_id: str
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_operator_path_assessment_id_invalid")
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    validate_profile(profile, production)
    validate_production_isolation()
    state = operator_state(snapshot)
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
            "projectId": snapshot["projectId"],
            "projectIdentityDigest": canonical_digest(snapshot["projectId"]),
            "expectedOpenShiftVersion": EXPECTED_VERSION,
        },
        "operatorPathState": state,
        "decision": decision_for(state),
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
            "generatedAt",
            "targetClass",
            "executionMode",
            "bindings",
            "operatorPathState",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_operator_path_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_operator_path_report_identity_invalid")
    parse_utc(value["generatedAt"], "sno_operator_path_report_time_invalid")
    bindings = object_value(
        value["bindings"], "sno_operator_path_bindings_invalid"
    )
    exact_keys(
        bindings,
        {
            "profileId",
            "profileDigest",
            "projectId",
            "projectIdentityDigest",
            "expectedOpenShiftVersion",
        },
        "sno_operator_path_bindings_keys_invalid",
    )
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    validate_profile(profile, production)
    if (
        bindings["profileId"] != TRIAL_PROFILE_ID
        or bindings["profileDigest"] != canonical_digest(profile)
        or not PROJECT_ID.fullmatch(str(bindings["projectId"]))
        or bindings["projectIdentityDigest"]
        != canonical_digest(bindings["projectId"])
        or bindings["expectedOpenShiftVersion"] != EXPECTED_VERSION
    ):
        fail("sno_operator_path_bindings_invalid")
    state = object_value(
        value["operatorPathState"],
        "sno_operator_path_state_invalid",
    )
    exact_keys(
        state,
        {
            "observedAt",
            "projectId",
            "projectIdentityDigest",
            "operatingSystem",
            "architecture",
            "activeIdentityCount",
            "activeIdentityDigests",
            "activeIdentitySetDigest",
            "configuredProjectMatches",
            "configuredProjectIdentityDigest",
            "sourceAddressFamily",
            "sourcePrefixLength",
            "sourceHostNetwork",
            "sourceCidrDigest",
            "installerVersion",
            "clientVersion",
        },
        "sno_operator_path_state_keys_invalid",
    )
    parse_utc(state["observedAt"], "sno_operator_path_state_time_invalid")
    expected_prefix = 32 if state.get("sourceAddressFamily") == "ipv4" else 128
    identity_digests = state.get("activeIdentityDigests")
    if (
        state["observedAt"] != value["generatedAt"]
        or state["projectId"] != bindings["projectId"]
        or state["projectIdentityDigest"] != bindings["projectIdentityDigest"]
        or state["operatingSystem"]
        not in {"linux", "darwin", "windows", "other"}
        or state["architecture"] not in {"amd64", "arm64", "other"}
        or type(state["activeIdentityCount"]) is not int
        or state["activeIdentityCount"] < 0
        or not isinstance(identity_digests, list)
        or identity_digests != sorted(set(identity_digests))
        or any(
            not DIGEST.fullmatch(str(item)) for item in identity_digests
        )
        or state["activeIdentityCount"] != len(identity_digests)
        or state["activeIdentitySetDigest"]
        != canonical_digest(identity_digests)
        or type(state["configuredProjectMatches"]) is not bool
        or state["configuredProjectMatches"]
        and state["configuredProjectIdentityDigest"]
        != state["projectIdentityDigest"]
        or state["sourceAddressFamily"] not in {"ipv4", "ipv6"}
        or state["sourcePrefixLength"] != expected_prefix
        or state["sourceHostNetwork"] is not True
        or any(
            not DIGEST.fullmatch(str(state[key]))
            for key in (
                "activeIdentitySetDigest",
                "configuredProjectIdentityDigest",
                "sourceCidrDigest",
            )
        )
        or any(
            not re.fullmatch(r"\d+\.\d+\.\d+", str(state[key]))
            for key in ("installerVersion", "clientVersion")
        )
    ):
        fail("sno_operator_path_state_invalid")
    decision = object_value(
        value["decision"], "sno_operator_path_decision_invalid"
    )
    exact_keys(
        decision,
        {"status", "reasonCodes", "nextAction"},
        "sno_operator_path_decision_keys_invalid",
    )
    if decision != decision_for(state):
        fail("sno_operator_path_decision_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_operator_path_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_operator_path_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_operator_path_report_digest_invalid")


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fail("sno_operator_path_output_exists")
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
        stream.write("\n")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--project-id", required=True)
    collect.add_argument("--source-cidr-file", type=Path, required=True)
    collect.add_argument("--installer", type=Path, required=True)
    collect.add_argument("--client", type=Path, required=True)
    collect.add_argument("--assessment-id", required=True)
    collect.add_argument("--output", type=Path, required=True)
    assess = commands.add_parser("assess")
    assess.add_argument("--snapshot", type=Path, required=True)
    assess.add_argument("--assessment-id", required=True)
    assess.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "collect":
        snapshot = collect_snapshot(
            args.project_id,
            args.source_cidr_file,
            args.installer,
            args.client,
            datetime.now(timezone.utc),
        )
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
        print(
            "sno_operator_path_collected "
            f"status={report['decision']['status']} "
            f"os={report['operatorPathState']['operatingSystem']} "
            f"architecture={report['operatorPathState']['architecture']} "
            "installAuthorized=false campaignEvidence=false"
        )
        return 0
    if args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_operator_path_live_snapshot_requires_collect")
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
        print(
            "sno_operator_path_assessed "
            f"status={report['decision']['status']} "
            "installAuthorized=false campaignEvidence=false"
        )
        return 0
    report = load_json(args.report)
    validate_assessment(report)
    print(
        "sno_operator_path_valid "
        f"digest={report['reportDigest']} "
        f"status={report['decision']['status']} "
        "installAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
