#!/usr/bin/env python3
"""Observe the SNO trial DNS delegation without mutation authority."""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_sno_trial_profile import (
        PRODUCTION_PROFILE,
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
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_production_isolation,
        validate_profile,
    )


REPORT_KIND = "orchestra.openshift.sno-trial-dns-delegation.v1"
SNAPSHOT_KIND = "orchestra.gcp.sno-trial-dns-delegation-snapshot.v1"
MANAGED_ZONE_NAME = "orchestra-ocp-sno-trial-planeon-public"
DNS_NAME = "ocp-lab.planeon.ai."
ASSESSMENT_ID = re.compile(r"^sno-dns-[a-z0-9][a-z0-9.-]{5,79}$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
RESOURCE_NAME = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
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
    "rawProviderOutputStored": False,
    "secretValuesStored": False,
    "cloudMutationAuthorized": False,
    "dnsMutationAuthorized": False,
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


def normalize_dns_name(value: Any, code: str) -> str:
    if not isinstance(value, str):
        fail(code)
    normalized = value.strip().lower().rstrip(".") + "."
    labels = normalized[:-1].split(".")
    if (
        len(normalized) > 254
        or len(labels) < 2
        or any(not DNS_LABEL.fullmatch(label) for label in labels)
    ):
        fail(code)
    return normalized


def normalize_nameservers(value: Any, code: str) -> list[str]:
    if not isinstance(value, list):
        fail(code)
    result = sorted(
        {
            normalize_dns_name(item, code)
            for item in value
            if isinstance(item, str) and item.strip()
        }
    )
    if len(result) != len(value):
        fail(code)
    return result


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def run_json(run: CommandRunner, command: list[str], code: str) -> Any:
    try:
        return json.loads(run(command).stdout)
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        subprocess.TimeoutExpired,
    ):
        fail(code)


def run_lines(run: CommandRunner, command: list[str], code: str) -> list[str]:
    try:
        completed = run(command)
    except (
        OSError,
        subprocess.SubprocessError,
        subprocess.TimeoutExpired,
    ):
        fail(code)
    return [line for line in completed.stdout.splitlines() if line.strip()]


def sanitize_managed_zone(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("sno_dns_delegation_managed_zone_invalid")
    name = value.get("name")
    dns_name = value.get("dnsName")
    visibility = value.get("visibility", "public")
    if (
        not isinstance(name, str)
        or not RESOURCE_NAME.fullmatch(name)
        or visibility not in {"public", "private"}
    ):
        fail("sno_dns_delegation_managed_zone_invalid")
    return {
        "name": name,
        "dnsName": normalize_dns_name(
            dns_name, "sno_dns_delegation_managed_zone_invalid"
        ),
        "visibility": visibility,
        "nameServers": normalize_nameservers(
            value.get("nameServers", []),
            "sno_dns_delegation_managed_zone_invalid",
        ),
    }


def collect_snapshot(
    project_id: str,
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    if not PROJECT_ID.fullmatch(project_id):
        fail("sno_dns_delegation_project_id_invalid")
    managed_zone = sanitize_managed_zone(
        run_json(
            run,
            [
                "gcloud",
                "dns",
                "managed-zones",
                "describe",
                MANAGED_ZONE_NAME,
                f"--project={project_id}",
                "--format=json(name,dnsName,visibility,nameServers)",
            ],
            "sno_dns_delegation_managed_zone_observation_failed",
        )
    )
    delegated = normalize_nameservers(
        run_lines(
            run,
            ["dig", "+short", "NS", DNS_NAME],
            "sno_dns_delegation_public_observation_failed",
        ),
        "sno_dns_delegation_public_nameservers_invalid",
    )
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-diagnostic",
        "observedAt": utc_text(observed_at),
        "projectId": project_id,
        "managedZone": managed_zone,
        "delegatedNameServers": delegated,
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
            "managedZone",
            "delegatedNameServers",
        },
        "sno_dns_delegation_snapshot_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in EXECUTION_MODES
        or not PROJECT_ID.fullmatch(str(value["projectId"]))
    ):
        fail("sno_dns_delegation_snapshot_identity_invalid")
    parse_utc(value["observedAt"], "sno_dns_delegation_snapshot_time_invalid")
    managed_zone = object_value(
        value["managedZone"], "sno_dns_delegation_managed_zone_invalid"
    )
    exact_keys(
        managed_zone,
        {"name", "dnsName", "visibility", "nameServers"},
        "sno_dns_delegation_managed_zone_keys_invalid",
    )
    if sanitize_managed_zone(managed_zone) != managed_zone:
        fail("sno_dns_delegation_managed_zone_invalid")
    if (
        normalize_nameservers(
            value["delegatedNameServers"],
            "sno_dns_delegation_public_nameservers_invalid",
        )
        != value["delegatedNameServers"]
    ):
        fail("sno_dns_delegation_public_nameservers_invalid")


def provider_state(snapshot: dict[str, Any]) -> dict[str, Any]:
    managed = snapshot["managedZone"]
    provider_nameservers = managed["nameServers"]
    delegated_nameservers = snapshot["delegatedNameServers"]
    provider_zone_matches = (
        managed["name"] == MANAGED_ZONE_NAME
        and managed["dnsName"] == DNS_NAME
        and managed["visibility"] == "public"
    )
    provider_nameservers_valid = len(provider_nameservers) == 4
    return {
        "observedAt": snapshot["observedAt"],
        "projectId": snapshot["projectId"],
        "projectIdentityDigest": canonical_digest(snapshot["projectId"]),
        "managedZoneIdentityDigest": canonical_digest(managed["name"]),
        "dnsName": managed["dnsName"],
        "visibility": managed["visibility"],
        "providerZoneMatches": provider_zone_matches,
        "providerNameServersValid": provider_nameservers_valid,
        "providerNameServerCount": len(provider_nameservers),
        "providerNameServerSetDigest": canonical_digest(provider_nameservers),
        "delegatedNameServerCount": len(delegated_nameservers),
        "delegatedNameServerSetDigest": canonical_digest(
            delegated_nameservers
        ),
        "delegationExact": (
            provider_zone_matches
            and provider_nameservers_valid
            and delegated_nameservers == provider_nameservers
        ),
    }


def decision_for(state: dict[str, Any]) -> dict[str, Any]:
    if not state["providerZoneMatches"]:
        return {
            "status": "BLOCKED",
            "reasonCodes": ["MANAGED_ZONE_POLICY_MISMATCH"],
            "nextAction": "reconcile-managed-zone-identity",
        }
    if not state["providerNameServersValid"]:
        return {
            "status": "BLOCKED",
            "reasonCodes": ["MANAGED_ZONE_NAMESERVERS_INVALID"],
            "nextAction": "reconcile-managed-zone-nameservers",
        }
    if state["delegatedNameServerCount"] == 0:
        return {
            "status": "WAITING_DELEGATION",
            "reasonCodes": ["PUBLIC_DELEGATION_MISSING"],
            "nextAction": "publish-parent-ns-delegation",
        }
    if not state["delegationExact"]:
        return {
            "status": "BLOCKED",
            "reasonCodes": ["PUBLIC_DELEGATION_MISMATCH"],
            "nextAction": "correct-parent-ns-delegation",
        }
    return {
        "status": "DELEGATION_OBSERVED",
        "reasonCodes": [],
        "nextAction": "verify-source-cidr-admin-path-and-operator-lease",
    }


def build_assessment(
    snapshot: dict[str, Any], assessment_id: str
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_dns_delegation_assessment_id_invalid")
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    validate_profile(profile, production)
    validate_production_isolation()
    if profile["location"]["dnsZone"].rstrip(".") + "." != DNS_NAME:
        fail("sno_dns_delegation_profile_dns_mismatch")
    state = provider_state(snapshot)
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
            "managedZoneName": MANAGED_ZONE_NAME,
            "dnsName": DNS_NAME,
        },
        "providerState": state,
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
            "providerState",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_dns_delegation_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_dns_delegation_report_identity_invalid")
    parse_utc(value["generatedAt"], "sno_dns_delegation_report_time_invalid")
    bindings = object_value(
        value["bindings"], "sno_dns_delegation_bindings_invalid"
    )
    exact_keys(
        bindings,
        {
            "profileId",
            "profileDigest",
            "projectId",
            "projectIdentityDigest",
            "managedZoneName",
            "dnsName",
        },
        "sno_dns_delegation_bindings_keys_invalid",
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
        or bindings["managedZoneName"] != MANAGED_ZONE_NAME
        or bindings["dnsName"] != DNS_NAME
    ):
        fail("sno_dns_delegation_bindings_invalid")
    state = object_value(
        value["providerState"], "sno_dns_delegation_provider_state_invalid"
    )
    exact_keys(
        state,
        {
            "observedAt",
            "projectId",
            "projectIdentityDigest",
            "managedZoneIdentityDigest",
            "dnsName",
            "visibility",
            "providerZoneMatches",
            "providerNameServersValid",
            "providerNameServerCount",
            "providerNameServerSetDigest",
            "delegatedNameServerCount",
            "delegatedNameServerSetDigest",
            "delegationExact",
        },
        "sno_dns_delegation_provider_state_keys_invalid",
    )
    parse_utc(
        state["observedAt"], "sno_dns_delegation_provider_state_time_invalid"
    )
    count_keys = ("providerNameServerCount", "delegatedNameServerCount")
    if (
        state["observedAt"] != value["generatedAt"]
        or state["projectId"] != bindings["projectId"]
        or state["projectIdentityDigest"] != bindings["projectIdentityDigest"]
        or state["visibility"] not in {"public", "private"}
        or any(
            type(state[key]) is not int or state[key] < 0 for key in count_keys
        )
        or any(
            type(state[key]) is not bool
            for key in (
                "providerZoneMatches",
                "providerNameServersValid",
                "delegationExact",
            )
        )
        or state["providerNameServersValid"]
        != (state["providerNameServerCount"] == 4)
        or state["providerZoneMatches"]
        and (
            state["managedZoneIdentityDigest"]
            != canonical_digest(bindings["managedZoneName"])
            or state["dnsName"] != bindings["dnsName"]
            or state["visibility"] != "public"
        )
        or state["delegationExact"]
        and (
            not state["providerZoneMatches"]
            or not state["providerNameServersValid"]
            or state["delegatedNameServerCount"]
            != state["providerNameServerCount"]
            or state["delegatedNameServerSetDigest"]
            != state["providerNameServerSetDigest"]
        )
        or not DIGEST.fullmatch(str(state["managedZoneIdentityDigest"]))
        or not DIGEST.fullmatch(str(state["providerNameServerSetDigest"]))
        or not DIGEST.fullmatch(str(state["delegatedNameServerSetDigest"]))
    ):
        fail("sno_dns_delegation_provider_state_invalid")
    decision = object_value(
        value["decision"], "sno_dns_delegation_decision_invalid"
    )
    exact_keys(
        decision,
        {"status", "reasonCodes", "nextAction"},
        "sno_dns_delegation_decision_keys_invalid",
    )
    if decision != decision_for(state):
        fail("sno_dns_delegation_decision_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_dns_delegation_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_dns_delegation_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_dns_delegation_report_digest_invalid")


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except FileExistsError:
        fail("sno_dns_delegation_output_exists")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--project-id", required=True)
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
            args.project_id, datetime.now(timezone.utc)
        )
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
        print(
            "sno_dns_delegation_collected "
            f"status={report['decision']['status']} "
            f"providerNameservers="
            f"{report['providerState']['providerNameServerCount']} "
            f"delegatedNameservers="
            f"{report['providerState']['delegatedNameServerCount']} "
            "installAuthorized=false campaignEvidence=false"
        )
        return 0
    if args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_dns_delegation_live_snapshot_requires_collect")
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
        print(
            "sno_dns_delegation_assessed "
            f"status={report['decision']['status']} "
            "installAuthorized=false campaignEvidence=false"
        )
        return 0
    report = load_json(args.report)
    validate_assessment(report)
    print(
        "sno_dns_delegation_valid "
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
