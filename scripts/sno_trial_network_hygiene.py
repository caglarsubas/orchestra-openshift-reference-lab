#!/usr/bin/env python3
"""Assess pre-install SNO trial network hygiene without mutation authority."""

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


REPORT_KIND = "orchestra.openshift.sno-trial-network-hygiene.v1"
SNAPSHOT_KIND = "orchestra.gcp.sno-trial-network-snapshot.v1"
ASSESSMENT_ID = re.compile(r"^sno-network-[a-z0-9][a-z0-9.-]{5,79}$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
RESOURCE_NAME = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$")
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
    "cleanupAuthorized": False,
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


def network_name_from_url(value: Any) -> str:
    if not isinstance(value, str) or "/networks/" not in value:
        fail("sno_network_hygiene_firewall_network_invalid")
    name = value.rsplit("/", 1)[-1]
    if not RESOURCE_NAME.fullmatch(name):
        fail("sno_network_hygiene_firewall_network_invalid")
    return name


def sanitize_networks(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        fail("sno_network_hygiene_networks_invalid")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            fail("sno_network_hygiene_networks_invalid")
        name = item.get("name")
        auto_mode = item.get("autoCreateSubnetworks")
        subnetworks = item.get("subnetworks", [])
        if (
            not isinstance(name, str)
            or not RESOURCE_NAME.fullmatch(name)
            or type(auto_mode) is not bool
            or not isinstance(subnetworks, list)
            or any(
                not isinstance(subnet, str) or "/subnetworks/" not in subnet
                for subnet in subnetworks
            )
        ):
            fail("sno_network_hygiene_networks_invalid")
        result.append(
            {
                "name": name,
                "autoMode": auto_mode,
                "subnetworkCount": len(subnetworks),
            }
        )
    result.sort(key=lambda item: item["name"])
    if len({item["name"] for item in result}) != len(result):
        fail("sno_network_hygiene_networks_invalid")
    return result


def sanitize_firewalls(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        fail("sno_network_hygiene_firewalls_invalid")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            fail("sno_network_hygiene_firewalls_invalid")
        name = item.get("name")
        direction = item.get("direction", "INGRESS")
        disabled = item.get("disabled", False)
        source_ranges = item.get("sourceRanges", [])
        if (
            not isinstance(name, str)
            or not RESOURCE_NAME.fullmatch(name)
            or direction not in {"INGRESS", "EGRESS"}
            or type(disabled) is not bool
            or not isinstance(source_ranges, list)
            or any(not isinstance(source, str) for source in source_ranges)
        ):
            fail("sno_network_hygiene_firewalls_invalid")
        result.append(
            {
                "name": name,
                "networkName": network_name_from_url(item.get("network")),
                "direction": direction,
                "disabled": disabled,
                "internetIngress": (
                    direction == "INGRESS"
                    and not disabled
                    and any(source in {"0.0.0.0/0", "::/0"} for source in source_ranges)
                ),
            }
        )
    result.sort(key=lambda item: item["name"])
    if len({item["name"] for item in result}) != len(result):
        fail("sno_network_hygiene_firewalls_invalid")
    return result


def collect_snapshot(
    project_id: str,
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    if not PROJECT_ID.fullmatch(project_id):
        fail("sno_network_hygiene_project_id_invalid")
    networks = run_json(
        run,
        [
            "gcloud",
            "compute",
            "networks",
            "list",
            f"--project={project_id}",
            "--format=json(name,autoCreateSubnetworks,subnetworks)",
        ],
        "sno_network_hygiene_network_observation_failed",
    )
    firewalls = run_json(
        run,
        [
            "gcloud",
            "compute",
            "firewall-rules",
            "list",
            f"--project={project_id}",
            "--format=json(name,network,direction,disabled,sourceRanges)",
        ],
        "sno_network_hygiene_firewall_observation_failed",
    )
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-diagnostic",
        "observedAt": utc_text(observed_at),
        "projectId": project_id,
        "networks": sanitize_networks(networks),
        "firewalls": sanitize_firewalls(firewalls),
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
            "networks",
            "firewalls",
        },
        "sno_network_hygiene_snapshot_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in EXECUTION_MODES
        or not PROJECT_ID.fullmatch(str(value["projectId"]))
    ):
        fail("sno_network_hygiene_snapshot_identity_invalid")
    parse_utc(value["observedAt"], "sno_network_hygiene_snapshot_time_invalid")
    networks = value["networks"]
    if not isinstance(networks, list):
        fail("sno_network_hygiene_networks_invalid")
    network_names: list[str] = []
    for item in networks:
        if not isinstance(item, dict):
            fail("sno_network_hygiene_networks_invalid")
        exact_keys(
            item,
            {"name", "autoMode", "subnetworkCount"},
            "sno_network_hygiene_networks_invalid",
        )
        if (
            not isinstance(item["name"], str)
            or not RESOURCE_NAME.fullmatch(item["name"])
            or type(item["autoMode"]) is not bool
            or type(item["subnetworkCount"]) is not int
            or item["subnetworkCount"] < 0
        ):
            fail("sno_network_hygiene_networks_invalid")
        network_names.append(item["name"])
    if network_names != sorted(set(network_names)):
        fail("sno_network_hygiene_networks_invalid")
    firewalls = value["firewalls"]
    if not isinstance(firewalls, list):
        fail("sno_network_hygiene_firewalls_invalid")
    firewall_names: list[str] = []
    for item in firewalls:
        if not isinstance(item, dict):
            fail("sno_network_hygiene_firewalls_invalid")
        exact_keys(
            item,
            {
                "name",
                "networkName",
                "direction",
                "disabled",
                "internetIngress",
            },
            "sno_network_hygiene_firewalls_invalid",
        )
        if (
            not isinstance(item["name"], str)
            or not RESOURCE_NAME.fullmatch(item["name"])
            or not isinstance(item["networkName"], str)
            or not RESOURCE_NAME.fullmatch(item["networkName"])
            or item["direction"] not in {"INGRESS", "EGRESS"}
            or type(item["disabled"]) is not bool
            or type(item["internetIngress"]) is not bool
            or (item["internetIngress"] and item["direction"] != "INGRESS")
            or (item["internetIngress"] and item["disabled"])
        ):
            fail("sno_network_hygiene_firewalls_invalid")
        firewall_names.append(item["name"])
    if firewall_names != sorted(set(firewall_names)):
        fail("sno_network_hygiene_firewalls_invalid")


def provider_state(snapshot: dict[str, Any]) -> dict[str, Any]:
    networks = snapshot["networks"]
    firewalls = snapshot["firewalls"]
    default_networks = [item for item in networks if item["name"] == "default"]
    default_firewalls = [
        item for item in firewalls if item["networkName"] == "default"
    ]
    return {
        "observedAt": snapshot["observedAt"],
        "projectId": snapshot["projectId"],
        "projectIdentityDigest": canonical_digest(snapshot["projectId"]),
        "networkCount": len(networks),
        "autoModeNetworkCount": sum(item["autoMode"] for item in networks),
        "defaultNetworkPresent": bool(default_networks),
        "defaultSubnetworkCount": sum(
            item["subnetworkCount"] for item in default_networks
        ),
        "firewallRuleCount": len(firewalls),
        "defaultFirewallRuleCount": len(default_firewalls),
        "internetIngressRuleCount": sum(
            item["internetIngress"] for item in firewalls
        ),
        "networkInventoryDigest": canonical_digest(networks),
        "firewallInventoryDigest": canonical_digest(firewalls),
    }


def decision_for(state: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if state["networkCount"]:
        reasons.append("PREEXISTING_NETWORKS_PRESENT")
    if state["autoModeNetworkCount"]:
        reasons.append("AUTO_MODE_NETWORK_PRESENT")
    if state["defaultNetworkPresent"]:
        reasons.append("DEFAULT_NETWORK_PRESENT")
    if state["defaultSubnetworkCount"]:
        reasons.append("DEFAULT_SUBNETWORKS_PRESENT")
    if state["firewallRuleCount"]:
        reasons.append("PREEXISTING_FIREWALL_RULES_PRESENT")
    if state["defaultFirewallRuleCount"]:
        reasons.append("DEFAULT_FIREWALL_RULES_PRESENT")
    if state["internetIngressRuleCount"]:
        reasons.append("PUBLIC_INGRESS_RULES_PRESENT")
    clean = not reasons
    return {
        "status": "CLEAN" if clean else "BLOCKED",
        "reasonCodes": reasons,
        "nextAction": (
            "continue-downstream-prerequisites"
            if clean
            else "remove-unused-default-network-resources"
        ),
    }


def build_assessment(
    snapshot: dict[str, Any], assessment_id: str
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_network_hygiene_assessment_id_invalid")
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    validate_profile(profile, production)
    validate_production_isolation()
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
        "sno_network_hygiene_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_network_hygiene_report_identity_invalid")
    parse_utc(value["generatedAt"], "sno_network_hygiene_report_time_invalid")
    bindings = object_value(
        value["bindings"], "sno_network_hygiene_bindings_invalid"
    )
    exact_keys(
        bindings,
        {"profileId", "profileDigest", "projectId", "projectIdentityDigest"},
        "sno_network_hygiene_bindings_keys_invalid",
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
    ):
        fail("sno_network_hygiene_bindings_invalid")
    state = object_value(
        value["providerState"], "sno_network_hygiene_provider_state_invalid"
    )
    exact_keys(
        state,
        {
            "observedAt",
            "projectId",
            "projectIdentityDigest",
            "networkCount",
            "autoModeNetworkCount",
            "defaultNetworkPresent",
            "defaultSubnetworkCount",
            "firewallRuleCount",
            "defaultFirewallRuleCount",
            "internetIngressRuleCount",
            "networkInventoryDigest",
            "firewallInventoryDigest",
        },
        "sno_network_hygiene_provider_state_keys_invalid",
    )
    parse_utc(
        state["observedAt"], "sno_network_hygiene_provider_state_time_invalid"
    )
    count_keys = (
        "networkCount",
        "autoModeNetworkCount",
        "defaultSubnetworkCount",
        "firewallRuleCount",
        "defaultFirewallRuleCount",
        "internetIngressRuleCount",
    )
    if (
        state["observedAt"] != value["generatedAt"]
        or state["projectId"] != bindings["projectId"]
        or state["projectIdentityDigest"] != bindings["projectIdentityDigest"]
        or any(
            type(state[key]) is not int or state[key] < 0 for key in count_keys
        )
        or type(state["defaultNetworkPresent"]) is not bool
        or (
            state["defaultSubnetworkCount"] > 0
            and not state["defaultNetworkPresent"]
        )
        or (state["defaultNetworkPresent"] and state["networkCount"] == 0)
        or state["autoModeNetworkCount"] > state["networkCount"]
        or state["defaultFirewallRuleCount"] > state["firewallRuleCount"]
        or state["internetIngressRuleCount"] > state["firewallRuleCount"]
        or not DIGEST.fullmatch(str(state["networkInventoryDigest"]))
        or not DIGEST.fullmatch(str(state["firewallInventoryDigest"]))
    ):
        fail("sno_network_hygiene_provider_state_invalid")
    decision = object_value(
        value["decision"], "sno_network_hygiene_decision_invalid"
    )
    exact_keys(
        decision,
        {"status", "reasonCodes", "nextAction"},
        "sno_network_hygiene_decision_keys_invalid",
    )
    if decision != decision_for(state):
        fail("sno_network_hygiene_decision_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_network_hygiene_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_network_hygiene_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_network_hygiene_report_digest_invalid")


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except FileExistsError:
        fail("sno_network_hygiene_output_exists")


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
            "sno_network_hygiene_collected "
            f"status={report['decision']['status']} "
            f"networks={report['providerState']['networkCount']} "
            f"firewalls={report['providerState']['firewallRuleCount']} "
            "mutationAuthorized=false campaignEvidence=false"
        )
        return 0
    if args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_network_hygiene_live_snapshot_requires_collect")
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
        print(
            "sno_network_hygiene_assessed "
            f"status={report['decision']['status']} "
            "mutationAuthorized=false campaignEvidence=false"
        )
        return 0
    report = load_json(args.report)
    validate_assessment(report)
    print(
        "sno_network_hygiene_valid "
        f"digest={report['reportDigest']} "
        f"status={report['decision']['status']} "
        "mutationAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
