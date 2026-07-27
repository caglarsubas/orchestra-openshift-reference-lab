#!/usr/bin/env python3
"""Observe bounded SNO trial cost exposure and teardown residuals read-only."""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_sno_trial_profile import (
        BILLING_EXECUTION_LOCK,
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_billing_execution,
        validate_production_isolation,
        validate_profile,
    )
except ModuleNotFoundError:
    from validate_sno_trial_profile import (  # type: ignore[no-redef]
        BILLING_EXECUTION_LOCK,
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_billing_execution,
        validate_production_isolation,
        validate_profile,
    )


ROOT = Path(__file__).resolve().parents[1]
RATE_CARD = ROOT / "config" / "sno-trial-cost-rate-card.lock.json"
REPORT_KIND = "orchestra.openshift.sno-trial-resource-exposure.v1"
SNAPSHOT_KIND = "orchestra.gcp.sno-trial-resource-snapshot.v1"
RATE_CARD_KIND = "orchestra.gcp.sno-trial-cost-rate-card.v1"
ASSESSMENT_ID = re.compile(r"^sno-exposure-[a-z0-9][a-z0-9.-]{5,79}$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
RESOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,254}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
DECIMAL_TEXT = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?$")
EXECUTION_MODES = {"simulated", "live-diagnostic"}
PHASES = {"active", "post-teardown"}
RESOURCE_CLASSES = (
    "addresses",
    "buckets",
    "customRoles",
    "firewalls",
    "forwardingRules",
    "networks",
    "routers",
    "serviceAccounts",
    "subnetworks",
    "workloadIdentityPools",
)
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
    "resourceNamesStored": False,
    "credentialValuesStored": False,
    "costEstimateOnly": True,
    "billedCostVerified": False,
    "cleanupAuthorized": False,
    "teardownAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
}
CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
MONEY_QUANTUM = Decimal("0.000001")
HOUR_QUANTUM = Decimal("0.0001")


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


def parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(code)
    if parsed.tzinfo is None:
        fail(code)
    return parsed.astimezone(timezone.utc)


def decimal_value(value: Any, code: str) -> Decimal:
    if not isinstance(value, str) or not DECIMAL_TEXT.fullmatch(value):
        fail(code)
    try:
        result = Decimal(value)
    except InvalidOperation:
        fail(code)
    if not result.is_finite() or result < 0:
        fail(code)
    return result


def decimal_text(value: Decimal, quantum: Decimal = MONEY_QUANTUM) -> str:
    return format(value.quantize(quantum, rounding=ROUND_HALF_UP), "f")


def path_tail(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value:
        fail(code)
    tail = value.rstrip("/").rsplit("/", 1)[-1]
    if not RESOURCE_NAME.fullmatch(tail):
        fail(code)
    return tail


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
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


def normalize_name_list(value: Any, code: str) -> list[str]:
    if not isinstance(value, list):
        fail(code)
    result = [path_tail(item, code) for item in value]
    if result != sorted(set(result)):
        fail(code)
    return result


def sanitize_named_rows(
    value: Any, field: str, code: str
) -> list[str]:
    if not isinstance(value, list):
        fail(code)
    result: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            fail(code)
        result.append(path_tail(item.get(field), code))
    return sorted(set(result))


def sanitize_instances(value: Any, code: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        fail(code)
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            fail(code)
        name = path_tail(item.get("name"), code)
        machine_type = path_tail(item.get("machineType"), code)
        status = item.get("status")
        created = parse_time(item.get("creationTimestamp"), code)
        if not isinstance(status, str) or not status:
            fail(code)
        result.append(
            {
                "name": name,
                "machineType": machine_type,
                "status": status,
                "creationTimestamp": utc_text(created),
            }
        )
    result.sort(key=lambda item: item["name"])
    if len({item["name"] for item in result}) != len(result):
        fail(code)
    return result


def sanitize_disks(value: Any, code: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        fail(code)
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            fail(code)
        name = path_tail(item.get("name"), code)
        disk_type = path_tail(item.get("type"), code)
        try:
            size = int(item.get("sizeGb"))
        except (TypeError, ValueError):
            fail(code)
        created = parse_time(item.get("creationTimestamp"), code)
        if size <= 0:
            fail(code)
        result.append(
            {
                "name": name,
                "diskType": disk_type,
                "sizeGiB": size,
                "creationTimestamp": utc_text(created),
            }
        )
    result.sort(key=lambda item: item["name"])
    if len({item["name"] for item in result}) != len(result):
        fail(code)
    return result


def collect_snapshot(
    target_project_id: str,
    operator_project_id: str,
    operator_instance_name: str,
    phase: str,
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    if (
        not PROJECT_ID.fullmatch(target_project_id)
        or not PROJECT_ID.fullmatch(operator_project_id)
        or not RESOURCE_NAME.fullmatch(operator_instance_name)
        or phase not in PHASES
    ):
        fail("sno_exposure_collection_input_invalid")

    def gcloud_json(arguments: list[str], code: str) -> Any:
        return run_json(run, ["gcloud", *arguments], code)

    target_instances = gcloud_json(
        [
            "compute",
            "instances",
            "list",
            f"--project={target_project_id}",
            "--format=json(name,machineType,status,creationTimestamp)",
        ],
        "sno_exposure_target_instances_failed",
    )
    target_disks = gcloud_json(
        [
            "compute",
            "disks",
            "list",
            f"--project={target_project_id}",
            "--format=json(name,type,sizeGb,creationTimestamp)",
        ],
        "sno_exposure_target_disks_failed",
    )
    operator_instances = gcloud_json(
        [
            "compute",
            "instances",
            "list",
            f"--project={operator_project_id}",
            f"--filter=name={operator_instance_name}",
            "--format=json(name,machineType,status,creationTimestamp)",
        ],
        "sno_exposure_operator_instances_failed",
    )
    operator_disks = gcloud_json(
        [
            "compute",
            "disks",
            "list",
            f"--project={operator_project_id}",
            f"--filter=name={operator_instance_name}",
            "--format=json(name,type,sizeGb,creationTimestamp)",
        ],
        "sno_exposure_operator_disks_failed",
    )
    list_commands = {
        "addresses": (
            ["compute", "addresses", "list"],
            "name",
        ),
        "buckets": (["storage", "buckets", "list"], "name"),
        "customRoles": (["iam", "roles", "list"], "name"),
        "firewalls": (["compute", "firewall-rules", "list"], "name"),
        "forwardingRules": (
            ["compute", "forwarding-rules", "list"],
            "name",
        ),
        "networks": (["compute", "networks", "list"], "name"),
        "routers": (["compute", "routers", "list"], "name"),
        "serviceAccounts": (
            ["iam", "service-accounts", "list"],
            "email",
        ),
        "subnetworks": (["compute", "networks", "subnets", "list"], "name"),
        "workloadIdentityPools": (
            [
                "iam",
                "workload-identity-pools",
                "list",
                "--location=global",
            ],
            "name",
        ),
    }
    resource_names: dict[str, list[str]] = {}
    for resource_class, (arguments, field) in list_commands.items():
        rows = gcloud_json(
            [
                *arguments,
                f"--project={target_project_id}",
                f"--format=json({field})",
            ],
            f"sno_exposure_{resource_class}_failed",
        )
        resource_names[resource_class] = sanitize_named_rows(
            rows, field, f"sno_exposure_{resource_class}_invalid"
        )

    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-diagnostic",
        "phase": phase,
        "observedAt": utc_text(observed_at),
        "targetProjectId": target_project_id,
        "operatorProjectId": operator_project_id,
        "operatorInstanceName": operator_instance_name,
        "target": {
            "instances": sanitize_instances(
                target_instances, "sno_exposure_target_instances_invalid"
            ),
            "disks": sanitize_disks(
                target_disks, "sno_exposure_target_disks_invalid"
            ),
            "resourceNames": resource_names,
        },
        "operator": {
            "instances": sanitize_instances(
                operator_instances,
                "sno_exposure_operator_instances_invalid",
            ),
            "disks": sanitize_disks(
                operator_disks, "sno_exposure_operator_disks_invalid"
            ),
        },
    }
    validate_snapshot(snapshot)
    return snapshot


def validate_instances(value: Any, code: str) -> list[dict[str, Any]]:
    result = list_value(value, code)
    names: list[str] = []
    for item in result:
        instance = object_value(item, code)
        exact_keys(
            instance,
            {"name", "machineType", "status", "creationTimestamp"},
            code,
        )
        if (
            not RESOURCE_NAME.fullmatch(str(instance["name"]))
            or not RESOURCE_NAME.fullmatch(str(instance["machineType"]))
            or not isinstance(instance["status"], str)
            or not instance["status"]
        ):
            fail(code)
        parse_time(instance["creationTimestamp"], code)
        names.append(instance["name"])
    if names != sorted(set(names)):
        fail(code)
    return result


def validate_disks(value: Any, code: str) -> list[dict[str, Any]]:
    result = list_value(value, code)
    names: list[str] = []
    for item in result:
        disk = object_value(item, code)
        exact_keys(
            disk,
            {"name", "diskType", "sizeGiB", "creationTimestamp"},
            code,
        )
        if (
            not RESOURCE_NAME.fullmatch(str(disk["name"]))
            or not RESOURCE_NAME.fullmatch(str(disk["diskType"]))
            or type(disk["sizeGiB"]) is not int
            or disk["sizeGiB"] <= 0
        ):
            fail(code)
        parse_time(disk["creationTimestamp"], code)
        names.append(disk["name"])
    if names != sorted(set(names)):
        fail(code)
    return result


def validate_snapshot(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "executionMode",
            "phase",
            "observedAt",
            "targetProjectId",
            "operatorProjectId",
            "operatorInstanceName",
            "target",
            "operator",
        },
        "sno_exposure_snapshot_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in EXECUTION_MODES
        or value["phase"] not in PHASES
        or not PROJECT_ID.fullmatch(str(value["targetProjectId"]))
        or not PROJECT_ID.fullmatch(str(value["operatorProjectId"]))
        or not RESOURCE_NAME.fullmatch(str(value["operatorInstanceName"]))
    ):
        fail("sno_exposure_snapshot_identity_invalid")
    observed_at = parse_time(
        value["observedAt"], "sno_exposure_snapshot_time_invalid"
    )
    target = object_value(value["target"], "sno_exposure_target_invalid")
    exact_keys(
        target,
        {"instances", "disks", "resourceNames"},
        "sno_exposure_target_keys_invalid",
    )
    operator = object_value(
        value["operator"], "sno_exposure_operator_invalid"
    )
    exact_keys(
        operator,
        {"instances", "disks"},
        "sno_exposure_operator_keys_invalid",
    )
    all_instances = [
        *validate_instances(
            target["instances"], "sno_exposure_target_instances_invalid"
        ),
        *validate_instances(
            operator["instances"], "sno_exposure_operator_instances_invalid"
        ),
    ]
    all_disks = [
        *validate_disks(
            target["disks"], "sno_exposure_target_disks_invalid"
        ),
        *validate_disks(
            operator["disks"], "sno_exposure_operator_disks_invalid"
        ),
    ]
    if any(
        parse_time(item["creationTimestamp"], "sno_exposure_creation_invalid")
        > observed_at
        for item in [*all_instances, *all_disks]
    ):
        fail("sno_exposure_creation_after_observation")
    resource_names = object_value(
        target["resourceNames"], "sno_exposure_resource_names_invalid"
    )
    exact_keys(
        resource_names,
        set(RESOURCE_CLASSES),
        "sno_exposure_resource_name_keys_invalid",
    )
    for resource_class in RESOURCE_CLASSES:
        normalize_name_list(
            resource_names[resource_class],
            f"sno_exposure_{resource_class}_invalid",
        )
    if any(
        item["name"] != value["operatorInstanceName"]
        for item in operator["instances"]
    ) or any(
        item["name"] != value["operatorInstanceName"]
        for item in operator["disks"]
    ):
        fail("sno_exposure_operator_name_mismatch")


def validate_rate_card(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "catalogServiceId",
            "catalogObservedAt",
            "currencyCode",
            "monthHours",
            "rates",
            "machineProfiles",
            "excludedChargeClasses",
            "estimateIsBilledSpend",
        },
        "sno_exposure_rate_card_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != RATE_CARD_KIND
        or value["profileId"] != TRIAL_PROFILE_ID
        or value["catalogServiceId"] != "6F81-5844-456A"
        or value["currencyCode"] != "USD"
        or type(value["monthHours"]) is not int
        or value["monthHours"] <= 0
        or value["estimateIsBilledSpend"] is not False
    ):
        fail("sno_exposure_rate_card_identity_invalid")
    parse_time(
        value["catalogObservedAt"], "sno_exposure_rate_card_time_invalid"
    )
    rates = list_value(value["rates"], "sno_exposure_rates_invalid")
    rate_keys: list[str] = []
    for item in rates:
        rate = object_value(item, "sno_exposure_rates_invalid")
        exact_keys(
            rate,
            {"key", "skuId", "description", "usageUnit", "unitRateUsd"},
            "sno_exposure_rate_keys_invalid",
        )
        if (
            not RESOURCE_NAME.fullmatch(str(rate["key"]))
            or not re.fullmatch(
                r"^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$",
                str(rate["skuId"]),
            )
            or not isinstance(rate["description"], str)
            or not rate["description"]
            or rate["usageUnit"] not in {"h", "GiBy.h", "GiBy.mo"}
        ):
            fail("sno_exposure_rate_invalid")
        decimal_value(rate["unitRateUsd"], "sno_exposure_rate_invalid")
        rate_keys.append(rate["key"])
    if rate_keys != sorted(set(rate_keys)):
        fail("sno_exposure_rate_order_invalid")
    profiles = list_value(
        value["machineProfiles"], "sno_exposure_machine_profiles_invalid"
    )
    profile_names: list[str] = []
    for item in profiles:
        profile = object_value(
            item, "sno_exposure_machine_profiles_invalid"
        )
        exact_keys(
            profile,
            {
                "machineType",
                "vcpu",
                "memoryGiB",
                "coreRateKey",
                "ramRateKey",
            },
            "sno_exposure_machine_profile_keys_invalid",
        )
        if (
            not RESOURCE_NAME.fullmatch(str(profile["machineType"]))
            or type(profile["vcpu"]) is not int
            or profile["vcpu"] <= 0
            or type(profile["memoryGiB"]) is not int
            or profile["memoryGiB"] <= 0
            or profile["coreRateKey"] not in rate_keys
            or profile["ramRateKey"] not in rate_keys
        ):
            fail("sno_exposure_machine_profile_invalid")
        profile_names.append(profile["machineType"])
    if profile_names != sorted(set(profile_names)):
        fail("sno_exposure_machine_profile_order_invalid")
    excluded = value["excludedChargeClasses"]
    if (
        not isinstance(excluded, list)
        or excluded != sorted(set(excluded))
        or any(not RESOURCE_NAME.fullmatch(str(item)) for item in excluded)
        or not excluded
    ):
        fail("sno_exposure_exclusions_invalid")


def is_managed_name(name: str, resource_class: str) -> bool:
    if resource_class == "customRoles":
        return name.startswith("prometaorchsno")
    if resource_class == "workloadIdentityPools":
        return name == "orchestra-trial"
    return name.startswith(("orchestra-trial-", "orchestra-tr-"))


def hours_since(created_at: str, observed_at: datetime) -> Decimal:
    seconds = Decimal(
        str(
            (
                observed_at
                - parse_time(created_at, "sno_exposure_creation_invalid")
            ).total_seconds()
        )
    )
    return max(seconds, Decimal(0)) / Decimal(3600)


def build_cost_estimate(
    snapshot: dict[str, Any], rate_card: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    observed_at = parse_time(
        snapshot["observedAt"], "sno_exposure_snapshot_time_invalid"
    )
    rates = {
        item["key"]: Decimal(item["unitRateUsd"])
        for item in rate_card["rates"]
    }
    profiles = {
        item["machineType"]: item for item in rate_card["machineProfiles"]
    }
    components = {
        "targetComputeUsd": Decimal(0),
        "targetDiskUsd": Decimal(0),
        "operatorComputeUsd": Decimal(0),
        "operatorDiskUsd": Decimal(0),
    }
    usage = {
        "targetInstanceHours": Decimal(0),
        "targetDiskGiBHours": Decimal(0),
        "operatorInstanceHours": Decimal(0),
        "operatorDiskGiBHours": Decimal(0),
    }
    unpriced: set[str] = set()
    for plane, inventory in (
        ("target", snapshot["target"]),
        ("operator", snapshot["operator"]),
    ):
        for instance in inventory["instances"]:
            hours = hours_since(instance["creationTimestamp"], observed_at)
            usage[f"{plane}InstanceHours"] += hours
            profile = profiles.get(instance["machineType"])
            if profile is None:
                unpriced.add(f"machine:{instance['machineType']}")
                continue
            hourly = (
                Decimal(profile["vcpu"]) * rates[profile["coreRateKey"]]
                + Decimal(profile["memoryGiB"])
                * rates[profile["ramRateKey"]]
            )
            components[
                "targetComputeUsd"
                if plane == "target"
                else "operatorComputeUsd"
            ] += hours * hourly
        for disk in inventory["disks"]:
            hours = hours_since(disk["creationTimestamp"], observed_at)
            gib_hours = hours * Decimal(disk["sizeGiB"])
            usage[f"{plane}DiskGiBHours"] += gib_hours
            if disk["diskType"] != "pd-balanced":
                unpriced.add(f"disk:{disk['diskType']}")
                continue
            disk_cost = (
                gib_hours
                * rates["balanced-pd"]
                / Decimal(rate_card["monthHours"])
            )
            components[
                "targetDiskUsd"
                if plane == "target"
                else "operatorDiskUsd"
            ] += disk_cost
    subtotal = sum(components.values(), Decimal(0))
    billing = load_json(BILLING_EXECUTION_LOCK)
    try_amount = subtotal * Decimal(billing["conversionRateTryPerUsd"])
    estimate = {
        **{
            key: decimal_text(value) for key, value in components.items()
        },
        **{
            key: decimal_text(value, HOUR_QUANTUM)
            for key, value in usage.items()
        },
        "estimatedUsdSubtotal": decimal_text(subtotal),
        "estimatedTrySubtotal": decimal_text(try_amount),
        "monthlyUsdAlertCeiling": decimal_text(
            Decimal(str(billing["monthlyUsdCeiling"]))
        ),
        "estimateComplete": not unpriced
        and not rate_card["excludedChargeClasses"],
        "unpricedResourceClasses": sorted(unpriced),
        "excludedChargeClasses": copy.deepcopy(
            rate_card["excludedChargeClasses"]
        ),
        "billingExportVerified": False,
        "estimateIsBilledSpend": False,
    }
    return estimate, sorted(unpriced)


def resource_state(snapshot: dict[str, Any]) -> dict[str, Any]:
    target = snapshot["target"]
    operator = snapshot["operator"]
    names = target["resourceNames"]
    managed_counts = {
        resource_class: sum(
            is_managed_name(name, resource_class)
            for name in names[resource_class]
        )
        for resource_class in RESOURCE_CLASSES
    }
    target_instances = target["instances"]
    target_disks = target["disks"]
    managed_instances = [
        item
        for item in target_instances
        if is_managed_name(item["name"], "instances")
    ]
    managed_disks = [
        item
        for item in target_disks
        if is_managed_name(item["name"], "disks")
    ]
    target_managed_total = (
        len(managed_instances)
        + len(managed_disks)
        + sum(managed_counts.values())
    )
    return {
        "phase": snapshot["phase"],
        "observedAt": snapshot["observedAt"],
        "target": {
            "instanceCount": len(target_instances),
            "managedInstanceCount": len(managed_instances),
            "diskCount": len(target_disks),
            "managedDiskCount": len(managed_disks),
            "managedNameCounts": managed_counts,
            "managedResourceCount": target_managed_total,
            "inventoryDigest": canonical_digest(target),
        },
        "operator": {
            "instanceCount": len(operator["instances"]),
            "diskCount": len(operator["disks"]),
            "resourceCount": len(operator["instances"])
            + len(operator["disks"]),
            "inventoryDigest": canonical_digest(operator),
        },
    }


def decision_for(
    state: dict[str, Any], estimate: dict[str, Any]
) -> dict[str, Any]:
    reasons: list[str] = []
    if state["phase"] == "active":
        if state["target"]["managedInstanceCount"] != 1:
            reasons.append("TARGET_INSTANCE_COUNT_MISMATCH")
        if state["target"]["managedDiskCount"] != 1:
            reasons.append("TARGET_DISK_COUNT_MISMATCH")
        if state["operator"]["instanceCount"] != 1:
            reasons.append("OPERATOR_INSTANCE_COUNT_MISMATCH")
        if state["operator"]["diskCount"] != 1:
            reasons.append("OPERATOR_DISK_COUNT_MISMATCH")
        if estimate["unpricedResourceClasses"]:
            reasons.append("UNPRICED_RESOURCE_PRESENT")
        if decimal_value(
            estimate["estimatedUsdSubtotal"], "sno_exposure_estimate_invalid"
        ) >= decimal_value(
            estimate["monthlyUsdAlertCeiling"],
            "sno_exposure_estimate_invalid",
        ):
            reasons.append("ESTIMATE_AT_OR_ABOVE_ALERT_CEILING")
        return {
            "status": "ACTIVE_EXPOSURE_OBSERVED" if not reasons else "BLOCKED",
            "reasonCodes": reasons,
            "nextAction": (
                "run-bounded-tests-then-teardown-before-lease-expiry"
                if not reasons
                else "review-resource-and-cost-drift"
            ),
        }
    if state["target"]["managedResourceCount"]:
        reasons.append("TARGET_RESIDUALS_PRESENT")
    if state["operator"]["resourceCount"]:
        reasons.append("OPERATOR_RESIDUALS_PRESENT")
    return {
        "status": "TEARDOWN_RESIDUALS_CLEAN" if not reasons else "BLOCKED",
        "reasonCodes": reasons,
        "nextAction": (
            "close-lease-and-preserve-payload-free-receipt"
            if not reasons
            else "reconcile-residual-resources"
        ),
    }


def build_assessment(
    snapshot: dict[str, Any], assessment_id: str
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_exposure_assessment_id_invalid")
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    billing = load_json(BILLING_EXECUTION_LOCK)
    rate_card = load_json(RATE_CARD)
    validate_profile(profile, production)
    validate_production_isolation()
    validate_billing_execution(billing, profile)
    validate_rate_card(rate_card)
    state = resource_state(snapshot)
    estimate, _ = build_cost_estimate(snapshot, rate_card)
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
            "billingExecutionDigest": canonical_digest(billing),
            "costRateCardDigest": canonical_digest(rate_card),
            "targetProjectId": snapshot["targetProjectId"],
            "targetProjectIdentityDigest": canonical_digest(
                snapshot["targetProjectId"]
            ),
            "operatorProjectIdentityDigest": canonical_digest(
                snapshot["operatorProjectId"]
            ),
            "operatorInstanceIdentityDigest": canonical_digest(
                snapshot["operatorInstanceName"]
            ),
        },
        "resourceState": state,
        "costEstimate": estimate,
        "decision": decision_for(state, estimate),
        "controls": copy.deepcopy(CONTROLS),
        "claims": copy.deepcopy(CLAIMS),
    }
    report["reportDigest"] = canonical_digest(report)
    validate_assessment(report)
    return report


def validate_count(value: Any, code: str) -> None:
    if type(value) is not int or value < 0:
        fail(code)


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
            "resourceState",
            "costEstimate",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_exposure_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_exposure_report_identity_invalid")
    parse_time(value["generatedAt"], "sno_exposure_report_time_invalid")
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    billing = load_json(BILLING_EXECUTION_LOCK)
    rate_card = load_json(RATE_CARD)
    validate_profile(profile, production)
    validate_billing_execution(billing, profile)
    validate_rate_card(rate_card)
    bindings = object_value(
        value["bindings"], "sno_exposure_bindings_invalid"
    )
    exact_keys(
        bindings,
        {
            "profileId",
            "profileDigest",
            "billingExecutionDigest",
            "costRateCardDigest",
            "targetProjectId",
            "targetProjectIdentityDigest",
            "operatorProjectIdentityDigest",
            "operatorInstanceIdentityDigest",
        },
        "sno_exposure_bindings_keys_invalid",
    )
    if (
        bindings["profileId"] != TRIAL_PROFILE_ID
        or bindings["profileDigest"] != canonical_digest(profile)
        or bindings["billingExecutionDigest"] != canonical_digest(billing)
        or bindings["costRateCardDigest"] != canonical_digest(rate_card)
        or not PROJECT_ID.fullmatch(str(bindings["targetProjectId"]))
        or bindings["targetProjectIdentityDigest"]
        != canonical_digest(bindings["targetProjectId"])
        or any(
            not DIGEST.fullmatch(str(bindings[key]))
            for key in (
                "operatorProjectIdentityDigest",
                "operatorInstanceIdentityDigest",
            )
        )
    ):
        fail("sno_exposure_bindings_invalid")
    state = object_value(
        value["resourceState"], "sno_exposure_resource_state_invalid"
    )
    exact_keys(
        state,
        {"phase", "observedAt", "target", "operator"},
        "sno_exposure_resource_state_keys_invalid",
    )
    if (
        state["phase"] not in PHASES
        or state["observedAt"] != value["generatedAt"]
    ):
        fail("sno_exposure_resource_state_invalid")
    target = object_value(
        state["target"], "sno_exposure_target_state_invalid"
    )
    exact_keys(
        target,
        {
            "instanceCount",
            "managedInstanceCount",
            "diskCount",
            "managedDiskCount",
            "managedNameCounts",
            "managedResourceCount",
            "inventoryDigest",
        },
        "sno_exposure_target_state_keys_invalid",
    )
    for key in (
        "instanceCount",
        "managedInstanceCount",
        "diskCount",
        "managedDiskCount",
        "managedResourceCount",
    ):
        validate_count(target[key], "sno_exposure_target_state_invalid")
    counts = object_value(
        target["managedNameCounts"], "sno_exposure_managed_counts_invalid"
    )
    exact_keys(
        counts,
        set(RESOURCE_CLASSES),
        "sno_exposure_managed_count_keys_invalid",
    )
    for count in counts.values():
        validate_count(count, "sno_exposure_managed_counts_invalid")
    if (
        target["managedInstanceCount"] > target["instanceCount"]
        or target["managedDiskCount"] > target["diskCount"]
        or target["managedResourceCount"]
        != target["managedInstanceCount"]
        + target["managedDiskCount"]
        + sum(counts.values())
        or not DIGEST.fullmatch(str(target["inventoryDigest"]))
    ):
        fail("sno_exposure_target_state_invalid")
    operator = object_value(
        state["operator"], "sno_exposure_operator_state_invalid"
    )
    exact_keys(
        operator,
        {"instanceCount", "diskCount", "resourceCount", "inventoryDigest"},
        "sno_exposure_operator_state_keys_invalid",
    )
    for key in ("instanceCount", "diskCount", "resourceCount"):
        validate_count(operator[key], "sno_exposure_operator_state_invalid")
    if (
        operator["resourceCount"]
        != operator["instanceCount"] + operator["diskCount"]
        or not DIGEST.fullmatch(str(operator["inventoryDigest"]))
    ):
        fail("sno_exposure_operator_state_invalid")
    estimate = object_value(
        value["costEstimate"], "sno_exposure_estimate_invalid"
    )
    money_keys = (
        "targetComputeUsd",
        "targetDiskUsd",
        "operatorComputeUsd",
        "operatorDiskUsd",
        "estimatedUsdSubtotal",
        "estimatedTrySubtotal",
        "monthlyUsdAlertCeiling",
    )
    usage_keys = (
        "targetInstanceHours",
        "targetDiskGiBHours",
        "operatorInstanceHours",
        "operatorDiskGiBHours",
    )
    exact_keys(
        estimate,
        {
            *money_keys,
            *usage_keys,
            "estimateComplete",
            "unpricedResourceClasses",
            "excludedChargeClasses",
            "billingExportVerified",
            "estimateIsBilledSpend",
        },
        "sno_exposure_estimate_keys_invalid",
    )
    values = {
        key: decimal_value(estimate[key], "sno_exposure_estimate_invalid")
        for key in (*money_keys, *usage_keys)
    }
    subtotal = sum(
        (
            values["targetComputeUsd"],
            values["targetDiskUsd"],
            values["operatorComputeUsd"],
            values["operatorDiskUsd"],
        ),
        Decimal(0),
    )
    if (
        abs(subtotal - values["estimatedUsdSubtotal"]) > MONEY_QUANTUM
        or estimate["monthlyUsdAlertCeiling"]
        != decimal_text(Decimal(str(billing["monthlyUsdCeiling"])))
        or type(estimate["estimateComplete"]) is not bool
        or estimate["estimateComplete"] is not False
        or not isinstance(estimate["unpricedResourceClasses"], list)
        or estimate["unpricedResourceClasses"]
        != sorted(set(estimate["unpricedResourceClasses"]))
        or estimate["excludedChargeClasses"]
        != rate_card["excludedChargeClasses"]
        or estimate["billingExportVerified"] is not False
        or estimate["estimateIsBilledSpend"] is not False
    ):
        fail("sno_exposure_estimate_invalid")
    decision = object_value(
        value["decision"], "sno_exposure_decision_invalid"
    )
    exact_keys(
        decision,
        {"status", "reasonCodes", "nextAction"},
        "sno_exposure_decision_keys_invalid",
    )
    if decision != decision_for(state, estimate):
        fail("sno_exposure_decision_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_exposure_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_exposure_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_exposure_report_digest_invalid")


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except FileExistsError:
        fail("sno_exposure_output_exists")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--target-project-id", required=True)
    collect.add_argument("--operator-project-id", required=True)
    collect.add_argument("--operator-instance-name", required=True)
    collect.add_argument("--phase", choices=sorted(PHASES), required=True)
    collect.add_argument("--assessment-id", required=True)
    collect.add_argument("--output", type=Path, required=True)
    assess = commands.add_parser("assess")
    assess.add_argument("--snapshot", type=Path, required=True)
    assess.add_argument("--assessment-id", required=True)
    assess.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    commands.add_parser("validate-rate-card")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "validate-rate-card":
        rate_card = load_json(RATE_CARD)
        validate_rate_card(rate_card)
        print(
            "sno_cost_rate_card_valid "
            f"digest={canonical_digest(rate_card)} "
            "estimateIsBilledSpend=false"
        )
        return 0
    if args.command == "collect":
        snapshot = collect_snapshot(
            args.target_project_id,
            args.operator_project_id,
            args.operator_instance_name,
            args.phase,
            datetime.now(timezone.utc),
        )
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
    elif args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_exposure_live_snapshot_requires_collect")
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
    else:
        report = load_json(args.report)
        validate_assessment(report)
    print(
        "sno_resource_exposure_valid "
        f"digest={report['reportDigest']} "
        f"status={report['decision']['status']} "
        f"estimatedUsd={report['costEstimate']['estimatedUsdSubtotal']} "
        "estimateOnly=true teardownAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
