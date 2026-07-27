#!/usr/bin/env python3
"""Observe a live SNO trial cluster without deployment or certification authority."""

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
    from scripts.sno_trial_operator_path import (
        executable_path,
        read_source_network,
    )
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
    from sno_trial_operator_path import (  # type: ignore[no-redef]
        executable_path,
        read_source_network,
    )
    from validate_sno_trial_profile import (  # type: ignore[no-redef]
        PRODUCTION_PROFILE,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_production_isolation,
        validate_profile,
    )


REPORT_KIND = "orchestra.openshift.sno-trial-cluster-observation.v1"
SNAPSHOT_KIND = "orchestra.openshift.sno-trial-cluster-snapshot.v1"
EXPECTED_VERSION = "4.20.27"
EXPECTED_REGION = "europe-west1"
EXPECTED_MACHINE_TYPE = "n2-standard-8"
EXPECTED_ISSUER = "https://storage.googleapis.com/orchestra-trial-oidc"
EXPECTED_STORAGE_CLASS = "standard-csi"
EXPECTED_STORAGE_PROVISIONER = "pd.csi.storage.gke.io"
ASSESSMENT_ID = re.compile(r"^sno-cluster-[a-z0-9][a-z0-9.-]{5,79}$")
PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
EXECUTION_MODES = {"simulated", "live-diagnostic"}
REASON_CODES = (
    "VERSION_MISMATCH",
    "TOPOLOGY_MISMATCH",
    "CREDENTIAL_CONFIGURATION_MISMATCH",
    "NODE_SHAPE_MISMATCH",
    "OPERATOR_HEALTH_MISMATCH",
    "COMPUTE_INVENTORY_MISMATCH",
    "ADMIN_SOURCE_MISMATCH",
    "CONSOLE_UNAVAILABLE",
    "STORAGE_CONFIGURATION_MISMATCH",
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
    "rawCommandOutputStored": False,
    "credentialValuesStored": False,
    "kubeconfigStored": False,
    "consoleCredentialStored": False,
    "cloudMutationAuthorized": False,
    "workloadMutationAuthorized": False,
    "teardownAuthorized": False,
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


def run_text(run: CommandRunner, command: list[str], code: str) -> str:
    try:
        return run(command).stdout.strip()
    except (
        OSError,
        subprocess.SubprocessError,
        subprocess.TimeoutExpired,
    ):
        fail(code)


def condition_status(value: dict[str, Any], name: str) -> str:
    for condition in value.get("status", {}).get("conditions", []):
        if condition.get("type") == name:
            return str(condition.get("status", "Unknown"))
    return "Unknown"


def resource_items(value: Any, code: str) -> list[dict[str, Any]]:
    result = object_value(value, code).get("items")
    if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
        fail(code)
    return result


def path_tail(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value:
        fail(code)
    return value.rstrip("/").rsplit("/", 1)[-1]


def collect_snapshot(
    project_id: str,
    source_cidr_file: Path,
    client_path: Path,
    observed_at: datetime,
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    if not PROJECT_ID.fullmatch(project_id):
        fail("sno_cluster_project_id_invalid")
    client = str(
        executable_path(client_path, "sno_cluster_client_invalid")
    )
    source_network = read_source_network(source_cidr_file)

    def oc(*arguments: str) -> Any:
        return run_json(
            run,
            [client, *arguments, "-o", "json"],
            "sno_cluster_oc_observation_failed",
        )

    version_resource = object_value(
        oc("get", "clusterversion", "version"),
        "sno_cluster_version_observation_invalid",
    )
    infrastructure = object_value(
        oc("get", "infrastructure", "cluster"),
        "sno_cluster_infrastructure_observation_invalid",
    )
    cloud_credential = object_value(
        oc("get", "cloudcredential", "cluster"),
        "sno_cluster_credential_observation_invalid",
    )
    authentication = object_value(
        oc("get", "authentication", "cluster"),
        "sno_cluster_authentication_observation_invalid",
    )
    nodes = resource_items(
        oc("get", "nodes"), "sno_cluster_node_observation_invalid"
    )
    operators = resource_items(
        oc("get", "clusteroperators"),
        "sno_cluster_operator_observation_invalid",
    )
    machines = resource_items(
        oc("get", "machines", "-n", "openshift-machine-api"),
        "sno_cluster_machine_observation_invalid",
    )
    route = object_value(
        oc("get", "route", "console", "-n", "openshift-console"),
        "sno_cluster_console_observation_invalid",
    )
    storage_classes = resource_items(
        oc("get", "storageclasses"),
        "sno_cluster_storage_observation_invalid",
    )
    infra_name = infrastructure.get("status", {}).get("infrastructureName")
    if not isinstance(infra_name, str) or not infra_name:
        fail("sno_cluster_infrastructure_observation_invalid")
    instances = run_json(
        run,
        [
            "gcloud",
            "compute",
            "instances",
            "list",
            f"--project={project_id}",
            f"--filter=name~^{infra_name}",
            "--format=json(name,status,machineType)",
        ],
        "sno_cluster_compute_observation_failed",
    )
    firewalls = run_json(
        run,
        [
            "gcloud",
            "compute",
            "firewall-rules",
            "list",
            f"--project={project_id}",
            f"--filter=name~^{infra_name}",
            "--format=json(name,sourceRanges,allowed,targetTags)",
        ],
        "sno_cluster_firewall_observation_failed",
    )
    if not isinstance(instances, list) or not isinstance(firewalls, list):
        fail("sno_cluster_provider_observation_invalid")
    console_host = route.get("spec", {}).get("host")
    if not isinstance(console_host, str) or not console_host:
        fail("sno_cluster_console_observation_invalid")
    console_status = run_text(
        run,
        [
            "curl",
            "--silent",
            "--show-error",
            "--insecure",
            "--max-time",
            "15",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            f"https://{console_host}",
        ],
        "sno_cluster_console_probe_failed",
    )

    version_status = version_resource.get("status", {})
    platform_status = infrastructure.get("status", {}).get("platformStatus", {})
    gcp_status = (
        platform_status.get("gcp", {})
        if isinstance(platform_status, dict)
        else {}
    )
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-diagnostic",
        "observedAt": utc_text(observed_at),
        "projectId": project_id,
        "clusterVersion": {
            "version": version_status.get("desired", {}).get("version"),
            "available": condition_status(version_resource, "Available"),
            "progressing": condition_status(version_resource, "Progressing"),
            "failing": condition_status(version_resource, "Failing"),
        },
        "infrastructure": {
            "platform": infrastructure.get("status", {}).get("platform"),
            "topology": infrastructure.get("status", {}).get(
                "controlPlaneTopology"
            ),
            "region": gcp_status.get("region"),
            "infrastructureName": infra_name,
        },
        "credentials": {
            "mode": cloud_credential.get("spec", {}).get("credentialsMode"),
            "serviceAccountIssuer": authentication.get("spec", {}).get(
                "serviceAccountIssuer"
            ),
        },
        "nodes": [
            {
                "name": item.get("metadata", {}).get("name"),
                "architecture": item.get("status", {})
                .get("nodeInfo", {})
                .get("architecture"),
                "ready": condition_status(item, "Ready"),
                "schedulable": item.get("spec", {}).get("unschedulable")
                is not True,
                "roles": sorted(
                    key.rsplit("/", 1)[-1]
                    for key in item.get("metadata", {}).get("labels", {})
                    if key.startswith("node-role.kubernetes.io/")
                ),
            }
            for item in nodes
        ],
        "machines": [
            {
                "name": item.get("metadata", {}).get("name"),
                "role": item.get("metadata", {})
                .get("labels", {})
                .get("machine.openshift.io/cluster-api-machine-role"),
                "machineType": item.get("spec", {})
                .get("providerSpec", {})
                .get("value", {})
                .get("machineType"),
                "phase": item.get("status", {}).get("phase"),
            }
            for item in machines
        ],
        "operators": [
            {
                "name": item.get("metadata", {}).get("name"),
                "version": next(
                    (
                        version.get("version")
                        for version in item.get("status", {}).get(
                            "versions", []
                        )
                        if version.get("name") == "operator"
                    ),
                    "",
                ),
                "available": condition_status(item, "Available"),
                "progressing": condition_status(item, "Progressing"),
                "degraded": condition_status(item, "Degraded"),
            }
            for item in operators
        ],
        "console": {
            "host": console_host,
            "statusCode": console_status,
        },
        "storageClasses": [
            {
                "name": item.get("metadata", {}).get("name"),
                "provisioner": item.get("provisioner"),
                "default": item.get("metadata", {})
                .get("annotations", {})
                .get("storageclass.kubernetes.io/is-default-class")
                == "true",
                "volumeBindingMode": item.get("volumeBindingMode"),
                "allowExpansion": item.get("allowVolumeExpansion") is True,
            }
            for item in storage_classes
        ],
        "compute": [
            {
                "name": item.get("name"),
                "status": item.get("status"),
                "machineType": path_tail(
                    item.get("machineType"),
                    "sno_cluster_compute_observation_invalid",
                ),
            }
            for item in instances
            if isinstance(item, dict)
        ],
        "apiFirewalls": [
            {
                "name": item.get("name"),
                "sourceRanges": sorted(item.get("sourceRanges", [])),
            }
            for item in firewalls
            if isinstance(item, dict) and item.get("name") == f"{infra_name}-api"
        ],
        "expectedSourceCidrDigest": source_network["cidrDigest"],
    }
    for key in (
        "nodes",
        "machines",
        "operators",
        "storageClasses",
        "compute",
        "apiFirewalls",
    ):
        snapshot[key].sort(key=lambda item: item["name"])
    validate_snapshot(snapshot)
    return snapshot


def validate_named_items(
    value: Any, expected_keys: set[str], code: str
) -> list[dict[str, Any]]:
    items = list_value(value, code)
    if any(not isinstance(item, dict) or set(item) != expected_keys for item in items):
        fail(code)
    names = [item["name"] for item in items]
    if any(not isinstance(name, str) or not name for name in names):
        fail(code)
    if names != sorted(names) or len(names) != len(set(names)):
        fail(code)
    return items


def validate_snapshot(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "executionMode",
            "observedAt",
            "projectId",
            "clusterVersion",
            "infrastructure",
            "credentials",
            "nodes",
            "machines",
            "operators",
            "console",
            "storageClasses",
            "compute",
            "apiFirewalls",
            "expectedSourceCidrDigest",
        },
        "sno_cluster_snapshot_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or value["executionMode"] not in EXECUTION_MODES
        or not PROJECT_ID.fullmatch(str(value["projectId"]))
        or not DIGEST.fullmatch(str(value["expectedSourceCidrDigest"]))
    ):
        fail("sno_cluster_snapshot_identity_invalid")
    parse_utc(value["observedAt"], "sno_cluster_snapshot_time_invalid")
    version = object_value(
        value["clusterVersion"], "sno_cluster_version_invalid"
    )
    exact_keys(
        version,
        {"version", "available", "progressing", "failing"},
        "sno_cluster_version_keys_invalid",
    )
    if any(
        not isinstance(version[key], str)
        for key in ("version", "available", "progressing", "failing")
    ):
        fail("sno_cluster_version_invalid")
    infrastructure = object_value(
        value["infrastructure"], "sno_cluster_infrastructure_invalid"
    )
    exact_keys(
        infrastructure,
        {"platform", "topology", "region", "infrastructureName"},
        "sno_cluster_infrastructure_keys_invalid",
    )
    if any(not isinstance(item, str) or not item for item in infrastructure.values()):
        fail("sno_cluster_infrastructure_invalid")
    credentials = object_value(
        value["credentials"], "sno_cluster_credentials_invalid"
    )
    exact_keys(
        credentials,
        {"mode", "serviceAccountIssuer"},
        "sno_cluster_credentials_keys_invalid",
    )
    if any(not isinstance(item, str) or not item for item in credentials.values()):
        fail("sno_cluster_credentials_invalid")
    nodes = validate_named_items(
        value["nodes"],
        {"name", "architecture", "ready", "schedulable", "roles"},
        "sno_cluster_nodes_invalid",
    )
    for node in nodes:
        if (
            not isinstance(node["architecture"], str)
            or node["ready"] not in {"True", "False", "Unknown"}
            or type(node["schedulable"]) is not bool
            or not isinstance(node["roles"], list)
            or node["roles"] != sorted(set(node["roles"]))
            or any(not isinstance(role, str) or not role for role in node["roles"])
        ):
            fail("sno_cluster_nodes_invalid")
    machines = validate_named_items(
        value["machines"],
        {"name", "role", "machineType", "phase"},
        "sno_cluster_machines_invalid",
    )
    for machine in machines:
        if any(
            not isinstance(machine[key], str) or not machine[key]
            for key in ("role", "machineType", "phase")
        ):
            fail("sno_cluster_machines_invalid")
    operators = validate_named_items(
        value["operators"],
        {"name", "version", "available", "progressing", "degraded"},
        "sno_cluster_operators_invalid",
    )
    for operator in operators:
        if any(
            not isinstance(operator[key], str)
            for key in ("version", "available", "progressing", "degraded")
        ):
            fail("sno_cluster_operators_invalid")
    console = object_value(value["console"], "sno_cluster_console_invalid")
    exact_keys(
        console, {"host", "statusCode"}, "sno_cluster_console_keys_invalid"
    )
    if (
        not isinstance(console["host"], str)
        or not console["host"]
        or not re.fullmatch(r"[1-5][0-9]{2}", str(console["statusCode"]))
    ):
        fail("sno_cluster_console_invalid")
    storage = validate_named_items(
        value["storageClasses"],
        {
            "name",
            "provisioner",
            "default",
            "volumeBindingMode",
            "allowExpansion",
        },
        "sno_cluster_storage_invalid",
    )
    for item in storage:
        if (
            not isinstance(item["provisioner"], str)
            or not item["provisioner"]
            or type(item["default"]) is not bool
            or not isinstance(item["volumeBindingMode"], str)
            or type(item["allowExpansion"]) is not bool
        ):
            fail("sno_cluster_storage_invalid")
    compute = validate_named_items(
        value["compute"],
        {"name", "status", "machineType"},
        "sno_cluster_compute_invalid",
    )
    for instance in compute:
        if any(
            not isinstance(instance[key], str) or not instance[key]
            for key in ("status", "machineType")
        ):
            fail("sno_cluster_compute_invalid")
    firewalls = validate_named_items(
        value["apiFirewalls"],
        {"name", "sourceRanges"},
        "sno_cluster_firewalls_invalid",
    )
    for firewall in firewalls:
        ranges = firewall["sourceRanges"]
        if (
            not isinstance(ranges, list)
            or ranges != sorted(set(ranges))
            or any(not isinstance(item, str) or not item for item in ranges)
        ):
            fail("sno_cluster_firewalls_invalid")


def cluster_state(snapshot: dict[str, Any]) -> dict[str, Any]:
    version = snapshot["clusterVersion"]
    infrastructure = snapshot["infrastructure"]
    credentials = snapshot["credentials"]
    nodes = snapshot["nodes"]
    machines = snapshot["machines"]
    operators = snapshot["operators"]
    compute = snapshot["compute"]
    firewalls = snapshot["apiFirewalls"]
    storage = snapshot["storageClasses"]
    expected_source_digest = snapshot["expectedSourceCidrDigest"]
    api_source_digests = sorted(
        canonical_digest(source)
        for firewall in firewalls
        for source in firewall["sourceRanges"]
    )
    version_matches = version == {
        "version": EXPECTED_VERSION,
        "available": "True",
        "progressing": "False",
        "failing": "False",
    }
    topology_matches = (
        infrastructure["platform"] == "GCP"
        and infrastructure["topology"] == "SingleReplica"
        and infrastructure["region"] == EXPECTED_REGION
    )
    credential_configuration_matches = (
        credentials["mode"] == "Manual"
        and credentials["serviceAccountIssuer"] == EXPECTED_ISSUER
    )
    expected_roles = ["control-plane", "master", "worker"]
    ready_schedulable_nodes = [
        node
        for node in nodes
        if node["architecture"] == "amd64"
        and node["ready"] == "True"
        and node["schedulable"]
        and node["roles"] == expected_roles
    ]
    worker_machines = [
        machine for machine in machines if machine["role"] == "worker"
    ]
    node_shape_matches = (
        len(nodes) == 1
        and len(ready_schedulable_nodes) == 1
        and len(machines) == 1
        and len(worker_machines) == 0
        and machines[0]["role"] == "master"
        and machines[0]["machineType"] == EXPECTED_MACHINE_TYPE
        and machines[0]["phase"] == "Running"
    )
    healthy_operators = [
        operator
        for operator in operators
        if operator["version"] == EXPECTED_VERSION
        and operator["available"] == "True"
        and operator["progressing"] == "False"
        and operator["degraded"] == "False"
    ]
    operator_health_matches = (
        len(operators) >= 30 and len(healthy_operators) == len(operators)
    )
    running_instances = [
        instance for instance in compute if instance["status"] == "RUNNING"
    ]
    bootstrap_instances = [
        instance for instance in compute if "bootstrap" in instance["name"]
    ]
    master_instances = [
        instance for instance in compute if "master" in instance["name"]
    ]
    compute_inventory_matches = (
        len(compute) == 1
        and len(running_instances) == 1
        and len(bootstrap_instances) == 0
        and len(master_instances) == 1
        and running_instances[0]["machineType"] == EXPECTED_MACHINE_TYPE
    )
    admin_source_matches = (
        len(firewalls) == 1
        and len(api_source_digests) == 1
        and api_source_digests[0] == expected_source_digest
    )
    console_reachable = snapshot["console"]["statusCode"] == "200"
    default_storage = [
        item
        for item in storage
        if item["name"] == EXPECTED_STORAGE_CLASS and item["default"]
    ]
    storage_configuration_matches = (
        len(default_storage) == 1
        and default_storage[0]["provisioner"] == EXPECTED_STORAGE_PROVISIONER
        and default_storage[0]["volumeBindingMode"] == "WaitForFirstConsumer"
        and default_storage[0]["allowExpansion"]
    )
    return {
        "observedAt": snapshot["observedAt"],
        "projectId": snapshot["projectId"],
        "projectIdentityDigest": canonical_digest(snapshot["projectId"]),
        "version": version["version"],
        "versionMatches": version_matches,
        "topology": infrastructure["topology"],
        "region": infrastructure["region"],
        "infrastructureIdentityDigest": canonical_digest(
            infrastructure["infrastructureName"]
        ),
        "topologyMatches": topology_matches,
        "credentialMode": credentials["mode"],
        "serviceAccountIssuerDigest": canonical_digest(
            credentials["serviceAccountIssuer"]
        ),
        "credentialConfigurationMatches": credential_configuration_matches,
        "nodeCount": len(nodes),
        "readySchedulableNodeCount": len(ready_schedulable_nodes),
        "workerMachineCount": len(worker_machines),
        "nodeSetDigest": canonical_digest(
            sorted(node["name"] for node in nodes)
        ),
        "nodeShapeMatches": node_shape_matches,
        "operatorCount": len(operators),
        "healthyOperatorCount": len(healthy_operators),
        "operatorSetDigest": canonical_digest(
            sorted(operator["name"] for operator in operators)
        ),
        "operatorHealthMatches": operator_health_matches,
        "computeInstanceCount": len(compute),
        "bootstrapInstanceCount": len(bootstrap_instances),
        "masterInstanceCount": len(master_instances),
        "computeSetDigest": canonical_digest(
            sorted(instance["name"] for instance in compute)
        ),
        "computeInventoryMatches": compute_inventory_matches,
        "apiFirewallCount": len(firewalls),
        "apiSourceSetDigest": canonical_digest(api_source_digests),
        "adminSourceMatches": admin_source_matches,
        "consoleHostDigest": canonical_digest(snapshot["console"]["host"]),
        "consoleStatusCode": int(snapshot["console"]["statusCode"]),
        "consoleReachable": console_reachable,
        "storageClassCount": len(storage),
        "storageClassSetDigest": canonical_digest(
            sorted(item["name"] for item in storage)
        ),
        "defaultStorageClass": (
            default_storage[0]["name"] if default_storage else ""
        ),
        "storageConfigurationMatches": storage_configuration_matches,
        "trialShapeMatches": all(
            (
                version_matches,
                topology_matches,
                credential_configuration_matches,
                node_shape_matches,
                operator_health_matches,
                compute_inventory_matches,
                admin_source_matches,
                console_reachable,
                storage_configuration_matches,
            )
        ),
    }


def decision_for(state: dict[str, Any]) -> dict[str, Any]:
    checks = (
        ("versionMatches", "VERSION_MISMATCH"),
        ("topologyMatches", "TOPOLOGY_MISMATCH"),
        (
            "credentialConfigurationMatches",
            "CREDENTIAL_CONFIGURATION_MISMATCH",
        ),
        ("nodeShapeMatches", "NODE_SHAPE_MISMATCH"),
        ("operatorHealthMatches", "OPERATOR_HEALTH_MISMATCH"),
        ("computeInventoryMatches", "COMPUTE_INVENTORY_MISMATCH"),
        ("adminSourceMatches", "ADMIN_SOURCE_MISMATCH"),
        ("consoleReachable", "CONSOLE_UNAVAILABLE"),
        (
            "storageConfigurationMatches",
            "STORAGE_CONFIGURATION_MISMATCH",
        ),
    )
    reasons = [reason for key, reason in checks if not state[key]]
    if reasons:
        return {
            "status": "BLOCKED",
            "reasonCodes": reasons,
            "nextAction": "reconcile-live-trial-cluster",
        }
    return {
        "status": "TRIAL_CLUSTER_OBSERVED",
        "reasonCodes": [],
        "nextAction": "capture-cost-and-plan-teardown",
    }


def build_assessment(
    snapshot: dict[str, Any], assessment_id: str
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_cluster_assessment_id_invalid")
    profile = load_json(TRIAL_PROFILE)
    production = load_json(PRODUCTION_PROFILE)
    validate_profile(profile, production)
    validate_production_isolation()
    state = cluster_state(snapshot)
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
        "clusterState": state,
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
            "clusterState",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_cluster_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_cluster_report_identity_invalid")
    parse_utc(value["generatedAt"], "sno_cluster_report_time_invalid")
    bindings = object_value(value["bindings"], "sno_cluster_bindings_invalid")
    exact_keys(
        bindings,
        {
            "profileId",
            "profileDigest",
            "projectId",
            "projectIdentityDigest",
        },
        "sno_cluster_bindings_keys_invalid",
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
        fail("sno_cluster_bindings_invalid")
    state = object_value(
        value["clusterState"], "sno_cluster_state_invalid"
    )
    exact_keys(
        state,
        {
            "observedAt",
            "projectId",
            "projectIdentityDigest",
            "version",
            "versionMatches",
            "topology",
            "region",
            "infrastructureIdentityDigest",
            "topologyMatches",
            "credentialMode",
            "serviceAccountIssuerDigest",
            "credentialConfigurationMatches",
            "nodeCount",
            "readySchedulableNodeCount",
            "workerMachineCount",
            "nodeSetDigest",
            "nodeShapeMatches",
            "operatorCount",
            "healthyOperatorCount",
            "operatorSetDigest",
            "operatorHealthMatches",
            "computeInstanceCount",
            "bootstrapInstanceCount",
            "masterInstanceCount",
            "computeSetDigest",
            "computeInventoryMatches",
            "apiFirewallCount",
            "apiSourceSetDigest",
            "adminSourceMatches",
            "consoleHostDigest",
            "consoleStatusCode",
            "consoleReachable",
            "storageClassCount",
            "storageClassSetDigest",
            "defaultStorageClass",
            "storageConfigurationMatches",
            "trialShapeMatches",
        },
        "sno_cluster_state_keys_invalid",
    )
    parse_utc(state["observedAt"], "sno_cluster_state_time_invalid")
    count_keys = (
        "nodeCount",
        "readySchedulableNodeCount",
        "workerMachineCount",
        "operatorCount",
        "healthyOperatorCount",
        "computeInstanceCount",
        "bootstrapInstanceCount",
        "masterInstanceCount",
        "apiFirewallCount",
        "consoleStatusCode",
        "storageClassCount",
    )
    bool_keys = (
        "versionMatches",
        "topologyMatches",
        "credentialConfigurationMatches",
        "nodeShapeMatches",
        "operatorHealthMatches",
        "computeInventoryMatches",
        "adminSourceMatches",
        "consoleReachable",
        "storageConfigurationMatches",
        "trialShapeMatches",
    )
    digest_keys = (
        "projectIdentityDigest",
        "infrastructureIdentityDigest",
        "serviceAccountIssuerDigest",
        "nodeSetDigest",
        "operatorSetDigest",
        "computeSetDigest",
        "apiSourceSetDigest",
        "consoleHostDigest",
        "storageClassSetDigest",
    )
    string_keys = (
        "version",
        "topology",
        "region",
        "credentialMode",
        "defaultStorageClass",
    )
    if (
        state["observedAt"] != value["generatedAt"]
        or state["projectId"] != bindings["projectId"]
        or not PROJECT_ID.fullmatch(str(state["projectId"]))
        or state["projectIdentityDigest"] != bindings["projectIdentityDigest"]
        or any(not isinstance(state[key], str) for key in string_keys)
        or any(type(state[key]) is not int or state[key] < 0 for key in count_keys)
        or any(type(state[key]) is not bool for key in bool_keys)
        or any(not DIGEST.fullmatch(str(state[key])) for key in digest_keys)
        or state["healthyOperatorCount"] > state["operatorCount"]
        or state["readySchedulableNodeCount"] > state["nodeCount"]
        or state["consoleReachable"] != (state["consoleStatusCode"] == 200)
        or state["trialShapeMatches"]
        != all(
            state[key]
            for key in (
                "versionMatches",
                "topologyMatches",
                "credentialConfigurationMatches",
                "nodeShapeMatches",
                "operatorHealthMatches",
                "computeInventoryMatches",
                "adminSourceMatches",
                "consoleReachable",
                "storageConfigurationMatches",
            )
        )
    ):
        fail("sno_cluster_state_invalid")
    decision = object_value(
        value["decision"], "sno_cluster_decision_invalid"
    )
    exact_keys(
        decision,
        {"status", "reasonCodes", "nextAction"},
        "sno_cluster_decision_keys_invalid",
    )
    if (
        decision != decision_for(state)
        or any(reason not in REASON_CODES for reason in decision["reasonCodes"])
    ):
        fail("sno_cluster_decision_invalid")
    if value["controls"] != CONTROLS:
        fail("sno_cluster_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_cluster_claims_invalid")
    digest = value["reportDigest"]
    unsigned = copy.deepcopy(value)
    unsigned.pop("reportDigest")
    if not isinstance(digest, str) or digest != canonical_digest(unsigned):
        fail("sno_cluster_report_digest_invalid")


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except FileExistsError:
        fail("sno_cluster_output_exists")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--project-id", required=True)
    collect.add_argument("--source-cidr-file", type=Path, required=True)
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
            args.client,
            datetime.now(timezone.utc),
        )
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
        print(
            "sno_cluster_observation_collected "
            f"status={report['decision']['status']} "
            f"version={report['clusterState']['version']} "
            f"nodes={report['clusterState']['nodeCount']} "
            f"operators={report['clusterState']['healthyOperatorCount']}/"
            f"{report['clusterState']['operatorCount']} "
            "campaignEvidence=false referenceProfileVerified=false"
        )
        return 0
    if args.command == "assess":
        snapshot = load_json(args.snapshot)
        if snapshot.get("executionMode") != "simulated":
            fail("sno_cluster_live_snapshot_requires_collect")
        report = build_assessment(snapshot, args.assessment_id)
        write_json_create_only(args.output, report)
        print(
            "sno_cluster_observation_assessed "
            f"status={report['decision']['status']} "
            "campaignEvidence=false referenceProfileVerified=false"
        )
        return 0
    report = load_json(args.report)
    validate_assessment(report)
    print(
        "sno_cluster_observation_valid "
        f"digest={report['reportDigest']} "
        f"status={report['decision']['status']} "
        "campaignEvidence=false referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
