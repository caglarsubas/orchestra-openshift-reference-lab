#!/usr/bin/env python3
"""Build and validate payload-free summaries of live foundation plans."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.prerequisite_observation import (
        PROFILE_ID,
        expected_bindings,
        parse_utc,
        payload_digest,
        require_digest,
    )
    from scripts.validate_repository import canonical_digest
except ModuleNotFoundError:
    from prerequisite_observation import (
        PROFILE_ID,
        expected_bindings,
        parse_utc,
        payload_digest,
        require_digest,
    )
    from validate_repository import canonical_digest


KIND = "orchestra.reference-lab.foundation-plan-summary.v1"
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
REF = "refs/heads/main"
WORKFLOW_REF = f"{REPOSITORY}/.github/workflows/foundation-plan.yml@{REF}"
ENVIRONMENT = "reference-lab-foundation-plan"
SHA = re.compile(r"^[a-f0-9]{40}$")
DIGITS = re.compile(r"^[1-9][0-9]*$")
SAFE_METADATA = re.compile(r'^[A-Za-z0-9_.:/@\-\[\]"]+$')
ACTION_CATEGORIES = {
    ("no-op",): "noOp",
    ("create",): "create",
    ("read",): "read",
    ("update",): "update",
    ("delete",): "delete",
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}
ACTION_COUNT_KEYS = ("noOp", "create", "read", "update", "delete", "replace")


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def load_json(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{code}:{error}")
    if not isinstance(value, dict):
        fail(code)
    return value


def require_safe_text(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or not SAFE_METADATA.fullmatch(value)
    ):
        fail(code)
    return value


def require_address(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= 4096)
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        fail("foundation_plan_resource_address_invalid")
    return value


def summarize_changes(
    plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    raw_changes = plan.get("resource_changes", [])
    if not isinstance(raw_changes, list):
        fail("foundation_plan_resource_changes_invalid")
    changes: list[dict[str, Any]] = []
    seen: set[str] = set()
    counts = {key: 0 for key in ACTION_COUNT_KEYS}
    for raw in raw_changes:
        if not isinstance(raw, dict):
            fail("foundation_plan_resource_change_invalid")
        address = require_address(raw.get("address"))
        if address in seen:
            fail("foundation_plan_resource_address_duplicate")
        seen.add(address)
        mode = raw.get("mode")
        if mode not in {"managed", "data"}:
            fail("foundation_plan_resource_mode_invalid")
        resource_type = require_safe_text(
            raw.get("type"), "foundation_plan_resource_type_invalid"
        )
        provider = require_safe_text(
            raw.get("provider_name"), "foundation_plan_provider_invalid"
        )
        change = raw.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        if not isinstance(actions, list) or not all(
            isinstance(action, str) for action in actions
        ):
            fail("foundation_plan_actions_invalid")
        category = ACTION_CATEGORIES.get(tuple(actions))
        if category is None:
            fail("foundation_plan_actions_invalid")
        counts[category] += 1
        changes.append(
            {
                "addressDigest": payload_digest(address),
                "mode": mode,
                "type": resource_type,
                "provider": provider,
                "actions": actions,
                "category": category,
            }
        )
    changes.sort(key=lambda item: item["addressDigest"])
    return changes, counts


def build_summary(
    plan: dict[str, Any],
    *,
    plan_digest: str,
    prerequisite_projection_digest: str,
    source_revision: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    actor_id: str,
    reason: str,
    execution_mode: str,
    created_at: str,
) -> dict[str, Any]:
    require_digest(plan_digest, "foundation_plan_digest_invalid")
    require_digest(
        prerequisite_projection_digest,
        "foundation_plan_prerequisite_projection_digest_invalid",
    )
    if not SHA.fullmatch(source_revision):
        fail("foundation_plan_source_revision_invalid")
    if not DIGITS.fullmatch(workflow_run_id) or not DIGITS.fullmatch(
        workflow_run_attempt
    ):
        fail("foundation_plan_workflow_run_invalid")
    if not DIGITS.fullmatch(actor_id):
        fail("foundation_plan_actor_id_invalid")
    if not isinstance(reason, str) or not (12 <= len(reason.strip()) <= 500):
        fail("foundation_plan_reason_invalid")
    if execution_mode not in {"simulated", "live"}:
        fail("foundation_plan_execution_mode_invalid")
    parse_utc(created_at, "foundation_plan_created_at_invalid")
    format_version = plan.get("format_version")
    terraform_version = plan.get("terraform_version")
    if not isinstance(format_version, str) or not format_version:
        fail("foundation_plan_format_version_invalid")
    if terraform_version != "1.14.6":
        fail("foundation_plan_terraform_version_invalid")
    changes, counts = summarize_changes(plan)
    result = {
        "schemaVersion": 1,
        "kind": KIND,
        "profileId": PROFILE_ID,
        "targetClass": (
            "vendor-reference-lab" if execution_mode == "live" else "fixture"
        ),
        "executionMode": execution_mode,
        "bindings": {
            **expected_bindings(),
            "prerequisiteProjectionDigest": prerequisite_projection_digest,
        },
        "source": {
            "repository": REPOSITORY,
            "revision": source_revision,
            "ref": REF,
            "workflowRef": WORKFLOW_REF,
            "environment": ENVIRONMENT,
            "workflowRunId": workflow_run_id,
            "workflowRunAttempt": workflow_run_attempt,
            "actorIdentityDigest": payload_digest(actor_id),
            "authorizationReasonDigest": payload_digest(reason.strip()),
        },
        "terraform": {
            "version": terraform_version,
            "formatVersion": format_version,
            "planDigest": plan_digest,
            "refreshEnabled": True,
            "stateLockUsed": False,
            "resourceChanges": changes,
            "actionCounts": counts,
        },
        "createdAt": created_at,
        "claims": {
            "readOnlyPlan": True,
            "applyAuthorized": False,
            "infrastructureApplied": False,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
        },
    }
    validate_summary(result)
    return result


def validate_summary(value: dict[str, Any]) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "source",
            "terraform",
            "createdAt",
            "claims",
        },
        "foundation_plan_summary_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != KIND
        or value["profileId"] != PROFILE_ID
        or (value["targetClass"], value["executionMode"])
        not in {("fixture", "simulated"), ("vendor-reference-lab", "live")}
    ):
        fail("foundation_plan_summary_identity_invalid")
    bindings = strict_keys(
        value["bindings"],
        {
            "topologyDigest",
            "releaseSetDigest",
            "policyDigest",
            "prerequisiteProjectionDigest",
        },
        "foundation_plan_summary_bindings_invalid",
    )
    expected = expected_bindings()
    if any(bindings[name] != digest for name, digest in expected.items()):
        fail("foundation_plan_summary_bindings_invalid")
    require_digest(
        bindings["prerequisiteProjectionDigest"],
        "foundation_plan_summary_bindings_invalid",
    )
    source = strict_keys(
        value["source"],
        {
            "repository",
            "revision",
            "ref",
            "workflowRef",
            "environment",
            "workflowRunId",
            "workflowRunAttempt",
            "actorIdentityDigest",
            "authorizationReasonDigest",
        },
        "foundation_plan_summary_source_invalid",
    )
    if (
        source["repository"] != REPOSITORY
        or source["ref"] != REF
        or source["workflowRef"] != WORKFLOW_REF
        or source["environment"] != ENVIRONMENT
        or not isinstance(source["revision"], str)
        or not SHA.fullmatch(source["revision"])
        or not isinstance(source["workflowRunId"], str)
        or not DIGITS.fullmatch(source["workflowRunId"])
        or not isinstance(source["workflowRunAttempt"], str)
        or not DIGITS.fullmatch(source["workflowRunAttempt"])
    ):
        fail("foundation_plan_summary_source_invalid")
    require_digest(
        source["actorIdentityDigest"], "foundation_plan_summary_source_invalid"
    )
    require_digest(
        source["authorizationReasonDigest"],
        "foundation_plan_summary_source_invalid",
    )
    terraform = strict_keys(
        value["terraform"],
        {
            "version",
            "formatVersion",
            "planDigest",
            "refreshEnabled",
            "stateLockUsed",
            "resourceChanges",
            "actionCounts",
        },
        "foundation_plan_summary_terraform_invalid",
    )
    if (
        terraform["version"] != "1.14.6"
        or not isinstance(terraform["formatVersion"], str)
        or not terraform["formatVersion"]
        or terraform["refreshEnabled"] is not True
        or terraform["stateLockUsed"] is not False
    ):
        fail("foundation_plan_summary_terraform_invalid")
    require_digest(terraform["planDigest"], "foundation_plan_summary_terraform_invalid")
    resources = terraform["resourceChanges"]
    if not isinstance(resources, list):
        fail("foundation_plan_summary_resources_invalid")
    addresses: list[str] = []
    counts = {key: 0 for key in ACTION_COUNT_KEYS}
    for resource in resources:
        strict_keys(
            resource,
            {"addressDigest", "mode", "type", "provider", "actions", "category"},
            "foundation_plan_summary_resource_invalid",
        )
        require_digest(
            resource["addressDigest"], "foundation_plan_summary_resource_invalid"
        )
        require_safe_text(resource["type"], "foundation_plan_summary_resource_invalid")
        require_safe_text(
            resource["provider"], "foundation_plan_summary_resource_invalid"
        )
        category = ACTION_CATEGORIES.get(tuple(resource["actions"]))
        if (
            resource["mode"] not in {"managed", "data"}
            or category is None
            or resource["category"] != category
        ):
            fail("foundation_plan_summary_resource_invalid")
        addresses.append(resource["addressDigest"])
        counts[category] += 1
    if addresses != sorted(set(addresses)):
        fail("foundation_plan_summary_resources_invalid")
    if terraform["actionCounts"] != counts:
        fail("foundation_plan_summary_action_counts_invalid")
    parse_utc(value["createdAt"], "foundation_plan_summary_created_at_invalid")
    if value["claims"] != {
        "readOnlyPlan": True,
        "applyAuthorized": False,
        "infrastructureApplied": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("foundation_plan_summary_claims_invalid")
    return canonical_digest(value)


def write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        fail("foundation_plan_summary_output_exists")
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--plan-json", type=Path, required=True)
    build.add_argument("--plan-digest", required=True)
    build.add_argument("--prerequisite-projection-digest", required=True)
    build.add_argument("--source-revision", required=True)
    build.add_argument("--workflow-run-id", required=True)
    build.add_argument("--workflow-run-attempt", required=True)
    build.add_argument("--actor-id", required=True)
    build.add_argument("--reason", required=True)
    build.add_argument("--execution-mode", choices=("simulated", "live"), required=True)
    build.add_argument("--created-at", required=True)
    build.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "build":
        summary = build_summary(
            load_json(args.plan_json, "foundation_plan_json_invalid"),
            plan_digest=args.plan_digest,
            prerequisite_projection_digest=args.prerequisite_projection_digest,
            source_revision=args.source_revision,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            actor_id=args.actor_id,
            reason=args.reason,
            execution_mode=args.execution_mode,
            created_at=args.created_at,
        )
        write_new(args.output, summary)
        digest = validate_summary(summary)
    else:
        summary = load_json(args.summary, "foundation_plan_summary_json_invalid")
        digest = validate_summary(summary)
    print(
        "foundation_plan_summary_valid "
        f"digest={digest} targetClass={summary['targetClass']} "
        f"executionMode={summary['executionMode']} "
        f"changes={len(summary['terraform']['resourceChanges'])} "
        "applyAuthorized=false infrastructureApplied=false "
        "campaignEvidence=false referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
