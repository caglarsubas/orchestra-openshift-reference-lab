#!/usr/bin/env python3
"""Create and verify short-lived operator leases for the SNO trial."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_sno_trial_profile import (
        ROOT,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_profile,
    )
except ModuleNotFoundError:
    from validate_sno_trial_profile import (  # type: ignore[no-redef]
        ROOT,
        TRIAL_PROFILE,
        TRIAL_PROFILE_ID,
        canonical_digest,
        load_json,
        validate_profile,
    )


PRODUCTION_PROFILE = ROOT / "config" / "lab.lock.json"
LEASE_KIND = "orchestra.openshift.sno-trial-lease.v1"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
GCP_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
LEASE_ID = re.compile(r"^sno-trial-[a-z0-9][a-z0-9-]{5,63}$")


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def parse_utc(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"trial_lease_time_invalid:{field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"trial_lease_time_invalid:{field}")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(f"trial_lease_time_invalid:{field}")
    return parsed


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def load_profile() -> dict[str, Any]:
    profile = load_json(TRIAL_PROFILE)
    validate_profile(profile, load_json(PRODUCTION_PROFILE))
    return profile


def build_lease(
    profile: dict[str, Any],
    project_id: str,
    operator_identity_digest: str,
    starts_at: datetime,
    hours: int,
    lease_id: str | None = None,
) -> dict[str, Any]:
    if not GCP_PROJECT.fullmatch(project_id):
        fail("trial_lease_project_invalid")
    if not DIGEST.fullmatch(operator_identity_digest):
        fail("trial_lease_operator_digest_invalid")
    maximum_hours = profile["guardrails"]["lease"]["maximumHours"]
    if type(hours) is not int or hours < 1 or hours > maximum_hours:
        fail("trial_lease_duration_invalid")
    if starts_at.tzinfo is None or starts_at.utcoffset() != timedelta(0):
        fail("trial_lease_start_not_utc")
    effective_id = lease_id or (
        f"sno-trial-{starts_at.strftime('%Y%m%d%H%M%S').lower()}-"
        f"{uuid.uuid4().hex[:8]}"
    )
    if not LEASE_ID.fullmatch(effective_id):
        fail("trial_lease_id_invalid")
    expires_at = starts_at + timedelta(hours=hours)
    return {
        "schemaVersion": 1,
        "kind": LEASE_KIND,
        "profileId": TRIAL_PROFILE_ID,
        "profileDigest": canonical_digest(profile),
        "leaseId": effective_id,
        "projectId": project_id,
        "operatorIdentityDigest": operator_identity_digest,
        "startsAt": utc_text(starts_at),
        "expiresAt": utc_text(expires_at),
        "maximumMonthlyBudgetUsd": profile["guardrails"]["budget"]["monthlyUsd"],
        "maximumActiveHoursPerMonth": profile["guardrails"]["budget"][
            "maxActiveHoursPerMonth"
        ],
        "budgetAcknowledged": True,
        "teardownRequired": True,
        "automaticProviderTeardown": False,
        "certificationEligible": False,
    }


def validate_lease(
    value: dict[str, Any],
    profile: dict[str, Any],
    at: datetime,
    expected_project_id: str | None = None,
) -> None:
    if set(value) != {
        "schemaVersion",
        "kind",
        "profileId",
        "profileDigest",
        "leaseId",
        "projectId",
        "operatorIdentityDigest",
        "startsAt",
        "expiresAt",
        "maximumMonthlyBudgetUsd",
        "maximumActiveHoursPerMonth",
        "budgetAcknowledged",
        "teardownRequired",
        "automaticProviderTeardown",
        "certificationEligible",
    }:
        fail("trial_lease_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["kind"] != LEASE_KIND
        or value["profileId"] != TRIAL_PROFILE_ID
        or value["profileDigest"] != canonical_digest(profile)
        or value["maximumMonthlyBudgetUsd"]
        != profile["guardrails"]["budget"]["monthlyUsd"]
        or value["maximumActiveHoursPerMonth"]
        != profile["guardrails"]["budget"]["maxActiveHoursPerMonth"]
        or value["budgetAcknowledged"] is not True
        or value["teardownRequired"] is not True
        or value["automaticProviderTeardown"] is not False
        or value["certificationEligible"] is not False
    ):
        fail("trial_lease_contract_invalid")
    if (
        not LEASE_ID.fullmatch(str(value["leaseId"]))
        or not GCP_PROJECT.fullmatch(str(value["projectId"]))
        or not DIGEST.fullmatch(str(value["operatorIdentityDigest"]))
    ):
        fail("trial_lease_identity_invalid")
    if expected_project_id is not None and value["projectId"] != expected_project_id:
        fail("trial_lease_project_mismatch")
    starts_at = parse_utc(value["startsAt"], "startsAt")
    expires_at = parse_utc(value["expiresAt"], "expiresAt")
    if (
        expires_at <= starts_at
        or expires_at - starts_at
        > timedelta(hours=profile["guardrails"]["lease"]["maximumHours"])
    ):
        fail("trial_lease_duration_invalid")
    if at.tzinfo is None or at.utcoffset() != timedelta(0):
        fail("trial_lease_assessment_not_utc")
    if at < starts_at:
        fail("trial_lease_not_started")
    if at >= expires_at:
        fail("trial_lease_expired")


def read_lease(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"trial_lease_invalid:{error}")
    if not isinstance(value, dict):
        fail("trial_lease_object_required")
    return value


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    output = path.resolve()
    allowed_root = (ROOT / "restricted" / "trial-leases").resolve()
    if allowed_root not in output.parents:
        fail("trial_lease_output_must_be_restricted")
    if output.exists():
        fail("trial_lease_output_already_exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--project-id", required=True)
    create.add_argument("--operator-identity-digest", required=True)
    create.add_argument("--hours", type=int, default=24)
    create.add_argument("--lease-id")
    create.add_argument("--starts-at")
    create.add_argument("--output", required=True, type=Path)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--lease", required=True, type=Path)
    verify.add_argument("--project-id", required=True)
    verify.add_argument("--at")

    args = parser.parse_args(argv)
    profile = load_profile()
    now = datetime.now(timezone.utc)
    if args.command == "create":
        starts_at = parse_utc(args.starts_at, "startsAt") if args.starts_at else now
        lease = build_lease(
            profile,
            args.project_id,
            args.operator_identity_digest,
            starts_at,
            args.hours,
            args.lease_id,
        )
        write_private_json(args.output, lease)
        print(
            f"trial_lease_created leaseId={lease['leaseId']} "
            f"expiresAt={lease['expiresAt']}"
        )
        return 0

    assessed_at = parse_utc(args.at, "assessment") if args.at else now
    lease = read_lease(args.lease.resolve())
    validate_lease(lease, profile, assessed_at, args.project_id)
    print(
        f"trial_lease_valid leaseId={lease['leaseId']} "
        f"expiresAt={lease['expiresAt']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
