#!/usr/bin/env python3
"""Render the SNO trial installer configuration behind an active lease."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

try:
    from scripts.trial_lease import (
        ROOT,
        load_profile,
        parse_utc,
        read_lease,
        validate_lease,
    )
except ModuleNotFoundError:
    from trial_lease import (  # type: ignore[no-redef]
        ROOT,
        load_profile,
        parse_utc,
        read_lease,
        validate_lease,
    )


TEMPLATE = ROOT / "infra" / "openshift" / "install-config.sno-trial.template.yaml"
ALLOWED_VALUES = {"TARGET_PROJECT_ID"}
SECRET_PLACEHOLDERS = {"PULL_SECRET_JSON", "SSH_PUBLIC_KEY"}
PLACEHOLDER = re.compile(r"\$\{([A-Z0-9_]+)\}")
GCP_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def load_values(path: Path) -> dict[str, str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"trial_install_values_invalid:{error}")
    if not isinstance(value, dict) or set(value) != ALLOWED_VALUES:
        fail("trial_install_values_keys_invalid")
    project_id = value["TARGET_PROJECT_ID"]
    if not isinstance(project_id, str) or not GCP_PROJECT.fullmatch(project_id):
        fail("trial_install_project_invalid")
    return value


def render(template: str, values: dict[str, str]) -> str:
    placeholders = set(PLACEHOLDER.findall(template))
    if placeholders != ALLOWED_VALUES | SECRET_PLACEHOLDERS:
        fail("trial_install_template_placeholders_invalid")

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return values.get(key, match.group(0))

    rendered = PLACEHOLDER.sub(replace, template)
    if set(PLACEHOLDER.findall(rendered)) != SECRET_PLACEHOLDERS:
        fail("trial_install_rendered_placeholders_invalid")
    required_fragments = (
        "baseDomain: ocp-lab.prometa.ai",
        "name: orchestra-trial",
        "name: worker\n    replicas: 0",
        "name: master\n  replicas: 1",
        "diskSizeGB: 150",
        "diskType: pd-balanced",
        "type: n2-standard-8",
        "- europe-west1-b",
        "networkType: OVNKubernetes",
        "region: europe-west1",
        "fips: false",
        "publish: External",
    )
    if any(fragment not in rendered for fragment in required_fragments):
        fail("trial_install_rendered_topology_invalid")
    forbidden_fragments = (
        "n2-standard-4",
        "pd-ssd",
        "europe-west1-c",
        "europe-west1-d",
        "publish: Internal",
    )
    if any(fragment in rendered for fragment in forbidden_fragments):
        fail("trial_install_rendered_production_topology")
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", required=True, type=Path)
    parser.add_argument("--lease", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--at")
    args = parser.parse_args(argv)

    output = args.output.resolve()
    allowed_root = (ROOT / "install-dir" / "trial").resolve()
    if allowed_root not in output.parents:
        fail("trial_install_output_must_be_under_trial_install_dir")
    if output.exists():
        fail("trial_install_output_already_exists")

    values = load_values(args.values.resolve())
    profile = load_profile()
    lease = read_lease(args.lease.resolve())
    assessed_at = (
        parse_utc(args.at, "assessment")
        if args.at
        else datetime.now(timezone.utc)
    )
    validate_lease(
        lease,
        profile,
        assessed_at,
        expected_project_id=values["TARGET_PROJECT_ID"],
    )
    rendered = render(TEMPLATE.read_text(encoding="utf-8"), values)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
