#!/usr/bin/env python3
"""Render the secret-free OpenShift install template into an ignored path."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "infra" / "openshift" / "install-config.template.yaml"
ALLOWED_VALUES = {
    "OCP_MACHINE_CIDR",
    "OCP_COMPUTE_SUBNET",
    "OCP_CONTROL_PLANE_SUBNET",
    "OCP_NETWORK_NAME",
    "TARGET_PROJECT_ID",
}
SECRET_PLACEHOLDERS = {"PULL_SECRET_JSON", "SSH_PUBLIC_KEY"}
PLACEHOLDER = re.compile(r"\$\{([A-Z0-9_]+)\}")
GCP_NAME = re.compile(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def load_values(path: Path) -> dict[str, str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"install_values_invalid:{error}")
    if not isinstance(value, dict) or set(value) != ALLOWED_VALUES:
        fail("install_values_keys_invalid")
    if not all(isinstance(item, str) and item for item in value.values()):
        fail("install_values_must_be_non_empty_strings")
    try:
        network = ipaddress.ip_network(value["OCP_MACHINE_CIDR"], strict=True)
    except ValueError as error:
        fail(f"install_machine_cidr_invalid:{error}")
    if not network.is_private or network.version != 4 or network.prefixlen > 24:
        fail("install_machine_cidr_not_private_ipv4")
    for key in ALLOWED_VALUES - {"OCP_MACHINE_CIDR"}:
        if not GCP_NAME.fullmatch(value[key]):
            fail(f"install_gcp_name_invalid:{key}")
    return value


def render(template: str, values: dict[str, str]) -> str:
    placeholders = set(PLACEHOLDER.findall(template))
    if placeholders != ALLOWED_VALUES | SECRET_PLACEHOLDERS:
        fail("install_template_placeholders_invalid")

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return values.get(key, match.group(0))

    rendered = PLACEHOLDER.sub(replace, template)
    remaining = set(PLACEHOLDER.findall(rendered))
    if remaining != SECRET_PLACEHOLDERS:
        fail("install_rendered_placeholders_invalid")
    required_fragments = (
        "baseDomain: ocp-lab.prometa.ai",
        "replicas: 3",
        "diskSizeGB: 256",
        "diskType: pd-ssd",
        "type: n2-standard-8",
        "type: n2-standard-4",
        "- europe-west1-b",
        "- europe-west1-c",
        "- europe-west1-d",
        "networkType: OVNKubernetes",
        "region: europe-west1",
        "fips: false",
        "publish: Internal",
    )
    if any(fragment not in rendered for fragment in required_fragments):
        fail("install_rendered_topology_invalid")
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    output = args.output.resolve()
    allowed_root = (ROOT / "install-dir").resolve()
    if allowed_root not in output.parents:
        fail("install_output_must_be_under_ignored_install_dir")
    if output.exists():
        fail("install_output_already_exists")

    values = load_values(args.values.resolve())
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
