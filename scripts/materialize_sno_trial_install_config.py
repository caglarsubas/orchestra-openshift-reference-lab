#!/usr/bin/env python3
"""Materialize the SNO install config without exposing secret values."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.sno_trial_install_admission import validate_admission
    from scripts.trial_lease import (
        ROOT,
        load_profile,
        parse_utc,
        read_lease,
        validate_lease,
    )
except ModuleNotFoundError:
    from sno_trial_install_admission import validate_admission
    from trial_lease import (
        ROOT,
        load_profile,
        parse_utc,
        read_lease,
        validate_lease,
    )


PULL_SECRET_PLACEHOLDER = "pullSecret: '${PULL_SECRET_JSON}'"
SSH_KEY_PLACEHOLDER = "sshKey: '${SSH_PUBLIC_KEY}'"
UNRESOLVED_PLACEHOLDER = re.compile(r"\$\{[A-Z0-9_]+\}")
SSH_PUBLIC_KEY = re.compile(
    r"^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) "
    r"[A-Za-z0-9+/]+={0,3}(?: [\x20-\x7e]{1,256})?$"
)
MAX_RENDERED_BYTES = 32 * 1024
MAX_PULL_SECRET_BYTES = 128 * 1024
MAX_SSH_PUBLIC_KEY_BYTES = 16 * 1024


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def private_regular_file(
    path: Path,
    *,
    allowed_root: Path,
    maximum_bytes: int,
    code: str,
) -> Path:
    try:
        lexical = path.expanduser().absolute()
        details = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except OSError:
        fail(code)
    root = allowed_root.resolve()
    if (
        lexical.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or details.st_mode & 0o077
        or details.st_size < 1
        or details.st_size > maximum_bytes
        or root not in resolved.parents
    ):
        fail(code)
    return resolved


def read_ascii_file(
    path: Path,
    *,
    allowed_root: Path,
    maximum_bytes: int,
    code: str,
) -> str:
    resolved = private_regular_file(
        path,
        allowed_root=allowed_root,
        maximum_bytes=maximum_bytes,
        code=code,
    )
    try:
        return resolved.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        fail(code)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("sno_materialize_pull_secret_duplicate_key")
        result[key] = value
    return result


def read_pull_secret(path: Path) -> str:
    raw = read_ascii_file(
        path,
        allowed_root=ROOT / "restricted",
        maximum_bytes=MAX_PULL_SECRET_BYTES,
        code="sno_materialize_pull_secret_file_invalid",
    )
    try:
        value = json.loads(raw, object_pairs_hook=strict_object)
    except json.JSONDecodeError:
        fail("sno_materialize_pull_secret_json_invalid")
    if not isinstance(value, dict):
        fail("sno_materialize_pull_secret_object_required")
    auths = value.get("auths")
    if (
        not isinstance(auths, dict)
        or not auths
        or any(
            not isinstance(registry, str)
            or not registry
            or not isinstance(credentials, dict)
            or not any(
                isinstance(credentials.get(field), str) and bool(credentials[field])
                for field in ("auth", "identitytoken")
            )
            for registry, credentials in auths.items()
        )
    ):
        fail("sno_materialize_pull_secret_auths_invalid")
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def read_ssh_public_key(path: Path) -> str:
    value = read_ascii_file(
        path,
        allowed_root=ROOT / "restricted",
        maximum_bytes=MAX_SSH_PUBLIC_KEY_BYTES,
        code="sno_materialize_ssh_public_key_file_invalid",
    ).strip()
    if "\n" in value or "\r" in value or not SSH_PUBLIC_KEY.fullmatch(value):
        fail("sno_materialize_ssh_public_key_invalid")
    return value


def materialize(
    rendered: str,
    pull_secret: str,
    ssh_public_key: str,
    project_id: str,
) -> str:
    if (
        rendered.count(PULL_SECRET_PLACEHOLDER) != 1
        or rendered.count(SSH_KEY_PLACEHOLDER) != 1
        or rendered.count(f"projectID: {project_id}") != 1
    ):
        fail("sno_materialize_rendered_contract_invalid")
    output = rendered.replace(
        PULL_SECRET_PLACEHOLDER,
        f"pullSecret: {json.dumps(pull_secret)}",
    ).replace(
        SSH_KEY_PLACEHOLDER,
        f"sshKey: {json.dumps(ssh_public_key)}",
    )
    if UNRESOLVED_PLACEHOLDER.search(output):
        fail("sno_materialize_unresolved_placeholder")
    return output


def read_admission(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("sno_materialize_admission_invalid")
    if not isinstance(value, dict):
        fail("sno_materialize_admission_invalid")
    return value


def output_path(path: Path) -> Path:
    lexical = path.expanduser().absolute()
    allowed_root = (ROOT / "install-dir" / "trial").resolve()
    if lexical.name != "install-config.yaml" or lexical.exists():
        fail("sno_materialize_output_invalid")
    try:
        lexical.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        details = lexical.parent.lstat()
        parent = lexical.parent.resolve(strict=True)
    except OSError:
        fail("sno_materialize_output_invalid")
    if (
        lexical.parent.is_symlink()
        or not stat.S_ISDIR(details.st_mode)
        or (parent != allowed_root and allowed_root not in parent.parents)
    ):
        fail("sno_materialize_output_invalid")
    try:
        lexical.parent.chmod(0o700)
    except OSError:
        fail("sno_materialize_output_invalid")
    return parent / lexical.name


def write_create_only(path: Path, value: str) -> None:
    created = False
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        fail("sno_materialize_output_write_failed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rendered", required=True, type=Path)
    parser.add_argument("--pull-secret", required=True, type=Path)
    parser.add_argument("--ssh-public-key", required=True, type=Path)
    parser.add_argument("--lease", required=True, type=Path)
    parser.add_argument("--admission", required=True, type=Path)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--at")
    args = parser.parse_args(argv)

    assessed_at = (
        parse_utc(args.at, "sno_materialize_assessment")
        if args.at
        else datetime.now(timezone.utc)
    )
    rendered = read_ascii_file(
        args.rendered,
        allowed_root=ROOT / "install-dir" / "trial",
        maximum_bytes=MAX_RENDERED_BYTES,
        code="sno_materialize_rendered_file_invalid",
    )
    profile = load_profile()
    lease = read_lease(args.lease.resolve())
    validate_lease(
        lease,
        profile,
        assessed_at,
        expected_project_id=args.project_id,
    )
    admission = read_admission(args.admission.resolve())
    validate_admission(
        admission,
        assessed_at,
        expected_project_id=args.project_id,
        lease=lease,
    )
    if (
        admission["decision"]["status"] != "READY_TO_RENDER"
        or admission["controls"]["installConfigRenderAuthorized"] is not True
        or admission["controls"]["clusterCreationAuthorized"] is not False
    ):
        fail("sno_materialize_admission_not_ready")

    value = materialize(
        rendered,
        read_pull_secret(args.pull_secret),
        read_ssh_public_key(args.ssh_public_key),
        args.project_id,
    )
    destination = output_path(args.output)
    write_create_only(destination, value)
    print(
        "sno_install_config_materialized "
        f"output={destination.relative_to(ROOT)} "
        "clusterCreationAuthorized=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
