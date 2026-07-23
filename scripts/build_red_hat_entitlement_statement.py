#!/usr/bin/env python3
"""Build a payload-free external Red Hat entitlement observation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
KIND = "orchestra.external.red-hat-entitlement-observation.v1"
MAXIMUM_TRIAL_WINDOW = timedelta(days=61)


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def parse_utc(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"entitlement_time_invalid:{field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"entitlement_time_invalid:{field}")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(f"entitlement_time_invalid:{field}")
    return parsed


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def read_private_identity(path: Path) -> bytes:
    resolved = path.resolve()
    allowed_root = (ROOT / "restricted").resolve()
    if allowed_root not in resolved.parents:
        fail("entitlement_account_identity_must_be_restricted")
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            fail("entitlement_account_identity_not_regular")
        mode = metadata.st_mode & 0o777
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            value = stream.read(4097).strip()
    except OSError as error:
        fail(f"entitlement_account_identity_invalid:{error}")
    if mode & 0o077:
        fail("entitlement_account_identity_permissions_invalid")
    if not value or len(value) > 4096:
        fail("entitlement_account_identity_size_invalid")
    return value


def build_statement(
    account_identity: bytes,
    issuer_evidence: bytes,
    observed_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    if not account_identity or len(account_identity) > 4096:
        fail("entitlement_account_identity_size_invalid")
    if not issuer_evidence or len(issuer_evidence) > 20 * 1024 * 1024:
        fail("entitlement_issuer_evidence_size_invalid")
    if (
        observed_at.tzinfo is None
        or observed_at.utcoffset() != timedelta(0)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() != timedelta(0)
    ):
        fail("entitlement_time_not_utc")
    if (
        expires_at <= observed_at
        or expires_at - observed_at > MAXIMUM_TRIAL_WINDOW
    ):
        fail("entitlement_window_invalid")
    return {
        "schemaVersion": 1,
        "kind": KIND,
        "status": "active",
        "product": "OpenShift Container Platform",
        "openshiftVersion": "4.20.27",
        "architecture": "linux/amd64",
        "accountIdentityDigest": digest_bytes(account_identity),
        "issuerEvidenceDigest": digest_bytes(issuer_evidence),
        "observedAt": observed_at.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "expiresAt": expires_at.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    output = path.resolve()
    allowed_root = (ROOT / "restricted").resolve()
    if allowed_root not in output.parents:
        fail("entitlement_output_must_be_restricted")
    if output.exists():
        fail("entitlement_output_already_exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-identity-file", required=True, type=Path)
    parser.add_argument("--issuer-evidence", required=True, type=Path)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        issuer_evidence = args.issuer_evidence.resolve().read_bytes()
    except OSError as error:
        fail(f"entitlement_issuer_evidence_invalid:{error}")
    statement = build_statement(
        read_private_identity(args.account_identity_file),
        issuer_evidence,
        parse_utc(args.observed_at, "observedAt"),
        parse_utc(args.expires_at, "expiresAt"),
    )
    write_private_json(args.output, statement)
    encoded = (
        json.dumps(statement, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")
    print(f"entitlement_statement_created digest={digest_bytes(encoded)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
