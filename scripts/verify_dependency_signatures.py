#!/usr/bin/env python3
"""Reproduce the bounded dependency signature observation against live registries."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_dependency_supply_chain import (
        ADMISSION,
        ISSUER,
        SOURCE_VERIFICATION,
        SIGNED_SUBJECTS,
        TOPOLOGY,
        UNSIGNED_SUBJECTS,
        parse_utc,
        validate_source_verification,
    )
    from scripts.validate_repository import canonical_digest, load_json
except ModuleNotFoundError:
    from validate_dependency_supply_chain import (
        ADMISSION,
        ISSUER,
        SOURCE_VERIFICATION,
        SIGNED_SUBJECTS,
        TOPOLOGY,
        UNSIGNED_SUBJECTS,
        parse_utc,
        validate_source_verification,
    )
    from validate_repository import canonical_digest, load_json


VERSION = re.compile(r"(?m)^GitVersion:\s+(v\S+)$")
COMMIT = re.compile(r"(?m)^GitCommit:\s+([a-f0-9]{40})$")


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def bundle_metadata(value: dict[str, Any]) -> tuple[str, str, str]:
    if "verificationMaterial" in value:
        material = value.get("verificationMaterial")
        if not isinstance(material, dict):
            fail("dependency_signature_bundle_material_invalid")
        entries = material.get("tlogEntries")
        if not isinstance(entries, list) or len(entries) != 1:
            fail("dependency_signature_tlog_entry_invalid")
        entry = entries[0]
        if not isinstance(entry, dict):
            fail("dependency_signature_tlog_entry_invalid")
        bundle_format = "sigstore-bundle-v3"
        log_index = entry.get("logIndex")
        integrated_time = entry.get("integratedTime")
    elif "Bundle" in value:
        bundle = value.get("Bundle")
        if not isinstance(bundle, dict) or not isinstance(bundle.get("Payload"), dict):
            fail("dependency_signature_legacy_bundle_invalid")
        payload = bundle["Payload"]
        bundle_format = "legacy-cosign-bundle"
        log_index = payload.get("logIndex")
        integrated_time = payload.get("integratedTime")
    else:
        fail("dependency_signature_bundle_format_unknown")
    if not isinstance(log_index, (str, int)) or not isinstance(
        integrated_time, (str, int)
    ):
        fail("dependency_signature_tlog_metadata_invalid")
    try:
        integrated_at = (
            datetime.fromtimestamp(int(integrated_time), timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (OverflowError, TypeError, ValueError):
        fail("dependency_signature_tlog_metadata_invalid")
    return bundle_format, str(log_index), integrated_at


def no_signature_observed(stderr: str, subject: str) -> bool:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    return lines == [
        f"Error: {subject}: no signatures associated",
        f"error during command execution: {subject}: no signatures associated",
    ]


def verify_arguments(subject: dict[str, Any]) -> list[str]:
    return [
        "verify",
        "--certificate-identity",
        subject["certificateIdentity"],
        "--certificate-oidc-issuer",
        ISSUER,
        "--output",
        "json",
        subject["subject"],
    ]


def run_cosign(binary: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [binary, *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def verify_tool(binary: str, observer: dict[str, Any]) -> None:
    result = run_cosign(binary, ["version"])
    version = VERSION.search(result.stdout)
    commit = COMMIT.search(result.stdout)
    if (
        result.returncode != 0
        or version is None
        or commit is None
        or version.group(1) != observer["toolVersion"]
        or commit.group(1) != observer["toolCommit"]
    ):
        fail("dependency_signature_cosign_version_mismatch")


def verify_trust_root(path: Path, observer: dict[str, Any]) -> None:
    try:
        digest = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    except OSError:
        fail("dependency_signature_trust_root_missing")
    if digest != observer["trustRootDigest"]:
        fail(f"dependency_signature_trust_root_drift:{digest}")


def validate_observation_fresh(report: dict[str, Any], now: datetime) -> None:
    observed_at = parse_utc(
        report["observationWindow"]["observedAt"],
        "dependency_signature_observation_window_invalid",
    )
    valid_until = parse_utc(
        report["observationWindow"]["validUntil"],
        "dependency_signature_observation_window_invalid",
    )
    if now.tzinfo is None or now < observed_at or now > valid_until:
        fail("dependency_signature_observation_stale:new_lock_required")


def verify_signed(binary: str, subject: dict[str, Any]) -> None:
    verification = run_cosign(binary, verify_arguments(subject))
    if verification.returncode != 0:
        fail(f"dependency_signature_verification_failed:{subject['id']}")
    bundle_result = run_cosign(binary, ["download", "signature", subject["subject"]])
    if bundle_result.returncode != 0:
        fail(f"dependency_signature_bundle_download_failed:{subject['id']}")
    try:
        bundle = json.loads(bundle_result.stdout)
    except json.JSONDecodeError:
        fail(f"dependency_signature_bundle_json_invalid:{subject['id']}")
    if not isinstance(bundle, dict):
        fail(f"dependency_signature_bundle_json_invalid:{subject['id']}")
    if canonical_digest(bundle) != subject["bundleDigest"]:
        fail(f"dependency_signature_bundle_digest_drift:{subject['id']}")
    bundle_format, log_index, integrated_at = bundle_metadata(bundle)
    if (
        bundle_format != subject["bundleFormat"]
        or log_index != subject["transparencyLog"]["logIndex"]
        or integrated_at != subject["transparencyLog"]["integratedAt"]
    ):
        fail(f"dependency_signature_bundle_metadata_drift:{subject['id']}")


def verify_unsigned(binary: str, subject: dict[str, Any]) -> None:
    result = run_cosign(binary, ["download", "signature", subject["subject"]])
    if result.returncode == 0:
        fail(f"dependency_signature_now_available:new_lock_required:{subject['id']}")
    if not no_signature_observed(result.stderr, subject["subject"]):
        fail(f"dependency_signature_probe_indeterminate:{subject['id']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument(
        "--trusted-root",
        type=Path,
        default=Path.home()
        / ".sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json",
    )
    parser.add_argument("--image", action="append", default=[])
    args = parser.parse_args(argv)

    report = load_json(SOURCE_VERIFICATION)
    admission = load_json(ADMISSION)
    topology = load_json(TOPOLOGY)
    validate_source_verification(report, admission, topology)
    validate_observation_fresh(report, datetime.now(timezone.utc))

    selected = set(args.image)
    known = set(SIGNED_SUBJECTS) | UNSIGNED_SUBJECTS
    if selected - known:
        fail(f"dependency_signature_image_unknown:{sorted(selected - known)[0]}")
    verify_tool(args.cosign, report["observer"])
    verify_trust_root(args.trusted_root, report["observer"])

    signed = 0
    for subject in report["verifiedSubjects"]:
        if selected and subject["id"] not in selected:
            continue
        verify_signed(args.cosign, subject)
        signed += 1
        print(f"dependency_signature_verified id={subject['id']}")
    unsigned = 0
    for subject in report["exceptionRequiredSubjects"]:
        if selected and subject["id"] not in selected:
            continue
        verify_unsigned(args.cosign, subject)
        unsigned += 1
        print(f"dependency_signature_absent id={subject['id']} exception=required")
    print(
        "dependency_signature_observation_reproduced "
        f"verified={signed} exceptionsRequired={unsigned} "
        "sourceAdmission=false mirrorAuthorization=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ValueError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(error)
        raise SystemExit(1)
