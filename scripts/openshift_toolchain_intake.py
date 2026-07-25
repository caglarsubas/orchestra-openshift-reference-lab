#!/usr/bin/env python3
"""Verify exact public OpenShift trial archives without granting readiness."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_sno_trial_profile import canonical_digest
except ModuleNotFoundError:
    from validate_sno_trial_profile import canonical_digest


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config" / "sno-trial-openshift-toolchain.lock.json"
REPORT_KIND = "orchestra.openshift.sno-trial-toolchain-intake.v1"
LOCK_KIND = "orchestra.openshift.sno-trial-toolchain-lock.v1"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
VERSION = "4.20.27"
ARCHITECTURE = "linux/amd64"
BASE_URL = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.20.27"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
CHECKSUM_LINE = re.compile(r"^([a-f0-9]{64})  ([A-Za-z0-9._+-]+)$")
INTAKE_ID = re.compile(r"^sno-toolchain-[a-z0-9][a-z0-9.-]{5,79}$")
EXECUTION_MODES = {"simulated", "live-local"}
LOCK_KEYS = {
    "schemaVersion",
    "kind",
    "profileId",
    "version",
    "architecture",
    "mirrorBaseUrl",
    "checksumDocument",
    "signatureDocument",
    "signingKey",
    "artifacts",
    "controls",
}
CHECKSUM_KEYS = {"fileName", "sizeBytes", "digest", "sourceUrl"}
SIGNATURE_KEYS = {"fileName", "sizeBytes", "digest", "sourceUrl", "format"}
SIGNING_KEY_KEYS = {
    "fileName",
    "sizeBytes",
    "digest",
    "sourceUrl",
    "fingerprint",
    "identity",
}
ARTIFACT_KEYS = {
    "role",
    "fileName",
    "sizeBytes",
    "digest",
    "sourceUrl",
    "members",
}
MEMBER_KEYS = {"name", "type", "sizeBytes", "mode", "linkName"}
EXPECTED_CHECKSUM = {
    "fileName": "sha256sum.txt",
    "sizeBytes": 6068,
    "digest": (
        "sha256:7b6eb2ee150d8a48583a0baf2b25b21dbf382a97c38e122179c7d216d1584902"
    ),
    "sourceUrl": f"{BASE_URL}/sha256sum.txt",
}
EXPECTED_SIGNATURE = {
    "fileName": "sha256sum.txt.gpg",
    "sizeBytes": 2281,
    "digest": (
        "sha256:919bdd806f41b48dc9a92ac19dd83896bcd51507860e0d751c0c636255f49624"
    ),
    "sourceUrl": f"{BASE_URL}/sha256sum.txt.gpg",
    "format": "openpgp-signed-message",
}
EXPECTED_SIGNING_KEY = {
    "fileName": "red-hat-release-key-2.asc",
    "sizeBytes": 1855,
    "digest": (
        "sha256:d4b2543626bee31d9438d4a31731aae712c072893c7aed8854f16c42fafc742b"
    ),
    "sourceUrl": "https://www.redhat.com/security/data/fd431d51.txt",
    "fingerprint": "567E347AD0044ADE55BA8A5F199E2F91FD431D51",
    "identity": "Red Hat, Inc. (release key 2) <security@redhat.com>",
}
EXPECTED_ARTIFACTS = [
    {
        "role": "installer",
        "fileName": "openshift-install-linux-4.20.27.tar.gz",
        "sizeBytes": 414760801,
        "digest": (
            "sha256:99b859b5453668d422356abf051ec2ae2501a13d0155a518af9f49989914a596"
        ),
        "sourceUrl": f"{BASE_URL}/openshift-install-linux-4.20.27.tar.gz",
        "members": [
            {
                "name": "README.md",
                "type": "regular",
                "sizeBytes": 706,
                "mode": 0o644,
                "linkName": None,
            },
            {
                "name": "openshift-install",
                "type": "regular",
                "sizeBytes": 631505080,
                "mode": 0o755,
                "linkName": None,
            },
        ],
    },
    {
        "role": "client",
        "fileName": "openshift-client-linux-4.20.27.tar.gz",
        "sizeBytes": 43386638,
        "digest": (
            "sha256:cac1364153e7afc2ebd2eef9b7d0ce6b06d1721b035feba9d846433a7ed4db81"
        ),
        "sourceUrl": f"{BASE_URL}/openshift-client-linux-4.20.27.tar.gz",
        "members": [
            {
                "name": "README.md",
                "type": "regular",
                "sizeBytes": 950,
                "mode": 0o644,
                "linkName": None,
            },
            {
                "name": "oc",
                "type": "regular",
                "sizeBytes": 138128200,
                "mode": 0o755,
                "linkName": None,
            },
            {
                "name": "kubectl",
                "type": "hardlink",
                "sizeBytes": 0,
                "mode": 0o755,
                "linkName": "oc",
            },
        ],
    },
]
EXPECTED_CONTROLS = {
    "scope": "engineering-trial-archive-intake",
    "integrityModel": "official-red-hat-openpgp-plus-sha256",
    "versionedArchiveNamesRequired": True,
    "archiveMembersPinned": True,
    "checksumSignatureRequired": True,
    "binaryExecutionRequiredDownstream": True,
    "pullSecretRequiredDownstream": True,
    "entitlementRequiredDownstream": True,
    "cloudMutationAuthorized": False,
    "campaignEligible": False,
}
REPORT_CONTROLS = {
    "archiveIntegrityVerified": True,
    "checksumSignatureVerified": True,
    "binaryExecutionVerified": False,
    "pullSecretObserved": False,
    "entitlementObserved": False,
    "cloudMutationAuthorized": False,
    "campaignEligible": False,
    "allowedCertificationSlots": [],
}
CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
CLAIMS = {
    "campaignEvidence": False,
    "referenceProfileVerified": False,
    "customerCertified": False,
    "redHatCertified": False,
    "contractualSla": False,
    "productionSupported": False,
}


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        fail(code)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("sno_toolchain_json_invalid")
    if not isinstance(value, dict):
        fail("sno_toolchain_json_object_required")
    return value


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_utc(value: Any) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail("sno_toolchain_report_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail("sno_toolchain_report_time_invalid")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        fail("sno_toolchain_report_time_invalid")


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        fail("sno_toolchain_file_unreadable")
    return f"sha256:{digest.hexdigest()}"


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def checked_file(
    directory: Path,
    expected: dict[str, Any],
    size_code: str,
    digest_code: str,
) -> Path:
    path = (directory / expected["fileName"]).resolve()
    if path.parent != directory.resolve() or not path.is_file():
        fail("sno_toolchain_supporting_file_missing")
    if path.stat().st_size != expected["sizeBytes"]:
        fail(size_code)
    if file_digest(path) != expected["digest"]:
        fail(digest_code)
    return path


def validate_lock(value: dict[str, Any]) -> None:
    exact_keys(value, LOCK_KEYS, "sno_toolchain_lock_keys_invalid")
    if (
        value["schemaVersion"] != 1
        or value["kind"] != LOCK_KIND
        or value["profileId"] != PROFILE_ID
        or value["version"] != VERSION
        or value["architecture"] != ARCHITECTURE
        or value["mirrorBaseUrl"] != BASE_URL
    ):
        fail("sno_toolchain_lock_identity_invalid")
    checksum = value["checksumDocument"]
    if not isinstance(checksum, dict):
        fail("sno_toolchain_lock_checksum_invalid")
    exact_keys(checksum, CHECKSUM_KEYS, "sno_toolchain_lock_checksum_keys_invalid")
    if checksum != EXPECTED_CHECKSUM:
        fail("sno_toolchain_lock_checksum_invalid")
    signature = value["signatureDocument"]
    if not isinstance(signature, dict):
        fail("sno_toolchain_lock_signature_invalid")
    exact_keys(
        signature,
        SIGNATURE_KEYS,
        "sno_toolchain_lock_signature_keys_invalid",
    )
    if signature != EXPECTED_SIGNATURE:
        fail("sno_toolchain_lock_signature_invalid")
    signing_key = value["signingKey"]
    if not isinstance(signing_key, dict):
        fail("sno_toolchain_lock_signing_key_invalid")
    exact_keys(
        signing_key,
        SIGNING_KEY_KEYS,
        "sno_toolchain_lock_signing_key_keys_invalid",
    )
    if signing_key != EXPECTED_SIGNING_KEY:
        fail("sno_toolchain_lock_signing_key_invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        fail("sno_toolchain_lock_artifacts_invalid")
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            fail("sno_toolchain_lock_artifacts_invalid")
        exact_keys(artifact, ARTIFACT_KEYS, "sno_toolchain_lock_artifact_keys_invalid")
        members = artifact["members"]
        if not isinstance(members, list):
            fail("sno_toolchain_lock_members_invalid")
        for member in members:
            if not isinstance(member, dict):
                fail("sno_toolchain_lock_members_invalid")
            exact_keys(member, MEMBER_KEYS, "sno_toolchain_lock_member_keys_invalid")
    if artifacts != EXPECTED_ARTIFACTS:
        fail("sno_toolchain_lock_artifacts_invalid")
    if value["controls"] != EXPECTED_CONTROLS:
        fail("sno_toolchain_lock_controls_invalid")


def checksum_entries(path: Path, expected: dict[str, Any]) -> dict[str, str]:
    try:
        if path.stat().st_size != expected["sizeBytes"]:
            fail("sno_toolchain_checksum_size_mismatch")
        if file_digest(path) != expected["digest"]:
            fail("sno_toolchain_checksum_digest_mismatch")
        raw = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        fail("sno_toolchain_checksum_unreadable")
    entries: dict[str, str] = {}
    for line in raw.splitlines():
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            fail("sno_toolchain_checksum_format_invalid")
        digest, name = match.groups()
        if name in entries:
            fail("sno_toolchain_checksum_duplicate")
        entries[name] = f"sha256:{digest}"
    return entries


def verify_signed_checksum(
    directory: Path,
    checksum_path: Path,
    signature: dict[str, Any],
    signing_key: dict[str, Any],
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    signature_path = checked_file(
        directory,
        signature,
        "sno_toolchain_signature_size_mismatch",
        "sno_toolchain_signature_digest_mismatch",
    )
    key_path = checked_file(
        directory,
        signing_key,
        "sno_toolchain_signing_key_size_mismatch",
        "sno_toolchain_signing_key_digest_mismatch",
    )
    try:
        with tempfile.TemporaryDirectory(prefix="orchestra-rh-gpg.") as home:
            home_path = Path(home)
            home_path.chmod(0o700)
            imported = run(
                [
                    "gpg",
                    "--batch",
                    "--no-tty",
                    "--homedir",
                    home,
                    "--status-fd=1",
                    "--import",
                    str(key_path),
                ]
            )
            if (
                "[GNUPG:] IMPORT_OK" not in imported.stdout
                or signing_key["fingerprint"] not in imported.stdout
            ):
                fail("sno_toolchain_signing_key_import_invalid")
            signed_payload = home_path / "signed-sha256sum.txt"
            verified = run(
                [
                    "gpg",
                    "--batch",
                    "--no-tty",
                    "--homedir",
                    home,
                    "--status-fd=1",
                    "--output",
                    str(signed_payload),
                    "--decrypt",
                    str(signature_path),
                ]
            )
            valid_signature = f"[GNUPG:] VALIDSIG {signing_key['fingerprint']} "
            if valid_signature not in verified.stdout:
                fail("sno_toolchain_signature_invalid")
            if signed_payload.read_bytes() != checksum_path.read_bytes():
                fail("sno_toolchain_signed_payload_mismatch")
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        fail("sno_toolchain_signature_verification_failed")
    return {
        "fileName": signature["fileName"],
        "sourceUrl": signature["sourceUrl"],
        "sizeBytes": signature["sizeBytes"],
        "digest": signature["digest"],
        "format": signature["format"],
        "signedPayloadDigest": file_digest(checksum_path),
        "validSignature": True,
    }


def member_type(member: tarfile.TarInfo) -> str:
    if member.isreg():
        return "regular"
    if member.islnk():
        return "hardlink"
    fail("sno_toolchain_archive_member_type_invalid")


def archive_members(path: Path) -> list[dict[str, Any]]:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError):
        fail("sno_toolchain_archive_invalid")
    facts: list[dict[str, Any]] = []
    for member in members:
        if (
            not member.name
            or member.name.startswith("/")
            or member.name.startswith("../")
            or "/../" in member.name
            or member.name.endswith("/")
        ):
            fail("sno_toolchain_archive_member_name_invalid")
        facts.append(
            {
                "name": member.name,
                "type": member_type(member),
                "sizeBytes": member.size,
                "mode": member.mode,
                "linkName": member.linkname or None,
            }
        )
    return facts


def inspect_artifact(
    directory: Path,
    artifact: dict[str, Any],
    published_checksums: dict[str, str],
) -> dict[str, Any]:
    path = (directory / artifact["fileName"]).resolve()
    if path.parent != directory.resolve() or not path.is_file():
        fail("sno_toolchain_archive_missing")
    if path.stat().st_size != artifact["sizeBytes"]:
        fail("sno_toolchain_archive_size_mismatch")
    published = published_checksums.get(artifact["fileName"])
    if published != artifact["digest"]:
        fail("sno_toolchain_published_digest_mismatch")
    actual = file_digest(path)
    if actual != artifact["digest"]:
        fail("sno_toolchain_archive_digest_mismatch")
    members = archive_members(path)
    if members != artifact["members"]:
        fail("sno_toolchain_archive_members_mismatch")
    return {
        "role": artifact["role"],
        "fileName": artifact["fileName"],
        "sourceUrl": artifact["sourceUrl"],
        "sizeBytes": artifact["sizeBytes"],
        "publishedDigest": published,
        "actualDigest": actual,
        "checksumMatch": True,
        "members": members,
    }


def report_digest(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("reportDigest", None)
    return canonical_digest(unsigned)


def build_report(
    directory: Path,
    intake_id: str,
    execution_mode: str,
    generated_at: datetime,
    lock: dict[str, Any],
    run: CommandRunner = default_runner,
) -> dict[str, Any]:
    validate_lock(lock)
    if not INTAKE_ID.fullmatch(intake_id):
        fail("sno_toolchain_intake_id_invalid")
    if execution_mode not in EXECUTION_MODES:
        fail("sno_toolchain_execution_mode_invalid")
    if execution_mode == "simulated" and directory.resolve().is_relative_to(
        (ROOT / "restricted").resolve()
    ):
        fail("sno_toolchain_restricted_input_cannot_be_simulated")
    checksum_path = directory / lock["checksumDocument"]["fileName"]
    published = checksum_entries(checksum_path, lock["checksumDocument"])
    signature = verify_signed_checksum(
        directory,
        checksum_path,
        lock["signatureDocument"],
        lock["signingKey"],
        run,
    )
    artifacts = [
        inspect_artifact(directory, artifact, published)
        for artifact in lock["artifacts"]
    ]
    report = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "intakeId": intake_id,
        "generatedAt": utc_text(generated_at),
        "targetClass": "engineering-trial",
        "executionMode": execution_mode,
        "bindings": {
            "profileId": PROFILE_ID,
            "toolchainLockDigest": canonical_digest(lock),
            "version": VERSION,
            "architecture": ARCHITECTURE,
        },
        "checksumDocument": {
            "fileName": lock["checksumDocument"]["fileName"],
            "sourceUrl": lock["checksumDocument"]["sourceUrl"],
            "sizeBytes": lock["checksumDocument"]["sizeBytes"],
            "digest": lock["checksumDocument"]["digest"],
            "signatureVerified": True,
        },
        "signatureDocument": signature,
        "signingKey": {
            **lock["signingKey"],
            "fingerprintVerified": True,
        },
        "artifacts": artifacts,
        "controls": dict(REPORT_CONTROLS),
        "claims": dict(CLAIMS),
    }
    report["reportDigest"] = report_digest(report)
    validate_report(report, lock)
    return report


def validate_report(value: dict[str, Any], lock: dict[str, Any]) -> None:
    validate_lock(lock)
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "intakeId",
            "generatedAt",
            "targetClass",
            "executionMode",
            "bindings",
            "checksumDocument",
            "signatureDocument",
            "signingKey",
            "artifacts",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_toolchain_report_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not isinstance(value["intakeId"], str)
        or not INTAKE_ID.fullmatch(value["intakeId"])
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] not in EXECUTION_MODES
    ):
        fail("sno_toolchain_report_identity_invalid")
    validate_utc(value["generatedAt"])
    if value["bindings"] != {
        "profileId": PROFILE_ID,
        "toolchainLockDigest": canonical_digest(lock),
        "version": VERSION,
        "architecture": ARCHITECTURE,
    }:
        fail("sno_toolchain_report_bindings_invalid")
    expected_checksum = {
        **lock["checksumDocument"],
        "signatureVerified": True,
    }
    if value["checksumDocument"] != expected_checksum:
        fail("sno_toolchain_report_checksum_invalid")
    if value["signatureDocument"] != {
        **lock["signatureDocument"],
        "signedPayloadDigest": lock["checksumDocument"]["digest"],
        "validSignature": True,
    }:
        fail("sno_toolchain_report_signature_invalid")
    if value["signingKey"] != {
        **lock["signingKey"],
        "fingerprintVerified": True,
    }:
        fail("sno_toolchain_report_signing_key_invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        fail("sno_toolchain_report_artifacts_invalid")
    for actual, expected in zip(artifacts, lock["artifacts"], strict=True):
        if actual != {
            "role": expected["role"],
            "fileName": expected["fileName"],
            "sourceUrl": expected["sourceUrl"],
            "sizeBytes": expected["sizeBytes"],
            "publishedDigest": expected["digest"],
            "actualDigest": expected["digest"],
            "checksumMatch": True,
            "members": expected["members"],
        }:
            fail("sno_toolchain_report_artifacts_invalid")
    if value["controls"] != REPORT_CONTROLS:
        fail("sno_toolchain_report_controls_invalid")
    if value["claims"] != CLAIMS:
        fail("sno_toolchain_report_claims_invalid")
    if not isinstance(value["reportDigest"], str) or not DIGEST.fullmatch(
        value["reportDigest"]
    ):
        fail("sno_toolchain_report_digest_invalid")
    if value["reportDigest"] != report_digest(value):
        fail("sno_toolchain_report_digest_mismatch")


def write_create_only(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError:
        fail("sno_toolchain_output_exists")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate-lock")

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--directory", type=Path, required=True)
    inspect.add_argument("--intake-id", required=True)
    inspect.add_argument(
        "--execution-mode",
        choices=sorted(EXECUTION_MODES),
        default="live-local",
    )
    inspect.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)

    args = parser.parse_args(argv)
    lock = load_json(LOCK_PATH)
    if args.command == "validate-lock":
        validate_lock(lock)
        print(f"validated {LOCK_PATH.relative_to(ROOT)}")
        return 0
    if args.command == "inspect":
        report = build_report(
            args.directory.resolve(),
            args.intake_id,
            args.execution_mode,
            datetime.now(timezone.utc),
            lock,
        )
        write_create_only(args.output.resolve(), report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    report = load_json(args.report.resolve())
    validate_report(report, lock)
    print(f"verified {args.report}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
