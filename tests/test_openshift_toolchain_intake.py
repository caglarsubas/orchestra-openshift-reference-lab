from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.openshift_toolchain_intake import (
    CLAIMS,
    EXPECTED_ARTIFACTS,
    EXPECTED_CHECKSUM,
    EXPECTED_SIGNATURE,
    EXPECTED_SIGNING_KEY,
    LOCK_PATH,
    REPORT_CONTROLS,
    REPORT_KIND,
    archive_members,
    checksum_entries,
    file_digest,
    inspect_artifact,
    load_json,
    main,
    report_digest,
    validate_lock,
    validate_report,
    verify_signed_checksum,
    write_create_only,
)
from scripts.validate_sno_trial_profile import canonical_digest


ROOT = Path(__file__).resolve().parents[1]


def sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def write_tar(path: Path, members: list[dict[str, object]]) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for member in members:
            info = tarfile.TarInfo(str(member["name"]))
            info.mode = int(member["mode"])
            info.mtime = 0
            if member["type"] == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = str(member["linkName"])
                info.size = 0
                archive.addfile(info)
                continue
            payload = bytes(member["payload"])
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def synthetic_archive(directory: Path) -> tuple[dict[str, object], Path]:
    path = directory / "synthetic-linux-4.20.27.tar.gz"
    members: list[dict[str, object]] = [
        {
            "name": "README.md",
            "type": "regular",
            "mode": 0o644,
            "linkName": None,
            "payload": b"fixture readme",
        },
        {
            "name": "oc",
            "type": "regular",
            "mode": 0o755,
            "linkName": None,
            "payload": b"fixture executable",
        },
        {
            "name": "kubectl",
            "type": "hardlink",
            "mode": 0o755,
            "linkName": "oc",
            "payload": b"",
        },
    ]
    write_tar(path, members)
    facts = archive_members(path)
    artifact: dict[str, object] = {
        "role": "client",
        "fileName": path.name,
        "sizeBytes": path.stat().st_size,
        "digest": file_digest(path),
        "sourceUrl": "https://mirror.invalid/synthetic-linux-4.20.27.tar.gz",
        "members": facts,
    }
    return artifact, path


def valid_report(lock: dict[str, object]) -> dict[str, object]:
    artifacts = []
    for expected in lock["artifacts"]:
        artifacts.append(
            {
                "role": expected["role"],
                "fileName": expected["fileName"],
                "sourceUrl": expected["sourceUrl"],
                "sizeBytes": expected["sizeBytes"],
                "publishedDigest": expected["digest"],
                "actualDigest": expected["digest"],
                "checksumMatch": True,
                "members": expected["members"],
            }
        )
    report: dict[str, object] = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "intakeId": "sno-toolchain-fixture-valid.1",
        "generatedAt": "2026-07-25T07:00:00Z",
        "targetClass": "engineering-trial",
        "executionMode": "simulated",
        "bindings": {
            "profileId": "orchestra-ocp-sno-trial-amd64-v1",
            "toolchainLockDigest": canonical_digest(lock),
            "version": "4.20.27",
            "architecture": "linux/amd64",
        },
        "checksumDocument": {
            **lock["checksumDocument"],
            "signatureVerified": True,
        },
        "signatureDocument": {
            **lock["signatureDocument"],
            "signedPayloadDigest": lock["checksumDocument"]["digest"],
            "validSignature": True,
        },
        "signingKey": {
            **lock["signingKey"],
            "fingerprintVerified": True,
        },
        "artifacts": artifacts,
        "controls": dict(REPORT_CONTROLS),
        "claims": dict(CLAIMS),
    }
    report["reportDigest"] = report_digest(report)
    return report


class OpenShiftToolchainIntakeTests(unittest.TestCase):
    def test_locked_public_toolchain_is_exact_and_non_authorizing(self) -> None:
        lock = load_json(LOCK_PATH)
        validate_lock(lock)
        self.assertEqual(lock["checksumDocument"], EXPECTED_CHECKSUM)
        self.assertEqual(lock["signatureDocument"], EXPECTED_SIGNATURE)
        self.assertEqual(lock["signingKey"], EXPECTED_SIGNING_KEY)
        self.assertEqual(lock["artifacts"], EXPECTED_ARTIFACTS)
        self.assertTrue(
            all("-4.20.27.tar.gz" in item["fileName"] for item in lock["artifacts"])
        )
        self.assertFalse(lock["controls"]["cloudMutationAuthorized"])
        self.assertFalse(lock["controls"]["campaignEligible"])
        self.assertTrue(lock["controls"]["checksumSignatureRequired"])

    def test_lock_rejects_alias_version_architecture_and_digest_drift(self) -> None:
        lock = load_json(LOCK_PATH)
        changed = copy.deepcopy(lock)
        changed["version"] = "4.20.28"
        with self.assertRaisesRegex(ValueError, "lock_identity_invalid"):
            validate_lock(changed)
        changed = copy.deepcopy(lock)
        changed["artifacts"][0]["fileName"] = "openshift-install-linux.tar.gz"
        with self.assertRaisesRegex(ValueError, "lock_artifacts_invalid"):
            validate_lock(changed)
        changed = copy.deepcopy(lock)
        changed["artifacts"][1]["digest"] = f"sha256:{'0' * 64}"
        with self.assertRaisesRegex(ValueError, "lock_artifacts_invalid"):
            validate_lock(changed)

    def test_checksum_document_must_match_bytes_and_have_unique_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sha256sum.txt"
            raw = (f"{'a' * 64}  first.tar.gz\n{'b' * 64}  second.tar.gz\n").encode(
                "ascii"
            )
            path.write_bytes(raw)
            expected = {
                "sizeBytes": len(raw),
                "digest": sha256(raw),
            }
            self.assertEqual(
                checksum_entries(path, expected),
                {
                    "first.tar.gz": f"sha256:{'a' * 64}",
                    "second.tar.gz": f"sha256:{'b' * 64}",
                },
            )
            expected["sizeBytes"] = len(raw) + 1
            with self.assertRaisesRegex(ValueError, "checksum_size_mismatch"):
                checksum_entries(path, expected)

            duplicate = (
                f"{'a' * 64}  repeated.tar.gz\n{'b' * 64}  repeated.tar.gz\n"
            ).encode("ascii")
            path.write_bytes(duplicate)
            expected = {
                "sizeBytes": len(duplicate),
                "digest": sha256(duplicate),
            }
            with self.assertRaisesRegex(ValueError, "checksum_duplicate"):
                checksum_entries(path, expected)

    def test_artifact_inspection_binds_size_digest_checksum_and_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            artifact, path = synthetic_archive(work)
            published = {path.name: artifact["digest"]}
            result = inspect_artifact(work, artifact, published)
            self.assertTrue(result["checksumMatch"])
            self.assertEqual(result["actualDigest"], artifact["digest"])
            self.assertEqual(result["members"], artifact["members"])

            changed = copy.deepcopy(artifact)
            changed["sizeBytes"] = int(changed["sizeBytes"]) + 1
            with self.assertRaisesRegex(ValueError, "archive_size_mismatch"):
                inspect_artifact(work, changed, published)
            changed = copy.deepcopy(artifact)
            changed["digest"] = f"sha256:{'f' * 64}"
            with self.assertRaisesRegex(ValueError, "published_digest_mismatch"):
                inspect_artifact(work, changed, published)
            changed = copy.deepcopy(artifact)
            changed["members"] = changed["members"][:-1]
            with self.assertRaisesRegex(ValueError, "archive_members_mismatch"):
                inspect_artifact(work, changed, published)

    def test_signed_checksum_requires_exact_key_signature_and_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            checksum = work / "sha256sum.txt"
            checksum.write_bytes(b"signed checksum fixture\n")
            signature_path = work / "sha256sum.txt.gpg"
            signature_path.write_bytes(b"signed message fixture")
            key_path = work / "release-key.asc"
            key_path.write_bytes(b"public key fixture")
            fingerprint = "A" * 40
            signature = {
                "fileName": signature_path.name,
                "sizeBytes": signature_path.stat().st_size,
                "digest": file_digest(signature_path),
                "sourceUrl": "https://mirror.invalid/sha256sum.txt.gpg",
                "format": "openpgp-signed-message",
            }
            signing_key = {
                "fileName": key_path.name,
                "sizeBytes": key_path.stat().st_size,
                "digest": file_digest(key_path),
                "sourceUrl": "https://security.invalid/release-key.asc",
                "fingerprint": fingerprint,
                "identity": "Fixture release key",
            }

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                if "--import" in command:
                    status = f"[GNUPG:] IMPORT_OK 1 {fingerprint}\n"
                else:
                    output = Path(command[command.index("--output") + 1])
                    output.write_bytes(checksum.read_bytes())
                    status = f"[GNUPG:] VALIDSIG {fingerprint} 0 0 0\n"
                return subprocess.CompletedProcess(command, 0, stdout=status, stderr="")

            result = verify_signed_checksum(
                work,
                checksum,
                signature,
                signing_key,
                run,
            )
            self.assertTrue(result["validSignature"])
            self.assertEqual(result["signedPayloadDigest"], file_digest(checksum))

            def wrong_key(command: list[str]) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="[GNUPG:] IMPORT_OK 1 WRONG\n",
                    stderr="",
                )

            with self.assertRaisesRegex(ValueError, "signing_key_import_invalid"):
                verify_signed_checksum(
                    work,
                    checksum,
                    signature,
                    signing_key,
                    wrong_key,
                )

    def test_archive_rejects_traversal_and_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            traversal = work / "traversal.tar.gz"
            write_tar(
                traversal,
                [
                    {
                        "name": "../escape",
                        "type": "regular",
                        "mode": 0o644,
                        "linkName": None,
                        "payload": b"bad",
                    }
                ],
            )
            with self.assertRaisesRegex(ValueError, "member_name_invalid"):
                archive_members(traversal)

            symbolic = work / "symbolic.tar.gz"
            with tarfile.open(symbolic, mode="w:gz") as archive:
                info = tarfile.TarInfo("oc")
                info.type = tarfile.SYMTYPE
                info.linkname = "/tmp/not-oc"
                archive.addfile(info)
            with self.assertRaisesRegex(ValueError, "member_type_invalid"):
                archive_members(symbolic)

    def test_report_is_payload_free_fail_closed_and_tamper_evident(self) -> None:
        lock = load_json(LOCK_PATH)
        report = valid_report(lock)
        validate_report(report, lock)
        self.assertTrue(report["controls"]["archiveIntegrityVerified"])
        self.assertTrue(report["controls"]["checksumSignatureVerified"])
        for control in (
            "binaryExecutionVerified",
            "pullSecretObserved",
            "entitlementObserved",
            "cloudMutationAuthorized",
            "campaignEligible",
        ):
            self.assertFalse(report["controls"][control])
        self.assertEqual(report["controls"]["allowedCertificationSlots"], [])
        self.assertTrue(all(value is False for value in report["claims"].values()))

        changed = copy.deepcopy(report)
        changed["controls"]["binaryExecutionVerified"] = True
        with self.assertRaisesRegex(ValueError, "report_controls_invalid"):
            validate_report(changed, lock)
        changed = copy.deepcopy(report)
        changed["artifacts"][0]["actualDigest"] = f"sha256:{'0' * 64}"
        with self.assertRaisesRegex(ValueError, "report_artifacts_invalid"):
            validate_report(changed, lock)
        changed = copy.deepcopy(report)
        changed["signatureDocument"]["validSignature"] = False
        with self.assertRaisesRegex(ValueError, "report_signature_invalid"):
            validate_report(changed, lock)
        changed = copy.deepcopy(report)
        changed["reportDigest"] = f"sha256:{'0' * 64}"
        with self.assertRaisesRegex(ValueError, "report_digest_mismatch"):
            validate_report(changed, lock)

    def test_schema_is_strict_at_all_object_boundaries(self) -> None:
        schema = json.loads(
            (
                ROOT / "schemas" / "sno-trial-openshift-toolchain-intake-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        for name in (
            "bindings",
            "checksumDocument",
            "signatureDocument",
            "signingKey",
            "artifact",
            "member",
            "controls",
            "claims",
        ):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])

    def test_output_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            value = {"createdAt": datetime.now(timezone.utc).isoformat()}
            write_create_only(output, value)
            with self.assertRaisesRegex(ValueError, "output_exists"):
                write_create_only(output, value)

    def test_cli_validates_lock_without_network_or_secret_access(self) -> None:
        self.assertEqual(main(["validate-lock"]), 0)


if __name__ == "__main__":
    unittest.main()
