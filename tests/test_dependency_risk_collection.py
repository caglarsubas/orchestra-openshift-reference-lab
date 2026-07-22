from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.dependency_risk_contract import (
    RELEASE_SET,
    blob_digest,
    expected_bindings,
    load_contract_inputs,
    unsigned_subjects,
)
from scripts.validate_release_set import validate_release_set
from scripts.validate_repository import load_json
from scripts.verify_dependency_risk_collection import (
    expected_collection_statement,
    verify_collection_attestation,
)


ROOT = Path(__file__).resolve().parents[1]


def digest_bytes(content: bytes) -> str:
    return blob_digest(content)


class DependencyRiskCollectionTests(unittest.TestCase):
    def write_fixture(
        self, directory: Path, *, cosign_exit: int = 0
    ) -> tuple[dict, Path]:
        release_set = load_json(RELEASE_SET)
        toolchain_bytes = (
            ROOT
            / "tests"
            / "fixtures"
            / "platform-rc10-certification-runner-toolchain-lock.json"
        ).read_bytes()
        toolchain_digest = digest_bytes(toolchain_bytes)
        self.assertEqual(
            toolchain_digest,
            release_set["certificationRunner"]["toolchainDigest"],
        )
        release_set_digest = validate_release_set(release_set)
        runner = release_set["certificationRunner"]

        release_manifest = {
            "release": {"tag": runner["release"]},
            "source": {
                "repository": runner["source"]["repository"],
                "revision": runner["source"]["revision"],
                "ref": f"refs/tags/{runner['release']}",
            },
            "productionProfile": release_set["profile"],
            "subjects": {"images": [{"ref": runner["image"]}]},
        }
        release_metadata = {
            "role": "certification-runner",
            "flavor": "ubi9",
            "repository": runner["image"].rsplit("@", 1)[0],
            "digest": runner["image"].rsplit("@", 1)[1],
            "tag": runner["release"],
            "revision": runner["source"]["revision"],
            "toolchain": {"digest": toolchain_digest},
        }
        artifacts = {
            "platform-release-manifest.json": (
                json.dumps(release_manifest, sort_keys=True) + "\n"
            ).encode(),
            "platform-release-manifest.sigstore.json": b'{"fixture":"signature"}\n',
            "platform-release-manifest.provenance.sigstore.json": b'{"fixture":"provenance"}\n',
            "release-orchestra-certification-runner-ubi.json": (
                json.dumps(release_metadata, sort_keys=True) + "\n"
            ).encode(),
            "certification-runner-toolchain-lock.json": toolchain_bytes,
            "dependency-risk-collector.sh": (
                ROOT / "scripts" / "collect_dependency_risk_evidence.sh"
            ).read_bytes(),
            "collection-signing-public-key.pem": b"fixture-public-key\n",
            "dependency-risk-collection-signature.sigstore.json": b'{"fixture":"collection-signature"}\n',
        }
        for name, content in artifacts.items():
            (directory / name).write_bytes(content)

        admission, _, _ = load_contract_inputs()
        subjects = [
            {
                "id": subject_id,
                "sourceSubject": binding["sourceSubject"],
                "platformSubject": binding["platformSubject"],
                "vulnerabilityReportFile": f"{subject_id}.trivy.json",
                "vulnerabilityReportDigest": digest_bytes(
                    f"trivy:{subject_id}".encode()
                ),
                "sbomFile": f"{subject_id}.spdx.json",
                "sbomDigest": digest_bytes(f"spdx:{subject_id}".encode()),
            }
            for subject_id, binding in unsigned_subjects(admission).items()
        ]
        for subject in subjects:
            (directory / subject["vulnerabilityReportFile"]).write_bytes(
                f"trivy:{subject['id']}".encode()
            )
            (directory / subject["sbomFile"]).write_bytes(
                f"spdx:{subject['id']}".encode()
            )

        bindings = expected_bindings()
        self.assertEqual(bindings["releaseSetDigest"], release_set_digest)
        manifest = {
            "schemaVersion": 1,
            "profileId": "orchestra-ocp-4.20-amd64-v1",
            "targetClass": "vendor-reference-lab",
            "executionMode": "live",
            "evidenceId": "orchestra-dependency-risk-evidence-fixture.1",
            "bindings": bindings,
            "collection": {
                "executionClass": "signed-certification-runner",
                "runnerRelease": runner["release"],
                "runnerRevision": runner["source"]["revision"],
                "runnerImage": runner["image"],
                "runnerImageDigest": runner["image"].rsplit("@", 1)[1],
                "runnerToolchainDigest": toolchain_digest,
                "runnerReleaseManifestFile": "platform-release-manifest.json",
                "runnerReleaseManifestDigest": digest_bytes(
                    artifacts["platform-release-manifest.json"]
                ),
                "runnerReleaseManifestSignatureBundleFile": "platform-release-manifest.sigstore.json",
                "runnerReleaseManifestSignatureBundleDigest": digest_bytes(
                    artifacts["platform-release-manifest.sigstore.json"]
                ),
                "runnerProvenanceBundleFile": "platform-release-manifest.provenance.sigstore.json",
                "runnerProvenanceBundleDigest": digest_bytes(
                    artifacts["platform-release-manifest.provenance.sigstore.json"]
                ),
                "runnerReleaseMetadataFile": "release-orchestra-certification-runner-ubi.json",
                "runnerReleaseMetadataDigest": digest_bytes(
                    artifacts["release-orchestra-certification-runner-ubi.json"]
                ),
                "runnerToolchainLockFile": "certification-runner-toolchain-lock.json",
                "collectorScriptFile": "dependency-risk-collector.sh",
                "collectorScriptDigest": digest_bytes(
                    artifacts["dependency-risk-collector.sh"]
                ),
                "actorIdentityDigest": digest_bytes(b"collector"),
                "signingPublicKeyFile": "collection-signing-public-key.pem",
                "signingPublicKeyDigest": digest_bytes(
                    artifacts["collection-signing-public-key.pem"]
                ),
                "startedAt": "2026-07-22T00:00:00Z",
                "completedAt": "2026-07-22T01:00:00Z",
                "collectionAttestationFile": "dependency-risk-collection-statement.json",
                "collectionAttestationDigest": digest_bytes(b"placeholder"),
                "collectionSignatureBundleFile": "dependency-risk-collection-signature.sigstore.json",
                "collectionSignatureBundleDigest": digest_bytes(
                    artifacts["dependency-risk-collection-signature.sigstore.json"]
                ),
                "vulnerabilityScanner": {
                    "name": "trivy",
                    "version": "0.72.0",
                    "databaseDigest": digest_bytes(b"trivy-db"),
                    "javaDatabaseDigest": digest_bytes(b"trivy-java-db"),
                },
                "sbomScanner": {"name": "syft", "version": "1.48.0"},
                "invocationPolicy": {
                    "platform": "linux/amd64",
                    "imageSource": "remote",
                    "vulnerabilityScanners": ["vuln"],
                    "ignoreFileUsed": False,
                    "ignoreUnfixed": False,
                    "severityFilter": [],
                    "externalConfigUsed": False,
                    "databaseUpdatesDuringScan": False,
                    "offlineScan": True,
                    "sbomSource": "registry",
                    "sbomFormat": "spdx-2.3-json",
                },
            },
            "subjects": subjects,
        }
        statement = expected_collection_statement(manifest)
        statement_bytes = (
            json.dumps(statement, sort_keys=True, indent=2) + "\n"
        ).encode()
        (directory / "dependency-risk-collection-statement.json").write_bytes(
            statement_bytes
        )
        manifest["collection"]["collectionAttestationDigest"] = digest_bytes(
            statement_bytes
        )

        cosign = directory / "cosign-fixture"
        cosign.write_text(
            "#!/usr/bin/env bash\n"
            'printf \'%s\\n\' "$*" >>"${COSIGN_CALL_LOG:?}"\n'
            f"exit {cosign_exit}\n",
            encoding="utf-8",
        )
        cosign.chmod(0o755)
        return manifest, cosign

    def verify_fixture(self, directory: Path, manifest: dict, cosign: Path) -> str:
        call_log = directory / "cosign-calls.log"
        with patch.dict(os.environ, {"COSIGN_CALL_LOG": str(call_log)}):
            result = verify_collection_attestation(
                manifest, directory, cosign=str(cosign)
            )
        calls = call_log.read_text(encoding="utf-8")
        self.assertIn("verify-blob --bundle", calls)
        self.assertIn("verify-blob-attestation --bundle", calls)
        self.assertIn("verify-attestation", calls)
        self.assertIn(
            f"--certificate-github-workflow-sha {manifest['collection']['runnerRevision']}",
            calls,
        )
        self.assertIn(
            f"--certificate-github-workflow-ref refs/tags/{manifest['collection']['runnerRelease']}",
            calls,
        )
        self.assertIn(
            "--certificate-github-workflow-repository caglarsubas/agent-hook-v2",
            calls,
        )
        self.assertIn("--certificate-github-workflow-trigger push", calls)
        return result

    def test_collection_projection_and_all_five_cosign_checks_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, cosign = self.write_fixture(directory)
            self.assertEqual(
                self.verify_fixture(directory, manifest, cosign),
                manifest["collection"]["collectionAttestationDigest"],
            )
            self.assertEqual(
                len((directory / "cosign-calls.log").read_text().splitlines()), 5
            )

    def test_statement_tamper_is_rejected_before_signature_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, cosign = self.write_fixture(directory)
            statement_path = directory / "dependency-risk-collection-statement.json"
            statement = json.loads(statement_path.read_text())
            statement["claims"]["mirrorAuthorization"] = True
            statement_path.write_text(json.dumps(statement), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "statement_digest_mismatch"):
                self.verify_fixture(directory, manifest, cosign)

    def test_invalid_detached_signature_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, cosign = self.write_fixture(directory, cosign_exit=1)
            with self.assertRaisesRegex(ValueError, "signature_verification_failed"):
                self.verify_fixture(directory, manifest, cosign)

    def test_invalid_evidence_identity_is_rejected_before_signature_verification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, cosign = self.write_fixture(directory)
            manifest["evidenceId"] = "invalid"
            with self.assertRaisesRegex(ValueError, "manifest_identity_invalid"):
                self.verify_fixture(directory, manifest, cosign)

    def test_raw_scan_artifact_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, cosign = self.write_fixture(directory)
            first = manifest["subjects"][0]
            (directory / first["vulnerabilityReportFile"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(
                ValueError, "collection_artifact_digest_mismatch"
            ):
                self.verify_fixture(directory, manifest, cosign)

    def test_collector_is_atomic_and_pins_scanner_invocations(self) -> None:
        source = (ROOT / "scripts" / "collect_dependency_risk_evidence.sh").read_text()
        for fragment in (
            '[[ ! -e "$OUTPUT_DIR" ]]',
            'mktemp -d "$OUTPUT_PARENT/.dependency-risk-collection.',
            'mv "$TEMP_DIR" "$OUTPUT_DIR"',
            "--download-db-only",
            "--download-java-db-only",
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--image-src remote",
            '"registry:$platform_subject"',
            "cosign sign-blob",
            '--key "$SIGNING_KEY"',
            "--preflight-only",
            "gcloud kms asymmetric-sign",
            "openssl dgst -sha256",
            "collectionStarted=false",
        ):
            self.assertIn(fragment, source)
        self.assertNotIn("--ignore-unfixed", source)
        self.assertLess(
            source.index('if [[ "$PREFLIGHT_ONLY" == "true" ]]'),
            source.index("--download-db-only"),
        )

    def test_preflight_verifies_kms_and_publishes_no_evidence(self) -> None:
        restricted = ROOT / "restricted"
        restricted.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-preflight.", dir=restricted
        ) as temporary:
            work = Path(temporary)
            release_dir = work / "platform-release"
            fake_bin = work / "bin"
            release_dir.mkdir()
            fake_bin.mkdir()
            self.write_fixture(release_dir)

            call_log = work / "calls.log"
            public_key = release_dir / "collection-signing-public-key.pem"

            def command(name: str, source: str) -> None:
                path = fake_bin / name
                path.write_text(
                    "#!/usr/bin/env bash\nset -euo pipefail\n"
                    'printf \'%s %s\\n\' "$(basename "$0")" "$*" '
                    '>>"${PREFLIGHT_CALL_LOG:?}"\n' + source,
                    encoding="utf-8",
                )
                path.chmod(0o755)

            command(
                "date",
                "printf '2026-07-22T02:00:00Z\\n'\n",
            )
            command(
                "realpath",
                "[[ \"${1:-}\" == '-m' ]] && shift\n"
                "python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' \"$1\"\n",
            )
            command(
                "trivy",
                "[[ \"${1:-}\" == '--version' ]] || exit 91\n"
                "printf 'Version: 0.72.0\\n'\n",
            )
            command(
                "syft",
                "[[ \"${1:-}\" == 'version' ]] || exit 92\n"
                'printf \'{"version":"1.48.0"}\\n\'\n',
            )
            command(
                "cosign",
                'case "${1:-}" in\n'
                '  version) printf \'{"gitVersion":"v3.1.1"}\\n\' ;;\n'
                '  public-key) cat "${FIXTURE_KMS_PUBLIC_KEY:?}" ;;\n'
                "  verify*) exit 0 ;;\n"
                "  *) exit 93 ;;\n"
                "esac\n",
            )
            command(
                "gcloud",
                "if [[ \"${1:-}\" == 'version' ]]; then\n"
                '  printf \'{"Google Cloud SDK":"576.0.0"}\\n\'\n'
                "elif [[ \"$*\" == *'keys versions describe'* ]]; then\n"
                "  printf 'EC_SIGN_P256_SHA256\\tENABLED\\n'\n"
                "elif [[ \"$*\" == *'kms asymmetric-sign'* ]]; then\n"
                "  signature_file=''\n"
                '  for argument in "$@"; do\n'
                '    case "$argument" in\n'
                '      --signature-file=*) signature_file="${argument#*=}" ;;\n'
                "    esac\n"
                "  done\n"
                '  [[ -n "$signature_file" ]] || exit 94\n'
                "  printf 'fixture-kms-signature' >\"$signature_file\"\n"
                "else\n"
                "  exit 95\n"
                "fi\n",
            )
            command(
                "openssl",
                "[[ \"${1:-}\" == 'dgst' && \"$*\" == *'-sha256'* ]] || exit 96\n",
            )
            command(
                "orchestra-certification",
                "[[ \"${1:-}\" == 'self-test' ]] || exit 97\n",
            )

            output_dir = work / "unpublished-evidence"
            actor_digest = digest_bytes(b"preflight-collector")
            public_key_digest = digest_bytes(public_key.read_bytes())
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "PREFLIGHT_CALL_LOG": str(call_log),
                    "FIXTURE_KMS_PUBLIC_KEY": str(public_key),
                    "ORCHESTRA_RUNNER_TOOLCHAIN_LOCK": str(
                        release_dir / "certification-runner-toolchain-lock.json"
                    ),
                }
            )
            collector_command = [
                str(ROOT / "scripts" / "collect_dependency_risk_evidence.sh"),
                "--output-dir",
                str(output_dir),
                "--evidence-id",
                "orchestra-dependency-risk-evidence-preflight.1",
                "--actor-identity-digest",
                actor_digest,
                "--platform-release-dir",
                str(release_dir),
                "--signing-key",
                (
                    "gcpkms://projects/lab/locations/europe-west1/keyRings/"
                    "evidence/cryptoKeys/dependency-risk/cryptoKeyVersions/1"
                ),
                "--expected-signing-public-key-digest",
                public_key_digest,
                "--preflight-only",
            ]
            result = subprocess.run(
                collector_command,
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("dependency_risk_collection_preflight_ready", result.stdout)
            self.assertIn("collectionStarted=false", result.stdout)
            self.assertIn("sourceAdmission=false", result.stdout)
            self.assertFalse(output_dir.exists())
            self.assertEqual(
                list(work.glob(".dependency-risk-collection.*")),
                [],
            )
            calls = call_log.read_text(encoding="utf-8")
            self.assertIn("gcloud kms asymmetric-sign", calls)
            self.assertIn("openssl dgst -sha256", calls)
            self.assertNotIn("--download-db-only", calls)
            self.assertNotIn("trivy image", calls)

            command("openssl", "exit 96\n")
            invalid_signature = subprocess.run(
                collector_command,
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(invalid_signature.returncode, 0)
            self.assertIn(
                "cloud_kms_signing_challenge_verification_failed",
                invalid_signature.stderr,
            )
            self.assertFalse(output_dir.exists())
            self.assertEqual(list(work.glob(".dependency-risk-collection.*")), [])

    def test_fixture_is_non_authorizing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest, _ = self.write_fixture(Path(temporary))
        statement = expected_collection_statement(manifest)
        self.assertEqual(
            statement["claims"],
            {
                "rawArtifactsRestricted": True,
                "sourceAdmissionAuthorized": False,
                "mirrorAuthorization": False,
                "activationAuthorized": False,
                "campaignEvidence": False,
            },
        )
        self.assertFalse(
            any(
                statement["claims"][key]
                for key in (
                    "sourceAdmissionAuthorized",
                    "mirrorAuthorization",
                    "activationAuthorized",
                    "campaignEvidence",
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
