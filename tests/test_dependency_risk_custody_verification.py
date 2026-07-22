from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.dependency_risk_collection_execution import (
    load_contract as load_collection_contract,
)
from scripts.dependency_risk_contract import blob_digest
from scripts.dependency_risk_custody_verification import (
    EXPECTED_AUTHORITY_DIGEST,
    load_contract,
    validate_authority,
    validate_declared_implementation,
)
from scripts.github_environment_contract import load_expected_environment
from scripts.validate_dependency_risk_custody_report import (
    main as validate_custody_report_main,
)
from scripts.validate_repository import ROOT, canonical_digest, load_json
from scripts.verify_dependency_risk_raw_custody import (
    RAW_OBJECTS,
    safe_extract_collection,
    validate_report,
    verify_and_build_report,
)


class DependencyRiskCustodyAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority, self.release_set, self.risk_policy = load_contract()

    def validate(self, authority: dict) -> str:
        return validate_authority(authority, self.release_set, self.risk_policy)

    def test_locked_authority_and_implementation_are_valid(self) -> None:
        self.assertEqual(self.validate(self.authority), EXPECTED_AUTHORITY_DIGEST)
        validate_declared_implementation()

    def test_custody_identity_cannot_gain_broader_privileges(self) -> None:
        changes = (
            ("projectRoles", ["roles/viewer"]),
            ("rawObjectWriteGranted", True),
            ("rawObjectDeleteGranted", True),
            ("signedEvidenceReadGranted", True),
            ("signedEvidenceDeleteGranted", True),
            ("artifactMirrorWriteGranted", True),
            ("sourceAdmissionAuthorityGranted", True),
            ("activationAuthorityGranted", True),
            ("userManagedServiceAccountKeyDeclared", True),
        )
        for key, value in changes:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["identity"][key] = value
                with self.assertRaisesRegex(ValueError, "identity_boundary_invalid"):
                    self.validate(changed)

    def test_raw_and_signed_access_must_remain_managed_folder_scoped(self) -> None:
        for key, value in (
            ("rawManagedFolder", ""),
            ("signedManagedFolder", ""),
            ("generationPinnedDownloads", False),
            ("metagenerationPinnedDownloads", False),
            ("completionMarkerUploadedLast", False),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["storage"][key] = value
                with self.assertRaisesRegex(ValueError, "authority_storage_invalid"):
                    self.validate(changed)

    def test_federation_is_bound_to_exact_private_main_workflow(self) -> None:
        for key, value in (
            ("repositoryId", "999"),
            ("repositoryVisibility", "public"),
            ("workflowRef", "different/workflow.yml@refs/heads/main"),
            ("environment", "unprotected"),
            ("deploymentBranch", "release"),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["federation"][key] = value
                with self.assertRaisesRegex(ValueError, "federation_invalid"):
                    self.validate(changed)

    def test_source_contract_cannot_claim_live_custody_or_authorization(self) -> None:
        for key in (
            "applied",
            "liveIdentityVerified",
            "liveKmsVerified",
            "liveRawCustodyVerified",
            "signedReportPublished",
            "sourceAdmissionAuthorized",
            "mirrorAuthorization",
            "activationAuthorized",
            "campaignEvidence",
            "referenceProfileVerified",
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["claim"][key] = True
                with self.assertRaisesRegex(ValueError, "authority_claim_invalid"):
                    self.validate(changed)

    def test_shared_environment_verifier_loads_exact_custody_contract(self) -> None:
        expected = load_expected_environment("dependency-risk-custody-verification")
        self.assertEqual(expected, self.authority["federation"])
        self.assertEqual(expected["providerId"], "dependency-risk-custody")

    def test_default_validation_and_ci_include_custody_gate(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        command = "python3 scripts/validate_dependency_risk_custody_verification.py"
        self.assertIn(
            "scripts/validate_dependency_risk_custody_verification.py", makefile
        )
        self.assertIn(command, ci)

    def test_verification_container_receives_no_registry_credentials(self) -> None:
        workflow = (
            ROOT
            / ".github"
            / "workflows"
            / "dependency-risk-custody-verification.yml"
        ).read_text(encoding="utf-8")
        container_run = workflow.split(
            "docker run --rm --platform linux/amd64", maxsplit=1
        )[1].split("| tee", maxsplit=1)[0]
        self.assertNotIn("DOCKER_CONFIG", container_run)
        self.assertNotIn("/run/orchestra-auth/docker", container_run)
        input_check = workflow.split(
            "- name: Require reviewed identity and bounded inputs", maxsplit=1
        )[1].split("- name: Check out reviewed main revision", maxsplit=1)[0]
        self.assertNotIn("DEPENDENCY_RISK_GITHUB_APP_PRIVATE_KEY", input_check)
        self.assertNotIn("DEPENDENCY_RISK_GITHUB_APP_ID", input_check)

    def test_report_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = load_json(
            ROOT / "schemas" / "dependency-risk-custody-verification-v1.schema.json"
        )

        def assert_strict(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(value.get("additionalProperties"), False)
                for child in value.values():
                    assert_strict(child)
            elif isinstance(value, list):
                for child in value:
                    assert_strict(child)

        assert_strict(schema)


class DependencyRiskRawCustodyVerifierTests(unittest.TestCase):
    evidence_id = "orchestra-dependency-risk-evidence-fixture.1"
    verification_id = "orchestra-dependency-risk-custody-verification-fixture.1"
    collection_key = (
        "gcpkms://projects/orchestra-services/locations/europe-west1/"
        "keyRings/orchestra-reference-evidence/cryptoKeys/"
        "dependency-risk-collection-signing/cryptoKeyVersions/1"
    )
    verification_key = (
        "gcpkms://projects/orchestra-services/locations/europe-west1/"
        "keyRings/orchestra-reference-evidence/cryptoKeys/"
        "dependency-risk-custody-verification-signing/cryptoKeyVersions/1"
    )

    def setUp(self) -> None:
        self.authority, _, _ = load_contract()
        self.collection_authority, _, _ = load_collection_contract()
        (ROOT / "restricted").mkdir(exist_ok=True)

    def write_archive(self, path: Path, manifest: dict, public_key: bytes) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            root = "dependency-risk-collection-fixture"
            root_info = tarfile.TarInfo(root)
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o700
            archive.addfile(root_info)
            for name, content in (
                (
                    "dependency-risk-scan-manifest.json",
                    (json.dumps(manifest, sort_keys=True) + "\n").encode(),
                ),
                ("collection-signing-public-key.pem", public_key),
            ):
                info = tarfile.TarInfo(f"{root}/{name}")
                info.size = len(content)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(content))

    def prepare_fixture(self, work: Path) -> dict:
        downloads = work / "downloads"
        downloads.mkdir()
        collection_public_key = b"fixture-collection-public-key\n"
        verification_public_key = b"fixture-verification-public-key\n"
        attestation_digest = "sha256:" + "a" * 64
        collection_signature_digest = "sha256:" + "b" * 64
        manifest = {
            "evidenceId": self.evidence_id,
            "collection": {
                "collectionAttestationDigest": attestation_digest,
                "collectionSignatureBundleDigest": collection_signature_digest,
            },
        }
        manifest_bytes = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        archive = downloads / "dependency-risk-raw-collection.tar.gz"
        self.write_archive(archive, manifest, collection_public_key)
        raw_public_key = downloads / "dependency-risk-raw-custody-public-key.pem"
        raw_public_key.write_bytes(collection_public_key)
        raw_signature = (
            downloads / "dependency-risk-raw-custody-signature.sigstore.json"
        )
        raw_signature.write_text('{"fixture":"signature"}\n', encoding="utf-8")
        statement = {
            "schemaVersion": 1,
            "kind": "orchestra.dependency-risk.raw-custody-statement.v1",
            "profileId": "orchestra-ocp-4.20-amd64-v1",
            "targetClass": "vendor-reference-lab",
            "executionMode": "live",
            "evidenceId": self.evidence_id,
            "bindings": {
                **self.collection_authority["bindings"],
                "collectionExecutionAuthorityDigest": canonical_digest(
                    self.collection_authority
                ),
            },
            "collection": {
                "manifestFile": "dependency-risk-scan-manifest.json",
                "manifestDigest": blob_digest(manifest_bytes),
                "collectionAttestationDigest": attestation_digest,
                "collectionSignatureBundleDigest": collection_signature_digest,
                "rawArchiveObject": "dependency-risk-raw-collection.tar.gz",
                "rawArchiveDigest": blob_digest(archive.read_bytes()),
            },
            "storage": {
                "bucket": "orchestra-reference-lab-raw-evidence",
                "prefix": (
                    f"dependency-risk/v1/orchestra-ocp-4.20-amd64-v1/{self.evidence_id}"
                ),
                "signingPublicKeyObject": (
                    "dependency-risk-raw-custody-public-key.pem"
                ),
                "custodyStatementObject": (
                    "dependency-risk-raw-custody-statement.json"
                ),
                "custodySignatureBundleObject": (
                    "dependency-risk-raw-custody-signature.sigstore.json"
                ),
                "createOnlyGenerationPrecondition": 0,
                "objectGenerationRecorded": False,
                "independentCustodyVerificationRequired": True,
            },
            "publisher": {
                "executionClass": "signed-certification-runner",
                "scriptDigest": self.collection_authority["bindings"][
                    "publisherScriptDigest"
                ],
                "actorIdentityDigest": "sha256:" + "c" * 64,
                "signingPublicKeyDigest": blob_digest(collection_public_key),
                "publishedAt": "2026-07-22T00:00:00Z",
            },
            "claims": {
                "rawCollectionUploaded": True,
                "rawArtifactsRestricted": True,
                "custodyVerified": False,
                "sourceAdmissionAuthorized": False,
                "mirrorAuthorization": False,
                "activationAuthorized": False,
                "campaignEvidence": False,
                "referenceProfileVerified": False,
            },
        }
        statement_path = downloads / "dependency-risk-raw-custody-statement.json"
        statement_path.write_text(
            json.dumps(statement, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        prefix = statement["storage"]["prefix"]
        times = (
            "2026-07-22T00:00:01Z",
            "2026-07-22T00:00:02Z",
            "2026-07-22T00:00:03Z",
            "2026-07-22T00:00:04Z",
        )
        objects = []
        for index, (name, created) in enumerate(
            zip(RAW_OBJECTS, times, strict=True), start=1
        ):
            objects.append(
                {
                    "name": f"{prefix}/{name}",
                    "generation": str(100 + index),
                    "metageneration": "1",
                    "sizeBytes": (downloads / name).stat().st_size,
                    "crc32c": "AAAAAA==",
                    "md5Hash": None,
                    "etag": f"fixture-etag-{index}",
                    "timeCreated": created,
                    "updated": created,
                }
            )
        inventory = {
            "schemaVersion": 1,
            "bucket": statement["storage"]["bucket"],
            "prefix": prefix,
            "objects": objects,
        }
        inventory_path = work / "inventory.json"
        inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
        collection_kms_public_key = work / "collection-kms-public-key.pem"
        collection_kms_public_key.write_bytes(collection_public_key)
        verification_key_path = work / "verification-public-key.pem"
        verification_key_path.write_bytes(verification_public_key)
        cosign = work / "cosign-fixture"
        cosign.write_text(
            '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >>"${COSIGN_CALL_LOG:?}"\n',
            encoding="utf-8",
        )
        cosign.chmod(0o755)
        return {
            "downloads": downloads,
            "inventory": inventory,
            "inventory_path": inventory_path,
            "collection_kms_public_key": collection_kms_public_key,
            "verification_public_key": verification_key_path,
            "collection_public_key_digest": blob_digest(collection_public_key),
            "verification_public_key_digest": blob_digest(verification_public_key),
            "attestation_digest": attestation_digest,
            "cosign": cosign,
        }

    def verify_fixture(self, work: Path, fixture: dict) -> dict:
        output = work / "custody-report.json"
        call_log = work / "cosign.log"
        with (
            patch.dict(os.environ, {"COSIGN_CALL_LOG": str(call_log)}),
            patch(
                "scripts.verify_dependency_risk_raw_custody."
                "verify_collection_attestation",
                return_value=fixture["attestation_digest"],
            ),
        ):
            report = verify_and_build_report(
                inventory_path=fixture["inventory_path"],
                download_dir=fixture["downloads"],
                collection_kms_public_key=fixture["collection_kms_public_key"],
                collection_signing_key=self.collection_key,
                expected_collection_public_key_digest=fixture[
                    "collection_public_key_digest"
                ],
                verification_signing_key=self.verification_key,
                verification_signing_public_key=fixture["verification_public_key"],
                expected_verification_public_key_digest=fixture[
                    "verification_public_key_digest"
                ],
                verification_id=self.verification_id,
                evidence_id=self.evidence_id,
                actor_identity_digest="sha256:" + "d" * 64,
                started_at="2026-07-22T00:01:00Z",
                output=output,
                cosign=str(fixture["cosign"]),
            )
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
        return report

    def test_generation_pinned_raw_custody_builds_non_authorizing_report(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fixture = self.prepare_fixture(work)
            report = self.verify_fixture(work, fixture)
            validate_report(report, self.authority)
            self.assertTrue(report["claims"]["custodyVerified"])
            self.assertTrue(report["claims"]["objectGenerationsRecorded"])
            self.assertFalse(report["claims"]["sourceAdmissionAuthorized"])
            self.assertEqual(report["rawCustody"]["objectCount"], 4)

    def test_inventory_extra_object_and_marker_reordering_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fixture = self.prepare_fixture(work)
            inventory = fixture["inventory"]
            inventory["objects"].append(copy.deepcopy(inventory["objects"][0]))
            fixture["inventory_path"].write_text(json.dumps(inventory))
            with self.assertRaisesRegex(ValueError, "inventory_identity_invalid"):
                self.verify_fixture(work, fixture)

        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fixture = self.prepare_fixture(work)
            inventory = fixture["inventory"]
            marker = next(
                item
                for item in inventory["objects"]
                if item["name"].endswith(
                    "dependency-risk-raw-custody-signature.sigstore.json"
                )
            )
            marker["timeCreated"] = "2026-07-22T00:00:00Z"
            fixture["inventory_path"].write_text(json.dumps(inventory))
            with self.assertRaisesRegex(ValueError, "completion_marker_order_invalid"):
                self.verify_fixture(work, fixture)

        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fixture = self.prepare_fixture(work)
            inventory = fixture["inventory"]
            marker = next(
                item
                for item in inventory["objects"]
                if item["name"].endswith(
                    "dependency-risk-raw-custody-signature.sigstore.json"
                )
            )
            marker["timeCreated"] = inventory["objects"][-2]["timeCreated"]
            fixture["inventory_path"].write_text(json.dumps(inventory))
            with self.assertRaisesRegex(ValueError, "completion_marker_order_invalid"):
                self.verify_fixture(work, fixture)

    def test_download_size_must_match_generation_metadata(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fixture = self.prepare_fixture(work)
            fixture["inventory"]["objects"][0]["sizeBytes"] += 1
            fixture["inventory_path"].write_text(json.dumps(fixture["inventory"]))
            with self.assertRaisesRegex(ValueError, "download_size_mismatch"):
                self.verify_fixture(work, fixture)

    def test_kms_public_key_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fixture = self.prepare_fixture(work)
            fixture["collection_kms_public_key"].write_bytes(b"wrong-public-key\n")
            with self.assertRaisesRegex(ValueError, "public_key_mismatch"):
                self.verify_fixture(work, fixture)

    def test_archive_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            archive = work / "bad.tar.gz"
            with tarfile.open(archive, mode="w:gz") as handle:
                content = b"escape"
                info = tarfile.TarInfo("../escape")
                info.size = len(content)
                handle.addfile(info, io.BytesIO(content))
            with self.assertRaisesRegex(ValueError, "archive_member_invalid"):
                safe_extract_collection(archive, work / "output")

    def test_report_claim_or_generation_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fixture = self.prepare_fixture(work)
            report = self.verify_fixture(work, fixture)

            changed = copy.deepcopy(report)
            changed["claims"]["sourceAdmissionAuthorized"] = True
            with self.assertRaisesRegex(ValueError, "report_claim_invalid"):
                validate_report(changed, self.authority)

            changed = copy.deepcopy(report)
            changed["rawCustody"]["objects"][0]["generation"] = "0"
            with self.assertRaisesRegex(ValueError, "inventory_object_invalid"):
                validate_report(changed, self.authority)

    def test_signed_report_can_be_replayed_offline(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fixture = self.prepare_fixture(work)
            self.verify_fixture(work, fixture)
            report = work / "custody-report.json"
            signature = work / "custody-report.sigstore.json"
            signature.write_text('{"fixture":"signature"}\n', encoding="utf-8")
            call_log = work / "report-cosign.log"
            arguments = [
                "--report",
                str(report),
                "--verification-public-key",
                str(fixture["verification_public_key"]),
                "--signature-bundle",
                str(signature),
                "--expected-verification-public-key-digest",
                fixture["verification_public_key_digest"],
                "--cosign",
                str(fixture["cosign"]),
            ]
            with patch.dict(os.environ, {"COSIGN_CALL_LOG": str(call_log)}):
                self.assertEqual(validate_custody_report_main(arguments), 0)
            self.assertIn("verify-blob", call_log.read_text(encoding="utf-8"))

            wrong_digest = "sha256:" + "f" * 64
            digest_index = arguments.index(fixture["verification_public_key_digest"])
            arguments[digest_index] = wrong_digest
            with self.assertRaisesRegex(ValueError, "signature_binding_invalid"):
                validate_custody_report_main(arguments)

            arguments[digest_index] = fixture["verification_public_key_digest"]
            failing_cosign = work / "cosign-fail"
            failing_cosign.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
            failing_cosign.chmod(0o755)
            arguments[arguments.index(str(fixture["cosign"]))] = str(failing_cosign)
            with self.assertRaisesRegex(ValueError, "signature_verification_failed"):
                validate_custody_report_main(arguments)

    def test_report_signature_arguments_are_all_or_none(self) -> None:
        with self.assertRaisesRegex(ValueError, "signature_inputs_incomplete"):
            validate_custody_report_main(
                [
                    "--report",
                    "missing.json",
                    "--verification-public-key",
                    "missing.pem",
                ]
            )


class DependencyRiskCustodyPublisherTests(unittest.TestCase):
    collection_key = DependencyRiskRawCustodyVerifierTests.collection_key
    verification_key = DependencyRiskRawCustodyVerifierTests.verification_key
    evidence_id = DependencyRiskRawCustodyVerifierTests.evidence_id
    verification_id = DependencyRiskRawCustodyVerifierTests.verification_id

    def setUp(self) -> None:
        (ROOT / "restricted").mkdir(exist_ok=True)

    @staticmethod
    def write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def prepare_fixture(self, work: Path) -> tuple[Path, Path, Path, Path]:
        fake_bin = work / "bin"
        raw = work / "raw"
        fake_bin.mkdir()
        raw.mkdir()
        collection_public_key = raw / "dependency-risk-raw-custody-public-key.pem"
        verification_public_key = work / "verification-public-key.pem"
        collection_public_key.write_text("fixture-collection-key\n", encoding="utf-8")
        verification_public_key.write_text(
            "fixture-verification-key\n", encoding="utf-8"
        )
        for name in RAW_OBJECTS:
            path = raw / name
            if not path.exists():
                path.write_text(f"fixture:{name}\n", encoding="utf-8")

        prefix = f"dependency-risk/v1/orchestra-ocp-4.20-amd64-v1/{self.evidence_id}"
        gcloud_inventory = []
        for index, name in enumerate(RAW_OBJECTS, start=1):
            gcloud_inventory.append(
                {
                    "url": f"gs://raw/{prefix}/{name}#{100 + index}",
                    "type": "cloud_object",
                    "metadata": {
                        "bucket": "orchestra-reference-lab-raw-evidence",
                        "name": f"{prefix}/{name}",
                        "generation": str(100 + index),
                        "metageneration": "1",
                        "size": str((raw / name).stat().st_size),
                        "crc32c": "AAAAAA==",
                        "md5Hash": None,
                        "etag": f"etag-{index}",
                        "timeCreated": f"2026-07-22T00:00:0{index}+00:00",
                        "updated": f"2026-07-22T00:00:0{index}+00:00",
                    },
                }
            )
        inventory_path = work / "gcloud-inventory.json"
        inventory_path.write_text(json.dumps(gcloud_inventory), encoding="utf-8")

        self.write_executable(
            fake_bin / "realpath",
            "#!/usr/bin/env bash\n"
            "[[ \"${1:-}\" == '-m' ]] && shift\n"
            'exec /bin/realpath "$@"\n',
        )
        self.write_executable(
            fake_bin / "python3",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'if [[ "$1" == *verify_dependency_risk_raw_custody.py ]]; then\n'
            "  shift\n"
            "  while (($#)); do\n"
            "    if [[ \"$1\" == '--output' ]]; then\n"
            '      printf \'{"fixture":"custody-report"}\\n\' >"$2"\n'
            "      exit 0\n"
            "    fi\n"
            "    shift\n"
            "  done\n"
            "  exit 2\n"
            "fi\n"
            "exit 0\n",
        )
        self.write_executable(
            fake_bin / "cosign",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ \"$1\" == 'public-key' ]]; then\n"
            '  if [[ "$*" == *dependency-risk-custody-verification-signing* ]]; then\n'
            '    cat "${FAKE_VERIFICATION_PUBLIC_KEY:?}"\n'
            "  else\n"
            '    cat "${FAKE_COLLECTION_PUBLIC_KEY:?}"\n'
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "[[ \"$1\" == 'sign-blob' ]]\n"
            "shift\n"
            "while (($#)); do\n"
            "  if [[ \"$1\" == '--bundle' ]]; then\n"
            '    printf \'{"fixture":"report-signature"}\\n\' >"$2"\n'
            "    exit 0\n"
            "  fi\n"
            "  shift\n"
            "done\n"
            "exit 2\n",
        )
        self.write_executable(
            fake_bin / "gcloud",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ \"$1 $2\" == 'storage ls' ]]; then\n"
            '  cat "${FAKE_GCLOUD_INVENTORY:?}"\n'
            "  exit 0\n"
            "fi\n"
            "[[ \"$1 $2\" == 'storage cp' ]]\n"
            "previous=''\n"
            "last=''\n"
            'for argument in "$@"; do previous="$last"; last="$argument"; done\n'
            'if [[ "$previous" == gs://orchestra-reference-lab-raw-evidence/* ]]; then\n'
            '  printf \'%s\\n\' "$*" >>"${GCLOUD_DOWNLOAD_LOG:?}"\n'
            '  cp "${FAKE_RAW_DIR:?}/${previous##*/}" "$last"\n'
            "  exit 0\n"
            "fi\n"
            "count=0\n"
            '[[ ! -f "${GCLOUD_UPLOAD_COUNT:?}" ]] || count=$(cat "$GCLOUD_UPLOAD_COUNT")\n'
            "count=$((count + 1))\n"
            'printf \'%s\' "$count" >"$GCLOUD_UPLOAD_COUNT"\n'
            'printf \'%s\\n\' "$*" >>"${GCLOUD_UPLOAD_LOG:?}"\n'
            '[[ "${GCLOUD_FAIL_UPLOAD_AT:-0}" != "$count" ]]\n',
        )
        return fake_bin, raw, inventory_path, verification_public_key

    def run_publisher(
        self, *, fail_upload_at: int = 0
    ) -> tuple[subprocess.CompletedProcess, list[str], list[str]]:
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-custody-publisher.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            fake_bin, raw, inventory, verification_public_key = self.prepare_fixture(
                work
            )
            upload_log = work / "uploads.log"
            download_log = work / "downloads.log"
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "FAKE_COLLECTION_PUBLIC_KEY": str(
                    raw / "dependency-risk-raw-custody-public-key.pem"
                ),
                "FAKE_VERIFICATION_PUBLIC_KEY": str(verification_public_key),
                "FAKE_GCLOUD_INVENTORY": str(inventory),
                "FAKE_RAW_DIR": str(raw),
                "GCLOUD_DOWNLOAD_LOG": str(download_log),
                "GCLOUD_UPLOAD_LOG": str(upload_log),
                "GCLOUD_UPLOAD_COUNT": str(work / "upload-count"),
                "GCLOUD_FAIL_UPLOAD_AT": str(fail_upload_at),
            }
            result = subprocess.run(
                [
                    "bash",
                    str(
                        ROOT
                        / "scripts"
                        / "verify_and_publish_dependency_risk_custody.sh"
                    ),
                    "--raw-evidence-bucket",
                    "orchestra-reference-lab-raw-evidence",
                    "--signed-evidence-bucket",
                    "orchestra-reference-lab-signed-evidence",
                    "--evidence-id",
                    self.evidence_id,
                    "--verification-id",
                    self.verification_id,
                    "--collection-signing-key",
                    self.collection_key,
                    "--expected-collection-signing-public-key-digest",
                    blob_digest(
                        (
                            raw / "dependency-risk-raw-custody-public-key.pem"
                        ).read_bytes()
                    ),
                    "--verification-signing-key",
                    self.verification_key,
                    "--expected-verification-signing-public-key-digest",
                    blob_digest(verification_public_key.read_bytes()),
                    "--actor-identity-digest",
                    "sha256:" + "e" * 64,
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            uploads = (
                upload_log.read_text(encoding="utf-8").splitlines()
                if upload_log.exists()
                else []
            )
            downloads = (
                download_log.read_text(encoding="utf-8").splitlines()
                if download_log.exists()
                else []
            )
            return result, downloads, uploads

    def test_shell_generation_pins_downloads_and_uploads_signature_last(self) -> None:
        result, downloads, uploads = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(downloads), 4)
        for call in downloads:
            self.assertIn("--if-generation-match=", call)
            self.assertIn("--if-metageneration-match=", call)
        self.assertEqual(len(uploads), 3)
        for call in uploads:
            self.assertIn("--if-generation-match=0", call)
        self.assertTrue(
            uploads[-1].endswith(
                "dependency-risk-custody-verification-signature.sigstore.json"
            )
        )
        self.assertIn("custodyVerified=true", result.stdout)

    def test_failed_report_completion_marker_cannot_report_success(self) -> None:
        result, _, uploads = self.run_publisher(fail_upload_at=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(uploads), 3)
        self.assertTrue(
            uploads[-1].endswith(
                "dependency-risk-custody-verification-signature.sigstore.json"
            )
        )
        self.assertNotIn(
            "dependency_risk_custody_verification_published", result.stdout
        )


if __name__ == "__main__":
    unittest.main()
