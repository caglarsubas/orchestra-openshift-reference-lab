from __future__ import annotations

import copy
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.build_sno_trial_dependency_risk_evidence import build_evidence
from scripts.sno_trial_dependency_risk import (
    blob_digest,
    expected_bindings,
    expected_subjects,
    load_inputs as load_risk_inputs,
    verified_custody_proof,
)
from scripts.sno_trial_dependency_risk_custody import (
    EXPECTED_POLICY_DIGEST,
    RAW_CUSTODY_SCHEMA_PATH,
    RAW_OBJECTS,
    VERIFICATION_SCHEMA_PATH,
    load_policy,
    validate_policy,
    validate_report,
)
from scripts.validate_repository import ROOT, canonical_digest, load_json
from scripts.verify_sno_trial_dependency_risk_raw_custody import (
    safe_extract_collection,
    verify_and_build_report,
)


def digest(number: int) -> str:
    return f"sha256:{number:064x}"


def assert_strict_object_schemas(test: unittest.TestCase, value: object) -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            test.assertIs(value.get("additionalProperties"), False)
        for child in value.values():
            assert_strict_object_schemas(test, child)
    elif isinstance(value, list):
        for child in value:
            assert_strict_object_schemas(test, child)


class SnoTrialDependencyRiskCustodyTests(unittest.TestCase):
    evidence_id = "orchestra-sno-trial-dependency-risk-evidence-fixture.1"
    verification_id = (
        "orchestra-sno-trial-dependency-risk-custody-verification-fixture.1"
    )
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
        self.policy = load_policy()
        self.artifacts, self.release_set, self.risk_policy = load_risk_inputs()

    def write_collection(self, directory: Path, public_key: bytes) -> dict:
        expected = expected_subjects(self.artifacts)
        runner = self.release_set["certificationRunner"]
        subjects = []
        for index, (subject_id, binding) in enumerate(expected.items(), start=1):
            vulnerability = {
                "SchemaVersion": 2,
                "ArtifactName": binding["platformSubject"],
                "ArtifactType": "container_image",
                "Results": [
                    {
                        "Target": f"{subject_id} (linux)",
                        "Class": "os-pkgs",
                        "Type": "linux",
                        "Vulnerabilities": [],
                    }
                ],
            }
            sbom = {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": subject_id,
                "documentNamespace": f"https://example.invalid/{subject_id}",
                "creationInfo": {
                    "created": "2026-07-28T00:30:00Z",
                    "creators": ["Tool: syft-1.48.0"],
                },
                "documentDescribes": ["SPDXRef-Package-1"],
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-1",
                        "name": f"package-{index}",
                        "versionInfo": "1.0.0",
                        "licenseDeclared": binding["declaredLicense"],
                        "licenseConcluded": "NOASSERTION",
                    }
                ],
            }
            signature_probe = {
                "schemaVersion": 1,
                "kind": (
                    "orchestra.openshift."
                    "sno-trial-upstream-signature-probe.v1"
                ),
                "indexSubject": binding["indexSubject"],
                "status": "no-signature-found",
                "cosignVersion": "3.1.1",
                "cosignExitCode": 1,
                "rawOutputDigest": digest(100 + index),
                "observedAt": "2026-07-28T00:20:00Z",
            }
            files = {
                "vulnerability": (
                    f"{subject_id}.trivy.json",
                    json.dumps(vulnerability, sort_keys=True).encode(),
                ),
                "sbom": (
                    f"{subject_id}.spdx.json",
                    json.dumps(sbom, sort_keys=True).encode(),
                ),
                "signature": (
                    f"{subject_id}.signature.json",
                    json.dumps(signature_probe, sort_keys=True).encode(),
                ),
            }
            for name, content in files.values():
                (directory / name).write_bytes(content)
            subjects.append(
                {
                    "id": subject_id,
                    "indexSubject": binding["indexSubject"],
                    "platformSubject": binding["platformSubject"],
                    "vulnerabilityReportFile": files["vulnerability"][0],
                    "vulnerabilityReportDigest": blob_digest(
                        files["vulnerability"][1]
                    ),
                    "sbomFile": files["sbom"][0],
                    "sbomDigest": blob_digest(files["sbom"][1]),
                    "signatureProbeFile": files["signature"][0],
                    "signatureProbeDigest": blob_digest(files["signature"][1]),
                }
            )
        collection_statement = {
            "schemaVersion": 1,
            "kind": (
                "orchestra.openshift."
                "sno-trial-dependency-risk-collection-statement.v1"
            ),
            "evidenceId": self.evidence_id,
            "collector": {
                "signingPublicKeyDigest": blob_digest(public_key),
            },
        }
        collection_statement_path = directory / "collection-statement.json"
        collection_statement_path.write_text(
            json.dumps(collection_statement, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        collection_signature_path = (
            directory / "collection-statement.sigstore.json"
        )
        collection_signature_path.write_text(
            '{"fixture":"collection-signature"}\n',
            encoding="utf-8",
        )
        (directory / "collection-signing-public-key.pem").write_bytes(public_key)
        collection = {
            "executionClass": "signed-certification-runner",
            "runnerRelease": runner["release"],
            "runnerRevision": runner["source"]["revision"],
            "runnerImage": runner["image"],
            "runnerImageDigest": runner["image"].rsplit("@", 1)[1],
            "runnerToolchainDigest": runner["toolchainDigest"],
            "actorIdentityDigest": digest(10),
            "startedAt": "2026-07-28T00:00:00Z",
            "completedAt": "2026-07-28T01:00:00Z",
            "collectionStatementDigest": blob_digest(
                collection_statement_path.read_bytes()
            ),
            "collectionSignatureBundleDigest": blob_digest(
                collection_signature_path.read_bytes()
            ),
            "vulnerabilityScanner": {
                "name": "trivy",
                "version": "0.72.0",
                "databaseDigest": digest(11),
                "javaDatabaseDigest": digest(12),
            },
            "sbomScanner": {"name": "syft", "version": "1.48.0"},
            "signatureProbe": {
                "name": "cosign",
                "version": "3.1.1",
                "trustedRootDigest": digest(13),
                "offlineVerification": False,
            },
            "rawArtifactsRestricted": True,
        }
        model = self.artifacts["models"][0]
        model_artifact = {
            "id": model["id"],
            "immutableUrl": model["immutableUrl"],
            "revision": model["revision"],
            "expectedDigest": model["digest"],
            "observedDigest": model["digest"],
            "expectedSizeBytes": model["sizeBytes"],
            "observedSizeBytes": model["sizeBytes"],
            "declaredLicense": model["license"],
            "bytesVerified": True,
            "contentLengthVerified": True,
            "licenseReview": {
                "state": "required",
                "reviewerIdentityDigest": None,
                "reviewDigest": None,
            },
        }
        manifest = {
            "schemaVersion": 1,
            "kind": (
                "orchestra.openshift."
                "sno-trial-dependency-risk-collection-manifest.v1"
            ),
            "evidenceId": self.evidence_id,
            "profileId": "orchestra-ocp-sno-trial-amd64-v1",
            "targetClass": "engineering-trial",
            "executionMode": "live",
            "bindings": {
                **expected_bindings(self.artifacts, self.release_set),
                "riskPolicyDigest": canonical_digest(self.risk_policy),
            },
            "collection": collection,
            "subjects": subjects,
            "modelArtifact": model_artifact,
        }
        manifest_path = directory / "collection-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        evidence = build_evidence(
            manifest,
            directory,
            self.artifacts,
            self.release_set,
        )
        evidence_path = directory / "risk-evidence.json"
        evidence_path.write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return {
            "manifest": manifest,
            "manifest_path": manifest_path,
            "evidence": evidence,
            "evidence_path": evidence_path,
            "collection_statement_path": collection_statement_path,
            "collection_signature_path": collection_signature_path,
        }

    def write_archive(self, path: Path, collection_dir: Path) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            root = "sno-dependency-risk-collection-fixture"
            root_info = tarfile.TarInfo(root)
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o700
            archive.addfile(root_info)
            for source in sorted(collection_dir.iterdir()):
                content = source.read_bytes()
                info = tarfile.TarInfo(f"{root}/{source.name}")
                info.size = len(content)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(content))

    def prepare_fixture(self, work: Path) -> dict:
        downloads = work / "downloads"
        downloads.mkdir()
        collection_dir = work / "sno-dependency-risk-collection-source"
        collection_dir.mkdir()
        collection_public_key = b"fixture-collection-public-key\n"
        verification_public_key = b"fixture-verification-public-key\n"
        collection = self.write_collection(collection_dir, collection_public_key)
        archive = downloads / "sno-dependency-risk-raw-collection.tar.gz"
        self.write_archive(archive, collection_dir)
        raw_public_key = (
            downloads / "sno-dependency-risk-raw-custody-public-key.pem"
        )
        raw_public_key.write_bytes(collection_public_key)
        raw_signature = (
            downloads
            / "sno-dependency-risk-raw-custody-signature.sigstore.json"
        )
        raw_signature.write_text(
            '{"fixture":"custody-signature"}\n',
            encoding="utf-8",
        )
        statement = {
            "schemaVersion": 1,
            "kind": (
                "orchestra.openshift.sno-trial-dependency-risk."
                "raw-custody-statement.v1"
            ),
            "profileId": "orchestra-ocp-sno-trial-amd64-v1",
            "targetClass": "engineering-trial",
            "executionMode": "live",
            "evidenceId": self.evidence_id,
            "bindings": {
                "artifactSetDigest": self.policy["bindings"][
                    "artifactSetDigest"
                ],
                "releaseSetDigest": self.policy["bindings"][
                    "releaseSetDigest"
                ],
                "riskPolicyDigest": self.policy["bindings"][
                    "riskPolicyDigest"
                ],
                "collectionAuthorityDigest": self.policy["bindings"][
                    "collectionAuthorityDigest"
                ],
                "collectorScriptDigest": self.risk_policy["collectionPolicy"][
                    "collectorScriptDigest"
                ],
                "publisherScriptDigest": self.policy["bindings"][
                    "publisherScriptDigest"
                ],
                "rawCustodySchemaDigest": self.policy["bindings"][
                    "rawCustodySchemaDigest"
                ],
            },
            "collection": {
                "manifestFile": "collection-manifest.json",
                "manifestDigest": blob_digest(
                    collection["manifest_path"].read_bytes()
                ),
                "riskEvidenceFile": "risk-evidence.json",
                "riskEvidenceDigest": blob_digest(
                    collection["evidence_path"].read_bytes()
                ),
                "collectionStatementDigest": blob_digest(
                    collection["collection_statement_path"].read_bytes()
                ),
                "collectionSignatureBundleDigest": blob_digest(
                    collection["collection_signature_path"].read_bytes()
                ),
                "rawArchiveObject": (
                    "sno-dependency-risk-raw-collection.tar.gz"
                ),
                "rawArchiveDigest": blob_digest(archive.read_bytes()),
            },
            "storage": {
                "bucket": "orchestra-reference-lab-raw-evidence",
                "prefix": (
                    "dependency-risk/sno-trial/v1/"
                    f"orchestra-ocp-sno-trial-amd64-v1/{self.evidence_id}"
                ),
                "signingPublicKeyObject": (
                    "sno-dependency-risk-raw-custody-public-key.pem"
                ),
                "custodyStatementObject": (
                    "sno-dependency-risk-raw-custody-statement.json"
                ),
                "custodySignatureBundleObject": (
                    "sno-dependency-risk-raw-custody-signature.sigstore.json"
                ),
                "createOnlyGenerationPrecondition": 0,
                "objectGenerationRecorded": False,
                "independentCustodyVerificationRequired": True,
            },
            "publisher": {
                "executionClass": "signed-certification-runner",
                "scriptDigest": self.policy["bindings"][
                    "publisherScriptDigest"
                ],
                "actorIdentityDigest": digest(20),
                "signingPublicKeyDigest": blob_digest(collection_public_key),
                "publishedAt": "2026-07-28T01:05:00Z",
            },
            "claims": {
                "rawCollectionUploaded": True,
                "rawArtifactsRestricted": True,
                "custodyVerified": False,
                "sourceAdmissionAuthorized": False,
                "mirrorAuthorization": False,
                "activationAuthorized": False,
                "deploymentAuthorized": False,
                "campaignEvidence": False,
                "referenceProfileVerified": False,
            },
        }
        statement_path = (
            downloads / "sno-dependency-risk-raw-custody-statement.json"
        )
        statement_path.write_text(
            json.dumps(statement, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        prefix = statement["storage"]["prefix"]
        times = (
            "2026-07-28T01:06:00Z",
            "2026-07-28T01:07:00Z",
            "2026-07-28T01:08:00Z",
            "2026-07-28T01:09:00Z",
        )
        objects = []
        for index, (name, created) in enumerate(
            zip(RAW_OBJECTS, times, strict=True),
            start=1,
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
            "collection_dir": collection_dir,
            "inventory": inventory,
            "inventory_path": inventory_path,
            "collection_kms_public_key": collection_kms_public_key,
            "verification_public_key": verification_key_path,
            "collection_public_key_digest": blob_digest(collection_public_key),
            "verification_public_key_digest": blob_digest(
                verification_public_key
            ),
            "cosign": cosign,
            "statement": statement,
        }

    def verify_fixture(self, work: Path, fixture: dict) -> dict:
        output = work / "custody-report.json"
        call_log = work / "cosign.log"
        with patch.dict(os.environ, {"COSIGN_CALL_LOG": str(call_log)}):
            return verify_and_build_report(
                inventory_path=fixture["inventory_path"],
                download_dir=fixture["downloads"],
                collection_kms_public_key=fixture[
                    "collection_kms_public_key"
                ],
                collection_signing_key=self.collection_key,
                expected_collection_public_key_digest=fixture[
                    "collection_public_key_digest"
                ],
                verification_signing_key=self.verification_key,
                verification_signing_public_key=fixture[
                    "verification_public_key"
                ],
                expected_verification_public_key_digest=fixture[
                    "verification_public_key_digest"
                ],
                verification_id=self.verification_id,
                evidence_id=self.evidence_id,
                actor_identity_digest=digest(30),
                started_at="2026-07-28T01:10:00Z",
                output=output,
                cosign=str(fixture["cosign"]),
            )

    def test_policy_is_stable_non_authorizing_and_managed_folder_scoped(
        self,
    ) -> None:
        self.assertEqual(validate_policy(self.policy), EXPECTED_POLICY_DIGEST)
        self.assertEqual(self.policy["collection"]["managedFolder"], "dependency-risk/")
        self.assertTrue(
            self.policy["collection"]["prefixTemplate"].startswith(
                "dependency-risk/sno-trial/"
            )
        )
        self.assertTrue(
            self.policy["verification"]["prefixTemplate"].startswith(
                "dependency-risk-custody/sno-trial/"
            )
        )
        for key in (
            "exceptionReviewAuthorized",
            "sourceAdmissionAuthorized",
            "mirrorAuthorization",
            "activationAuthorized",
            "deploymentAuthorized",
            "campaignEvidence",
            "referenceProfileVerified",
        ):
            self.assertFalse(self.policy["claim"][key])

    def test_schemas_are_strict(self) -> None:
        assert_strict_object_schemas(
            self,
            load_json(RAW_CUSTODY_SCHEMA_PATH),
        )
        assert_strict_object_schemas(
            self,
            load_json(VERIFICATION_SCHEMA_PATH),
        )

    def test_valid_fixture_recomputes_evidence_and_grants_no_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            work = Path(directory_name)
            fixture = self.prepare_fixture(work)
            report = self.verify_fixture(work, fixture)
        validate_report(report, self.policy)
        self.assertTrue(report["claims"]["custodyVerified"])
        self.assertTrue(report["collection"]["riskEvidenceRecomputed"])
        for key in (
            "sourceAdmissionAuthorized",
            "mirrorAuthorization",
            "activationAuthorized",
            "deploymentAuthorized",
            "campaignEvidence",
            "referenceProfileVerified",
        ):
            self.assertFalse(report["claims"][key])

    def test_completion_marker_order_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            work = Path(directory_name)
            fixture = self.prepare_fixture(work)
            marker = next(
                item
                for item in fixture["inventory"]["objects"]
                if item["name"].endswith(
                    "sno-dependency-risk-raw-custody-signature.sigstore.json"
                )
            )
            marker["timeCreated"] = "2026-07-28T01:05:30Z"
            fixture["inventory_path"].write_text(
                json.dumps(fixture["inventory"]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "completion_marker_order_invalid",
            ):
                self.verify_fixture(work, fixture)

    def test_archive_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            work = Path(directory_name)
            archive = work / "bad.tar.gz"
            with tarfile.open(archive, mode="w:gz") as handle:
                content = b"tamper"
                member = tarfile.TarInfo("../escape")
                member.size = len(content)
                handle.addfile(member, io.BytesIO(content))
            with self.assertRaisesRegex(
                ValueError,
                "archive_member_invalid",
            ):
                safe_extract_collection(archive, work / "extract")

    def test_archive_evidence_tamper_breaks_raw_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            work = Path(directory_name)
            fixture = self.prepare_fixture(work)
            archive = (
                fixture["downloads"]
                / "sno-dependency-risk-raw-collection.tar.gz"
            )
            archive.write_bytes(archive.read_bytes() + b"tamper")
            with self.assertRaisesRegex(
                ValueError,
                "download_size_mismatch",
            ):
                self.verify_fixture(work, fixture)

    def test_valid_but_manifest_inconsistent_evidence_is_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            work = Path(directory_name)
            fixture = self.prepare_fixture(work)
            evidence_path = fixture["collection_dir"] / "risk-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["modelArtifact"]["licenseReview"] = {
                "state": "complete",
                "reviewerIdentityDigest": digest(70),
                "reviewDigest": digest(71),
            }
            evidence["modelArtifact"]["verificationDigest"] = canonical_digest(
                {
                    key: value
                    for key, value in evidence["modelArtifact"].items()
                    if key != "verificationDigest"
                }
            )
            evidence["claims"]["modelLicenseReviewComplete"] = True
            evidence_path.write_text(
                json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            archive = (
                fixture["downloads"]
                / "sno-dependency-risk-raw-collection.tar.gz"
            )
            archive.unlink()
            self.write_archive(archive, fixture["collection_dir"])
            statement_path = (
                fixture["downloads"]
                / "sno-dependency-risk-raw-custody-statement.json"
            )
            statement = json.loads(statement_path.read_text(encoding="utf-8"))
            statement["collection"]["riskEvidenceDigest"] = blob_digest(
                evidence_path.read_bytes()
            )
            statement["collection"]["rawArchiveDigest"] = blob_digest(
                archive.read_bytes()
            )
            statement_path.write_text(
                json.dumps(statement, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            for item in fixture["inventory"]["objects"]:
                name = item["name"].rsplit("/", maxsplit=1)[1]
                item["sizeBytes"] = (fixture["downloads"] / name).stat().st_size
            fixture["inventory_path"].write_text(
                json.dumps(fixture["inventory"]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "evidence_recompute_invalid",
            ):
                self.verify_fixture(work, fixture)

    def test_report_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            work = Path(directory_name)
            fixture = self.prepare_fixture(work)
            report = self.verify_fixture(work, fixture)
        changed = copy.deepcopy(report)
        changed["claims"]["deploymentAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "report_claim_invalid"):
            validate_report(changed, self.policy)

    def test_exception_proof_requires_signed_report_and_exact_evidence_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            work = Path(directory_name)
            fixture = self.prepare_fixture(work)
            report = self.verify_fixture(work, fixture)
            report_path = work / "custody-report.json"
            signature_path = work / "custody-report.sigstore.json"
            signature_path.write_text(
                '{"fixture":"report-signature"}\n',
                encoding="utf-8",
            )
            evidence_path = fixture["collection_dir"] / "risk-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            with patch.dict(
                os.environ,
                {"COSIGN_CALL_LOG": str(work / "exception-cosign.log")},
            ):
                proof = verified_custody_proof(
                    report_path=report_path,
                    verification_public_key=fixture["verification_public_key"],
                    signature_bundle=signature_path,
                    expected_verification_public_key_digest=fixture[
                        "verification_public_key_digest"
                    ],
                    risk_evidence_path=evidence_path,
                    risk_evidence=evidence,
                    cosign=str(fixture["cosign"]),
                )
            self.assertEqual(proof["status"], "verified")
            self.assertEqual(proof["verificationId"], report["verificationId"])
            self.assertEqual(
                proof["riskEvidenceCanonicalDigest"],
                report["collection"]["riskEvidenceCanonicalDigest"],
            )
            evidence_path.write_text(
                evidence_path.read_text(encoding="utf-8") + " ",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"COSIGN_CALL_LOG": str(work / "tamper-cosign.log")},
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "custody_evidence_binding_invalid",
                ):
                    verified_custody_proof(
                        report_path=report_path,
                        verification_public_key=fixture[
                            "verification_public_key"
                        ],
                        signature_bundle=signature_path,
                        expected_verification_public_key_digest=fixture[
                            "verification_public_key_digest"
                        ],
                        risk_evidence_path=evidence_path,
                        risk_evidence=json.loads(
                            evidence_path.read_text(encoding="utf-8")
                        ),
                        cosign=str(fixture["cosign"]),
                    )

    def test_workflows_preserve_production_defaults_and_use_scoped_publishers(
        self,
    ) -> None:
        collection = (
            ROOT / ".github" / "workflows" / "dependency-risk-collection.yml"
        ).read_text(encoding="utf-8")
        custody = (
            ROOT
            / ".github"
            / "workflows"
            / "dependency-risk-custody-verification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("default: production-dependencies", collection)
        self.assertIn(
            "scripts/publish_sno_trial_dependency_risk_collection.sh",
            collection,
        )
        self.assertIn("default: production-dependencies", custody)
        self.assertIn(
            "scripts/verify_and_publish_sno_trial_dependency_risk_custody.sh",
            custody,
        )
        self.assertIn("dependency-risk/sno-trial/v1/", self.policy["collection"][
            "prefixTemplate"
        ])

    def test_publisher_and_verifier_use_create_only_and_signature_last(
        self,
    ) -> None:
        publisher = (
            ROOT / "scripts" / "publish_sno_trial_dependency_risk_collection.sh"
        ).read_text(encoding="utf-8")
        verifier = (
            ROOT
            / "scripts"
            / "verify_and_publish_sno_trial_dependency_risk_custody.sh"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(publisher.count("--if-generation-match=0"), 1)
        self.assertGreaterEqual(verifier.count("--if-generation-match=0"), 1)
        self.assertLess(
            publisher.find('upload_create_only "$CUSTODY_STATEMENT"'),
            publisher.find('upload_create_only "$CUSTODY_SIGNATURE"'),
        )
        self.assertLess(
            verifier.find('upload_create_only "$REPORT"'),
            verifier.find('upload_create_only "$REPORT_SIGNATURE"'),
        )


if __name__ == "__main__":
    unittest.main()
