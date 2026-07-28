from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.dependency_risk_collection_execution import (
    AUTHORITY_PATH,
    EXPECTED_AUTHORITY_DIGEST,
    load_contract,
    validate_authority,
    validate_declared_implementation,
)
from scripts.dependency_risk_contract import blob_digest
from scripts.github_environment_contract import load_expected_environment
from scripts.validate_dependency_risk_collection_custody import validate_statement
from scripts.validate_repository import ROOT, canonical_digest, load_json


class DependencyRiskCollectionExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority, self.release_set, self.risk_policy = load_contract()

    def validate(self, authority: dict) -> str:
        return validate_authority(authority, self.release_set, self.risk_policy)

    def test_locked_authority_and_implementation_are_valid(self) -> None:
        self.assertEqual(self.validate(self.authority), EXPECTED_AUTHORITY_DIGEST)
        validate_declared_implementation()

    def test_collection_identity_cannot_gain_broader_privileges(self) -> None:
        changes = (
            ("allowedKmsRole", "roles/cloudkms.admin"),
            ("rawEvidenceRole", "roles/storage.objectAdmin"),
            ("projectRoles", ["roles/viewer"]),
            ("rawEvidenceReadGranted", True),
            ("rawEvidenceDeleteGranted", True),
            ("signedEvidenceWriteGranted", True),
            ("artifactMirrorWriteGranted", True),
            ("userManagedServiceAccountKeyDeclared", True),
        )
        for key, value in changes:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["identity"][key] = value
                with self.assertRaisesRegex(ValueError, "identity_boundary_invalid"):
                    self.validate(changed)

    def test_collection_federation_is_bound_to_exact_private_main_workflow(
        self,
    ) -> None:
        changes = (
            ("repositoryId", "999"),
            ("repositoryVisibility", "public"),
            ("workflowRef", "different/workflow.yml@refs/heads/main"),
            ("environment", "unprotected"),
            ("deploymentBranch", "release"),
        )
        for key, value in changes:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["federation"][key] = value
                with self.assertRaisesRegex(ValueError, "federation_invalid"):
                    self.validate(changed)

    def test_source_contract_cannot_claim_live_collection_or_authorization(
        self,
    ) -> None:
        for key in (
            "applied",
            "liveIdentityVerified",
            "liveKmsVerified",
            "liveCollectionPassed",
            "rawEvidencePublished",
            "custodyVerified",
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

    def test_shared_environment_verifier_loads_exact_collection_contract(self) -> None:
        expected = load_expected_environment("dependency-risk-collection")
        self.assertEqual(expected, self.authority["federation"])
        self.assertEqual(expected["providerId"], "dependency-risk-collection")
        self.assertEqual(
            expected["environment"],
            "reference-lab-dependency-risk-collection",
        )

    def test_default_validation_and_ci_include_collection_gate(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        command = "python3 scripts/validate_dependency_risk_collection_execution.py"
        self.assertIn(
            "scripts/validate_dependency_risk_collection_execution.py", makefile
        )
        self.assertIn(command, ci)

    def test_collection_workflow_keeps_production_default_and_scoped_sno_lane(
        self,
    ) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "dependency-risk-collection.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("default: production-dependencies", workflow)
        self.assertEqual(
            workflow.count("scripts/collect_dependency_risk_evidence.sh"),
            2,
        )
        self.assertEqual(
            workflow.count(
                "scripts/collect_sno_trial_dependency_risk_evidence.sh"
            ),
            2,
        )
        self.assertEqual(
            workflow.count(
                "scripts/publish_sno_trial_dependency_risk_collection.sh"
            ),
            1,
        )
        self.assertEqual(workflow.count("--preflight-only"), 2)

    def test_raw_custody_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = load_json(
            ROOT / "schemas" / "dependency-risk-raw-custody-statement-v1.schema.json"
        )
        self.assertFalse(schema["additionalProperties"])
        for definition in (
            "bindings",
            "collection",
            "storage",
            "publisher",
            "claims",
        ):
            with self.subTest(definition=definition):
                self.assertFalse(schema["$defs"][definition]["additionalProperties"])

    def custody_statement(self) -> dict:
        digest = "sha256:" + "a" * 64
        return {
            "schemaVersion": 1,
            "kind": "orchestra.dependency-risk.raw-custody-statement.v1",
            "profileId": "orchestra-ocp-4.20-amd64-v1",
            "targetClass": "vendor-reference-lab",
            "executionMode": "live",
            "evidenceId": "orchestra-dependency-risk-evidence-fixture.1",
            "bindings": {
                **self.authority["bindings"],
                "collectionExecutionAuthorityDigest": canonical_digest(self.authority),
            },
            "collection": {
                "manifestFile": "dependency-risk-scan-manifest.json",
                "manifestDigest": digest,
                "collectionAttestationDigest": digest,
                "collectionSignatureBundleDigest": digest,
                "rawArchiveObject": "dependency-risk-raw-collection.tar.gz",
                "rawArchiveDigest": digest,
            },
            "storage": {
                "bucket": "orchestra-reference-lab-raw-evidence",
                "prefix": (
                    "dependency-risk/v1/orchestra-ocp-4.20-amd64-v1/"
                    "orchestra-dependency-risk-evidence-fixture.1"
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
                "scriptDigest": self.authority["bindings"]["publisherScriptDigest"],
                "actorIdentityDigest": digest,
                "signingPublicKeyDigest": digest,
                "publishedAt": "2026-07-23T00:00:00Z",
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

    def test_custody_statement_binds_collection_and_stays_non_authorizing(self) -> None:
        validate_statement(self.custody_statement(), self.authority)

        changed = self.custody_statement()
        changed["storage"]["objectGenerationRecorded"] = True
        with self.assertRaisesRegex(ValueError, "custody_storage_invalid"):
            validate_statement(changed, self.authority)

        changed = self.custody_statement()
        changed["claims"]["sourceAdmissionAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "custody_claim_invalid"):
            validate_statement(changed, self.authority)


class DependencyRiskCollectionPublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = load_json(AUTHORITY_PATH)
        (ROOT / "restricted").mkdir(exist_ok=True)

    @staticmethod
    def write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def prepare_fixture(self, work: Path) -> tuple[Path, Path, Path]:
        collection = work / "dependency-risk-collection-fixture"
        fake_bin = work / "bin"
        collection.mkdir()
        fake_bin.mkdir()

        public_key = collection / "collection-signing-public-key.pem"
        public_key.write_text("fixture-kms-public-key\n", encoding="utf-8")
        digest = "sha256:" + "b" * 64
        manifest = {
            "profileId": "orchestra-ocp-4.20-amd64-v1",
            "targetClass": "vendor-reference-lab",
            "executionMode": "live",
            "evidenceId": "orchestra-dependency-risk-evidence-publisher.1",
            "bindings": {
                "topologyDigest": self.authority["bindings"]["topologyDigest"],
                "dependencyAdmissionDigest": self.authority["bindings"][
                    "dependencyAdmissionDigest"
                ],
                "releaseSetDigest": self.authority["bindings"]["releaseSetDigest"],
                "sourceVerificationDigest": self.authority["bindings"][
                    "sourceVerificationDigest"
                ],
                "riskPolicyDigest": self.authority["bindings"]["riskPolicyDigest"],
            },
            "collection": {
                "collectorScriptDigest": self.authority["bindings"][
                    "collectorScriptDigest"
                ],
                "signingPublicKeyDigest": blob_digest(public_key.read_bytes()),
                "collectionAttestationDigest": digest,
                "collectionSignatureBundleDigest": digest,
            },
        }
        (collection / "dependency-risk-scan-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )

        self.write_executable(
            fake_bin / "python3",
            '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >>"${PYTHON_CALL_LOG:?}"\n',
        )
        self.write_executable(
            fake_bin / "realpath",
            "#!/usr/bin/env bash\n"
            "[[ \"${1:-}\" == '-m' ]] && shift\n"
            'exec /bin/realpath "$@"\n',
        )
        self.write_executable(
            fake_bin / "tar",
            "#!/usr/bin/env bash\nprintf 'fixture deterministic archive\\n'\n",
        )
        self.write_executable(fake_bin / "gzip", "#!/usr/bin/env bash\ncat\n")
        self.write_executable(
            fake_bin / "cosign",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ \"$1\" == 'public-key' ]]; then\n"
            '  cat "${FAKE_PUBLIC_KEY:?}"\n'
            "  exit 0\n"
            "fi\n"
            "[[ \"$1\" == 'sign-blob' ]]\n"
            "shift\n"
            "while (($#)); do\n"
            "  if [[ \"$1\" == '--bundle' ]]; then\n"
            '    printf \'{"fixture":"custody-signature"}\\n\' >"$2"\n'
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
            "count=0\n"
            '[[ ! -f "${GCLOUD_COUNT_FILE:?}" ]] || count=$(cat "$GCLOUD_COUNT_FILE")\n'
            "count=$((count + 1))\n"
            'printf \'%s\' "$count" >"$GCLOUD_COUNT_FILE"\n'
            'printf \'%s\\n\' "$*" >>"${GCLOUD_CALL_LOG:?}"\n'
            '[[ "${GCLOUD_FAIL_AT:-0}" != "$count" ]]\n',
        )
        return collection, fake_bin, public_key

    def run_publisher(
        self, *, fail_at: int = 0
    ) -> tuple[subprocess.CompletedProcess, list[str]]:
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-publisher.", dir=ROOT / "restricted"
        ) as temporary:
            work = Path(temporary)
            collection, fake_bin, public_key = self.prepare_fixture(work)
            gcloud_log = work / "gcloud.log"
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "FAKE_PUBLIC_KEY": str(public_key),
                "PYTHON_CALL_LOG": str(work / "python.log"),
                "GCLOUD_CALL_LOG": str(gcloud_log),
                "GCLOUD_COUNT_FILE": str(work / "gcloud-count"),
                "GCLOUD_FAIL_AT": str(fail_at),
            }
            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "publish_dependency_risk_collection.sh"),
                    "--collection-dir",
                    str(collection),
                    "--raw-evidence-bucket",
                    "orchestra-reference-lab-raw-evidence",
                    "--signing-key",
                    (
                        "gcpkms://projects/orchestra-services/locations/europe-west1/"
                        "keyRings/orchestra-reference-evidence/cryptoKeys/"
                        "dependency-risk-collection-signing/cryptoKeyVersions/1"
                    ),
                    "--expected-signing-public-key-digest",
                    blob_digest(public_key.read_bytes()),
                    "--actor-identity-digest",
                    "sha256:" + "c" * 64,
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            calls = (
                gcloud_log.read_text(encoding="utf-8").splitlines()
                if gcloud_log.exists()
                else []
            )
            return result, calls

    def test_publisher_uses_create_only_writes_and_signature_last(self) -> None:
        result, calls = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("custodyVerified=false", result.stdout)
        self.assertEqual(len(calls), 4)
        for call in calls:
            self.assertIn("--if-generation-match=0", call)
        expected_objects = (
            "dependency-risk-raw-collection.tar.gz",
            "dependency-risk-raw-custody-public-key.pem",
            "dependency-risk-raw-custody-statement.json",
            "dependency-risk-raw-custody-signature.sigstore.json",
        )
        for call, object_name in zip(calls, expected_objects, strict=True):
            self.assertTrue(call.endswith(object_name), call)

    def test_failed_completion_marker_upload_cannot_report_success(self) -> None:
        result, calls = self.run_publisher(fail_at=4)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 4)
        self.assertTrue(
            calls[-1].endswith("dependency-risk-raw-custody-signature.sigstore.json")
        )
        self.assertNotIn("dependency_risk_raw_custody_published", result.stdout)


if __name__ == "__main__":
    unittest.main()
