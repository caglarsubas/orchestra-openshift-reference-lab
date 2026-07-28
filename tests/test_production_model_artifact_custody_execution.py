from __future__ import annotations

import copy
import unittest

from scripts.production_model_artifact_custody_execution import (
    BOOTSTRAP_OUTPUTS_PATH,
    BOOTSTRAP_TERRAFORM_PATH,
    EXPECTED_AUTHORITY_DIGEST,
    FOUNDATION_OUTPUTS_PATH,
    FOUNDATION_TERRAFORM_PATH,
    FOUNDATION_VARIABLES_PATH,
    UPLOADER_ID,
    VERIFIER_ID,
    WORKFLOW_PATH,
    blob_digest,
    load_contract,
    validate_authority,
    validate_declared_implementation,
)
from scripts.validate_repository import ROOT


class ProductionModelArtifactCustodyExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.authority,
            self.topology,
            self.release_set,
            self.custody_inputs,
        ) = load_contract()

    def validate(self, authority: dict) -> str:
        return validate_authority(
            authority,
            self.topology,
            self.release_set,
            self.custody_inputs,
        )

    def test_locked_authority_and_terraform_are_valid(self) -> None:
        self.assertEqual(self.validate(self.authority), EXPECTED_AUTHORITY_DIGEST)
        validate_declared_implementation(self.authority)

    def test_authority_binds_every_new_terraform_surface(self) -> None:
        expected = {
            "bootstrapTerraformDigest": blob_digest(BOOTSTRAP_TERRAFORM_PATH),
            "bootstrapOutputsDigest": blob_digest(BOOTSTRAP_OUTPUTS_PATH),
            "foundationTerraformDigest": blob_digest(FOUNDATION_TERRAFORM_PATH),
            "foundationVariablesDigest": blob_digest(FOUNDATION_VARIABLES_PATH),
            "foundationOutputsDigest": blob_digest(FOUNDATION_OUTPUTS_PATH),
        }
        for name, digest in expected.items():
            self.assertEqual(self.authority["bindings"][name], digest)

    def test_corrected_service_account_ids_fit_gcp_limit(self) -> None:
        self.assertEqual(UPLOADER_ID, "orchestra-model-custody-writer")
        self.assertEqual(VERIFIER_ID, "orchestra-model-custody-verify")
        self.assertLessEqual(len(UPLOADER_ID), 30)
        self.assertLessEqual(len(VERIFIER_ID), 30)

    def test_identity_privilege_escalation_is_rejected(self) -> None:
        changes = (
            ("uploader", "projectRoles", ["roles/storage.admin"]),
            ("uploader", "artifactReadGranted", True),
            ("uploader", "artifactDeleteGranted", True),
            ("uploader", "signedRecordAccessGranted", True),
            ("uploader", "userManagedServiceAccountKeyDeclared", True),
            ("verifier", "projectRoles", ["roles/viewer"]),
            ("verifier", "artifactWriteGranted", True),
            ("verifier", "artifactDeleteGranted", True),
            ("verifier", "signedRecordReadGranted", True),
            ("verifier", "signedRecordDeleteGranted", True),
            ("verifier", "userManagedServiceAccountKeyDeclared", True),
        )
        for actor, key, value in changes:
            with self.subTest(actor=actor, key=key):
                changed = copy.deepcopy(self.authority)
                changed["identities"][actor][key] = value
                with self.assertRaisesRegex(ValueError, "identity_boundary_invalid"):
                    self.validate(changed)

    def test_cross_plane_authority_escalation_is_rejected(self) -> None:
        for key in (
            "artifactMirrorWriteGranted",
            "sourceAdmissionAuthorityGranted",
            "deploymentAuthorityGranted",
            "campaignAuthorityGranted",
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["identities"][key] = True
                with self.assertRaisesRegex(ValueError, "identity_boundary_invalid"):
                    self.validate(changed)

    def test_federation_stays_bound_to_private_exact_main(self) -> None:
        changes = (
            ("repository", "other/repository"),
            ("repositoryId", "999"),
            ("repositoryVisibility", "public"),
            ("deploymentBranch", "release"),
            ("trigger", "push"),
            ("uploaderEnvironment", "unprotected"),
            ("verifierEnvironment", "unprotected"),
            ("preventSelfReview", False),
        )
        for key, value in changes:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["federation"][key] = value
                with self.assertRaisesRegex(ValueError, "federation_invalid"):
                    self.validate(changed)

    def test_source_contract_cannot_claim_apply_or_verification(self) -> None:
        for key, value in self.authority["claim"].items():
            if key == "terraformDeclared":
                self.assertTrue(value)
                continue
            self.assertFalse(value, key)
            changed = copy.deepcopy(self.authority)
            changed["claim"][key] = True
            with self.assertRaisesRegex(ValueError, "authority_claim_invalid"):
                self.validate(changed)

    def test_workflow_remains_a_non_executable_reservation(self) -> None:
        self.assertFalse(WORKFLOW_PATH.exists())
        self.assertFalse(self.authority["workflowReservation"]["declared"])
        self.assertTrue(
            self.authority["workflowReservation"][
                "transferBoundaryDecisionRequired"
            ]
        )
        self.assertFalse(
            self.authority["workflowReservation"][
                "localRestrictedDirectoryReadableByGitHubHostedRunner"
            ]
        )

    def test_bucket_and_kms_contract_is_retained_and_separated(self) -> None:
        foundation = FOUNDATION_TERRAFORM_PATH.read_text(encoding="utf-8")
        self.assertIn("retention_period = 400 * 24 * 60 * 60", foundation)
        self.assertIn("enable_object_retention     = true", foundation)
        self.assertIn('purpose         = "ENCRYPT_DECRYPT"', foundation)
        self.assertIn('purpose  = "ASYMMETRIC_SIGN"', foundation)
        self.assertIn('name            = "production-model-artifacts/"', foundation)
        self.assertIn('name            = "production-model-custody/"', foundation)
        self.assertNotIn("roles/storage.admin", foundation)

    def test_default_validation_ci_docs_and_status_include_authority_gate(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        runbook = (
            ROOT / "docs" / "runbooks" / "production-model-artifacts.md"
        ).read_text(encoding="utf-8")
        status = (ROOT / "docs" / "implementation-status.md").read_text(
            encoding="utf-8"
        )
        command = "scripts/validate_production_model_artifact_custody_execution.py"
        self.assertIn(command, makefile)
        self.assertIn(command, ci)
        self.assertIn("validate-production-model-artifact-custody-authority", runbook)
        self.assertIn("Production model custody cloud authority", status)


if __name__ == "__main__":
    unittest.main()
