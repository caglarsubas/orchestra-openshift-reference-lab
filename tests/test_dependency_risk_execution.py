from __future__ import annotations

import copy
import unittest
from pathlib import Path

from scripts.dependency_risk_execution import (
    EXPECTED_AUTHORITY_DIGEST,
    load_contract,
    validate_authority,
    validate_declared_implementation,
)
from scripts.github_environment_contract import load_expected_environment


class DependencyRiskExecutionAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority, self.release_set, self.risk_policy = load_contract()

    def validate(self, authority: dict) -> str:
        return validate_authority(authority, self.release_set, self.risk_policy)

    def test_locked_authority_and_implementation_are_valid(self) -> None:
        self.assertEqual(self.validate(self.authority), EXPECTED_AUTHORITY_DIGEST)
        validate_declared_implementation()

    def test_kms_authority_cannot_be_broadened(self) -> None:
        changed = copy.deepcopy(self.authority)
        changed["kms"]["purpose"] = "ENCRYPT_DECRYPT"
        with self.assertRaisesRegex(ValueError, "authority_kms_invalid"):
            self.validate(changed)

        changed = copy.deepcopy(self.authority)
        changed["identity"]["allowedKmsRole"] = "roles/cloudkms.admin"
        with self.assertRaisesRegex(ValueError, "identity_boundary_invalid"):
            self.validate(changed)

        changed = copy.deepcopy(self.authority)
        changed["identity"]["projectRoles"] = ["roles/viewer"]
        with self.assertRaisesRegex(ValueError, "identity_boundary_invalid"):
            self.validate(changed)

    def test_storage_mirror_and_static_key_grants_are_rejected(self) -> None:
        for key in (
            "evidenceBucketWriteGranted",
            "artifactMirrorWriteGranted",
            "userManagedServiceAccountKeyDeclared",
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["identity"][key] = True
                with self.assertRaisesRegex(ValueError, "identity_boundary_invalid"):
                    self.validate(changed)

    def test_federation_is_bound_to_exact_private_main_workflow(self) -> None:
        for key, value in (
            ("repositoryId", "999"),
            ("repositoryVisibility", "public"),
            ("deploymentBranch", "release"),
            ("environment", "unprotected"),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.authority)
                changed["federation"][key] = value
                with self.assertRaisesRegex(ValueError, "federation_invalid"):
                    self.validate(changed)

    def test_preflight_cannot_claim_collection_or_authorization(self) -> None:
        for key in (
            "collectionStarted",
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

    def test_shared_environment_verifier_loads_exact_preflight_contract(self) -> None:
        expected = load_expected_environment("dependency-risk-preflight")
        self.assertEqual(expected, self.authority["federation"])
        self.assertEqual(expected["providerId"], "dependency-risk-preflight")
        self.assertEqual(
            expected["environment"], "reference-lab-dependency-risk-preflight"
        )

    def test_unknown_environment_contract_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "contract_invalid"):
            load_expected_environment("unknown")

    def test_default_validation_and_ci_include_the_authority_gate(self) -> None:
        root = Path(__file__).resolve().parents[1]
        makefile = (root / "Makefile").read_text(encoding="utf-8")
        ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        command = "python3 scripts/validate_dependency_risk_execution.py"
        self.assertIn("scripts/validate_dependency_risk_execution.py", makefile)
        self.assertIn(command, ci)


if __name__ == "__main__":
    unittest.main()
