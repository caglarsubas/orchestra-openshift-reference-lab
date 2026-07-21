from __future__ import annotations

import copy
import unittest

from scripts.validate_dependency_supply_chain import (
    ADMISSION,
    EXPECTED_MIRROR_INTAKE_DIGEST,
    EXPECTED_SOURCE_VERIFICATION_DIGEST,
    MIRROR_INTAKE,
    SOURCE_VERIFICATION,
    TOPOLOGY,
    validate_mirror_intake,
    validate_source_verification,
)
from scripts.validate_repository import load_json


class DependencySupplyChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admission = load_json(ADMISSION)
        self.topology = load_json(TOPOLOGY)
        self.source = load_json(SOURCE_VERIFICATION)
        self.mirror = load_json(MIRROR_INTAKE)

    def validate_source(self, value: dict) -> str:
        return validate_source_verification(value, self.admission, self.topology)

    def validate_mirror(self, value: dict) -> str:
        return validate_mirror_intake(
            value,
            self.admission,
            EXPECTED_SOURCE_VERIFICATION_DIGEST,
            self.topology,
        )

    def test_bounded_source_observation_is_valid_but_not_admitted(self) -> None:
        self.assertEqual(
            self.validate_source(self.source), EXPECTED_SOURCE_VERIFICATION_DIGEST
        )
        self.assertEqual(len(self.source["verifiedSubjects"]), 3)
        self.assertEqual(len(self.source["exceptionRequiredSubjects"]), 8)
        self.assertFalse(self.source["claim"]["signedRunnerReverified"])
        self.assertFalse(self.source["claim"]["allSubjectsSourceAdmitted"])
        self.assertFalse(self.source["claim"]["mirroringAuthorized"])
        self.assertFalse(self.source["claim"]["campaignEvidence"])

    def test_wildcard_certificate_identity_is_rejected(self) -> None:
        changed = copy.deepcopy(self.source)
        changed["verifiedSubjects"][0]["certificateIdentity"] = ".*"
        with self.assertRaisesRegex(ValueError, "signed_invalid"):
            self.validate_source(changed)

    def test_signature_bundle_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.source)
        changed["verifiedSubjects"][0]["bundleDigest"] = f"sha256:{1:064x}"
        with self.assertRaisesRegex(ValueError, "signed_invalid"):
            self.validate_source(changed)

    def test_observation_window_cannot_be_extended(self) -> None:
        changed = copy.deepcopy(self.source)
        changed["observationWindow"]["validUntil"] = "2026-08-21T17:10:00Z"
        with self.assertRaisesRegex(ValueError, "window_invalid"):
            self.validate_source(changed)

    def test_unsigned_subject_cannot_self_approve_an_exception(self) -> None:
        changed = copy.deepcopy(self.source)
        exception = changed["exceptionRequiredSubjects"][0]["exception"]
        exception["status"] = "approved"
        exception["approvedByIdentityDigests"] = [f"sha256:{2:064x}"]
        with self.assertRaisesRegex(ValueError, "unsigned_invalid"):
            self.validate_source(changed)

    def test_source_inventory_must_cover_every_admission_subject(self) -> None:
        changed = copy.deepcopy(self.source)
        changed["exceptionRequiredSubjects"].pop()
        with self.assertRaisesRegex(ValueError, "unsigned_inventory_invalid"):
            self.validate_source(changed)

    def test_empty_mirror_intake_is_valid_and_blocked(self) -> None:
        self.assertEqual(
            self.validate_mirror(self.mirror), EXPECTED_MIRROR_INTAKE_DIGEST
        )
        self.assertFalse(self.mirror["claim"]["activationAuthorized"])
        self.assertFalse(self.mirror["claim"]["applied"])
        self.assertEqual(self.mirror["approvals"]["reviewerIdentityDigests"], [])

    def test_unattested_mirror_receipt_cannot_be_inserted(self) -> None:
        changed = copy.deepcopy(self.mirror)
        changed["subjects"][0]["artifactRegistry"] = {
            "reference": "europe-west1-docker.pkg.dev/example/orchestra/image",
            "digest": f"sha256:{3:064x}",
            "objectGeneration": "1",
            "actorIdentityDigest": f"sha256:{4:064x}",
            "receiptDigest": f"sha256:{5:064x}",
        }
        with self.assertRaisesRegex(ValueError, "subject_invalid"):
            self.validate_mirror(changed)

    def test_destination_cannot_claim_readiness_without_live_bindings(self) -> None:
        changed = copy.deepcopy(self.mirror)
        changed["destinations"]["harbor"]["ready"] = True
        with self.assertRaisesRegex(ValueError, "destinations_invalid"):
            self.validate_mirror(changed)

    def test_mirror_activation_claim_cannot_move_ahead(self) -> None:
        changed = copy.deepcopy(self.mirror)
        changed["claim"]["activationAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "claim_invalid"):
            self.validate_mirror(changed)

    def test_source_state_must_match_signature_observation(self) -> None:
        changed = copy.deepcopy(self.mirror)
        changed["subjects"][0]["sourceAdmissionState"] = "admitted"
        with self.assertRaisesRegex(ValueError, "subject_invalid"):
            self.validate_mirror(changed)


if __name__ == "__main__":
    unittest.main()
