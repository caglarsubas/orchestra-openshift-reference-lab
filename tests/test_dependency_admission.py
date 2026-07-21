from __future__ import annotations

import copy
import unittest

from scripts.validate_dependency_admission import (
    ADMISSION_LOCK,
    EXPECTED_ADMISSION_DIGEST,
    validate_admission,
)
from scripts.validate_repository import ROOT, load_json


class DependencyAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admission = load_json(ADMISSION_LOCK)
        self.dependency_bom = load_json(ROOT / "config" / "dependency-bom.lock.json")
        self.topology = load_json(ROOT / "config" / "lab.lock.json")

    def validate(self, value: dict) -> str:
        return validate_admission(value, self.dependency_bom, self.topology)

    def service(self, value: dict, service_id: str) -> dict:
        return next(
            service
            for service in value["serviceContracts"]
            if service["id"] == service_id
        )

    def test_source_resolved_contract_is_valid_but_not_admitted(self) -> None:
        self.assertEqual(self.validate(self.admission), EXPECTED_ADMISSION_DIGEST)
        self.assertTrue(self.admission["claim"]["sourceImagesResolved"])
        self.assertTrue(self.admission["claim"]["serviceContractsDeclared"])
        for state in (
            "upstreamSignaturesVerified",
            "mirrored",
            "labSigned",
            "serverDryRunPassed",
            "twoPersonApproved",
            "activated",
            "applied",
            "liveTested",
            "campaignEvidence",
        ):
            self.assertFalse(self.admission["claim"][state])

    def test_mutable_image_tag_is_rejected(self) -> None:
        changed = copy.deepcopy(self.admission)
        changed["images"][0]["source"]["reference"] = (
            "ghcr.io/cloudnative-pg/cloudnative-pg:latest"
        )
        with self.assertRaisesRegex(ValueError, "source_lock_invalid"):
            self.validate(changed)

    def test_platform_digest_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.admission)
        changed["images"][0]["source"]["platformDigest"] = f"sha256:{1:064x}"
        with self.assertRaisesRegex(ValueError, "source_lock_invalid"):
            self.validate(changed)

    def test_unattested_destination_mirror_cannot_be_added(self) -> None:
        changed = copy.deepcopy(self.admission)
        changed["images"][0]["mirrors"]["artifactRegistry"] = {
            "reference": "example.invalid/orchestra/cloudnative-pg",
            "digest": f"sha256:{2:064x}",
        }
        with self.assertRaisesRegex(ValueError, "mirror_must_be_empty"):
            self.validate(changed)

    def test_activation_claim_cannot_move_ahead_of_evidence(self) -> None:
        changed = copy.deepcopy(self.admission)
        changed["claim"]["activated"] = True
        with self.assertRaisesRegex(ValueError, "identity_invalid"):
            self.validate(changed)

    def test_service_cannot_reference_an_uninventoried_image(self) -> None:
        changed = copy.deepcopy(self.admission)
        self.service(changed, "jetstream")["images"].append("mutable-helper")
        with self.assertRaisesRegex(ValueError, "service_contract_invalid"):
            self.validate(changed)

    def test_external_secrets_is_owned_by_openshift(self) -> None:
        external_secrets = self.service(self.admission, "external-secrets")
        self.assertEqual(external_secrets["targetCluster"], "openshift")
        self.assertEqual(external_secrets["namespace"], "orchestra-external-secrets")
        changed = copy.deepcopy(self.admission)
        self.service(changed, "external-secrets")["targetCluster"] = "services-gke"
        with self.assertRaisesRegex(ValueError, "service_contract_invalid"):
            self.validate(changed)

    def test_clickhouse_backup_gap_cannot_be_hidden(self) -> None:
        changed = copy.deepcopy(self.admission)
        clickhouse = self.service(changed, "clickhouse-and-keeper")
        clickhouse["backup"]["provider"] = "claimed-complete"
        with self.assertRaisesRegex(ValueError, "clickhouse_backup_gap_hidden"):
            self.validate(changed)

    def test_topology_counts_are_bound(self) -> None:
        changed = copy.deepcopy(self.admission)
        self.service(changed, "postgresql-platform")["availability"]["instances"] = 2
        with self.assertRaisesRegex(ValueError, "topology_mismatch"):
            self.validate(changed)

    def test_barman_manifest_digest_is_immutable(self) -> None:
        changed = copy.deepcopy(self.admission)
        changed["sourceArtifacts"][0]["sourceDigest"] = f"sha256:{3:064x}"
        with self.assertRaisesRegex(ValueError, "source_artifact_invalid"):
            self.validate(changed)


if __name__ == "__main__":
    unittest.main()
