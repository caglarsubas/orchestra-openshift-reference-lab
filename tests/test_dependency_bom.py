from __future__ import annotations

import copy
import unittest

from scripts.validate_dependency_bom import (
    DEPENDENCY_BOM,
    EXPECTED_BOM_DIGEST,
    validate_dependency_bom,
)
from scripts.validate_repository import ROOT, load_json


class DependencyBomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bom = load_json(DEPENDENCY_BOM)
        self.topology = load_json(ROOT / "config" / "lab.lock.json")

    def test_locked_bom_is_valid_and_non_activatable(self) -> None:
        self.assertEqual(
            validate_dependency_bom(self.bom, self.topology),
            EXPECTED_BOM_DIGEST,
        )
        self.assertEqual(self.bom["admission"]["activation"], "blocked")
        self.assertTrue(
            all(
                service["activationState"] == "blocked"
                for service in self.bom["serviceContracts"]
            )
        )

    def test_mutable_chart_version_is_rejected(self) -> None:
        changed = copy.deepcopy(self.bom)
        changed["chartPackages"][0]["chartVersion"] = "latest"
        with self.assertRaisesRegex(ValueError, "chart_lock_invalid"):
            validate_dependency_bom(changed, self.topology)

    def test_topology_service_is_not_optional(self) -> None:
        changed = copy.deepcopy(self.bom)
        changed["serviceContracts"] = [
            item for item in changed["serviceContracts"] if item["id"] != "jetstream"
        ]
        with self.assertRaisesRegex(ValueError, "service_inventory_invalid"):
            validate_dependency_bom(changed, self.topology)

    def test_sentinel_gap_cannot_be_silently_admitted(self) -> None:
        changed = copy.deepcopy(self.bom)
        valkey = next(
            item for item in changed["serviceContracts"] if item["id"] == "valkey"
        )
        valkey["activationState"] = "ready"
        valkey["reasonCodes"] = ["IMAGE_INVENTORY_MISSING"]
        with self.assertRaisesRegex(ValueError, "service_contract_invalid"):
            validate_dependency_bom(changed, self.topology)

    def test_claim_cannot_imply_live_execution(self) -> None:
        changed = copy.deepcopy(self.bom)
        changed["claim"]["applied"] = True
        with self.assertRaisesRegex(ValueError, "identity_invalid"):
            validate_dependency_bom(changed, self.topology)


if __name__ == "__main__":
    unittest.main()
