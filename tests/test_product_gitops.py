from __future__ import annotations

import copy
import unittest

from scripts.validate_product_gitops import (
    EXPECTED_RENDERED_COUNTS,
    PRODUCT_ROOT,
    validate_applications,
    validate_rendered,
)
from scripts.validate_repository import ROOT, load_json


class ProductGitOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.release_set = load_json(
            ROOT / "config" / "cross-plane-release-set.lock.json"
        )

    def test_applications_bind_the_frozen_release_set(self) -> None:
        self.assertEqual(
            validate_applications(self.release_set),
            "sha256:7be0106ffe6ff7c79a4d4cc5dadd77f74201dcc7913e12711a05e6ea27dfc635",
        )

    def test_changed_release_digest_is_rejected(self) -> None:
        changed = copy.deepcopy(self.release_set)
        changed["planes"][1]["deploymentImage"] = changed["planes"][1][
            "deploymentImage"
        ].replace("09675478", "19675478")
        changed["planes"][1]["subjects"][0]["ref"] = changed["planes"][1][
            "deploymentImage"
        ]
        with self.assertRaisesRegex(ValueError, "application_contract_invalid"):
            validate_applications(changed)

    def test_platform_keeps_active_execution_disabled(self) -> None:
        platform = load_json(PRODUCT_ROOT / "platform-application.json")
        values = platform["spec"]["source"]["helm"]["valuesObject"]
        self.assertEqual(values["agentQuerying"], {"enabled": False})
        self.assertEqual(values["toolExecution"], {"enabled": False})
        self.assertEqual(values["releaseValidation"], {"enabled": False})

    def test_rendered_secret_objects_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "secret_object_forbidden"):
            validate_rendered("apiVersion: v1\nkind: Secret\nmetadata:\n  name: no\n")

    def test_expected_product_inventory_is_explicit(self) -> None:
        self.assertEqual(
            EXPECTED_RENDERED_COUNTS,
            {
                "AppProject": 1,
                "Application": 3,
                "Certificate": 2,
                "ConfigMap": 3,
                "ExternalSecret": 13,
                "NetworkPolicy": 1,
                "ServiceAccount": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()
