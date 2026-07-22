from __future__ import annotations

import copy
import unittest

from scripts.validate_product_gitops import (
    DEPENDENCY_ADMISSION_DIGEST,
    DEPENDENCY_BOM_DIGEST,
    DEPENDENCY_SOURCE_VERIFICATION_DIGEST,
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
            "sha256:d4b4ef7e33a6918d8a31d1f62cf704ae4bd8d4973e406f5a8a6d7ef0c1786428",
        )

    def test_applications_bind_the_dependency_bom(self) -> None:
        for filename in (
            "platform-application.json",
            "runtime-application.json",
            "model-application.json",
        ):
            application = load_json(PRODUCT_ROOT / filename)
            self.assertEqual(
                application["metadata"]["annotations"][
                    "orchestra.prometa.ai/dependency-bom-digest"
                ],
                DEPENDENCY_BOM_DIGEST,
            )

    def test_applications_bind_the_blocked_dependency_admission(self) -> None:
        for filename in (
            "platform-application.json",
            "runtime-application.json",
            "model-application.json",
        ):
            application = load_json(PRODUCT_ROOT / filename)
            self.assertEqual(
                application["metadata"]["annotations"][
                    "orchestra.prometa.ai/dependency-admission-digest"
                ],
                DEPENDENCY_ADMISSION_DIGEST,
            )

    def test_applications_bind_the_source_verification_observation(self) -> None:
        for filename in (
            "platform-application.json",
            "runtime-application.json",
            "model-application.json",
        ):
            application = load_json(PRODUCT_ROOT / filename)
            self.assertEqual(
                application["metadata"]["annotations"][
                    "orchestra.prometa.ai/dependency-source-verification-digest"
                ],
                DEPENDENCY_SOURCE_VERIFICATION_DIGEST,
            )

    def test_product_project_has_an_enforced_continuous_deny_window(self) -> None:
        project = load_json(PRODUCT_ROOT / "project.json")
        self.assertEqual(
            project["spec"]["syncWindows"],
            [
                {
                    "kind": "deny",
                    "schedule": "0 0 * * *",
                    "duration": "24h",
                    "applications": ["*"],
                    "manualSync": False,
                }
            ],
        )

    def test_changed_release_digest_is_rejected(self) -> None:
        changed = copy.deepcopy(self.release_set)
        changed["planes"][1]["deploymentImage"] = changed["planes"][1][
            "deploymentImage"
        ].replace("09675478", "19675478")
        changed["planes"][1]["subjects"][0]["ref"] = changed["planes"][1][
            "deploymentImage"
        ]
        with self.assertRaisesRegex(ValueError, "project_contract_invalid"):
            validate_applications(changed)

    def test_platform_keeps_active_execution_disabled(self) -> None:
        platform = load_json(PRODUCT_ROOT / "platform-application.json")
        values = platform["spec"]["source"]["helm"]["valuesObject"]
        self.assertEqual(values["agentQuerying"], {"enabled": False})
        self.assertEqual(values["toolExecution"], {"enabled": False})
        self.assertEqual(values["releaseValidation"], {"enabled": False})

    def test_platform_uses_service_ca_backed_reencrypt_tls(self) -> None:
        platform = load_json(PRODUCT_ROOT / "platform-application.json")
        values = platform["spec"]["source"]["helm"]["valuesObject"]
        self.assertEqual(
            values["backendTls"],
            {
                "enabled": True,
                "port": 3443,
                "existingSecret": "orchestra-platform-backend-tls",
                "certificateKey": "tls.crt",
                "privateKeyKey": "tls.key",
                "rolloutId": "release-set-d4b4ef7e",
                "serverName": "orchestra-platform.orchestra-platform.svc",
                "serviceServingCertificate": {
                    "enabled": True,
                    "caBundleConfigMapName": "orchestra-platform-service-ca",
                },
            },
        )
        self.assertEqual(
            values["route"]["tls"],
            {
                "termination": "reencrypt",
                "insecureEdgeTerminationPolicy": "Redirect",
            },
        )

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
