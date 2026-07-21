from __future__ import annotations

import copy
import unittest

from scripts.validate_dependency_gitops import (
    EXPECTED_RENDERED_COUNTS,
    GITOPS_ROOT,
    validate_project,
    validate_rendered,
)
from scripts.validate_repository import load_json


class DependencyGitOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project = load_json(GITOPS_ROOT / "project.json")

    def test_project_is_permanently_denied_until_admitted_overlay(self) -> None:
        validate_project(self.project)
        self.assertEqual(
            self.project["metadata"]["annotations"][
                "orchestra.prometa.ai/activation"
            ],
            "blocked",
        )
        self.assertFalse(self.project["spec"]["syncWindows"][0]["manualSync"])

    def test_sync_window_cannot_be_relaxed_in_foundation(self) -> None:
        changed = copy.deepcopy(self.project)
        changed["spec"]["syncWindows"][0]["manualSync"] = True
        with self.assertRaisesRegex(ValueError, "project_contract_invalid"):
            validate_project(changed)

    def test_application_is_forbidden_in_non_admitted_overlay(self) -> None:
        with self.assertRaisesRegex(ValueError, "forbidden_object:Application"):
            validate_rendered(
                "apiVersion: argoproj.io/v1alpha1\n"
                "kind: Application\nmetadata:\n  name: unsafe\n"
            )

    def test_rendered_inventory_is_explicit(self) -> None:
        self.assertEqual(
            EXPECTED_RENDERED_COUNTS,
            {"AppProject": 1, "Namespace": 12, "NetworkPolicy": 12},
        )


if __name__ == "__main__":
    unittest.main()
