import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class FoundationCostControlsTest(unittest.TestCase):
    def test_paused_mode_is_the_default_and_bounds_runtime_costs(self) -> None:
        variables = (ROOT / "infra/terraform/foundation/variables.tf").read_text()
        foundation = (ROOT / "infra/terraform/foundation/main.tf").read_text()

        self.assertIn('variable "reference_lab_active"', variables)
        self.assertRegex(
            variables,
            r'variable "reference_lab_active" \{[^}]*default\s+=\s+false',
        )
        self.assertIn(
            "node_count     = var.reference_lab_active ? 1 : 0", foundation
        )
        self.assertEqual(
            foundation.count(
                'desired_status            = var.reference_lab_active ? "RUNNING" : "TERMINATED"'
            ),
            2,
        )
        self.assertEqual(
            foundation.count(
                'enable_components = var.reference_lab_active ?'
            ),
            2,
        )
        self.assertIn("enabled = var.reference_lab_active", foundation)
        self.assertIn(
            "condition     = !var.certification_mode || var.reference_lab_active",
            foundation,
        )

    def test_protected_workflows_share_the_same_runtime_mode(self) -> None:
        expected = (
            "TF_VAR_reference_lab_active: "
            "${{ vars.GCP_REFERENCE_LAB_ACTIVE || 'false' }}"
        )
        for workflow_name in (
            "foundation-plan.yml",
            "foundation-apply.yml",
            "foundation-observation.yml",
        ):
            workflow = (ROOT / ".github/workflows" / workflow_name).read_text()
            self.assertIn(expected, workflow, workflow_name)


if __name__ == "__main__":
    unittest.main()
