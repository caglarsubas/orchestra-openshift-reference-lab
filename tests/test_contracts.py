from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.render_install_config import load_values, render
from scripts.validate_repository import (
    ROOT,
    canonical_digest,
    load_json,
    validate_lock,
    validate_lab_services,
    validate_prerequisites,
)


class ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = load_json(ROOT / "config" / "lab.lock.json")
        self.prerequisites = load_json(ROOT / "config" / "prerequisites.example.json")
        self.services = load_json(ROOT / "config" / "lab-services.lock.json")

    def test_locked_topology_is_valid_and_stable(self) -> None:
        validate_lock(self.lock)
        self.assertEqual(
            canonical_digest(self.lock),
            "sha256:40cc2969f5cce416a92dc5df47c556932f5e733639c38eef9393c068dffc9bc0",
        )

    def test_reference_claim_starts_false(self) -> None:
        self.assertEqual(
            self.lock["claim"],
            {
                "referenceProfileVerified": False,
                "customerCertified": False,
                "redHatCertified": False,
                "contractualSla": False,
            },
        )

    def test_lab_receiver_remains_source_only(self) -> None:
        validate_lab_services(self.services)
        receiver = self.services["services"][0]
        self.assertEqual(receiver["activation"], "source-only")
        self.assertIsNone(receiver["image"])
        self.assertFalse(receiver["gitOpsReferenced"])

    def test_synthetic_tenant_kit_remains_source_only(self) -> None:
        validate_lab_services(self.services)
        synthetic = self.services["services"][1]
        self.assertEqual(synthetic["id"], "synthetic-tenant-kit")
        self.assertEqual(synthetic["activation"], "source-only")
        self.assertIsNone(synthetic["image"])
        self.assertFalse(synthetic["gitOpsReferenced"])

    def test_lab_receiver_cannot_activate_without_publication(self) -> None:
        changed = copy.deepcopy(self.services)
        changed["services"][0]["activation"] = "active"
        changed["services"][0]["gitOpsReferenced"] = True
        with self.assertRaisesRegex(ValueError, "lab_service_activation_invalid"):
            validate_lab_services(changed)

    def test_topology_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["openshift"]["version"] = "4.20.28"
        with self.assertRaisesRegex(ValueError, "lab_lock_openshift_invalid"):
            validate_lock(changed)

    def test_missing_prerequisites_are_valid_but_not_ready(self) -> None:
        validate_prerequisites(self.prerequisites, require_ready=False)
        with self.assertRaisesRegex(ValueError, "prerequisite_gate_missing"):
            validate_prerequisites(self.prerequisites, require_ready=True)

    def test_bootstrap_stage_does_not_require_resources_created_by_bootstrap(
        self,
    ) -> None:
        changed = copy.deepcopy(self.prerequisites)
        verified_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        bootstrap_gates = (
            "redHatEntitlement",
            "openshiftPullSecret",
            "openshiftInstaller",
            "certificationRunner",
            "crossPlaneReleaseSet",
        )
        for index, name in enumerate(bootstrap_gates, start=1):
            changed["gates"][name].update(
                {
                    "status": "verified",
                    "evidenceDigest": f"sha256:{index:064x}",
                    "verifiedAt": verified_at,
                    "verifiedByIdentityDigest": f"sha256:{index + 30:064x}",
                }
            )
        validate_prerequisites(changed, require_ready=True, readiness_stage="bootstrap")
        with self.assertRaisesRegex(ValueError, "prerequisite_gate_missing"):
            validate_prerequisites(
                changed, require_ready=True, readiness_stage="foundation"
            )

    def test_verified_gate_requires_all_evidence(self) -> None:
        changed = copy.deepcopy(self.prerequisites)
        changed["gates"]["redHatEntitlement"]["status"] = "verified"
        with self.assertRaisesRegex(ValueError, "digest_invalid"):
            validate_prerequisites(changed, require_ready=False)

    def test_complete_independently_verified_gates_are_ready(self) -> None:
        changed = copy.deepcopy(self.prerequisites)
        verified_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for index, gate in enumerate(changed["gates"].values(), start=1):
            gate.update(
                {
                    "status": "verified",
                    "evidenceDigest": f"sha256:{index:064x}",
                    "verifiedAt": verified_at,
                    "verifiedByIdentityDigest": f"sha256:{index + 20:064x}",
                }
            )
        validate_prerequisites(changed, require_ready=True)

    def test_ready_gates_require_independent_verifiers(self) -> None:
        changed = copy.deepcopy(self.prerequisites)
        verified_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for index, gate in enumerate(changed["gates"].values(), start=1):
            gate.update(
                {
                    "status": "verified",
                    "evidenceDigest": f"sha256:{index:064x}",
                    "verifiedAt": verified_at,
                    "verifiedByIdentityDigest": f"sha256:{99:064x}",
                }
            )
        with self.assertRaisesRegex(ValueError, "verifiers_not_independent"):
            validate_prerequisites(changed, require_ready=True)

    def test_verified_gate_evidence_expires(self) -> None:
        changed = copy.deepcopy(self.prerequisites)
        gate = changed["gates"]["redHatEntitlement"]
        gate.update(
            {
                "status": "verified",
                "evidenceDigest": f"sha256:{1:064x}",
                "verifiedAt": "2026-01-01T00:00:00Z",
                "verifiedByIdentityDigest": f"sha256:{2:064x}",
            }
        )
        with self.assertRaisesRegex(ValueError, "gate_time_invalid"):
            validate_prerequisites(
                changed,
                require_ready=False,
                now=datetime(2026, 7, 21, tzinfo=timezone.utc),
            )

    def test_install_values_reject_secret_fields(self) -> None:
        values = {
            "OCP_MACHINE_CIDR": "10.40.0.0/20",
            "OCP_COMPUTE_SUBNET": "orchestra-ocp-compute",
            "OCP_CONTROL_PLANE_SUBNET": "orchestra-ocp-control",
            "OCP_NETWORK_NAME": "orchestra-ocp-network",
            "TARGET_PROJECT_ID": "orchestra-target-12345",
            "PULL_SECRET_JSON": "not-allowed",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "values.json"
            path.write_text(json.dumps(values), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "install_values_keys_invalid"):
                load_values(path)

    def test_installer_render_keeps_operator_secret_placeholders(self) -> None:
        template = (
            ROOT / "infra" / "openshift" / "install-config.template.yaml"
        ).read_text(encoding="utf-8")
        rendered = render(
            template,
            {
                "OCP_MACHINE_CIDR": "10.40.0.0/20",
                "OCP_COMPUTE_SUBNET": "orchestra-ocp-compute",
                "OCP_CONTROL_PLANE_SUBNET": "orchestra-ocp-control",
                "OCP_NETWORK_NAME": "orchestra-ocp-network",
                "TARGET_PROJECT_ID": "orchestra-target-12345",
            },
        )
        self.assertIn("publish: Internal", rendered)
        self.assertIn("${PULL_SECRET_JSON}", rendered)
        self.assertIn("${SSH_PUBLIC_KEY}", rendered)
        self.assertNotIn("${TARGET_PROJECT_ID}", rendered)


if __name__ == "__main__":
    unittest.main()
