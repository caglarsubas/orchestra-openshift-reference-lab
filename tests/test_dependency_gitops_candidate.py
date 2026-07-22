from __future__ import annotations

import copy
import unittest

from scripts.validate_dependency_gitops_candidate import (
    ACTIVE_KUSTOMIZATION,
    CANDIDATE_LOCK,
    CANDIDATE_ROOT,
    DEPENDENCY_ADMISSION_LOCK,
    DEPENDENCY_BOM_LOCK,
    EXPECTED_CANDIDATE_DIGEST,
    MIRROR_INTAKE,
    RELEASE_SET_LOCK,
    RISK_POLICY_LOCK,
    SOURCE_VERIFICATION_LOCK,
    TOPOLOGY_LOCK,
    repo_path,
    validate_application_values,
    validate_candidate,
    validate_candidate_tree,
    validate_service_overlays,
)
from scripts.validate_repository import load_json


class DependencyGitOpsCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = load_json(CANDIDATE_LOCK)
        self.topology = load_json(TOPOLOGY_LOCK)
        self.release_set = load_json(RELEASE_SET_LOCK)
        self.bom = load_json(DEPENDENCY_BOM_LOCK)
        self.admission = load_json(DEPENDENCY_ADMISSION_LOCK)
        self.source_verification = load_json(SOURCE_VERIFICATION_LOCK)
        self.risk_policy = load_json(RISK_POLICY_LOCK)
        self.mirror_intake = load_json(MIRROR_INTAKE)
        self.images = {item["id"]: item for item in self.admission["images"]}
        self.admission_services = {
            item["id"]: item for item in self.admission["serviceContracts"]
        }

    def validate(self, value: dict) -> str:
        return validate_candidate(
            value,
            self.topology,
            self.release_set,
            self.bom,
            self.admission,
            self.source_verification,
            self.risk_policy,
            self.mirror_intake,
        )

    def application(self, value: dict, application_id: str) -> dict:
        return next(
            item for item in value["applications"] if item["id"] == application_id
        )

    def test_checked_in_candidate_is_digest_bound_and_inert(self) -> None:
        self.assertEqual(self.validate(self.candidate), EXPECTED_CANDIDATE_DIGEST)
        self.assertFalse(self.candidate["renderPolicy"]["applicationEmissionAllowed"])
        self.assertFalse(self.candidate["renderPolicy"]["serverDryRunAllowed"])
        self.assertFalse(self.candidate["claim"]["applicationsEmitted"])
        self.assertFalse(self.candidate["claim"]["campaignEvidence"])

    def test_values_digest_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.candidate)
        self.application(changed, "vault")["values"]["canonicalDigest"] = (
            f"sha256:{1:064x}"
        )
        with self.assertRaisesRegex(ValueError, "values_lock_invalid"):
            self.validate(changed)

    def test_destination_reference_cannot_be_predeclared(self) -> None:
        changed = copy.deepcopy(self.candidate)
        self.application(changed, "jetstream")["images"][0]["destinationReference"] = (
            "registry.example.invalid/nats@sha256:blocked"
        )
        with self.assertRaisesRegex(ValueError, "image_lock_invalid"):
            self.validate(changed)

    def test_application_emission_and_activation_cannot_be_enabled(self) -> None:
        changed = copy.deepcopy(self.candidate)
        changed["renderPolicy"]["applicationEmissionAllowed"] = True
        changed["claim"]["applicationsEmitted"] = True
        changed["claim"]["activated"] = True
        with self.assertRaisesRegex(ValueError, "identity_invalid"):
            self.validate(changed)

    def test_values_path_cannot_escape_candidate_root(self) -> None:
        with self.assertRaisesRegex(ValueError, "path_escape"):
            repo_path("config/dependency-admission.lock.json")

    def test_mutable_image_projection_is_rejected(self) -> None:
        values = load_json(CANDIDATE_ROOT / "jetstream.values.json")
        changed = copy.deepcopy(values)
        changed["container"]["image"]["tag"] = "latest"
        with self.assertRaisesRegex(ValueError, "values_image_invalid"):
            validate_application_values("jetstream", changed, self.images)

    def test_clickhouse_crd_hook_cannot_reintroduce_mutable_helper(self) -> None:
        values = load_json(CANDIDATE_ROOT / "clickhouse-operator.values.json")
        changed = copy.deepcopy(values)
        changed["crdHook"]["enabled"] = True
        with self.assertRaisesRegex(ValueError, "clickhouse_values_invalid"):
            validate_application_values("clickhouse-operator", changed, self.images)

    def test_vault_does_not_override_chart_provided_raft_node_id(self) -> None:
        values = load_json(CANDIDATE_ROOT / "vault.values.json")
        changed = copy.deepcopy(values)
        changed["server"]["ha"]["raft"]["config"] += (
            '\nnode_id = "VAULT_RAFT_NODE_ID"\n'
        )
        with self.assertRaisesRegex(ValueError, "vault_values_invalid"):
            validate_application_values("vault", changed, self.images)

    def test_vault_container_hardening_cannot_be_relaxed(self) -> None:
        values = load_json(CANDIDATE_ROOT / "vault.values.json")
        changed = copy.deepcopy(values)
        changed["server"]["statefulSet"]["securityContext"]["container"][
            "readOnlyRootFilesystem"
        ] = False
        with self.assertRaisesRegex(ValueError, "vault_values_invalid"):
            validate_application_values("vault", changed, self.images)

    def test_external_secrets_cannot_generate_webhook_credentials(self) -> None:
        values = load_json(CANDIDATE_ROOT / "external-secrets.values.json")
        changed = copy.deepcopy(values)
        changed["webhook"]["certManager"]["enabled"] = False
        changed["certController"]["create"] = True
        with self.assertRaisesRegex(ValueError, "external_secrets_values_invalid"):
            validate_application_values("external-secrets", changed, self.images)

    def test_service_overlay_inventory_cannot_omit_a_service(self) -> None:
        overlays = load_json(CANDIDATE_ROOT / "service-overlays.json")
        changed = copy.deepcopy(overlays)
        changed["overlays"] = changed["overlays"][:-1]
        with self.assertRaisesRegex(ValueError, "service_overlay_inventory_invalid"):
            validate_service_overlays(changed, self.admission_services)

    def test_unresolved_service_inventory_is_fail_closed(self) -> None:
        changed = copy.deepcopy(self.candidate)
        changed["unresolvedServices"] = changed["unresolvedServices"][:-1]
        with self.assertRaisesRegex(ValueError, "unresolved_inventory_invalid"):
            self.validate(changed)

    def test_active_kustomization_cannot_reference_candidate(self) -> None:
        unsafe = ACTIVE_KUSTOMIZATION.read_text(encoding="utf-8") + (
            "\n  - ../candidates/reference-lab\n"
        )
        with self.assertRaisesRegex(ValueError, "active_reference_forbidden"):
            validate_candidate_tree(active_kustomization_content=unsafe)


if __name__ == "__main__":
    unittest.main()
