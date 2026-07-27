from __future__ import annotations

import copy
import json
import unittest

from scripts.validate_repository import load_json
from scripts.validate_sno_trial_dependency_runtime_contracts import (
    ACTIVATION_REASONS,
    CANDIDATE_PATH,
    CLAIMS,
    CONTRACT_PATH,
    CONTROLS,
    DEPENDENCY_PATH,
    OPERATOR_INPUT_PATH,
    RUNTIME_DEFAULTS,
    ROOT,
    SERVICE_IDS,
    unsigned_digest,
    validate_contract_set,
)


class SnoTrialDependencyRuntimeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract_set = load_json(CONTRACT_PATH)
        self.candidate = load_json(CANDIDATE_PATH)
        self.dependency_admission = load_json(DEPENDENCY_PATH)
        self.operator_inputs = load_json(OPERATOR_INPUT_PATH)

    def validate(self, value: dict[str, object]) -> str:
        return validate_contract_set(
            value,
            self.candidate,
            self.dependency_admission,
            self.operator_inputs,
        )

    def contract(self, value: dict[str, object], identifier: str) -> dict[str, object]:
        return next(item for item in value["contracts"] if item["id"] == identifier)

    def test_contract_set_is_source_only_and_digest_bound(self) -> None:
        digest = self.validate(self.contract_set)
        self.assertEqual(digest, unsigned_digest(self.contract_set))
        self.assertEqual(
            [item["id"] for item in self.contract_set["contracts"]],
            list(SERVICE_IDS),
        )
        self.assertEqual(self.contract_set["runtimeDefaults"], RUNTIME_DEFAULTS)
        self.assertEqual(
            self.contract_set["activation"],
            {"state": "blocked", "reasonCodes": ACTIVATION_REASONS},
        )
        self.assertEqual(self.contract_set["controls"], CONTROLS)
        self.assertEqual(self.contract_set["claims"], CLAIMS)
        self.assertFalse(self.contract_set["controls"]["manifestsEmitted"])
        self.assertFalse(self.contract_set["controls"]["deploymentAuthorized"])

    def test_resources_and_artifacts_are_derived_from_candidate(self) -> None:
        workloads = {item["id"]: item for item in self.candidate["workloads"]}
        for contract in self.contract_set["contracts"]:
            workload = workloads[contract["id"]]
            self.assertEqual(contract["resources"], workload["resources"])
            self.assertEqual(contract["artifact"], workload["artifact"])
            self.assertEqual(
                contract["persistence"]["sizeGiB"],
                workload["persistentVolumeGiB"],
            )

        unresolved = {
            item["id"]
            for item in self.contract_set["contracts"]
            if item["artifact"]["admissionState"] == "unresolved"
        }
        self.assertEqual(unresolved, {"valkey", "model-backend"})

    def test_security_transport_and_network_defaults_fail_closed(self) -> None:
        defaults = self.contract_set["runtimeDefaults"]
        self.assertTrue(defaults["security"]["arbitraryUidRequired"])
        self.assertIsNone(defaults["security"]["fixedUid"])
        self.assertTrue(defaults["security"]["readOnlyRootFilesystem"])
        self.assertFalse(defaults["serviceAccountTokenAutomount"])
        for contract in self.contract_set["contracts"]:
            self.assertTrue(contract["network"]["defaultDeny"])
            self.assertTrue(contract["protocol"]["tlsRequired"])
            self.assertTrue(contract["protocol"]["authenticationRequired"])
            self.assertFalse(contract["protocol"]["referencesResolved"])
            self.assertFalse(contract["behavior"]["runtimeDownloadAllowed"])

    def test_security_or_protocol_downgrade_is_rejected(self) -> None:
        changes = [
            ("runtimeDefaults", "security", "readOnlyRootFilesystem", False),
            ("runtimeDefaults", None, "serviceAccountTokenAutomount", True),
        ]
        for section, subsection, field, replacement in changes:
            changed = copy.deepcopy(self.contract_set)
            target = changed[section]
            if subsection is not None:
                target = target[subsection]
            target[field] = replacement
            changed["contractSetDigest"] = unsigned_digest(changed)
            with self.assertRaisesRegex(ValueError, "defaults_invalid"):
                self.validate(changed)

        changed = copy.deepcopy(self.contract_set)
        self.contract(changed, "valkey")["protocol"]["tlsRequired"] = False
        changed["contractSetDigest"] = unsigned_digest(changed)
        with self.assertRaisesRegex(ValueError, "contract_invalid:valkey"):
            self.validate(changed)

    def test_resource_network_and_durability_drift_is_rejected(self) -> None:
        changes = [
            ("postgresql", "resources", "requests", "memoryMiB", 512),
            (
                "clickhouse",
                "network",
                None,
                "allowedClients",
                ["platform", "runtime-host"],
            ),
            ("jetstream", "behavior", None, "durability", "memory-only"),
            ("model-backend", "behavior", None, "runtimeDownloadAllowed", True),
        ]
        for identifier, section, subsection, field, replacement in changes:
            with self.subTest(identifier=identifier, field=field):
                changed = copy.deepcopy(self.contract_set)
                target = self.contract(changed, identifier)[section]
                if subsection is not None:
                    target = target[subsection]
                target[field] = replacement
                changed["contractSetDigest"] = unsigned_digest(changed)
                with self.assertRaisesRegex(
                    ValueError, f"contract_invalid:{identifier}"
                ):
                    self.validate(changed)

    def test_binding_and_digest_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.contract_set)
        changed["bindings"]["workloadCandidateDigest"] = f"sha256:{1:064x}"
        changed["contractSetDigest"] = unsigned_digest(changed)
        with self.assertRaisesRegex(ValueError, "bindings_invalid"):
            self.validate(changed)

        changed = copy.deepcopy(self.contract_set)
        changed["contractSetDigest"] = f"sha256:{2:064x}"
        with self.assertRaisesRegex(ValueError, "digest_invalid"):
            self.validate(changed)

    def test_inline_deployment_and_secret_material_are_rejected(self) -> None:
        changed = copy.deepcopy(self.contract_set)
        self.contract(changed, "valkey")["manifest"] = {"apiVersion": "apps/v1"}
        changed["contractSetDigest"] = unsigned_digest(changed)
        with self.assertRaisesRegex(ValueError, "inline_deployment_forbidden"):
            self.validate(changed)

        changed = copy.deepcopy(self.contract_set)
        self.contract(changed, "postgresql")["secretValue"] = "not-allowed"
        changed["contractSetDigest"] = unsigned_digest(changed)
        with self.assertRaisesRegex(ValueError, "inline_deployment_forbidden"):
            self.validate(changed)

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "schemas"
                / "sno-trial-dependency-runtime-contract-set-v1.schema.json"
            ).read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        for name in (
            "bindings",
            "security",
            "runtimeDefaults",
            "quantities",
            "resources",
            "artifact",
            "persistence",
            "network",
            "protocol",
            "behavior",
            "contractBase",
            "activation",
            "controls",
            "claims",
        ):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
