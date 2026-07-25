from __future__ import annotations

import copy
import json
import unittest

from scripts.validate_sno_trial_profile import (
    PRODUCTION_PROFILE,
    TRIAL_PROFILE,
    load_json,
    validate_production_isolation,
)
from scripts.validate_sno_trial_workload_candidate import (
    ACTIVATION_REASONS,
    CANDIDATE_PATH,
    CLAIMS,
    CONTROLS,
    DEPENDENCY_PATH,
    LAB_SERVICES_PATH,
    RELEASE_SET_PATH,
    RESOURCE_PLAN,
    ROOT,
    TOOLCHAIN_PATH,
    validate_candidate,
    validate_resources,
)


class SnoTrialWorkloadCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = load_json(CANDIDATE_PATH)
        self.trial = load_json(TRIAL_PROFILE)
        self.production = load_json(PRODUCTION_PROFILE)
        self.toolchain = load_json(TOOLCHAIN_PATH)
        self.release_set = load_json(RELEASE_SET_PATH)
        self.admission = load_json(DEPENDENCY_PATH)
        self.lab_services = load_json(LAB_SERVICES_PATH)

    def validate(self, candidate: dict[str, object] | None = None) -> str:
        return validate_candidate(
            candidate or self.candidate,
            self.trial,
            self.production,
            self.toolchain,
            self.release_set,
            self.admission,
            self.lab_services,
        )

    def workload(
        self, candidate: dict[str, object], identifier: str
    ) -> dict[str, object]:
        workloads = candidate["workloads"]
        self.assertIsInstance(workloads, list)
        matches = [
            item
            for item in workloads
            if isinstance(item, dict) and item.get("id") == identifier
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_candidate_is_valid_inert_and_capacity_only(self) -> None:
        digest = self.validate()
        self.assertEqual(digest, self.candidate["candidateDigest"])
        self.assertEqual(len(self.candidate["workloads"]), len(RESOURCE_PLAN))
        self.assertEqual(
            self.candidate["activation"],
            {"state": "blocked", "reasonCodes": ACTIVATION_REASONS},
        )
        self.assertEqual(self.candidate["controls"], CONTROLS)
        self.assertEqual(self.candidate["claims"], CLAIMS)
        self.assertFalse(self.candidate["controls"]["manifestsEmitted"])
        self.assertFalse(self.candidate["controls"]["cloudMutationAuthorized"])
        self.assertFalse(self.candidate["controls"]["campaignEligible"])
        validate_production_isolation()

    def test_envelope_preserves_system_reserve_and_positive_headroom(self) -> None:
        envelope = self.candidate["nodeEnvelope"]
        self.assertEqual(
            envelope["workloadRequestBudget"],
            {"cpuMillicores": 5000, "memoryMiB": 20480},
        )
        self.assertEqual(
            envelope["steadyRequests"],
            {"cpuMillicores": 3400, "memoryMiB": 14720},
        )
        self.assertEqual(
            envelope["peakRequests"],
            {"cpuMillicores": 3650, "memoryMiB": 14976},
        )
        self.assertEqual(
            envelope["requestHeadroom"],
            {"cpuMillicores": 1350, "memoryMiB": 5504},
        )
        self.assertEqual(envelope["persistentVolumeGiB"], 48)

    def test_request_overcommit_is_rejected_before_activation(self) -> None:
        changed = copy.deepcopy(self.candidate)
        backend = self.workload(changed, "model-backend")
        backend["resources"]["requests"]["cpuMillicores"] = 4000
        backend["resources"]["limits"]["cpuMillicores"] = 4500
        with self.assertRaisesRegex(
            ValueError, "sno_candidate_request_budget_exceeded"
        ):
            validate_resources(changed["workloads"], changed["nodeEnvelope"])

    def test_aggregate_limits_cannot_exceed_physical_node(self) -> None:
        changed = copy.deepcopy(self.candidate)
        platform = self.workload(changed, "platform")
        platform["resources"]["limits"]["cpuMillicores"] = 9000
        with self.assertRaisesRegex(
            ValueError, "sno_candidate_physical_limit_exceeded"
        ):
            validate_resources(changed["workloads"], changed["nodeEnvelope"])

    def test_resource_or_replica_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.candidate)
        self.workload(changed, "platform")["replicas"] = 2
        with self.assertRaisesRegex(
            ValueError, "sno_candidate_workload_contract_invalid:platform"
        ):
            self.validate(changed)

        changed = copy.deepcopy(self.candidate)
        self.workload(changed, "runtime-host")["persistentVolumeGiB"] = 1
        with self.assertRaisesRegex(
            ValueError, "sno_candidate_workload_contract_invalid:runtime-host"
        ):
            self.validate(changed)

    def test_artifacts_remain_source_bound_and_two_are_unresolved(self) -> None:
        artifacts = {
            item["id"]: item["artifact"] for item in self.candidate["workloads"]
        }
        unresolved = {
            identifier
            for identifier, artifact in artifacts.items()
            if artifact["admissionState"] == "unresolved"
        }
        self.assertEqual(unresolved, {"valkey", "model-backend"})
        self.assertTrue(
            all(
                artifact["usableForCapacityOnly"] is True
                for artifact in artifacts.values()
            )
        )

        changed = copy.deepcopy(self.candidate)
        self.workload(changed, "valkey")["artifact"] = copy.deepcopy(
            artifacts["jetstream"]
        )
        with self.assertRaisesRegex(
            ValueError, "sno_candidate_artifact_invalid:valkey"
        ):
            self.validate(changed)

    def test_release_dependency_and_publication_drift_is_rejected(self) -> None:
        for identifier in ("platform", "postgresql", "synthetic-tenant-kit"):
            with self.subTest(identifier=identifier):
                changed = copy.deepcopy(self.candidate)
                artifact = self.workload(changed, identifier)["artifact"]
                artifact["platformDigest"] = f"sha256:{9:064x}"
                with self.assertRaisesRegex(
                    ValueError,
                    f"sno_candidate_artifact_invalid:{identifier}",
                ):
                    self.validate(changed)

    def test_activation_controls_and_claims_cannot_be_escalated(self) -> None:
        changed = copy.deepcopy(self.candidate)
        changed["activation"]["state"] = "ready"
        with self.assertRaisesRegex(ValueError, "sno_candidate_activation_invalid"):
            self.validate(changed)

        changed = copy.deepcopy(self.candidate)
        changed["controls"]["activationAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "sno_candidate_controls_invalid"):
            self.validate(changed)

        changed = copy.deepcopy(self.candidate)
        changed["claims"]["referenceProfileVerified"] = True
        with self.assertRaisesRegex(ValueError, "sno_candidate_claims_invalid"):
            self.validate(changed)

    def test_inline_deployment_and_production_profile_references_are_rejected(
        self,
    ) -> None:
        changed = copy.deepcopy(self.candidate)
        self.workload(changed, "platform")["mode"]["manifest"] = {}
        with self.assertRaisesRegex(
            ValueError, "sno_candidate_inline_deployment_forbidden:manifest"
        ):
            self.validate(changed)

        changed = copy.deepcopy(self.candidate)
        self.workload(changed, "platform")["artifact"]["sourceId"] = (
            "orchestra-ocp-4.20-amd64-v1"
        )
        with self.assertRaisesRegex(
            ValueError, "sno_candidate_production_profile_reference_forbidden"
        ):
            self.validate(changed)

    def test_candidate_digest_and_source_bindings_are_fail_closed(self) -> None:
        changed = copy.deepcopy(self.candidate)
        changed["candidateDigest"] = f"sha256:{7:064x}"
        with self.assertRaisesRegex(ValueError, "sno_candidate_digest_invalid"):
            self.validate(changed)

        changed = copy.deepcopy(self.candidate)
        changed["bindings"]["artifactReleaseSetDigest"] = f"sha256:{8:064x}"
        with self.assertRaisesRegex(ValueError, "sno_candidate_bindings_invalid"):
            self.validate(changed)

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (
                ROOT / "schemas" / "sno-trial-workload-candidate-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        object_definitions = {
            name
            for name, definition in schema["$defs"].items()
            if definition.get("type") == "object"
        }
        self.assertEqual(
            object_definitions,
            {
                "activation",
                "artifact",
                "bindings",
                "claims",
                "clickhouseMode",
                "controls",
                "jetstreamMode",
                "modelBackendMode",
                "modelPlaneMode",
                "nodeEnvelope",
                "platformMode",
                "postgresMode",
                "quantities",
                "resources",
                "runtimeMode",
                "syntheticMode",
                "transient",
                "valkeyMode",
                "workload",
            },
        )
        for definition in object_definitions:
            self.assertIs(
                schema["$defs"][definition].get("additionalProperties"),
                False,
                definition,
            )


if __name__ == "__main__":
    unittest.main()
