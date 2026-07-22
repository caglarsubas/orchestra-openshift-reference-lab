from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.validate_reference_lab_contract_intake import (
    EXPECTED_INTAKE_DIGEST,
    INTAKE_PATH,
    canonical_bytes,
    parse_json_bytes,
    raw_digest,
    read_json,
    validate_contract_intake,
    validate_fixture_campaign,
    validate_policy,
    validate_schema_bundle,
    verify_upstream_bytes,
)
from scripts.validate_repository import ROOT


class ReferenceLabContractIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        _, self.intake = read_json(INTAKE_PATH, "test_intake")
        _, self.policy = read_json(
            ROOT
            / "contracts"
            / "platform"
            / "reference-lab-certification-policy.v2.json",
            "test_policy",
        )
        _, self.schemas = read_json(
            ROOT / "contracts" / "platform" / "reference-lab-contract-schemas.v2.json",
            "test_schemas",
        )
        _, self.fixture = read_json(
            ROOT / "contracts" / "platform" / "reference-lab-campaign.fixture.json",
            "test_fixture",
        )
        _, self.topology = read_json(ROOT / "config" / "lab.lock.json", "test_topology")

    def copy_intake_root(self, destination: Path) -> None:
        (destination / "config").mkdir(parents=True)
        (destination / "contracts" / "platform").mkdir(parents=True)
        for name in (
            "lab.lock.json",
            "cross-plane-release-set.lock.json",
            "dependency-bom.lock.json",
            "reference-lab-certification-contract.lock.json",
        ):
            shutil.copy2(ROOT / "config" / name, destination / "config" / name)
        for name in (
            "reference-lab-certification-policy.v2.json",
            "reference-lab-contract-schemas.v2.json",
            "reference-lab-campaign.fixture.json",
        ):
            shutil.copy2(
                ROOT / "contracts" / "platform" / name,
                destination / "contracts" / "platform" / name,
            )

    def test_locked_intake_is_valid_and_non_authorizing(self) -> None:
        self.assertEqual(validate_contract_intake(self.intake), EXPECTED_INTAKE_DIGEST)
        self.assertEqual(len(self.policy["requiredEvidence"]), 18)
        self.assertEqual(
            self.intake["claim"],
            {
                "contractSourceOnly": True,
                "liveCampaignStarted": False,
                "campaignEvidence": False,
                "referenceProfileVerified": False,
                "customerCertified": False,
                "redHatCertified": False,
                "contractualSla": False,
            },
        )

    def test_artifact_byte_or_canonical_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_intake_root(root)
            policy_path = (
                root
                / "contracts"
                / "platform"
                / "reference-lab-certification-policy.v2.json"
            )
            policy_path.write_text(
                json.dumps(self.policy, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            _, intake = read_json(
                root / "config" / "reference-lab-certification-contract.lock.json",
                "copied_intake",
            )
            with self.assertRaisesRegex(ValueError, "artifact_digest_invalid"):
                validate_contract_intake(intake, root=root)

    def test_live_policy_cannot_be_widened_or_reordered(self) -> None:
        changed = copy.deepcopy(self.policy)
        changed["acceptedTargetClasses"].append("fixture")
        with self.assertRaisesRegex(ValueError, "policy_semantics_invalid"):
            validate_policy(changed)
        changed = copy.deepcopy(self.policy)
        changed["requiredEvidence"][1]["dependencies"] = []
        with self.assertRaisesRegex(ValueError, "policy_semantics_invalid"):
            validate_policy(changed)

    def test_schema_bundle_cannot_loosen_or_change_reference_claims(self) -> None:
        changed = copy.deepcopy(self.schemas)
        changed["contracts"]["campaign"]["additionalProperties"] = True
        with self.assertRaisesRegex(ValueError, "schema_not_strict"):
            validate_schema_bundle(changed, self.policy)
        changed = copy.deepcopy(self.schemas)
        claims = changed["contracts"]["referenceProfileVerificationBom"]["properties"][
            "claims"
        ]["properties"]
        claims["customerCertified"]["const"] = True
        with self.assertRaisesRegex(ValueError, "bom_claim_schema_invalid"):
            validate_schema_bundle(changed, self.policy)

    def test_fixture_vector_cannot_be_promoted_or_use_real_runner(self) -> None:
        changed = copy.deepcopy(self.fixture)
        changed["targetClass"] = "vendor-reference-lab"
        changed["executionMode"] = "live"
        with self.assertRaisesRegex(ValueError, "fixture_identity_invalid"):
            validate_fixture_campaign(
                changed,
                self.schemas["contracts"]["campaign"],
                self.policy,
                self.topology,
            )
        changed = copy.deepcopy(self.fixture)
        changed["runner"]["image"] = self.intake["source"]["certificationRunnerImage"]
        with self.assertRaisesRegex(ValueError, "fixture_live_boundary_invalid"):
            validate_fixture_campaign(
                changed,
                self.schemas["contracts"]["campaign"],
                self.policy,
                self.topology,
            )

    def test_release_runner_or_claim_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_intake_root(root)
            _, changed = read_json(
                root / "config" / "reference-lab-certification-contract.lock.json",
                "copied_intake",
            )
            changed["source"]["release"] = "platform-v0.1.0-rc.7"
            with self.assertRaisesRegex(ValueError, "source_invalid"):
                validate_contract_intake(changed, root=root)
            changed = copy.deepcopy(self.intake)
            changed["claim"]["referenceProfileVerified"] = True
            with self.assertRaisesRegex(ValueError, "claim_invalid"):
                validate_contract_intake(changed, root=root)

    def test_duplicate_json_keys_and_path_escape_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate_key"):
            parse_json_bytes(b'{"schemaVersion":1,"schemaVersion":2}', "duplicate")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_intake_root(root)
            _, changed = read_json(
                root / "config" / "reference-lab-certification-contract.lock.json",
                "copied_intake",
            )
            changed["artifacts"][0]["vendoredPath"] = "../outside.json"
            with self.assertRaisesRegex(ValueError, "artifact_invalid"):
                validate_contract_intake(changed, root=root)

    def test_upstream_git_object_replay_detects_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            repository = workspace / "platform-source"
            lab_root = workspace / "lab"
            source_path = repository / "prometa-platform" / "contract.json"
            vendored_path = lab_root / "contracts" / "platform" / "contract.json"
            source_path.parent.mkdir(parents=True)
            vendored_path.parent.mkdir(parents=True)
            value = {"kind": "fixture-contract", "schemaVersion": 1}
            raw = canonical_bytes(value)
            source_path.write_bytes(raw)
            vendored_path.write_bytes(raw)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Fixture"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "fixture@example.invalid",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "add", "prometa-platform/contract.json"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            artifacts = [
                {
                    "id": "fixture",
                    "sourcePath": "prometa-platform/contract.json",
                    "vendoredPath": "contracts/platform/contract.json",
                    "rawDigest": raw_digest(raw),
                }
            ]
            verify_upstream_bytes(repository, revision, artifacts, root=lab_root)
            vendored_path.write_bytes(canonical_bytes({"kind": "substituted"}))
            with self.assertRaisesRegex(ValueError, "upstream_bytes_mismatch"):
                verify_upstream_bytes(repository, revision, artifacts, root=lab_root)

    def test_default_validation_and_ci_include_contract_intake(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        command = "python3 scripts/validate_reference_lab_contract_intake.py"
        self.assertIn(
            "$(PYTHON) scripts/validate_reference_lab_contract_intake.py", makefile
        )
        self.assertIn("verify-platform-contract-source:", makefile)
        self.assertIn('--platform-repository "$(PLATFORM_REPOSITORY)"', makefile)
        self.assertIn(command, workflow)


if __name__ == "__main__":
    unittest.main()
