from __future__ import annotations

import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts.lab_service_publication import (
    build_observation,
    canonical_bytes,
    canonical_digest,
)
from scripts.lab_service_publication_replay import (
    build_replay_report,
    expected_claims,
    load_policy,
    project_origin,
    validate_declared_implementation,
    validate_origin,
    validate_report,
    write_create_only,
)
from tests import test_lab_service_publication as publication_test_support


class LabServicePublicationReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy, self.policy_digest = load_policy()
        self.revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.publication_run_id = "30002879030"
        self.verifier_run_id = "30003000001"
        publication_case = publication_test_support.LabServicePublicationTests()
        publication_case.setUp()
        publication_case.release = "lab-services-v0.1.0-rc.1"
        publication_case.tag = f"{publication_case.release}-{publication_case.revision}"
        self.fixtures, image_digests = publication_case.fixtures()
        self.inspector = publication_case.inspector(self.fixtures)
        self.signature_calls: list[tuple[str, str, str]] = []

        def verify(subject: str, identity: str, issuer: str) -> None:
            self.signature_calls.append((subject, identity, issuer))

        self.verify_signature = verify
        self.publication = build_observation(
            release=publication_case.release,
            revision=self.revision,
            run_id=self.publication_run_id,
            run_attempt=1,
            actor_id="37515097",
            published_at="2026-07-23T12:00:00Z",
            image_digests=image_digests,
            inspect_raw=self.inspector,
            verify_signature=lambda *_: None,
        )
        self.publication_digest = canonical_digest(self.publication)
        self.origin = {
            "id": int(self.publication_run_id),
            "runAttempt": 1,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "headSha": self.revision,
            "headBranch": "main",
            "path": ".github/workflows/lab-service-publication.yml",
            "repository": {
                "id": 1307302690,
                "fullName": "caglarsubas/orchestra-openshift-reference-lab",
            },
            "artifact": {
                "id": 8561772783,
                "name": (
                    f"lab-service-publication-observation-{self.publication_run_id}-1"
                ),
                "sizeInBytes": 1880,
                "expired": False,
            },
        }

    def build(self, *, publication: dict[str, Any] | None = None) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publication_path = root / "publication.json"
            origin_path = root / "origin.json"
            publication_value = publication or self.publication
            publication_path.write_bytes(canonical_bytes(publication_value))
            origin_path.write_bytes(canonical_bytes(self.origin))
            return build_replay_report(
                publication_path=publication_path,
                origin_path=origin_path,
                expected_observation_digest=canonical_digest(publication_value),
                expected_publication_run_id=self.publication_run_id,
                expected_publication_revision=self.revision,
                verifier_revision=self.revision,
                verifier_run_id=self.verifier_run_id,
                verifier_run_attempt=1,
                verifier_actor_id="37515097",
                verified_at="2026-07-23T12:05:00Z",
                inspect_raw=self.inspector,
                verify_signature=self.verify_signature,
            )

    def test_policy_and_workflow_are_read_only_and_digest_locked(self) -> None:
        self.assertEqual(
            self.policy_digest,
            "sha256:0607daa157b5a0a49284305d8216d6ecf98019eb25a5d48032c26bc09e050317",
        )
        self.assertEqual(
            self.policy["workflow"]["permissions"],
            {"actions": "read", "contents": "read", "packages": "read"},
        )
        self.assertFalse(self.policy["workflow"]["idTokenPermission"])
        self.assertFalse(self.policy["workflow"]["registryMutation"])
        self.assertFalse(self.policy["workflow"]["imageSigning"])
        validate_declared_implementation(self.policy)
        replay_workflow = Path(
            ".github/workflows/lab-service-publication-replay.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "lab_service_publication_replay.py project-origin",
            replay_workflow,
        )
        self.assertEqual(
            replay_workflow.count("EXPECTED_MAIN_SHA: ${{ inputs.expected_main_sha }}"),
            1,
        )
        self.assertEqual(
            replay_workflow.count(
                "EXPECTED_PUBLICATION_REVISION: "
                "${{ inputs.expected_publication_revision }}"
            ),
            1,
        )
        self.assertEqual(
            replay_workflow.count(
                "EXPECTED_OBSERVATION_DIGEST: ${{ inputs.expected_observation_digest }}"
            ),
            1,
        )
        self.assertEqual(
            replay_workflow.count(
                "PUBLICATION_RUN_ID: ${{ inputs.publication_run_id }}"
            ),
            1,
        )
        self.assertNotIn("jq ", replay_workflow)
        makefile = Path("Makefile").read_text(encoding="utf-8")
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        command = "scripts/lab_service_publication_replay.py validate-policy"
        self.assertIn(command, makefile)
        self.assertIn(command, workflow)
        self.assertIn("verify-lab-service-publication-replay:", makefile)

    def test_replay_binds_origin_source_registry_attestations_and_signatures(
        self,
    ) -> None:
        report = self.build()
        validate_report(report, self.policy, self.policy_digest)
        self.assertEqual(report["claims"], expected_claims())
        self.assertEqual(len(self.signature_calls), 2)
        self.assertEqual(
            report["publication"]["observationDigest"],
            self.publication_digest,
        )
        self.assertEqual(
            [item["imageDigest"] for item in report["services"]],
            [item["image"]["digest"] for item in self.publication["services"]],
        )

    def test_origin_must_be_exact_successful_first_attempt_and_unique_artifact(
        self,
    ) -> None:
        validate_origin(
            self.origin,
            self.publication,
            expected_run_id=self.publication_run_id,
            expected_revision=self.revision,
        )
        for field, value in (
            ("runAttempt", 2),
            ("runAttempt", True),
            ("event", "push"),
            ("conclusion", "failure"),
            ("headBranch", "release"),
        ):
            changed = copy.deepcopy(self.origin)
            changed[field] = value
            with self.assertRaisesRegex(ValueError, "origin_invalid"):
                validate_origin(
                    changed,
                    self.publication,
                    expected_run_id=self.publication_run_id,
                    expected_revision=self.revision,
                )
        changed = copy.deepcopy(self.origin)
        changed["artifact"]["expired"] = True
        with self.assertRaisesRegex(ValueError, "origin_invalid"):
            validate_origin(
                changed,
                self.publication,
                expected_run_id=self.publication_run_id,
                expected_revision=self.revision,
            )

    def test_github_api_origin_projection_is_strict_and_create_only(self) -> None:
        run = {
            "id": int(self.publication_run_id),
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": self.revision,
            "head_branch": "main",
            "path": ".github/workflows/lab-service-publication.yml",
            "repository": {
                "id": 1307302690,
                "full_name": "caglarsubas/orchestra-openshift-reference-lab",
            },
            "ignored": "github-api-field",
        }
        artifact = {
            "id": self.origin["artifact"]["id"],
            "name": self.origin["artifact"]["name"],
            "size_in_bytes": self.origin["artifact"]["sizeInBytes"],
            "expired": False,
            "ignored": "github-api-field",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_path = root / "run.json"
            inventory_path = root / "inventory.json"
            run_path.write_bytes(canonical_bytes(run))
            inventory_path.write_bytes(canonical_bytes({"artifacts": [artifact]}))
            projected = project_origin(
                run_path=run_path,
                inventory_path=inventory_path,
                expected_run_id=self.publication_run_id,
                expected_revision=self.revision,
            )
            self.assertEqual(projected, self.origin)
            duplicate = {"artifacts": [artifact, copy.deepcopy(artifact)]}
            inventory_path.write_bytes(canonical_bytes(duplicate))
            with self.assertRaisesRegex(ValueError, "artifact_inventory_invalid"):
                project_origin(
                    run_path=run_path,
                    inventory_path=inventory_path,
                    expected_run_id=self.publication_run_id,
                    expected_revision=self.revision,
                )

    def test_publication_digest_and_source_tree_tamper_are_rejected(self) -> None:
        changed = copy.deepcopy(self.publication)
        changed["services"][0]["sourceTreeDigest"] = "sha256:" + ("f" * 64)
        with self.assertRaisesRegex(ValueError, "source_mismatch"):
            self.build(publication=changed)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publication_path = root / "publication.json"
            origin_path = root / "origin.json"
            publication_path.write_bytes(canonical_bytes(self.publication))
            origin_path.write_bytes(canonical_bytes(self.origin))
            with self.assertRaisesRegex(ValueError, "observation_digest_invalid"):
                build_replay_report(
                    publication_path=publication_path,
                    origin_path=origin_path,
                    expected_observation_digest="sha256:" + ("f" * 64),
                    expected_publication_run_id=self.publication_run_id,
                    expected_publication_revision=self.revision,
                    verifier_revision=self.revision,
                    verifier_run_id=self.verifier_run_id,
                    verifier_run_attempt=1,
                    verifier_actor_id="37515097",
                    verified_at="2026-07-23T12:05:00Z",
                    inspect_raw=self.inspector,
                    verify_signature=self.verify_signature,
                )

    def test_stale_publication_cannot_be_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publication_path = root / "publication.json"
            origin_path = root / "origin.json"
            publication_path.write_bytes(canonical_bytes(self.publication))
            origin_path.write_bytes(canonical_bytes(self.origin))
            with self.assertRaisesRegex(ValueError, "observation_stale"):
                build_replay_report(
                    publication_path=publication_path,
                    origin_path=origin_path,
                    expected_observation_digest=self.publication_digest,
                    expected_publication_run_id=self.publication_run_id,
                    expected_publication_revision=self.revision,
                    verifier_revision=self.revision,
                    verifier_run_id=self.verifier_run_id,
                    verifier_run_attempt=1,
                    verifier_actor_id="37515097",
                    verified_at="2026-08-07T12:05:00Z",
                    inspect_raw=self.inspector,
                    verify_signature=self.verify_signature,
                )

    def test_replay_statement_cannot_claim_human_review_or_activation(self) -> None:
        report = self.build()
        changed = copy.deepcopy(report)
        changed["claims"]["independentHumanReview"] = True
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed, self.policy, self.policy_digest)
        changed = copy.deepcopy(report)
        changed["claims"]["harborMirrored"] = True
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed, self.policy, self.policy_digest)
        changed = copy.deepcopy(report)
        changed["services"][1]["imageDigest"] = changed["services"][0]["imageDigest"]
        changed["services"][1]["signatureSubject"] = (
            f"{changed['services'][1]['imageRepository']}@"
            f"{changed['services'][1]['imageDigest']}"
        )
        with self.assertRaisesRegex(ValueError, "service_substitution"):
            validate_report(changed, self.policy, self.policy_digest)

    def test_schema_scalar_types_and_release_are_enforced(self) -> None:
        report = self.build()
        changed = copy.deepcopy(report)
        changed["schemaVersion"] = True
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed, self.policy, self.policy_digest)
        changed = copy.deepcopy(report)
        changed["verifier"]["runId"] = int(changed["verifier"]["runId"])
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed, self.policy, self.policy_digest)
        changed = copy.deepcopy(report)
        changed["verifier"]["runAttempt"] = True
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed, self.policy, self.policy_digest)
        changed = copy.deepcopy(report)
        changed["publication"]["release"] = "mutable-latest"
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed, self.policy, self.policy_digest)
        changed = copy.deepcopy(report)
        changed["claims"]["separateWorkflowReplay"] = 1
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed, self.policy, self.policy_digest)

    def test_replay_output_is_create_only_and_canonical(self) -> None:
        report = self.build()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "replay.json"
            write_create_only(output, report)
            self.assertEqual(output.read_bytes(), canonical_bytes(report))
            with self.assertRaisesRegex(ValueError, "output_create_failed"):
                write_create_only(output, report)


if __name__ == "__main__":
    unittest.main()
