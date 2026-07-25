from __future__ import annotations

import base64
import copy
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.sno_trial_product_artifacts import (
    ACTIVATION_REASONS,
    ARTIFACT_SET_ID,
    CANDIDATE_PATH,
    CLAIMS,
    CONTROLS,
    EXPECTED_PLANES,
    LOCK_PATH,
    REPORT_CONTROLS,
    REPORT_EXECUTION_MODE,
    REPORT_KIND,
    ROOT,
    bytes_digest,
    inspect_chart_package,
    load_json,
    report_digest,
    unsigned_digest,
    validate_lock,
    validate_report,
    verify_attestation,
    verify_image_index,
    verify_publication_run,
    verify_signature,
)


def completed(command: list[str], stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


class SnoTrialProductArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = load_json(LOCK_PATH)
        self.candidate = load_json(CANDIDATE_PATH)
        self.artifacts = self.lock["artifacts"]
        self.model_artifact = self.artifacts[-1]

    def test_lock_is_three_plane_and_non_authorizing(self) -> None:
        validate_lock(self.lock, self.candidate)
        self.assertEqual(
            self.lock["completeness"],
            "published-three-plane-not-trial-admitted",
        )
        self.assertEqual(
            tuple(artifact["plane"] for artifact in self.artifacts),
            EXPECTED_PLANES,
        )
        self.assertEqual(
            self.lock["artifactSetDigest"],
            unsigned_digest(self.lock, "artifactSetDigest"),
        )
        self.assertEqual(
            self.lock["activation"],
            {"state": "blocked", "reasonCodes": ACTIVATION_REASONS},
        )
        self.assertEqual(self.lock["controls"], CONTROLS)
        self.assertEqual(self.lock["claims"], CLAIMS)
        self.assertFalse(self.lock["controls"]["productionReleaseSetMutated"])
        self.assertFalse(self.lock["controls"]["cloudMutationAuthorized"])
        self.assertFalse(self.lock["controls"]["deploymentAuthorized"])

    def test_lock_requires_exact_unique_plane_order(self) -> None:
        for artifacts in (
            list(reversed(self.artifacts)),
            self.artifacts[:2],
            [self.artifacts[0], self.artifacts[0], self.artifacts[2]],
        ):
            with self.subTest(planes=[item["plane"] for item in artifacts]):
                changed = copy.deepcopy(self.lock)
                changed["artifacts"] = copy.deepcopy(artifacts)
                changed["artifactSetDigest"] = unsigned_digest(
                    changed, "artifactSetDigest"
                )
                with self.assertRaisesRegex(
                    ValueError, "artifacts_invalid|release_invalid"
                ):
                    validate_lock(changed, self.candidate)

    def test_lock_does_not_mutate_production_release_lineage(self) -> None:
        release_set = load_json(ROOT / "config" / "cross-plane-release-set.lock.json")
        production = {item["plane"]: item for item in release_set["planes"]}
        for artifact in self.artifacts:
            with self.subTest(plane=artifact["plane"]):
                self.assertNotEqual(
                    production[artifact["plane"]]["deploymentImage"],
                    artifact["image"]["reference"],
                )

    def test_source_image_chart_and_publication_drift_fail_closed(self) -> None:
        changes = [
            ("source", "revision", "f" * 40, "source_invalid"),
            ("image", "digest", f"sha256:{1:064x}", "image_invalid"),
            ("chart", "version", "99.0.0", "chart_invalid"),
        ]
        for artifact_index, artifact in enumerate(self.artifacts):
            artifact_changes = changes + [
                (
                    "publication",
                    "runAttempt",
                    artifact["publication"]["runAttempt"] + 1,
                    "publication_invalid",
                )
            ]
            for section, field, value, code in artifact_changes:
                with self.subTest(
                    plane=artifact["plane"], section=section, field=field
                ):
                    changed = copy.deepcopy(self.lock)
                    changed["artifacts"][artifact_index][section][field] = value
                    changed["artifactSetDigest"] = unsigned_digest(
                        changed, "artifactSetDigest"
                    )
                    with self.assertRaisesRegex(ValueError, code):
                        validate_lock(changed, self.candidate)

    def test_admission_activation_controls_and_claims_cannot_escalate(self) -> None:
        changes = [
            ("admission", "activationAuthorized", True, "admission_invalid"),
            ("activation", "state", "ready", "activation_invalid"),
            ("controls", "deploymentAuthorized", True, "controls_invalid"),
            ("claims", "referenceProfileVerified", True, "claims_invalid"),
        ]
        for section, field, value, code in changes:
            with self.subTest(section=section, field=field):
                changed = copy.deepcopy(self.lock)
                target = (
                    changed["artifacts"][0][section]
                    if section == "admission"
                    else changed[section]
                )
                target[field] = value
                changed["artifactSetDigest"] = unsigned_digest(
                    changed, "artifactSetDigest"
                )
                with self.assertRaisesRegex(ValueError, code):
                    validate_lock(changed, self.candidate)

    def test_candidate_and_self_digest_drift_are_rejected(self) -> None:
        changed = copy.deepcopy(self.lock)
        changed["bindings"]["workloadCandidateDigest"] = f"sha256:{2:064x}"
        changed["artifactSetDigest"] = unsigned_digest(changed, "artifactSetDigest")
        with self.assertRaisesRegex(ValueError, "bindings_invalid"):
            validate_lock(changed, self.candidate)

        changed = copy.deepcopy(self.lock)
        changed["artifactSetDigest"] = f"sha256:{3:064x}"
        with self.assertRaisesRegex(ValueError, "digest_mismatch"):
            validate_lock(changed, self.candidate)

    def test_publication_origin_requires_exact_repository_and_attempt(
        self,
    ) -> None:
        artifact = self.artifacts[0]
        publication = artifact["publication"]
        source = artifact["source"]
        response = {
            "id": publication["runId"],
            "run_attempt": 1,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": publication["tag"],
            "head_sha": source["revision"],
            "path": publication["workflow"],
            "html_url": publication["runUrl"],
        }

        def run(
            command: list[str], cwd: Path | None
        ) -> subprocess.CompletedProcess[str]:
            self.assertIsNone(cwd)
            self.assertIn(f"repos/{source['repository']}/actions/runs/", command[-1])
            return completed(command, json.dumps(response))

        result = verify_publication_run(artifact, run)
        self.assertEqual(result["conclusion"], "success")

        response["run_attempt"] = 2
        with self.assertRaisesRegex(ValueError, "publication_origin_invalid"):
            verify_publication_run(artifact, run)

    def test_dispatched_publication_binds_main_and_exact_source_tag(
        self,
    ) -> None:
        artifact = self.artifacts[1]
        publication = artifact["publication"]
        source = artifact["source"]
        response = {
            "id": publication["runId"],
            "run_attempt": publication["runAttempt"],
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": source["revision"],
            "path": publication["workflow"],
            "html_url": publication["runUrl"],
        }

        def run(
            command: list[str], cwd: Path | None
        ) -> subprocess.CompletedProcess[str]:
            self.assertIsNone(cwd)
            return completed(command, json.dumps(response))

        result = verify_publication_run(artifact, run)
        self.assertEqual(result["tag"], "v0.18.7")

        response["head_sha"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "publication_origin_invalid"):
            verify_publication_run(artifact, run)

    def test_signature_requires_exact_repository_digest_and_workflow_claims(
        self,
    ) -> None:
        artifact = self.artifacts[0]
        image = artifact["image"]
        source = artifact["source"]
        publication = artifact["publication"]
        signature = [
            {
                "critical": {
                    "identity": {"docker-reference": image["repository"]},
                    "image": {"docker-manifest-digest": image["digest"]},
                },
                "optional": {
                    "githubWorkflowSha": source["revision"],
                    "githubWorkflowRef": f"refs/tags/{publication['tag']}",
                    "githubWorkflowRepository": source["repository"],
                    "githubWorkflowName": publication["workflowName"],
                },
            }
        ]

        def run(
            command: list[str], cwd: Path | None
        ) -> subprocess.CompletedProcess[str]:
            self.assertIsNone(cwd)
            return completed(command, json.dumps(signature))

        verify_signature(
            image["reference"],
            image["repository"],
            image["digest"],
            source,
            publication,
            run,
        )
        signature[0]["critical"]["identity"]["docker-reference"] = image["reference"]
        signature[0]["optional"] = {}
        verify_signature(
            image["reference"],
            image["repository"],
            image["digest"],
            source,
            publication,
            run,
        )
        signature[0]["critical"]["identity"]["docker-reference"] = "wrong/reference"
        with self.assertRaisesRegex(ValueError, "signature_claims_invalid"):
            verify_signature(
                image["reference"],
                image["repository"],
                image["digest"],
                source,
                publication,
                run,
            )
        signature[0]["critical"]["identity"]["docker-reference"] = image["repository"]
        signature[0]["optional"] = {
            "githubWorkflowRepository": "wrong/repository"
        }
        with self.assertRaisesRegex(ValueError, "signature_claims_invalid"):
            verify_signature(
                image["reference"],
                image["repository"],
                image["digest"],
                source,
                publication,
                run,
            )

    def test_image_index_requires_exact_single_amd64_manifest(self) -> None:
        image = self.artifacts[0]["image"]
        index = {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "digest": image["platformManifestDigest"],
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "digest": f"sha256:{7:064x}",
                    "platform": {"os": "unknown", "architecture": "unknown"},
                },
            ],
        }

        def run(
            command: list[str], cwd: Path | None
        ) -> subprocess.CompletedProcess[str]:
            self.assertIsNone(cwd)
            return completed(command, json.dumps(index))

        verify_image_index(image, run)
        index["manifests"][0]["digest"] = f"sha256:{8:064x}"
        with self.assertRaisesRegex(ValueError, "image_platform_invalid"):
            verify_image_index(image, run)

    def test_attestation_requires_cyclonedx_subject_digest(self) -> None:
        image = self.artifacts[0]["image"]
        publication = self.artifacts[0]["publication"]
        statement = {
            "predicateType": "https://cyclonedx.org/bom",
            "subject": [
                {
                    "name": image["repository"],
                    "digest": {"sha256": image["digest"].removeprefix("sha256:")},
                }
            ],
        }

        def run(
            command: list[str], cwd: Path | None
        ) -> subprocess.CompletedProcess[str]:
            self.assertIsNone(cwd)
            payload = base64.b64encode(json.dumps(statement).encode()).decode()
            return completed(command, json.dumps({"payload": payload}))

        verify_attestation(
            image["reference"],
            image["repository"],
            image["digest"],
            publication,
            run,
        )
        statement["predicateType"] = "https://spdx.dev/Document"
        with self.assertRaisesRegex(ValueError, "attestation_subject_invalid"):
            verify_attestation(
                image["reference"],
                image["repository"],
                image["digest"],
                publication,
                run,
            )

    def test_chart_package_is_inspected_without_extraction(self) -> None:
        artifact = self.model_artifact
        chart = copy.deepcopy(artifact["chart"])
        trial_values = (
            "engineeringTrialProfile:\n"
            "  enabled: true\n"
            "  profileId: orchestra-ocp-sno-trial-amd64-v1\n"
            "  sourceOnlyAcknowledged: true\n"
        ).encode()
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / f"{chart['name']}-{chart['version']}.tgz"
            with tarfile.open(package, mode="w:gz") as archive:
                member = tarfile.TarInfo(chart["trialValuesPath"])
                member.size = len(trial_values)
                archive.addfile(member, io.BytesIO(trial_values))
            chart["packageDigest"] = bytes_digest(package.read_bytes())
            chart["trialValuesDigest"] = bytes_digest(trial_values)

            def run(
                command: list[str], cwd: Path | None
            ) -> subprocess.CompletedProcess[str]:
                self.assertIsNone(cwd)
                return completed(
                    command,
                    f"name: {chart['name']}\n"
                    f"version: {chart['version']}\n"
                    f"appVersion: {chart['appVersion']}\n",
                )

            result = inspect_chart_package(package, chart, run)
            self.assertTrue(result["trialValuesVerified"])
            chart["trialValuesDigest"] = f"sha256:{5:064x}"
            with self.assertRaisesRegex(ValueError, "trial_values_digest_invalid"):
                inspect_chart_package(package, chart, run)

    def valid_report(self) -> dict[str, object]:
        report_artifacts = []
        for artifact in self.artifacts:
            publication = artifact["publication"]
            source = artifact["source"]
            image = artifact["image"]
            chart = artifact["chart"]
            report_artifacts.append(
                {
                    "plane": artifact["plane"],
                    "publication": {
                        "runId": publication["runId"],
                        "runAttempt": publication["runAttempt"],
                        "runUrl": publication["runUrl"],
                        "tag": publication["tag"],
                        "sourceRevision": source["revision"],
                        "workflow": publication["workflow"],
                        "workflowName": publication["workflowName"],
                        "conclusion": "success",
                    },
                    "image": {
                        **image,
                        "platformManifestVerified": True,
                        "signatureVerified": True,
                        "cycloneDxAttestationVerified": True,
                    },
                    "chart": {
                        "reference": chart["reference"],
                        "digest": chart["digest"],
                        "name": chart["name"],
                        "version": chart["version"],
                        "appVersion": chart["appVersion"],
                        "packageDigest": chart["packageDigest"],
                        "trialValuesPath": chart["trialValuesPath"],
                        "trialValuesDigest": chart["trialValuesDigest"],
                        "signatureVerified": True,
                        "cycloneDxAttestationVerified": True,
                        "packagePulled": True,
                        "trialValuesVerified": True,
                    },
                    "admission": copy.deepcopy(artifact["admission"]),
                }
            )
        report: dict[str, object] = {
            "schemaVersion": 2,
            "kind": REPORT_KIND,
            "verificationId": "sno-product-replay-test-001",
            "generatedAt": "2026-07-25T09:00:00Z",
            "targetClass": "engineering-trial",
            "executionMode": REPORT_EXECUTION_MODE,
            "bindings": {
                "profileId": "orchestra-ocp-sno-trial-amd64-v1",
                "artifactSetId": ARTIFACT_SET_ID,
                "artifactSetDigest": self.lock["artifactSetDigest"],
                "workloadCandidateDigest": self.candidate["candidateDigest"],
                "verifierRevision": "a" * 40,
                "verifierRunId": 1,
                "verifierRunAttempt": 1,
            },
            "artifacts": report_artifacts,
            "activation": copy.deepcopy(self.lock["activation"]),
            "controls": copy.deepcopy(REPORT_CONTROLS),
            "claims": copy.deepcopy(CLAIMS),
        }
        report["reportDigest"] = report_digest(report)
        return report

    def test_report_is_payload_free_bound_and_non_authorizing(self) -> None:
        report = self.valid_report()
        validate_report(report, self.lock, self.candidate)
        self.assertFalse(report["controls"]["payloadsCollected"])
        self.assertFalse(report["controls"]["secretsCollected"])
        self.assertTrue(report["controls"]["githubApiTokenUsed"])
        self.assertTrue(report["controls"]["registryCredentialsRequired"])
        self.assertFalse(report["controls"]["providerCredentialsUsed"])
        self.assertFalse(report["controls"]["deploymentAuthorized"])
        self.assertFalse(report["claims"]["campaignEvidence"])

        changed = copy.deepcopy(report)
        changed["controls"]["cloudMutationAuthorized"] = True
        changed["reportDigest"] = report_digest(changed)
        with self.assertRaisesRegex(ValueError, "report_controls_invalid"):
            validate_report(changed, self.lock, self.candidate)

    def test_report_rejects_digest_order_and_attempt_drift(self) -> None:
        report = self.valid_report()
        report["artifacts"][0]["image"]["digest"] = f"sha256:{6:064x}"
        report["reportDigest"] = report_digest(report)
        with self.assertRaisesRegex(ValueError, "report_image_invalid"):
            validate_report(report, self.lock, self.candidate)

        report = self.valid_report()
        report["artifacts"] = list(reversed(report["artifacts"]))
        report["reportDigest"] = report_digest(report)
        with self.assertRaisesRegex(ValueError, "report_artifacts_invalid"):
            validate_report(report, self.lock, self.candidate)

        report = self.valid_report()
        report["bindings"]["verifierRunAttempt"] = 2
        report["reportDigest"] = report_digest(report)
        with self.assertRaisesRegex(ValueError, "report_bindings_invalid"):
            validate_report(report, self.lock, self.candidate)

    def test_v2_schemas_are_strict_at_every_object_boundary(self) -> None:
        for name in (
            "sno-trial-product-artifact-set-v2.schema.json",
            "sno-trial-product-artifact-replay-v2.schema.json",
        ):
            with self.subTest(name=name):
                schema = json.loads(
                    (ROOT / "schemas" / name).read_text(encoding="utf-8")
                )
                self.assertFalse(schema["additionalProperties"])
                for definition_name, definition in schema["$defs"].items():
                    if definition.get("type") == "object":
                        self.assertIs(
                            definition.get("additionalProperties"),
                            False,
                            definition_name,
                        )


if __name__ == "__main__":
    unittest.main()
