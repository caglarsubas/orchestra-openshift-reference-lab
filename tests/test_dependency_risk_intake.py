from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.build_dependency_risk_evidence import build_risk_evidence
from scripts.dependency_risk_contract import (
    EXCEPTION_TEMPLATE,
    EXPECTED_EXCEPTION_TEMPLATE_DIGEST,
    EXPECTED_RISK_POLICY_DIGEST,
    blob_digest,
    exception_approval_digest,
    exception_candidate_digest,
    expected_bindings,
    expected_intake_summary,
    load_contract_inputs,
    unsigned_subjects,
    validate_exception_intake,
    validate_risk_evidence,
    validate_risk_policy,
)
from scripts.validate_repository import canonical_digest, load_json


def digest(number: int) -> str:
    return f"sha256:{number:064x}"


def assert_strict_object_schemas(test: unittest.TestCase, value: object) -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            test.assertIs(
                value.get("additionalProperties"),
                False,
                msg=f"object schema is not strict: {value.get('title', value.get('$id'))}",
            )
        for child in value.values():
            assert_strict_object_schemas(test, child)
    elif isinstance(value, list):
        for child in value:
            assert_strict_object_schemas(test, child)


class DependencyRiskIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.admission, self.source, self.policy = load_contract_inputs()
        self.template = load_json(EXCEPTION_TEMPLATE)
        self.assessed_at = datetime(2026, 7, 22, 3, tzinfo=timezone.utc)

    def write_scan_inputs(
        self, directory: Path, *, blocked_subject: str | None = None
    ) -> dict:
        subjects = []
        for index, (subject_id, binding) in enumerate(
            unsigned_subjects(self.admission).items(), start=1
        ):
            vulnerabilities = []
            if subject_id == blocked_subject:
                vulnerabilities.append(
                    {
                        "VulnerabilityID": "CVE-2099-0001",
                        "Severity": "HIGH",
                        "FixedVersion": "9.9.9",
                    }
                )
            trivy = {
                "SchemaVersion": 2,
                "ArtifactName": binding["platformSubject"],
                "ArtifactType": "container_image",
                "Results": [
                    {
                        "Target": f"{subject_id} (linux)",
                        "Class": "os-pkgs",
                        "Type": "linux",
                        "Vulnerabilities": vulnerabilities,
                    }
                ],
            }
            spdx = {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": subject_id,
                "documentNamespace": f"https://example.invalid/{subject_id}",
                "creationInfo": {
                    "created": "2026-07-22T01:00:00Z",
                    "creators": ["Tool: syft-1.0.0"],
                },
                "documentDescribes": ["SPDXRef-Package-1"],
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-1",
                        "name": f"package-{index}",
                        "versionInfo": "1.0.0",
                        "licenseDeclared": "Apache-2.0",
                        "licenseConcluded": "NOASSERTION",
                    }
                ],
            }
            vulnerability_name = f"{subject_id}.trivy.json"
            sbom_name = f"{subject_id}.spdx.json"
            vulnerability_bytes = json.dumps(trivy, sort_keys=True).encode("utf-8")
            sbom_bytes = json.dumps(spdx, sort_keys=True).encode("utf-8")
            (directory / vulnerability_name).write_bytes(vulnerability_bytes)
            (directory / sbom_name).write_bytes(sbom_bytes)
            subjects.append(
                {
                    "id": subject_id,
                    "sourceSubject": binding["sourceSubject"],
                    "platformSubject": binding["platformSubject"],
                    "vulnerabilityReportFile": vulnerability_name,
                    "vulnerabilityReportDigest": blob_digest(vulnerability_bytes),
                    "sbomFile": sbom_name,
                    "sbomDigest": blob_digest(sbom_bytes),
                }
            )
        return {
            "schemaVersion": 1,
            "profileId": "orchestra-ocp-4.20-amd64-v1",
            "targetClass": "vendor-reference-lab",
            "executionMode": "live",
            "evidenceId": "orchestra-dependency-risk-evidence-test.1",
            "bindings": expected_bindings(),
            "collection": {
                "executionClass": "signed-certification-runner",
                "runnerImageDigest": digest(1),
                "runnerProvenanceBundleDigest": digest(2),
                "actorIdentityDigest": digest(3),
                "startedAt": "2026-07-22T00:00:00Z",
                "completedAt": "2026-07-22T01:00:00Z",
                "collectionAttestationDigest": digest(4),
                "vulnerabilityScanner": {
                    "name": "trivy",
                    "version": "0.67.2",
                    "databaseDigest": digest(5),
                },
                "sbomScanner": {"name": "syft", "version": "1.33.0"},
                "invocationPolicy": {
                    "platform": "linux/amd64",
                    "vulnerabilityScanners": ["vuln"],
                    "ignoreFileUsed": False,
                    "ignoreUnfixed": False,
                    "severityFilter": [],
                    "sbomFormat": "spdx-2.3-json",
                },
            },
            "subjects": subjects,
        }

    def build_evidence(
        self, directory: Path, *, blocked_subject: str | None = None
    ) -> dict:
        manifest = self.write_scan_inputs(directory, blocked_subject=blocked_subject)
        return build_risk_evidence(manifest, directory, self.admission, self.source)

    def populate_review(
        self,
        intake: dict,
        evidence: dict,
        subject_index: int,
        *,
        approved: bool,
    ) -> None:
        item = intake["subjects"][subject_index]
        risk_subject = {subject["id"]: subject for subject in evidence["subjects"]}[
            item["id"]
        ]
        item["evidence"] = {
            "riskEvidenceDigest": canonical_digest(evidence),
            "collectionAttestationDigest": evidence["collection"][
                "collectionAttestationDigest"
            ],
            "runnerImageDigest": evidence["collection"]["runnerImageDigest"],
            "runnerProvenanceBundleDigest": evidence["collection"][
                "runnerProvenanceBundleDigest"
            ],
            "sbomDigest": risk_subject["artifacts"]["sbom"]["digest"],
            "vulnerabilityReportDigest": risk_subject["artifacts"]["vulnerability"][
                "digest"
            ],
            "licenseInventoryDigest": risk_subject["licenses"]["inventoryDigest"],
            "machineReviewDigest": risk_subject["machineReview"]["reviewDigest"],
            "licenseReviewDigest": digest(20 + subject_index),
            "riskReviewDigest": digest(40 + subject_index),
            "compensatingControlsDigest": risk_subject["compensatingControls"][
                "planDigest"
            ],
        }
        item["request"] = {
            "status": "approved" if approved else "review-pending",
            "exceptionId": f"orchestra-upstream-signature-exception-test.{subject_index}",
            "requestedAt": "2026-07-22T01:30:00Z",
            "requestorIdentityDigest": digest(60 + subject_index),
            "candidateDigest": None,
        }
        candidate_digest = exception_candidate_digest(intake, item)
        item["request"]["candidateDigest"] = candidate_digest
        if not approved:
            item["approvals"] = []
            item["decision"] = {
                "status": "required-not-approved",
                "approvedAt": None,
                "expiresAt": None,
                "approvalDigest": None,
            }
            item["sourceAdmissionState"] = "blocked"
            item["reasonCodes"] = [
                "INDEPENDENT_REVIEWS_MISSING",
                "SIGNED_RUNNER_REVERIFICATION_REQUIRED",
            ]
            return
        approvals = [
            {
                "role": "security-reviewer",
                "reviewerIdentityDigest": digest(100 + subject_index),
                "decision": "approve",
                "decidedAt": "2026-07-22T02:00:00Z",
                "candidateDigest": candidate_digest,
                "signatureBundleDigest": digest(120 + subject_index),
            },
            {
                "role": "service-owner",
                "reviewerIdentityDigest": digest(140 + subject_index),
                "decision": "approve",
                "decidedAt": "2026-07-22T02:10:00Z",
                "candidateDigest": candidate_digest,
                "signatureBundleDigest": digest(160 + subject_index),
            },
        ]
        item["approvals"] = approvals
        item["decision"] = {
            "status": "approved",
            "approvedAt": "2026-07-22T02:15:00Z",
            "expiresAt": "2026-07-23T02:15:00Z",
            "approvalDigest": exception_approval_digest(candidate_digest, approvals),
        }
        item["sourceAdmissionState"] = "exception-approved-pending-source-aggregate"
        item["reasonCodes"] = [
            "SIGNED_RUNNER_REVERIFICATION_REQUIRED",
            "SOURCE_ADMISSION_AGGREGATION_REQUIRED",
        ]

    def refresh_intake_summary(self, intake: dict) -> None:
        intake["claim"], intake["admission"] = expected_intake_summary(
            intake["subjects"]
        )

    def test_locked_policy_and_empty_exception_template_are_blocked(self) -> None:
        self.assertEqual(validate_risk_policy(self.policy), EXPECTED_RISK_POLICY_DIGEST)
        self.assertEqual(
            validate_exception_intake(
                self.template,
                self.admission,
                now=self.assessed_at,
                require_template_digest=True,
            ),
            EXPECTED_EXCEPTION_TEMPLATE_DIGEST,
        )
        self.assertEqual(self.template["claim"]["approvedExceptions"], 0)
        self.assertFalse(self.template["claim"]["sourceAdmissionAuthorized"])
        self.assertFalse(self.template["claim"]["mirrorAuthorization"])

    def test_contract_schemas_are_strict_json_objects(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for name in (
            "dependency-risk-scan-manifest-v1.schema.json",
            "dependency-risk-evidence-v1.schema.json",
            "dependency-signature-exceptions-v1.schema.json",
        ):
            schema = json.loads((root / "schemas" / name).read_text(encoding="utf-8"))
            assert_strict_object_schemas(self, schema)

    def test_clean_reports_build_reviewable_but_non_authorizing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        self.assertEqual(evidence["claim"]["eligibleForHumanReviewCount"], 8)
        self.assertFalse(evidence["claim"]["exceptionsApproved"])
        self.assertFalse(evidence["claim"]["sourceAdmissionAuthorized"])
        self.assertFalse(evidence["claim"]["mirrorAuthorization"])
        self.assertEqual(
            validate_risk_evidence(evidence, self.admission, self.source),
            canonical_digest(evidence),
        )

    def test_high_finding_blocks_machine_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(
                Path(directory), blocked_subject="barman-cloud-controller"
            )
        first = {subject["id"]: subject for subject in evidence["subjects"]}[
            "barman-cloud-controller"
        ]
        self.assertEqual(first["vulnerabilities"]["thresholdState"], "blocked")
        self.assertEqual(first["machineReview"]["state"], "blocked")

    def test_raw_report_digest_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            manifest = self.write_scan_inputs(path)
            manifest["subjects"][0]["vulnerabilityReportDigest"] = digest(999)
            with self.assertRaisesRegex(ValueError, "raw_artifact_digest_mismatch"):
                build_risk_evidence(manifest, path, self.admission, self.source)

    def test_report_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            manifest = self.write_scan_inputs(path)
            manifest["subjects"][0]["sbomFile"] = "../outside.json"
            with self.assertRaisesRegex(ValueError, "artifact_name_invalid"):
                build_risk_evidence(manifest, path, self.admission, self.source)

    def test_sbom_must_bind_the_scanned_subject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            manifest = self.write_scan_inputs(path)
            first = manifest["subjects"][0]
            sbom_path = path / first["sbomFile"]
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            sbom["name"] = "different-subject"
            sbom["documentNamespace"] = "https://example.invalid/different-subject"
            sbom_bytes = json.dumps(sbom, sort_keys=True).encode("utf-8")
            sbom_path.write_bytes(sbom_bytes)
            first["sbomDigest"] = blob_digest(sbom_bytes)
            with self.assertRaisesRegex(ValueError, "spdx_identity_invalid"):
                build_risk_evidence(manifest, path, self.admission, self.source)

    def test_unknown_exception_field_is_rejected(self) -> None:
        changed = copy.deepcopy(self.template)
        changed["subjects"][0]["evidence"]["automaticApproval"] = True
        with self.assertRaisesRegex(ValueError, "evidence_invalid"):
            validate_exception_intake(changed, self.admission, now=self.assessed_at)

    def test_review_pending_candidate_remains_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.1"
        self.populate_review(intake, evidence, 0, approved=False)
        self.refresh_intake_summary(intake)
        validate_exception_intake(
            intake, self.admission, evidence, now=self.assessed_at
        )
        self.assertEqual(intake["claim"]["reviewReadySubjects"], 1)
        self.assertEqual(intake["claim"]["approvedExceptions"], 0)
        self.assertFalse(intake["claim"]["sourceAdmissionAuthorized"])

    def test_requestor_cannot_approve_own_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.2"
        self.populate_review(intake, evidence, 0, approved=True)
        item = intake["subjects"][0]
        item["approvals"][0]["reviewerIdentityDigest"] = item["request"][
            "requestorIdentityDigest"
        ]
        self.refresh_intake_summary(intake)
        with self.assertRaisesRegex(ValueError, "approval_independence_invalid"):
            validate_exception_intake(
                intake, self.admission, evidence, now=self.assessed_at
            )

    def test_collector_cannot_approve_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.3"
        self.populate_review(intake, evidence, 0, approved=True)
        intake["subjects"][0]["approvals"][0]["reviewerIdentityDigest"] = evidence[
            "collection"
        ]["actorIdentityDigest"]
        self.refresh_intake_summary(intake)
        with self.assertRaisesRegex(ValueError, "approval_independence_invalid"):
            validate_exception_intake(
                intake, self.admission, evidence, now=self.assessed_at
            )

    def test_duplicate_reviewer_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.4"
        self.populate_review(intake, evidence, 0, approved=True)
        approvals = intake["subjects"][0]["approvals"]
        approvals[1]["reviewerIdentityDigest"] = approvals[0]["reviewerIdentityDigest"]
        self.refresh_intake_summary(intake)
        with self.assertRaisesRegex(ValueError, "approval_independence_invalid"):
            validate_exception_intake(
                intake, self.admission, evidence, now=self.assessed_at
            )

    def test_approval_cannot_be_replayed_into_another_intake(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.4a"
        self.populate_review(intake, evidence, 0, approved=True)
        self.refresh_intake_summary(intake)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.4b"
        with self.assertRaisesRegex(ValueError, "candidate_digest_invalid"):
            validate_exception_intake(
                intake, self.admission, evidence, now=self.assessed_at
            )

    def test_exception_lifetime_cannot_exceed_thirty_days(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.5"
        self.populate_review(intake, evidence, 0, approved=True)
        intake["subjects"][0]["decision"]["expiresAt"] = "2026-08-22T02:15:01Z"
        self.refresh_intake_summary(intake)
        with self.assertRaisesRegex(ValueError, "approved_state_invalid"):
            validate_exception_intake(
                intake, self.admission, evidence, now=self.assessed_at
            )

    def test_stale_scan_cannot_back_a_new_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.6"
        self.populate_review(intake, evidence, 0, approved=False)
        self.refresh_intake_summary(intake)
        with self.assertRaisesRegex(ValueError, "risk_evidence_stale"):
            validate_exception_intake(
                intake,
                self.admission,
                evidence,
                now=datetime(2026, 7, 25, 1, 0, 1, tzinfo=timezone.utc),
            )

    def test_blocked_machine_review_cannot_enter_human_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(
                Path(directory), blocked_subject="barman-cloud-controller"
            )
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.7"
        self.populate_review(intake, evidence, 0, approved=False)
        self.refresh_intake_summary(intake)
        with self.assertRaisesRegex(ValueError, "machine_review_blocked"):
            validate_exception_intake(
                intake, self.admission, evidence, now=self.assessed_at
            )

    def test_all_approved_exceptions_still_do_not_authorize_source_or_mirror(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.build_evidence(Path(directory))
        intake = copy.deepcopy(self.template)
        intake["intakeId"] = "orchestra-dependency-signature-exceptions-test.8"
        for index in range(8):
            self.populate_review(intake, evidence, index, approved=True)
        self.refresh_intake_summary(intake)
        validate_exception_intake(
            intake, self.admission, evidence, now=self.assessed_at
        )
        self.assertTrue(intake["claim"]["allExceptionsApproved"])
        self.assertFalse(intake["claim"]["sourceAdmissionAuthorized"])
        self.assertFalse(intake["claim"]["mirrorAuthorization"])
        self.assertEqual(
            intake["admission"]["reasonCodes"],
            [
                "SIGNED_RUNNER_REVERIFICATION_REQUIRED",
                "SOURCE_ADMISSION_INCOMPLETE",
                "MIRRORING_NOT_AUTHORIZED",
            ],
        )


if __name__ == "__main__":
    unittest.main()
