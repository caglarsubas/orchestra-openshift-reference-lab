from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.build_sno_trial_dependency_risk_evidence import build_evidence
from scripts.sno_trial_dependency_risk import (
    CONTROL_PLAN,
    EXCEPTION_TEMPLATE_PATH,
    EXPECTED_EXCEPTION_TEMPLATE_DIGEST,
    EXPECTED_POLICY_DIGEST,
    blob_digest,
    exception_approval_digest,
    exception_candidate_digest,
    expected_bindings,
    expected_intake_summary,
    expected_machine_review,
    expected_subjects,
    load_inputs,
    validate_exception_intake,
    validate_policy,
    validate_risk_evidence,
)
from scripts.validate_repository import ROOT, canonical_digest, load_json


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


class SnoTrialDependencyRiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifacts, self.release_set, self.policy = load_inputs()
        self.template = load_json(EXCEPTION_TEMPLATE_PATH)
        self.assessed_at = datetime(2026, 7, 28, 3, tzinfo=timezone.utc)

    def evidence(
        self,
        *,
        blocked_subject: str | None = None,
        model_license_review_complete: bool = True,
    ) -> dict:
        runner = self.release_set["certificationRunner"]
        collection = {
            "executionClass": "signed-certification-runner",
            "runnerRelease": runner["release"],
            "runnerRevision": runner["source"]["revision"],
            "runnerImage": runner["image"],
            "runnerImageDigest": runner["image"].rsplit("@", 1)[1],
            "runnerToolchainDigest": runner["toolchainDigest"],
            "actorIdentityDigest": digest(10),
            "startedAt": "2026-07-28T00:00:00Z",
            "completedAt": "2026-07-28T01:00:00Z",
            "collectionStatementDigest": digest(11),
            "collectionSignatureBundleDigest": digest(12),
            "vulnerabilityScanner": {
                "name": "trivy",
                "version": "0.72.0",
                "databaseDigest": digest(13),
                "javaDatabaseDigest": digest(14),
            },
            "sbomScanner": {"name": "syft", "version": "1.48.0"},
            "signatureProbe": {
                "name": "cosign",
                "version": "3.1.1",
                "trustedRootDigest": digest(15),
                "offlineVerification": False,
            },
            "rawArtifactsRestricted": True,
        }
        subjects = []
        for index, (subject_id, binding) in enumerate(
            expected_subjects(self.artifacts).items(), start=1
        ):
            counts = {
                "CRITICAL": 0,
                "HIGH": 1 if subject_id == blocked_subject else 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0,
            }
            fixed = dict(counts)
            vulnerabilities = {
                "total": sum(counts.values()),
                "bySeverity": counts,
                "fixAvailableBySeverity": fixed,
                "scanTargetCount": 1,
                "thresholdState": (
                    "blocked" if subject_id == blocked_subject else "passed"
                ),
            }
            signature = {
                "status": "no-signature-found",
                "indexSubject": binding["indexSubject"],
                "probeDigest": digest(20 + index),
            }
            raw_artifacts = {
                "vulnerability": {
                    "fileName": f"{subject_id}.trivy.json",
                    "digest": digest(30 + index),
                },
                "sbom": {
                    "fileName": f"{subject_id}.spdx.json",
                    "digest": digest(40 + index),
                },
            }
            licenses = {
                "packageCount": 1,
                "expressions": [binding["declaredLicense"]],
                "noAssertionCount": 0,
                "noneCount": 0,
                "inventoryDigest": digest(50 + index),
                "humanReviewState": "required",
            }
            control_states = [
                {
                    "id": control["id"],
                    "requiredBefore": control["requiredBefore"],
                    "status": "declared-not-proven",
                }
                for control in CONTROL_PLAN
            ]
            controls = {
                "planDigest": canonical_digest(
                    {
                        "subject": binding["indexSubject"],
                        "controls": control_states,
                    }
                ),
                "controls": control_states,
            }
            state, reasons = expected_machine_review(vulnerabilities)
            review_payload = {
                "indexSubject": binding["indexSubject"],
                "platformSubject": binding["platformSubject"],
                "signatureObservation": signature,
                "artifacts": raw_artifacts,
                "vulnerabilities": vulnerabilities,
                "licenses": licenses,
                "compensatingControls": controls,
                "collectionStatementDigest": collection["collectionStatementDigest"],
            }
            subjects.append(
                {
                    "id": subject_id,
                    **binding,
                    "signatureObservation": signature,
                    "artifacts": raw_artifacts,
                    "vulnerabilities": vulnerabilities,
                    "licenses": licenses,
                    "compensatingControls": controls,
                    "machineReview": {
                        "state": state,
                        "reasonCodes": reasons,
                        "reviewDigest": canonical_digest(review_payload),
                    },
                }
            )
        model = self.artifacts["models"][0]
        if model_license_review_complete:
            license_review = {
                "state": "complete",
                "reviewerIdentityDigest": digest(70),
                "reviewDigest": digest(71),
            }
        else:
            license_review = {
                "state": "required",
                "reviewerIdentityDigest": None,
                "reviewDigest": None,
            }
        model_artifact = {
            "id": model["id"],
            "immutableUrl": model["immutableUrl"],
            "revision": model["revision"],
            "expectedDigest": model["digest"],
            "observedDigest": model["digest"],
            "expectedSizeBytes": model["sizeBytes"],
            "observedSizeBytes": model["sizeBytes"],
            "declaredLicense": model["license"],
            "bytesVerified": True,
            "contentLengthVerified": True,
            "verificationDigest": None,
            "licenseReview": license_review,
        }
        model_artifact["verificationDigest"] = canonical_digest(
            {
                key: model_artifact[key]
                for key in model_artifact
                if key != "verificationDigest"
            }
        )
        threshold_passed = sum(
            item["vulnerabilities"]["thresholdState"] == "passed"
            for item in subjects
        )
        eligible = sum(
            item["machineReview"]["state"] == "eligible-for-human-review"
            for item in subjects
        )
        return {
            "schemaVersion": 1,
            "kind": "orchestra.openshift.sno-trial-dependency-risk-evidence.v1",
            "evidenceId": "orchestra-sno-trial-dependency-risk-evidence-test.1",
            "profileId": "orchestra-ocp-sno-trial-amd64-v1",
            "targetClass": "engineering-trial",
            "executionMode": "live",
            "bindings": {
                **expected_bindings(self.artifacts, self.release_set),
                "riskPolicyDigest": EXPECTED_POLICY_DIGEST,
            },
            "collection": collection,
            "subjects": subjects,
            "modelArtifact": model_artifact,
            "claims": {
                "allSubjectsCollected": True,
                "vulnerabilityThresholdPassedCount": threshold_passed,
                "eligibleForHumanReviewCount": eligible,
                "modelIntegrityVerified": True,
                "modelLicenseReviewComplete": model_license_review_complete,
                "containerLicenseReviewsComplete": False,
                "exceptionsApproved": False,
                "sourceAdmissionAuthorized": False,
                "mirrorAuthorization": False,
                "activationAuthorized": False,
                "deploymentAuthorized": False,
                "campaignEvidence": False,
                "referenceProfileVerified": False,
            },
        }

    def populate_subject(
        self,
        intake: dict,
        evidence: dict,
        subject_index: int,
        *,
        approved: bool,
    ) -> None:
        if intake["custody"]["status"] == "verification-required":
            intake["custody"] = {
                "status": "verified",
                "verificationId": (
                    "orchestra-sno-trial-dependency-risk-"
                    "custody-verification-test.1"
                ),
                "evidenceId": evidence["evidenceId"],
                "reportDigest": digest(200),
                "signatureBundleDigest": digest(201),
                "verificationSigningPublicKeyDigest": digest(202),
                "riskEvidenceDigest": digest(203),
                "riskEvidenceCanonicalDigest": canonical_digest(evidence),
                "verifierIdentityDigest": digest(204),
                "verifiedAt": "2026-07-28T01:15:00Z",
            }
        item = intake["subjects"][subject_index]
        risk_subject = {entry["id"]: entry for entry in evidence["subjects"]}[
            item["id"]
        ]
        item["evidence"] = {
            "riskEvidenceDigest": canonical_digest(evidence),
            "collectionStatementDigest": evidence["collection"][
                "collectionStatementDigest"
            ],
            "collectionSignatureBundleDigest": evidence["collection"][
                "collectionSignatureBundleDigest"
            ],
            "runnerImageDigest": evidence["collection"]["runnerImageDigest"],
            "runnerToolchainDigest": evidence["collection"]["runnerToolchainDigest"],
            "signatureProbeDigest": risk_subject["signatureObservation"]["probeDigest"],
            "sbomDigest": risk_subject["artifacts"]["sbom"]["digest"],
            "vulnerabilityReportDigest": risk_subject["artifacts"]["vulnerability"][
                "digest"
            ],
            "licenseInventoryDigest": risk_subject["licenses"]["inventoryDigest"],
            "machineReviewDigest": risk_subject["machineReview"]["reviewDigest"],
            "licenseReviewDigest": digest(80 + subject_index),
            "riskReviewDigest": digest(90 + subject_index),
            "compensatingControlsDigest": risk_subject["compensatingControls"][
                "planDigest"
            ],
        }
        item["request"] = {
            "status": "approved" if approved else "review-pending",
            "exceptionId": (
                "orchestra-sno-trial-dependency-signature-exception-"
                f"test.{subject_index}"
            ),
            "requestedAt": "2026-07-28T01:30:00Z",
            "requestorIdentityDigest": digest(100 + subject_index),
            "candidateDigest": None,
        }
        candidate = exception_candidate_digest(intake, item)
        item["request"]["candidateDigest"] = candidate
        if not approved:
            item["approvals"] = []
            item["decision"] = {
                "status": "required-not-approved",
                "approvedAt": None,
                "expiresAt": None,
                "approvalDigest": None,
            }
            item["sourceAdmissionState"] = "blocked"
            item["reasonCodes"] = ["INDEPENDENT_REVIEWS_MISSING"]
            return
        approvals = [
            {
                "role": "security-reviewer",
                "reviewerIdentityDigest": digest(120 + subject_index),
                "decision": "approve",
                "decidedAt": "2026-07-28T02:00:00Z",
                "candidateDigest": candidate,
                "signatureBundleDigest": digest(140 + subject_index),
            },
            {
                "role": "service-owner",
                "reviewerIdentityDigest": digest(160 + subject_index),
                "decision": "approve",
                "decidedAt": "2026-07-28T02:10:00Z",
                "candidateDigest": candidate,
                "signatureBundleDigest": digest(180 + subject_index),
            },
        ]
        item["approvals"] = approvals
        item["decision"] = {
            "status": "approved",
            "approvedAt": "2026-07-28T02:15:00Z",
            "expiresAt": "2026-08-27T02:15:00Z",
            "approvalDigest": exception_approval_digest(candidate, approvals),
        }
        item["sourceAdmissionState"] = (
            "exception-approved-pending-artifact-set-reissue"
        )
        item["reasonCodes"] = [
            "ARTIFACT_SET_REISSUE_REQUIRED",
            "MIRRORING_NOT_AUTHORIZED",
            "ACTIVATION_NOT_AUTHORIZED",
        ]

    def finalize_summary(self, intake: dict, evidence: dict | None) -> None:
        claims, admission = expected_intake_summary(
            intake["subjects"],
            evidence,
            custody_verified=intake["custody"]["status"] == "verified",
        )
        intake["claims"] = claims
        intake["admission"] = admission

    def test_locked_policy_and_empty_template_are_stable(self) -> None:
        self.assertEqual(
            validate_policy(self.policy, self.artifacts, self.release_set),
            EXPECTED_POLICY_DIGEST,
        )
        self.assertEqual(
            validate_exception_intake(
                self.template,
                self.artifacts,
                self.release_set,
                require_template_digest=True,
            ),
            EXPECTED_EXCEPTION_TEMPLATE_DIGEST,
        )
        collector = (
            ROOT / "scripts" / "collect_sno_trial_dependency_risk_evidence.sh"
        )
        self.assertEqual(
            self.policy["collectionPolicy"]["collectorScriptDigest"],
            blob_digest(collector.read_bytes()),
        )

    def test_default_validation_and_protected_workflow_include_the_lane(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        collection = (
            ROOT / ".github" / "workflows" / "dependency-risk-collection.yml"
        ).read_text(encoding="utf-8")
        validation = "scripts/sno_trial_dependency_risk.py validate-policy"
        self.assertIn(validation, makefile)
        self.assertIn(validation, ci)
        self.assertIn("sno-trial-dependencies", collection)
        self.assertIn(
            "scripts/collect_sno_trial_dependency_risk_evidence.sh",
            collection,
        )
        self.assertIn("ORCHESTRA_CERTIFICATION_RUNNER_IMAGE", collection)

    def test_evidence_is_valid_but_never_authorizes_activation(self) -> None:
        evidence = self.evidence()
        self.assertTrue(
            validate_risk_evidence(evidence, self.artifacts, self.release_set).startswith(
                "sha256:"
            )
        )
        for claim in (
            "sourceAdmissionAuthorized",
            "mirrorAuthorization",
            "activationAuthorized",
            "deploymentAuthorized",
            "campaignEvidence",
            "referenceProfileVerified",
        ):
            self.assertFalse(evidence["claims"][claim])

    def test_builder_derives_payload_free_evidence_from_raw_reports(self) -> None:
        expected = expected_subjects(self.artifacts)
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            subjects = []
            for index, (subject_id, binding) in enumerate(expected.items(), start=1):
                vulnerability = {
                    "SchemaVersion": 2,
                    "ArtifactName": binding["platformSubject"],
                    "ArtifactType": "container_image",
                    "Results": [
                        {
                            "Target": f"{subject_id} (linux)",
                            "Class": "os-pkgs",
                            "Type": "linux",
                            "Vulnerabilities": [],
                        }
                    ],
                }
                sbom = {
                    "spdxVersion": "SPDX-2.3",
                    "dataLicense": "CC0-1.0",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": subject_id,
                    "documentNamespace": f"https://example.invalid/{subject_id}",
                    "creationInfo": {
                        "created": "2026-07-28T00:30:00Z",
                        "creators": ["Tool: syft-1.48.0"],
                    },
                    "documentDescribes": ["SPDXRef-Package-1"],
                    "packages": [
                        {
                            "SPDXID": "SPDXRef-Package-1",
                            "name": f"package-{index}",
                            "versionInfo": "1.0.0",
                            "licenseDeclared": binding["declaredLicense"],
                            "licenseConcluded": "NOASSERTION",
                        }
                    ],
                }
                signature_probe = {
                    "schemaVersion": 1,
                    "kind": "orchestra.openshift.sno-trial-upstream-signature-probe.v1",
                    "indexSubject": binding["indexSubject"],
                    "status": "no-signature-found",
                    "cosignVersion": "3.1.1",
                    "cosignExitCode": 1,
                    "rawOutputDigest": digest(200 + index),
                    "observedAt": "2026-07-28T00:20:00Z",
                }
                files = {
                    "vulnerability": (
                        f"{subject_id}.trivy.json",
                        json.dumps(vulnerability, sort_keys=True).encode(),
                    ),
                    "sbom": (
                        f"{subject_id}.spdx.json",
                        json.dumps(sbom, sort_keys=True).encode(),
                    ),
                    "signature": (
                        f"{subject_id}.signature.json",
                        json.dumps(signature_probe, sort_keys=True).encode(),
                    ),
                }
                for _, (name, content) in files.items():
                    (directory / name).write_bytes(content)
                subjects.append(
                    {
                        "id": subject_id,
                        "indexSubject": binding["indexSubject"],
                        "platformSubject": binding["platformSubject"],
                        "vulnerabilityReportFile": files["vulnerability"][0],
                        "vulnerabilityReportDigest": blob_digest(
                            files["vulnerability"][1]
                        ),
                        "sbomFile": files["sbom"][0],
                        "sbomDigest": blob_digest(files["sbom"][1]),
                        "signatureProbeFile": files["signature"][0],
                        "signatureProbeDigest": blob_digest(files["signature"][1]),
                    }
                )
            fixture = self.evidence(model_license_review_complete=False)
            model_artifact = dict(fixture["modelArtifact"])
            model_artifact.pop("verificationDigest")
            manifest = {
                "schemaVersion": 1,
                "kind": "orchestra.openshift.sno-trial-dependency-risk-collection-manifest.v1",
                "evidenceId": fixture["evidenceId"],
                "profileId": fixture["profileId"],
                "targetClass": fixture["targetClass"],
                "executionMode": fixture["executionMode"],
                "bindings": fixture["bindings"],
                "collection": fixture["collection"],
                "subjects": subjects,
                "modelArtifact": model_artifact,
            }
            built = build_evidence(
                manifest,
                directory,
                self.artifacts,
                self.release_set,
            )
            self.assertEqual(built["claims"]["eligibleForHumanReviewCount"], 2)
            self.assertFalse(built["claims"]["modelLicenseReviewComplete"])
            self.assertNotIn("packages", built["subjects"][0]["licenses"])

    def test_high_finding_blocks_exception_review(self) -> None:
        evidence = self.evidence(blocked_subject="valkey-image")
        validate_risk_evidence(evidence, self.artifacts, self.release_set)
        intake = copy.deepcopy(self.template)
        self.populate_subject(intake, evidence, 0, approved=False)
        self.populate_subject(intake, evidence, 1, approved=False)
        self.finalize_summary(intake, evidence)
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_exception_machine_review_blocked:valkey-image"
        ):
            validate_exception_intake(
                intake,
                self.artifacts,
                self.release_set,
                evidence,
                intake["custody"],
                now=self.assessed_at,
            )

    def test_unknown_license_requires_explicit_review_digest(self) -> None:
        evidence = self.evidence()
        intake = copy.deepcopy(self.template)
        self.populate_subject(intake, evidence, 0, approved=False)
        self.populate_subject(intake, evidence, 1, approved=False)
        intake["subjects"][0]["evidence"]["licenseReviewDigest"] = None
        self.finalize_summary(intake, evidence)
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_exception_review_digest_invalid"
        ):
            validate_exception_intake(
                intake,
                self.artifacts,
                self.release_set,
                evidence,
                intake["custody"],
                now=self.assessed_at,
            )

    def test_stale_evidence_is_rejected(self) -> None:
        evidence = self.evidence()
        intake = copy.deepcopy(self.template)
        for index in range(2):
            self.populate_subject(intake, evidence, index, approved=False)
        self.finalize_summary(intake, evidence)
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_exception_risk_evidence_stale"
        ):
            validate_exception_intake(
                intake,
                self.artifacts,
                self.release_set,
                evidence,
                intake["custody"],
                now=datetime(2026, 8, 1, 2, tzinfo=timezone.utc),
            )

    def test_requestor_collector_and_duplicate_reviewer_are_rejected(self) -> None:
        evidence = self.evidence()
        for identity_source in ("requestor", "collector", "duplicate"):
            with self.subTest(identity_source=identity_source):
                intake = copy.deepcopy(self.template)
                for index in range(2):
                    self.populate_subject(intake, evidence, index, approved=True)
                item = intake["subjects"][0]
                if identity_source == "requestor":
                    item["approvals"][0]["reviewerIdentityDigest"] = item["request"][
                        "requestorIdentityDigest"
                    ]
                elif identity_source == "collector":
                    item["approvals"][0]["reviewerIdentityDigest"] = evidence[
                        "collection"
                    ]["actorIdentityDigest"]
                else:
                    item["approvals"][1]["reviewerIdentityDigest"] = item["approvals"][
                        0
                    ]["reviewerIdentityDigest"]
                self.finalize_summary(intake, evidence)
                with self.assertRaisesRegex(
                    ValueError, "sno_dependency_exception_approval_independence_invalid"
                ):
                    validate_exception_intake(
                        intake,
                        self.artifacts,
                        self.release_set,
                        evidence,
                        intake["custody"],
                        now=self.assessed_at,
                    )

    def test_approved_exceptions_remain_non_authorizing(self) -> None:
        evidence = self.evidence()
        intake = copy.deepcopy(self.template)
        for index in range(2):
            self.populate_subject(intake, evidence, index, approved=True)
        self.finalize_summary(intake, evidence)
        validate_exception_intake(
            intake,
            self.artifacts,
            self.release_set,
            evidence,
            intake["custody"],
            now=self.assessed_at,
        )
        self.assertTrue(intake["claims"]["allExceptionsApproved"])
        self.assertEqual(intake["admission"]["status"], "blocked")
        self.assertIn(
            "ARTIFACT_SET_REISSUE_REQUIRED", intake["admission"]["reasonCodes"]
        )
        for claim in (
            "sourceAdmissionAuthorized",
            "mirrorAuthorization",
            "activationAuthorized",
            "deploymentAuthorized",
            "campaignEvidence",
            "referenceProfileVerified",
        ):
            self.assertFalse(intake["claims"][claim])

    def test_expired_or_overlong_exception_is_rejected(self) -> None:
        evidence = self.evidence()
        intake = copy.deepcopy(self.template)
        for index in range(2):
            self.populate_subject(intake, evidence, index, approved=True)
        intake["subjects"][0]["decision"]["expiresAt"] = "2026-09-01T02:15:00Z"
        self.finalize_summary(intake, evidence)
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_exception_approved_state_invalid"
        ):
            validate_exception_intake(
                intake,
                self.artifacts,
                self.release_set,
                evidence,
                intake["custody"],
                now=self.assessed_at,
            )

    def test_populated_review_requires_exact_verified_custody(self) -> None:
        evidence = self.evidence()
        intake = copy.deepcopy(self.template)
        for index in range(2):
            self.populate_subject(intake, evidence, index, approved=False)
        self.finalize_summary(intake, evidence)
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_exception_custody_required"
        ):
            validate_exception_intake(
                intake,
                self.artifacts,
                self.release_set,
                evidence,
                now=self.assessed_at,
            )
        changed = copy.deepcopy(intake["custody"])
        changed["reportDigest"] = digest(999)
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_exception_custody_binding_invalid"
        ):
            validate_exception_intake(
                intake,
                self.artifacts,
                self.release_set,
                evidence,
                changed,
                now=self.assessed_at,
            )

    def test_reviewer_candidate_digest_binds_verified_custody(self) -> None:
        evidence = self.evidence()
        intake = copy.deepcopy(self.template)
        for index in range(2):
            self.populate_subject(intake, evidence, index, approved=False)
        self.finalize_summary(intake, evidence)
        intake["custody"]["reportDigest"] = digest(999)
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_exception_candidate_digest_invalid"
        ):
            validate_exception_intake(
                intake,
                self.artifacts,
                self.release_set,
                evidence,
                intake["custody"],
                now=self.assessed_at,
            )

    def test_custody_chronology_precedes_every_review(self) -> None:
        evidence = self.evidence()
        intake = copy.deepcopy(self.template)
        for index in range(2):
            self.populate_subject(intake, evidence, index, approved=False)
        self.finalize_summary(intake, evidence)

        before_collection = copy.deepcopy(intake)
        before_collection["custody"]["verifiedAt"] = "2026-07-28T00:59:59Z"
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_exception_custody_time_invalid"
        ):
            validate_exception_intake(
                before_collection,
                self.artifacts,
                self.release_set,
                evidence,
                before_collection["custody"],
                now=self.assessed_at,
            )

        before_custody = copy.deepcopy(intake)
        before_custody["subjects"][0]["request"]["requestedAt"] = (
            "2026-07-28T01:14:59Z"
        )
        with self.assertRaisesRegex(
            ValueError,
            "sno_dependency_exception_custody_time_invalid:model-backend-image",
        ):
            validate_exception_intake(
                before_custody,
                self.artifacts,
                self.release_set,
                evidence,
                before_custody["custody"],
                now=self.assessed_at,
            )

    def test_model_digest_size_and_license_review_are_bound(self) -> None:
        evidence = self.evidence(model_license_review_complete=False)
        validate_risk_evidence(evidence, self.artifacts, self.release_set)
        self.assertFalse(evidence["claims"]["modelLicenseReviewComplete"])
        changed = copy.deepcopy(evidence)
        changed["modelArtifact"]["observedSizeBytes"] += 1
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_risk_model_verification_invalid"
        ):
            validate_risk_evidence(changed, self.artifacts, self.release_set)

    def test_policy_and_evidence_binding_drift_are_rejected(self) -> None:
        changed_policy = copy.deepcopy(self.policy)
        changed_policy["bindings"]["artifactSetDigest"] = digest(999)
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_risk_policy_identity_invalid"
        ):
            validate_policy(changed_policy, self.artifacts, self.release_set)
        evidence = self.evidence()
        evidence["subjects"][0]["indexSubject"] = (
            "ghcr.io/ggml-org/llama.cpp@" + digest(998)
        )
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_risk_subject_binding_invalid"
        ):
            validate_risk_evidence(evidence, self.artifacts, self.release_set)

    def test_claim_escalation_is_rejected(self) -> None:
        evidence = self.evidence()
        evidence["claims"]["activationAuthorized"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_risk_evidence_claims_invalid"
        ):
            validate_risk_evidence(evidence, self.artifacts, self.release_set)

    def test_schemas_are_closed_and_accept_contracts(self) -> None:
        policy_schema = load_json(
            ROOT / "schemas" / "sno-trial-dependency-risk-policy-v1.schema.json"
        )
        evidence_schema = load_json(
            ROOT / "schemas" / "sno-trial-dependency-risk-evidence-v1.schema.json"
        )
        exception_schema = load_json(
            ROOT
            / "schemas"
            / "sno-trial-dependency-signature-exceptions-v1.schema.json"
        )
        for schema in (policy_schema, evidence_schema, exception_schema):
            assert_strict_object_schemas(self, schema)
        fixtures = (
            (
                ROOT / "schemas" / "sno-trial-dependency-risk-policy-v1.schema.json",
                self.policy,
            ),
            (
                ROOT / "schemas" / "sno-trial-dependency-risk-evidence-v1.schema.json",
                self.evidence(),
            ),
            (
                ROOT
                / "schemas"
                / "sno-trial-dependency-signature-exceptions-v1.schema.json",
                self.template,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, (schema_path, value) in enumerate(fixtures):
                with self.subTest(schema=schema_path.name):
                    fixture_path = Path(directory) / f"fixture-{index}.json"
                    fixture_path.write_text(
                        json.dumps(value, sort_keys=True),
                        encoding="utf-8",
                    )
                    completed = subprocess.run(
                        [
                            "npx",
                            "--yes",
                            "ajv-cli@5.0.0",
                            "validate",
                            "--spec=draft2020",
                            "--strict=false",
                            f"-s={schema_path}",
                            f"-d={fixture_path}",
                        ],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
