from __future__ import annotations

import copy
import unittest

from scripts.production_model_artifact_custody import (
    CUSTODY_CLAIMS,
    CUSTODY_CONTROLS,
    REVIEW_ATTESTATION,
    REVIEW_CLAIMS,
    REVIEW_SCHEMA_PATH,
    CUSTODY_SCHEMA_PATH,
    digest_without_field,
    expected_artifacts,
    load_contract_inputs,
    validate_custody_record,
    validate_policy,
    validate_review_decision,
    validate_review_set,
)
from scripts.validate_repository import ROOT, canonical_digest, load_json


class ProductionModelArtifactCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        (
            self.candidate,
            self.source_policy,
            self.policy,
            self.custody_schema,
            self.review_schema,
        ) = load_contract_inputs()
        validate_policy(
            self.policy,
            self.candidate,
            self.source_policy,
            self.custody_schema,
            self.review_schema,
        )
        self.custody = self.valid_custody_record()

    @staticmethod
    def identity(seed: str) -> str:
        return f"sha256:{seed * 64}"

    @staticmethod
    def resign(value: dict[str, object], field: str) -> None:
        value[field] = digest_without_field(value, field)

    def valid_custody_record(self) -> dict[str, object]:
        record_id = "production-model-custody-fixture.1"
        prefix = (
            "production-model-artifacts/v1/"
            "orchestra-ocp-4.20-amd64-v1/"
            f"{record_id}"
        )
        artifacts = []
        for index, source in enumerate(expected_artifacts(self.candidate), start=1):
            artifacts.append(
                {
                    "artifactId": source["artifactId"],
                    "serviceId": source["serviceId"],
                    "filename": source["filename"],
                    "revision": source["revision"],
                    "expectedDigest": source["digest"],
                    "expectedSizeBytes": source["sizeBytes"],
                    "object": {
                        "name": f"{prefix}/{source['filename']}",
                        "generation": str(index),
                        "metageneration": "1",
                        "sizeBytes": source["sizeBytes"],
                        "crc32c": "AAAAAA==",
                        "contentDigest": source["digest"],
                        "kmsKeyVersion": (
                            "projects/orchestra-services-12345/locations/"
                            "europe-west1/keyRings/orchestra-reference-evidence/"
                            "cryptoKeys/production-model-artifact-custody/"
                            "cryptoKeyVersions/1"
                        ),
                        "eventBasedHold": True,
                        "temporaryHold": False,
                        "timeCreated": "2026-07-28T01:00:00Z",
                        "updated": "2026-07-28T01:00:01Z",
                    },
                    "verification": {
                        "generationPinnedRead": True,
                        "metagenerationPinnedRead": True,
                        "exactSizeMatched": True,
                        "expectedDigestMatched": True,
                        "objectMetadataStable": True,
                        "verifiedAt": "2026-07-28T01:05:00Z",
                    },
                }
            )
        value: dict[str, object] = {
            "schemaVersion": 1,
            "kind": (
                "orchestra.openshift."
                "production-model-artifact-custody-record.v1"
            ),
            "recordId": record_id,
            "profileId": "orchestra-ocp-4.20-amd64-v1",
            "targetClass": "vendor-reference-lab",
            "executionMode": "live",
            "bindings": {
                "candidateId": self.candidate["candidateId"],
                "candidateDigest": self.candidate["candidateDigest"],
                "sourceIntakePolicyDigest": self.source_policy["policyDigest"],
                "sourceObservationId": "production-model-intake-fixture.1",
                "sourceObservationDigest": self.identity("a"),
                "sourceObservationObservedAt": "2026-07-28T00:30:00Z",
                "custodyPolicyId": self.policy["policyId"],
                "custodyPolicyDigest": self.policy["policyDigest"],
                "custodyRecordSchemaDigest": canonical_digest(self.custody_schema),
            },
            "storage": {
                "projectPlane": "services-evidence",
                "bucket": "orchestra-model-artifacts-fixture",
                "managedFolder": "production-model-artifacts/",
                "prefix": prefix,
                "cmekRequired": True,
                "uniformBucketLevelAccess": True,
                "publicAccessPrevention": "enforced",
                "versioningEnabled": True,
                "objectRetentionEnabled": True,
                "createOnlyGenerationPrecondition": 0,
            },
            "publication": {
                "bucket": "orchestra-signed-evidence-fixture",
                "managedFolder": "production-model-custody/",
                "prefix": (
                    "production-model-custody/v1/"
                    "orchestra-ocp-4.20-amd64-v1/"
                    f"{record_id}"
                ),
                "recordObject": "production-model-artifact-custody-record.json",
                "publicKeyObject": (
                    "production-model-artifact-custody-public-key.pem"
                ),
                "completionMarker": (
                    "production-model-artifact-custody-signature.sigstore.json"
                ),
                "createOnlyGenerationPrecondition": 0,
                "completionMarkerUploadedLast": True,
            },
            "artifacts": artifacts,
            "actors": {
                "uploaderIdentityDigest": self.identity("b"),
                "verifierIdentityDigest": self.identity("c"),
                "identitiesDistinct": True,
                "uploaderServiceAccountId": "orchestra-model-custody-writer",
                "verifierServiceAccountId": "orchestra-model-custody-verifier",
            },
            "timestamps": {
                "copyStartedAt": "2026-07-28T00:59:00Z",
                "copyCompletedAt": "2026-07-28T01:01:00Z",
                "verifiedAt": "2026-07-28T01:06:00Z",
            },
            "controls": copy.deepcopy(CUSTODY_CONTROLS),
            "claims": copy.deepcopy(CUSTODY_CLAIMS),
            "recordDigest": self.identity("0"),
        }
        self.resign(value, "recordDigest")
        return value

    def valid_review(
        self, role: str, identity_seed: str, decision: str = "APPROVED"
    ) -> dict[str, object]:
        artifacts = []
        for index, source in enumerate(expected_artifacts(self.candidate), start=1):
            artifact_decision = (
                "REJECTED" if decision == "REJECTED" and index == 1 else "APPROVED"
            )
            artifacts.append(
                {
                    "artifactId": source["artifactId"],
                    "declaredLicense": source["declaredLicense"],
                    "licenseTextDigest": self.identity(str(index)),
                    "modelCardDigest": self.identity(str(index + 2)),
                    "usageRestrictions": ["NONE_IDENTIFIED"],
                    "decision": artifact_decision,
                    "reasonCodes": (
                        ["TERMS_NOT_ACCEPTABLE"]
                        if artifact_decision == "REJECTED"
                        else []
                    ),
                }
            )
        value: dict[str, object] = {
            "schemaVersion": 1,
            "kind": (
                "orchestra.openshift."
                "production-model-license-review-decision.v1"
            ),
            "reviewId": f"production-model-license-review-{role}.fixture",
            "profileId": "orchestra-ocp-4.20-amd64-v1",
            "targetClass": "vendor-reference-lab",
            "executionMode": "live-human-review",
            "bindings": {
                "candidateId": self.candidate["candidateId"],
                "candidateDigest": self.candidate["candidateDigest"],
                "custodyPolicyId": self.policy["policyId"],
                "custodyPolicyDigest": self.policy["policyDigest"],
                "custodyRecordId": self.custody["recordId"],
                "custodyRecordDigest": self.custody["recordDigest"],
                "reviewDecisionSchemaDigest": canonical_digest(self.review_schema),
            },
            "reviewer": {
                "role": role,
                "identityDigest": self.identity(identity_seed),
            },
            "artifactReviews": artifacts,
            "decision": decision,
            "reviewedAt": "2026-07-28T02:00:00Z",
            "attestation": copy.deepcopy(REVIEW_ATTESTATION),
            "claims": copy.deepcopy(REVIEW_CLAIMS),
            "reviewDigest": self.identity("0"),
        }
        self.resign(value, "reviewDigest")
        return value

    def test_policy_is_bound_and_non_live(self) -> None:
        digest = validate_policy(
            self.policy,
            self.candidate,
            self.source_policy,
            self.custody_schema,
            self.review_schema,
        )
        self.assertEqual(digest, self.policy["policyDigest"])
        self.assertEqual(
            self.policy["bindings"]["custodyRecordSchemaDigest"],
            canonical_digest(load_json(CUSTODY_SCHEMA_PATH)),
        )
        self.assertEqual(
            self.policy["bindings"]["reviewDecisionSchemaDigest"],
            canonical_digest(load_json(REVIEW_SCHEMA_PATH)),
        )
        self.assertEqual(self.policy["storage"]["provisioningState"], "not-declared")
        self.assertFalse(self.policy["claims"]["artifactCustodyVerified"])
        self.assertFalse(self.policy["claims"]["licenseApproved"])
        self.assertFalse(self.policy["claims"]["deploymentAuthorized"])

    def test_policy_drift_is_rejected_even_when_resigned(self) -> None:
        changed = copy.deepcopy(self.policy)
        changed["identities"]["uploaderObjectReadGranted"] = True
        self.resign(changed, "policyDigest")
        with self.assertRaisesRegex(ValueError, "identities_invalid"):
            validate_policy(
                changed,
                self.candidate,
                self.source_policy,
                self.custody_schema,
                self.review_schema,
            )

        changed = copy.deepcopy(self.policy)
        changed["licenseReview"]["minimumReviewers"] = 1
        self.resign(changed, "policyDigest")
        with self.assertRaisesRegex(ValueError, "license_review_invalid"):
            validate_policy(
                changed,
                self.candidate,
                self.source_policy,
                self.custody_schema,
                self.review_schema,
            )

    def test_schemas_are_strict_at_every_object_boundary(self) -> None:
        for schema in (self.custody_schema, self.review_schema):
            stack = [schema]
            while stack:
                value = stack.pop()
                if isinstance(value, list):
                    stack.extend(value)
                elif isinstance(value, dict):
                    if value.get("type") == "object":
                        self.assertIs(value.get("additionalProperties"), False)
                    stack.extend(value.values())

    def test_valid_record_binds_both_exact_artifacts(self) -> None:
        digest = validate_custody_record(
            self.custody, self.policy, self.candidate, self.custody_schema
        )
        self.assertEqual(digest, self.custody["recordDigest"])
        self.assertEqual(
            [artifact["artifactId"] for artifact in self.custody["artifacts"]],
            [
                "orchestra-reference-chat-model",
                "orchestra-reference-embedding-model",
            ],
        )

    def test_custody_rejects_object_substitution_and_unpinned_read(self) -> None:
        changed = copy.deepcopy(self.custody)
        changed["artifacts"][0]["object"]["contentDigest"] = self.identity("d")
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "object_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

        changed = copy.deepcopy(self.custody)
        changed["publication"]["completionMarkerUploadedLast"] = False
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "publication_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

        changed = copy.deepcopy(self.custody)
        changed["artifacts"][0]["verification"]["generationPinnedRead"] = False
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "verification_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

    def test_custody_rejects_identity_reuse_and_time_reversal(self) -> None:
        changed = copy.deepcopy(self.custody)
        changed["actors"]["verifierIdentityDigest"] = changed["actors"][
            "uploaderIdentityDigest"
        ]
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "actors_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

        changed = copy.deepcopy(self.custody)
        changed["actors"]["verifierIdentityDigest"] = None
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "actors_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

        changed = copy.deepcopy(self.custody)
        changed["timestamps"]["verifiedAt"] = "2026-07-28T00:58:00Z"
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "timestamp_order_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

        changed = copy.deepcopy(self.custody)
        changed["bindings"]["sourceObservationObservedAt"] = "2026-07-26T00:00:00Z"
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "timestamp_order_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

    def test_custody_record_cannot_claim_license_or_admission(self) -> None:
        changed = copy.deepcopy(self.custody)
        changed["claims"]["licenseApproved"] = True
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "claims_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

        changed = copy.deepcopy(self.custody)
        changed["claims"]["sourceAdmissionAuthorized"] = True
        self.resign(changed, "recordDigest")
        with self.assertRaisesRegex(ValueError, "claims_invalid"):
            validate_custody_record(
                changed, self.policy, self.candidate, self.custody_schema
            )

    def test_valid_single_review_still_cannot_claim_aggregate_approval(self) -> None:
        review = self.valid_review("model-risk-reviewer", "d")
        digest = validate_review_decision(
            review,
            self.policy,
            self.candidate,
            self.custody,
            self.review_schema,
        )
        self.assertEqual(digest, review["reviewDigest"])
        self.assertFalse(review["claims"]["aggregateLicenseApproval"])
        self.assertFalse(review["claims"]["sourceAdmissionAuthorized"])

    def test_review_rejects_custody_actor_and_automated_approval(self) -> None:
        changed = self.valid_review("model-risk-reviewer", "d")
        changed["reviewer"]["identityDigest"] = self.custody["actors"][
            "verifierIdentityDigest"
        ]
        self.resign(changed, "reviewDigest")
        with self.assertRaisesRegex(ValueError, "reviewer_invalid"):
            validate_review_decision(
                changed,
                self.policy,
                self.candidate,
                self.custody,
                self.review_schema,
            )

        changed = self.valid_review("model-risk-reviewer", "d")
        changed["attestation"]["automatedApproval"] = True
        self.resign(changed, "reviewDigest")
        with self.assertRaisesRegex(ValueError, "attestation_invalid"):
            validate_review_decision(
                changed,
                self.policy,
                self.candidate,
                self.custody,
                self.review_schema,
            )

    def test_review_rejects_inconsistent_decision_and_pre_custody_time(self) -> None:
        changed = self.valid_review("model-risk-reviewer", "d")
        changed["artifactReviews"][0]["decision"] = "REJECTED"
        changed["artifactReviews"][0]["reasonCodes"] = ["TERMS_NOT_ACCEPTABLE"]
        self.resign(changed, "reviewDigest")
        with self.assertRaisesRegex(ValueError, "decision_inconsistent"):
            validate_review_decision(
                changed,
                self.policy,
                self.candidate,
                self.custody,
                self.review_schema,
            )

        changed = self.valid_review("model-risk-reviewer", "d")
        changed["reviewedAt"] = "2026-07-28T00:00:00Z"
        self.resign(changed, "reviewDigest")
        with self.assertRaisesRegex(ValueError, "precedes_custody"):
            validate_review_decision(
                changed,
                self.policy,
                self.candidate,
                self.custody,
                self.review_schema,
            )

    def test_review_set_requires_both_roles_and_distinct_humans(self) -> None:
        risk = self.valid_review("model-risk-reviewer", "d")
        owner = self.valid_review("service-owner", "e")
        validate_review_set(
            [risk, owner],
            self.policy,
            self.candidate,
            self.custody,
            self.review_schema,
        )

        reused = self.valid_review("service-owner", "d")
        with self.assertRaisesRegex(ValueError, "identity_reuse"):
            validate_review_set(
                [risk, reused],
                self.policy,
                self.candidate,
                self.custody,
                self.review_schema,
            )

    def test_rejected_review_blocks_complete_review_set(self) -> None:
        risk = self.valid_review("model-risk-reviewer", "d")
        owner = self.valid_review("service-owner", "e", decision="REJECTED")
        with self.assertRaisesRegex(ValueError, "not_approved"):
            validate_review_set(
                [risk, owner],
                self.policy,
                self.candidate,
                self.custody,
                self.review_schema,
            )

    def test_checked_in_policy_contains_no_live_or_certification_claim(self) -> None:
        self.assertTrue(self.policy["claims"]["contractDeclared"])
        for name, value in self.policy["claims"].items():
            if name != "contractDeclared":
                self.assertFalse(value, name)
        self.assertFalse(self.policy["controls"]["artifactDownloadPerformed"])
        self.assertFalse(self.policy["controls"]["artifactCopyPerformed"])

    def test_default_validation_ci_and_docs_include_contract(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        runbook = (
            ROOT / "docs" / "runbooks" / "production-model-artifacts.md"
        ).read_text(encoding="utf-8")
        command = "scripts/production_model_artifact_custody.py validate-policy"
        self.assertIn(command, makefile)
        self.assertIn(command, workflow)
        self.assertIn("validate-production-model-artifact-custody", runbook)
        self.assertIn(self.policy["policyDigest"], runbook)


if __name__ == "__main__":
    unittest.main()
