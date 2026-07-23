from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.collect_foundation_observer_authority import collect
from scripts.foundation_apply_receipt import build_receipt
from scripts.foundation_observation import (
    EXPECTED_AUTHORITY_DIGEST,
    load_contract,
    validate_authority,
    validate_declared_implementation,
)
from scripts.foundation_observation_report import (
    build_report,
    validate_receipt_inventory,
    validate_report,
)
from scripts.foundation_plan_package import build_statement, file_digest
from scripts.foundation_plan_summary import build_summary
from scripts.validate_repository import ROOT, canonical_digest
from scripts.verify_foundation_plan_package import verify_package


class FoundationObservationTests(unittest.TestCase):
    revision = "a" * 40
    plan_id = "orchestra-foundation-plan-101.1"
    apply_id = "orchestra-foundation-apply-303.1"
    observation_id = "orchestra-foundation-observation-505.1"
    plan_key = (
        "gcpkms://projects/orchestra-services/locations/europe-west1/keyRings/"
        "orchestra-lab-foundation-execution/cryptoKeys/foundation-plan-signing/"
        "cryptoKeyVersions/1"
    )
    receipt_key = (
        "gcpkms://projects/orchestra-services/locations/europe-west1/keyRings/"
        "orchestra-lab-foundation-execution/cryptoKeys/"
        "foundation-apply-receipt-signing/cryptoKeyVersions/1"
    )
    observation_key = (
        "gcpkms://projects/orchestra-services/locations/europe-west1/keyRings/"
        "orchestra-lab-foundation-execution/cryptoKeys/"
        "foundation-observation-signing/cryptoKeyVersions/1"
    )

    @staticmethod
    def write_json(path: Path, value: dict) -> None:
        path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n",
            encoding="ascii",
        )

    @staticmethod
    def object_metadata(
        name: str,
        path: Path,
        generation: int,
        created_at: str,
    ) -> dict:
        return {
            "name": name,
            "generation": str(generation),
            "metageneration": "1",
            "sizeBytes": path.stat().st_size,
            "crc32c": "AAAAAA==",
            "md5Hash": "A" * 22 + "==",
            "etag": f"fixture-etag-{generation}",
            "timeCreated": created_at,
            "updated": created_at,
        }

    def make_report(self, work: Path) -> dict:
        plan = work / "foundation.tfplan"
        plan.write_bytes(b"opaque-saved-foundation-plan\n")
        plan_json = {
            "format_version": "1.2",
            "terraform_version": "1.14.6",
            "resource_changes": [
                {
                    "address": "google_compute_network.target",
                    "mode": "managed",
                    "type": "google_compute_network",
                    "provider_name": "registry.terraform.io/hashicorp/google",
                    "change": {"actions": ["create"]},
                }
            ],
        }
        plan_json_path = work / "foundation-plan.json"
        self.write_json(plan_json_path, plan_json)
        summary = build_summary(
            plan_json,
            plan_digest=file_digest(plan),
            prerequisite_projection_digest=f"sha256:{8:064x}",
            source_revision=self.revision,
            workflow_run_id="101",
            workflow_run_attempt="1",
            actor_id="202",
            reason="Review immutable foundation resources",
            execution_mode="live",
            created_at="2026-07-23T12:00:00Z",
        )
        summary_path = work / "foundation-plan-summary.json"
        self.write_json(summary_path, summary)
        plan_public_key = work / "foundation-plan-package-public-key.pem"
        plan_public_key.write_bytes(b"fixture-plan-public-key\n")
        statement = build_statement(
            plan_path=plan,
            summary_path=summary_path,
            bucket="orchestra-foundation-state-fixture",
            plan_id=self.plan_id,
            environment_approval_digest=f"sha256:{7:064x}",
            signing_key=self.plan_key,
            signing_public_key=plan_public_key,
            expected_public_key_digest=file_digest(plan_public_key),
            signed_at="2026-07-23T12:01:00Z",
        )
        statement_path = work / "foundation-plan-package-statement.json"
        self.write_json(statement_path, statement)
        plan_signature = work / "foundation-plan-package-signature.sigstore.json"
        plan_signature.write_text('{"fixture":"plan-signature"}\n', encoding="ascii")
        prefix = statement["package"]["prefix"]
        plan_paths = {
            "foundation.tfplan": plan,
            "foundation-plan-summary.json": summary_path,
            "foundation-plan-package-public-key.pem": plan_public_key,
            "foundation-plan-package-statement.json": statement_path,
            "foundation-plan-package-signature.sigstore.json": plan_signature,
        }
        plan_inventory = {
            "schemaVersion": 1,
            "bucket": "orchestra-foundation-state-fixture",
            "prefix": prefix,
            "objects": sorted(
                [
                    self.object_metadata(
                        f"{prefix}/{name}",
                        path,
                        1000 + index,
                        (
                            "2026-07-23T12:01:02Z"
                            if name
                            == "foundation-plan-package-signature.sigstore.json"
                            else "2026-07-23T12:01:01Z"
                        ),
                    )
                    for index, (name, path) in enumerate(
                        plan_paths.items(), start=1
                    )
                ],
                key=lambda item: item["name"],
            ),
        }
        plan_inventory_path = work / "plan-inventory.json"
        self.write_json(plan_inventory_path, plan_inventory)
        with patch("scripts.verify_foundation_plan_package.run_cosign"):
            verify_package(
                inventory_path=plan_inventory_path,
                download_dir=work,
                plan_json_path=plan_json_path,
                source_revision=self.revision,
                plan_id=self.plan_id,
                expected_statement_digest=file_digest(statement_path),
                expected_public_key_digest=file_digest(plan_public_key),
                verified_at="2026-07-23T12:02:00Z",
                output=work / "verified-package.json",
            )

        state_before = work / "state-before.json"
        state_after = work / "state-after.json"
        state_before.write_text(
            '{"lineage":"fixture-lineage","serial":4}\n', encoding="ascii"
        )
        state_after.write_text(
            '{"lineage":"fixture-lineage","serial":5}\n', encoding="ascii"
        )
        receipt_public_key = work / "foundation-apply-receipt-public-key.pem"
        receipt_public_key.write_bytes(b"fixture-receipt-public-key\n")
        receipt = build_receipt(
            verified_package_path=work / "verified-package.json",
            state_before_path=state_before,
            state_after_path=state_after,
            apply_id=self.apply_id,
            environment_approval_digest=f"sha256:{9:064x}",
            actor_id="404",
            reason="Apply exact independently reviewed foundation plan",
            source_revision=self.revision,
            workflow_run_id="303",
            workflow_run_attempt="1",
            started_at="2026-07-23T12:03:00Z",
            completed_at="2026-07-23T12:04:00Z",
            signing_key=self.receipt_key,
            signing_public_key=receipt_public_key,
            expected_public_key_digest=file_digest(receipt_public_key),
            expected_plan_statement_digest=file_digest(statement_path),
        )
        receipt_path = work / "foundation-apply-receipt.json"
        self.write_json(receipt_path, receipt)
        receipt_signature = (
            work / "foundation-apply-receipt-signature.sigstore.json"
        )
        receipt_signature.write_text(
            '{"fixture":"receipt-signature"}\n', encoding="ascii"
        )
        receipt_prefix = (
            f"foundation-apply-reports/v1/orchestra-ocp-4.20-amd64-v1/"
            f"{self.revision}/{self.plan_id}/{self.apply_id}"
        )
        receipt_paths = {
            "foundation-apply-receipt.json": receipt_path,
            "foundation-apply-receipt-public-key.pem": receipt_public_key,
            "foundation-apply-receipt-signature.sigstore.json": receipt_signature,
        }
        receipt_inventory = {
            "schemaVersion": 1,
            "bucket": "orchestra-foundation-state-fixture",
            "prefix": receipt_prefix,
            "objects": sorted(
                [
                    self.object_metadata(
                        f"{receipt_prefix}/{name}",
                        path,
                        2000 + index,
                        (
                            "2026-07-23T12:04:02Z"
                            if name
                            == "foundation-apply-receipt-signature.sigstore.json"
                            else "2026-07-23T12:04:01Z"
                        ),
                    )
                    for index, (name, path) in enumerate(
                        receipt_paths.items(), start=1
                    )
                ],
                key=lambda item: item["name"],
            ),
        }
        receipt_inventory_path = work / "receipt-inventory.json"
        self.write_json(receipt_inventory_path, receipt_inventory)

        state_object = work / "state-object.json"
        state_pull = work / "state-pull.json"
        state_object.write_bytes(state_after.read_bytes())
        state_pull.write_bytes(state_after.read_bytes())
        state_metadata = self.object_metadata(
            "foundation/default.tfstate",
            state_object,
            3001,
            "2026-07-23T12:04:03Z",
        )
        state_before_metadata = work / "state-metadata-before.json"
        state_after_metadata = work / "state-metadata-after.json"
        self.write_json(state_before_metadata, state_metadata)
        self.write_json(state_after_metadata, state_metadata)
        refresh_plan = {
            "format_version": "1.2",
            "terraform_version": "1.14.6",
            "resource_changes": [
                {
                    "address": "google_compute_network.target",
                    "mode": "managed",
                    "type": "google_compute_network",
                    "provider_name": "registry.terraform.io/hashicorp/google",
                    "change": {"actions": ["no-op"]},
                }
            ],
        }
        refresh_plan_path = work / "refresh-plan.json"
        self.write_json(refresh_plan_path, refresh_plan)
        observation_public_key = work / "foundation-observation-public-key.pem"
        observation_public_key.write_bytes(b"fixture-observation-public-key\n")
        observer_authority_observation = {
            "schemaVersion": 1,
            "kind": (
                "orchestra.reference-lab."
                "foundation-observer-authority-observation.v1"
            ),
            "serviceAccount": (
                "orchestra-foundation-observer@orchestra-services."
                "iam.gserviceaccount.com"
            ),
            "provider": (
                "projects/123456789/locations/global/workloadIdentityPools/"
                "orchestra-lab-github/providers/foundation-observation"
            ),
            "checks": {
                "providerConditionExact": True,
                "impersonationBindingExact": True,
                "noUserManagedKeys": True,
                "targetProjectRolesExact": True,
                "servicesProjectRolesExact": True,
                "customStorageRoleExact": True,
                "directAncestorBindingsExact": True,
                "storageRolesExact": True,
                "kmsRolesExact": True,
            },
            "evidenceDigests": {
                name: f"sha256:{index:064x}"
                for index, name in enumerate(
                    (
                        "provider",
                        "serviceAccount",
                        "serviceAccountPolicy",
                        "userManagedKeys",
                        "targetProjectPolicy",
                        "servicesProjectPolicy",
                        "customStorageRole",
                        "ancestorPolicies",
                        "stateBucketPolicy",
                        "stateFolderPolicy",
                        "planFolderPolicy",
                        "receiptFolderPolicy",
                        "observationFolderPolicy",
                        "planKeyPolicy",
                        "receiptKeyPolicy",
                        "observationKeyPolicy",
                    ),
                    start=1,
                )
            },
            "claims": {
                "directReadOnlyBoundaryObserved": True,
                "infrastructureMutationGranted": False,
                "sourceObjectMutationGranted": False,
                "reportReadGranted": False,
                "reportCreateOnlyGranted": True,
                "artifactMirrorWriteGranted": False,
                "campaignAuthorityGranted": False,
            },
        }
        observer_authority_path = work / "observer-authority.json"
        self.write_json(
            observer_authority_path, observer_authority_observation
        )
        with patch("scripts.foundation_observation_report.run_cosign") as verify:
            report = build_report(
                receipt_path=receipt_path,
                receipt_inventory_path=receipt_inventory_path,
                receipt_public_key=receipt_public_key,
                receipt_signature=receipt_signature,
                expected_receipt_public_key_digest=file_digest(receipt_public_key),
                expected_receipt_digest=file_digest(receipt_path),
                plan_statement_path=statement_path,
                plan_summary_path=summary_path,
                plan_inventory_path=plan_inventory_path,
                plan_public_key=plan_public_key,
                plan_signature=plan_signature,
                expected_plan_public_key_digest=file_digest(plan_public_key),
                state_object_path=state_object,
                state_pull_path=state_pull,
                state_metadata_before_path=state_before_metadata,
                state_metadata_after_path=state_after_metadata,
                refresh_plan_path=refresh_plan_path,
                observer_authority_observation_path=observer_authority_path,
                observation_id=self.observation_id,
                environment_approval_digest=f"sha256:{10:064x}",
                actor_id="606",
                reason="Observe the exact applied foundation without mutation",
                source_revision=self.revision,
                workflow_run_id="505",
                workflow_run_attempt="1",
                started_at="2026-07-23T12:05:00Z",
                completed_at="2026-07-23T12:06:00Z",
                signing_key=self.observation_key,
                signing_public_key=observation_public_key,
                expected_signing_public_key_digest=file_digest(
                    observation_public_key
                ),
            )
        self.assertEqual(verify.call_count, 2)
        return report

    def test_authority_is_valid_and_fail_closed_in_source(self) -> None:
        authority, release, policy, apply_authority = load_contract()
        self.assertEqual(
            validate_authority(authority, release, policy, apply_authority),
            EXPECTED_AUTHORITY_DIGEST,
        )
        validate_declared_implementation()
        self.assertFalse(authority["observer"]["infrastructureMutationGranted"])
        self.assertFalse(authority["observer"]["stateLockGranted"])
        self.assertFalse(authority["observer"]["reportObjectReadGranted"])
        self.assertFalse(authority["claim"]["independentlyObserved"])

    def test_valid_report_is_independent_but_not_campaign_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self.make_report(Path(temporary))
            authority, release, policy, apply_authority = load_contract()
            digest = validate_report(
                report, authority, release, policy, apply_authority
            )
        self.assertTrue(digest.startswith("sha256:"))
        self.assertTrue(report["claims"]["independentlyObserved"])
        self.assertFalse(report["claims"]["campaignEvidence"])
        self.assertFalse(report["claims"]["referenceProfileVerified"])
        self.assertFalse(report["claims"]["customerCertified"])

    def test_report_rejects_drift_state_change_and_claim_escalation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self.make_report(Path(temporary))
        authority, release, policy, apply_authority = load_contract()
        changed = copy.deepcopy(report)
        changed["providerRefresh"]["driftDetected"] = True
        with self.assertRaisesRegex(ValueError, "refresh_invalid"):
            validate_report(changed, authority, release, policy, apply_authority)
        changed = copy.deepcopy(report)
        changed["state"]["generationStable"] = False
        with self.assertRaisesRegex(ValueError, "state_invalid"):
            validate_report(changed, authority, release, policy, apply_authority)
        changed = copy.deepcopy(report)
        changed["claims"]["referenceProfileVerified"] = True
        with self.assertRaisesRegex(ValueError, "claims_invalid"):
            validate_report(changed, authority, release, policy, apply_authority)

    def test_receipt_inventory_rejects_extra_or_early_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            report = self.make_report(work)
            receipt_inventory = json.loads(
                (work / "receipt-inventory.json").read_text(encoding="ascii")
            )
            receipt_inventory["objects"].append(
                copy.deepcopy(receipt_inventory["objects"][0])
            )
            with self.assertRaisesRegex(ValueError, "inventory_invalid"):
                validate_receipt_inventory(
                    receipt_inventory,
                    bucket=report["receiptCustody"]["bucket"],
                    prefix=report["receiptCustody"]["prefix"],
                )
            receipt_inventory = json.loads(
                (work / "receipt-inventory.json").read_text(encoding="ascii")
            )
            marker = next(
                item
                for item in receipt_inventory["objects"]
                if item["name"].endswith(
                    "foundation-apply-receipt-signature.sigstore.json"
                )
            )
            marker["timeCreated"] = "2026-07-23T12:04:01Z"
            with self.assertRaisesRegex(ValueError, "marker_invalid"):
                validate_receipt_inventory(
                    receipt_inventory,
                    bucket=report["receiptCustody"]["bucket"],
                    prefix=report["receiptCustody"]["prefix"],
                )

    def test_schema_and_executable_path_are_strict_and_read_only(self) -> None:
        schema = json.loads(
            (
                ROOT / "schemas" / "foundation-observation-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertTrue(
            all(
                definition.get("additionalProperties") is False
                for definition in schema["$defs"].values()
                if definition.get("type") == "object"
            )
        )
        script = (
            ROOT / "scripts" / "observe_foundation_apply.sh"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github" / "workflows" / "foundation-observation.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("-refresh-only", script)
        self.assertIn("-lock=false", script)
        self.assertIn("-detailed-exitcode", script)
        self.assertIn("--if-generation-match=0", script)
        receipt_gate = script.index(
            'python3 "$REPORT_MODULE" receipt-inventory'
        )
        plan_gate = script.index(
            'python3 "$PLAN_INVENTORY_MODULE" inventory'
        )
        first_download = script.index(
            'download_from_inventory "$RECEIPT_INVENTORY"'
        )
        self.assertLess(receipt_gate, first_download)
        self.assertLess(plan_gate, first_download)
        self.assertIn("$size > 67108864", script)
        self.assertNotIn("terraform apply", script + workflow)
        self.assertNotIn("terraform destroy", script + workflow)
        self.assertNotIn("actions/upload-artifact", workflow)
        self.assertIn(
            "foundation-observation-signature.sigstore.json", script
        )

    def test_authority_rejects_mutation_or_report_read_grants(self) -> None:
        authority, release, policy, apply_authority = load_contract()
        changed = copy.deepcopy(authority)
        changed["observer"]["infrastructureMutationGranted"] = True
        with self.assertRaisesRegex(ValueError, "boundary_invalid"):
            validate_authority(changed, release, policy, apply_authority)
        changed = copy.deepcopy(authority)
        changed["observer"]["reportObjectReadGranted"] = True
        with self.assertRaisesRegex(ValueError, "boundary_invalid"):
            validate_authority(changed, release, policy, apply_authority)

    def test_live_authority_projection_rejects_broad_or_inherited_roles(
        self,
    ) -> None:
        services_project = "orchestra-services"
        target_project = "orchestra-target"
        email = (
            "orchestra-foundation-observer@orchestra-services."
            "iam.gserviceaccount.com"
        )
        member = f"serviceAccount:{email}"
        provider_name = (
            "projects/123456789/locations/global/workloadIdentityPools/"
            "orchestra-lab-github/providers/foundation-observation"
        )
        pool = provider_name.rsplit("/providers/", maxsplit=1)[0]
        impersonation = (
            f"principal://iam.googleapis.com/{pool}/subject/"
            "foundation-observation:1307302690:"
            "reference-lab-foundation-observation"
        )
        target_roles = {
            "roles/browser",
            "roles/compute.viewer",
            "roles/dns.reader",
            "roles/iam.securityReviewer",
            "roles/iam.serviceAccountViewer",
            "roles/serviceusage.serviceUsageConsumer",
        }
        services_roles = {
            "roles/artifactregistry.reader",
            "roles/browser",
            "roles/cloudkms.viewer",
            "roles/compute.viewer",
            "roles/container.clusterViewer",
            "roles/dns.reader",
            "roles/iam.securityReviewer",
            "roles/iam.serviceAccountViewer",
            "roles/serviceusage.serviceUsageConsumer",
            (
                "projects/orchestra-services/roles/"
                "orchestraFoundationStorageMetadataObserver"
            ),
        }

        def policy(roles: set[str]) -> dict:
            return {
                "bindings": [
                    {"role": role, "members": [member]}
                    for role in sorted(roles)
                ]
            }

        def runner(
            arguments: list[str],
            *,
            ancestor_grant: bool = False,
            service_account_grant: bool = False,
        ):
            command = " ".join(arguments)
            if "workload-identity-pools providers describe" in command:
                return {
                    "name": provider_name,
                    "state": "ACTIVE",
                    "attributeMapping": {
                        "google.subject": (
                            "'foundation-observation:' + "
                            "assertion.repository_id + ':' + "
                            "assertion.environment"
                        ),
                        "attribute.actor_id": "assertion.actor_id",
                        "attribute.environment": "assertion.environment",
                        "attribute.event_name": "assertion.event_name",
                        "attribute.ref": "assertion.ref",
                        "attribute.repository": "assertion.repository",
                        "attribute.repository_id": "assertion.repository_id",
                        "attribute.repository_owner_id": (
                            "assertion.repository_owner_id"
                        ),
                        "attribute.repository_visibility": (
                            "assertion.repository_visibility"
                        ),
                        "attribute.workflow_ref": "assertion.workflow_ref",
                    },
                    "attributeCondition": (
                        "assertion.repository == "
                        "'caglarsubas/orchestra-openshift-reference-lab' && "
                        "assertion.repository_id == '1307302690' && "
                        "assertion.repository_owner_id == '37515097' && "
                        "assertion.repository_visibility == 'private' && "
                        "assertion.ref == 'refs/heads/main' && "
                        "assertion.event_name == 'workflow_dispatch' && "
                        "assertion.workflow_ref == "
                        "'caglarsubas/orchestra-openshift-reference-lab/"
                        ".github/workflows/foundation-observation.yml@"
                        "refs/heads/main' && assertion.environment == "
                        "'reference-lab-foundation-observation'"
                    ),
                    "oidc": {
                        "issuerUri": (
                            "https://token.actions.githubusercontent.com"
                        )
                    },
                }
            if "service-accounts describe" in command:
                return {
                    "email": email,
                    "disabled": False,
                    "name": f"projects/orchestra-services/serviceAccounts/{email}",
                }
            if "service-accounts get-iam-policy" in command:
                bindings = [
                    {
                        "role": "roles/iam.workloadIdentityUser",
                        "members": [impersonation],
                    }
                ]
                if service_account_grant:
                    bindings.append(
                        {
                            "role": "roles/iam.serviceAccountTokenCreator",
                            "members": ["user:unexpected@example.com"],
                        }
                    )
                return {"bindings": bindings}
            if "service-accounts keys list" in command:
                return []
            if "iam roles describe" in command:
                return {
                    "name": (
                        "projects/orchestra-services/roles/"
                        "orchestraFoundationStorageMetadataObserver"
                    ),
                    "stage": "GA",
                    "includedPermissions": [
                        "storage.buckets.get",
                        "storage.buckets.getIamPolicy",
                        "storage.managedFolders.get",
                        "storage.managedFolders.getIamPolicy",
                        "storage.managedFolders.list",
                    ],
                }
            if "projects get-ancestors" in command:
                return [
                    {"type": "project", "id": "987654321"},
                    {"type": "organization", "id": "111111111"},
                ]
            if "organizations get-iam-policy" in command:
                bindings = [
                    {
                        "role": "roles/iam.securityReviewer",
                        "members": [member],
                    }
                ]
                if ancestor_grant:
                    bindings.append(
                        {
                            "role": "roles/owner",
                            "members": [impersonation],
                        }
                    )
                return {"bindings": bindings}
            if command == f"projects get-iam-policy {target_project}":
                return policy(target_roles)
            if command == f"projects get-iam-policy {services_project}":
                return policy(services_roles)
            if "storage buckets get-iam-policy" in command:
                return policy(set())
            if "storage managed-folders get-iam-policy" in command:
                return policy(
                    {"roles/storage.objectCreator"}
                    if "foundation-observations/" in command
                    else {"roles/storage.objectViewer"}
                )
            if "kms keys get-iam-policy" in command:
                return policy(
                    {"roles/cloudkms.signerVerifier"}
                    if "foundation-observation-signing" in command
                    else {"roles/cloudkms.publicKeyViewer"}
                )
            self.fail(f"unexpected command: {command}")

        result = collect(
            target_project_id=target_project,
            services_project_id=services_project,
            state_bucket="orchestra-foundation-state",
            run_json=runner,
        )
        self.assertTrue(result["checks"]["directAncestorBindingsExact"])
        self.assertTrue(
            result["claims"]["directReadOnlyBoundaryObserved"]
        )
        with self.assertRaisesRegex(ValueError, "ancestor_binding_present"):
            collect(
                target_project_id=target_project,
                services_project_id=services_project,
                state_bucket="orchestra-foundation-state",
                run_json=lambda arguments: runner(
                    arguments, ancestor_grant=True
                ),
            )
        with self.assertRaisesRegex(ValueError, "impersonation_invalid"):
            collect(
                target_project_id=target_project,
                services_project_id=services_project,
                state_bucket="orchestra-foundation-state",
                run_json=lambda arguments: runner(
                    arguments, service_account_grant=True
                ),
            )

    def test_report_digest_is_canonical_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self.make_report(Path(temporary))
        self.assertEqual(canonical_digest(report), canonical_digest(copy.deepcopy(report)))


if __name__ == "__main__":
    unittest.main()
