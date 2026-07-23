from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.foundation_apply_execution import (
    EXPECTED_AUTHORITY_DIGEST,
    load_contract,
    validate_authority,
    validate_declared_implementation,
)
from scripts.foundation_apply_receipt import (
    build_receipt,
    main as receipt_main,
    validate_receipt,
)
from scripts.foundation_plan_package import (
    build_statement,
    file_digest,
    main as package_main,
    validate_statement,
)
from scripts.foundation_plan_summary import build_summary
from scripts.validate_repository import ROOT
from scripts.verify_foundation_plan_package import (
    MAX_OBJECT_BYTES,
    PLAN_OBJECTS,
    validate_inventory,
    verify_package,
)


class FoundationApplyExecutionTests(unittest.TestCase):
    revision = "a" * 40
    plan_id = "orchestra-foundation-plan-101.1"
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
    approval_digest = f"sha256:{7:064x}"

    def make_package(self, work: Path) -> dict[str, object]:
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
        plan_json_path.write_text(
            json.dumps(plan_json, sort_keys=True), encoding="utf-8"
        )
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
        summary_path.write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n",
            encoding="ascii",
        )
        public_key = work / "foundation-plan-package-public-key.pem"
        public_key.write_bytes(b"fixture-plan-public-key\n")
        public_key_digest = file_digest(public_key)
        statement = build_statement(
            plan_path=plan,
            summary_path=summary_path,
            bucket="orchestra-foundation-state-fixture",
            plan_id=self.plan_id,
            environment_approval_digest=self.approval_digest,
            signing_key=self.plan_key,
            signing_public_key=public_key,
            expected_public_key_digest=public_key_digest,
            signed_at="2026-07-23T12:01:00Z",
        )
        statement_path = work / "foundation-plan-package-statement.json"
        statement_path.write_text(
            json.dumps(statement, sort_keys=True, indent=2) + "\n",
            encoding="ascii",
        )
        signature = work / "foundation-plan-package-signature.sigstore.json"
        signature.write_bytes(b"fixture-signature-bundle\n")
        prefix = statement["package"]["prefix"]
        paths = {
            "foundation.tfplan": plan,
            "foundation-plan-summary.json": summary_path,
            "foundation-plan-package-public-key.pem": public_key,
            "foundation-plan-package-statement.json": statement_path,
            "foundation-plan-package-signature.sigstore.json": signature,
        }
        objects = []
        for index, (name, path) in enumerate(paths.items(), start=1):
            timestamp = (
                "2026-07-23T12:01:02Z"
                if name == "foundation-plan-package-signature.sigstore.json"
                else "2026-07-23T12:01:01Z"
            )
            objects.append(
                {
                    "name": f"{prefix}/{name}",
                    "generation": str(1000 + index),
                    "metageneration": "1",
                    "sizeBytes": path.stat().st_size,
                    "crc32c": "AAAAAA==",
                    "md5Hash": "A" * 22 + "==",
                    "etag": f"fixture-etag-{index}",
                    "timeCreated": timestamp,
                    "updated": timestamp,
                }
            )
        inventory = {
            "schemaVersion": 1,
            "bucket": "orchestra-foundation-state-fixture",
            "prefix": prefix,
            "objects": sorted(objects, key=lambda item: item["name"]),
        }
        inventory_path = work / "inventory.json"
        inventory_path.write_text(
            json.dumps(inventory, sort_keys=True, indent=2) + "\n",
            encoding="ascii",
        )
        return {
            "plan": plan,
            "planJson": plan_json,
            "planJsonPath": plan_json_path,
            "statement": statement,
            "statementPath": statement_path,
            "statementDigest": file_digest(statement_path),
            "publicKey": public_key,
            "publicKeyDigest": public_key_digest,
            "inventory": inventory,
            "inventoryPath": inventory_path,
        }

    def verify_fixture(self, work: Path, fixture: dict[str, object]) -> dict:
        output = work / "verified-package.json"
        with patch(
            "scripts.verify_foundation_plan_package.run_cosign"
        ) as cosign_verify:
            verified = verify_package(
                inventory_path=fixture["inventoryPath"],
                download_dir=work,
                plan_json_path=fixture["planJsonPath"],
                source_revision=self.revision,
                plan_id=self.plan_id,
                expected_statement_digest=fixture["statementDigest"],
                expected_public_key_digest=fixture["publicKeyDigest"],
                verified_at="2026-07-23T12:02:00Z",
                output=output,
            )
        cosign_verify.assert_called_once()
        return verified

    def test_locked_authority_and_declared_boundaries_are_valid(self) -> None:
        authority, release_set, policy = load_contract()
        self.assertEqual(
            validate_authority(authority, release_set, policy),
            EXPECTED_AUTHORITY_DIGEST,
        )
        validate_declared_implementation()
        self.assertFalse(authority["claim"]["foundationApplied"])
        self.assertFalse(authority["claim"]["independentlyObserved"])
        self.assertTrue(authority["applyExecutor"]["infrastructureMutationGranted"])
        self.assertTrue(authority["applyExecutor"]["artifactMirrorWriteGranted"])
        self.assertFalse(authority["workflow"]["artifactMirrorOperationsAllowed"])
        self.assertEqual(
            authority["planReviewer"]["role"], "roles/storage.objectViewer"
        )
        self.assertFalse(authority["planReviewer"]["stateReadGranted"])

    def test_apply_runner_declares_exact_object_absent_state_path(
        self,
    ) -> None:
        script = (
            ROOT / "scripts" / "verify_and_apply_foundation_plan.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "https://storage.googleapis.com/storage/v1/b/"
            "$STATE_BUCKET/o/foundation%2Fdefault.tfstate",
            script,
        )
        self.assertIn('state_http_status" in', script)
        self.assertIn("404)", script)
        self.assertNotIn('"gs://$STATE_BUCKET/foundation/**"', script)
        self.assertNotIn('--recursive \\\n  --limit=100001', script)
        self.assertIn('if [[ "$state_count" == "1" ]]; then', script)
        self.assertNotIn(
            'chmod 0600 "$STATE_BEFORE" "$STATE_AFTER" 2>/dev/null || true',
            script,
        )

    def test_plan_packager_cannot_gain_project_or_state_authority(self) -> None:
        authority, release_set, policy = load_contract()
        changed = copy.deepcopy(authority)
        changed["planPublisher"]["projectRoles"] = ["roles/storage.admin"]
        with self.assertRaisesRegex(ValueError, "plan_publisher_boundary_invalid"):
            validate_authority(changed, release_set, policy)
        changed = copy.deepcopy(authority)
        changed["planPublisher"]["stateReadGranted"] = True
        with self.assertRaisesRegex(ValueError, "plan_publisher_boundary_invalid"):
            validate_authority(changed, release_set, policy)
        changed = copy.deepcopy(authority)
        changed["planReviewer"]["objectWriteGranted"] = True
        with self.assertRaisesRegex(ValueError, "plan_reviewer_boundary_invalid"):
            validate_authority(changed, release_set, policy)

    def test_bootstrap_requires_a_group_plan_reviewer(self) -> None:
        variables = (
            ROOT / "infra" / "terraform" / "bootstrap" / "variables.tf"
        ).read_text(encoding="utf-8")
        reviewer_block = variables.split(
            'variable "foundation_plan_reviewer_members"', maxsplit=1
        )[1]
        self.assertIn(
            "length(var.foundation_plan_reviewer_members) >= 1",
            reviewer_block,
        )
        self.assertIn(
            'can(regex("^group:[^@]+@[^@]+$", member))',
            reviewer_block,
        )
        self.assertNotIn("default     = []", reviewer_block)

    def test_package_is_signature_bound_and_non_authorizing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            fixture = self.make_package(work)
            authority, _, _ = load_contract()
            digest = validate_statement(fixture["statement"], authority)
            verified = self.verify_fixture(work, fixture)
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(verified["planDigest"], fixture["statement"]["package"]["planDigest"])
        self.assertEqual(
            fixture["statement"]["claims"],
            {
                "reviewablePlanPackage": True,
                "applyAuthorized": False,
                "infrastructureApplied": False,
                "independentlyObserved": False,
                "campaignEvidence": False,
                "referenceProfileVerified": False,
            },
        )

    def test_inventory_rejects_oversize_or_incomplete_custody(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.make_package(Path(temporary))
            inventory = copy.deepcopy(fixture["inventory"])
            plan_name = f"{inventory['prefix']}/foundation.tfplan"
            next(
                item for item in inventory["objects"] if item["name"] == plan_name
            )["sizeBytes"] = MAX_OBJECT_BYTES["foundation.tfplan"] + 1
            with self.assertRaisesRegex(ValueError, "inventory_object_invalid"):
                validate_inventory(inventory, self.revision, self.plan_id)
            inventory = copy.deepcopy(fixture["inventory"])
            inventory["objects"][-1]["generation"] = "0"
            with self.assertRaisesRegex(ValueError, "inventory_object_invalid"):
                validate_inventory(inventory, self.revision, self.plan_id)

    def test_cli_signature_paths_reject_shape_before_field_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            malformed = work / "malformed.json"
            malformed.write_text('{"schemaVersion": 1}\n', encoding="ascii")
            public_key = work / "public-key.pem"
            public_key.write_bytes(b"fixture-public-key\n")
            signature = work / "signature.json"
            signature.write_text("{}\n", encoding="ascii")
            digest = file_digest(public_key)
            with self.assertRaisesRegex(
                ValueError, "foundation_plan_package_keys_invalid"
            ):
                package_main(
                    [
                        "validate",
                        "--statement",
                        str(malformed),
                        "--signing-public-key",
                        str(public_key),
                        "--signature-bundle",
                        str(signature),
                        "--expected-public-key-digest",
                        digest,
                    ]
                )
            with self.assertRaisesRegex(
                ValueError, "foundation_apply_receipt_keys_invalid"
            ):
                receipt_main(
                    [
                        "validate",
                        "--receipt",
                        str(malformed),
                        "--signing-public-key",
                        str(public_key),
                        "--signature-bundle",
                        str(signature),
                        "--expected-public-key-digest",
                        digest,
                    ]
                )

    def test_completion_marker_must_be_strictly_last(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.make_package(Path(temporary))
            inventory = copy.deepcopy(fixture["inventory"])
            marker = next(
                item
                for item in inventory["objects"]
                if item["name"].endswith(
                    "foundation-plan-package-signature.sigstore.json"
                )
            )
            marker["timeCreated"] = "2026-07-23T12:01:01Z"
            marker["updated"] = marker["timeCreated"]
            with self.assertRaisesRegex(ValueError, "completion_marker_order_invalid"):
                validate_inventory(inventory, self.revision, self.plan_id)

    def test_replayed_destructive_plan_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            fixture = self.make_package(work)
            replay = copy.deepcopy(fixture["planJson"])
            replay["resource_changes"][0]["change"]["actions"] = ["delete"]
            fixture["planJsonPath"].write_text(
                json.dumps(replay, sort_keys=True), encoding="utf-8"
            )
            with patch("scripts.verify_foundation_plan_package.run_cosign"):
                with self.assertRaisesRegex(ValueError, "plan_replay_mismatch"):
                    verify_package(
                        inventory_path=fixture["inventoryPath"],
                        download_dir=work,
                        plan_json_path=fixture["planJsonPath"],
                        source_revision=self.revision,
                        plan_id=self.plan_id,
                        expected_statement_digest=fixture["statementDigest"],
                        expected_public_key_digest=fixture["publicKeyDigest"],
                        verified_at="2026-07-23T12:02:00Z",
                        output=work / "verified-package.json",
                    )

    def test_receipt_binds_exact_plan_and_remains_self_attested(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            fixture = self.make_package(work)
            verified = self.verify_fixture(work, fixture)
            verified_path = work / "verified-package.json"
            state_before = work / "state-before.json"
            state_after = work / "state-after.json"
            state_before.write_text(
                json.dumps({"serial": 4, "lineage": "fixture-lineage"}),
                encoding="utf-8",
            )
            state_after.write_text(
                json.dumps({"serial": 5, "lineage": "fixture-lineage"}),
                encoding="utf-8",
            )
            receipt_public_key = work / "receipt-public-key.pem"
            receipt_public_key.write_bytes(b"fixture-receipt-public-key\n")
            receipt = build_receipt(
                verified_package_path=verified_path,
                state_before_path=state_before,
                state_after_path=state_after,
                apply_id="orchestra-foundation-apply-303.1",
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
                expected_plan_statement_digest=fixture["statementDigest"],
            )
            authority, _, _ = load_contract()
            validate_receipt(receipt, authority)
        self.assertEqual(receipt["planId"], verified["planId"])
        self.assertEqual(
            receipt["bindings"]["planPackageStatementDigest"],
            fixture["statementDigest"],
        )
        self.assertEqual(
            receipt["claims"],
            {
                "exactReviewedPlanApplied": True,
                "infrastructureApplied": True,
                "receiptSelfAttested": True,
                "independentlyObserved": False,
                "campaignEvidence": False,
                "referenceProfileVerified": False,
            },
        )

    def test_receipt_rejects_state_lineage_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            fixture = self.make_package(work)
            self.verify_fixture(work, fixture)
            before = work / "before.json"
            after = work / "after.json"
            before.write_text(
                json.dumps({"serial": 1, "lineage": "lineage-one"}),
                encoding="utf-8",
            )
            after.write_text(
                json.dumps({"serial": 2, "lineage": "lineage-two"}),
                encoding="utf-8",
            )
            receipt_key = work / "receipt-key.pem"
            receipt_key.write_bytes(b"fixture-receipt-key\n")
            with self.assertRaisesRegex(ValueError, "state_transition_invalid"):
                build_receipt(
                    verified_package_path=work / "verified-package.json",
                    state_before_path=before,
                    state_after_path=after,
                    apply_id="orchestra-foundation-apply-303.1",
                    environment_approval_digest=f"sha256:{9:064x}",
                    actor_id="404",
                    reason="Apply exact independently reviewed foundation plan",
                    source_revision=self.revision,
                    workflow_run_id="303",
                    workflow_run_attempt="1",
                    started_at="2026-07-23T12:03:00Z",
                    completed_at="2026-07-23T12:04:00Z",
                    signing_key=self.receipt_key,
                    signing_public_key=receipt_key,
                    expected_public_key_digest=file_digest(receipt_key),
                    expected_plan_statement_digest=fixture["statementDigest"],
                )

    def test_workflow_and_shell_never_publish_the_plan_to_github(self) -> None:
        plan_workflow = (
            ROOT / ".github" / "workflows" / "foundation-plan.yml"
        ).read_text(encoding="utf-8")
        apply_workflow = (
            ROOT / ".github" / "workflows" / "foundation-apply.yml"
        ).read_text(encoding="utf-8")
        apply_script = (
            ROOT / "scripts" / "verify_and_apply_foundation_plan.sh"
        ).read_text(encoding="utf-8")
        review_script = (
            ROOT / "scripts" / "review_foundation_plan_package.sh"
        ).read_text(encoding="utf-8")
        publisher_script = (
            ROOT / "scripts" / "publish_foundation_plan_package.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("GCP_FOUNDATION_PLAN_PACKAGER_SERVICE_ACCOUNT", plan_workflow)
        self.assertIn("publish_foundation_plan_package.sh", plan_workflow)
        self.assertNotIn(
            "path: ${{ runner.temp }}/foundation.tfplan", plan_workflow
        )
        self.assertIn("environment: reference-lab-foundation-apply", apply_workflow)
        self.assertIn("--contract foundation-apply", apply_workflow)
        self.assertIn('terraform -chdir="$FOUNDATION_DIR" apply', apply_script)
        self.assertIn('-lock-timeout=300s "$DOWNLOAD_DIR/foundation.tfplan"', apply_script)
        self.assertIn("--if-generation-match=", apply_script)
        self.assertIn("--if-metageneration-match=", apply_script)
        self.assertNotIn("-auto-approve", apply_workflow + apply_script)
        self.assertNotIn("terraform destroy", apply_workflow + apply_script)
        self.assertNotIn("artifactregistry repositories", apply_workflow + apply_script)
        self.assertIn("--if-metageneration-match=", review_script)
        self.assertIn('git -C "$ROOT" rev-parse HEAD', review_script)
        self.assertIn(
            'git -C "$ROOT" status --porcelain --untracked-files=all',
            review_script,
        )
        self.assertIn("foundation-plan-review.txt", review_script)
        self.assertIn("restricted", review_script)
        self.assertNotIn("terraform apply", review_script)
        self.assertNotIn("cosign sign-blob", review_script)
        self.assertIn(
            "https://storage.googleapis.com/upload/storage/v1/b/",
            publisher_script,
        )
        self.assertIn("ifGenerationMatch=0", publisher_script)
        self.assertNotIn("gcloud storage cp", publisher_script)
        self.assertNotIn("gcloud storage ls", publisher_script)

    def test_create_only_publisher_uses_five_json_api_inserts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            plan = work / "foundation.tfplan"
            plan.write_bytes(b"opaque-saved-foundation-plan\n")
            summary = build_summary(
                {
                    "format_version": "1.2",
                    "terraform_version": "1.14.6",
                    "resource_changes": [
                        {
                            "address": "google_compute_network.target",
                            "mode": "managed",
                            "type": "google_compute_network",
                            "provider_name": (
                                "registry.terraform.io/hashicorp/google"
                            ),
                            "change": {"actions": ["create"]},
                        }
                    ],
                },
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
            summary_path.write_text(
                json.dumps(summary, sort_keys=True, indent=2) + "\n",
                encoding="ascii",
            )
            fake_bin = work / "bin"
            fake_bin.mkdir()
            key_bytes = b"fixture-plan-public-key\n"
            curl_log = work / "curl.log"
            cosign = fake_bin / "cosign"
            cosign.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  public-key)
    printf 'fixture-plan-public-key\\n'
    ;;
  sign-blob)
    while (($# > 0)); do
      if [[ "$1" == "--bundle" ]]; then
        printf '{}\\n' >"$2"
        exit 0
      fi
      shift
    done
    exit 1
    ;;
  verify-blob)
    exit 0
    ;;
  *)
    exit 1
    ;;
esac
""",
                encoding="utf-8",
            )
            gcloud = fake_bin / "gcloud"
            gcloud.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == "auth print-access-token" ]]
printf 'fixture-access-token\\n'
""",
                encoding="utf-8",
            )
            curl = fake_bin / "curl"
            curl.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
config=""
previous=""
for argument in "$@"; do
  if [[ "$previous" == "--config" ]]; then
    config="$argument"
  fi
  previous="$argument"
done
[[ -f "$config" ]]
grep -q 'Authorization: Bearer fixture-access-token' "$config"
[[ "$*" == *"ifGenerationMatch=0"* ]]
printf '%s\\n' "$*" >>"$FAKE_CURL_LOG"
""",
                encoding="utf-8",
            )
            for executable in (cosign, gcloud, curl):
                executable.chmod(0o700)
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "RUNNER_TEMP": str(work),
                "FAKE_CURL_LOG": str(curl_log),
            }
            result = subprocess.run(
                [
                    str(
                        ROOT
                        / "scripts"
                        / "publish_foundation_plan_package.sh"
                    ),
                    "--plan",
                    str(plan),
                    "--summary",
                    str(summary_path),
                    "--state-bucket",
                    "orchestra-foundation-state-fixture",
                    "--plan-id",
                    self.plan_id,
                    "--signing-key",
                    self.plan_key,
                    "--expected-signing-public-key-digest",
                    f"sha256:{hashlib.sha256(key_bytes).hexdigest()}",
                    "--environment-approval-digest",
                    self.approval_digest,
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            uploads = curl_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(uploads), 5)
            self.assertTrue(
                uploads[-1].find(
                    "foundation-plan-package-signature.sigstore.json"
                )
                >= 0
            )

    def test_schemas_are_strict_at_every_new_object_boundary(self) -> None:
        package_schema = json.loads(
            (ROOT / "schemas" / "foundation-plan-package-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        receipt_schema = json.loads(
            (ROOT / "schemas" / "foundation-apply-receipt-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(package_schema["additionalProperties"])
        self.assertTrue(
            all(
                definition.get("additionalProperties") is False
                for definition in package_schema["$defs"].values()
                if definition.get("type") == "object"
            )
        )
        self.assertFalse(receipt_schema["additionalProperties"])
        self.assertTrue(
            all(
                definition.get("additionalProperties") is False
                for definition in receipt_schema["$defs"].values()
                if definition.get("type") == "object"
            )
        )
        self.assertEqual(set(PLAN_OBJECTS), set(MAX_OBJECT_BYTES))


if __name__ == "__main__":
    unittest.main()
