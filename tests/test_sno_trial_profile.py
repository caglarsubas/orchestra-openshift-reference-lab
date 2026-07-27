from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.build_red_hat_entitlement_statement import (
    build_statement,
    read_private_identity,
)
from scripts.render_sno_trial_install_config import (
    TEMPLATE,
    load_values,
    render,
)
from scripts.trial_lease import build_lease, validate_lease
from scripts.validate_sno_trial_profile import (
    BILLING_EXECUTION_LOCK,
    EXPECTED_BILLING_EXECUTION_DIGEST,
    EXPECTED_PRODUCTION_DIGEST,
    EXPECTED_TRIAL_DIGEST,
    PRODUCTION_PROFILE,
    PRODUCTION_PROFILE_ID,
    ROOT,
    TRIAL_PROFILE,
    TRIAL_PROFILE_ID,
    canonical_digest,
    load_json,
    validate_billing_execution,
    validate_profile,
    validate_production_isolation,
)


class SnoTrialProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_json(TRIAL_PROFILE)
        self.billing_execution = load_json(BILLING_EXECUTION_LOCK)
        self.production = load_json(PRODUCTION_PROFILE)
        self.starts_at = datetime(2026, 7, 24, 8, 0, tzinfo=timezone.utc)

    def lease(self) -> dict[str, object]:
        return build_lease(
            self.profile,
            "prometa-orch-ocp-trial",
            f"sha256:{1:064x}",
            self.starts_at,
            8,
            "sno-trial-contract-test-001",
        )

    def test_profile_is_valid_stable_and_distinct_from_production(self) -> None:
        validate_profile(self.profile, self.production)
        validate_production_isolation()
        self.assertEqual(self.profile["profileId"], TRIAL_PROFILE_ID)
        self.assertEqual(self.production["profileId"], PRODUCTION_PROFILE_ID)
        self.assertEqual(canonical_digest(self.profile), EXPECTED_TRIAL_DIGEST)
        self.assertEqual(canonical_digest(self.production), EXPECTED_PRODUCTION_DIGEST)

    def test_billing_execution_is_profile_bound_and_below_usd_ceiling(self) -> None:
        validate_billing_execution(self.billing_execution, self.profile)
        self.assertEqual(
            canonical_digest(self.billing_execution),
            EXPECTED_BILLING_EXECUTION_DIGEST,
        )
        self.assertEqual(self.billing_execution["billingCurrencyCode"], "TRY")
        self.assertLess(
            float(self.billing_execution["equivalentUsdAtLockedRate"]),
            self.profile["guardrails"]["budget"]["monthlyUsd"],
        )

    def test_billing_execution_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.billing_execution)
        changed["billingAmountUnits"] = 3501
        with self.assertRaisesRegex(
            ValueError, "trial_billing_execution_invalid"
        ):
            validate_billing_execution(changed, self.profile)

    def test_only_named_trial_locks_may_reference_trial_profile_in_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.mkdir()
            (config / "sno-trial.lock.json").write_text(
                TRIAL_PROFILE_ID, encoding="utf-8"
            )
            (config / "sno-trial-openshift-toolchain.lock.json").write_text(
                TRIAL_PROFILE_ID, encoding="utf-8"
            )
            (
                config
                / "sno-trial-product-artifact-admission-policy.lock.json"
            ).write_text(TRIAL_PROFILE_ID, encoding="utf-8")
            (config / "sno-trial-workload-candidate.lock.json").write_text(
                TRIAL_PROFILE_ID, encoding="utf-8"
            )
            validate_production_isolation(root)
            (config / "production-like.json").write_text(
                TRIAL_PROFILE_ID, encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ValueError,
                "trial_profile_referenced_by_production_config:production-like.json",
            ):
                validate_production_isolation(root)

    def test_profile_cannot_make_certification_or_production_claims(self) -> None:
        self.assertFalse(self.profile["certificationEligible"])
        self.assertTrue(
            all(value is False for value in self.profile["claim"].values())
        )
        self.assertFalse(self.profile["evidence"]["campaignEligible"])
        self.assertEqual(self.profile["evidence"]["allowedCertificationSlots"], [])

    def test_profile_locks_supported_sno_minimum_and_zero_workers(self) -> None:
        openshift = self.profile["openshift"]
        self.assertEqual(openshift["controlPlane"]["count"], 1)
        self.assertEqual(openshift["controlPlane"]["machineType"], "n2-standard-8")
        self.assertGreaterEqual(openshift["controlPlane"]["diskSizeGB"], 120)
        self.assertEqual(openshift["workers"], {"count": 0})
        self.assertEqual(openshift["cni"], "OVN-Kubernetes")

    def test_topology_drift_is_rejected_before_digest_check(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["openshift"]["controlPlane"]["machineType"] = "e2-standard-8"
        with self.assertRaisesRegex(ValueError, "trial_openshift_invalid"):
            validate_profile(changed, self.production)

    def test_budget_or_claim_escalation_is_rejected(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["guardrails"]["budget"]["monthlyUsd"] = 76
        with self.assertRaisesRegex(ValueError, "trial_guardrails_invalid"):
            validate_profile(changed, self.production)
        changed = copy.deepcopy(self.profile)
        changed["claim"]["referenceProfileVerified"] = True
        with self.assertRaisesRegex(ValueError, "trial_claim_invalid"):
            validate_profile(changed, self.production)

    def test_renderer_preserves_secrets_for_operator_injection(self) -> None:
        rendered = render(
            TEMPLATE.read_text(encoding="utf-8"),
            {"TARGET_PROJECT_ID": "prometa-orch-ocp-trial"},
        )
        self.assertIn("replicas: 0", rendered)
        self.assertIn("replicas: 1", rendered)
        self.assertIn("type: n2-standard-8", rendered)
        self.assertIn("diskType: pd-balanced", rendered)
        self.assertIn("publish: External", rendered)
        self.assertIn("credentialsMode: Manual", rendered)
        self.assertIn("baseDomain: ocp-lab.planeon.ai", rendered)
        self.assertIn("${PULL_SECRET_JSON}", rendered)
        self.assertIn("${SSH_PUBLIC_KEY}", rendered)
        self.assertNotIn("${TARGET_PROJECT_ID}", rendered)
        self.assertNotIn("n2-standard-4", rendered)

    def test_renderer_values_reject_secret_or_extra_fields(self) -> None:
        values = {
            "TARGET_PROJECT_ID": "prometa-orch-ocp-trial",
            "PULL_SECRET_JSON": "forbidden",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "values.json"
            path.write_text(json.dumps(values), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "trial_install_values_keys_invalid"
            ):
                load_values(path)

    def test_active_lease_is_bound_to_profile_project_and_budget(self) -> None:
        lease = self.lease()
        validate_lease(
            lease,
            self.profile,
            self.starts_at + timedelta(hours=1),
            "prometa-orch-ocp-trial",
        )
        self.assertEqual(lease["profileDigest"], EXPECTED_TRIAL_DIGEST)
        self.assertEqual(lease["maximumMonthlyBudgetUsd"], 75)
        self.assertEqual(lease["maximumActiveHoursPerMonth"], 48)
        self.assertFalse(lease["certificationEligible"])
        self.assertFalse(lease["automaticProviderTeardown"])

    def test_expired_or_not_started_lease_is_rejected(self) -> None:
        lease = self.lease()
        with self.assertRaisesRegex(ValueError, "trial_lease_not_started"):
            validate_lease(
                lease,
                self.profile,
                self.starts_at - timedelta(seconds=1),
            )
        with self.assertRaisesRegex(ValueError, "trial_lease_expired"):
            validate_lease(
                lease,
                self.profile,
                self.starts_at + timedelta(hours=8),
            )

    def test_lease_rejects_project_substitution_and_claim_escalation(self) -> None:
        lease = self.lease()
        with self.assertRaisesRegex(ValueError, "trial_lease_project_mismatch"):
            validate_lease(
                lease,
                self.profile,
                self.starts_at + timedelta(hours=1),
                "different-project-12345",
            )
        changed = copy.deepcopy(lease)
        changed["certificationEligible"] = True
        with self.assertRaisesRegex(ValueError, "trial_lease_contract_invalid"):
            validate_lease(
                changed,
                self.profile,
                self.starts_at + timedelta(hours=1),
            )

    def test_lease_duration_is_capped_at_twelve_hours(self) -> None:
        with self.assertRaisesRegex(ValueError, "trial_lease_duration_invalid"):
            build_lease(
                self.profile,
                "prometa-orch-ocp-trial",
                f"sha256:{1:064x}",
                self.starts_at,
                13,
                "sno-trial-contract-test-002",
            )

    def test_entitlement_builder_emits_only_payload_free_identity_digests(
        self,
    ) -> None:
        statement = build_statement(
            b"private-account-identity",
            b"red-hat-trial-confirmation-image",
            self.starts_at,
            self.starts_at + timedelta(days=60),
        )
        encoded = json.dumps(statement)
        self.assertNotIn("private-account-identity", encoded)
        self.assertNotIn("red-hat-trial-confirmation-image", encoded)
        self.assertEqual(statement["status"], "active")
        self.assertEqual(statement["openshiftVersion"], "4.20.27")
        self.assertTrue(statement["accountIdentityDigest"].startswith("sha256:"))
        self.assertTrue(statement["issuerEvidenceDigest"].startswith("sha256:"))

    def test_entitlement_builder_rejects_overlong_or_empty_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "entitlement_window_invalid"):
            build_statement(
                b"private-account-identity",
                b"red-hat-trial-confirmation-image",
                self.starts_at,
                self.starts_at + timedelta(days=62),
            )
        with self.assertRaisesRegex(
            ValueError, "entitlement_issuer_evidence_size_invalid"
        ):
            build_statement(
                b"private-account-identity",
                b"",
                self.starts_at,
                self.starts_at + timedelta(days=60),
            )

    def test_entitlement_identity_input_is_private_regular_and_restricted(
        self,
    ) -> None:
        restricted = ROOT / "restricted"
        restricted.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=restricted) as directory:
            path = Path(directory) / "identity.txt"
            path.write_bytes(b"private-account-identity")
            path.chmod(0o600)
            self.assertEqual(
                read_private_identity(path), b"private-account-identity"
            )
            path.chmod(0o644)
            with self.assertRaisesRegex(
                ValueError, "entitlement_account_identity_permissions_invalid"
            ):
                read_private_identity(path)
            path.chmod(0o600)
            link = Path(directory) / "identity-link.txt"
            link.symlink_to(path)
            with self.assertRaisesRegex(
                ValueError, "entitlement_account_identity_not_regular"
            ):
                read_private_identity(link)

        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "identity.txt"
            outside.write_bytes(b"private-account-identity")
            outside.chmod(0o600)
            with self.assertRaisesRegex(
                ValueError, "entitlement_account_identity_must_be_restricted"
            ):
                read_private_identity(outside)


if __name__ == "__main__":
    unittest.main()
