from __future__ import annotations

import unittest
from datetime import datetime, timezone

from scripts.verify_dependency_signatures import (
    bundle_metadata,
    no_signature_observed,
    validate_observation_fresh,
    verify_arguments,
)


class DependencySignatureVerificationTests(unittest.TestCase):
    def test_sigstore_v3_bundle_metadata_is_normalized(self) -> None:
        value = {
            "verificationMaterial": {
                "tlogEntries": [{"logIndex": "42", "integratedTime": "1782751271"}]
            }
        }
        self.assertEqual(
            bundle_metadata(value),
            ("sigstore-bundle-v3", "42", "2026-06-29T16:41:11Z"),
        )

    def test_legacy_bundle_metadata_is_normalized(self) -> None:
        value = {"Bundle": {"Payload": {"logIndex": 43, "integratedTime": 1763192818}}}
        self.assertEqual(
            bundle_metadata(value),
            ("legacy-cosign-bundle", "43", "2025-11-15T07:46:58Z"),
        )

    def test_multiple_transparency_entries_are_rejected(self) -> None:
        value = {
            "verificationMaterial": {
                "tlogEntries": [
                    {"logIndex": "1", "integratedTime": "1"},
                    {"logIndex": "2", "integratedTime": "2"},
                ]
            }
        }
        with self.assertRaisesRegex(ValueError, "tlog_entry_invalid"):
            bundle_metadata(value)

    def test_only_explicit_no_signature_response_is_accepted(self) -> None:
        subject = "registry.example/image@sha256:abc"
        expected = (
            f"Error: {subject}: no signatures associated\n"
            f"error during command execution: {subject}: no signatures associated"
        )
        self.assertTrue(no_signature_observed(expected, subject))
        self.assertFalse(no_signature_observed("connection reset", subject))
        self.assertFalse(
            no_signature_observed(f"{expected}\nconnection reset", subject)
        )
        self.assertFalse(
            no_signature_observed(expected, "registry.example/other@sha256:def")
        )

    def test_verification_uses_exact_identity_and_never_a_regex(self) -> None:
        arguments = verify_arguments(
            {
                "subject": "registry.example/image@sha256:abc",
                "certificateIdentity": "https://github.com/org/repo/workflow@refs/tags/v1",
            }
        )
        self.assertIn("--certificate-identity", arguments)
        self.assertNotIn("--certificate-identity-regexp", arguments)
        self.assertNotIn("--certificate-oidc-issuer-regexp", arguments)

    def test_stale_observation_requires_a_new_lock(self) -> None:
        report = {
            "observationWindow": {
                "observedAt": "2026-07-21T17:10:00Z",
                "validUntil": "2026-07-28T17:10:00Z",
            }
        }
        validate_observation_fresh(report, datetime(2026, 7, 22, tzinfo=timezone.utc))
        with self.assertRaisesRegex(ValueError, "observation_stale"):
            validate_observation_fresh(
                report, datetime(2026, 7, 29, tzinfo=timezone.utc)
            )


if __name__ == "__main__":
    unittest.main()
