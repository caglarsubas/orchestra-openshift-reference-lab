from __future__ import annotations

import json
import unittest

from orchestra_receiver.contracts import parse_event, validate_transport_headers
from orchestra_receiver.errors import ReceiverError
from orchestra_receiver.signing import (
    load_signing_secrets,
    sign_for_test,
    verify_signature,
)

from .helpers import clone_event, event_body


class ContractTests(unittest.TestCase):
    def test_valid_event_is_strictly_parsed(self) -> None:
        action = parse_event(event_body())
        self.assertEqual(action.event_id, "event-4")
        self.assertEqual(action.state_version, 4)
        self.assertEqual(action.recommendation, "rollback")
        self.assertTrue(action.body_digest.startswith("sha256:"))

    def test_rejects_extra_properties_and_authority_changes(self) -> None:
        extra = clone_event()
        extra["data"]["extra"] = True
        with self.assertRaisesRegex(ReceiverError, "unsupported properties"):
            parse_event(json.dumps(extra).encode())
        authority = clone_event()
        authority["data"]["authority"]["platformDeploysOrRollsBack"] = True
        with self.assertRaisesRegex(ReceiverError, "authority boundary"):
            parse_event(json.dumps(authority).encode())

    def test_rejects_duplicate_properties_and_non_finite_numbers(self) -> None:
        with self.assertRaisesRegex(ReceiverError, "UTF-8 JSON"):
            parse_event(b'{"id":"one","id":"two"}')
        invalid_number = clone_event()
        invalid_number["data"]["validation"]["stateVersion"] = float("nan")
        with self.assertRaisesRegex(ReceiverError, "UTF-8 JSON"):
            parse_event(json.dumps(invalid_number).encode())

    def test_rejects_recommendation_and_identity_mismatch(self) -> None:
        recommendation = clone_event()
        recommendation["data"]["recommendation"] = "continue"
        with self.assertRaisesRegex(ReceiverError, "recommendation"):
            parse_event(json.dumps(recommendation).encode())
        identity = clone_event()
        identity["source"] = "prometa://organizations/org-2"
        with self.assertRaisesRegex(ReceiverError, "identity"):
            parse_event(json.dumps(identity).encode())

    def test_identity_encoding_matches_javascript_encode_uri_component(self) -> None:
        special = clone_event()
        special["data"]["organizationId"] = "org!*"
        special["data"]["validation"]["id"] = "validation()'"
        special["source"] = "prometa://organizations/org!*"
        special["subject"] = "release-validations/validation()'"
        parsed = parse_event(json.dumps(special).encode())
        self.assertEqual(parsed.organization_id, "org!*")
        self.assertEqual(parsed.validation_id, "validation()'")

    def test_transport_headers_bind_the_signed_event(self) -> None:
        action = parse_event(event_body())
        headers = {
            "content-type": "application/cloudevents+json; charset=utf-8",
            "x-prometa-event-id": "event-4",
            "idempotency-key": "event-4",
            "x-prometa-event-type": "release.validation.completed.v1",
            "x-prometa-state-version": "4",
        }
        validate_transport_headers(headers, action)
        headers["idempotency-key"] = "other"
        with self.assertRaisesRegex(ReceiverError, "transport identity"):
            validate_transport_headers(headers, action)


class SignatureTests(unittest.TestCase):
    def test_accepts_rotation_overlap_and_rejects_expiry(self) -> None:
        body = event_body()
        old = b"o" * 48
        current = b"n" * 48
        timestamp = 1_774_180_800
        verify_signature(
            body=body,
            signature_header=sign_for_test(body, old, timestamp),
            timestamp_header=str(timestamp),
            secrets=(current, old),
            now=lambda: timestamp + 10,
        )
        with self.assertRaisesRegex(ReceiverError, "outside tolerance"):
            verify_signature(
                body=body,
                signature_header=sign_for_test(body, old, timestamp),
                timestamp_header=str(timestamp),
                secrets=(old,),
                now=lambda: timestamp + 301,
            )

    def test_rejects_malformed_and_wrong_signatures(self) -> None:
        body = event_body()
        secret = b"s" * 48
        with self.assertRaises(ReceiverError):
            verify_signature(
                body=body,
                signature_header="t=1,v1=not-hex",
                timestamp_header="1",
                secrets=(secret,),
                now=lambda: 1,
            )
        with self.assertRaisesRegex(ReceiverError, "signature is invalid"):
            verify_signature(
                body=body,
                signature_header=sign_for_test(body, b"x" * 48, 1),
                timestamp_header="1",
                secrets=(secret,),
                now=lambda: 1,
            )

    def test_secret_file_contract(self) -> None:
        self.assertEqual(
            load_signing_secrets(b"a" * 32 + b"\n" + b"b" * 48), (b"a" * 32, b"b" * 48)
        )
        with self.assertRaises(ValueError):
            load_signing_secrets(b"short")
        with self.assertRaises(ValueError):
            load_signing_secrets(b"a" * 32 + b"\n" + b"b" * 32 + b"\n" + b"c" * 32)


if __name__ == "__main__":
    unittest.main()
