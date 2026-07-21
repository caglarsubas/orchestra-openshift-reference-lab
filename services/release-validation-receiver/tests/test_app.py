from __future__ import annotations

import io
import json
import time
import unittest
from typing import Any

from orchestra_receiver.app import ReceiverApplication
from orchestra_receiver.config import ApiConfig
from orchestra_receiver.store import AdmissionResult
from orchestra_receiver.signing import sign_for_test

from .helpers import digest, event_body


class FakeStore:
    def __init__(self) -> None:
        self.actions = []
        self.reconciliations = []

    def ready(self) -> bool:
        return True

    def admit(self, action):
        self.actions.append(action)
        return AdmissionResult(
            outcome="applied",
            event_id=action.event_id,
            validation_id=action.validation_id,
            state_version=action.state_version,
            recommendation=action.recommendation,
            action_state="queued",
        )

    def status_counts(self):
        return {"PENDING": 1, "INDETERMINATE": 2}

    def event_status(self, event_id):
        return {"event_id": event_id, "action_status": "INDETERMINATE"}

    def reconcile(self, event_id, resolved_status, evidence_digest, actor_digest):
        self.reconciliations.append(
            (event_id, resolved_status, evidence_digest, actor_digest)
        )


def call(
    app,
    method: str,
    path: str,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
):
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    for name, value in (headers or {}).items():
        normalized = name.upper().replace("-", "_")
        if normalized == "CONTENT_TYPE":
            environ["CONTENT_TYPE"] = value
        else:
            environ[f"HTTP_{normalized}"] = value
    captured: dict[str, Any] = {}

    def start_response(status, response_headers):
        captured["status"] = int(status.split(" ", 1)[0])
        captured["headers"] = dict(response_headers)

    raw = b"".join(app(environ, start_response))
    content_type = captured["headers"].get("Content-Type", "")
    payload = json.loads(raw) if content_type == "application/json" else raw.decode()
    return captured["status"], payload


class ApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = b"s" * 48
        self.admin = b"a" * 48
        self.store = FakeStore()
        self.app = ReceiverApplication(
            ApiConfig(
                database_url="unused",
                signing_secrets=(self.secret,),
                admin_token=self.admin,
                signature_tolerance_seconds=300,
                maximum_body_bytes=262_144,
            ),
            self.store,
        )

    def webhook_headers(self, body: bytes) -> dict[str, str]:
        timestamp = int(time.time())
        return {
            "Content-Type": "application/cloudevents+json",
            "X-Prometa-Signature": sign_for_test(body, self.secret, timestamp),
            "X-Prometa-Timestamp": str(timestamp),
            "X-Prometa-Event-Id": "event-4",
            "X-Prometa-Event-Type": "release.validation.completed.v1",
            "X-Prometa-State-Version": "4",
            "Idempotency-Key": "event-4",
        }

    def test_accepts_valid_event_after_signature_and_header_checks(self) -> None:
        body = event_body()
        status, payload = call(
            self.app,
            "POST",
            "/v1/release-validation/completed",
            body,
            self.webhook_headers(body),
        )
        self.assertEqual(status, 202)
        self.assertEqual(payload["actionState"], "queued")
        self.assertEqual(len(self.store.actions), 1)

    def test_rejects_signature_before_parsing(self) -> None:
        body = b"not-json"
        headers = self.webhook_headers(body)
        headers["X-Prometa-Signature"] = sign_for_test(
            body, b"x" * 48, int(time.time())
        )
        status, payload = call(
            self.app, "POST", "/v1/release-validation/completed", body, headers
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "invalid_signature")
        self.assertEqual(self.store.actions, [])

    def test_admin_status_and_reconciliation_require_bearer_token(self) -> None:
        status, _ = call(self.app, "GET", "/internal/v1/actions/event-4")
        self.assertEqual(status, 401)
        headers = {"Authorization": f"Bearer {self.admin.decode()}"}
        status, payload = call(
            self.app, "GET", "/internal/v1/actions/event-4", headers=headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["action_status"], "INDETERMINATE")

        body = json.dumps(
            {
                "resolvedStatus": "DELIVERED",
                "evidenceDigest": digest("reconciliation"),
                "actorDigest": digest("actor"),
            }
        ).encode()
        status, payload = call(
            self.app,
            "POST",
            "/internal/v1/actions/event-4/reconcile",
            body,
            {**headers, "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["resolvedStatus"], "DELIVERED")
        self.assertEqual(len(self.store.reconciliations), 1)

    def test_health_readiness_and_metrics(self) -> None:
        self.assertEqual(call(self.app, "GET", "/healthz")[0], 200)
        self.assertEqual(call(self.app, "GET", "/readyz")[1], {"ready": True})
        status, metrics = call(self.app, "GET", "/metrics")
        self.assertEqual(status, 200)
        self.assertIn('status="indeterminate"} 2', metrics)


if __name__ == "__main__":
    unittest.main()
