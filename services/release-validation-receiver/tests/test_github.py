from __future__ import annotations

import json
import unittest
import urllib.error
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from orchestra_receiver.errors import (
    IndeterminateDispatchError,
    PermanentDispatchError,
    RetryableDispatchError,
)
from orchestra_receiver.github import GitHubAppExecutor

from .helpers import action


class FakeResponse:
    def __init__(
        self, status: int, body: bytes = b"", headers: dict[str, str] | None = None
    ):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self, _limit: int = -1) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def private_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


class GitHubExecutorTests(unittest.TestCase):
    def executor(self, opener, now: float = 1_774_180_800) -> GitHubAppExecutor:
        return GitHubAppExecutor(
            app_id="123",
            installation_id="456",
            private_key_pem=private_key(),
            repository_owner="tenant-alpha",
            repository_name="runtime-gitops",
            api_url="https://github.invalid",
            now=lambda: now,
            opener=opener,
        )

    def test_mints_installation_token_and_dispatches_bounded_payload(self) -> None:
        requests = []
        expires = (
            datetime.fromtimestamp(1_774_184_400, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

        def opener(request, timeout):
            requests.append((request, timeout))
            if request.full_url.endswith("/access_tokens"):
                return FakeResponse(
                    201,
                    json.dumps(
                        {
                            "token": "token-value-that-is-long-enough",
                            "expires_at": expires,
                        }
                    ).encode(),
                )
            return FakeResponse(204, headers={"X-GitHub-Request-Id": "request-1"})

        executor = self.executor(opener)
        receipt = executor.execute(action())
        self.assertEqual(receipt.request_id, "request-1")
        self.assertEqual(len(requests), 2)
        dispatch = requests[1][0]
        payload = json.loads(dispatch.data)
        self.assertEqual(payload["event_type"], "orchestra-release-validation")
        self.assertEqual(payload["client_payload"]["eventId"], "event-4")
        self.assertTrue(payload["client_payload"]["authority"]["recommendationOnly"])
        self.assertNotIn("bodyDigest", json.dumps(payload))

        executor.execute(action(event_id="event-5", state_version=5))
        self.assertEqual(
            sum(request.full_url.endswith("/access_tokens") for request, _ in requests),
            1,
        )

    def test_token_endpoint_transient_failure_is_retryable(self) -> None:
        def opener(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 503, "unavailable", {}, None)

        with self.assertRaises(RetryableDispatchError):
            self.executor(opener).execute(action())

    def test_rejects_expired_installation_token(self) -> None:
        def opener(_request, timeout):
            self.assertEqual(timeout, 10.0)
            return FakeResponse(
                201,
                json.dumps(
                    {
                        "token": "token-value-that-is-long-enough",
                        "expires_at": "2026-03-22T12:00:30Z",
                    }
                ).encode(),
            )

        with self.assertRaisesRegex(PermanentDispatchError, "already expired"):
            self.executor(opener).execute(action())

    def test_ambiguous_dispatch_network_failure_is_indeterminate(self) -> None:
        expires = "2026-03-22T13:00:00Z"
        calls = 0

        def opener(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                return FakeResponse(
                    201,
                    json.dumps(
                        {
                            "token": "token-value-that-is-long-enough",
                            "expires_at": expires,
                        }
                    ).encode(),
                )
            raise urllib.error.URLError("connection reset")

        with self.assertRaises(IndeterminateDispatchError):
            self.executor(opener, now=1_774_180_800).execute(action())

    def test_rejects_repository_path_or_non_https_api_configuration(self) -> None:
        with self.assertRaisesRegex(ValueError, "repository identity"):
            GitHubAppExecutor(
                app_id="123",
                installation_id="456",
                private_key_pem=private_key(),
                repository_owner="tenant/other",
                repository_name="runtime-gitops",
            )
        with self.assertRaisesRegex(ValueError, "HTTPS origin"):
            GitHubAppExecutor(
                app_id="123",
                installation_id="456",
                private_key_pem=private_key(),
                repository_owner="tenant",
                repository_name="runtime-gitops",
                api_url="http://github.invalid",
            )


if __name__ == "__main__":
    unittest.main()
