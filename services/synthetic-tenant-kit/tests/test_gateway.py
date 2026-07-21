from __future__ import annotations

import json
import unittest

import httpx

from orchestra_synthetic.contracts import SyntheticError, identity_digest
from orchestra_synthetic.gateway import HttpRuntimeExecutor, TenantGateway
from orchestra_synthetic.oidc import VerifiedIdentity

from tests.helpers import gateway_config


class FakeVerifier:
    def __init__(self, error: SyntheticError | None = None) -> None:
        self.error = error
        self.tokens: list[str] = []

    async def verify(self, token: str) -> VerifiedIdentity:
        self.tokens.append(token)
        if self.error:
            raise self.error
        return VerifiedIdentity(
            subject="synthetic-alpha",
            tenant_id="tenant-alpha",
            actor_digest=identity_digest("https://issuer", "synthetic-alpha"),
            key_id="kid-1",
        )


class FakeRuntime:
    def __init__(self, error: SyntheticError | None = None) -> None:
        self.error = error
        self.requests: list[dict] = []

    async def execute(self, request: dict) -> dict:
        self.requests.append(request)
        if self.error:
            raise self.error
        return {
            "requestId": request["requestId"],
            "output": {"answer": "synthetic-ok"},
            "modelName": "reference-cpu-model",
            "attempts": 1,
            "toolCalls": 0,
            "usedFallback": False,
        }


def runtime_response(request_id: str) -> dict:
    return {
        "requestId": request_id,
        "output": {"answer": "synthetic-ok"},
        "modelName": "reference-cpu-model",
        "attempts": 1,
        "toolCalls": 0,
        "usedFallback": False,
    }


class TenantGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def client(self, verifier=None, runtime=None):
        gateway = TenantGateway(
            gateway_config(), verifier or FakeVerifier(), runtime or FakeRuntime()
        )
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway.application()),
            base_url="https://tenant-gateway.test",
        )

    async def test_forwards_valid_alpha_request_and_exposes_bounded_metrics(
        self,
    ) -> None:
        verifier = FakeVerifier()
        runtime = FakeRuntime()
        async with await self.client(verifier, runtime) as client:
            response = await client.post(
                "/v1/tenant/execute",
                headers={"authorization": "Bearer alpha-token"},
                json={"requestId": "journey-1", "input": {"question": "status"}},
            )
            metrics = await client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), runtime_response("journey-1"))
        self.assertEqual(verifier.tokens, ["alpha-token"])
        self.assertEqual(
            runtime.requests,
            [{"requestId": "journey-1", "input": {"question": "status"}}],
        )
        self.assertIn('outcome="success"} 1', metrics.text)
        self.assertNotIn("journey-1", metrics.text)

    async def test_authentication_precedes_json_parsing(self) -> None:
        verifier = FakeVerifier()
        runtime = FakeRuntime()
        async with await self.client(verifier, runtime) as client:
            response = await client.post(
                "/v1/tenant/execute",
                content=b'{"broken":',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": {"code": "unauthorized"}})
        self.assertEqual(verifier.tokens, [])
        self.assertEqual(runtime.requests, [])

    async def test_rejects_beta_duplicate_json_and_duplicate_auth(self) -> None:
        beta = FakeVerifier(SyntheticError("forbidden", 403))
        async with await self.client(beta, FakeRuntime()) as client:
            forbidden = await client.post(
                "/v1/tenant/execute",
                headers={"authorization": "Bearer beta-token"},
                json={"requestId": "journey-2", "input": {}},
            )
        self.assertEqual(forbidden.status_code, 403)

        async with await self.client() as client:
            duplicate_json = await client.post(
                "/v1/tenant/execute",
                headers={
                    "authorization": "Bearer alpha-token",
                    "content-type": "application/json",
                },
                content=b'{"requestId":"one","requestId":"two","input":{}}',
            )
            duplicate_auth = await client.post(
                "/v1/tenant/execute",
                headers=[
                    ("authorization", "Bearer one"),
                    ("authorization", "Bearer two"),
                    ("content-type", "application/json"),
                ],
                content=b'{"requestId":"three","input":{}}',
            )
        self.assertEqual(duplicate_json.status_code, 400)
        self.assertEqual(
            duplicate_json.json(), {"error": {"code": "request_invalid_json"}}
        )
        self.assertEqual(duplicate_auth.status_code, 401)

    async def test_sanitizes_runtime_failures(self) -> None:
        runtime = FakeRuntime(SyntheticError("runtime_unavailable", 503))
        async with await self.client(FakeVerifier(), runtime) as client:
            response = await client.post(
                "/v1/tenant/execute",
                headers={"authorization": "Bearer alpha-token"},
                json={"requestId": "journey-3", "input": {}},
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": {"code": "runtime_unavailable"}})
        self.assertNotIn("runtime.lab.example", response.text)


class HttpRuntimeExecutorTests(unittest.IsolatedAsyncioTestCase):
    async def test_sends_bounded_request_and_accepts_exact_response(self) -> None:
        observed = []

        async def handler(request: httpx.Request) -> httpx.Response:
            observed.append(request)
            payload = json.loads(request.content)
            return httpx.Response(200, json=runtime_response(payload["requestId"]))

        executor = HttpRuntimeExecutor(
            gateway_config(), transport=httpx.MockTransport(handler)
        )
        result = await executor.execute({"requestId": "direct-1", "input": {}})
        self.assertEqual(result, runtime_response("direct-1"))
        self.assertEqual(observed[0].url.scheme, "https")
        self.assertEqual(observed[0].headers["authorization"], "Bearer " + "r" * 48)

    async def test_refuses_redirect_and_mismatched_response_identity(self) -> None:
        async def redirect(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(307, headers={"location": "https://other.test"})

        with self.assertRaises(SyntheticError) as redirected:
            await HttpRuntimeExecutor(
                gateway_config(), transport=httpx.MockTransport(redirect)
            ).execute({"requestId": "direct-2", "input": {}})
        self.assertEqual(redirected.exception.code, "runtime_rejected")

        async def mismatch(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=runtime_response("another-request"))

        with self.assertRaises(SyntheticError) as mismatched:
            await HttpRuntimeExecutor(
                gateway_config(), transport=httpx.MockTransport(mismatch)
            ).execute({"requestId": "direct-3", "input": {}})
        self.assertEqual(mismatched.exception.code, "runtime_response_invalid")


if __name__ == "__main__":
    unittest.main()
