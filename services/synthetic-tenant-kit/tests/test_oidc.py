from __future__ import annotations

import unittest

import certifi
import httpx

from orchestra_synthetic.contracts import SyntheticError, identity_digest
from orchestra_synthetic.oidc import HttpJwksFetcher, OidcJwtVerifier

from tests.helpers import NOW, duplicate_claim_token, rsa_identity, token


class FakeFetcher:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    async def fetch(self):
        self.calls += 1
        if not self.responses:
            raise SyntheticError("identity_provider_unavailable", 503)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def verifier(fetcher, *, monotonic=lambda: 100.0):
    return OidcJwtVerifier(
        issuer="https://identity.lab.example/realms/orchestra",
        audience="orchestra-tenant-gateway",
        tenant_claim="org_id",
        tenant_id="tenant-alpha",
        required_scope="runtime:execute",
        fetcher=fetcher,
        jwks_ttl_seconds=300,
        clock_skew_seconds=30,
        maximum_token_age_seconds=900,
        wall_clock=lambda: NOW,
        monotonic_clock=monotonic,
    )


class OidcVerifierTests(unittest.IsolatedAsyncioTestCase):
    async def test_accepts_exact_alpha_identity_and_caches_jwks(self) -> None:
        private, jwk = rsa_identity()
        fetcher = FakeFetcher({"keys": [jwk]})
        subject = await verifier(fetcher).verify(token(private))
        self.assertEqual(subject.tenant_id, "tenant-alpha")
        self.assertEqual(subject.key_id, "kid-1")
        self.assertEqual(
            subject.actor_digest,
            identity_digest(
                "https://identity.lab.example/realms/orchestra",
                "synthetic-user-alpha",
            ),
        )
        self.assertEqual(fetcher.calls, 1)

    async def test_rejects_beta_missing_scope_wrong_audience_and_expiry(self) -> None:
        private, jwk = rsa_identity()
        cases = (
            (token(private, tenant_id="tenant-beta"), "forbidden"),
            (token(private, scope="openid"), "forbidden"),
            (token(private, audience="another-audience"), "unauthorized"),
            (token(private, expires_at=NOW - 31), "unauthorized"),
        )
        for encoded, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(SyntheticError) as caught:
                    await verifier(FakeFetcher({"keys": [jwk]})).verify(encoded)
                self.assertEqual(caught.exception.code, code)

    async def test_unknown_kid_refreshes_once_for_rotation(self) -> None:
        old_private, old_jwk = rsa_identity("kid-old")
        new_private, new_jwk = rsa_identity("kid-new")
        fetcher = FakeFetcher({"keys": [old_jwk]}, {"keys": [old_jwk, new_jwk]})
        subject_verifier = verifier(fetcher)
        await subject_verifier.verify(token(old_private, kid="kid-old"))
        rotated = await subject_verifier.verify(token(new_private, kid="kid-new"))
        self.assertEqual(rotated.key_id, "kid-new")
        self.assertEqual(fetcher.calls, 2)

    async def test_expired_cache_fails_closed_when_provider_is_unavailable(
        self,
    ) -> None:
        private, jwk = rsa_identity()
        clock = [100.0]
        fetcher = FakeFetcher(
            {"keys": [jwk]},
            SyntheticError("identity_provider_unavailable", 503),
        )
        subject_verifier = verifier(fetcher, monotonic=lambda: clock[0])
        await subject_verifier.verify(token(private))
        clock[0] = 401.0
        with self.assertRaises(SyntheticError) as caught:
            await subject_verifier.verify(token(private))
        self.assertEqual(caught.exception.code, "identity_provider_unavailable")
        self.assertEqual(fetcher.calls, 2)

    async def test_duplicate_claims_and_private_jwk_material_are_rejected(self) -> None:
        private, jwk = rsa_identity()
        with self.assertRaises(SyntheticError) as duplicate:
            await verifier(FakeFetcher({"keys": [jwk]})).verify(
                duplicate_claim_token(private)
            )
        self.assertEqual(duplicate.exception.code, "unauthorized")

        private_jwk = dict(jwk)
        private_jwk["d"] = "not-allowed"
        with self.assertRaises(SyntheticError) as private_material:
            await verifier(FakeFetcher({"keys": [private_jwk]})).verify(token(private))
        self.assertEqual(
            private_material.exception.code, "identity_provider_unavailable"
        )


class HttpJwksFetcherTests(unittest.IsolatedAsyncioTestCase):
    async def test_accepts_bounded_jwks_without_ambient_proxy_or_redirect(self) -> None:
        _private, jwk = rsa_identity()
        calls = []

        async def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json={"keys": [jwk]})

        result = await HttpJwksFetcher(
            "https://identity.test/certs",
            certifi.where(),
            transport=httpx.MockTransport(handler),
        ).fetch()
        self.assertEqual(result, {"keys": [jwk]})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].url.scheme, "https")

    async def test_redirect_and_oversized_jwks_fail_closed(self) -> None:
        async def redirect(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"location": "https://other.test"})

        with self.assertRaises(SyntheticError) as redirected:
            await HttpJwksFetcher(
                "https://identity.test/certs",
                certifi.where(),
                transport=httpx.MockTransport(redirect),
            ).fetch()
        self.assertEqual(redirected.exception.code, "identity_provider_unavailable")

        async def oversized(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-length": "999999"},
                content=b"{}",
            )

        with self.assertRaises(SyntheticError) as too_large:
            await HttpJwksFetcher(
                "https://identity.test/certs",
                certifi.where(),
                maximum_bytes=1024,
                transport=httpx.MockTransport(oversized),
            ).fetch()
        self.assertEqual(too_large.exception.code, "identity_provider_unavailable")


if __name__ == "__main__":
    unittest.main()
