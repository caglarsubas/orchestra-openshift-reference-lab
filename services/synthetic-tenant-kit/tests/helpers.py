from __future__ import annotations

import base64
import json
from dataclasses import replace
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwt.algorithms import RSAAlgorithm

from orchestra_synthetic.config import GatewayConfig


NOW = 1_800_000_000


def gateway_config(**changes: Any) -> GatewayConfig:
    config = GatewayConfig(
        issuer="https://identity.lab.example/realms/orchestra",
        audience="orchestra-tenant-gateway",
        jwks_url="https://identity.lab.example/realms/orchestra/protocol/openid-connect/certs",
        oidc_ca_file="/trust/identity-ca.pem",
        tenant_claim="org_id",
        tenant_id="tenant-alpha",
        required_scope="runtime:execute",
        jwks_ttl_seconds=300,
        clock_skew_seconds=30,
        maximum_token_age_seconds=900,
        maximum_request_bytes=262_144,
        maximum_response_bytes=1_048_576,
        runtime_endpoint="https://runtime.lab.example/v1/runtime/execute",
        runtime_token=b"r" * 48,
        runtime_ca_file="/trust/runtime-ca.pem",
        runtime_client_certificate_file=None,
        runtime_client_key_file=None,
        runtime_timeout_seconds=30,
    )
    return replace(config, **changes)


def rsa_identity(kid: str = "kid-1"):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return private, jwk


def token(
    private,
    *,
    kid: str = "kid-1",
    issuer: str = "https://identity.lab.example/realms/orchestra",
    audience: str = "orchestra-tenant-gateway",
    tenant_id: str = "tenant-alpha",
    scope: str = "openid runtime:execute",
    subject: str = "synthetic-user-alpha",
    issued_at: int = NOW - 30,
    expires_at: int = NOW + 300,
) -> str:
    return jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "iat": issued_at,
            "exp": expires_at,
            "nbf": issued_at,
            "org_id": tenant_id,
            "scope": scope,
        },
        private,
        algorithm="RS256",
        headers={"kid": kid, "typ": "JWT"},
    )


def duplicate_claim_token(private) -> str:
    header = b'{"alg":"RS256","kid":"kid-1","typ":"JWT"}'
    claims = (
        b'{"iss":"https://identity.lab.example/realms/orchestra",'
        b'"aud":"orchestra-tenant-gateway","sub":"alpha","iat":1799999970,'
        b'"exp":1800000300,"org_id":"tenant-alpha",'
        b'"org_id":"tenant-beta","scope":"runtime:execute"}'
    )

    def encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    signing_input = f"{encode(header)}.{encode(claims)}".encode("ascii")
    signature = private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode("ascii") + "." + encode(signature)
