from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm

from .contracts import SyntheticError, identity_digest, strict_json


class JwksFetcher(Protocol):
    async def fetch(self) -> dict[str, Any]: ...


class HttpJwksFetcher:
    def __init__(
        self,
        url: str,
        ca_file: str,
        *,
        timeout_seconds: float = 5.0,
        maximum_bytes: int = 262_144,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = url
        self._ca_file = ca_file
        self._timeout = timeout_seconds
        self._maximum_bytes = maximum_bytes
        self._transport = transport

    async def fetch(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                verify=self._ca_file,
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                async with client.stream(
                    "GET", self._url, headers={"accept": "application/json"}
                ) as response:
                    if response.status_code != 200:
                        raise SyntheticError("identity_provider_unavailable", 503)
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            declared = int(content_length)
                        except ValueError as error:
                            raise SyntheticError(
                                "identity_provider_unavailable", 503
                            ) from error
                        if declared < 1 or declared > self._maximum_bytes:
                            raise SyntheticError("identity_provider_unavailable", 503)
                    chunks = bytearray()
                    async for chunk in response.aiter_bytes():
                        chunks.extend(chunk)
                        if len(chunks) > self._maximum_bytes:
                            raise SyntheticError("identity_provider_unavailable", 503)
        except SyntheticError:
            raise
        except (httpx.HTTPError, OSError) as error:
            raise SyntheticError("identity_provider_unavailable", 503) from error

        try:
            parsed = strict_json(bytes(chunks), maximum_bytes=self._maximum_bytes)
        except SyntheticError as error:
            raise SyntheticError("identity_provider_unavailable", 503) from error
        if not isinstance(parsed, dict):
            raise SyntheticError("identity_provider_unavailable", 503)
        return parsed


@dataclass(frozen=True)
class VerifiedIdentity:
    subject: str
    tenant_id: str
    actor_digest: str
    key_id: str


def _decode_segment(segment: str) -> bytes:
    if not segment or "=" in segment:
        raise SyntheticError("unauthorized", 401)
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, TypeError) as error:
        raise SyntheticError("unauthorized", 401) from error
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != segment:
        raise SyntheticError("unauthorized", 401)
    return raw


def _strict_token_parts(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if not token or len(token) > 16_384 or not token.isascii():
        raise SyntheticError("unauthorized", 401)
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        raise SyntheticError("unauthorized", 401)
    try:
        header = strict_json(_decode_segment(parts[0]), maximum_bytes=4096)
        claims = strict_json(_decode_segment(parts[1]), maximum_bytes=12_288)
    except SyntheticError as error:
        raise SyntheticError("unauthorized", 401) from error
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise SyntheticError("unauthorized", 401)
    if not {"alg", "kid"}.issubset(header) or not set(header).issubset(
        {"alg", "kid", "typ"}
    ):
        raise SyntheticError("unauthorized", 401)
    if header["alg"] != "RS256" or (
        "typ" in header and header["typ"] not in {"JWT", "at+jwt"}
    ):
        raise SyntheticError("unauthorized", 401)
    if (
        not isinstance(header["kid"], str)
        or not header["kid"]
        or len(header["kid"]) > 256
        or header["kid"].strip() != header["kid"]
    ):
        raise SyntheticError("unauthorized", 401)
    return header, claims


def _parse_jwks(value: dict[str, Any]) -> dict[str, RSAPublicKey]:
    if set(value) != {"keys"} or not isinstance(value["keys"], list):
        raise SyntheticError("identity_provider_unavailable", 503)
    if not 1 <= len(value["keys"]) <= 16:
        raise SyntheticError("identity_provider_unavailable", 503)
    result: dict[str, RSAPublicKey] = {}
    for item in value["keys"]:
        if not isinstance(item, dict):
            raise SyntheticError("identity_provider_unavailable", 503)
        if any(field in item for field in ("d", "p", "q", "dp", "dq", "qi")):
            raise SyntheticError("identity_provider_unavailable", 503)
        if item.get("kty") != "RSA" or item.get("alg") not in {None, "RS256"}:
            continue
        if item.get("use") not in {None, "sig"}:
            continue
        kid = item.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 256 or kid in result:
            raise SyntheticError("identity_provider_unavailable", 503)
        try:
            key = RSAAlgorithm.from_jwk(json.dumps(item))
        except (TypeError, ValueError, jwt.PyJWTError) as error:
            raise SyntheticError("identity_provider_unavailable", 503) from error
        if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
            raise SyntheticError("identity_provider_unavailable", 503)
        result[kid] = key
    if not result:
        raise SyntheticError("identity_provider_unavailable", 503)
    return result


class OidcJwtVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        tenant_claim: str,
        tenant_id: str,
        required_scope: str,
        fetcher: JwksFetcher,
        jwks_ttl_seconds: int,
        clock_skew_seconds: int,
        maximum_token_age_seconds: int,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._tenant_claim = tenant_claim
        self._tenant_id = tenant_id
        self._required_scope = required_scope
        self._fetcher = fetcher
        self._jwks_ttl = jwks_ttl_seconds
        self._clock_skew = clock_skew_seconds
        self._maximum_token_age = maximum_token_age_seconds
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._keys: dict[str, RSAPublicKey] = {}
        self._keys_expire_at = 0.0
        self._lock = asyncio.Lock()

    async def _refresh(self) -> None:
        keys = _parse_jwks(await self._fetcher.fetch())
        self._keys = keys
        self._keys_expire_at = self._monotonic_clock() + self._jwks_ttl

    async def _key(self, kid: str) -> RSAPublicKey:
        async with self._lock:
            now = self._monotonic_clock()
            if now >= self._keys_expire_at:
                await self._refresh()
            key = self._keys.get(kid)
            if key is None:
                await self._refresh()
                key = self._keys.get(kid)
            if key is None:
                raise SyntheticError("unauthorized", 401)
            return key

    async def verify(self, token: str) -> VerifiedIdentity:
        header, untrusted_claims = _strict_token_parts(token)
        key = await self._key(header["kid"])
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "require": ["iss", "aud", "sub", "exp", "iat"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError as error:
            raise SyntheticError("unauthorized", 401) from error
        if claims != untrusted_claims:
            raise SyntheticError("unauthorized", 401)

        now = int(self._wall_clock())
        exp = claims.get("exp")
        iat = claims.get("iat")
        nbf = claims.get("nbf")
        if type(exp) is not int or type(iat) is not int:
            raise SyntheticError("unauthorized", 401)
        if nbf is not None and type(nbf) is not int:
            raise SyntheticError("unauthorized", 401)
        if (
            exp <= iat
            or now > exp + self._clock_skew
            or iat > now + self._clock_skew
            or now - iat > self._maximum_token_age + self._clock_skew
            or (nbf is not None and nbf > now + self._clock_skew)
        ):
            raise SyntheticError("unauthorized", 401)

        subject = claims.get("sub")
        tenant_id = claims.get(self._tenant_claim)
        scope = claims.get("scope")
        if (
            not isinstance(subject, str)
            or not subject
            or len(subject) > 256
            or subject != subject.strip()
            or tenant_id != self._tenant_id
            or not isinstance(scope, str)
        ):
            raise SyntheticError("forbidden", 403)
        scopes = scope.split(" ")
        if (
            not scopes
            or any(not item for item in scopes)
            or len(scopes) != len(set(scopes))
            or self._required_scope not in scopes
        ):
            raise SyntheticError("forbidden", 403)
        return VerifiedIdentity(
            subject=subject,
            tenant_id=tenant_id,
            actor_digest=identity_digest(self._issuer, subject),
            key_id=header["kid"],
        )
