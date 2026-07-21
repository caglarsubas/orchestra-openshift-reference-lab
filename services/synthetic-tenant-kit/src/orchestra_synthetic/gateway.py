from __future__ import annotations

import hmac
import threading
from collections import Counter
from typing import Any, Protocol

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from .config import GatewayConfig
from .contracts import (
    SyntheticError,
    canonical_json,
    parse_runtime_request,
    parse_runtime_response,
)
from .oidc import HttpJwksFetcher, OidcJwtVerifier, VerifiedIdentity


class IdentityVerifier(Protocol):
    async def verify(self, token: str) -> VerifiedIdentity: ...


class RuntimeExecutor(Protocol):
    async def execute(self, request: dict[str, Any]) -> dict[str, Any]: ...


class GatewayMetrics:
    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._lock = threading.Lock()

    def record(self, outcome: str) -> None:
        with self._lock:
            self._counts[outcome] += 1

    def render(self) -> str:
        with self._lock:
            counts = dict(self._counts)
        lines = [
            "# HELP orchestra_synthetic_gateway_requests_total Tenant gateway requests by bounded outcome.",
            "# TYPE orchestra_synthetic_gateway_requests_total counter",
        ]
        for outcome in (
            "success",
            "unauthorized",
            "forbidden",
            "invalid",
            "runtime_error",
            "internal_error",
        ):
            lines.append(
                'orchestra_synthetic_gateway_requests_total{outcome="%s"} %d'
                % (outcome, counts.get(outcome, 0))
            )
        return "\n".join(lines) + "\n"


class HttpRuntimeExecutor:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        try:
            token = config.runtime_token.decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError("runtime token must be ASCII") from error
        if (
            len(token) < 32
            or len(token) > 4096
            or token != token.strip()
            or any(ord(character) < 33 or ord(character) > 126 for character in token)
        ):
            raise RuntimeError("runtime token is invalid")
        self._endpoint = config.runtime_endpoint
        self._token = token
        self._ca_file = config.runtime_ca_file
        self._client_certificate = (
            (config.runtime_client_certificate_file, config.runtime_client_key_file)
            if config.runtime_client_certificate_file and config.runtime_client_key_file
            else None
        )
        self._timeout = config.runtime_timeout_seconds
        self._maximum_response_bytes = config.maximum_response_bytes
        self._transport = transport

    async def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        body = canonical_json(request)
        try:
            async with httpx.AsyncClient(
                verify=self._ca_file,
                cert=self._client_certificate,
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                async with client.stream(
                    "POST",
                    self._endpoint,
                    headers={
                        "authorization": f"Bearer {self._token}",
                        "content-type": "application/json",
                        "accept": "application/json",
                    },
                    content=body,
                ) as response:
                    if response.status_code != 200:
                        if response.status_code in {408, 425, 429, 502, 503, 504}:
                            raise SyntheticError("runtime_unavailable", 503)
                        raise SyntheticError("runtime_rejected", 502)
                    content_type = response.headers.get("content-type", "").split(
                        ";", 1
                    )[0]
                    if content_type != "application/json":
                        raise SyntheticError("runtime_response_invalid", 502)
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            declared = int(content_length)
                        except ValueError as error:
                            raise SyntheticError(
                                "runtime_response_invalid", 502
                            ) from error
                        if declared < 1 or declared > self._maximum_response_bytes:
                            raise SyntheticError("runtime_response_invalid", 502)
                    payload = bytearray()
                    async for chunk in response.aiter_bytes():
                        payload.extend(chunk)
                        if len(payload) > self._maximum_response_bytes:
                            raise SyntheticError("runtime_response_invalid", 502)
        except SyntheticError:
            raise
        except (httpx.HTTPError, OSError) as error:
            raise SyntheticError("runtime_unavailable", 503) from error

        result = parse_runtime_response(
            bytes(payload), maximum_bytes=self._maximum_response_bytes
        )
        if result["requestId"] != request["requestId"]:
            raise SyntheticError("runtime_response_invalid", 502)
        return result


def _error(code: str, status: int) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code}},
        status_code=status,
        headers={"cache-control": "no-store"},
    )


async def _bounded_body(request: Request, maximum_bytes: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as error:
            raise SyntheticError("request_invalid", 400) from error
        if declared < 1 or declared > maximum_bytes:
            raise SyntheticError("request_too_large", 413)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum_bytes:
            raise SyntheticError("request_too_large", 413)
    return bytes(body)


class TenantGateway:
    def __init__(
        self,
        config: GatewayConfig,
        verifier: IdentityVerifier,
        runtime: RuntimeExecutor,
        *,
        metrics: GatewayMetrics | None = None,
    ) -> None:
        self._config = config
        self._verifier = verifier
        self._runtime = runtime
        self._metrics = metrics or GatewayMetrics()

    async def health(self, _request: Request) -> Response:
        return JSONResponse({"status": "ok", "role": "tenant-gateway"})

    async def ready(self, _request: Request) -> Response:
        return JSONResponse({"status": "ready", "role": "tenant-gateway"})

    async def metrics(self, _request: Request) -> Response:
        return PlainTextResponse(
            self._metrics.render(), media_type="text/plain; version=0.0.4"
        )

    async def execute(self, request: Request) -> Response:
        try:
            if request.headers.get("content-type", "").split(";", 1)[0] != (
                "application/json"
            ):
                raise SyntheticError("content_type_unsupported", 415)
            authorization = request.headers.getlist("authorization")
            if len(authorization) != 1 or not authorization[0].startswith("Bearer "):
                raise SyntheticError("unauthorized", 401)
            token = authorization[0][7:]
            if not token or not hmac.compare_digest(token, token.strip()):
                raise SyntheticError("unauthorized", 401)
            await self._verifier.verify(token)
            body = await _bounded_body(request, self._config.maximum_request_bytes)
            parsed = parse_runtime_request(
                body, maximum_bytes=self._config.maximum_request_bytes
            )
            result = await self._runtime.execute(parsed)
            self._metrics.record("success")
            return JSONResponse(
                result,
                status_code=200,
                headers={"cache-control": "no-store"},
            )
        except SyntheticError as error:
            if error.code == "unauthorized":
                outcome = "unauthorized"
            elif error.code == "forbidden":
                outcome = "forbidden"
            elif error.code.startswith("runtime_"):
                outcome = "runtime_error"
            else:
                outcome = "invalid"
            self._metrics.record(outcome)
            return _error(error.code, error.status)
        except Exception:
            self._metrics.record("internal_error")
            return _error("internal_error", 500)

    def application(self) -> Starlette:
        return Starlette(
            debug=False,
            routes=[
                Route("/healthz", self.health, methods=["GET"]),
                Route("/readyz", self.ready, methods=["GET"]),
                Route("/metrics", self.metrics, methods=["GET"]),
                Route("/v1/tenant/execute", self.execute, methods=["POST"]),
            ],
        )


def build_gateway(config: GatewayConfig) -> TenantGateway:
    verifier = OidcJwtVerifier(
        issuer=config.issuer,
        audience=config.audience,
        tenant_claim=config.tenant_claim,
        tenant_id=config.tenant_id,
        required_scope=config.required_scope,
        fetcher=HttpJwksFetcher(config.jwks_url, config.oidc_ca_file),
        jwks_ttl_seconds=config.jwks_ttl_seconds,
        clock_skew_seconds=config.clock_skew_seconds,
        maximum_token_age_seconds=config.maximum_token_age_seconds,
    )
    return TenantGateway(config, verifier, HttpRuntimeExecutor(config))
