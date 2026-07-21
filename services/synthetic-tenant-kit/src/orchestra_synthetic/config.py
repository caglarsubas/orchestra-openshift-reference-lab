from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .contracts import read_file


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CLAIM = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value or value != value.strip() or "\x00" in value:
        raise RuntimeError(f"{name} is required")
    return value


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer") from error
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def _https_url(name: str, *, path_suffix: str | None = None) -> str:
    value = _required(name)
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise RuntimeError(f"{name} has an invalid port") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise RuntimeError(f"{name} must be an HTTPS URL without credentials")
    if path_suffix is not None and parsed.path != path_suffix:
        raise RuntimeError(f"{name} must end at {path_suffix}")
    return value.rstrip("/")


def _mounted_file(name: str, *, maximum_bytes: int = 262_144) -> str:
    path = _required(name)
    read_file(path, maximum_bytes=maximum_bytes)
    return path


def _optional_mounted_file(name: str, *, maximum_bytes: int = 262_144) -> str | None:
    path = os.environ.get(name)
    if not path:
        return None
    if path != path.strip():
        raise RuntimeError(f"{name} is invalid")
    read_file(path, maximum_bytes=maximum_bytes)
    return path


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int
    certificate_file: str
    private_key_file: str
    client_ca_file: str | None

    @classmethod
    def from_env(cls) -> "ServerConfig":
        host = os.environ.get("SYNTHETIC_LISTEN_HOST", "0.0.0.0")
        if host not in {"0.0.0.0", "::"}:
            raise RuntimeError("SYNTHETIC_LISTEN_HOST must bind all pod interfaces")
        return cls(
            host=host,
            port=_bounded_int("SYNTHETIC_LISTEN_PORT", 8443, 1024, 65535),
            certificate_file=_mounted_file("SYNTHETIC_TLS_CERTIFICATE_FILE"),
            private_key_file=_mounted_file("SYNTHETIC_TLS_PRIVATE_KEY_FILE"),
            client_ca_file=_optional_mounted_file("SYNTHETIC_TLS_CLIENT_CA_FILE"),
        )


@dataclass(frozen=True)
class GatewayConfig:
    issuer: str
    audience: str
    jwks_url: str
    oidc_ca_file: str
    tenant_claim: str
    tenant_id: str
    required_scope: str
    jwks_ttl_seconds: int
    clock_skew_seconds: int
    maximum_token_age_seconds: int
    maximum_request_bytes: int
    maximum_response_bytes: int
    runtime_endpoint: str
    runtime_token: bytes
    runtime_ca_file: str
    runtime_client_certificate_file: str | None
    runtime_client_key_file: str | None
    runtime_timeout_seconds: int

    @classmethod
    def from_env(cls) -> "GatewayConfig":
        tenant_claim = os.environ.get("SYNTHETIC_TENANT_CLAIM", "org_id")
        tenant_id = _required("SYNTHETIC_TENANT_ID")
        audience = _required("SYNTHETIC_OIDC_AUDIENCE")
        required_scope = os.environ.get("SYNTHETIC_REQUIRED_SCOPE", "runtime:execute")
        for name, value in (
            ("SYNTHETIC_TENANT_ID", tenant_id),
            ("SYNTHETIC_OIDC_AUDIENCE", audience),
            ("SYNTHETIC_REQUIRED_SCOPE", required_scope),
        ):
            if not _NAME.fullmatch(value):
                raise RuntimeError(f"{name} is invalid")
        if not _CLAIM.fullmatch(tenant_claim):
            raise RuntimeError("SYNTHETIC_TENANT_CLAIM is invalid")
        if (
            audience != "orchestra-tenant-gateway"
            or tenant_claim != "org_id"
            or tenant_id != "tenant-alpha"
            or required_scope != "runtime:execute"
        ):
            raise RuntimeError("synthetic gateway identity contract is locked")

        client_certificate = _optional_mounted_file(
            "SYNTHETIC_RUNTIME_CLIENT_CERTIFICATE_FILE"
        )
        client_key = _optional_mounted_file("SYNTHETIC_RUNTIME_CLIENT_KEY_FILE")
        if bool(client_certificate) != bool(client_key):
            raise RuntimeError(
                "runtime client certificate and key must be configured together"
            )

        return cls(
            issuer=_https_url("SYNTHETIC_OIDC_ISSUER"),
            audience=audience,
            jwks_url=_https_url("SYNTHETIC_OIDC_JWKS_URL"),
            oidc_ca_file=_mounted_file("SYNTHETIC_OIDC_CA_FILE"),
            tenant_claim=tenant_claim,
            tenant_id=tenant_id,
            required_scope=required_scope,
            jwks_ttl_seconds=_bounded_int("SYNTHETIC_JWKS_TTL_SECONDS", 300, 30, 3600),
            clock_skew_seconds=_bounded_int("SYNTHETIC_CLOCK_SKEW_SECONDS", 30, 0, 120),
            maximum_token_age_seconds=_bounded_int(
                "SYNTHETIC_MAXIMUM_TOKEN_AGE_SECONDS", 900, 60, 3600
            ),
            maximum_request_bytes=_bounded_int(
                "SYNTHETIC_MAXIMUM_REQUEST_BYTES", 262_144, 1024, 1_048_576
            ),
            maximum_response_bytes=_bounded_int(
                "SYNTHETIC_MAXIMUM_RESPONSE_BYTES", 1_048_576, 1024, 4_194_304
            ),
            runtime_endpoint=_https_url(
                "SYNTHETIC_RUNTIME_ENDPOINT", path_suffix="/v1/runtime/execute"
            ),
            runtime_token=read_file(
                _required("SYNTHETIC_RUNTIME_TOKEN_FILE"), maximum_bytes=8192
            ),
            runtime_ca_file=_mounted_file("SYNTHETIC_RUNTIME_CA_FILE"),
            runtime_client_certificate_file=client_certificate,
            runtime_client_key_file=client_key,
            runtime_timeout_seconds=_bounded_int(
                "SYNTHETIC_RUNTIME_TIMEOUT_SECONDS", 30, 1, 120
            ),
        )


@dataclass(frozen=True)
class McpConfig:
    mode: str
    tenant_id: str
    bearer_token: bytes
    slow_milliseconds: int

    @classmethod
    def from_env(cls) -> "McpConfig":
        mode = _required("SYNTHETIC_MCP_MODE")
        if mode not in {"normal", "slow", "unavailable", "wrong-tenant"}:
            raise RuntimeError("SYNTHETIC_MCP_MODE is invalid")
        tenant_id = _required("SYNTHETIC_MCP_TENANT_ID")
        expected_tenant = "tenant-beta" if mode == "wrong-tenant" else "tenant-alpha"
        if tenant_id != expected_tenant:
            raise RuntimeError(
                f"SYNTHETIC_MCP_TENANT_ID must be {expected_tenant} for {mode} mode"
            )
        token = read_file(_required("SYNTHETIC_MCP_TOKEN_FILE"), maximum_bytes=8192)
        if len(token) < 32:
            raise RuntimeError(
                "SYNTHETIC_MCP_TOKEN_FILE must contain at least 32 bytes"
            )
        return cls(
            mode=mode,
            tenant_id=tenant_id,
            bearer_token=token,
            slow_milliseconds=_bounded_int(
                "SYNTHETIC_MCP_SLOW_MILLISECONDS", 5000, 100, 120_000
            ),
        )


def service_role_from_env() -> str:
    role = _required("SYNTHETIC_SERVICE_ROLE")
    if role not in {"tenant-gateway", "mcp"}:
        raise RuntimeError("SYNTHETIC_SERVICE_ROLE is invalid")
    return role


def ensure_private_key_permissions(path: str) -> None:
    mode = Path(path).stat().st_mode & 0o777
    if mode & 0o007:
        raise RuntimeError("TLS private key must not be world-accessible")
