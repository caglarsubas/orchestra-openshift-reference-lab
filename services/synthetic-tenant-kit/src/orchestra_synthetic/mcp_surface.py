from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import threading
from collections import Counter

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from .config import McpConfig


_ORDER_ID = re.compile(r"^order-[a-z0-9]{1,32}$")


class McpMetrics:
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
            "# HELP orchestra_synthetic_mcp_requests_total MCP requests by bounded outcome.",
            "# TYPE orchestra_synthetic_mcp_requests_total counter",
        ]
        for outcome in ("completed", "unauthorized", "forbidden", "unavailable"):
            lines.append(
                'orchestra_synthetic_mcp_requests_total{outcome="%s"} %d'
                % (outcome, counts.get(outcome, 0))
            )
        return "\n".join(lines) + "\n"


async def _http_error(send, code: str, status: int) -> None:
    body = json.dumps(
        {"error": {"code": code}}, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class McpAccessBoundary:
    def __init__(self, app, config: McpConfig, metrics: McpMetrics) -> None:
        self._app = app
        self._config = config
        self._metrics = metrics
        try:
            self._token = config.bearer_token.decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError("MCP bearer token must be ASCII") from error
        if (
            len(self._token) < 32
            or len(self._token) > 4096
            or self._token != self._token.strip()
            or any(
                ord(character) < 33 or ord(character) > 126 for character in self._token
            )
        ):
            raise RuntimeError("MCP bearer token is invalid")

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("path") != "/mcp":
            await self._app(scope, receive, send)
            return
        if self._config.mode == "unavailable":
            self._metrics.record("unavailable")
            await _http_error(send, "synthetic_mcp_unavailable", 503)
            return

        headers: dict[bytes, list[bytes]] = {}
        for name, value in scope.get("headers", []):
            headers.setdefault(name.lower(), []).append(value)
        authorization = headers.get(b"authorization", [])
        tenants = headers.get(b"x-orchestra-tenant", [])
        expected_authorization = ("Bearer " + self._token).encode("ascii")
        if len(authorization) != 1 or not hmac.compare_digest(
            authorization[0], expected_authorization
        ):
            self._metrics.record("unauthorized")
            await _http_error(send, "unauthorized", 401)
            return
        if len(tenants) != 1 or not hmac.compare_digest(
            tenants[0], self._config.tenant_id.encode("ascii")
        ):
            self._metrics.record("forbidden")
            await _http_error(send, "tenant_forbidden", 403)
            return
        await self._app(scope, receive, send)


def create_mcp_application(config: McpConfig):
    metrics = McpMetrics()
    mcp = FastMCP(
        "Orchestra synthetic read-only tools",
        instructions="Synthetic read-only evidence surface; no customer data.",
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        log_level="WARNING",
    )

    @mcp.tool(
        name="lookup_order_status",
        description="Read one deterministic synthetic order status.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
        structured_output=True,
    )
    async def lookup_order_status(order_id: str) -> dict[str, str]:
        if not _ORDER_ID.fullmatch(order_id):
            raise ValueError("order_id_invalid")
        if config.mode == "slow":
            await asyncio.sleep(config.slow_milliseconds / 1000)
        bucket = int(hashlib.sha256(order_id.encode("ascii")).hexdigest()[:2], 16)
        metrics.record("completed")
        return {
            "orderId": order_id,
            "status": ("ready" if bucket % 2 == 0 else "processing"),
            "source": "synthetic-reference-lab",
        }

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "role": "synthetic-mcp"})

    @mcp.custom_route("/readyz", methods=["GET"], include_in_schema=False)
    async def ready(_request: Request) -> JSONResponse:
        status = "degraded" if config.mode == "unavailable" else "ready"
        return JSONResponse({"status": status, "role": "synthetic-mcp"})

    @mcp.custom_route("/metrics", methods=["GET"], include_in_schema=False)
    async def prometheus_metrics(_request: Request) -> PlainTextResponse:
        return PlainTextResponse(
            metrics.render(), media_type="text/plain; version=0.0.4"
        )

    return McpAccessBoundary(mcp.streamable_http_app(), config, metrics)
