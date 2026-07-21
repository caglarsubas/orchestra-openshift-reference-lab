from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
import unittest

import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from orchestra_synthetic.config import McpConfig
from orchestra_synthetic.mcp_surface import create_mcp_application


TOKEN = b"mcp-synthetic-token-0123456789abcdef"


@contextlib.contextmanager
def running_server(config: McpConfig):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = uvicorn.Server(
        uvicorn.Config(
            create_mcp_application(config),
            host="127.0.0.1",
            port=port,
            log_level="error",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("test MCP server did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("test MCP server did not stop")


def config(
    mode: str = "normal", tenant_id: str = "tenant-alpha", slow_ms: int = 50
) -> McpConfig:
    return McpConfig(
        mode=mode,
        tenant_id=tenant_id,
        bearer_token=TOKEN,
        slow_milliseconds=slow_ms,
    )


async def call_tool(base_url: str, tenant_id: str = "tenant-alpha"):
    async with httpx.AsyncClient(
        headers={
            "authorization": "Bearer " + TOKEN.decode("ascii"),
            "x-orchestra-tenant": tenant_id,
        },
        follow_redirects=False,
        trust_env=False,
    ) as client:
        async with streamable_http_client(
            base_url + "/mcp", http_client=client, terminate_on_close=True
        ) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool(
                    "lookup_order_status", {"order_id": "order-123"}
                )
                return tools, result


class McpSurfaceTests(unittest.TestCase):
    def test_official_client_sees_one_read_only_tool_and_calls_it(self) -> None:
        with running_server(config()) as base_url:
            tools, result = asyncio.run(call_tool(base_url))
        self.assertEqual([tool.name for tool in tools.tools], ["lookup_order_status"])
        annotations = tools.tools[0].annotations
        self.assertIsNotNone(annotations)
        self.assertTrue(annotations.readOnlyHint)
        self.assertFalse(annotations.destructiveHint)
        self.assertTrue(annotations.idempotentHint)
        self.assertFalse(annotations.openWorldHint)
        self.assertFalse(result.isError)
        self.assertEqual(result.structuredContent["orderId"], "order-123")
        self.assertEqual(result.structuredContent["source"], "synthetic-reference-lab")

    def test_slow_lane_delays_the_real_tool_response(self) -> None:
        with running_server(config(mode="slow", slow_ms=75)) as base_url:
            started = time.monotonic()
            _tools, result = asyncio.run(call_tool(base_url))
            elapsed = time.monotonic() - started
        self.assertFalse(result.isError)
        self.assertGreaterEqual(elapsed, 0.06)

    def test_unavailable_and_wrong_tenant_lanes_fail_before_mcp(self) -> None:
        with running_server(config(mode="unavailable")) as base_url:
            unavailable = httpx.post(
                base_url + "/mcp",
                headers={
                    "authorization": "Bearer " + TOKEN.decode("ascii"),
                    "x-orchestra-tenant": "tenant-alpha",
                },
                json={},
                trust_env=False,
            )
        self.assertEqual(unavailable.status_code, 503)
        self.assertEqual(
            unavailable.json(),
            {"error": {"code": "synthetic_mcp_unavailable"}},
        )

        with running_server(
            config(mode="wrong-tenant", tenant_id="tenant-beta")
        ) as base_url:
            forbidden = httpx.post(
                base_url + "/mcp",
                headers={
                    "authorization": "Bearer " + TOKEN.decode("ascii"),
                    "x-orchestra-tenant": "tenant-alpha",
                },
                json={},
                trust_env=False,
            )
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(forbidden.json(), {"error": {"code": "tenant_forbidden"}})

    def test_wrong_bearer_is_rejected_without_protocol_details(self) -> None:
        with running_server(config()) as base_url:
            unauthorized = httpx.post(
                base_url + "/mcp",
                headers={
                    "authorization": "Bearer wrong-token",
                    "x-orchestra-tenant": "tenant-alpha",
                },
                json={},
                trust_env=False,
            )
        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(unauthorized.json(), {"error": {"code": "unauthorized"}})


if __name__ == "__main__":
    unittest.main()
