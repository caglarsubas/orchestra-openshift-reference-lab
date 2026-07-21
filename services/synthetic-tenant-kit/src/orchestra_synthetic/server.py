from __future__ import annotations

import ssl

import uvicorn

from .config import (
    GatewayConfig,
    McpConfig,
    ServerConfig,
    ensure_private_key_permissions,
    service_role_from_env,
)
from .gateway import build_gateway
from .mcp_surface import create_mcp_application


def build_application(role: str, gateway: GatewayConfig | None, mcp: McpConfig | None):
    if role == "tenant-gateway" and gateway is not None and mcp is None:
        return build_gateway(gateway).application()
    if role == "mcp" and mcp is not None and gateway is None:
        return create_mcp_application(mcp)
    raise RuntimeError("synthetic service role configuration is inconsistent")


def main() -> None:
    role = service_role_from_env()
    server = ServerConfig.from_env()
    ensure_private_key_permissions(server.private_key_file)
    application = build_application(
        role,
        GatewayConfig.from_env() if role == "tenant-gateway" else None,
        McpConfig.from_env() if role == "mcp" else None,
    )
    uvicorn.run(
        application,
        host=server.host,
        port=server.port,
        log_level="warning",
        access_log=False,
        proxy_headers=False,
        server_header=False,
        date_header=False,
        ssl_certfile=server.certificate_file,
        ssl_keyfile=server.private_key_file,
        ssl_ca_certs=server.client_ca_file,
        ssl_cert_reqs=(ssl.CERT_REQUIRED if server.client_ca_file else ssl.CERT_NONE),
    )


if __name__ == "__main__":
    main()
