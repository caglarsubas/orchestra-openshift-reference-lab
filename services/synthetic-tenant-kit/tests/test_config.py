from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from orchestra_synthetic.config import (
    GatewayConfig,
    McpConfig,
    ServerConfig,
    ensure_private_key_permissions,
)
from orchestra_synthetic.contracts import read_file


class ConfigTests(unittest.TestCase):
    def test_projected_secret_symlink_and_private_key_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "..data"
            data.mkdir()
            secret = data / "token"
            secret.write_bytes(b"x" * 32 + b"\n")
            secret.chmod(0o440)
            link = root / "token"
            link.symlink_to(Path("..data") / "token")
            self.assertEqual(read_file(str(link)), b"x" * 32)
            ensure_private_key_permissions(str(link))
            secret.chmod(0o444)
            with self.assertRaisesRegex(RuntimeError, "world-accessible"):
                ensure_private_key_permissions(str(link))

    def test_mcp_mode_binds_expected_tenant_and_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_bytes(b"t" * 40)
            environment = {
                "SYNTHETIC_MCP_MODE": "wrong-tenant",
                "SYNTHETIC_MCP_TENANT_ID": "tenant-beta",
                "SYNTHETIC_MCP_TOKEN_FILE": str(token),
            }
            with patch.dict(os.environ, environment, clear=True):
                config = McpConfig.from_env()
            self.assertEqual(config.tenant_id, "tenant-beta")
            self.assertEqual(config.bearer_token, b"t" * 40)

            environment["SYNTHETIC_MCP_TENANT_ID"] = "tenant-alpha"
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(RuntimeError, "tenant-beta"):
                    McpConfig.from_env()

    def test_gateway_and_server_env_require_https_and_complete_tls_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {}
            for name in ("ca", "token", "cert", "key", "client-cert"):
                path = root / name
                path.write_bytes((b"x" * 48) if name == "token" else b"fixture")
                path.chmod(0o440)
                files[name] = str(path)
            environment = {
                "SYNTHETIC_OIDC_ISSUER": "https://identity.test/realms/orchestra",
                "SYNTHETIC_OIDC_AUDIENCE": "orchestra-tenant-gateway",
                "SYNTHETIC_OIDC_JWKS_URL": "https://identity.test/certs",
                "SYNTHETIC_OIDC_CA_FILE": files["ca"],
                "SYNTHETIC_TENANT_ID": "tenant-alpha",
                "SYNTHETIC_RUNTIME_ENDPOINT": "https://runtime.test/v1/runtime/execute",
                "SYNTHETIC_RUNTIME_TOKEN_FILE": files["token"],
                "SYNTHETIC_RUNTIME_CA_FILE": files["ca"],
                "SYNTHETIC_RUNTIME_CLIENT_CERTIFICATE_FILE": files["client-cert"],
                "SYNTHETIC_TLS_CERTIFICATE_FILE": files["cert"],
                "SYNTHETIC_TLS_PRIVATE_KEY_FILE": files["key"],
            }
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(RuntimeError, "configured together"):
                    GatewayConfig.from_env()
                server = ServerConfig.from_env()
            self.assertEqual(server.port, 8443)

            environment["SYNTHETIC_RUNTIME_CLIENT_KEY_FILE"] = files["key"]
            environment["SYNTHETIC_RUNTIME_ENDPOINT"] = (
                "http://runtime.test/v1/runtime/execute"
            )
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                    GatewayConfig.from_env()

            environment["SYNTHETIC_RUNTIME_ENDPOINT"] = (
                "https://runtime.test/v1/runtime/execute"
            )
            environment["SYNTHETIC_TENANT_ID"] = "tenant-beta"
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(
                    RuntimeError, "identity contract is locked"
                ):
                    GatewayConfig.from_env()


if __name__ == "__main__":
    unittest.main()
