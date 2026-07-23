from __future__ import annotations

import base64
import copy
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from scripts.operator_control_plane_readiness import (
    ENVIRONMENT_CONTRACTS,
    collect_readiness,
    create_app_jwt,
    load_policy,
    observe_github_app,
    read_private_key,
    validate_report,
    write_create_only,
)
from scripts.validate_repository import ROOT


class OperatorControlPlaneReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy, self.policy_digest = load_policy()
        self.now = datetime(2026, 7, 23, 5, 0, tzinfo=timezone.utc)
        self.app_id = 424242
        self.installation_id = 737373
        self.permissions = {
            "contents": "read",
            "metadata": "read",
            "packages": "read",
        }
        self.app = {
            "id": self.app_id,
            "slug": self.policy["githubApp"]["slug"],
            "owner": {
                "id": self.policy["githubApp"]["owner"]["id"],
                "type": self.policy["githubApp"]["owner"]["type"],
                "login": "must-not-enter-report",
            },
            "permissions": copy.deepcopy(self.permissions),
            "events": [],
        }
        self.installation = {
            "id": self.installation_id,
            "app_id": self.app_id,
            "app_slug": self.policy["githubApp"]["slug"],
            "target_type": "User",
            "account": {
                "id": self.policy["githubApp"]["owner"]["id"],
                "type": "User",
                "login": "must-not-enter-report",
            },
            "repository_selection": "selected",
            "permissions": copy.deepcopy(self.permissions),
            "events": [],
            "suspended_at": None,
        }
        self.repository = {
            "id": 1214962908,
            "full_name": "caglarsubas/agent-hook-v2",
            "private": True,
            "visibility": "private",
            "archived": False,
            "owner": {
                "id": 37515097,
                "login": "must-not-enter-report",
            },
        }
        self.token_response = {
            "token": "ghs_fixture_installation_token_1234567890",
            "expires_at": "2026-07-23T06:00:00Z",
            "permissions": copy.deepcopy(self.permissions),
            "repository_selection": "selected",
        }

    def private_key(self, directory: Path, *, mode: int = 0o600) -> Path:
        path = directory / "github-app.pem"
        path.write_text(
            "-----BEGIN "
            + "PRIVATE KEY-----\n"
            + ("A" * 320)
            + "\n-----END "
            + "PRIVATE KEY-----\n",
            encoding="ascii",
        )
        path.chmod(mode)
        return path

    @staticmethod
    def signer(message: bytes, path: Path) -> bytes:
        if b"." not in message or path.name != "github-app.pem":
            raise AssertionError("unexpected signing input")
        return b"s" * 64

    def app_request(
        self,
        calls: list[tuple[str, str, str, dict[str, Any] | None]],
        *,
        repositories: list[dict[str, Any]] | None = None,
        installations: list[dict[str, Any]] | None = None,
        delete_error: bool = False,
        app: dict[str, Any] | None = None,
        installation: dict[str, Any] | None = None,
        token_response: dict[str, Any] | None = None,
    ):
        def request(
            method: str,
            path: str,
            token: str,
            body: dict[str, Any] | None,
        ) -> Any:
            calls.append((method, path, token, body))
            if method == "GET" and path == "/app":
                return copy.deepcopy(app or self.app)
            if method == "GET" and path == "/app/installations?per_page=100":
                values = (
                    installations
                    if installations is not None
                    else [installation or self.installation]
                )
                return copy.deepcopy(values)
            if method == "GET" and path.startswith("/app/installations/"):
                return copy.deepcopy(installation or self.installation)
            if method == "POST":
                return copy.deepcopy(token_response or self.token_response)
            if method == "GET" and path == "/installation/repositories?per_page=100":
                values = repositories if repositories is not None else [self.repository]
                return {
                    "total_count": len(values),
                    "repositories": copy.deepcopy(values),
                }
            if method == "DELETE" and path == "/installation/token":
                if delete_error:
                    raise ValueError("fixture_token_revocation_failed")
                return None
            raise AssertionError(f"unexpected request: {method} {path}")

        return request

    def environment_getter(self):
        contracts = {
            contract: self._expected_environment(contract)
            for contract in ENVIRONMENT_CONTRACTS
        }
        environments = {
            expected["environment"]: {
                "id": index + 1000,
                "name": expected["environment"],
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
                "protection_rules": [
                    {
                        "id": index + 2000,
                        "type": "required_reviewers",
                        "prevent_self_review": True,
                        "reviewers": [
                            {
                                "type": expected["reviewerType"],
                                "reviewer": {
                                    "id": 24681012,
                                    "login": "must-not-enter-report",
                                },
                            }
                        ],
                    },
                    {"id": index + 3000, "type": "branch_policy"},
                ],
            }
            for index, expected in enumerate(contracts.values())
        }
        repository = {
            "id": 1307302690,
            "full_name": "caglarsubas/orchestra-openshift-reference-lab",
            "private": True,
            "visibility": "private",
            "default_branch": "main",
            "archived": False,
            "owner": {
                "id": 37515097,
                "login": "must-not-enter-report",
            },
        }

        def get_json(path: str, token: str) -> dict[str, Any]:
            self.assertEqual(token, "fixture-environment-admin-token-123456")
            if path.endswith("/deployment-branch-policies?per_page=100"):
                return {
                    "total_count": 1,
                    "branch_policies": [{"id": 9999, "name": "main"}],
                }
            if "/environments/" in path:
                encoded = path.split("/environments/", 1)[1].split("/", 1)[0]
                return copy.deepcopy(environments[encoded])
            return copy.deepcopy(repository)

        return get_json

    @staticmethod
    def _expected_environment(contract: str) -> dict[str, Any]:
        from scripts.github_environment_contract import load_expected_environment

        return load_expected_environment(contract)

    def test_app_jwt_is_short_lived_and_contains_no_key_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key = self.private_key(Path(temporary))
            token = create_app_jwt(
                self.app_id,
                key,
                self.now,
                sign=self.signer,
            )
        header, payload, signature = token.split(".")
        decoded_header = json.loads(
            base64.urlsafe_b64decode(header + ("=" * (-len(header) % 4)))
        )
        decoded_payload = json.loads(
            base64.urlsafe_b64decode(payload + ("=" * (-len(payload) % 4)))
        )
        self.assertEqual(decoded_header, {"alg": "RS256", "typ": "JWT"})
        self.assertEqual(decoded_payload["iss"], str(self.app_id))
        self.assertEqual(decoded_payload["exp"] - decoded_payload["iat"], 600)
        self.assertTrue(signature)
        self.assertNotIn("PRIVATE KEY", token)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "observed_at_invalid"):
                create_app_jwt(
                    self.app_id,
                    self.private_key(Path(temporary)),
                    self.now.replace(tzinfo=None),
                    sign=self.signer,
                )

    def test_app_jwt_signature_verifies_with_generated_rsa_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "generated.pem"
            public_key = root / "generated-public.pem"
            signature_path = root / "signature.bin"
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                    str(key),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            key.chmod(0o600)
            token = create_app_jwt(self.app_id, key, self.now)
            header, payload, signature = token.split(".")
            signature_path.write_bytes(
                base64.urlsafe_b64decode(signature + ("=" * (-len(signature) % 4)))
            )
            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(key),
                    "-pubout",
                    "-out",
                    str(public_key),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            verified = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(public_key),
                    "-signature",
                    str(signature_path),
                ],
                input=f"{header}.{payload}".encode("ascii"),
                capture_output=True,
                check=False,
            )
        self.assertEqual(verified.returncode, 0)
        self.assertIn(b"Verified OK", verified.stdout)

    def test_app_observation_uses_full_scope_token_and_revokes_it(self) -> None:
        calls: list[tuple[str, str, str, dict[str, Any] | None]] = []
        with tempfile.TemporaryDirectory() as temporary:
            observation = observe_github_app(
                self.policy,
                self.private_key(Path(temporary)),
                self.app_id,
                self.installation_id,
                self.now,
                request_json=self.app_request(calls),
                sign=self.signer,
            )
        self.assertEqual(observation["repositoryCount"], 1)
        self.assertEqual(observation["applicationInstallationCount"], 1)
        self.assertTrue(observation["tokenRevoked"])
        self.assertEqual(
            [call[:2] for call in calls],
            [
                ("GET", "/app"),
                ("GET", "/app/installations?per_page=100"),
                (
                    "POST",
                    f"/app/installations/{self.installation_id}/access_tokens",
                ),
                ("GET", "/installation/repositories?per_page=100"),
                ("DELETE", "/installation/token"),
            ],
        )
        self.assertEqual(calls[2][3], {})
        encoded = json.dumps(observation)
        self.assertNotIn(self.token_response["token"], encoded)
        self.assertNotIn("must-not-enter-report", encoded)
        self.assertNotIn(str(self.app_id), encoded)
        self.assertNotIn(str(self.installation_id), encoded)

    def test_broad_app_or_repository_write_permission_or_suspension_is_rejected(
        self,
    ) -> None:
        cases: list[tuple[str, dict[str, Any]]] = []
        second_repository = copy.deepcopy(self.repository)
        second_repository["id"] = 999999
        second_repository["full_name"] = "caglarsubas/another-private-repository"
        cases.append(
            (
                "repository_scope_invalid",
                {"repositories": [self.repository, second_repository]},
            )
        )
        second_installation = copy.deepcopy(self.installation)
        second_installation["id"] = 848484
        second_installation["account"]["id"] = 97531
        cases.append(
            (
                "app_installation_set_invalid",
                {"installations": [self.installation, second_installation]},
            )
        )
        writable = copy.deepcopy(self.installation)
        writable["permissions"]["contents"] = "write"
        cases.append(("permissions_invalid", {"installation": writable}))
        suspended = copy.deepcopy(self.installation)
        suspended["suspended_at"] = "2026-07-23T04:00:00Z"
        cases.append(("identity_invalid", {"installation": suspended}))

        for expected_error, changes in cases:
            with self.subTest(expected_error=expected_error):
                calls: list[tuple[str, str, str, dict[str, Any] | None]] = []
                with tempfile.TemporaryDirectory() as temporary:
                    with self.assertRaisesRegex(ValueError, expected_error):
                        observe_github_app(
                            self.policy,
                            self.private_key(Path(temporary)),
                            self.app_id,
                            self.installation_id,
                            self.now,
                            request_json=self.app_request(calls, **changes),
                            sign=self.signer,
                        )

    def test_failed_token_revocation_fails_the_observation(self) -> None:
        calls: list[tuple[str, str, str, dict[str, Any] | None]] = []
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "token_revocation_failed"):
                observe_github_app(
                    self.policy,
                    self.private_key(Path(temporary)),
                    self.app_id,
                    self.installation_id,
                    self.now,
                    request_json=self.app_request(calls, delete_error=True),
                    sign=self.signer,
                )
        self.assertEqual(calls[-1][0], "DELETE")

    def test_invalid_token_metadata_still_revokes_the_token(self) -> None:
        changed = copy.deepcopy(self.token_response)
        changed["permissions"]["contents"] = "write"
        calls: list[tuple[str, str, str, dict[str, Any] | None]] = []
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "token_permissions_invalid"):
                observe_github_app(
                    self.policy,
                    self.private_key(Path(temporary)),
                    self.app_id,
                    self.installation_id,
                    self.now,
                    request_json=self.app_request(calls, token_response=changed),
                    sign=self.signer,
                )
        self.assertEqual(calls[-1][0], "DELETE")

    def test_private_key_must_be_regular_private_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = self.private_key(root, mode=0o644)
            with self.assertRaisesRegex(ValueError, "permissions_invalid"):
                read_private_key(key)
            key.chmod(0o600)
            read_private_key(key)
            symlink = root / "linked.pem"
            symlink.symlink_to(key)
            with self.assertRaisesRegex(ValueError, "symlink_forbidden"):
                read_private_key(symlink)

    def test_aggregate_report_is_payload_free_and_fail_closed(self) -> None:
        calls: list[tuple[str, str, str, dict[str, Any] | None]] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment_token = root / "environment-token"
            environment_token.write_text(
                "fixture-environment-admin-token-123456", encoding="ascii"
            )
            environment_token.chmod(0o600)
            report = collect_readiness(
                observation_id="operator-readiness.fixture-1",
                repository_revision="a" * 40,
                observed_at=self.now,
                environment_token_path=environment_token,
                app_private_key_path=self.private_key(root),
                app_id=self.app_id,
                installation_id=self.installation_id,
                environment_get_json=self.environment_getter(),
                app_request_json=self.app_request(calls),
                sign=self.signer,
            )
        validate_report(report, assessed_at=self.now + timedelta(minutes=30))
        self.assertEqual(
            [item["contract"] for item in report["environmentObservations"]],
            list(ENVIRONMENT_CONTRACTS),
        )
        self.assertFalse(report["claims"]["provisioningReady"])
        encoded = json.dumps(report)
        self.assertNotIn("fixture-environment-admin-token", encoded)
        self.assertNotIn("must-not-enter-report", encoded)
        self.assertNotIn("ghs_", encoded)
        self.assertNotIn("PRIVATE KEY", encoded)

        changed = copy.deepcopy(report)
        changed["claims"]["campaignEvidence"] = True
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed)
        changed = copy.deepcopy(report)
        changed["claims"]["operatorControlPlaneObserved"] = 1
        with self.assertRaisesRegex(ValueError, "report_identity_invalid"):
            validate_report(changed)
        changed = copy.deepcopy(report)
        changed["githubAppObservation"]["repositoryIdentityDigest"] = "sha256:" + (
            "f" * 64
        )
        with self.assertRaisesRegex(ValueError, "report_app_invalid"):
            validate_report(changed)
        changed = copy.deepcopy(report)
        changed["githubAppObservation"]["applicationInstallationSetDigest"] = (
            "sha256:" + ("e" * 64)
        )
        with self.assertRaisesRegex(ValueError, "report_app_invalid"):
            validate_report(changed)
        changed = copy.deepcopy(report)
        changed["githubAppObservation"]["repositoryCount"] = True
        with self.assertRaisesRegex(ValueError, "report_app_invalid"):
            validate_report(changed)
        changed = copy.deepcopy(report)
        changed["observedAt"] = changed["observedAt"].replace("T", " ")
        with self.assertRaisesRegex(ValueError, "report_time_invalid"):
            validate_report(changed)
        with self.assertRaisesRegex(ValueError, "report_stale"):
            validate_report(report, assessed_at=self.now + timedelta(minutes=61))

    def test_duplicate_environment_identity_and_report_overwrite_are_rejected(
        self,
    ) -> None:
        calls: list[tuple[str, str, str, dict[str, Any] | None]] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment_token = root / "environment-token"
            environment_token.write_text(
                "fixture-environment-admin-token-123456", encoding="ascii"
            )
            environment_token.chmod(0o600)
            report = collect_readiness(
                observation_id="operator-readiness.fixture-2",
                repository_revision="b" * 40,
                observed_at=self.now,
                environment_token_path=environment_token,
                app_private_key_path=self.private_key(root),
                app_id=self.app_id,
                installation_id=self.installation_id,
                environment_get_json=self.environment_getter(),
                app_request_json=self.app_request(calls),
                sign=self.signer,
            )
            output = root / "report.json"
            write_create_only(output, report)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, "create_failed"):
                write_create_only(output, report)

        changed = copy.deepcopy(report)
        changed["environmentObservations"][1]["environmentIdentityDigest"] = changed[
            "environmentObservations"
        ][0]["environmentIdentityDigest"]
        with self.assertRaisesRegex(ValueError, "environment_set_invalid"):
            validate_report(changed)

    def test_default_validation_and_protected_workflows_enforce_the_contract(
        self,
    ) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        command = "scripts/operator_control_plane_readiness.py validate-policy"
        self.assertIn(f"$(PYTHON) {command}", makefile)
        self.assertIn(f"python3 {command}", ci)
        for workflow_name in (
            "dependency-risk-preflight.yml",
            "dependency-risk-collection.yml",
            "dependency-risk-custody-verification.yml",
        ):
            workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(
                encoding="utf-8"
            )
            self.assertIn(
                "DEPENDENCY_RISK_GITHUB_APP_INSTALLATION_ID",
                workflow,
            )
            self.assertIn(
                "operator_control_plane_readiness.py verify-app",
                workflow,
            )
            self.assertIn("GITHUB_APP_INSTALLATION_DIGEST", workflow)
            self.assertIn(
                '"$RUNNER_TEMP/github-app-private-key.pem"',
                workflow,
            )


if __name__ == "__main__":
    unittest.main()
