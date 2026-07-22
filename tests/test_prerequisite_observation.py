from __future__ import annotations

import copy
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.collect_prerequisite_observation import (
    Inputs,
    collect,
    observe_dns,
    observe_entitlement,
    observe_gcp,
    observe_installer,
    observe_pull_secret,
    observe_runner,
    observe_wif,
    require_live_storage,
    verify_live_runner_environment,
)
from scripts.prerequisite_observation import (
    EXPECTED_POLICY_DIGEST,
    GATE_ORDER,
    load_contract,
    validate_observation,
    validate_policy,
)
from scripts.validate_prerequisite_observation import main as validate_main


class PrerequisiteObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
        self.actor = f"sha256:{91:064x}"

    @staticmethod
    def command_success(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="verified\n", stderr="")

    def diagnostic_report(self) -> dict:
        with patch(
            "scripts.collect_prerequisite_observation.shutil.which", return_value=None
        ):
            return collect(
                Inputs(
                    observation_id="orchestra-prerequisite-observation-fixture.1",
                    actor_identity_digest=self.actor,
                    execution_mode="simulated",
                ),
                run=self.command_success,
                started_at=self.now - timedelta(minutes=1),
                completed_at=self.now,
            )

    def test_locked_policy_is_valid_and_stable(self) -> None:
        policy, release_set = load_contract()
        self.assertEqual(validate_policy(policy, release_set), EXPECTED_POLICY_DIGEST)

    def test_diagnostic_report_is_fixture_simulated_and_non_authoritative(self) -> None:
        report = self.diagnostic_report()
        validate_observation(report, now=self.now)
        self.assertEqual(
            (report["targetClass"], report["executionMode"]), ("fixture", "simulated")
        )
        self.assertEqual(set(report["gates"]), set(GATE_ORDER))
        self.assertEqual(
            report["summary"], {"passedGates": 1, "blockedGates": 9, "totalGates": 10}
        )
        self.assertEqual(report["gates"]["crossPlaneReleaseSet"]["status"], "passed")
        self.assertFalse(report["claims"]["eligibleForIndependentReview"])
        self.assertFalse(report["claims"]["provisioningReady"])
        self.assertEqual(report["claims"]["verifiedPrerequisiteGates"], 0)

    def test_origin_pair_cannot_be_upgraded(self) -> None:
        report = self.diagnostic_report()
        report["targetClass"] = "vendor-reference-lab"
        with self.assertRaisesRegex(ValueError, "origin_invalid"):
            validate_observation(report, now=self.now)

    def test_diagnostic_cannot_claim_review_eligibility(self) -> None:
        report = self.diagnostic_report()
        report["claims"]["eligibleForIndependentReview"] = True
        with self.assertRaisesRegex(ValueError, "claims_invalid"):
            validate_observation(report, now=self.now)

    def test_gate_summary_tamper_is_rejected(self) -> None:
        report = self.diagnostic_report()
        report["gates"]["redHatEntitlement"]["status"] = "passed"
        with self.assertRaisesRegex(ValueError, "gate_summary_invalid"):
            validate_observation(report, now=self.now)

    def test_unknown_check_is_rejected(self) -> None:
        report = self.diagnostic_report()
        report["gates"]["redHatEntitlement"]["checks"][0]["id"] = "other-check"
        with self.assertRaisesRegex(ValueError, "checks_invalid"):
            validate_observation(report, now=self.now)

    def test_stale_observation_is_rejected(self) -> None:
        report = self.diagnostic_report()
        with self.assertRaisesRegex(ValueError, "observation_stale"):
            validate_observation(report, now=self.now + timedelta(hours=25))

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            Path("schemas/prerequisite-observation-v1.schema.json").read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(schema["properties"]["bindings"]["additionalProperties"])
        self.assertFalse(schema["properties"]["collection"]["additionalProperties"])
        self.assertFalse(schema["properties"]["gates"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["gate"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["check"]["additionalProperties"])

    def test_entitlement_statement_is_payload_free_and_time_bounded(self) -> None:
        statement = {
            "schemaVersion": 1,
            "kind": "orchestra.external.red-hat-entitlement-observation.v1",
            "status": "active",
            "product": "OpenShift Container Platform",
            "openshiftVersion": "4.20.27",
            "architecture": "linux/amd64",
            "accountIdentityDigest": f"sha256:{1:064x}",
            "issuerEvidenceDigest": f"sha256:{2:064x}",
            "observedAt": "2026-07-22T11:00:00Z",
            "expiresAt": "2026-07-29T11:00:00Z",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "entitlement.json"
            path.write_text(json.dumps(statement), encoding="utf-8")
            check = observe_entitlement(path, self.now)
        self.assertEqual(check["status"], "passed")
        self.assertNotIn("accountIdentityDigest", json.dumps(check))

    def test_pull_secret_is_read_but_never_embedded(self) -> None:
        secret = {
            "auths": {
                "cloud.openshift.com": {"auth": "secret-one"},
                "quay.io": {"auth": "secret-two"},
                "registry.redhat.io": {"auth": "secret-three"},
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pull-secret.json"
            path.write_text(json.dumps(secret), encoding="utf-8")
            check = observe_pull_secret(path, self.now)
        self.assertEqual(check["status"], "passed")
        self.assertNotIn("secret-one", json.dumps(check))
        self.assertNotIn('"auths":', json.dumps(check))

    def test_installer_requires_exact_digest_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "openshift-install"
            binary.write_bytes(b"installer-fixture")
            from scripts.prerequisite_observation import blob_digest

            def installer_runner(
                command: list[str],
            ) -> subprocess.CompletedProcess[str]:
                stdout = (
                    "openshift-install 4.20.27\nbuilt from commit fixture\n"
                    if command[-1] == "version"
                    else "ELF 64-bit LSB executable, x86-64\n"
                )
                return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

            check = observe_installer(
                binary,
                blob_digest(binary.read_bytes()),
                self.now,
                installer_runner,
            )
        self.assertEqual(check["status"], "passed")

    def test_gcp_dns_wif_and_runner_probes_validate_exact_live_shapes(self) -> None:
        policy, _ = load_contract()
        target_project = "orchestra-target-fixture"
        services_project = "orchestra-services-fixture"
        calls: list[list[str]] = []

        def project_from(command: list[str]) -> str:
            project_flag = next(
                (item for item in command if item.startswith("--project=")), None
            )
            if project_flag:
                return project_flag.split("=", 1)[1]
            if command[1:4] in (
                ["projects", "describe", target_project],
                ["projects", "describe", services_project],
            ):
                return command[3]
            if command[1:4] == ["billing", "projects", "describe"]:
                return command[4]
            raise AssertionError(f"project_not_found:{command}")

        def quota_response(project: str, scope: str) -> dict:
            plane = "target" if project == target_project else "services"
            required = policy["gcp"]["quotaMinimumAvailable"][plane][scope]
            return {
                "quotas": [
                    {"metric": metric, "limit": minimum + 10, "usage": 0}
                    for metric, minimum in required.items()
                ]
            }

        def live_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command[0] == "dig":
                output: object = "ns1.fixture.example.\nns2.fixture.example.\n"
            elif command[0] == "cosign":
                output = "verified\n"
            elif command[1:4] == ["projects", "describe", target_project]:
                output = {
                    "lifecycleState": "ACTIVE",
                    "labels": policy["gcp"]["targetLabels"],
                }
            elif command[1:4] == ["projects", "describe", services_project]:
                output = {
                    "lifecycleState": "ACTIVE",
                    "labels": policy["gcp"]["servicesLabels"],
                }
            elif command[1:4] == ["billing", "projects", "describe"]:
                output = {"billingEnabled": True}
            elif command[1:3] == ["services", "list"]:
                project = project_from(command)
                apis = policy["gcp"][
                    "targetRequiredApis"
                    if project == target_project
                    else "servicesRequiredApis"
                ]
                output = [{"config": {"name": api}, "state": "ENABLED"} for api in apis]
            elif command[1:4] == ["compute", "project-info", "describe"]:
                output = quota_response(project_from(command), "global")
            elif command[1:4] == ["compute", "regions", "describe"]:
                output = quota_response(project_from(command), "regional")
            elif command[1:5] == [
                "dns",
                "managed-zones",
                "describe",
                "orchestra-ocp-lab-public",
            ]:
                output = {
                    "name": "orchestra-ocp-lab-public",
                    "dnsName": "ocp-lab.prometa.ai.",
                    "visibility": "public",
                    "nameServers": [
                        "ns1.fixture.example.",
                        "ns2.fixture.example.",
                    ],
                }
            elif command[1:5] == [
                "iam",
                "workload-identity-pools",
                "providers",
                "describe",
            ]:
                output = {
                    "name": "projects/123456/locations/global/workloadIdentityPools/orchestra-lab-github/providers/github",
                    "state": "ACTIVE",
                    "oidc": {"issuerUri": policy["gcp"]["wif"]["issuerUri"]},
                    "attributeCondition": policy["gcp"]["wif"]["attributeCondition"],
                    "attributeMapping": {
                        "google.subject": "assertion.sub",
                        "attribute.actor_id": "assertion.actor_id",
                        "attribute.environment": "assertion.environment",
                        "attribute.event_name": "assertion.event_name",
                        "attribute.ref": "assertion.ref",
                        "attribute.repository": "assertion.repository",
                        "attribute.repository_id": "assertion.repository_id",
                        "attribute.repository_owner_id": "assertion.repository_owner_id",
                        "attribute.repository_visibility": "assertion.repository_visibility",
                        "attribute.workflow_ref": "assertion.workflow_ref",
                    },
                }
            elif command[1:5] == [
                "iam",
                "service-accounts",
                "keys",
                "list",
            ]:
                output = [{"keyType": "SYSTEM_MANAGED"}]
            elif command[1:4] == [
                "iam",
                "service-accounts",
                "get-iam-policy",
            ]:
                output = (
                    {
                        "bindings": [
                            {
                                "role": "roles/iam.workloadIdentityUser",
                                "members": [
                                    "principalSet://iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/orchestra-lab-github/attribute.repository_id/1307302690"
                                ],
                            }
                        ]
                    }
                    if command[4].startswith("orchestra-lab-foundation-plan@")
                    else {"bindings": []}
                )
            else:
                raise AssertionError(f"unexpected_command:{command}")
            stdout = output if isinstance(output, str) else json.dumps(output)
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        gcp = observe_gcp(
            target_project,
            services_project,
            self.now,
            live_runner,
            policy,
        )
        self.assertTrue(all(item["status"] == "passed" for item in gcp.values()))
        self.assertEqual(
            observe_dns(
                "orchestra-ocp-lab-public",
                services_project,
                self.now,
                live_runner,
                policy,
            )["status"],
            "passed",
        )
        self.assertEqual(
            observe_wif(services_project, self.now, live_runner, policy)["status"],
            "passed",
        )

        def executor_federated_runner(
            command: list[str],
        ) -> subprocess.CompletedProcess[str]:
            if command[1:4] == [
                "iam",
                "service-accounts",
                "get-iam-policy",
            ] and command[4].startswith("orchestra-lab-foundation@"):
                output = {
                    "bindings": [
                        {
                            "role": "roles/iam.workloadIdentityUser",
                            "members": [
                                "principalSet://iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/orchestra-lab-github/attribute.repository_id/1307302690"
                            ],
                        }
                    ]
                }
                return subprocess.CompletedProcess(
                    command, 0, stdout=json.dumps(output), stderr=""
                )
            return live_runner(command)

        self.assertEqual(
            observe_wif(
                services_project,
                self.now,
                executor_federated_runner,
                policy,
            )["status"],
            "failed",
        )
        with patch(
            "scripts.collect_prerequisite_observation.shutil.which",
            return_value="/usr/local/bin/cosign",
        ):
            self.assertEqual(
                observe_runner(self.now, live_runner, policy)["status"], "passed"
            )
        cosign_calls = [command for command in calls if command[0] == "cosign"]
        self.assertEqual(len(cosign_calls), 2)
        self.assertTrue(
            all("--certificate-identity" in command for command in cosign_calls)
        )
        self.assertTrue(
            all(
                "--certificate-github-workflow-sha" in command
                for command in cosign_calls
            )
        )
        self.assertTrue(
            all(
                "--certificate-github-workflow-ref" in command
                for command in cosign_calls
            )
        )
        self.assertTrue(
            all(
                "--certificate-github-workflow-repository" in command
                for command in cosign_calls
            )
        )
        self.assertTrue(
            all(
                "--certificate-github-workflow-trigger" in command
                for command in cosign_calls
            )
        )

    def test_dns_probe_rejects_an_unlocked_managed_zone_before_provider_access(
        self,
    ) -> None:
        policy, _ = load_contract()

        def unexpected_runner(
            command: list[str],
        ) -> subprocess.CompletedProcess[str]:
            raise AssertionError(f"provider_access_not_expected:{command}")

        check = observe_dns(
            "unreviewed-zone",
            "orchestra-services-fixture",
            self.now,
            unexpected_runner,
            policy,
        )
        self.assertEqual(check["status"], "failed")
        self.assertEqual(check["reasonCode"], "DNS_MANAGED_ZONE_POLICY_MISMATCH")

    def test_live_report_binds_the_published_runner_but_grants_nothing(self) -> None:
        with patch(
            "scripts.collect_prerequisite_observation.shutil.which", return_value=None
        ):
            report = collect(
                Inputs(
                    observation_id="orchestra-prerequisite-observation-live.1",
                    actor_identity_digest=self.actor,
                    execution_mode="live",
                ),
                run=self.command_success,
                started_at=self.now - timedelta(minutes=1),
                completed_at=self.now,
            )
        validate_observation(report, now=self.now)
        policy, _ = load_contract()
        self.assertEqual(report["targetClass"], "vendor-reference-lab")
        self.assertEqual(
            report["collection"]["runnerImageDigest"],
            policy["runner"]["imageDigest"],
        )
        self.assertFalse(report["claims"]["provisioningReady"])

    def test_live_collection_requires_restricted_storage(self) -> None:
        require_live_storage(
            Path("restricted/prerequisite-observation.json"),
            [Path("restricted/pull-secret.json")],
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "output_outside_restricted"):
                require_live_storage(Path(temporary) / "observation.json", [])
            with self.assertRaisesRegex(ValueError, "input_outside_restricted"):
                require_live_storage(
                    Path("restricted/prerequisite-observation.json"),
                    [Path(temporary) / "pull-secret.json"],
                )

    def test_live_runner_environment_requires_exact_platform_and_toolchain(
        self,
    ) -> None:
        policy, _ = load_contract()
        commands: list[list[str]] = []

        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        environment = {
            "ORCHESTRA_CERTIFICATION_RUNNER_IMAGE": policy["runner"]["image"],
            "ORCHESTRA_CERTIFICATION_RUNNER_TOOLCHAIN_DIGEST": policy["runner"][
                "toolchainDigest"
            ],
        }
        with patch(
            "scripts.collect_prerequisite_observation.shutil.which",
            return_value="/opt/orchestra/bin/tool",
        ):
            verify_live_runner_environment(
                policy,
                environ=environment,
                run=runner,
                toolchain_path=Path(
                    "tests/fixtures/platform-rc10-certification-runner-toolchain-lock.json"
                ),
                system_name="Linux",
                machine="x86_64",
            )
            with self.assertRaisesRegex(ValueError, "runner_platform_invalid"):
                verify_live_runner_environment(
                    policy,
                    environ=environment,
                    run=runner,
                    toolchain_path=Path(
                        "tests/fixtures/platform-rc10-certification-runner-toolchain-lock.json"
                    ),
                    system_name="Darwin",
                    machine="arm64",
                )
        self.assertEqual(commands, [["orchestra-certification", "self-test"]])

    def test_observation_copy_tamper_does_not_change_original(self) -> None:
        report = self.diagnostic_report()
        changed = copy.deepcopy(report)
        changed["summary"]["passedGates"] = 10
        with self.assertRaisesRegex(ValueError, "summary_invalid"):
            validate_observation(changed, now=self.now)
        validate_observation(report, now=self.now)

    def test_standalone_validator_accepts_a_path_argument(self) -> None:
        report = self.diagnostic_report()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "observation.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            with patch("scripts.prerequisite_observation.datetime") as datetime_mock:
                datetime_mock.now.return_value = self.now
                datetime_mock.fromisoformat.side_effect = datetime.fromisoformat
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        validate_main(["--observation", str(path)]),
                        0,
                    )


if __name__ == "__main__":
    unittest.main()
