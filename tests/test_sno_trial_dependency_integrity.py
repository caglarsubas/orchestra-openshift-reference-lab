from __future__ import annotations

import base64
import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.materialize_sno_trial_dependency_manifests import (
    build_receipt,
    materialize_resources,
)
from scripts.sno_trial_dependency_inputs import (
    build_assessment as build_input_assessment,
    collect_snapshot as collect_input_snapshot,
)
from scripts.sno_trial_dependency_integrity import (
    build_assessment,
    collect_snapshot,
    inspect_certificate,
    load_policy,
    simulated_snapshot,
    validate_assessment,
)
from scripts.validate_repository import ROOT, canonical_digest


AT = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
MODEL_DIGEST = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
MODEL_SIZE = 491400032


class MetadataOcFixture:
    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        get_index = command.index("get")
        identity = (command[get_index + 1], command[get_index + 2])
        outputs = {
            ("storageclass", "standard-csi"): (
                "standard-csi\npd.csi.storage.gke.io\nWaitForFirstConsumer\ntrue\n"
            ),
            ("secret", "orchestra-sno-valkey-auth"): (
                "orchestra-sno-valkey-auth\nOpaque\npassword\n"
            ),
            ("secret", "orchestra-sno-valkey-server-tls"): (
                "orchestra-sno-valkey-server-tls\n"
                "kubernetes.io/tls\n"
                "ca.crt\n"
                "tls.crt\n"
                "tls.key\n"
            ),
            ("persistentvolumeclaim", "orchestra-sno-model-artifact"): (
                "orchestra-sno-model-artifact\n"
                "Bound\n"
                "ReadWriteOnce\n"
                "Filesystem\n"
                "standard-csi\n"
                "10Gi\n"
            ),
            ("secret", "orchestra-sno-model-auth"): (
                "orchestra-sno-model-auth\nOpaque\napi-keys\n"
            ),
            ("secret", "orchestra-sno-model-server-tls"): (
                "orchestra-sno-model-server-tls\n"
                "kubernetes.io/tls\n"
                "ca.crt\n"
                "tls.crt\n"
                "tls.key\n"
            ),
        }
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=outputs[identity],
            stderr="",
        )


class IntegrityOcFixture:
    def __init__(
        self,
        *,
        model_size: int = MODEL_SIZE,
        model_digest: str = MODEL_DIGEST,
        writable: bool = False,
        duplicate_secret_key: bool = False,
    ) -> None:
        self.model_size = model_size
        self.model_digest = model_digest
        self.writable = writable
        self.duplicate_secret_key = duplicate_secret_key
        self.commands: list[list[str]] = []

    def __call__(
        self,
        command: list[str],
        *,
        input_bytes: bytes | None = None,
        pass_fds: tuple[int, ...] = (),
        timeout: int = 90,
    ) -> subprocess.CompletedProcess[bytes]:
        del input_bytes, pass_fds, timeout
        self.commands.append(command)
        if command[-1] == "version":
            return subprocess.CompletedProcess(
                command, 0, stdout=b"OpenSSL 3.0.0 7 Sep 2021\n", stderr=b""
            )
        if "exec" in command:
            output = (
                f"{self.model_size}\n{self.model_digest}\n"
                f"{str(self.writable).lower()}\n"
            ).encode("ascii")
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")
        get_index = command.index("get")
        kind = command[get_index + 1]
        name = command[get_index + 2]
        if kind == "pod":
            output = (
                "orchestra-sno-model-backend-0\n"
                "12345678-1234-1234-1234-123456789abc\n"
                "sno-node.example.internal\n"
                "Running\n"
                "ghcr.io/ggml-org/llama.cpp@"
                "sha256:7a670b0633a2b33d915ca958fc1e4977334924590c9bd5ffc9d4813dd168d77b\n"
                "true\n"
            ).encode("ascii")
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")
        namespace = command[command.index("--namespace") + 1]
        payload = {
            "metadata": {
                "name": name,
                "namespace": namespace,
                "resourceVersion": f"rv-{name}",
            },
            "type": "kubernetes.io/tls",
            "data": {
                "ca.crt": base64.b64encode(b"ca-bytes").decode("ascii"),
                "tls.crt": base64.b64encode(b"certificate-bytes").decode("ascii"),
                "tls.key": base64.b64encode(b"private-key-bytes").decode("ascii"),
            },
        }
        if self.duplicate_secret_key:
            output = (
                '{"metadata":{"name":"'
                + name
                + '","namespace":"'
                + namespace
                + '","resourceVersion":"rv"},"type":"kubernetes.io/tls",'
                '"data":{"ca.crt":"YQ==","ca.crt":"Yg==",'
                '"tls.crt":"Yw==","tls.key":"ZA=="}}'
            ).encode("ascii")
        else:
            output = json.dumps(payload).encode("ascii")
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")


def good_certificate_inspector(
    certificate: bytes,
    private_key: bytes,
    trust_bundle: bytes,
    openssl: Path,
    **_: object,
) -> dict:
    del certificate, private_key, trust_bundle, openssl
    return {
        "leafCertificateDigest": canonical_digest("leaf-certificate"),
        "trustBundleDigest": canonical_digest("trust-bundle"),
        "publicKeyDigest": canonical_digest("public-key"),
        "notBefore": AT - timedelta(days=1),
        "notAfter": AT + timedelta(days=30),
        "dnsNames": [],
        "keyMatches": True,
        "chainVerified": True,
    }


class SnoTrialDependencyIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy()
        self.restricted = ROOT / "restricted"
        self.restricted.mkdir(mode=0o700, exist_ok=True)

    def tooling(self, root: Path) -> tuple[Path, Path, Path]:
        client = root / "oc"
        kubeconfig = root / "kubeconfig"
        openssl = root / "openssl"
        client.write_text("#!/bin/sh\n", encoding="ascii")
        kubeconfig.write_text("fixture\n", encoding="ascii")
        openssl.write_text("#!/bin/sh\n", encoding="ascii")
        client.chmod(0o700)
        kubeconfig.chmod(0o600)
        openssl.chmod(0o700)
        return client, kubeconfig, openssl

    def prerequisites(self) -> tuple[dict, dict]:
        with tempfile.TemporaryDirectory() as directory:
            client, kubeconfig, _ = self.tooling(Path(directory))
            input_snapshot = collect_input_snapshot(
                client,
                kubeconfig,
                "standard-csi",
                AT,
                MetadataOcFixture(),
            )
        input_report = build_input_assessment(
            input_snapshot,
            "sno-dependency-inputs-integrity.1",
            AT,
        )
        resources, count = materialize_resources("standard-csi")
        materialization = build_receipt(
            input_report,
            resources,
            "standard-csi",
            count,
            "sno-dependency-materialization-integrity.1",
            AT,
        )
        return input_report, materialization

    def inspector(self, policy_item: dict, **changes: object):
        result = {
            "leafCertificateDigest": canonical_digest(
                f"{policy_item['certificateId']}-leaf"
            ),
            "trustBundleDigest": canonical_digest(f"{policy_item['certificateId']}-ca"),
            "publicKeyDigest": canonical_digest(
                f"{policy_item['certificateId']}-public-key"
            ),
            "notBefore": AT - timedelta(days=1),
            "notAfter": AT + timedelta(days=30),
            "dnsNames": policy_item["requiredDnsNames"],
            "keyMatches": True,
            "chainVerified": True,
        }
        result.update(changes)
        return result

    def test_simulated_report_is_strictly_non_authorizing(self) -> None:
        report = build_assessment(
            simulated_snapshot(AT),
            "sno-dependency-integrity-simulated.1",
            AT,
        )
        validate_assessment(report)
        self.assertEqual(
            report["decision"]["status"],
            "DEPENDENCY_INTEGRITY_UNRESOLVED",
        )
        self.assertIn(
            "LIVE_CLUSTER_OBSERVATION_REQUIRED",
            report["decision"]["reasonCodes"],
        )
        self.assertFalse(report["controls"]["secretValuesObserved"])
        self.assertFalse(report["controls"]["deploymentAuthorized"])
        self.assertFalse(report["claims"]["campaignEvidence"])

    def test_report_schema_is_closed_and_accepts_simulation(self) -> None:
        schema = (
            ROOT
            / "schemas"
            / "sno-trial-dependency-integrity-observation-v1.schema.json"
        )
        report = build_assessment(
            simulated_snapshot(AT),
            "sno-dependency-integrity-schema.1",
            AT,
        )
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "report.json"
            payload.write_text(json.dumps(report), encoding="ascii")
            completed = subprocess.run(
                [
                    "npx",
                    "--yes",
                    "ajv-cli@5.0.0",
                    "validate",
                    "--spec=draft2020",
                    f"-s={schema}",
                    f"-d={payload}",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0)
            report["unexpected"] = True
            payload.write_text(json.dumps(report), encoding="ascii")
            completed = subprocess.run(
                [
                    "npx",
                    "--yes",
                    "ajv-cli@5.0.0",
                    "validate",
                    "--spec=draft2020",
                    f"-s={schema}",
                    f"-d={payload}",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)

    def test_live_collection_verifies_model_and_tls_without_auth_secrets(self) -> None:
        input_report, materialization = self.prerequisites()
        with tempfile.TemporaryDirectory() as directory:
            client, kubeconfig, openssl = self.tooling(Path(directory))
            runner = IntegrityOcFixture()
            calls = iter(self.policy["certificates"])

            def inspector(*_: object, **__: object) -> dict:
                return self.inspector(next(calls))

            snapshot = collect_snapshot(
                client,
                kubeconfig,
                openssl,
                input_report,
                materialization,
                AT,
                runner,
                inspector,
            )
        report = build_assessment(
            snapshot,
            "sno-dependency-integrity-live.1",
            AT,
        )
        validate_assessment(report)
        self.assertEqual(
            report["decision"],
            {"status": "DEPENDENCY_INTEGRITY_VERIFIED", "reasonCodes": []},
        )
        self.assertTrue(report["controls"]["modelArtifactDigestVerified"])
        self.assertTrue(report["controls"]["certificateValidityVerified"])
        self.assertTrue(report["controls"]["secretValuesObserved"])
        self.assertFalse(report["controls"]["authenticationSecretValuesObserved"])
        commands = [" ".join(command) for command in runner.commands]
        self.assertFalse(any("valkey-auth" in command for command in commands))
        self.assertFalse(any("model-auth" in command for command in commands))
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("certificate-bytes", serialized)
        self.assertNotIn("private-key-bytes", serialized)
        self.assertNotIn("ca-bytes", serialized)

    def test_mismatches_are_reported_and_cannot_be_forged_away(self) -> None:
        input_report, materialization = self.prerequisites()
        with tempfile.TemporaryDirectory() as directory:
            client, kubeconfig, openssl = self.tooling(Path(directory))
            runner = IntegrityOcFixture(
                model_size=MODEL_SIZE - 1,
                model_digest="f" * 64,
                writable=True,
            )
            calls = iter(self.policy["certificates"])

            def inspector(*_: object, **__: object) -> dict:
                item = next(calls)
                return self.inspector(
                    item,
                    notAfter=AT + timedelta(hours=1),
                    dnsNames=[],
                    keyMatches=False,
                    chainVerified=False,
                )

            snapshot = collect_snapshot(
                client,
                kubeconfig,
                openssl,
                input_report,
                materialization,
                AT,
                runner,
                inspector,
            )
        report = build_assessment(
            snapshot,
            "sno-dependency-integrity-mismatch.1",
            AT,
        )
        self.assertEqual(
            report["decision"]["status"],
            "DEPENDENCY_INTEGRITY_UNRESOLVED",
        )
        for reason in (
            "MODEL_ARTIFACT_SIZE_MISMATCH",
            "MODEL_ARTIFACT_DIGEST_MISMATCH",
            "MODEL_ARTIFACT_WRITABLE",
            "CERTIFICATE_EXPIRES_TOO_SOON",
            "CERTIFICATE_SAN_MISMATCH",
            "CERTIFICATE_KEY_MISMATCH",
            "CERTIFICATE_CHAIN_INVALID",
        ):
            self.assertIn(reason, report["decision"]["reasonCodes"])
        forged = copy.deepcopy(report)
        forged["decision"] = {
            "status": "DEPENDENCY_INTEGRITY_VERIFIED",
            "reasonCodes": [],
        }
        forged["reportDigest"] = canonical_digest(
            {key: value for key, value in forged.items() if key != "reportDigest"}
        )
        with self.assertRaisesRegex(
            ValueError, "sno_dependency_integrity_report_semantics_invalid"
        ):
            validate_assessment(forged)

    def test_stale_or_unbound_prerequisites_and_duplicate_secret_keys_fail(
        self,
    ) -> None:
        input_report, materialization = self.prerequisites()
        with tempfile.TemporaryDirectory() as directory:
            client, kubeconfig, openssl = self.tooling(Path(directory))
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_integrity_prerequisite_not_ready"
            ):
                collect_snapshot(
                    client,
                    kubeconfig,
                    openssl,
                    input_report,
                    materialization,
                    AT + timedelta(hours=2),
                    IntegrityOcFixture(),
                    good_certificate_inspector,
                )
            changed = copy.deepcopy(materialization)
            changed["bindings"]["inputObservationDigest"] = canonical_digest("wrong")
            changed["receiptDigest"] = canonical_digest(
                {key: value for key, value in changed.items() if key != "receiptDigest"}
            )
            with self.assertRaises(ValueError):
                collect_snapshot(
                    client,
                    kubeconfig,
                    openssl,
                    input_report,
                    changed,
                    AT,
                    IntegrityOcFixture(),
                    good_certificate_inspector,
                )
            with self.assertRaisesRegex(
                ValueError, "sno_dependency_integrity_tls_secret_duplicate_key"
            ):
                collect_snapshot(
                    client,
                    kubeconfig,
                    openssl,
                    input_report,
                    materialization,
                    AT,
                    IntegrityOcFixture(duplicate_secret_key=True),
                    good_certificate_inspector,
                )

    def test_repository_wires_integrity_policy_targets_docs_and_ci(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        runbook = (ROOT / "docs" / "runbooks" / "sno-trial.md").read_text(
            encoding="utf-8"
        )
        manifest = (
            ROOT
            / "gitops"
            / "dependencies"
            / "candidates"
            / "sno-trial"
            / "model-backend-stateful-set.json"
        ).read_text(encoding="utf-8")
        for target in (
            "validate-sno-trial-dependency-integrity-policy:",
            "observe-sno-trial-dependency-integrity:",
            "verify-sno-trial-dependency-integrity:",
        ):
            self.assertIn(target, makefile)
        self.assertIn("tests.test_sno_trial_dependency_integrity", workflow)
        self.assertIn("DEPENDENCY_INTEGRITY_VERIFIED", runbook)
        self.assertIn("only the Valkey and model TLS Secrets", runbook)
        self.assertIn("never the Valkey password or model API", runbook)
        self.assertIn("/var/run/secrets/orchestra-model/ca.crt", manifest)

    @unittest.skipUnless(
        hasattr(os, "memfd_create")
        and Path("/proc/self/fd").is_dir()
        and shutil.which("openssl"),
        "Linux anonymous file descriptors and OpenSSL are required",
    )
    def test_real_openssl_chain_san_and_key_match(self) -> None:
        openssl = Path(shutil.which("openssl") or "")
        policy_item = self.policy["certificates"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "server.cnf"
            config.write_text(
                "[req]\n"
                "distinguished_name=dn\n"
                "req_extensions=req_ext\n"
                "prompt=no\n"
                "[dn]\nCN=orchestra-sno-valkey\n"
                "[req_ext]\nsubjectAltName=@alt_names\n"
                "[alt_names]\n"
                + "\n".join(
                    f"DNS.{index}={name}"
                    for index, name in enumerate(
                        policy_item["requiredDnsNames"], start=1
                    )
                )
                + "\n",
                encoding="ascii",
            )
            commands = [
                [
                    str(openssl),
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "30",
                    "-subj",
                    "/CN=Orchestra Test CA",
                    "-keyout",
                    str(root / "ca.key"),
                    "-out",
                    str(root / "ca.crt"),
                ],
                [
                    str(openssl),
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-config",
                    str(config),
                    "-keyout",
                    str(root / "server.key"),
                    "-out",
                    str(root / "server.csr"),
                ],
                [
                    str(openssl),
                    "x509",
                    "-req",
                    "-days",
                    "30",
                    "-in",
                    str(root / "server.csr"),
                    "-CA",
                    str(root / "ca.crt"),
                    "-CAkey",
                    str(root / "ca.key"),
                    "-CAcreateserial",
                    "-extfile",
                    str(config),
                    "-extensions",
                    "req_ext",
                    "-out",
                    str(root / "server.crt"),
                ],
            ]
            for command in commands:
                subprocess.run(command, check=True, capture_output=True)
            result = inspect_certificate(
                (root / "server.crt").read_bytes(),
                (root / "server.key").read_bytes(),
                (root / "ca.crt").read_bytes(),
                openssl,
            )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertTrue(result["chainVerified"])
        self.assertTrue(result["keyMatches"])
        self.assertTrue(
            set(policy_item["requiredDnsNames"]).issubset(result["dnsNames"])
        )


if __name__ == "__main__":
    unittest.main()
