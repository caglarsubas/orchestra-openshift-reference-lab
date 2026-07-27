from __future__ import annotations

import copy
import json
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.openshift_toolchain_intake import (
    CLAIMS as TOOLCHAIN_CLAIMS,
    LOCK_PATH as TOOLCHAIN_LOCK,
    REPORT_CONTROLS as TOOLCHAIN_CONTROLS,
    REPORT_KIND as TOOLCHAIN_KIND,
    report_digest as toolchain_report_digest,
)
from scripts.sno_trial_dns_delegation import (
    build_assessment as build_dns_report,
)
from scripts.sno_trial_install_admission import (
    build_admission,
    validate_admission,
)
from scripts.sno_trial_network_hygiene import (
    build_assessment as build_network_report,
)
from scripts.sno_trial_operator_path import (
    build_assessment as build_operator_report,
)
from scripts.sno_trial_readiness import (
    REQUIRED_APIS,
    build_assessment as build_readiness_report,
)
from scripts.trial_lease import build_lease
from scripts.validate_sno_trial_profile import (
    ROOT,
    TRIAL_PROFILE,
    canonical_digest,
    load_json,
)


PROJECT_ID = "prometa-orch-sno-fixture"
IDENTITY_DIGEST = f"sha256:{'a' * 64}"


def utc_text(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fixture(name: str) -> dict[str, object]:
    return json.loads((ROOT / "tests" / "fixtures" / name).read_text(encoding="utf-8"))


def toolchain_report(generated_at: datetime, execution_mode: str) -> dict[str, object]:
    lock = load_json(TOOLCHAIN_LOCK)
    artifacts = [
        {
            "role": item["role"],
            "fileName": item["fileName"],
            "sourceUrl": item["sourceUrl"],
            "sizeBytes": item["sizeBytes"],
            "publishedDigest": item["digest"],
            "actualDigest": item["digest"],
            "checksumMatch": True,
            "members": item["members"],
        }
        for item in lock["artifacts"]
    ]
    report: dict[str, object] = {
        "schemaVersion": 1,
        "kind": TOOLCHAIN_KIND,
        "intakeId": "sno-toolchain-fixture-admission.1",
        "generatedAt": utc_text(generated_at),
        "targetClass": "engineering-trial",
        "executionMode": execution_mode,
        "bindings": {
            "profileId": "orchestra-ocp-sno-trial-amd64-v1",
            "toolchainLockDigest": canonical_digest(lock),
            "version": "4.20.27",
            "architecture": "linux/amd64",
        },
        "checksumDocument": {
            **lock["checksumDocument"],
            "signatureVerified": True,
        },
        "signatureDocument": {
            **lock["signatureDocument"],
            "signedPayloadDigest": lock["checksumDocument"]["digest"],
            "validSignature": True,
        },
        "signingKey": {
            **lock["signingKey"],
            "fingerprintVerified": True,
        },
        "artifacts": artifacts,
        "controls": dict(TOOLCHAIN_CONTROLS),
        "claims": dict(TOOLCHAIN_CLAIMS),
    }
    report["reportDigest"] = toolchain_report_digest(report)
    return report


def source_reports(
    at: datetime,
    *,
    execution_mode: str = "live-diagnostic",
    readiness_age_minutes: int = 1,
) -> dict[str, dict[str, object]]:
    readiness = fixture("sno-trial-cloud-pending.json")
    readiness.update(
        {
            "executionMode": execution_mode,
            "observedAt": utc_text(at - timedelta(minutes=readiness_age_minutes)),
            "projectId": PROJECT_ID,
            "billingEnabled": True,
            "enabledApis": list(REQUIRED_APIS),
            "quotaRequest": {
                "status": "approved",
                "source": "operator-declared",
                "requestedAdditionalProjects": 1,
            },
        }
    )
    network = fixture("sno-trial-network-dirty.json")
    network.update(
        {
            "executionMode": execution_mode,
            "observedAt": utc_text(at - timedelta(minutes=1)),
            "projectId": PROJECT_ID,
            "networks": [],
            "firewalls": [],
        }
    )
    dns = fixture("sno-trial-dns-delegation-missing.json")
    dns.update(
        {
            "executionMode": execution_mode,
            "observedAt": utc_text(at - timedelta(minutes=1)),
            "projectId": PROJECT_ID,
            "delegatedNameServers": dns["managedZone"]["nameServers"],
        }
    )
    operator = fixture("sno-trial-operator-path-ready.json")
    operator.update(
        {
            "executionMode": execution_mode,
            "observedAt": utc_text(at - timedelta(minutes=1)),
            "projectId": PROJECT_ID,
            "configuredProjectId": PROJECT_ID,
        }
    )
    return {
        "readiness": build_readiness_report(
            readiness, "sno-readiness-fixture-admission.1"
        ),
        "network": build_network_report(network, "sno-network-fixture-admission.1"),
        "dns": build_dns_report(dns, "sno-dns-fixture-admission.1"),
        "operator": build_operator_report(operator, "sno-operator-fixture-admission.1"),
        "toolchain": toolchain_report(
            at - timedelta(days=1),
            "live-local" if execution_mode == "live-diagnostic" else execution_mode,
        ),
    }


def lease(at: datetime, operator_digest: str = IDENTITY_DIGEST) -> dict:
    return build_lease(
        load_json(TRIAL_PROFILE),
        PROJECT_ID,
        operator_digest,
        at - timedelta(minutes=2),
        8,
        "sno-trial-render-admission-001",
    )


def admission(
    at: datetime,
    reports: dict[str, dict[str, object]],
    active_lease: dict,
) -> dict:
    return build_admission(
        readiness=reports["readiness"],
        network=reports["network"],
        dns=reports["dns"],
        operator=reports["operator"],
        toolchain=reports["toolchain"],
        lease=active_lease,
        project_id=PROJECT_ID,
        admission_id="sno-render-fixture-ready.1",
        assessed_at=at,
    )


class SnoTrialInstallAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.at = datetime(2026, 7, 27, 2, 0, tzinfo=timezone.utc)

    def test_all_live_fresh_gates_authorize_only_secret_free_render(self) -> None:
        active_lease = lease(self.at)
        report = admission(self.at, source_reports(self.at), active_lease)
        validate_admission(
            report,
            self.at,
            expected_project_id=PROJECT_ID,
            lease=active_lease,
        )
        self.assertEqual(report["decision"]["status"], "READY_TO_RENDER")
        self.assertTrue(report["controls"]["installConfigRenderAuthorized"])
        self.assertFalse(report["controls"]["clusterCreationAuthorized"])
        self.assertFalse(report["controls"]["cloudMutationAuthorized"])
        self.assertTrue(all(item["accepted"] for item in report["evidence"]))

    def test_simulated_sources_cannot_authorize_render(self) -> None:
        active_lease = lease(self.at)
        report = admission(
            self.at,
            source_reports(self.at, execution_mode="simulated"),
            active_lease,
        )
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertIn("LIVE_EVIDENCE_REQUIRED", report["decision"]["reasonCodes"])
        self.assertFalse(report["controls"]["installConfigRenderAuthorized"])

    def test_stale_evidence_cannot_authorize_render(self) -> None:
        active_lease = lease(self.at)
        report = admission(
            self.at,
            source_reports(self.at, readiness_age_minutes=15),
            active_lease,
        )
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertIn("EVIDENCE_STALE_OR_FUTURE", report["decision"]["reasonCodes"])

    def test_lease_must_bind_the_observed_operator_identity(self) -> None:
        active_lease = lease(self.at, f"sha256:{'c' * 64}")
        report = admission(self.at, source_reports(self.at), active_lease)
        self.assertEqual(report["decision"]["status"], "BLOCKED")
        self.assertIn(
            "LEASE_OPERATOR_IDENTITY_MISMATCH",
            report["decision"]["reasonCodes"],
        )

    def test_admission_expiry_and_tamper_fail_closed(self) -> None:
        active_lease = lease(self.at)
        report = admission(self.at, source_reports(self.at), active_lease)
        expired_at = datetime.fromisoformat(report["validUntil"].replace("Z", "+00:00"))
        with self.assertRaisesRegex(ValueError, "sno_render_admission_ready_invalid"):
            validate_admission(
                report,
                expired_at,
                expected_project_id=PROJECT_ID,
                lease=active_lease,
            )
        changed = copy.deepcopy(report)
        changed["controls"]["clusterCreationAuthorized"] = True
        with self.assertRaisesRegex(
            ValueError, "sno_render_admission_controls_invalid"
        ):
            validate_admission(
                changed,
                self.at,
                expected_project_id=PROJECT_ID,
                lease=active_lease,
            )
        changed = copy.deepcopy(report)
        changed["reportDigest"] = f"sha256:{'f' * 64}"
        with self.assertRaisesRegex(
            ValueError, "sno_render_admission_report_digest_invalid"
        ):
            validate_admission(
                changed,
                self.at,
                expected_project_id=PROJECT_ID,
                lease=active_lease,
            )

    def test_renderer_requires_the_aggregate_admission(self) -> None:
        source = (ROOT / "scripts" / "render_sno_trial_install_config.py").read_text(
            encoding="utf-8"
        )
        materializer = (
            ROOT / "scripts" / "materialize_sno_trial_install_config.py"
        ).read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--admission", required=True', source)
        self.assertIn("validate_admission(", source)
        self.assertIn("trial_install_render_not_authorized", source)
        self.assertIn("validate_admission(", materializer)
        self.assertIn("materialize-sno-trial-install-config:", makefile)

    def test_renderer_accepts_only_ready_unexpired_admission(self) -> None:
        from scripts.render_sno_trial_install_config import main as render_main

        active_lease = lease(self.at)
        ready = admission(self.at, source_reports(self.at), active_lease)
        blocked = admission(
            self.at,
            source_reports(self.at, execution_mode="simulated"),
            active_lease,
        )
        output = (
            ROOT / "install-dir" / "trial" / f"admission-test-{uuid.uuid4().hex}.yaml"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = root / "values.json"
            lease_path = root / "lease.json"
            ready_path = root / "ready.json"
            blocked_path = root / "blocked.json"
            values.write_text(
                json.dumps({"TARGET_PROJECT_ID": PROJECT_ID}),
                encoding="utf-8",
            )
            lease_path.write_text(json.dumps(active_lease), encoding="utf-8")
            ready_path.write_text(json.dumps(ready), encoding="utf-8")
            blocked_path.write_text(json.dumps(blocked), encoding="utf-8")
            try:
                self.assertEqual(
                    render_main(
                        [
                            "--values",
                            str(values),
                            "--lease",
                            str(lease_path),
                            "--admission",
                            str(ready_path),
                            "--output",
                            str(output),
                            "--at",
                            utc_text(self.at),
                        ]
                    ),
                    0,
                )
                self.assertTrue(output.exists())
                second_output = output.with_name(f"blocked-{uuid.uuid4().hex}.yaml")
                with self.assertRaisesRegex(
                    ValueError, "trial_install_render_not_authorized"
                ):
                    render_main(
                        [
                            "--values",
                            str(values),
                            "--lease",
                            str(lease_path),
                            "--admission",
                            str(blocked_path),
                            "--output",
                            str(second_output),
                            "--at",
                            utc_text(self.at),
                        ]
                    )
            finally:
                output.unlink(missing_ok=True)
                second_output = locals().get("second_output")
                if isinstance(second_output, Path):
                    second_output.unlink(missing_ok=True)

    def test_materializer_is_file_backed_private_and_create_only(self) -> None:
        from scripts.materialize_sno_trial_install_config import (
            main as materialize_main,
            write_create_only,
        )
        from scripts.render_sno_trial_install_config import (
            TEMPLATE,
            render,
        )

        active_lease = lease(self.at)
        ready = admission(self.at, source_reports(self.at), active_lease)
        restricted = ROOT / "restricted"
        install_root = ROOT / "install-dir" / "trial"
        restricted.mkdir(exist_ok=True)
        install_root.mkdir(parents=True, exist_ok=True)
        with (
            tempfile.TemporaryDirectory(
                prefix="materialize-secrets-", dir=restricted
            ) as secret_directory,
            tempfile.TemporaryDirectory(
                prefix="materialize-output-", dir=install_root
            ) as install_directory,
        ):
            secret_root = Path(secret_directory)
            output_root = Path(install_directory)
            rendered = output_root / "rendered.yaml"
            pull_secret = secret_root / "pull-secret.json"
            public_key = secret_root / "orchestra-trial.pub"
            lease_path = secret_root / "lease.json"
            admission_path = secret_root / "admission.json"
            output = output_root / "operator" / "install-config.yaml"
            rendered.write_text(
                render(
                    TEMPLATE.read_text(encoding="utf-8"),
                    {"TARGET_PROJECT_ID": PROJECT_ID},
                ),
                encoding="ascii",
            )
            pull_secret.write_text(
                json.dumps(
                    {
                        "auths": {
                            "quay.io": {
                                "auth": "fixture-credential",
                                "email": "operator@example.com",
                            }
                        }
                    }
                ),
                encoding="ascii",
            )
            public_key.write_text(
                "ssh-ed25519 "
                "AAAAC3NzaC1lZDI1NTE5AAAAIFixtureMaterialOnly "
                "operator@example.com\n",
                encoding="ascii",
            )
            lease_path.write_text(json.dumps(active_lease), encoding="utf-8")
            admission_path.write_text(json.dumps(ready), encoding="utf-8")
            for path in (
                rendered,
                pull_secret,
                public_key,
                lease_path,
                admission_path,
            ):
                path.chmod(0o600)
            arguments = [
                "--rendered",
                str(rendered),
                "--pull-secret",
                str(pull_secret),
                "--ssh-public-key",
                str(public_key),
                "--lease",
                str(lease_path),
                "--admission",
                str(admission_path),
                "--project-id",
                PROJECT_ID,
                "--output",
                str(output),
                "--at",
                utc_text(self.at),
            ]
            self.assertEqual(materialize_main(arguments), 0)
            materialized = output.read_text(encoding="utf-8")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("${PULL_SECRET_JSON}", materialized)
            self.assertNotIn("${SSH_PUBLIC_KEY}", materialized)
            self.assertIn("fixture-credential", materialized)
            self.assertIn("ssh-ed25519", materialized)
            with self.assertRaisesRegex(ValueError, "sno_materialize_output_invalid"):
                materialize_main(arguments)
            existing = output_root / "existing.yaml"
            existing.write_text("retain-me\n", encoding="ascii")
            with self.assertRaisesRegex(
                ValueError, "sno_materialize_output_write_failed"
            ):
                write_create_only(existing, "replacement\n")
            self.assertEqual(existing.read_text(encoding="ascii"), "retain-me\n")

    def test_materializer_rejects_stale_admission_and_bad_secret_input(
        self,
    ) -> None:
        from scripts.materialize_sno_trial_install_config import (
            main as materialize_main,
            read_pull_secret,
        )
        from scripts.render_sno_trial_install_config import (
            TEMPLATE,
            render,
        )

        active_lease = lease(self.at)
        ready = admission(self.at, source_reports(self.at), active_lease)
        restricted = ROOT / "restricted"
        install_root = ROOT / "install-dir" / "trial"
        restricted.mkdir(exist_ok=True)
        install_root.mkdir(parents=True, exist_ok=True)
        with (
            tempfile.TemporaryDirectory(
                prefix="materialize-bad-secrets-", dir=restricted
            ) as secret_directory,
            tempfile.TemporaryDirectory(
                prefix="materialize-stale-", dir=install_root
            ) as install_directory,
        ):
            secret_root = Path(secret_directory)
            output_root = Path(install_directory)
            rendered = output_root / "rendered.yaml"
            pull_secret = secret_root / "pull-secret.json"
            public_key = secret_root / "orchestra-trial.pub"
            lease_path = secret_root / "lease.json"
            admission_path = secret_root / "admission.json"
            output = output_root / "operator" / "install-config.yaml"
            rendered.write_text(
                render(
                    TEMPLATE.read_text(encoding="utf-8"),
                    {"TARGET_PROJECT_ID": PROJECT_ID},
                ),
                encoding="ascii",
            )
            pull_secret.write_text(
                '{"auths":{"quay.io":{"auth":"one","auth":"two"}}}',
                encoding="ascii",
            )
            public_key.write_text(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureMaterialOnly\n",
                encoding="ascii",
            )
            lease_path.write_text(json.dumps(active_lease), encoding="utf-8")
            admission_path.write_text(json.dumps(ready), encoding="utf-8")
            for path in (
                rendered,
                pull_secret,
                public_key,
                lease_path,
                admission_path,
            ):
                path.chmod(0o600)
            with self.assertRaisesRegex(
                ValueError, "sno_materialize_pull_secret_duplicate_key"
            ):
                read_pull_secret(pull_secret)
            pull_secret.write_text(
                '{"auths":{"quay.io":{"auth":"fixture"}}}',
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                ValueError, "sno_render_admission_ready_invalid"
            ):
                materialize_main(
                    [
                        "--rendered",
                        str(rendered),
                        "--pull-secret",
                        str(pull_secret),
                        "--ssh-public-key",
                        str(public_key),
                        "--lease",
                        str(lease_path),
                        "--admission",
                        str(admission_path),
                        "--project-id",
                        PROJECT_ID,
                        "--output",
                        str(output),
                        "--at",
                        utc_text(self.at + timedelta(minutes=15)),
                    ]
                )
            self.assertFalse(output.exists())

    def test_schema_is_strict_at_every_object_boundary(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "sno-trial-render-admission-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        for name in ("bindings", "evidence", "decision", "controls", "claims"):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])

    def test_cli_output_is_create_only(self) -> None:
        from scripts.sno_trial_install_admission import write_create_only

        active_lease = lease(self.at)
        report = admission(self.at, source_reports(self.at), active_lease)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "admission.json"
            write_create_only(output, report)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(
                ValueError, "sno_render_admission_output_exists"
            ):
                write_create_only(output, report)


if __name__ == "__main__":
    unittest.main()
