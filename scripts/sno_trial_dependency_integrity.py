#!/usr/bin/env python3
"""Observe SNO model and TLS integrity without persisting payload bytes."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.materialize_sno_trial_dependency_manifests import (
        validate_receipt as validate_materialization_receipt,
    )
    from scripts.sno_trial_dependency_inputs import (
        CLAIMS,
        load_json,
        parse_utc,
        utc_text,
        validate_assessment as validate_input_assessment,
    )
    from scripts.validate_repository import ROOT, canonical_digest
    from scripts.validate_sno_trial_dependency_manifests import (
        load_validated_candidate,
    )
except ModuleNotFoundError:
    from materialize_sno_trial_dependency_manifests import (
        validate_receipt as validate_materialization_receipt,
    )
    from sno_trial_dependency_inputs import (
        CLAIMS,
        load_json,
        parse_utc,
        utc_text,
        validate_assessment as validate_input_assessment,
    )
    from validate_repository import ROOT, canonical_digest
    from validate_sno_trial_dependency_manifests import load_validated_candidate


POLICY_PATH = ROOT / "config" / "sno-trial-dependency-integrity-policy.lock.json"
ARTIFACT_PATH = ROOT / "config" / "sno-trial-dependency-artifacts.lock.json"
POLICY_KIND = "orchestra.openshift.sno-trial-dependency-integrity-policy.v1"
SNAPSHOT_KIND = "orchestra.openshift.sno-trial-dependency-integrity-snapshot.v1"
REPORT_KIND = "orchestra.openshift.sno-trial-dependency-integrity-observation.v1"
POLICY_ID = "orchestra-sno-trial-dependency-integrity-2026-07-28.2"
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
ASSESSMENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
HEX_DIGEST = re.compile(r"^[a-f0-9]{64}$")
KUBE_UID = re.compile(r"^[a-f0-9-]{16,64}$")
OPENSSL_VERSION = re.compile(r"^OpenSSL ([0-9]+)\.")
MODEL_POD_NAME = "orchestra-sno-model-backend-0"
MODEL_NAMESPACE = "orchestra-sno-model-backend"
MODEL_CONTAINER = "model-backend"
MODEL_IMAGE = (
    "ghcr.io/ggml-org/llama.cpp@"
    "sha256:7a670b0633a2b33d915ca958fc1e4977334924590c9bd5ffc9d4813dd168d77b"
)
CERTIFICATE_SECRET_REFERENCES = {
    "valkey-server": {
        "namespace": "orchestra-sno-valkey",
        "name": "orchestra-sno-valkey-server-tls",
    },
    "model-backend-server": {
        "namespace": "orchestra-sno-model-backend",
        "name": "orchestra-sno-model-server-tls",
    },
}
MODEL_REASON_ORDER = [
    "MODEL_ARTIFACT_SIZE_MISMATCH",
    "MODEL_ARTIFACT_DIGEST_MISMATCH",
    "MODEL_ARTIFACT_WRITABLE",
]
CERTIFICATE_REASON_ORDER = [
    "CERTIFICATE_INVALID",
    "CERTIFICATE_NOT_YET_VALID",
    "CERTIFICATE_EXPIRES_TOO_SOON",
    "CERTIFICATE_SAN_MISMATCH",
    "CERTIFICATE_KEY_MISMATCH",
    "CERTIFICATE_CHAIN_INVALID",
]
DECISION_REASON_ORDER = [
    "LIVE_CLUSTER_OBSERVATION_REQUIRED",
    *MODEL_REASON_ORDER,
    *CERTIFICATE_REASON_ORDER,
]
CommandRunner = Callable[..., subprocess.CompletedProcess[bytes]]
CertificateInspector = Callable[[bytes, bytes, bytes, Path], dict[str, Any] | None]


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def exact_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def list_value(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list):
        fail(code)
    return value


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def digest_file(path: Path, code: str) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > 512 * 1024 * 1024:
                    fail(code)
                digest.update(chunk)
    except OSError:
        fail(code)
    return f"sha256:{digest.hexdigest()}"


def digest_without_self(value: dict[str, Any], field: str) -> str:
    unsigned = copy.deepcopy(value)
    unsigned.pop(field, None)
    return canonical_digest(unsigned)


def private_regular_file(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        fail(code)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o077
    ):
        fail(code)


def executable_file(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        fail(code)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & 0o100
        or metadata.st_mode & 0o022
    ):
        fail(code)


def restricted_report(path: Path, code: str) -> dict[str, Any]:
    private_regular_file(path, code)
    try:
        path.resolve(strict=True).relative_to((ROOT / "restricted").resolve())
    except (OSError, ValueError):
        fail(code)
    return load_json(path)


def load_artifact_set() -> dict[str, Any]:
    artifact = load_json(ARTIFACT_PATH)
    if artifact.get("artifactSetDigest") != digest_without_self(
        artifact, "artifactSetDigest"
    ):
        fail("sno_dependency_integrity_artifact_set_invalid")
    return artifact


def expected_policy_certificates() -> list[dict[str, Any]]:
    return [
        {
            "certificateId": "valkey-server",
            "secretInputId": "valkey-server-tls",
            "certificateMountPath": "/var/run/secrets/orchestra-valkey/tls.crt",
            "privateKeyMountPath": "/var/run/secrets/orchestra-valkey/tls.key",
            "trustBundleMountPath": "/var/run/secrets/orchestra-valkey/ca.crt",
            "requiredDnsNames": [
                "orchestra-sno-valkey",
                "orchestra-sno-valkey.orchestra-sno-valkey",
                "orchestra-sno-valkey.orchestra-sno-valkey.svc",
                "orchestra-sno-valkey.orchestra-sno-valkey.svc.cluster.local",
            ],
            "minimumRemainingSeconds": 86400,
        },
        {
            "certificateId": "model-backend-server",
            "secretInputId": "model-server-tls",
            "certificateMountPath": "/var/run/secrets/orchestra-model/tls.crt",
            "privateKeyMountPath": "/var/run/secrets/orchestra-model/tls.key",
            "trustBundleMountPath": "/var/run/secrets/orchestra-model/ca.crt",
            "requiredDnsNames": [
                "orchestra-sno-model-backend",
                "orchestra-sno-model-backend.orchestra-sno-model-backend",
                "orchestra-sno-model-backend.orchestra-sno-model-backend.svc",
                (
                    "orchestra-sno-model-backend."
                    "orchestra-sno-model-backend.svc.cluster.local"
                ),
            ],
            "minimumRemainingSeconds": 86400,
        },
    ]


def expected_controls() -> dict[str, Any]:
    return {
        "scope": "sno-engineering-trial-model-and-tls-integrity-only",
        "liveClusterInputsRequired": True,
        "secretValuesStored": False,
        "certificateBytesStored": False,
        "privateKeyBytesStored": False,
        "modelBytesStored": False,
        "operatorClusterAccessRequired": True,
        "dependencyEgressRequired": False,
        "serverSideDryRunExecuted": False,
        "connectivityVerified": False,
        "cloudMutationAuthorized": False,
        "deploymentAuthorized": False,
        "campaignEligible": False,
        "allowedCertificationSlots": [],
    }


def validate_policy(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "profileId",
            "targetClass",
            "bindings",
            "modelArtifact",
            "certificates",
            "execution",
            "controls",
            "claims",
            "policyDigest",
        },
        "sno_dependency_integrity_policy_invalid",
    )
    candidate = load_validated_candidate()
    artifact = load_artifact_set()
    if (
        value["schemaVersion"] != 1
        or value["kind"] != POLICY_KIND
        or value["policyId"] != POLICY_ID
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["bindings"]
        != {
            "candidateId": candidate["candidateId"],
            "candidateDigest": candidate["candidateDigest"],
            "manifestSetDigest": candidate["manifestSetDigest"],
            "artifactSetId": artifact["artifactSetId"],
            "artifactSetDigest": artifact["artifactSetDigest"],
        }
    ):
        fail("sno_dependency_integrity_policy_identity_invalid")
    models = artifact.get("models")
    if not isinstance(models, list) or len(models) != 1:
        fail("sno_dependency_integrity_policy_model_invalid")
    model = models[0]
    if value["modelArtifact"] != {
        "artifactId": model["id"],
        "filename": model["filename"],
        "mountPath": model["mountPath"],
        "digest": model["digest"],
        "sizeBytes": model["sizeBytes"],
        "maximumAllowedBytes": model["maximumAllowedBytes"],
    }:
        fail("sno_dependency_integrity_policy_model_invalid")
    if value["certificates"] != expected_policy_certificates():
        fail("sno_dependency_integrity_policy_certificates_invalid")
    if value["execution"] != {
        "requiredMode": "live-cluster-read-only",
        "maximumInputObservationAgeSeconds": 3600,
        "maximumMaterializationAgeSeconds": 3600,
        "opensslMajorVersion": 3,
        "maximumCertificateBytes": 65536,
        "maximumPrivateKeyBytes": 65536,
        "maximumTrustBundleBytes": 262144,
    }:
        fail("sno_dependency_integrity_policy_execution_invalid")
    if value["controls"] != expected_controls() or value["claims"] != CLAIMS:
        fail("sno_dependency_integrity_policy_claims_invalid")
    if value["policyDigest"] != digest_without_self(value, "policyDigest"):
        fail("sno_dependency_integrity_policy_digest_invalid")


def load_policy() -> dict[str, Any]:
    value = load_json(POLICY_PATH)
    validate_policy(value)
    return value


def default_runner(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
    timeout: int = 90,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        input=input_bytes,
        check=False,
        capture_output=True,
        timeout=timeout,
        pass_fds=pass_fds,
    )


def run_checked(
    command: list[str],
    *,
    run: CommandRunner,
    input_bytes: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
    timeout: int = 90,
    maximum_stdout: int = 1048576,
    code: str,
) -> bytes:
    try:
        completed = run(
            command,
            input_bytes=input_bytes,
            pass_fds=pass_fds,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        fail(code)
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > maximum_stdout
    ):
        fail(code)
    return completed.stdout


def oc_command(client: Path, kubeconfig: Path, arguments: list[str]) -> list[str]:
    return [
        str(client.resolve()),
        "--kubeconfig",
        str(kubeconfig.resolve()),
        *arguments,
    ]


def collect_model_observation(
    client: Path,
    kubeconfig: Path,
    policy: dict[str, Any],
    run: CommandRunner,
) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata_output = run_checked(
        oc_command(
            client,
            kubeconfig,
            [
                "get",
                "pod",
                MODEL_POD_NAME,
                "--namespace",
                MODEL_NAMESPACE,
                "--output",
                (
                    'go-template={{.metadata.name}}{{"\\n"}}'
                    '{{.metadata.uid}}{{"\\n"}}'
                    '{{.spec.nodeName}}{{"\\n"}}'
                    '{{.status.phase}}{{"\\n"}}'
                    '{{(index .spec.containers 0).image}}{{"\\n"}}'
                    '{{(index .status.containerStatuses 0).ready}}{{"\\n"}}'
                ),
            ],
        ),
        run=run,
        code="sno_dependency_integrity_model_pod_observation_failed",
        maximum_stdout=2048,
    )
    try:
        metadata_lines = metadata_output.decode("ascii").rstrip("\n").split("\n")
    except UnicodeError:
        fail("sno_dependency_integrity_model_pod_output_invalid")
    if (
        len(metadata_lines) != 6
        or metadata_lines[0] != MODEL_POD_NAME
        or not KUBE_UID.fullmatch(metadata_lines[1])
        or not metadata_lines[2]
        or metadata_lines[3] != "Running"
        or metadata_lines[4] != MODEL_IMAGE
        or metadata_lines[5].lower() != "true"
    ):
        fail("sno_dependency_integrity_model_pod_output_invalid")
    model = policy["modelArtifact"]
    script = (
        'set -eu; p="$1"; test -f "$p"; test ! -L "$p"; '
        'size="$(wc -c < "$p" | tr -d "[:space:]")"; '
        'digest="$(sha256sum "$p" | cut -d" " -f1)"; '
        'writable=false; if test -w "$p"; then writable=true; fi; '
        'printf "%s\\n%s\\n%s\\n" "$size" "$digest" "$writable"'
    )
    output = run_checked(
        oc_command(
            client,
            kubeconfig,
            [
                "exec",
                MODEL_POD_NAME,
                "--namespace",
                MODEL_NAMESPACE,
                "--container",
                MODEL_CONTAINER,
                "--",
                "/bin/sh",
                "-ec",
                script,
                "orchestra-integrity-probe",
                model["mountPath"],
            ],
        ),
        run=run,
        timeout=900,
        maximum_stdout=1024,
        code="sno_dependency_integrity_model_probe_failed",
    )
    try:
        lines = output.decode("ascii").rstrip("\n").split("\n")
        size = int(lines[0])
    except (UnicodeError, ValueError, IndexError):
        fail("sno_dependency_integrity_model_probe_output_invalid")
    if (
        len(lines) != 3
        or size < 0
        or size > model["maximumAllowedBytes"]
        or not HEX_DIGEST.fullmatch(lines[1])
        or lines[2] not in {"true", "false"}
    ):
        fail("sno_dependency_integrity_model_probe_output_invalid")
    digest = f"sha256:{lines[1]}"
    size_matches = size == model["sizeBytes"]
    digest_matches = digest == model["digest"]
    read_only = lines[2] == "false"
    reasons = []
    if not size_matches:
        reasons.append("MODEL_ARTIFACT_SIZE_MISMATCH")
    if not digest_matches:
        reasons.append("MODEL_ARTIFACT_DIGEST_MISMATCH")
    if not read_only:
        reasons.append("MODEL_ARTIFACT_WRITABLE")
    return (
        {
            "artifactId": model["artifactId"],
            "observed": True,
            "sizeBytes": size,
            "digest": digest,
            "sizeMatches": size_matches,
            "digestMatches": digest_matches,
            "readOnly": read_only,
            "reasonCodes": reasons,
        },
        {
            "podUidDigest": canonical_digest(metadata_lines[1]),
            "nodeNameDigest": canonical_digest(metadata_lines[2]),
            "modelImage": metadata_lines[4],
        },
    )


def decode_secret(
    raw: bytes,
    reference: dict[str, str],
    limits: dict[str, int],
) -> tuple[dict[str, bytes], str]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=lambda pairs: _reject_duplicate_keys(pairs),
        )
    except (UnicodeError, json.JSONDecodeError):
        fail("sno_dependency_integrity_tls_secret_invalid")
    if not isinstance(value, dict):
        fail("sno_dependency_integrity_tls_secret_invalid")
    metadata = value.get("metadata")
    data = value.get("data")
    if (
        value.get("type") != "kubernetes.io/tls"
        or not isinstance(metadata, dict)
        or metadata.get("name") != reference["name"]
        or metadata.get("namespace") != reference["namespace"]
        or not isinstance(metadata.get("resourceVersion"), str)
        or not metadata["resourceVersion"]
        or not isinstance(data, dict)
        or set(data) != {"ca.crt", "tls.crt", "tls.key"}
    ):
        fail("sno_dependency_integrity_tls_secret_invalid")
    result: dict[str, bytes] = {}
    for key, maximum in limits.items():
        encoded = data.get(key)
        if not isinstance(encoded, str):
            fail("sno_dependency_integrity_tls_secret_invalid")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            fail("sno_dependency_integrity_tls_secret_invalid")
        if not decoded or len(decoded) > maximum:
            fail("sno_dependency_integrity_tls_secret_invalid")
        result[key] = decoded
    return result, canonical_digest(metadata["resourceVersion"])


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("sno_dependency_integrity_tls_secret_duplicate_key")
        result[key] = value
    return result


def memfd(name: str, value: bytes) -> int:
    if not hasattr(os, "memfd_create") or not Path("/proc/self/fd").is_dir():
        fail("sno_dependency_integrity_anonymous_file_unavailable")
    try:
        descriptor = os.memfd_create(name, flags=0)
        os.write(descriptor, value)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        fail("sno_dependency_integrity_anonymous_file_failed")
    return descriptor


def openssl_output(
    openssl: Path,
    arguments: list[str],
    *,
    run: CommandRunner,
    stdin: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
    code: str = "sno_dependency_integrity_certificate_invalid",
) -> bytes:
    return run_checked(
        [str(openssl.resolve()), *arguments],
        run=run,
        input_bytes=stdin,
        pass_fds=pass_fds,
        maximum_stdout=1048576,
        code=code,
    )


def parse_certificate_time(value: str) -> datetime:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        fail("sno_dependency_integrity_certificate_time_invalid")
    if parsed.tzinfo is None:
        fail("sno_dependency_integrity_certificate_time_invalid")
    return parsed.astimezone(timezone.utc)


def inspect_certificate(
    certificate: bytes,
    private_key: bytes,
    trust_bundle: bytes,
    openssl: Path,
    run: CommandRunner = default_runner,
) -> dict[str, Any] | None:
    descriptors: list[int] = []
    try:
        certificate_fd = memfd("orchestra-certificate", certificate)
        key_fd = memfd("orchestra-private-key", private_key)
        ca_fd = memfd("orchestra-trust-bundle", trust_bundle)
        descriptors.extend([certificate_fd, key_fd, ca_fd])
        certificate_path = f"/proc/self/fd/{certificate_fd}"
        key_path = f"/proc/self/fd/{key_fd}"
        ca_path = f"/proc/self/fd/{ca_fd}"
        pass_fds = tuple(descriptors)
        der = openssl_output(
            openssl,
            ["x509", "-in", certificate_path, "-outform", "DER"],
            run=run,
            pass_fds=pass_fds,
        )
        cert_public_pem = openssl_output(
            openssl,
            ["x509", "-in", certificate_path, "-pubkey", "-noout"],
            run=run,
            pass_fds=pass_fds,
        )
        cert_public_der = openssl_output(
            openssl,
            ["pkey", "-pubin", "-outform", "DER"],
            run=run,
            stdin=cert_public_pem,
        )
        key_public_der = openssl_output(
            openssl,
            ["pkey", "-in", key_path, "-pubout", "-outform", "DER"],
            run=run,
            pass_fds=pass_fds,
        )
        dates_raw = openssl_output(
            openssl,
            ["x509", "-in", certificate_path, "-noout", "-startdate", "-enddate"],
            run=run,
            pass_fds=pass_fds,
        )
        san_raw = openssl_output(
            openssl,
            ["x509", "-in", certificate_path, "-noout", "-ext", "subjectAltName"],
            run=run,
            pass_fds=pass_fds,
        )
        verify = run(
            [
                str(openssl.resolve()),
                "verify",
                "-CAfile",
                ca_path,
                certificate_path,
            ],
            input_bytes=None,
            pass_fds=pass_fds,
            timeout=90,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        date_lines = dates_raw.decode("ascii").strip().splitlines()
        if len(date_lines) != 2:
            return None
        not_before = parse_certificate_time(date_lines[0].removeprefix("notBefore="))
        not_after = parse_certificate_time(date_lines[1].removeprefix("notAfter="))
        san_text = san_raw.decode("ascii")
    except (UnicodeError, ValueError):
        return None
    sans = sorted(set(re.findall(r"DNS:([^,\s]+)", san_text)))
    if not sans:
        return None
    return {
        "leafCertificateDigest": digest_bytes(der),
        "trustBundleDigest": digest_bytes(trust_bundle),
        "publicKeyDigest": digest_bytes(cert_public_der),
        "notBefore": not_before,
        "notAfter": not_after,
        "dnsNames": sans,
        "keyMatches": cert_public_der == key_public_der,
        "chainVerified": (
            verify.returncode == 0 and not verify.stderr and len(verify.stdout) <= 4096
        ),
    }


def collect_certificate_observation(
    client: Path,
    kubeconfig: Path,
    openssl: Path,
    policy: dict[str, Any],
    item: dict[str, Any],
    observed_at: datetime,
    run: CommandRunner,
    inspector: Callable[..., dict[str, Any] | None],
) -> dict[str, Any]:
    reference = CERTIFICATE_SECRET_REFERENCES[item["certificateId"]]
    raw = run_checked(
        oc_command(
            client,
            kubeconfig,
            [
                "get",
                "secret",
                reference["name"],
                "--namespace",
                reference["namespace"],
                "--output",
                "json",
            ],
        ),
        run=run,
        maximum_stdout=1048576,
        code="sno_dependency_integrity_tls_secret_observation_failed",
    )
    execution = policy["execution"]
    values, resource_version_digest = decode_secret(
        raw,
        reference,
        {
            "tls.crt": execution["maximumCertificateBytes"],
            "tls.key": execution["maximumPrivateKeyBytes"],
            "ca.crt": execution["maximumTrustBundleBytes"],
        },
    )
    inspected = inspector(
        values["tls.crt"],
        values["tls.key"],
        values["ca.crt"],
        openssl,
        run=run,
    )
    if inspected is None:
        return {
            "certificateId": item["certificateId"],
            "secretReferenceDigest": canonical_digest(reference),
            "secretResourceVersionDigest": resource_version_digest,
            "observed": True,
            "leafCertificateDigest": None,
            "trustBundleDigest": None,
            "publicKeyDigest": None,
            "notBefore": None,
            "notAfter": None,
            "remainingSeconds": None,
            "dnsNameCount": 0,
            "dnsNameSetDigest": canonical_digest([]),
            "requiredDnsNameSetDigest": canonical_digest(item["requiredDnsNames"]),
            "validityValid": False,
            "sansValid": False,
            "keyMatches": False,
            "chainVerified": False,
            "reasonCodes": ["CERTIFICATE_INVALID"],
        }
    not_before = inspected["notBefore"]
    not_after = inspected["notAfter"]
    current = observed_at.astimezone(timezone.utc)
    remaining = int((not_after - current).total_seconds())
    validity_valid = (
        not_before <= current and remaining >= item["minimumRemainingSeconds"]
    )
    required_dns = set(item["requiredDnsNames"])
    dns_names = set(inspected["dnsNames"])
    sans_valid = required_dns.issubset(dns_names)
    reasons = []
    if not_before > current:
        reasons.append("CERTIFICATE_NOT_YET_VALID")
    if remaining < item["minimumRemainingSeconds"]:
        reasons.append("CERTIFICATE_EXPIRES_TOO_SOON")
    if not sans_valid:
        reasons.append("CERTIFICATE_SAN_MISMATCH")
    if not inspected["keyMatches"]:
        reasons.append("CERTIFICATE_KEY_MISMATCH")
    if not inspected["chainVerified"]:
        reasons.append("CERTIFICATE_CHAIN_INVALID")
    return {
        "certificateId": item["certificateId"],
        "secretReferenceDigest": canonical_digest(reference),
        "secretResourceVersionDigest": resource_version_digest,
        "observed": True,
        "leafCertificateDigest": inspected["leafCertificateDigest"],
        "trustBundleDigest": inspected["trustBundleDigest"],
        "publicKeyDigest": inspected["publicKeyDigest"],
        "notBefore": utc_text(not_before),
        "notAfter": utc_text(not_after),
        "remainingSeconds": remaining,
        "dnsNameCount": len(dns_names),
        "dnsNameSetDigest": canonical_digest(sorted(dns_names)),
        "requiredDnsNameSetDigest": canonical_digest(item["requiredDnsNames"]),
        "validityValid": validity_valid,
        "sansValid": sans_valid,
        "keyMatches": inspected["keyMatches"],
        "chainVerified": inspected["chainVerified"],
        "reasonCodes": reasons,
    }


def validate_prerequisites(
    input_report: dict[str, Any],
    materialization: dict[str, Any],
    policy: dict[str, Any],
    observed_at: datetime,
) -> None:
    validate_input_assessment(input_report)
    validate_materialization_receipt(materialization)
    if observed_at.tzinfo is None:
        fail("sno_dependency_integrity_observation_time_invalid")
    current = observed_at.astimezone(timezone.utc)
    input_at = parse_utc(
        input_report["observedAt"],
        "sno_dependency_integrity_input_time_invalid",
    )
    materialized_at = parse_utc(
        materialization["materializedAt"],
        "sno_dependency_integrity_materialization_time_invalid",
    )
    if (
        input_report["executionMode"] != "live-read-only"
        or input_report["decision"]
        != {"status": "DEPENDENCY_INPUTS_OBSERVED", "reasonCodes": []}
        or materialization["bindings"]["inputObservationId"]
        != input_report["assessmentId"]
        or materialization["bindings"]["inputObservationDigest"]
        != input_report["reportDigest"]
        or materialization["bindings"]["candidateDigest"]
        != policy["bindings"]["candidateDigest"]
        or current < input_at
        or current < materialized_at
        or current - input_at
        > timedelta(seconds=policy["execution"]["maximumInputObservationAgeSeconds"])
        or current - materialized_at
        > timedelta(seconds=policy["execution"]["maximumMaterializationAgeSeconds"])
    ):
        fail("sno_dependency_integrity_prerequisite_not_ready")


def collect_snapshot(
    client: Path,
    kubeconfig: Path,
    openssl: Path,
    input_report: dict[str, Any],
    materialization: dict[str, Any],
    observed_at: datetime,
    run: CommandRunner = default_runner,
    inspector: Callable[..., dict[str, Any] | None] = inspect_certificate,
) -> dict[str, Any]:
    executable_file(client, "sno_dependency_integrity_tooling_invalid")
    executable_file(openssl, "sno_dependency_integrity_tooling_invalid")
    private_regular_file(kubeconfig, "sno_dependency_integrity_tooling_invalid")
    policy = load_policy()
    validate_prerequisites(input_report, materialization, policy, observed_at)
    version_raw = run_checked(
        [str(openssl.resolve()), "version"],
        run=run,
        maximum_stdout=1024,
        code="sno_dependency_integrity_openssl_invalid",
    )
    try:
        version = version_raw.decode("ascii").strip()
    except UnicodeError:
        fail("sno_dependency_integrity_openssl_invalid")
    match = OPENSSL_VERSION.match(version)
    if not match or int(match.group(1)) != policy["execution"]["opensslMajorVersion"]:
        fail("sno_dependency_integrity_openssl_invalid")
    model, execution_context = collect_model_observation(
        client, kubeconfig, policy, run
    )
    certificates = [
        collect_certificate_observation(
            client,
            kubeconfig,
            openssl,
            policy,
            item,
            observed_at,
            run,
            inspector,
        )
        for item in policy["certificates"]
    ]
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "live-cluster-read-only",
        "observedAt": utc_text(observed_at),
        "bindings": {
            **copy.deepcopy(policy["bindings"]),
            "policyId": policy["policyId"],
            "policyDigest": policy["policyDigest"],
            "inputObservationId": input_report["assessmentId"],
            "inputObservationDigest": input_report["reportDigest"],
            "materializationId": materialization["materializationId"],
            "materializationDigest": materialization["receiptDigest"],
            "opensslExecutableDigest": digest_file(
                openssl, "sno_dependency_integrity_openssl_invalid"
            ),
            "opensslVersionDigest": canonical_digest(version),
        },
        "executionContext": execution_context,
        "modelArtifact": model,
        "certificates": certificates,
    }
    validate_snapshot(snapshot)
    return snapshot


def simulated_snapshot(observed_at: datetime) -> dict[str, Any]:
    policy = load_policy()
    model = policy["modelArtifact"]
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": "simulated",
        "observedAt": utc_text(observed_at),
        "bindings": {
            **copy.deepcopy(policy["bindings"]),
            "policyId": policy["policyId"],
            "policyDigest": policy["policyDigest"],
            "inputObservationId": "sno-dependency-inputs-simulated.1",
            "inputObservationDigest": canonical_digest("simulated-input"),
            "materializationId": "sno-dependency-materialization-simulated.1",
            "materializationDigest": canonical_digest("simulated-materialization"),
            "opensslExecutableDigest": canonical_digest("simulated-openssl"),
            "opensslVersionDigest": canonical_digest("simulated-openssl-version"),
        },
        "executionContext": {
            "podUidDigest": None,
            "nodeNameDigest": None,
            "modelImage": MODEL_IMAGE,
        },
        "modelArtifact": {
            "artifactId": model["artifactId"],
            "observed": False,
            "sizeBytes": None,
            "digest": None,
            "sizeMatches": False,
            "digestMatches": False,
            "readOnly": False,
            "reasonCodes": [
                "MODEL_ARTIFACT_SIZE_MISMATCH",
                "MODEL_ARTIFACT_DIGEST_MISMATCH",
                "MODEL_ARTIFACT_WRITABLE",
            ],
        },
        "certificates": [
            {
                "certificateId": item["certificateId"],
                "secretReferenceDigest": canonical_digest(
                    CERTIFICATE_SECRET_REFERENCES[item["certificateId"]]
                ),
                "secretResourceVersionDigest": None,
                "observed": False,
                "leafCertificateDigest": None,
                "trustBundleDigest": None,
                "publicKeyDigest": None,
                "notBefore": None,
                "notAfter": None,
                "remainingSeconds": None,
                "dnsNameCount": 0,
                "dnsNameSetDigest": canonical_digest([]),
                "requiredDnsNameSetDigest": canonical_digest(item["requiredDnsNames"]),
                "validityValid": False,
                "sansValid": False,
                "keyMatches": False,
                "chainVerified": False,
                "reasonCodes": ["CERTIFICATE_INVALID"],
            }
            for item in policy["certificates"]
        ],
    }
    validate_snapshot(snapshot)
    return snapshot


def validate_model(value: Any, policy: dict[str, Any], mode: str) -> dict[str, Any]:
    item = exact_keys(
        value,
        {
            "artifactId",
            "observed",
            "sizeBytes",
            "digest",
            "sizeMatches",
            "digestMatches",
            "readOnly",
            "reasonCodes",
        },
        "sno_dependency_integrity_model_observation_invalid",
    )
    model = policy["modelArtifact"]
    reasons = item["reasonCodes"]
    if (
        item["artifactId"] != model["artifactId"]
        or type(item["observed"]) is not bool
        or item["sizeBytes"] is not None
        and (
            type(item["sizeBytes"]) is not int
            or item["sizeBytes"] < 0
            or item["sizeBytes"] > model["maximumAllowedBytes"]
        )
        or item["digest"] is not None
        and not DIGEST.fullmatch(str(item["digest"]))
        or any(
            type(item[key]) is not bool
            for key in ("sizeMatches", "digestMatches", "readOnly")
        )
        or not isinstance(reasons, list)
        or reasons != [reason for reason in MODEL_REASON_ORDER if reason in reasons]
        or len(reasons) != len(set(reasons))
    ):
        fail("sno_dependency_integrity_model_observation_invalid")
    expected_reasons = []
    if item["sizeBytes"] != model["sizeBytes"]:
        expected_reasons.append("MODEL_ARTIFACT_SIZE_MISMATCH")
    if item["digest"] != model["digest"]:
        expected_reasons.append("MODEL_ARTIFACT_DIGEST_MISMATCH")
    if not item["readOnly"]:
        expected_reasons.append("MODEL_ARTIFACT_WRITABLE")
    if (
        item["sizeMatches"] != (item["sizeBytes"] == model["sizeBytes"])
        or item["digestMatches"] != (item["digest"] == model["digest"])
        or reasons != expected_reasons
        or item["observed"] != (mode == "live-cluster-read-only")
    ):
        fail("sno_dependency_integrity_model_observation_semantics_invalid")
    return item


def validate_certificate(
    value: Any,
    policy_item: dict[str, Any],
    mode: str,
    observed_at: datetime,
) -> dict[str, Any]:
    item = exact_keys(
        value,
        {
            "certificateId",
            "secretReferenceDigest",
            "secretResourceVersionDigest",
            "observed",
            "leafCertificateDigest",
            "trustBundleDigest",
            "publicKeyDigest",
            "notBefore",
            "notAfter",
            "remainingSeconds",
            "dnsNameCount",
            "dnsNameSetDigest",
            "requiredDnsNameSetDigest",
            "validityValid",
            "sansValid",
            "keyMatches",
            "chainVerified",
            "reasonCodes",
        },
        "sno_dependency_integrity_certificate_observation_invalid",
    )
    reasons = item["reasonCodes"]
    payload_digests = (
        "leafCertificateDigest",
        "trustBundleDigest",
        "publicKeyDigest",
    )
    if (
        item["certificateId"] != policy_item["certificateId"]
        or item["secretReferenceDigest"]
        != canonical_digest(CERTIFICATE_SECRET_REFERENCES[policy_item["certificateId"]])
        or any(
            item[key] is not None and not DIGEST.fullmatch(str(item[key]))
            for key in ("secretResourceVersionDigest", *payload_digests)
        )
        or type(item["observed"]) is not bool
        or any(
            type(item[key]) is not bool
            for key in (
                "validityValid",
                "sansValid",
                "keyMatches",
                "chainVerified",
            )
        )
        or type(item["dnsNameCount"]) is not int
        or item["dnsNameCount"] < 0
        or not DIGEST.fullmatch(str(item["dnsNameSetDigest"]))
        or item["requiredDnsNameSetDigest"]
        != canonical_digest(policy_item["requiredDnsNames"])
        or not isinstance(reasons, list)
        or reasons
        != [reason for reason in CERTIFICATE_REASON_ORDER if reason in reasons]
        or len(reasons) != len(set(reasons))
    ):
        fail("sno_dependency_integrity_certificate_observation_invalid")
    if item["observed"] != (mode == "live-cluster-read-only"):
        fail("sno_dependency_integrity_certificate_observation_semantics_invalid")
    if not item["observed"] or "CERTIFICATE_INVALID" in reasons:
        if (
            reasons != ["CERTIFICATE_INVALID"]
            or (item["secretResourceVersionDigest"] is not None) != item["observed"]
            or any(item[key] is not None for key in payload_digests)
            or item["notBefore"] is not None
            or item["notAfter"] is not None
            or item["remainingSeconds"] is not None
            or any(
                item[key]
                for key in (
                    "validityValid",
                    "sansValid",
                    "keyMatches",
                    "chainVerified",
                )
            )
        ):
            fail("sno_dependency_integrity_certificate_observation_semantics_invalid")
        return item
    not_before = parse_utc(
        item["notBefore"],
        "sno_dependency_integrity_certificate_time_invalid",
    )
    not_after = parse_utc(
        item["notAfter"],
        "sno_dependency_integrity_certificate_time_invalid",
    )
    expected_remaining = int(
        (not_after - observed_at.astimezone(timezone.utc)).total_seconds()
    )
    expected_reasons = []
    if not_before > observed_at.astimezone(timezone.utc):
        expected_reasons.append("CERTIFICATE_NOT_YET_VALID")
    if expected_remaining < policy_item["minimumRemainingSeconds"]:
        expected_reasons.append("CERTIFICATE_EXPIRES_TOO_SOON")
    if not item["sansValid"]:
        expected_reasons.append("CERTIFICATE_SAN_MISMATCH")
    if not item["keyMatches"]:
        expected_reasons.append("CERTIFICATE_KEY_MISMATCH")
    if not item["chainVerified"]:
        expected_reasons.append("CERTIFICATE_CHAIN_INVALID")
    if (
        not isinstance(item["remainingSeconds"], int)
        or item["remainingSeconds"] != expected_remaining
        or not_before >= not_after
        or any(item[key] is None for key in payload_digests)
        or item["validityValid"]
        != (
            "CERTIFICATE_NOT_YET_VALID" not in reasons
            and "CERTIFICATE_EXPIRES_TOO_SOON" not in reasons
        )
        or item["sansValid"] != ("CERTIFICATE_SAN_MISMATCH" not in reasons)
        or item["keyMatches"] != ("CERTIFICATE_KEY_MISMATCH" not in reasons)
        or item["chainVerified"] != ("CERTIFICATE_CHAIN_INVALID" not in reasons)
        or reasons != expected_reasons
    ):
        fail("sno_dependency_integrity_certificate_observation_semantics_invalid")
    return item


def validate_snapshot(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "executionMode",
            "observedAt",
            "bindings",
            "executionContext",
            "modelArtifact",
            "certificates",
        },
        "sno_dependency_integrity_snapshot_invalid",
    )
    policy = load_policy()
    mode = value["executionMode"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != SNAPSHOT_KIND
        or mode not in {"simulated", "live-cluster-read-only"}
    ):
        fail("sno_dependency_integrity_snapshot_invalid")
    observed_at = parse_utc(
        value["observedAt"], "sno_dependency_integrity_snapshot_time_invalid"
    )
    bindings = exact_keys(
        value["bindings"],
        {
            *policy["bindings"].keys(),
            "policyId",
            "policyDigest",
            "inputObservationId",
            "inputObservationDigest",
            "materializationId",
            "materializationDigest",
            "opensslExecutableDigest",
            "opensslVersionDigest",
        },
        "sno_dependency_integrity_snapshot_bindings_invalid",
    )
    if (
        any(bindings[key] != expected for key, expected in policy["bindings"].items())
        or bindings["policyId"] != policy["policyId"]
        or bindings["policyDigest"] != policy["policyDigest"]
        or not ASSESSMENT_ID.fullmatch(str(bindings["inputObservationId"]))
        or not ASSESSMENT_ID.fullmatch(str(bindings["materializationId"]))
        or any(
            not DIGEST.fullmatch(str(bindings[key]))
            for key in (
                "inputObservationDigest",
                "materializationDigest",
                "opensslExecutableDigest",
                "opensslVersionDigest",
            )
        )
    ):
        fail("sno_dependency_integrity_snapshot_bindings_invalid")
    context = exact_keys(
        value["executionContext"],
        {"podUidDigest", "nodeNameDigest", "modelImage"},
        "sno_dependency_integrity_execution_context_invalid",
    )
    expected_context_present = mode == "live-cluster-read-only"
    if (
        context["modelImage"] != MODEL_IMAGE
        or (context["podUidDigest"] is not None) != expected_context_present
        or (context["nodeNameDigest"] is not None) != expected_context_present
        or any(
            context[key] is not None and not DIGEST.fullmatch(str(context[key]))
            for key in ("podUidDigest", "nodeNameDigest")
        )
    ):
        fail("sno_dependency_integrity_execution_context_invalid")
    validate_model(value["modelArtifact"], policy, mode)
    certificates = list_value(
        value["certificates"],
        "sno_dependency_integrity_certificate_observations_invalid",
    )
    if len(certificates) != len(policy["certificates"]):
        fail("sno_dependency_integrity_certificate_observations_invalid")
    for observed, expected in zip(certificates, policy["certificates"], strict=True):
        validate_certificate(observed, expected, mode, observed_at)


def decision_for(snapshot: dict[str, Any]) -> dict[str, Any]:
    reasons = []
    if snapshot["executionMode"] != "live-cluster-read-only":
        reasons.append("LIVE_CLUSTER_OBSERVATION_REQUIRED")
    reasons.extend(snapshot["modelArtifact"]["reasonCodes"])
    for item in snapshot["certificates"]:
        reasons.extend(item["reasonCodes"])
    ordered = [reason for reason in DECISION_REASON_ORDER if reason in set(reasons)]
    return {
        "status": (
            "DEPENDENCY_INTEGRITY_VERIFIED"
            if snapshot["executionMode"] == "live-cluster-read-only" and not ordered
            else "DEPENDENCY_INTEGRITY_UNRESOLVED"
        ),
        "reasonCodes": ordered,
    }


def report_controls(snapshot: dict[str, Any]) -> dict[str, Any]:
    live = snapshot["executionMode"] == "live-cluster-read-only"
    return {
        "secretValuesObserved": live,
        "secretValuesStored": False,
        "authenticationSecretValuesObserved": False,
        "certificateBytesObserved": live,
        "certificateBytesStored": False,
        "privateKeyBytesObserved": live,
        "privateKeyBytesStored": False,
        "modelArtifactReadInCluster": live,
        "modelBytesStored": False,
        "modelArtifactDigestVerified": (
            live
            and snapshot["modelArtifact"]["sizeMatches"]
            and snapshot["modelArtifact"]["digestMatches"]
        ),
        "certificateValidityVerified": (
            live and all(item["validityValid"] for item in snapshot["certificates"])
        ),
        "certificateKeyMatchVerified": (
            live and all(item["keyMatches"] for item in snapshot["certificates"])
        ),
        "certificateChainVerified": (
            live and all(item["chainVerified"] for item in snapshot["certificates"])
        ),
        "serverSideDryRunExecuted": False,
        "connectivityVerified": False,
        "cloudMutationAuthorized": False,
        "deploymentAuthorized": False,
        "campaignEligible": False,
        "allowedCertificationSlots": [],
    }


def build_assessment(
    snapshot: dict[str, Any],
    assessment_id: str,
    assessed_at: datetime | None = None,
) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if not ASSESSMENT_ID.fullmatch(assessment_id):
        fail("sno_dependency_integrity_assessment_id_invalid")
    assessed = assessed_at or datetime.now(timezone.utc)
    observed = parse_utc(
        snapshot["observedAt"],
        "sno_dependency_integrity_assessment_time_invalid",
    )
    if assessed.tzinfo is None or observed > assessed.astimezone(timezone.utc):
        fail("sno_dependency_integrity_assessment_time_invalid")
    report = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "assessmentId": assessment_id,
        "profileId": PROFILE_ID,
        "targetClass": "engineering-trial",
        "executionMode": snapshot["executionMode"],
        "observedAt": snapshot["observedAt"],
        "assessedAt": utc_text(assessed),
        "bindings": copy.deepcopy(snapshot["bindings"]),
        "executionContext": copy.deepcopy(snapshot["executionContext"]),
        "modelArtifact": copy.deepcopy(snapshot["modelArtifact"]),
        "certificates": copy.deepcopy(snapshot["certificates"]),
        "decision": decision_for(snapshot),
        "controls": report_controls(snapshot),
        "claims": copy.deepcopy(CLAIMS),
    }
    report["reportDigest"] = canonical_digest(report)
    validate_assessment(report)
    return report


def validate_assessment(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "assessmentId",
            "profileId",
            "targetClass",
            "executionMode",
            "observedAt",
            "assessedAt",
            "bindings",
            "executionContext",
            "modelArtifact",
            "certificates",
            "decision",
            "controls",
            "claims",
            "reportDigest",
        },
        "sno_dependency_integrity_report_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["kind"] != REPORT_KIND
        or not ASSESSMENT_ID.fullmatch(str(value["assessmentId"]))
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
    ):
        fail("sno_dependency_integrity_report_invalid")
    observed = parse_utc(
        value["observedAt"], "sno_dependency_integrity_report_time_invalid"
    )
    assessed = parse_utc(
        value["assessedAt"], "sno_dependency_integrity_report_time_invalid"
    )
    if observed > assessed:
        fail("sno_dependency_integrity_report_time_invalid")
    snapshot = {
        "schemaVersion": 1,
        "kind": SNAPSHOT_KIND,
        "executionMode": value["executionMode"],
        "observedAt": value["observedAt"],
        "bindings": value["bindings"],
        "executionContext": value["executionContext"],
        "modelArtifact": value["modelArtifact"],
        "certificates": value["certificates"],
    }
    validate_snapshot(snapshot)
    if (
        value["decision"] != decision_for(snapshot)
        or value["controls"] != report_controls(snapshot)
        or value["claims"] != CLAIMS
        or value["reportDigest"] != digest_without_self(value, "reportDigest")
    ):
        fail("sno_dependency_integrity_report_semantics_invalid")


def write_json_create_only(path: Path, value: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
    except OSError:
        fail("sno_dependency_integrity_output_write_failed")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-policy")
    collect = commands.add_parser("collect")
    collect.add_argument("--client", type=Path, required=True)
    collect.add_argument("--kubeconfig", type=Path, required=True)
    collect.add_argument("--openssl", type=Path, required=True)
    collect.add_argument("--input-report", type=Path, required=True)
    collect.add_argument("--materialization-receipt", type=Path, required=True)
    collect.add_argument("--assessment-id", required=True)
    collect.add_argument("--observed-at", required=True)
    collect.add_argument("--output", type=Path, required=True)
    simulate = commands.add_parser("simulate")
    simulate.add_argument("--assessment-id", required=True)
    simulate.add_argument("--at", required=True)
    simulate.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if args.command == "validate-policy":
        load_policy()
        return 0
    if args.command == "verify":
        validate_assessment(load_json(args.report))
        return 0
    if args.command == "simulate":
        at = parse_utc(args.at, "sno_dependency_integrity_simulation_time_invalid")
        report = build_assessment(
            simulated_snapshot(at),
            args.assessment_id,
            at,
        )
        write_json_create_only(args.output, report)
        return 0
    observed_at = parse_utc(
        args.observed_at,
        "sno_dependency_integrity_observation_time_invalid",
    )
    input_report = restricted_report(
        args.input_report,
        "sno_dependency_integrity_input_report_invalid",
    )
    materialization = restricted_report(
        args.materialization_receipt,
        "sno_dependency_integrity_materialization_receipt_invalid",
    )
    snapshot = collect_snapshot(
        args.client,
        args.kubeconfig,
        args.openssl,
        input_report,
        materialization,
        observed_at,
    )
    report = build_assessment(snapshot, args.assessment_id, observed_at)
    write_json_create_only(args.output, report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
