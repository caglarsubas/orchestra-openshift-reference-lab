#!/usr/bin/env python3
"""Read-only replay of a completed lab service publication observation."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.lab_service_publication import (
        CERTIFICATE_IDENTITY,
        OIDC_ISSUER,
        PACKAGE_VERSION,
        PROFILE_ID,
        RELEASE,
        ROOT,
        canonical_bytes,
        canonical_digest,
        cosign_verify,
        load_policy as load_publication_policy,
        package_metadata,
        parse_json_bytes,
        parse_time,
        registry_inspect_raw,
        source_tree_digest,
        strict_keys,
        validate_report as validate_publication_report,
        verify_oci_image,
        write_create_only,
    )
except ModuleNotFoundError:
    from lab_service_publication import (
        CERTIFICATE_IDENTITY,
        OIDC_ISSUER,
        PACKAGE_VERSION,
        PROFILE_ID,
        RELEASE,
        ROOT,
        canonical_bytes,
        canonical_digest,
        cosign_verify,
        load_policy as load_publication_policy,
        package_metadata,
        parse_json_bytes,
        parse_time,
        registry_inspect_raw,
        source_tree_digest,
        strict_keys,
        validate_report as validate_publication_report,
        verify_oci_image,
        write_create_only,
    )


POLICY_PATH = ROOT / "config" / "lab-service-publication-replay.lock.json"
SCHEMA_PATH = ROOT / "schemas" / "lab-service-publication-replay-v1.schema.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "lab-service-publication-replay.yml"
EXPECTED_POLICY_DIGEST = (
    "sha256:0607daa157b5a0a49284305d8216d6ecf98019eb25a5d48032c26bc09e050317"
)
POLICY_KIND = "orchestra.reference-lab.lab-service-publication-replay-policy.v1"
REPORT_KIND = "orchestra.reference-lab.lab-service-publication-replay.v1"
REPOSITORY_ID = 1307302690
REPOSITORY = "caglarsubas/orchestra-openshift-reference-lab"
PUBLICATION_POLICY_DIGEST = (
    "sha256:61e1af0f3c2874df6ec8077e3ac03f2a036197e0998d224a7cafea8c5130b8e1"
)
PUBLICATION_WORKFLOW_PATH = ".github/workflows/lab-service-publication.yml"
WORKFLOW_RELATIVE_PATH = ".github/workflows/lab-service-publication-replay.yml"
WORKFLOW_REF = "refs/heads/main"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
MAXIMUM_AGE = timedelta(days=14)


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def expected_services() -> list[dict[str, str]]:
    return [
        {
            "id": "release-validation-receiver",
            "sourcePath": "services/release-validation-receiver",
            "packageName": "orchestra-reference-lab-release-receiver",
            "imageRepository": (
                "ghcr.io/caglarsubas/orchestra-lab-release-validation-receiver"
            ),
        },
        {
            "id": "synthetic-tenant-kit",
            "sourcePath": "services/synthetic-tenant-kit",
            "packageName": "orchestra-reference-lab-synthetic-tenant-kit",
            "imageRepository": (
                "ghcr.io/caglarsubas/orchestra-lab-synthetic-tenant-kit"
            ),
        },
    ]


def expected_claims() -> dict[str, bool]:
    return {
        "separateWorkflowReplay": True,
        "sourceArtifactsPublished": True,
        "sourceTreeReplayed": True,
        "registryDigestReplayed": True,
        "embeddedSbomReplayed": True,
        "provenanceReplayed": True,
        "keylessSignatureReplayed": True,
        "independentHumanReview": False,
        "signedVerificationStatement": False,
        "certificationRiskScan": False,
        "harborMirrored": False,
        "rhtasAdmissionVerified": False,
        "gitOpsReferenced": False,
        "deployed": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }


def expected_policy(schema_digest: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": POLICY_KIND,
        "profileId": PROFILE_ID,
        "repository": {
            "id": REPOSITORY_ID,
            "fullName": REPOSITORY,
            "defaultBranch": "main",
        },
        "publication": {
            "policyDigest": PUBLICATION_POLICY_DIGEST,
            "workflowPath": PUBLICATION_WORKFLOW_PATH,
            "artifactNameTemplate": ("lab-service-publication-observation-{runId}-1"),
            "maximumAgeDays": 14,
        },
        "workflow": {
            "path": WORKFLOW_RELATIVE_PATH,
            "ref": WORKFLOW_REF,
            "requiredRunAttempt": 1,
            "permissions": {
                "actions": "read",
                "contents": "read",
                "packages": "read",
            },
            "idTokenPermission": False,
            "registryMutation": False,
            "imageSigning": False,
        },
        "services": expected_services(),
        "observation": {
            "schema": "schemas/lab-service-publication-replay-v1.schema.json",
            "schemaDigest": schema_digest,
        },
        "requiredClaims": expected_claims(),
    }


def read_json(path: Path, code: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"{code}_read_failed") from error
    return raw, parse_json_bytes(raw, code)


def validate_schema(schema: dict[str, Any]) -> None:
    def require_strict_objects(value: Any, path: str = "$") -> None:
        if isinstance(value, list):
            for index, child in enumerate(value):
                require_strict_objects(child, f"{path}/{index}")
            return
        if not isinstance(value, dict):
            return
        if (
            value.get("type") == "object"
            and value.get("additionalProperties") is not False
        ):
            fail(f"lab_service_publication_replay_schema_not_strict:{path}")
        for key, child in value.items():
            require_strict_objects(child, f"{path}/{key}")

    strict_keys(
        schema,
        {
            "$schema",
            "$id",
            "additionalProperties",
            "properties",
            "required",
            "type",
        },
        "lab_service_publication_replay_schema_keys_invalid",
    )
    if (
        schema["type"] != "object"
        or schema["additionalProperties"] is not False
        or schema["properties"].get("kind", {}).get("const") != REPORT_KIND
        or schema["properties"].get("profileId", {}).get("const") != PROFILE_ID
    ):
        fail("lab_service_publication_replay_schema_identity_invalid")
    require_strict_objects(schema)


def load_policy() -> tuple[dict[str, Any], str]:
    _, schema = read_json(SCHEMA_PATH, "lab_service_publication_replay_schema")
    validate_schema(schema)
    schema_digest = canonical_digest(schema)
    _, policy = read_json(POLICY_PATH, "lab_service_publication_replay_policy")
    if policy != expected_policy(schema_digest):
        fail("lab_service_publication_replay_policy_semantics_invalid")
    policy_digest = canonical_digest(policy)
    if policy_digest != EXPECTED_POLICY_DIGEST:
        fail("lab_service_publication_replay_policy_digest_invalid")
    publication_policy, publication_digest = load_publication_policy()
    if publication_digest != PUBLICATION_POLICY_DIGEST or publication_policy[
        "services"
    ] != [
        {
            **service,
            "containerfile": (f"{service['sourcePath']}/Containerfile"),
        }
        for service in policy["services"]
    ]:
        fail("lab_service_publication_replay_publication_policy_mismatch")
    return policy, policy_digest


def validate_declared_implementation(policy: dict[str, Any]) -> None:
    try:
        content = WORKFLOW_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError("lab_service_publication_replay_workflow_missing") from error
    required = (
        "workflow_dispatch:",
        "expected_main_sha:",
        "publication_run_id:",
        "expected_publication_revision:",
        "expected_observation_digest:",
        "actions: read",
        "contents: read",
        "packages: read",
        "if: github.ref == 'refs/heads/main'",
        '[[ "$GITHUB_RUN_ATTEMPT" == "1" ]]',
        '[[ "$EXPECTED_MAIN_SHA" == "$GITHUB_SHA" ]]',
        "fetch-depth: 0",
        "registry: ghcr.io",
        "gh run download",
        "lab_service_publication_replay.py project-origin",
        '[[ "${#artifact_entries[@]}" -eq 1 ]]',
        '[[ -f "$observation" && ! -L "$observation" ]]',
        '[[ "$(wc -c < "$observation")" -le 65536 ]]',
        "lab_service_publication_replay.py replay",
        "lab-service-publication-replay-",
        policy["services"][0]["imageRepository"],
        policy["services"][1]["imageRepository"],
    )
    if any(fragment not in content for fragment in required):
        fail("lab_service_publication_replay_workflow_contract_invalid")
    forbidden = (
        "id-token:",
        "packages: write",
        "docker/build-push-action",
        "docker build --",
        "docker buildx build",
        "docker push",
        "cosign sign",
        "push: true",
        "--method ",
        "-x post",
        "-x put",
        "-x patch",
        "-x delete",
        "kubectl ",
        "oc ",
        "helm ",
        "argocd ",
        "harbor",
        "artifactregistry",
        "jq ",
    )
    if any(fragment in content.lower() for fragment in forbidden):
        fail("lab_service_publication_replay_workflow_authority_invalid")


def require_exact_checkout(revision: str) -> None:
    if not REVISION.fullmatch(revision):
        fail("lab_service_publication_replay_revision_invalid")
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("lab_service_publication_replay_git_head_failed") from error
    if head != revision:
        fail("lab_service_publication_replay_checkout_mismatch")


def validate_projected_origin(
    origin: dict[str, Any],
    *,
    expected_run_id: str,
    expected_revision: str,
) -> None:
    strict_keys(
        origin,
        {
            "id",
            "runAttempt",
            "event",
            "status",
            "conclusion",
            "headSha",
            "headBranch",
            "path",
            "repository",
            "artifact",
        },
        "lab_service_publication_replay_origin_shape_invalid",
    )
    repository = strict_keys(
        origin["repository"],
        {"id", "fullName"},
        "lab_service_publication_replay_origin_repository_invalid",
    )
    artifact = strict_keys(
        origin["artifact"],
        {"id", "name", "sizeInBytes", "expired"},
        "lab_service_publication_replay_origin_artifact_invalid",
    )
    expected_artifact = f"lab-service-publication-observation-{expected_run_id}-1"
    if (
        not POSITIVE_INTEGER.fullmatch(expected_run_id)
        or not REVISION.fullmatch(expected_revision)
        or type(origin["id"]) is not int
        or type(origin["runAttempt"]) is not int
        or origin["id"] != int(expected_run_id)
        or origin["runAttempt"] != 1
        or origin["event"] != "workflow_dispatch"
        or origin["status"] != "completed"
        or origin["conclusion"] != "success"
        or origin["headSha"] != expected_revision
        or origin["headBranch"] != "main"
        or origin["path"] != PUBLICATION_WORKFLOW_PATH
        or repository != {"id": REPOSITORY_ID, "fullName": REPOSITORY}
        or not isinstance(artifact["id"], int)
        or isinstance(artifact["id"], bool)
        or artifact["id"] <= 0
        or artifact["name"] != expected_artifact
        or not isinstance(artifact["sizeInBytes"], int)
        or isinstance(artifact["sizeInBytes"], bool)
        or not 1 <= artifact["sizeInBytes"] <= 100_000
        or artifact["expired"] is not False
    ):
        fail("lab_service_publication_replay_origin_invalid")


def validate_origin(
    origin: dict[str, Any],
    publication: dict[str, Any],
    *,
    expected_run_id: str,
    expected_revision: str,
) -> None:
    validate_projected_origin(
        origin,
        expected_run_id=expected_run_id,
        expected_revision=expected_revision,
    )
    if (
        publication["workflow"]["runId"] != expected_run_id
        or type(publication["workflow"]["runAttempt"]) is not int
        or publication["workflow"]["runAttempt"] != 1
        or publication["repository"]["revision"] != expected_revision
    ):
        fail("lab_service_publication_replay_origin_invalid")


def project_origin(
    *,
    run_path: Path,
    inventory_path: Path,
    expected_run_id: str,
    expected_revision: str,
) -> dict[str, Any]:
    _, run = read_json(run_path, "lab_service_publication_replay_run")
    _, inventory = read_json(
        inventory_path, "lab_service_publication_replay_artifact_inventory"
    )
    artifacts = inventory.get("artifacts")
    expected_artifact = f"lab-service-publication-observation-{expected_run_id}-1"
    if not isinstance(artifacts, list):
        fail("lab_service_publication_replay_artifact_inventory_invalid")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("name") == expected_artifact
    ]
    if len(matches) != 1 or not isinstance(run.get("repository"), dict):
        fail("lab_service_publication_replay_artifact_inventory_invalid")
    artifact = matches[0]
    repository = run["repository"]
    origin = {
        "id": run.get("id"),
        "runAttempt": run.get("run_attempt"),
        "event": run.get("event"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "headSha": run.get("head_sha"),
        "headBranch": run.get("head_branch"),
        "path": run.get("path"),
        "repository": {
            "id": repository.get("id"),
            "fullName": repository.get("full_name"),
        },
        "artifact": {
            "id": artifact.get("id"),
            "name": artifact.get("name"),
            "sizeInBytes": artifact.get("size_in_bytes"),
            "expired": artifact.get("expired"),
        },
    }
    validate_projected_origin(
        origin,
        expected_run_id=expected_run_id,
        expected_revision=expected_revision,
    )
    return origin


def validate_report(
    report: dict[str, Any],
    policy: dict[str, Any],
    policy_digest: str,
) -> None:
    strict_keys(
        report,
        {
            "schemaVersion",
            "kind",
            "verificationId",
            "profileId",
            "targetClass",
            "executionMode",
            "policyDigest",
            "publication",
            "verifier",
            "services",
            "claims",
        },
        "lab_service_publication_replay_report_shape_invalid",
    )
    publication = strict_keys(
        report["publication"],
        {
            "observationId",
            "observationDigest",
            "workflowRunId",
            "artifactId",
            "artifactName",
            "repositoryRevision",
            "release",
            "publishedAt",
        },
        "lab_service_publication_replay_report_publication_invalid",
    )
    verifier = strict_keys(
        report["verifier"],
        {
            "repositoryRevision",
            "workflowPath",
            "ref",
            "runId",
            "runAttempt",
            "actorId",
            "verifiedAt",
        },
        "lab_service_publication_replay_report_verifier_invalid",
    )
    if (
        type(report["schemaVersion"]) is not int
        or report["schemaVersion"] != 1
        or report["kind"] != REPORT_KIND
        or report["profileId"] != PROFILE_ID
        or report["targetClass"] != "vendor-reference-lab"
        or report["executionMode"] != "live"
        or report["policyDigest"] != policy_digest
        or report["verificationId"]
        != f"lab-services-publication-replay-{verifier['runId']}.1"
        or not isinstance(verifier["runId"], str)
        or not POSITIVE_INTEGER.fullmatch(verifier["runId"])
        or type(verifier["runAttempt"]) is not int
        or not isinstance(verifier["actorId"], str)
        or not POSITIVE_INTEGER.fullmatch(verifier["actorId"])
        or not isinstance(verifier["repositoryRevision"], str)
        or not REVISION.fullmatch(verifier["repositoryRevision"])
        or verifier["workflowPath"] != WORKFLOW_RELATIVE_PATH
        or verifier["ref"] != WORKFLOW_REF
        or verifier["runAttempt"] != 1
        or not isinstance(publication["observationDigest"], str)
        or not DIGEST.fullmatch(publication["observationDigest"])
        or not isinstance(publication["workflowRunId"], str)
        or not POSITIVE_INTEGER.fullmatch(publication["workflowRunId"])
        or not isinstance(publication["artifactId"], str)
        or not POSITIVE_INTEGER.fullmatch(publication["artifactId"])
        or not isinstance(publication["repositoryRevision"], str)
        or not REVISION.fullmatch(publication["repositoryRevision"])
        or publication["observationId"]
        != f"lab-services-publication-{publication['workflowRunId']}.1"
        or publication["artifactName"]
        != (f"lab-service-publication-observation-{publication['workflowRunId']}-1")
        or not isinstance(publication["release"], str)
        or not RELEASE.fullmatch(publication["release"])
        or not isinstance(report["claims"], dict)
        or not all(type(value) is bool for value in report["claims"].values())
        or report["claims"] != expected_claims()
    ):
        fail("lab_service_publication_replay_report_identity_invalid")
    published_at = parse_time(
        publication["publishedAt"],
        "lab_service_publication_replay_report_published_at_invalid",
    )
    verified_at = parse_time(
        verifier["verifiedAt"],
        "lab_service_publication_replay_report_verified_at_invalid",
    )
    if verified_at < published_at or verified_at - published_at > MAXIMUM_AGE:
        fail("lab_service_publication_replay_report_age_invalid")

    services = report["services"]
    if not isinstance(services, list) or len(services) != 2:
        fail("lab_service_publication_replay_report_services_invalid")
    for actual, expected in zip(services, policy["services"], strict=True):
        strict_keys(
            actual,
            {
                "id",
                "sourceTreeDigest",
                "imageRepository",
                "imageDigest",
                "imageManifestDigest",
                "attestationManifestDigest",
                "sbomDigest",
                "provenanceDigest",
                "signatureSubject",
            },
            "lab_service_publication_replay_report_service_shape_invalid",
        )
        if (
            actual["id"] != expected["id"]
            or actual["imageRepository"] != expected["imageRepository"]
            or not all(
                DIGEST.fullmatch(str(actual[field]))
                for field in (
                    "sourceTreeDigest",
                    "imageDigest",
                    "imageManifestDigest",
                    "attestationManifestDigest",
                    "sbomDigest",
                    "provenanceDigest",
                )
            )
            or actual["signatureSubject"]
            != f"{expected['imageRepository']}@{actual['imageDigest']}"
        ):
            fail(
                "lab_service_publication_replay_report_service_invalid:"
                f"{expected['id']}"
            )
    if (
        len({service["sourceTreeDigest"] for service in services}) != 2
        or len({service["imageDigest"] for service in services}) != 2
        or len({service["imageManifestDigest"] for service in services}) != 2
    ):
        fail("lab_service_publication_replay_report_service_substitution")


def build_replay_report(
    *,
    publication_path: Path,
    origin_path: Path,
    expected_observation_digest: str,
    expected_publication_run_id: str,
    expected_publication_revision: str,
    verifier_revision: str,
    verifier_run_id: str,
    verifier_run_attempt: int,
    verifier_actor_id: str,
    verified_at: str,
    inspect_raw=registry_inspect_raw,
    verify_signature=cosign_verify,
) -> dict[str, Any]:
    policy, policy_digest = load_policy()
    validate_declared_implementation(policy)
    require_exact_checkout(verifier_revision)
    if (
        not DIGEST.fullmatch(expected_observation_digest)
        or not POSITIVE_INTEGER.fullmatch(expected_publication_run_id)
        or not REVISION.fullmatch(expected_publication_revision)
        or not POSITIVE_INTEGER.fullmatch(verifier_run_id)
        or type(verifier_run_attempt) is not int
        or verifier_run_attempt != 1
        or not POSITIVE_INTEGER.fullmatch(verifier_actor_id)
    ):
        fail("lab_service_publication_replay_invocation_invalid")
    verified_time = parse_time(
        verified_at, "lab_service_publication_replay_verified_at_invalid"
    )

    publication_raw, publication = read_json(
        publication_path, "lab_service_publication_replay_publication"
    )
    publication_policy, publication_policy_digest = load_publication_policy()
    validate_publication_report(
        publication,
        publication_policy,
        publication_policy_digest,
        assessed_at=verified_time,
    )
    if (
        publication_raw != canonical_bytes(publication)
        or canonical_digest(publication) != expected_observation_digest
        or publication["policyDigest"] != PUBLICATION_POLICY_DIGEST
    ):
        fail("lab_service_publication_replay_observation_digest_invalid")
    _, origin = read_json(origin_path, "lab_service_publication_replay_origin")
    validate_origin(
        origin,
        publication,
        expected_run_id=expected_publication_run_id,
        expected_revision=expected_publication_revision,
    )
    published_time = parse_time(
        publication["publishedAt"],
        "lab_service_publication_replay_published_at_invalid",
    )
    if verified_time < published_time or verified_time - published_time > MAXIMUM_AGE:
        fail("lab_service_publication_replay_observation_stale")

    services: list[dict[str, Any]] = []
    for actual, expected in zip(
        publication["services"], policy["services"], strict=True
    ):
        source_digest = source_tree_digest(
            expected_publication_revision, expected["sourcePath"]
        )
        package = package_metadata(
            expected_publication_revision,
            {
                **expected,
                "containerfile": f"{expected['sourcePath']}/Containerfile",
            },
        )
        if (
            actual["id"] != expected["id"]
            or actual["sourcePath"] != expected["sourcePath"]
            or actual["sourceTreeDigest"] != source_digest
            or actual["packageName"] != package["name"]
            or actual["packageVersion"] != package["version"]
            or package["version"] != PACKAGE_VERSION
        ):
            fail(f"lab_service_publication_replay_source_mismatch:{expected['id']}")
        image = actual["image"]
        replay = verify_oci_image(
            expected["imageRepository"],
            image["tag"],
            image["digest"],
            inspect_raw=inspect_raw,
        )
        expected_replay = {
            "imageManifestDigest": image["imageManifestDigest"],
            "attestationManifestDigest": image["attestationManifestDigest"],
            "sbomDigest": actual["attestations"]["sbomDigest"],
            "provenanceDigest": actual["attestations"]["provenanceDigest"],
        }
        if replay != expected_replay:
            fail(f"lab_service_publication_replay_registry_mismatch:{expected['id']}")
        signature = actual["signature"]
        if (
            signature["certificateIdentity"] != CERTIFICATE_IDENTITY
            or signature["issuer"] != OIDC_ISSUER
            or signature["subject"]
            != f"{expected['imageRepository']}@{image['digest']}"
        ):
            fail(
                "lab_service_publication_replay_signature_identity_mismatch:"
                f"{expected['id']}"
            )
        verify_signature(
            signature["subject"],
            signature["certificateIdentity"],
            signature["issuer"],
        )
        services.append(
            {
                "id": expected["id"],
                "sourceTreeDigest": source_digest,
                "imageRepository": expected["imageRepository"],
                "imageDigest": image["digest"],
                "imageManifestDigest": replay["imageManifestDigest"],
                "attestationManifestDigest": replay["attestationManifestDigest"],
                "sbomDigest": replay["sbomDigest"],
                "provenanceDigest": replay["provenanceDigest"],
                "signatureSubject": signature["subject"],
            }
        )

    report = {
        "schemaVersion": 1,
        "kind": REPORT_KIND,
        "verificationId": (f"lab-services-publication-replay-{verifier_run_id}.1"),
        "profileId": PROFILE_ID,
        "targetClass": "vendor-reference-lab",
        "executionMode": "live",
        "policyDigest": policy_digest,
        "publication": {
            "observationId": publication["observationId"],
            "observationDigest": expected_observation_digest,
            "workflowRunId": expected_publication_run_id,
            "artifactId": str(origin["artifact"]["id"]),
            "artifactName": origin["artifact"]["name"],
            "repositoryRevision": expected_publication_revision,
            "release": publication["release"]["name"],
            "publishedAt": publication["publishedAt"],
        },
        "verifier": {
            "repositoryRevision": verifier_revision,
            "workflowPath": WORKFLOW_RELATIVE_PATH,
            "ref": WORKFLOW_REF,
            "runId": verifier_run_id,
            "runAttempt": verifier_run_attempt,
            "actorId": verifier_actor_id,
            "verifiedAt": verified_at,
        },
        "services": services,
        "claims": expected_claims(),
    }
    validate_report(report, policy, policy_digest)
    return report


def command_validate_policy() -> None:
    policy, digest = load_policy()
    validate_declared_implementation(policy)
    print(f"lab_service_publication_replay_policy_valid digest={digest}")


def command_project_origin(args: argparse.Namespace) -> None:
    origin = project_origin(
        run_path=args.run.resolve(),
        inventory_path=args.inventory.resolve(),
        expected_run_id=args.expected_publication_run_id,
        expected_revision=args.expected_publication_revision,
    )
    write_create_only(args.output.resolve(), origin)
    print(
        "lab_service_publication_replay_origin_projected "
        f"runId={origin['id']} artifactId={origin['artifact']['id']}"
    )


def command_replay(args: argparse.Namespace) -> None:
    report = build_replay_report(
        publication_path=args.publication.resolve(),
        origin_path=args.origin.resolve(),
        expected_observation_digest=args.expected_observation_digest,
        expected_publication_run_id=args.expected_publication_run_id,
        expected_publication_revision=args.expected_publication_revision,
        verifier_revision=args.verifier_revision,
        verifier_run_id=args.verifier_run_id,
        verifier_run_attempt=args.verifier_run_attempt,
        verifier_actor_id=args.verifier_actor_id,
        verified_at=args.verified_at,
    )
    write_create_only(args.output.resolve(), report)
    print(
        "lab_service_publication_replay_complete "
        f"verificationId={report['verificationId']} "
        f"digest={canonical_digest(report)}"
    )


def command_verify(args: argparse.Namespace) -> None:
    policy, policy_digest = load_policy()
    raw, report = read_json(
        args.report.resolve(), "lab_service_publication_replay_report"
    )
    validate_report(report, policy, policy_digest)
    if raw != canonical_bytes(report):
        fail("lab_service_publication_replay_report_not_canonical")
    print(
        "lab_service_publication_replay_valid "
        f"verificationId={report['verificationId']} "
        f"digest={canonical_digest(report)}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-policy")

    project = commands.add_parser("project-origin")
    project.add_argument("--run", type=Path, required=True)
    project.add_argument("--inventory", type=Path, required=True)
    project.add_argument("--expected-publication-run-id", required=True)
    project.add_argument("--expected-publication-revision", required=True)
    project.add_argument("--output", type=Path, required=True)

    replay = commands.add_parser("replay")
    replay.add_argument("--publication", type=Path, required=True)
    replay.add_argument("--origin", type=Path, required=True)
    replay.add_argument("--expected-observation-digest", required=True)
    replay.add_argument("--expected-publication-run-id", required=True)
    replay.add_argument("--expected-publication-revision", required=True)
    replay.add_argument("--verifier-revision", required=True)
    replay.add_argument("--verifier-run-id", required=True)
    replay.add_argument("--verifier-run-attempt", type=int, required=True)
    replay.add_argument("--verifier-actor-id", required=True)
    replay.add_argument("--verified-at", required=True)
    replay.add_argument("--output", type=Path, required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("--report", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "validate-policy":
        command_validate_policy()
    elif args.command == "project-origin":
        command_project_origin(args)
    elif args.command == "replay":
        command_replay(args)
    else:
        command_verify(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
