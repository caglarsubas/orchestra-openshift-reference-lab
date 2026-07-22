#!/usr/bin/env python3
"""Validate one payload-free dependency-risk raw-custody statement."""

from __future__ import annotations

import argparse
import re
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.validate_repository import DIGEST, ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from validate_repository import DIGEST, ROOT, canonical_digest, load_json


AUTHORITY_PATH = ROOT / "config" / "dependency-risk-collection-execution.lock.json"
EVIDENCE_ID = re.compile(r"^orchestra-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def strict_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(code)
    return value


def require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(code)
    return value


def validate_statement(value: dict[str, Any], authority: dict[str, Any]) -> None:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "targetClass",
            "executionMode",
            "evidenceId",
            "bindings",
            "collection",
            "storage",
            "publisher",
            "claims",
        },
        "dependency_risk_custody_keys_invalid",
    )
    evidence_id = value["evidenceId"]
    if (
        value["schemaVersion"] != 1
        or value["kind"] != "orchestra.dependency-risk.raw-custody-statement.v1"
        or value["profileId"] != "orchestra-ocp-4.20-amd64-v1"
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or not isinstance(evidence_id, str)
        or not EVIDENCE_ID.fullmatch(evidence_id)
    ):
        fail("dependency_risk_custody_identity_invalid")

    bindings = strict_keys(
        value["bindings"],
        {
            "topologyDigest",
            "dependencyAdmissionDigest",
            "releaseSetDigest",
            "sourceVerificationDigest",
            "riskPolicyDigest",
            "preflightAuthorityDigest",
            "collectionExecutionAuthorityDigest",
            "collectorScriptDigest",
            "publisherScriptDigest",
            "rawCustodySchemaDigest",
        },
        "dependency_risk_custody_bindings_invalid",
    )
    if bindings != {
        "topologyDigest": authority["bindings"]["topologyDigest"],
        "dependencyAdmissionDigest": authority["bindings"]["dependencyAdmissionDigest"],
        "releaseSetDigest": authority["bindings"]["releaseSetDigest"],
        "sourceVerificationDigest": authority["bindings"]["sourceVerificationDigest"],
        "riskPolicyDigest": authority["bindings"]["riskPolicyDigest"],
        "preflightAuthorityDigest": authority["bindings"]["preflightAuthorityDigest"],
        "collectionExecutionAuthorityDigest": canonical_digest(authority),
        "collectorScriptDigest": authority["bindings"]["collectorScriptDigest"],
        "publisherScriptDigest": authority["bindings"]["publisherScriptDigest"],
        "rawCustodySchemaDigest": authority["bindings"]["rawCustodySchemaDigest"],
    }:
        fail("dependency_risk_custody_bindings_invalid")

    collection = strict_keys(
        value["collection"],
        {
            "manifestFile",
            "manifestDigest",
            "collectionAttestationDigest",
            "collectionSignatureBundleDigest",
            "rawArchiveObject",
            "rawArchiveDigest",
        },
        "dependency_risk_custody_collection_invalid",
    )
    if (
        collection["manifestFile"] != "dependency-risk-scan-manifest.json"
        or collection["rawArchiveObject"] != "dependency-risk-raw-collection.tar.gz"
    ):
        fail("dependency_risk_custody_collection_invalid")
    for key in (
        "manifestDigest",
        "collectionAttestationDigest",
        "collectionSignatureBundleDigest",
        "rawArchiveDigest",
    ):
        require_digest(collection[key], "dependency_risk_custody_collection_invalid")

    storage = strict_keys(
        value["storage"],
        {
            "bucket",
            "prefix",
            "signingPublicKeyObject",
            "custodyStatementObject",
            "custodySignatureBundleObject",
            "createOnlyGenerationPrecondition",
            "objectGenerationRecorded",
            "independentCustodyVerificationRequired",
        },
        "dependency_risk_custody_storage_invalid",
    )
    if (
        storage
        != {
            "bucket": storage["bucket"],
            "prefix": (f"dependency-risk/v1/orchestra-ocp-4.20-amd64-v1/{evidence_id}"),
            "signingPublicKeyObject": "dependency-risk-raw-custody-public-key.pem",
            "custodyStatementObject": "dependency-risk-raw-custody-statement.json",
            "custodySignatureBundleObject": (
                "dependency-risk-raw-custody-signature.sigstore.json"
            ),
            "createOnlyGenerationPrecondition": 0,
            "objectGenerationRecorded": False,
            "independentCustodyVerificationRequired": True,
        }
        or not isinstance(storage["bucket"], str)
        or not BUCKET.fullmatch(storage["bucket"])
    ):
        fail("dependency_risk_custody_storage_invalid")

    publisher = strict_keys(
        value["publisher"],
        {
            "executionClass",
            "scriptDigest",
            "actorIdentityDigest",
            "signingPublicKeyDigest",
            "publishedAt",
        },
        "dependency_risk_custody_publisher_invalid",
    )
    for key in ("scriptDigest", "actorIdentityDigest", "signingPublicKeyDigest"):
        require_digest(publisher[key], "dependency_risk_custody_publisher_invalid")
    if (
        publisher["executionClass"] != "signed-certification-runner"
        or publisher["scriptDigest"] != authority["bindings"]["publisherScriptDigest"]
        or not isinstance(publisher["publishedAt"], str)
        or not publisher["publishedAt"].endswith("Z")
    ):
        fail("dependency_risk_custody_publisher_invalid")
    try:
        datetime.fromisoformat(publisher["publishedAt"].replace("Z", "+00:00"))
    except ValueError:
        fail("dependency_risk_custody_publisher_invalid")

    if value["claims"] != {
        "rawCollectionUploaded": True,
        "rawArtifactsRestricted": True,
        "custodyVerified": False,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("dependency_risk_custody_claim_invalid")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--statement", type=Path, required=True)
    args = parser.parse_args(argv)
    authority = load_json(AUTHORITY_PATH)
    statement = load_json(args.statement.resolve())
    validate_statement(statement, authority)
    print(
        "dependency_risk_raw_custody_statement_valid "
        f"evidenceId={statement['evidenceId']} custodyVerified=false "
        "campaignEvidence=false referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
