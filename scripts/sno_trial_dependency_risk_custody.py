#!/usr/bin/env python3
"""Validate SNO dependency-risk raw custody and independent verification."""

from __future__ import annotations

import argparse
import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

try:
    from scripts.dependency_risk_collection_execution import (
        load_contract as load_collection_authority,
        validate_authority as validate_collection_authority,
    )
    from scripts.dependency_risk_custody_verification import (
        load_contract as load_custody_authority,
        validate_authority as validate_custody_authority,
    )
    from scripts.sno_trial_dependency_risk import (
        load_inputs as load_risk_inputs,
        validate_policy as validate_risk_policy,
    )
    from scripts.validate_repository import ROOT, canonical_digest, load_json
except ModuleNotFoundError:
    from dependency_risk_collection_execution import (
        load_contract as load_collection_authority,
        validate_authority as validate_collection_authority,
    )
    from dependency_risk_custody_verification import (
        load_contract as load_custody_authority,
        validate_authority as validate_custody_authority,
    )
    from sno_trial_dependency_risk import (
        load_inputs as load_risk_inputs,
        validate_policy as validate_risk_policy,
    )
    from validate_repository import ROOT, canonical_digest, load_json


POLICY_PATH = (
    ROOT / "config" / "sno-trial-dependency-risk-custody-policy.lock.json"
)
RAW_CUSTODY_SCHEMA_PATH = (
    ROOT / "schemas" / "sno-trial-dependency-risk-raw-custody-statement-v1.schema.json"
)
VERIFICATION_SCHEMA_PATH = (
    ROOT / "schemas" / "sno-trial-dependency-risk-custody-verification-v1.schema.json"
)
PUBLISHER_PATH = ROOT / "scripts" / "publish_sno_trial_dependency_risk_collection.sh"
VERIFIER_PATH = ROOT / "scripts" / "verify_sno_trial_dependency_risk_raw_custody.py"
VERIFICATION_SCRIPT_PATH = (
    ROOT / "scripts" / "verify_and_publish_sno_trial_dependency_risk_custody.sh"
)
REPORT_VALIDATOR_PATH = (
    ROOT / "scripts" / "validate_sno_trial_dependency_risk_custody_report.py"
)
PROFILE_ID = "orchestra-ocp-sno-trial-amd64-v1"
EVIDENCE_ID = re.compile(
    r"^orchestra-sno-trial-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$"
)
VERIFICATION_ID = re.compile(
    r"^orchestra-sno-trial-dependency-risk-custody-verification-"
    r"[a-z0-9][a-z0-9.-]+$"
)
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
COLLECTION_KEY = re.compile(
    r"^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/"
    r"europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/"
    r"dependency-risk-collection-signing/cryptoKeyVersions/[1-9][0-9]*$"
)
VERIFICATION_KEY = re.compile(
    r"^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/"
    r"europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/"
    r"dependency-risk-custody-verification-signing/cryptoKeyVersions/"
    r"[1-9][0-9]*$"
)
EXPECTED_POLICY_DIGEST = (
    "sha256:3a8923e05eaf7411557993ad6ac58a8f5ae4cd39849adfee162d7544a52927dc"
)
RAW_OBJECTS = {
    "sno-dependency-risk-raw-collection.tar.gz": "raw-archive",
    "sno-dependency-risk-raw-custody-public-key.pem": (
        "collection-signing-public-key"
    ),
    "sno-dependency-risk-raw-custody-statement.json": "custody-statement",
    "sno-dependency-risk-raw-custody-signature.sigstore.json": (
        "completion-marker"
    ),
}


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


def blob_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def parse_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(code)
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        fail(code)
    return parsed


def _expected_bindings() -> tuple[dict[str, str], dict[str, Any]]:
    artifacts, release_set, risk_policy = load_risk_inputs()
    risk_policy_digest = validate_risk_policy(risk_policy, artifacts, release_set)
    collection_contract, collection_release, collection_risk = (
        load_collection_authority()
    )
    collection_digest = validate_collection_authority(
        collection_contract,
        collection_release,
        collection_risk,
    )
    custody_contract, custody_release, custody_risk = load_custody_authority()
    custody_digest = validate_custody_authority(
        custody_contract,
        custody_release,
        custody_risk,
    )
    bindings = {
        "artifactSetDigest": artifacts["artifactSetDigest"],
        "releaseSetDigest": canonical_digest(release_set),
        "riskPolicyDigest": risk_policy_digest,
        "collectionAuthorityDigest": collection_digest,
        "custodyAuthorityDigest": custody_digest,
        "rawCustodySchemaDigest": blob_digest(RAW_CUSTODY_SCHEMA_PATH.read_bytes()),
        "custodyVerificationSchemaDigest": blob_digest(
            VERIFICATION_SCHEMA_PATH.read_bytes()
        ),
        "publisherScriptDigest": blob_digest(PUBLISHER_PATH.read_bytes()),
        "verifierModuleDigest": blob_digest(VERIFIER_PATH.read_bytes()),
        "verificationScriptDigest": blob_digest(
            VERIFICATION_SCRIPT_PATH.read_bytes()
        ),
        "reportValidatorDigest": blob_digest(REPORT_VALIDATOR_PATH.read_bytes()),
    }
    return bindings, risk_policy


def validate_policy(value: dict[str, Any]) -> str:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "policyId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "collection",
            "verification",
            "sharedAuthority",
            "claim",
        },
        "sno_dependency_risk_custody_policy_keys_invalid",
    )
    bindings, _ = _expected_bindings()
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.openshift.sno-trial-dependency-risk.custody-policy.v1"
        or value["policyId"]
        != "orchestra-sno-trial-dependency-risk-custody-2026-07-28.1"
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "live"
        or value["bindings"] != bindings
    ):
        fail("sno_dependency_risk_custody_policy_identity_invalid")
    if value["collection"] != {
        "managedFolder": "dependency-risk/",
        "prefixTemplate": (
            "dependency-risk/sno-trial/v1/{profileId}/{evidenceId}"
        ),
        "requiredObjectCount": 4,
        "rawArchiveObject": "sno-dependency-risk-raw-collection.tar.gz",
        "publicKeyObject": "sno-dependency-risk-raw-custody-public-key.pem",
        "statementObject": "sno-dependency-risk-raw-custody-statement.json",
        "completionMarker": (
            "sno-dependency-risk-raw-custody-signature.sigstore.json"
        ),
        "completionMarkerUploadedLast": True,
        "createOnlyGenerationPrecondition": 0,
        "objectGenerationRecorded": False,
        "independentVerificationRequired": True,
    }:
        fail("sno_dependency_risk_custody_policy_collection_invalid")
    if value["verification"] != {
        "managedFolder": "dependency-risk-custody/",
        "prefixTemplate": (
            "dependency-risk-custody/sno-trial/v1/"
            "{profileId}/{evidenceId}/{verificationId}"
        ),
        "reportObject": "sno-dependency-risk-custody-verification.json",
        "publicKeyObject": (
            "sno-dependency-risk-custody-verification-public-key.pem"
        ),
        "completionMarker": (
            "sno-dependency-risk-custody-verification-signature.sigstore.json"
        ),
        "completionMarkerUploadedLast": True,
        "generationPinnedDownloads": True,
        "metagenerationPinnedDownloads": True,
        "safeArchiveExtractionRequired": True,
        "collectionStatementVerificationRequired": True,
        "riskEvidenceRecomputationRequired": True,
        "createOnlyGenerationPrecondition": 0,
        "reportGenerationRecordedByVerifier": False,
    }:
        fail("sno_dependency_risk_custody_policy_verification_invalid")
    if value["sharedAuthority"] != {
        "collectionServiceAccountId": "orchestra-risk-collector",
        "custodyServiceAccountId": "orchestra-custody-verifier",
        "collectionKeyId": "dependency-risk-collection-signing",
        "verificationKeyId": "dependency-risk-custody-verification-signing",
        "workflowEnvironment": (
            "reference-lab-dependency-risk-custody-verification"
        ),
        "currentRunApprovalRequired": True,
        "minimumIndependentReviewers": 1,
        "preventSelfReview": True,
        "rawObjectReadGrantedToVerifier": True,
        "rawObjectWriteGrantedToVerifier": False,
        "rawObjectDeleteGrantedToVerifier": False,
        "signedEvidenceCreateGranted": True,
        "signedEvidenceReadGranted": False,
        "signedEvidenceDeleteGranted": False,
        "artifactMirrorWriteGranted": False,
    }:
        fail("sno_dependency_risk_custody_policy_authority_invalid")
    if value["claim"] != {
        "sourceDeclared": True,
        "ciValidated": True,
        "liveCollectionPublished": False,
        "liveCustodyVerified": False,
        "signedReportPublished": False,
        "exceptionReviewAuthorized": False,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "deploymentAuthorized": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
        "customerCertified": False,
        "redHatCertified": False,
        "contractualSla": False,
    }:
        fail("sno_dependency_risk_custody_policy_claim_invalid")
    digest = canonical_digest(value)
    if digest != EXPECTED_POLICY_DIGEST:
        fail(f"sno_dependency_risk_custody_policy_digest_changed:{digest}")
    return digest


def expected_statement_bindings(
    policy: dict[str, Any], risk_policy: dict[str, Any]
) -> dict[str, str]:
    return {
        "artifactSetDigest": policy["bindings"]["artifactSetDigest"],
        "releaseSetDigest": policy["bindings"]["releaseSetDigest"],
        "riskPolicyDigest": policy["bindings"]["riskPolicyDigest"],
        "collectionAuthorityDigest": policy["bindings"][
            "collectionAuthorityDigest"
        ],
        "collectorScriptDigest": risk_policy["collectionPolicy"][
            "collectorScriptDigest"
        ],
        "publisherScriptDigest": policy["bindings"]["publisherScriptDigest"],
        "rawCustodySchemaDigest": policy["bindings"]["rawCustodySchemaDigest"],
    }


def validate_raw_statement(
    value: dict[str, Any], policy: dict[str, Any], risk_policy: dict[str, Any]
) -> None:
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
        "sno_dependency_risk_raw_custody_statement_keys_invalid",
    )
    evidence_id = value["evidenceId"]
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != (
            "orchestra.openshift.sno-trial-dependency-risk."
            "raw-custody-statement.v1"
        )
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "live"
        or not isinstance(evidence_id, str)
        or not EVIDENCE_ID.fullmatch(evidence_id)
        or value["bindings"] != expected_statement_bindings(policy, risk_policy)
    ):
        fail("sno_dependency_risk_raw_custody_statement_identity_invalid")
    collection = strict_keys(
        value["collection"],
        {
            "manifestFile",
            "manifestDigest",
            "riskEvidenceFile",
            "riskEvidenceDigest",
            "collectionStatementDigest",
            "collectionSignatureBundleDigest",
            "rawArchiveObject",
            "rawArchiveDigest",
        },
        "sno_dependency_risk_raw_custody_collection_invalid",
    )
    if (
        collection["manifestFile"] != "collection-manifest.json"
        or collection["riskEvidenceFile"] != "risk-evidence.json"
        or collection["rawArchiveObject"]
        != "sno-dependency-risk-raw-collection.tar.gz"
    ):
        fail("sno_dependency_risk_raw_custody_collection_invalid")
    for field in (
        "manifestDigest",
        "riskEvidenceDigest",
        "collectionStatementDigest",
        "collectionSignatureBundleDigest",
        "rawArchiveDigest",
    ):
        require_digest(
            collection[field],
            "sno_dependency_risk_raw_custody_collection_invalid",
        )
    prefix = (
        f"dependency-risk/sno-trial/v1/{PROFILE_ID}/{evidence_id}"
    )
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
        "sno_dependency_risk_raw_custody_storage_invalid",
    )
    if storage != {
        "bucket": storage.get("bucket"),
        "prefix": prefix,
        "signingPublicKeyObject": (
            "sno-dependency-risk-raw-custody-public-key.pem"
        ),
        "custodyStatementObject": (
            "sno-dependency-risk-raw-custody-statement.json"
        ),
        "custodySignatureBundleObject": (
            "sno-dependency-risk-raw-custody-signature.sigstore.json"
        ),
        "createOnlyGenerationPrecondition": 0,
        "objectGenerationRecorded": False,
        "independentCustodyVerificationRequired": True,
    } or not isinstance(storage["bucket"], str) or not BUCKET.fullmatch(
        storage["bucket"]
    ):
        fail("sno_dependency_risk_raw_custody_storage_invalid")
    publisher = strict_keys(
        value["publisher"],
        {
            "executionClass",
            "scriptDigest",
            "actorIdentityDigest",
            "signingPublicKeyDigest",
            "publishedAt",
        },
        "sno_dependency_risk_raw_custody_publisher_invalid",
    )
    if (
        publisher["executionClass"] != "signed-certification-runner"
        or publisher["scriptDigest"] != policy["bindings"]["publisherScriptDigest"]
    ):
        fail("sno_dependency_risk_raw_custody_publisher_invalid")
    for field in ("actorIdentityDigest", "signingPublicKeyDigest"):
        require_digest(
            publisher[field],
            "sno_dependency_risk_raw_custody_publisher_invalid",
        )
    parse_timestamp(
        publisher["publishedAt"],
        "sno_dependency_risk_raw_custody_publisher_invalid",
    )
    if value["claims"] != {
        "rawCollectionUploaded": True,
        "rawArtifactsRestricted": True,
        "custodyVerified": False,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "deploymentAuthorized": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("sno_dependency_risk_raw_custody_claim_invalid")


def expected_report_bindings(policy: dict[str, Any]) -> dict[str, str]:
    return dict(policy["bindings"])


def validate_report(value: dict[str, Any], policy: dict[str, Any]) -> None:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "profileId",
            "targetClass",
            "executionMode",
            "verificationId",
            "evidenceId",
            "bindings",
            "rawCustody",
            "collection",
            "verifier",
            "claims",
        },
        "sno_dependency_risk_custody_report_keys_invalid",
    )
    evidence_id = value["evidenceId"]
    verification_id = value["verificationId"]
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != (
            "orchestra.openshift.sno-trial-dependency-risk."
            "custody-verification.v1"
        )
        or value["profileId"] != PROFILE_ID
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "live"
        or not isinstance(evidence_id, str)
        or not EVIDENCE_ID.fullmatch(evidence_id)
        or not isinstance(verification_id, str)
        or not VERIFICATION_ID.fullmatch(verification_id)
        or value["bindings"] != expected_report_bindings(policy)
    ):
        fail("sno_dependency_risk_custody_report_identity_invalid")
    raw = strict_keys(
        value["rawCustody"],
        {
            "bucket",
            "prefix",
            "managedFolder",
            "objectCount",
            "objects",
            "completionMarkerObject",
            "completionMarkerGeneration",
            "custodyStatementDigest",
            "custodySignatureBundleDigest",
            "collectionSigningPublicKeyDigest",
            "collectionSigningKeyVersionResource",
        },
        "sno_dependency_risk_custody_report_raw_invalid",
    )
    expected_prefix = (
        f"dependency-risk/sno-trial/v1/{PROFILE_ID}/{evidence_id}"
    )
    if (
        not isinstance(raw["bucket"], str)
        or not BUCKET.fullmatch(raw["bucket"])
        or raw["prefix"] != expected_prefix
        or raw["managedFolder"] != "dependency-risk/"
        or raw["objectCount"] != 4
        or not isinstance(raw["objects"], list)
        or len(raw["objects"]) != 4
        or raw["completionMarkerObject"]
        != "sno-dependency-risk-raw-custody-signature.sigstore.json"
        or not isinstance(raw["completionMarkerGeneration"], str)
        or not POSITIVE_INTEGER.fullmatch(raw["completionMarkerGeneration"])
        or not COLLECTION_KEY.fullmatch(
            str(raw["collectionSigningKeyVersionResource"])
        )
    ):
        fail("sno_dependency_risk_custody_report_raw_invalid")
    for field in (
        "custodyStatementDigest",
        "custodySignatureBundleDigest",
        "collectionSigningPublicKeyDigest",
    ):
        require_digest(
            raw[field], "sno_dependency_risk_custody_report_raw_invalid"
        )
    seen: set[str] = set()
    marker_generation = None
    for item in raw["objects"]:
        strict_keys(
            item,
            {
                "role",
                "name",
                "generation",
                "metageneration",
                "sizeBytes",
                "crc32c",
                "md5Hash",
                "etag",
                "contentDigest",
                "timeCreated",
                "updated",
            },
            "sno_dependency_risk_custody_report_object_invalid",
        )
        name = item["name"]
        basename = (
            name.removeprefix(f"{expected_prefix}/")
            if isinstance(name, str)
            else ""
        )
        if (
            basename not in RAW_OBJECTS
            or basename in seen
            or item["role"] != RAW_OBJECTS[basename]
            or not isinstance(item["generation"], str)
            or not POSITIVE_INTEGER.fullmatch(item["generation"])
            or not isinstance(item["metageneration"], str)
            or not POSITIVE_INTEGER.fullmatch(item["metageneration"])
            or not isinstance(item["sizeBytes"], int)
            or isinstance(item["sizeBytes"], bool)
            or item["sizeBytes"] <= 0
            or not isinstance(item["crc32c"], str)
            or not item["crc32c"]
            or not isinstance(item["etag"], str)
            or not item["etag"]
        ):
            fail("sno_dependency_risk_custody_report_object_invalid")
        require_digest(
            item["contentDigest"],
            "sno_dependency_risk_custody_report_object_invalid",
        )
        parse_timestamp(
            item["timeCreated"],
            "sno_dependency_risk_custody_report_object_invalid",
        )
        parse_timestamp(
            item["updated"],
            "sno_dependency_risk_custody_report_object_invalid",
        )
        if item["role"] == "completion-marker":
            marker_generation = item["generation"]
        seen.add(basename)
    if seen != set(RAW_OBJECTS) or marker_generation != raw[
        "completionMarkerGeneration"
    ]:
        fail("sno_dependency_risk_custody_report_object_invalid")
    collection = strict_keys(
        value["collection"],
        {
            "rawArchiveDigest",
            "manifestDigest",
            "riskEvidenceDigest",
            "riskEvidenceCanonicalDigest",
            "collectionStatementDigest",
            "collectionSignatureBundleDigest",
            "safeArchiveVerified",
            "collectionStatementVerified",
            "riskEvidenceRecomputed",
        },
        "sno_dependency_risk_custody_report_collection_invalid",
    )
    for field in (
        "rawArchiveDigest",
        "manifestDigest",
        "riskEvidenceDigest",
        "riskEvidenceCanonicalDigest",
        "collectionStatementDigest",
        "collectionSignatureBundleDigest",
    ):
        require_digest(
            collection[field],
            "sno_dependency_risk_custody_report_collection_invalid",
        )
    if (
        collection["safeArchiveVerified"] is not True
        or collection["collectionStatementVerified"] is not True
        or collection["riskEvidenceRecomputed"] is not True
    ):
        fail("sno_dependency_risk_custody_report_collection_invalid")
    verifier = strict_keys(
        value["verifier"],
        {
            "executionClass",
            "actorIdentityDigest",
            "startedAt",
            "completedAt",
            "verificationSigningKeyVersionResource",
            "verificationSigningPublicKeyDigest",
        },
        "sno_dependency_risk_custody_report_verifier_invalid",
    )
    started = parse_timestamp(
        verifier["startedAt"],
        "sno_dependency_risk_custody_report_verifier_invalid",
    )
    completed = parse_timestamp(
        verifier["completedAt"],
        "sno_dependency_risk_custody_report_verifier_invalid",
    )
    require_digest(
        verifier["actorIdentityDigest"],
        "sno_dependency_risk_custody_report_verifier_invalid",
    )
    require_digest(
        verifier["verificationSigningPublicKeyDigest"],
        "sno_dependency_risk_custody_report_verifier_invalid",
    )
    if (
        verifier["executionClass"] != "signed-certification-runner"
        or completed < started
        or not VERIFICATION_KEY.fullmatch(
            str(verifier["verificationSigningKeyVersionResource"])
        )
    ):
        fail("sno_dependency_risk_custody_report_verifier_invalid")
    if value["claims"] != {
        "custodyVerified": True,
        "objectGenerationsRecorded": True,
        "sourceAdmissionAuthorized": False,
        "mirrorAuthorization": False,
        "activationAuthorized": False,
        "deploymentAuthorized": False,
        "campaignEvidence": False,
        "referenceProfileVerified": False,
    }:
        fail("sno_dependency_risk_custody_report_claim_invalid")


def load_policy() -> dict[str, Any]:
    return load_json(POLICY_PATH)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-policy")
    statement = subparsers.add_parser("validate-statement")
    statement.add_argument("--statement", type=Path, required=True)
    report = subparsers.add_parser("validate-report")
    report.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    policy = load_policy()
    digest = validate_policy(policy)
    if args.command == "validate-policy":
        print(
            "sno_dependency_risk_custody_policy_valid "
            f"digest={digest} liveCustodyVerified=false "
            "sourceAdmission=false activation=false deployment=false"
        )
        return 0
    _, _, risk_policy = load_risk_inputs()
    value = load_json(args.statement if args.command == "validate-statement" else args.report)
    if args.command == "validate-statement":
        validate_raw_statement(value, policy, risk_policy)
        print(
            "sno_dependency_risk_raw_custody_statement_valid "
            "custodyVerified=false sourceAdmission=false deployment=false"
        )
    else:
        validate_report(value, policy)
        print(
            "sno_dependency_risk_custody_report_valid "
            "custodyVerified=true sourceAdmission=false deployment=false"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
