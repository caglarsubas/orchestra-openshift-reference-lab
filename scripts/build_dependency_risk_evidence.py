#!/usr/bin/env python3
"""Build a payload-free review bundle from signed-runner scan artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.dependency_risk_contract import (
        CONTROL_PLAN,
        SEVERITIES,
        blob_digest,
        expected_bindings,
        expected_machine_review,
        fail,
        load_contract_inputs,
        strict_keys,
        unsigned_subjects,
        validate_collection,
        validate_risk_evidence,
    )
    from scripts.validate_repository import canonical_digest
except ModuleNotFoundError:
    from dependency_risk_contract import (
        CONTROL_PLAN,
        SEVERITIES,
        blob_digest,
        expected_bindings,
        expected_machine_review,
        fail,
        load_contract_inputs,
        strict_keys,
        unsigned_subjects,
        validate_collection,
        validate_risk_evidence,
    )
    from validate_repository import canonical_digest


def load_json_bytes(path: Path, code: str) -> tuple[dict[str, Any], bytes]:
    try:
        content = path.read_bytes()
        value = json.loads(content)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{code}:{error}")
    if not isinstance(value, dict):
        fail(code)
    return value, content


def artifact_path(base_dir: Path, file_name: Any, subject_id: str, kind: str) -> Path:
    if (
        not isinstance(file_name, str)
        or not file_name
        or Path(file_name).name != file_name
    ):
        fail(f"dependency_risk_manifest_artifact_name_invalid:{subject_id}:{kind}")
    path = (base_dir / file_name).resolve()
    if path.parent != base_dir.resolve():
        fail(f"dependency_risk_manifest_artifact_name_invalid:{subject_id}:{kind}")
    return path


def summarize_vulnerabilities(
    report: dict[str, Any], platform_subject: str, subject_id: str
) -> dict[str, Any]:
    if (
        not isinstance(report.get("SchemaVersion"), int)
        or report["SchemaVersion"] < 2
        or report.get("ArtifactName") != platform_subject
        or report.get("ArtifactType") not in {"container_image", "oci", "image"}
    ):
        fail(f"dependency_risk_trivy_identity_invalid:{subject_id}")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        fail(f"dependency_risk_trivy_results_invalid:{subject_id}")
    counts = {severity: 0 for severity in SEVERITIES}
    fixed = {severity: 0 for severity in SEVERITIES}
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
            fail(f"dependency_risk_trivy_result_invalid:{subject_id}")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            fail(f"dependency_risk_trivy_vulnerabilities_invalid:{subject_id}")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                fail(f"dependency_risk_trivy_vulnerability_invalid:{subject_id}")
            severity = vulnerability.get("Severity", "UNKNOWN")
            if severity not in SEVERITIES:
                severity = "UNKNOWN"
            counts[severity] += 1
            fixed_version = vulnerability.get("FixedVersion")
            if isinstance(fixed_version, str) and fixed_version.strip():
                fixed[severity] += 1
    threshold_state = (
        "passed"
        if counts["CRITICAL"] == counts["HIGH"] == counts["UNKNOWN"] == 0
        else "blocked"
    )
    return {
        "total": sum(counts.values()),
        "bySeverity": counts,
        "fixAvailableBySeverity": fixed,
        "scanTargetCount": len(results),
        "thresholdState": threshold_state,
    }


def license_value(package: dict[str, Any], field: str) -> str:
    value = package.get(field, "NOASSERTION")
    if not isinstance(value, str) or not value.strip():
        return "NOASSERTION"
    return value.strip()


def summarize_licenses(
    document: dict[str, Any], subject_id: str, platform_subject: str
) -> dict[str, Any]:
    document_name = document.get("name")
    document_namespace = document.get("documentNamespace")
    platform_digest = platform_subject.rsplit("@", maxsplit=1)[-1]
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("dataLicense") != "CC0-1.0"
        or not isinstance(document_name, str)
        or not document_name.strip()
        or not isinstance(document_namespace, str)
        or (
            document_name not in {subject_id, platform_subject}
            and platform_digest not in document_namespace
        )
    ):
        fail(f"dependency_risk_spdx_identity_invalid:{subject_id}")
    creation = document.get("creationInfo")
    creators = creation.get("creators") if isinstance(creation, dict) else None
    if not isinstance(creators, list) or not any(
        isinstance(creator, str) and creator.lower().startswith("tool: syft")
        for creator in creators
    ):
        fail(f"dependency_risk_spdx_creator_invalid:{subject_id}")
    described = document.get("documentDescribes")
    relationships = document.get("relationships") or []
    has_describes = isinstance(described, list) and bool(described)
    if not has_describes and isinstance(relationships, list):
        has_describes = any(
            isinstance(relationship, dict)
            and relationship.get("relationshipType") == "DESCRIBES"
            for relationship in relationships
        )
    if not has_describes:
        fail(f"dependency_risk_spdx_describes_missing:{subject_id}")
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        fail(f"dependency_risk_spdx_packages_invalid:{subject_id}")
    rows: list[dict[str, str]] = []
    expressions: set[str] = set()
    no_assertion = 0
    none = 0
    for package in packages:
        if (
            not isinstance(package, dict)
            or not isinstance(package.get("SPDXID"), str)
            or not isinstance(package.get("name"), str)
        ):
            fail(f"dependency_risk_spdx_package_invalid:{subject_id}")
        declared = license_value(package, "licenseDeclared")
        concluded = license_value(package, "licenseConcluded")
        for expression in (declared, concluded):
            if expression == "NOASSERTION":
                no_assertion += 1
            elif expression == "NONE":
                none += 1
            else:
                expressions.add(expression)
        version = package.get("versionInfo", "")
        rows.append(
            {
                "spdxId": package["SPDXID"],
                "name": package["name"],
                "version": version if isinstance(version, str) else "",
                "declared": declared,
                "concluded": concluded,
            }
        )
    rows.sort(key=lambda row: (row["spdxId"], row["name"], row["version"]))
    return {
        "packageCount": len(rows),
        "expressions": sorted(expressions),
        "noAssertionCount": no_assertion,
        "noneCount": none,
        "inventoryDigest": canonical_digest({"packages": rows}),
        "humanReviewState": "required",
    }


def validate_manifest(
    value: dict[str, Any],
    admission: dict[str, Any],
    source_verification: dict[str, Any],
) -> None:
    strict_keys(
        value,
        {
            "schemaVersion",
            "profileId",
            "targetClass",
            "executionMode",
            "evidenceId",
            "bindings",
            "collection",
            "subjects",
        },
        "dependency_risk_manifest_keys_invalid",
    )
    if (
        value["schemaVersion"] != 1
        or value["profileId"] != "orchestra-ocp-4.20-amd64-v1"
        or value["targetClass"] != "vendor-reference-lab"
        or value["executionMode"] != "live"
        or not isinstance(value["evidenceId"], str)
        or value["bindings"] != expected_bindings()
    ):
        fail("dependency_risk_manifest_identity_invalid")
    validate_collection(value["collection"], source_verification)
    expected = unsigned_subjects(admission)
    items = value["subjects"]
    if not isinstance(items, list) or len(items) != len(expected):
        fail("dependency_risk_manifest_inventory_invalid")
    seen: set[str] = set()
    for item in items:
        strict_keys(
            item,
            {
                "id",
                "sourceSubject",
                "platformSubject",
                "vulnerabilityReportFile",
                "vulnerabilityReportDigest",
                "sbomFile",
                "sbomDigest",
            },
            "dependency_risk_manifest_subject_shape_invalid",
        )
        subject_id = item["id"]
        if subject_id not in expected or subject_id in seen:
            fail("dependency_risk_manifest_inventory_invalid")
        seen.add(subject_id)
        if (
            item["sourceSubject"] != expected[subject_id]["sourceSubject"]
            or item["platformSubject"] != expected[subject_id]["platformSubject"]
        ):
            fail(f"dependency_risk_manifest_subject_binding_invalid:{subject_id}")
        for field in ("vulnerabilityReportDigest", "sbomDigest"):
            digest = item[field]
            if (
                not isinstance(digest, str)
                or len(digest) != 71
                or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])
            ):
                fail(f"dependency_risk_manifest_digest_invalid:{subject_id}:{field}")
    if seen != set(expected):
        fail("dependency_risk_manifest_inventory_invalid")


def build_risk_evidence(
    manifest: dict[str, Any],
    input_dir: Path,
    admission: dict[str, Any],
    source_verification: dict[str, Any],
) -> dict[str, Any]:
    validate_manifest(manifest, admission, source_verification)
    subjects: list[dict[str, Any]] = []
    for item in manifest["subjects"]:
        subject_id = item["id"]
        vulnerability_path = artifact_path(
            input_dir, item["vulnerabilityReportFile"], subject_id, "vulnerability"
        )
        sbom_path = artifact_path(input_dir, item["sbomFile"], subject_id, "sbom")
        vulnerability_report, vulnerability_bytes = load_json_bytes(
            vulnerability_path, f"dependency_risk_trivy_json_invalid:{subject_id}"
        )
        sbom, sbom_bytes = load_json_bytes(
            sbom_path, f"dependency_risk_spdx_json_invalid:{subject_id}"
        )
        vulnerability_digest = blob_digest(vulnerability_bytes)
        sbom_digest = blob_digest(sbom_bytes)
        if (
            vulnerability_digest != item["vulnerabilityReportDigest"]
            or sbom_digest != item["sbomDigest"]
        ):
            fail(f"dependency_risk_raw_artifact_digest_mismatch:{subject_id}")
        vulnerabilities = summarize_vulnerabilities(
            vulnerability_report, item["platformSubject"], subject_id
        )
        licenses = summarize_licenses(sbom, subject_id, item["platformSubject"])
        control_states = [
            {
                "id": control["id"],
                "requiredBefore": control["requiredBefore"],
                "status": "declared-not-proven",
            }
            for control in CONTROL_PLAN
        ]
        controls = {
            "planDigest": canonical_digest(
                {"subject": item["sourceSubject"], "controls": control_states}
            ),
            "controls": control_states,
        }
        artifacts = {
            "vulnerability": {
                "fileName": item["vulnerabilityReportFile"],
                "digest": vulnerability_digest,
            },
            "sbom": {"fileName": item["sbomFile"], "digest": sbom_digest},
        }
        state, reasons = expected_machine_review(vulnerabilities)
        review_payload = {
            "subject": item["sourceSubject"],
            "platformSubject": item["platformSubject"],
            "artifacts": artifacts,
            "vulnerabilities": vulnerabilities,
            "licenses": licenses,
            "compensatingControls": controls,
            "collectionAttestationDigest": manifest["collection"][
                "collectionAttestationDigest"
            ],
        }
        subjects.append(
            {
                "id": subject_id,
                "sourceSubject": item["sourceSubject"],
                "platformSubject": item["platformSubject"],
                "artifacts": artifacts,
                "vulnerabilities": vulnerabilities,
                "licenses": licenses,
                "compensatingControls": controls,
                "machineReview": {
                    "state": state,
                    "reasonCodes": reasons,
                    "reviewDigest": canonical_digest(review_payload),
                },
            }
        )
    threshold_passed = sum(
        subject["vulnerabilities"]["thresholdState"] == "passed" for subject in subjects
    )
    eligible = sum(
        subject["machineReview"]["state"] == "eligible-for-human-review"
        for subject in subjects
    )
    result = {
        "schemaVersion": 1,
        "profileId": manifest["profileId"],
        "targetClass": manifest["targetClass"],
        "executionMode": manifest["executionMode"],
        "evidenceId": manifest["evidenceId"],
        "bindings": manifest["bindings"],
        "collection": manifest["collection"],
        "subjects": subjects,
        "claim": {
            "allSubjectsCollected": True,
            "vulnerabilityThresholdPassedCount": threshold_passed,
            "eligibleForHumanReviewCount": eligible,
            "licenseReviewsComplete": False,
            "exceptionsApproved": False,
            "sourceAdmissionAuthorized": False,
            "mirrorAuthorization": False,
            "activationAuthorized": False,
            "campaignEvidence": False,
        },
    }
    validate_risk_evidence(result, admission, source_verification)
    return result


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, ensure_ascii=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Signed-runner scan manifest; raw report paths must be sibling basenames.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New candidate path, normally under ignored restricted/ storage.",
    )
    args = parser.parse_args(argv)
    manifest, _ = load_json_bytes(
        args.manifest, "dependency_risk_manifest_json_invalid"
    )
    admission, source_verification, _ = load_contract_inputs()
    result = build_risk_evidence(
        manifest, args.manifest.resolve().parent, admission, source_verification
    )
    write_new_json(args.output, result)
    print(
        "dependency_risk_evidence_built "
        f"digest={canonical_digest(result)} subjects={len(result['subjects'])} "
        f"eligible={result['claim']['eligibleForHumanReviewCount']} "
        "exceptionsApproved=false sourceAdmission=false mirrorAuthorization=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
