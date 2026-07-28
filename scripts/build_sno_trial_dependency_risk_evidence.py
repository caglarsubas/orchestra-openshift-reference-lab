#!/usr/bin/env python3
"""Build payload-free SNO dependency risk evidence from restricted raw inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.build_dependency_risk_evidence import (
        artifact_path,
        load_json_bytes,
        summarize_licenses,
        summarize_vulnerabilities,
    )
    from scripts.sno_trial_dependency_risk import (
        CONTROL_PLAN,
        EXPECTED_POLICY_DIGEST,
        EVIDENCE_ID,
        blob_digest,
        expected_bindings,
        expected_machine_review,
        expected_subjects,
        fail,
        load_inputs,
        strict_keys,
        validate_collection,
        validate_risk_evidence,
    )
    from scripts.validate_repository import canonical_digest
except ModuleNotFoundError:
    from build_dependency_risk_evidence import (
        artifact_path,
        load_json_bytes,
        summarize_licenses,
        summarize_vulnerabilities,
    )
    from sno_trial_dependency_risk import (
        CONTROL_PLAN,
        EXPECTED_POLICY_DIGEST,
        EVIDENCE_ID,
        blob_digest,
        expected_bindings,
        expected_machine_review,
        expected_subjects,
        fail,
        load_inputs,
        strict_keys,
        validate_collection,
        validate_risk_evidence,
    )
    from validate_repository import canonical_digest


def validate_manifest(
    value: dict[str, Any],
    artifacts: dict[str, Any],
    release_set: dict[str, Any],
) -> None:
    strict_keys(
        value,
        {
            "schemaVersion",
            "kind",
            "evidenceId",
            "profileId",
            "targetClass",
            "executionMode",
            "bindings",
            "collection",
            "subjects",
            "modelArtifact",
        },
        "sno_dependency_risk_manifest_keys_invalid",
    )
    expected_evidence_bindings = {
        **expected_bindings(artifacts, release_set),
        "riskPolicyDigest": EXPECTED_POLICY_DIGEST,
    }
    if (
        value["schemaVersion"] != 1
        or value["kind"]
        != "orchestra.openshift.sno-trial-dependency-risk-collection-manifest.v1"
        or not isinstance(value["evidenceId"], str)
        or not EVIDENCE_ID.fullmatch(value["evidenceId"])
        or value["profileId"] != "orchestra-ocp-sno-trial-amd64-v1"
        or value["targetClass"] != "engineering-trial"
        or value["executionMode"] != "live"
        or value["bindings"] != expected_evidence_bindings
    ):
        fail("sno_dependency_risk_manifest_identity_invalid")
    validate_collection(value["collection"], release_set)
    expected = expected_subjects(artifacts)
    subjects = value["subjects"]
    if not isinstance(subjects, list) or len(subjects) != len(expected):
        fail("sno_dependency_risk_manifest_inventory_invalid")
    seen: set[str] = set()
    for item in subjects:
        strict_keys(
            item,
            {
                "id",
                "indexSubject",
                "platformSubject",
                "vulnerabilityReportFile",
                "vulnerabilityReportDigest",
                "sbomFile",
                "sbomDigest",
                "signatureProbeFile",
                "signatureProbeDigest",
            },
            "sno_dependency_risk_manifest_subject_shape_invalid",
        )
        subject_id = item["id"]
        if subject_id not in expected or subject_id in seen:
            fail("sno_dependency_risk_manifest_inventory_invalid")
        seen.add(subject_id)
        if (
            item["indexSubject"] != expected[subject_id]["indexSubject"]
            or item["platformSubject"] != expected[subject_id]["platformSubject"]
        ):
            fail(f"sno_dependency_risk_manifest_subject_binding_invalid:{subject_id}")
        for field in (
            "vulnerabilityReportDigest",
            "sbomDigest",
            "signatureProbeDigest",
        ):
            if (
                not isinstance(item[field], str)
                or not item[field].startswith("sha256:")
                or len(item[field]) != 71
            ):
                fail(f"sno_dependency_risk_manifest_digest_invalid:{subject_id}:{field}")
    if seen != set(expected):
        fail("sno_dependency_risk_manifest_inventory_invalid")
    strict_keys(
        value["modelArtifact"],
        {
            "id",
            "immutableUrl",
            "revision",
            "expectedDigest",
            "observedDigest",
            "expectedSizeBytes",
            "observedSizeBytes",
            "declaredLicense",
            "bytesVerified",
            "contentLengthVerified",
            "licenseReview",
        },
        "sno_dependency_risk_manifest_model_invalid",
    )


def read_signature_probe(
    path: Path,
    expected_digest: str,
    index_subject: str,
    subject_id: str,
) -> tuple[dict[str, Any], str]:
    report, content = load_json_bytes(
        path, f"sno_dependency_risk_signature_probe_json_invalid:{subject_id}"
    )
    digest = blob_digest(content)
    if digest != expected_digest:
        fail(f"sno_dependency_risk_signature_probe_digest_mismatch:{subject_id}")
    strict_keys(
        report,
        {
            "schemaVersion",
            "kind",
            "indexSubject",
            "status",
            "cosignVersion",
            "cosignExitCode",
            "rawOutputDigest",
            "observedAt",
        },
        f"sno_dependency_risk_signature_probe_shape_invalid:{subject_id}",
    )
    if (
        report["schemaVersion"] != 1
        or report["kind"]
        != "orchestra.openshift.sno-trial-upstream-signature-probe.v1"
        or report["indexSubject"] != index_subject
        or report["status"] != "no-signature-found"
        or report["cosignVersion"] != "3.1.1"
        or report["cosignExitCode"] != 1
        or not isinstance(report["rawOutputDigest"], str)
        or not report["rawOutputDigest"].startswith("sha256:")
        or len(report["rawOutputDigest"]) != 71
        or not isinstance(report["observedAt"], str)
        or not report["observedAt"].endswith("Z")
    ):
        fail(f"sno_dependency_risk_signature_probe_invalid:{subject_id}")
    return report, digest


def build_evidence(
    manifest: dict[str, Any],
    input_dir: Path,
    artifacts: dict[str, Any],
    release_set: dict[str, Any],
) -> dict[str, Any]:
    validate_manifest(manifest, artifacts, release_set)
    expected = expected_subjects(artifacts)
    subjects: list[dict[str, Any]] = []
    for item in manifest["subjects"]:
        subject_id = item["id"]
        vulnerability_path = artifact_path(
            input_dir,
            item["vulnerabilityReportFile"],
            subject_id,
            "vulnerability",
        )
        sbom_path = artifact_path(input_dir, item["sbomFile"], subject_id, "sbom")
        signature_path = artifact_path(
            input_dir,
            item["signatureProbeFile"],
            subject_id,
            "signature",
        )
        vulnerability_report, vulnerability_bytes = load_json_bytes(
            vulnerability_path,
            f"sno_dependency_risk_trivy_json_invalid:{subject_id}",
        )
        sbom, sbom_bytes = load_json_bytes(
            sbom_path,
            f"sno_dependency_risk_spdx_json_invalid:{subject_id}",
        )
        vulnerability_digest = blob_digest(vulnerability_bytes)
        sbom_digest = blob_digest(sbom_bytes)
        if (
            vulnerability_digest != item["vulnerabilityReportDigest"]
            or sbom_digest != item["sbomDigest"]
        ):
            fail(f"sno_dependency_risk_raw_artifact_digest_mismatch:{subject_id}")
        _, signature_digest = read_signature_probe(
            signature_path,
            item["signatureProbeDigest"],
            item["indexSubject"],
            subject_id,
        )
        vulnerabilities = summarize_vulnerabilities(
            vulnerability_report,
            item["platformSubject"],
            subject_id,
        )
        licenses = summarize_licenses(
            sbom,
            subject_id,
            item["platformSubject"],
        )
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
                {"subject": item["indexSubject"], "controls": control_states}
            ),
            "controls": control_states,
        }
        raw_artifacts = {
            "vulnerability": {
                "fileName": item["vulnerabilityReportFile"],
                "digest": vulnerability_digest,
            },
            "sbom": {
                "fileName": item["sbomFile"],
                "digest": sbom_digest,
            },
        }
        signature = {
            "status": "no-signature-found",
            "indexSubject": item["indexSubject"],
            "probeDigest": signature_digest,
        }
        state, reasons = expected_machine_review(vulnerabilities)
        review_payload = {
            "indexSubject": item["indexSubject"],
            "platformSubject": item["platformSubject"],
            "signatureObservation": signature,
            "artifacts": raw_artifacts,
            "vulnerabilities": vulnerabilities,
            "licenses": licenses,
            "compensatingControls": controls,
            "collectionStatementDigest": manifest["collection"][
                "collectionStatementDigest"
            ],
        }
        subjects.append(
            {
                "id": subject_id,
                "indexSubject": item["indexSubject"],
                "platformSubject": item["platformSubject"],
                "sourceRevision": expected[subject_id]["sourceRevision"],
                "declaredLicense": expected[subject_id]["declaredLicense"],
                "signatureObservation": signature,
                "artifacts": raw_artifacts,
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
    model_artifact = dict(manifest["modelArtifact"])
    model_artifact["verificationDigest"] = canonical_digest(model_artifact)
    threshold_passed = sum(
        item["vulnerabilities"]["thresholdState"] == "passed" for item in subjects
    )
    eligible = sum(
        item["machineReview"]["state"] == "eligible-for-human-review"
        for item in subjects
    )
    result = {
        "schemaVersion": 1,
        "kind": "orchestra.openshift.sno-trial-dependency-risk-evidence.v1",
        "evidenceId": manifest["evidenceId"],
        "profileId": manifest["profileId"],
        "targetClass": manifest["targetClass"],
        "executionMode": manifest["executionMode"],
        "bindings": manifest["bindings"],
        "collection": manifest["collection"],
        "subjects": subjects,
        "modelArtifact": model_artifact,
        "claims": {
            "allSubjectsCollected": True,
            "vulnerabilityThresholdPassedCount": threshold_passed,
            "eligibleForHumanReviewCount": eligible,
            "modelIntegrityVerified": True,
            "modelLicenseReviewComplete": (
                model_artifact["licenseReview"]["state"] == "complete"
            ),
            "containerLicenseReviewsComplete": False,
            "exceptionsApproved": False,
            "sourceAdmissionAuthorized": False,
            "mirrorAuthorization": False,
            "activationAuthorized": False,
            "deploymentAuthorized": False,
            "campaignEvidence": False,
            "referenceProfileVerified": False,
        },
    }
    validate_risk_evidence(result, artifacts, release_set)
    return result


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, ensure_ascii=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest, _ = load_json_bytes(
        args.manifest,
        "sno_dependency_risk_manifest_json_invalid",
    )
    artifacts, release_set, _ = load_inputs()
    result = build_evidence(
        manifest,
        args.manifest.resolve().parent,
        artifacts,
        release_set,
    )
    write_new_json(args.output, result)
    print(
        "sno_trial_dependency_risk_evidence_built "
        f"digest={canonical_digest(result)} "
        f"eligible={result['claims']['eligibleForHumanReviewCount']} "
        "sourceAdmission=false activation=false deployment=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
