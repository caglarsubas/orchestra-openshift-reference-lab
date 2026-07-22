#!/usr/bin/env python3
"""Validate one payload-free dependency-risk custody verification report."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from scripts.dependency_risk_custody_verification import (
        load_contract,
        validate_authority,
    )
    from scripts.verify_dependency_risk_raw_custody import (
        file_digest,
        load_json_object,
        require_digest,
        run_cosign,
        validate_report,
    )
except ModuleNotFoundError:
    from dependency_risk_custody_verification import load_contract, validate_authority
    from verify_dependency_risk_raw_custody import (
        file_digest,
        load_json_object,
        require_digest,
        run_cosign,
        validate_report,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--verification-public-key", type=Path)
    parser.add_argument("--signature-bundle", type=Path)
    parser.add_argument("--expected-verification-public-key-digest")
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)
    signature_inputs = (
        args.verification_public_key,
        args.signature_bundle,
        args.expected_verification_public_key_digest,
    )
    if any(value is not None for value in signature_inputs) and not all(
        value is not None for value in signature_inputs
    ):
        raise ValueError("dependency_risk_custody_report_signature_inputs_incomplete")
    authority, release_set, risk_policy = load_contract()
    validate_authority(authority, release_set, risk_policy)
    report_path = args.report.resolve()
    report, _ = load_json_object(
        report_path, "dependency_risk_custody_report_json_invalid"
    )
    validate_report(report, authority)
    signature_verified = False
    if all(value is not None for value in signature_inputs):
        expected_digest = require_digest(
            args.expected_verification_public_key_digest,
            "dependency_risk_custody_report_public_key_digest_invalid",
        )
        public_key = args.verification_public_key.resolve()
        signature_bundle = args.signature_bundle.resolve()
        if (
            not signature_bundle.is_file()
            or signature_bundle.stat().st_size <= 0
            or file_digest(public_key) != expected_digest
            or report["verifier"]["verificationSigningPublicKeyDigest"]
            != expected_digest
        ):
            raise ValueError("dependency_risk_custody_report_signature_binding_invalid")
        run_cosign(
            args.cosign,
            [
                "verify-blob",
                "--bundle",
                str(signature_bundle),
                "--key",
                str(public_key),
                str(report_path),
            ],
            "dependency_risk_custody_report_signature_verification_failed",
        )
        signature_verified = True
    print(
        "dependency_risk_custody_report_valid "
        f"verificationId={report['verificationId']} "
        f"evidenceId={report['evidenceId']} custodyVerified=true "
        f"signatureVerified={str(signature_verified).lower()} "
        "objectGenerationsRecorded=true sourceAdmission=false "
        "campaignEvidence=false referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
