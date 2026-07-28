#!/usr/bin/env python3
"""Validate and optionally verify a signed SNO dependency-risk custody report."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from scripts.sno_trial_dependency_risk_custody import (
        load_policy,
        require_digest,
        validate_policy,
        validate_report,
    )
    from scripts.verify_dependency_risk_raw_custody import (
        file_digest,
        load_json_object,
        run_cosign,
    )
except ModuleNotFoundError:
    from sno_trial_dependency_risk_custody import (
        load_policy,
        require_digest,
        validate_policy,
        validate_report,
    )
    from verify_dependency_risk_raw_custody import (
        file_digest,
        load_json_object,
        run_cosign,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--verification-public-key", type=Path)
    parser.add_argument("--signature-bundle", type=Path)
    parser.add_argument("--expected-verification-public-key-digest")
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)
    optional = (
        args.verification_public_key,
        args.signature_bundle,
        args.expected_verification_public_key_digest,
    )
    if any(value is not None for value in optional) and not all(
        value is not None for value in optional
    ):
        raise ValueError(
            "sno_dependency_risk_custody_signature_inputs_incomplete"
        )
    policy = load_policy()
    validate_policy(policy)
    report, content = load_json_object(
        args.report.resolve(),
        "sno_dependency_risk_custody_report_json_invalid",
    )
    validate_report(report, policy)
    signature_verified = False
    if args.verification_public_key is not None:
        expected_digest = require_digest(
            args.expected_verification_public_key_digest,
            "sno_dependency_risk_custody_verification_key_digest_invalid",
        )
        if (
            file_digest(args.verification_public_key.resolve())
            != expected_digest
            or report["verifier"]["verificationSigningPublicKeyDigest"]
            != expected_digest
        ):
            raise ValueError(
                "sno_dependency_risk_custody_verification_key_mismatch"
            )
        run_cosign(
            args.cosign,
            [
                "verify-blob",
                "--bundle",
                str(args.signature_bundle.resolve()),
                "--key",
                str(args.verification_public_key.resolve()),
                str(args.report.resolve()),
            ],
            "sno_dependency_risk_custody_report_signature_invalid",
        )
        signature_verified = True
    print(
        "sno_dependency_risk_custody_report_valid "
        f"verificationId={report['verificationId']} "
        f"evidenceId={report['evidenceId']} report={file_digest(args.report)} "
        f"bytes={len(content)} custodyVerified=true "
        f"signatureVerified={str(signature_verified).lower()} "
        "sourceAdmission=false activation=false deployment=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
