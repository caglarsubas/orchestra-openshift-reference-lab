#!/usr/bin/env python3
"""Validate the locked risk policy, empty exception intake, or live candidates."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    from scripts.dependency_risk_contract import (
        EXCEPTION_TEMPLATE,
        load_contract_inputs,
        validate_exception_intake,
        validate_risk_evidence,
        validate_risk_policy,
    )
    from scripts.validate_repository import load_json
except ModuleNotFoundError:
    from dependency_risk_contract import (
        EXCEPTION_TEMPLATE,
        load_contract_inputs,
        validate_exception_intake,
        validate_risk_evidence,
        validate_risk_policy,
    )
    from validate_repository import load_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--risk-evidence",
        type=Path,
        help="Optional generated risk-evidence bundle in restricted storage.",
    )
    parser.add_argument(
        "--exception-intake",
        type=Path,
        help="Optional populated exception intake; requires --risk-evidence.",
    )
    parser.add_argument(
        "--at-time",
        help="UTC validation time for deterministic review/expiry checks.",
    )
    args = parser.parse_args(argv)
    if args.exception_intake and not args.risk_evidence:
        raise ValueError("dependency_exception_risk_evidence_argument_required")
    admission, source_verification, policy = load_contract_inputs()
    policy_digest = validate_risk_policy(policy)
    if args.at_time:
        if not args.at_time.endswith("Z"):
            raise ValueError("dependency_risk_validation_time_invalid")
        try:
            assessed_at = datetime.fromisoformat(args.at_time.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("dependency_risk_validation_time_invalid") from error
    else:
        assessed_at = datetime.now(timezone.utc)
    risk_evidence = None
    risk_digest = None
    if args.risk_evidence:
        risk_evidence = load_json(args.risk_evidence)
        risk_digest = validate_risk_evidence(
            risk_evidence, admission, source_verification
        )
    if args.exception_intake:
        exception_path = args.exception_intake
        require_template_digest = False
    else:
        exception_path = EXCEPTION_TEMPLATE
        require_template_digest = True
    exception_intake = load_json(exception_path)
    exception_digest = validate_exception_intake(
        exception_intake,
        admission,
        risk_evidence,
        now=assessed_at,
        require_template_digest=require_template_digest,
    )
    print(
        "dependency_risk_intake_valid "
        f"riskPolicyDigest={policy_digest} "
        f"riskEvidenceDigest={risk_digest or 'none'} "
        f"exceptionIntakeDigest={exception_digest} "
        f"exceptionsApproved={exception_intake['claim']['approvedExceptions']} "
        f"sourceAdmission={str(exception_intake['claim']['sourceAdmissionAuthorized']).lower()} "
        f"mirrorAuthorization={str(exception_intake['claim']['mirrorAuthorization']).lower()} "
        f"campaignEvidence={str(exception_intake['claim']['campaignEvidence']).lower()}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error)
        raise SystemExit(1)
