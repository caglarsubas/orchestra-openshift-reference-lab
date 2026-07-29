#!/usr/bin/env python3
"""CLI wrapper for production model custody source authority validation."""

try:
    from scripts.production_model_artifact_custody_execution import (
        validate_contract_and_implementation,
    )
except ModuleNotFoundError:
    from production_model_artifact_custody_execution import (
        validate_contract_and_implementation,
    )


def main() -> int:
    digest = validate_contract_and_implementation()
    print(
        "production_model_custody_authority_valid "
        f"digest={digest} terraformDeclared=true workflowDeclared=true "
        "applied=false artifactCustodyVerified=false licenseApproved=false "
        "admissionAuthorized=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
