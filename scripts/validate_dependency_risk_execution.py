#!/usr/bin/env python3
"""Validate dependency-risk preflight authority and source boundaries."""

try:
    from scripts.dependency_risk_execution import validate_contract_and_implementation
except ModuleNotFoundError:
    from dependency_risk_execution import validate_contract_and_implementation


def main() -> int:
    digest = validate_contract_and_implementation()
    print(
        "dependency_risk_preflight_authority_valid "
        f"digest={digest} applied=false livePreflight=false collectionStarted=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
