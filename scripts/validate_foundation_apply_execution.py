#!/usr/bin/env python3
"""Validate foundation apply authority and source-only proof boundaries."""

try:
    from scripts.foundation_apply_execution import (
        validate_contract_and_implementation,
    )
except ModuleNotFoundError:
    from foundation_apply_execution import validate_contract_and_implementation


def main() -> int:
    digest = validate_contract_and_implementation()
    print(
        "foundation_apply_authority_valid "
        f"digest={digest} bootstrapApplied=false planPublished=false "
        "foundationApplied=false receiptPublished=false "
        "independentlyObserved=false campaignEvidence=false "
        "referenceProfileVerified=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
