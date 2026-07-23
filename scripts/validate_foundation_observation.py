#!/usr/bin/env python3
"""Validate independent foundation-observation authority and boundaries."""

try:
    from scripts.foundation_observation import validate_contract_and_implementation
except ModuleNotFoundError:
    from foundation_observation import validate_contract_and_implementation


def main() -> int:
    digest = validate_contract_and_implementation()
    print(
        "foundation_observation_authority_valid "
        f"digest={digest} bootstrapApplied=false foundationApplied=false "
        "applyReceiptVerified=false providerRefreshExecuted=false "
        "observationPublished=false independentlyObserved=false "
        "campaignEvidence=false referenceProfileVerified=false "
        "customerCertified=false redHatCertified=false contractualSla=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
