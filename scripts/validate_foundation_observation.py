#!/usr/bin/env python3
"""Validate independent foundation-observation authority and boundaries."""

try:
    from scripts.foundation_observation import validate_contract_and_implementation
except ModuleNotFoundError:
    from foundation_observation import validate_contract_and_implementation


REPIN_HINT = (
    "The authority binds digests over the bootstrap and foundation Terraform\n"
    "sources, the observer script and the observation workflow. If one of\n"
    "those files changed on purpose (a provider bump rewriting versions.tf,\n"
    "for example), re-pin the bindings and review the resulting diff:\n"
    "    python3 scripts/refresh_foundation_observation_digest.py check\n"
    "    python3 scripts/refresh_foundation_observation_digest.py refresh"
)


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
        if str(error).startswith("foundation_observation_authority_"):
            print(REPIN_HINT)
        raise SystemExit(1)
