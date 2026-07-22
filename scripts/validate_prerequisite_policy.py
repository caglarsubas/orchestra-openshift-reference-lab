#!/usr/bin/env python3
"""Validate the locked prerequisite observation policy."""

try:
    from scripts.prerequisite_observation import load_contract, validate_policy
except ModuleNotFoundError:
    from prerequisite_observation import load_contract, validate_policy


def main() -> int:
    policy, release_set = load_contract()
    digest = validate_policy(policy, release_set)
    print(
        "prerequisite_observation_policy_valid "
        f"digest={digest} collectorMayVerify=false provisioningReady=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
