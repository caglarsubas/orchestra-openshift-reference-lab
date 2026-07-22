#!/usr/bin/env python3
"""Validate a prerequisite observation without upgrading its claims."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from scripts.prerequisite_observation import load_json, validate_observation
except ModuleNotFoundError:
    from prerequisite_observation import load_json, validate_observation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--allow-stale", action="store_true")
    args = parser.parse_args(argv)
    observation = load_json(args.observation)
    digest = validate_observation(observation, require_fresh=not args.allow_stale)
    print(
        "prerequisite_observation_valid "
        f"digest={digest} targetClass={observation['targetClass']} "
        f"executionMode={observation['executionMode']} "
        f"passed={observation['summary']['passedGates']} "
        f"blocked={observation['summary']['blockedGates']} "
        "verified=0 provisioningReady=false campaignEvidence=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error)
        raise SystemExit(1)
