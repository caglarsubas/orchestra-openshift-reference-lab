#!/usr/bin/env python3
"""Re-pin foundation-observation bindings after an intentional source change.

The foundation-observation authority binds digests over the bootstrap and
foundation Terraform sources, the observer script and the observation
workflow. Any edit to those files -- including a Dependabot provider bump
that only rewrites ``versions.tf`` -- invalidates the pinned bindings and
fails ``validate_foundation_observation``.

Re-pinning stays a deliberate human step: this tool only rewrites the
bindings, and the resulting diff must be reviewed like any other change to
the authority. Never run it to make an unexplained failure disappear.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from scripts.foundation_observation import (
        AUTHORITY_PATH,
        EXPECTED_AUTHORITY_DIGEST,
        expected_bindings,
        load_contract,
    )
    from scripts.validate_repository import ROOT, canonical_digest
except ModuleNotFoundError:
    from foundation_observation import (
        AUTHORITY_PATH,
        EXPECTED_AUTHORITY_DIGEST,
        expected_bindings,
        load_contract,
    )
    from validate_repository import ROOT, canonical_digest


MODULE_PATH = ROOT / "scripts" / "foundation_observation.py"


def recomputed_authority() -> tuple[dict, dict[str, str], str]:
    """Return the authority re-pinned to the working tree, plus its digest."""
    authority, release_set, policy, apply_authority = load_contract()
    bindings = expected_bindings(release_set, policy, apply_authority)
    repinned = dict(authority)
    repinned["bindings"] = bindings
    return repinned, bindings, canonical_digest(repinned)


def changed_bindings(
    current: dict[str, str], expected: dict[str, str]
) -> list[tuple[str, str, str]]:
    return [
        (name, current.get(name, "<missing>"), value)
        for name, value in expected.items()
        if current.get(name) != value
    ]


def report(
    drift: list[tuple[str, str, str]], digest: str
) -> None:
    for name, old, new in drift:
        print(f"  {name}\n    {old}\n -> {new}")
    if digest != EXPECTED_AUTHORITY_DIGEST:
        print(
            "  EXPECTED_AUTHORITY_DIGEST\n"
            f"    {EXPECTED_AUTHORITY_DIGEST}\n -> {digest}"
        )


def write_repinned(repinned: dict, digest: str) -> None:
    AUTHORITY_PATH.write_text(
        json.dumps(repinned, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    module = MODULE_PATH.read_text(encoding="utf-8")
    if module.count(EXPECTED_AUTHORITY_DIGEST) != 1:
        raise ValueError("foundation_observation_digest_constant_not_unique")
    MODULE_PATH.write_text(
        module.replace(EXPECTED_AUTHORITY_DIGEST, digest), encoding="utf-8"
    )


def command_check() -> int:
    authority, _, _, _ = load_contract()
    _, bindings, digest = recomputed_authority()
    drift = changed_bindings(authority.get("bindings", {}), bindings)
    if not drift and digest == EXPECTED_AUTHORITY_DIGEST:
        print(f"foundation_observation_digest_current digest={digest}")
        return 0
    print("foundation_observation_digest_stale", file=sys.stderr)
    report(drift, digest)
    print(
        "\nRe-pin with: python3 "
        "scripts/refresh_foundation_observation_digest.py refresh\n"
        "Review the resulting diff before committing it.",
        file=sys.stderr,
    )
    return 1


def command_refresh() -> int:
    authority, _, _, _ = load_contract()
    repinned, bindings, digest = recomputed_authority()
    drift = changed_bindings(authority.get("bindings", {}), bindings)
    if not drift and digest == EXPECTED_AUTHORITY_DIGEST:
        print(f"foundation_observation_digest_current digest={digest}")
        return 0
    report(drift, digest)
    write_repinned(repinned, digest)
    print(f"foundation_observation_digest_repinned digest={digest}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    commands.add_parser("refresh")
    args = parser.parse_args(argv)
    if args.command == "check":
        return command_check()
    return command_refresh()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
