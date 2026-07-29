#!/usr/bin/env python3
"""Operator-facing entrypoint for reference-lab environment bootstrap."""

from __future__ import annotations

try:
    from scripts.configure_sno_trial_product_admission_environment import (
        ALL_ENVIRONMENT_CONTRACTS,
        main,
    )
except ModuleNotFoundError:
    from configure_sno_trial_product_admission_environment import (
        ALL_ENVIRONMENT_CONTRACTS,
        main,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(
            main(
                contract_choices=ALL_ENVIRONMENT_CONTRACTS,
                contract_required=True,
            )
        )
    except ValueError as error:
        print(error)
        raise SystemExit(1)
