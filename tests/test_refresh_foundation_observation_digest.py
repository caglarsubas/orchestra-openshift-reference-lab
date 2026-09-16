from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from scripts.foundation_observation import (
    AUTHORITY_PATH,
    EXPECTED_AUTHORITY_DIGEST,
)
from scripts.refresh_foundation_observation_digest import (
    MODULE_PATH,
    changed_bindings,
    main,
    recomputed_authority,
)


class RefreshFoundationObservationDigestTests(unittest.TestCase):
    """The refresh tool must agree with the committed authority."""

    def test_check_passes_on_committed_tree(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["check"]), 0)
        self.assertIn(
            "foundation_observation_digest_current", stdout.getvalue()
        )

    def test_recomputed_digest_matches_pinned_constant(self) -> None:
        _, _, digest = recomputed_authority()
        self.assertEqual(digest, EXPECTED_AUTHORITY_DIGEST)

    def test_check_reports_drift_without_writing(self) -> None:
        authority_before = AUTHORITY_PATH.read_bytes()
        module_before = MODULE_PATH.read_bytes()
        drifted = {"foundationSourceDigest": "sha256:" + "0" * 64}
        with patch(
            "scripts.refresh_foundation_observation_digest.expected_bindings",
            return_value=drifted,
        ):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(["check"]), 1)
        self.assertIn("foundation_observation_digest_stale", stderr.getvalue())
        self.assertEqual(AUTHORITY_PATH.read_bytes(), authority_before)
        self.assertEqual(MODULE_PATH.read_bytes(), module_before)

    def test_changed_bindings_reports_only_drifted_entries(self) -> None:
        current = {"a": "sha256:1", "b": "sha256:2"}
        expected = {"a": "sha256:1", "b": "sha256:9", "c": "sha256:3"}
        self.assertEqual(
            changed_bindings(current, expected),
            [("b", "sha256:2", "sha256:9"), ("c", "<missing>", "sha256:3")],
        )


if __name__ == "__main__":
    unittest.main()
