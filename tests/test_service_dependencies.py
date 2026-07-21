from __future__ import annotations

import re
import tomllib
import unittest

from scripts.validate_repository import ROOT


_LOCK_ENTRY = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+) \\\s*$", re.MULTILINE)


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_identity(requirement: str) -> tuple[str, str]:
    match = re.fullmatch(
        r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([^\s]+)", requirement
    )
    if not match:
        raise AssertionError(f"requirement is not exactly pinned: {requirement}")
    return normalized(match.group(1)), match.group(2)


class ServiceDependencyLockTests(unittest.TestCase):
    def assert_service_lock(self, service: str) -> dict[str, str]:
        root = ROOT / "services" / service
        pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        lock = (root / "requirements-linux-amd64.lock").read_text(encoding="utf-8")
        matches = list(_LOCK_ENTRY.finditer(lock))
        self.assertTrue(matches)
        packages: dict[str, str] = {}
        for index, match in enumerate(matches):
            name = normalized(match.group(1))
            self.assertNotIn(name, packages)
            packages[name] = match.group(2)
            end = matches[index + 1].start() if index + 1 < len(matches) else len(lock)
            self.assertIn("--hash=sha256:", lock[match.end() : end])

        requirements = [
            *pyproject["project"]["dependencies"],
            *pyproject["build-system"]["requires"],
        ]
        for requirement in requirements:
            name, version = requirement_identity(requirement)
            self.assertEqual(packages.get(name), version)
        self.assertEqual(packages["setuptools"], "83.0.0")
        return packages

    def test_receiver_lock_matches_exact_project_and_build_dependencies(self) -> None:
        self.assert_service_lock("release-validation-receiver")

    def test_synthetic_lock_and_input_match_exact_direct_dependencies(self) -> None:
        packages = self.assert_service_lock("synthetic-tenant-kit")
        root = ROOT / "services" / "synthetic-tenant-kit"
        inputs = {
            requirement_identity(line)[0]: requirement_identity(line)[1]
            for line in (root / "requirements-linux-amd64.in")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#")
        }
        pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        expected = {
            requirement_identity(requirement)[0]: requirement_identity(requirement)[1]
            for requirement in (
                *pyproject["project"]["dependencies"],
                *pyproject["build-system"]["requires"],
            )
        }
        self.assertEqual(inputs, expected)
        for name, version in inputs.items():
            self.assertEqual(packages[name], version)


if __name__ == "__main__":
    unittest.main()
