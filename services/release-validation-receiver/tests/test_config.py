from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from orchestra_receiver.config import read_secret_file


class ConfigTests(unittest.TestCase):
    def test_accepts_kubernetes_style_projected_secret_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "..data"
            data.mkdir()
            target = data / "token"
            target.write_bytes(b"projected-secret\n")
            projected = root / "token"
            projected.symlink_to(Path("..data") / "token")
            self.assertEqual(read_secret_file(str(projected)), b"projected-secret")

    def test_rejects_missing_and_empty_secret_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(RuntimeError):
                read_secret_file(str(root / "missing"))
            empty = root / "empty"
            empty.write_bytes(b"")
            with self.assertRaises(RuntimeError):
                read_secret_file(str(empty))


if __name__ == "__main__":
    unittest.main()
