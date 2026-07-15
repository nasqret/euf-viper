from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wmi" / "execution_closure.py"
SPEC = importlib.util.spec_from_file_location("execution_closure_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CLOSURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOSURE)
LINUX = sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir()


class ExecutionClosureTests(unittest.TestCase):
    @unittest.skipUnless(LINUX, "real execution-closure inventory requires Linux")
    def test_dynamic_loader_and_executable_substitution_are_bound(self) -> None:
        ldd = Path(shutil.which("ldd") or "").resolve(strict=True)
        source_executable = Path(shutil.which("true") or "").resolve(strict=True)
        replacement_executable = Path(shutil.which("false") or "").resolve(strict=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "solver"
            artifact = root / "source.smt2"
            shutil.copy2(source_executable, executable)
            executable.chmod(0o755)
            artifact.write_bytes(b"(check-sat)\n")
            value = CLOSURE.create_manifest(
                {"solver": executable.resolve(strict=True)},
                {"source": artifact.resolve(strict=True)},
                ldd,
            )
            self.assertTrue(value["libraries"])
            self.assertTrue(
                any(
                    "ld-linux" in record["path"] or "ld-musl" in record["path"]
                    for record in value["libraries"]
                )
            )
            raw = CLOSURE.canonical_bytes(value)
            manifest = root / "closure.json"
            manifest.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(
                CLOSURE.verify_manifest(manifest, digest)["status"], "accepted"
            )

            replacement = root / "replacement"
            shutil.copy2(replacement_executable, replacement)
            replacement.chmod(0o755)
            os.replace(replacement, executable)
            with self.assertRaisesRegex(CLOSURE.ClosureError, "drifted"):
                CLOSURE.verify_manifest(manifest, digest)

    @unittest.skipIf(LINUX, "non-Linux fail-closed test")
    def test_inventory_fails_closed_without_linux_procfd(self) -> None:
        with self.assertRaisesRegex(CLOSURE.ClosureError, "requires Linux"):
            CLOSURE.create_manifest({}, {}, Path("/usr/bin/false"))


if __name__ == "__main__":
    unittest.main()
