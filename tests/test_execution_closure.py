from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wmi" / "execution_closure.py"
SPEC = importlib.util.spec_from_file_location("execution_closure_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CLOSURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOSURE)
LINUX = sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir()


class ExecutionClosureTests(unittest.TestCase):
    def test_relocatable_elf_is_not_a_dynamic_loader_target(self) -> None:
        def elf_header(object_type: int) -> bytes:
            content = bytearray(64)
            content[:7] = b"\x7fELF\x02\x01\x01"
            content[16:18] = object_type.to_bytes(2, "little")
            return bytes(content)

        self.assertFalse(CLOSURE.is_dynamic_elf(elf_header(1), "python.o"))
        self.assertTrue(CLOSURE.is_dynamic_elf(elf_header(3), "extension.so"))
        with self.assertRaisesRegex(CLOSURE.ClosureError, "truncated ELF"):
            CLOSURE.is_dynamic_elf(b"\x7fELF", "truncated.so")

    def test_loader_target_second_read_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "tool"
            replacement = Path(temporary) / "replacement"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            replacement.write_bytes(b"#!/bin/sh\nexit 9\n")
            executable.chmod(0o755)
            replacement.chmod(0o755)
            original = CLOSURE.stable_read
            replaced = False

            def substitute(path: Path, label: str):
                nonlocal replaced
                result = original(path, label)
                if path == executable and not replaced:
                    os.replace(replacement, executable)
                    replaced = True
                return result

            with mock.patch.object(CLOSURE, "stable_read", side_effect=substitute):
                with self.assertRaisesRegex(CLOSURE.ClosureError, "descriptor differs"):
                    CLOSURE.open_verified_descriptor(executable, "fixture loader target")
            self.assertTrue(replaced)

    def test_production_runtime_forbids_unbound_recursive_copy_roots(self) -> None:
        helper = MODULE_PATH.read_text(encoding="ascii")
        for script_name in (
            "euf_viper_locked_shard.sbatch",
            "euf_viper_locked_audit.sbatch",
        ):
            script = (ROOT / "scripts" / "wmi" / script_name).read_text(
                encoding="ascii"
            )
            self.assertNotIn("--copy-root", script)
            self.assertIn("os.memfd_create", script)
            self.assertIn("compile(raw, helper, \"exec\")", script)
            self.assertIn("exec 9<\"$PYTHON_BIN\"", script)
            self.assertIn("python_expected", script)
            self.assertNotIn(
                'python_clean "$EXECUTION_CLOSURE_HELPER"', script
            )
        prepare = (
            ROOT / "scripts" / "wmi" / "euf_viper_locked_prepare.sbatch"
        ).read_text(encoding="ascii")
        for helper_name in (
            "SEALED_BUILD_HELPER",
            "EXECUTION_CLOSURE_HELPER",
            "BUILD_ATTESTOR",
        ):
            self.assertIn(f'python_bound "${helper_name}"', prepare)
        self.assertIn('exec 9<"$PYTHON_BIN"', prepare)
        self.assertIn("unbound recursive runtime copy roots are forbidden", helper)

    @unittest.skipUnless(LINUX, "real execution-closure inventory requires Linux")
    def test_dynamic_loader_and_executable_substitution_are_bound(self) -> None:
        ldd = Path(shutil.which("ldd") or "").resolve(strict=True)
        source_executable = Path(shutil.which("true") or "").resolve(strict=True)
        replacement_executable = Path(shutil.which("false") or "").resolve(strict=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "solver"
            artifact = root / "source.smt2"
            python_script = root / "probe.py"
            shutil.copy2(source_executable, executable)
            executable.chmod(0o755)
            artifact.write_bytes(b"(check-sat)\n")
            python_script.write_text("import json\nimport pathlib\n", encoding="ascii")
            value = CLOSURE.create_manifest(
                {
                    "python": Path(sys.executable).resolve(strict=True),
                    "solver": executable.resolve(strict=True),
                },
                {"source": artifact.resolve(strict=True)},
                ldd,
                python_executable_name="python",
                python_scripts={"probe": python_script.resolve(strict=True)},
            )
            self.assertTrue(value["libraries"])
            self.assertTrue(value["python_runtime"]["native_extensions"])
            self.assertFalse(
                any(
                    Path(record["path"]).name == "python.o"
                    for record in value["python_runtime"]["native_extensions"]
                )
            )
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

    @unittest.skipUnless(LINUX, "real execution-closure inventory requires Linux")
    def test_python_script_bytes_are_reprobed_and_bound(self) -> None:
        ldd = Path(shutil.which("ldd") or "").resolve(strict=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "probe.py"
            script.write_text("import hashlib\n", encoding="ascii")
            value = CLOSURE.create_manifest(
                {"python": Path(sys.executable).resolve(strict=True)},
                {},
                ldd,
                python_executable_name="python",
                python_scripts={"probe": script.resolve(strict=True)},
            )
            raw = CLOSURE.canonical_bytes(value)
            manifest = root / "closure.json"
            manifest.write_bytes(raw)
            script.write_text("import decimal\n", encoding="ascii")
            with self.assertRaisesRegex(
                CLOSURE.ClosureError, "drifted|Python imported-module closure"
            ):
                CLOSURE.verify_manifest(manifest, hashlib.sha256(raw).hexdigest())

    @unittest.skipIf(LINUX, "non-Linux fail-closed test")
    def test_inventory_fails_closed_without_linux_procfd(self) -> None:
        with self.assertRaisesRegex(CLOSURE.ClosureError, "requires Linux"):
            CLOSURE.create_manifest(
                {},
                {},
                Path("/usr/bin/false"),
                python_executable_name="python",
                python_scripts={},
            )


if __name__ == "__main__":
    unittest.main()
