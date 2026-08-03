from __future__ import annotations

import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
BENCH = ROOT / "scripts" / "bench"
sys.path.insert(0, str(BENCH))
MODULE_PATH = BENCH / "prepare_t11_prebuilt.py"
SPEC = importlib.util.spec_from_file_location("prepare_t11_prebuilt", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PREPARE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PREPARE
SPEC.loader.exec_module(PREPARE)


def synthetic_elf(*, interpreter: bool = True, runpath: bool = False) -> bytes:
    size = 0x500
    value = bytearray(size)
    value[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    phnum = 3 if interpreter else 2
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        value,
        16,
        3,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        phnum,
        0,
        0,
        0,
    )
    headers = [
        (1, 5, 0, 0x400000, 0, size, size, 0x1000),
        (2, 4, 0x280, 0x400280, 0, 0x50, 0x50, 8),
    ]
    if interpreter:
        text = b"/lib64/ld-linux-x86-64.so.2\0"
        value[0x200 : 0x200 + len(text)] = text
        headers.append((3, 4, 0x200, 0x400200, 0, len(text), len(text), 1))
    for index, header in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", value, 64 + index * 56, *header)
    strings = b"\0libc.so.6\0forbidden\0"
    value[0x300 : 0x300 + len(strings)] = strings
    entries = [(5, 0x400300), (10, len(strings)), (1, 1)]
    if runpath:
        entries.append((29, 11))
    entries.append((0, 0))
    for index, entry in enumerate(entries):
        struct.pack_into("<qQ", value, 0x280 + index * 16, *entry)
    return bytes(value)


class PrepareT11PrebuiltTests(unittest.TestCase):
    def test_parses_supported_candidate_elf(self) -> None:
        info = PREPARE._parse_elf_bytes(
            synthetic_elf(), "fixture", require_interpreter=True
        )
        self.assertEqual(info.elf_type, 3)
        self.assertEqual(info.interpreter, "/lib64/ld-linux-x86-64.so.2")
        self.assertEqual(info.needed, ("libc.so.6",))

    def test_rejects_non_elf_candidate(self) -> None:
        with self.assertRaisesRegex(PREPARE.PreparationError, "not an ELF"):
            PREPARE._parse_elf_bytes(b"#!/bin/sh\n", "fixture", require_interpreter=True)

    def test_requires_candidate_interpreter(self) -> None:
        with self.assertRaisesRegex(PREPARE.PreparationError, "absolute PT_INTERP"):
            PREPARE._parse_elf_bytes(
                synthetic_elf(interpreter=False),
                "fixture",
                require_interpreter=True,
            )

    def test_allows_library_without_interpreter(self) -> None:
        info = PREPARE._parse_elf_bytes(
            synthetic_elf(interpreter=False), "fixture"
        )
        self.assertIsNone(info.interpreter)
        self.assertEqual(info.needed, ("libc.so.6",))

    def test_rejects_runpath(self) -> None:
        with self.assertRaisesRegex(PREPARE.PreparationError, "RPATH/RUNPATH"):
            PREPARE._parse_elf_bytes(
                synthetic_elf(runpath=True), "fixture", require_interpreter=True
            )

    def test_rejects_user_writable_runtime_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.so"
            path.write_bytes(b"runtime")
            with self.assertRaisesRegex(PREPARE.PreparationError, "writable"):
                PREPARE._assert_not_user_writable(path.resolve(), "runtime")

    def test_canonical_json_rejects_nonfinite_numbers(self) -> None:
        with self.assertRaises(ValueError):
            PREPARE._canonical_json({"value": float("nan")})


if __name__ == "__main__":
    unittest.main()
