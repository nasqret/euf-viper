"""Locked ordinary-CLI cases shared by oracle recording and comparison."""

from __future__ import annotations

from pathlib import Path


def cases(root: Path) -> list[tuple[str, list[str], bytes]]:
    basic = "tests/fixtures/basic_sat.smt2"
    malformed = "tests/fixtures/parser_parity/malformed_unclosed.smt2"
    missing = "tests/fixtures/__f8d9205_missing__.smt2"
    if (root / missing).exists():
        raise ValueError(f"locked missing-file fixture unexpectedly exists: {missing}")
    source = (root / basic).read_bytes()
    return [
        ("no arguments", [], b""),
        ("--help", ["--help"], b""),
        ("-h", ["-h"], b""),
        ("help", ["help"], b""),
        ("unknown top-level command", ["--build-features"], b""),
        ("missing solve input", ["solve", "--stats"], b""),
        ("file solve", ["solve", basic], b""),
        (
            "legacy unknown and extra solve arguments",
            ["solve", "--legacy-option", basic, missing, "--another-option"],
            b"",
        ),
        ("parse error", ["solve", malformed], b""),
        ("missing file", ["solve", missing], b""),
        ("parse-check file", ["parse-check", basic], b""),
        ("parse-check stdin", ["parse-check", "-"], source),
    ]
