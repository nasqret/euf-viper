#!/usr/bin/env python3
"""Compare the ordinary CLI byte-for-byte with an independently built baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


BASELINE_REVISION = "f8d9205"
PINNED_TOOLCHAIN = "1.96.0"
HEX_DIGITS = frozenset("0123456789abcdef")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(
    binary: Path, root: Path, arguments: list[str], stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EUF_VIPER_")
    }
    environment.update({"LANG": "C", "LC_ALL": "C"})
    return subprocess.run(
        [str(binary), *arguments],
        cwd=root,
        input=stdin,
        capture_output=True,
        check=False,
        env=environment,
    )


def result(completed: subprocess.CompletedProcess[bytes]) -> tuple[int, bytes, bytes]:
    return completed.returncode, completed.stdout, completed.stderr


def verify_baseline_receipt(receipt: Path, binary: Path) -> dict[str, object]:
    raw = receipt.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid baseline build receipt: {error}") from error
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != canonical:
        raise SystemExit("baseline build receipt is not canonical JSON")
    expected_keys = {
        "schema",
        "status",
        "revision",
        "revision_short",
        "tree",
        "checkout",
        "cargo_lock_sha256",
        "toolchain",
        "executable",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise SystemExit("baseline build receipt keys differ")
    if (
        value["schema"] != "euf-viper.cli-baseline-build.v1"
        or value["status"] != "built"
    ):
        raise SystemExit("baseline build receipt schema mismatch")
    revision = value["revision"]
    tree = value["tree"]
    if (
        value["revision_short"] != BASELINE_REVISION
        or type(revision) is not str
        or not revision.startswith(BASELINE_REVISION)
        or len(revision) not in {40, 64}
        or any(character not in HEX_DIGITS for character in revision)
        or type(tree) is not str
        or len(tree) not in {40, 64}
        or any(character not in HEX_DIGITS for character in tree)
    ):
        raise SystemExit("baseline build receipt is not for f8d9205")
    if type(value["cargo_lock_sha256"]) is not str or len(
        value["cargo_lock_sha256"]
    ) != 64:
        raise SystemExit("baseline Cargo.lock binding is malformed")
    toolchain = value["toolchain"]
    if (
        type(toolchain) is not dict
        or set(toolchain) != {"cargo", "rustc"}
        or not str(toolchain["cargo"]).startswith(f"cargo {PINNED_TOOLCHAIN} ")
        or f"release: {PINNED_TOOLCHAIN}" not in str(toolchain["rustc"])
    ):
        raise SystemExit("baseline toolchain differs from the pinned release")
    executable = value["executable"]
    if not isinstance(executable, dict) or set(executable) != {"bytes", "path", "sha256"}:
        raise SystemExit("baseline receipt lacks an executable binding")
    if Path(str(executable.get("path"))).resolve(strict=True) != binary:
        raise SystemExit("baseline executable path differs from its build receipt")
    if executable.get("sha256") != sha256(binary):
        raise SystemExit("baseline executable SHA-256 differs from its build receipt")
    if executable.get("bytes") != binary.stat().st_size:
        raise SystemExit("baseline executable size differs from its build receipt")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--baseline-binary", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    root = args.repository.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    baseline = args.baseline_binary.resolve(strict=True)
    if binary == baseline or sha256(binary) == sha256(baseline):
        raise SystemExit("candidate and independent baseline must be distinct build artifacts")
    verify_baseline_receipt(args.baseline_receipt.resolve(strict=True), baseline)

    basic = "tests/fixtures/basic_sat.smt2"
    malformed = "tests/fixtures/parser_parity/malformed_unclosed.smt2"
    missing = "tests/fixtures/__f8d9205_missing__.smt2"
    if (root / missing).exists():
        raise SystemExit(f"locked missing-file fixture unexpectedly exists: {missing}")
    source = (root / basic).read_bytes()
    cases = [
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
    for label, arguments, stdin in cases:
        expected = result(execute(baseline, root, arguments, stdin))
        actual = result(execute(binary, root, arguments, stdin))
        if actual != expected:
            raise SystemExit(
                f"{label} differs from independently built f8d9205:\n"
                f"  baseline code/stdout/stderr={expected!r}\n"
                f"  candidate code/stdout/stderr={actual!r}"
            )
    print("ordinary CLI matches independently built f8d9205 byte-for-byte")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
