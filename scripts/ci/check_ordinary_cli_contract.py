#!/usr/bin/env python3
"""Check byte-exact f8d9205 ordinary CLI behavior on a compiled solver."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


BASE_USAGE = """usage:
  euf-viper solve [--stats] FILE
  euf-viper portfolio --yices PATH [--stats] FILE
  euf-viper stats FILE
  euf-viper parse-check FILE|-
  euf-viper gen chain N [--sat]
  euf-viper gen grid WIDTH DEPTH
  euf-viper gen diamond BRANCHES DEPTH
  euf-viper gen pruned-or BRANCHES
  euf-viper bench [--cases N] [--size N]
  euf-viper bench-or [--cases N] [--branches N] [--depth N]"""

CERTIFICATE_USAGE = """usage:
  euf-viper solve [--stats] FILE
  euf-viper portfolio --yices PATH [--stats] FILE
  euf-viper stats FILE
  euf-viper parse-check FILE|-
  euf-viper dump-eager-cnf FILE --out PATH
  euf-viper solve-dimacs FILE
  euf-viper certify FILE --out-prefix PATH [--max-theory-rounds N]
  euf-viper gen chain N [--sat]
  euf-viper gen grid WIDTH DEPTH
  euf-viper gen diamond BRANCHES DEPTH
  euf-viper gen pruned-or BRANCHES
  euf-viper bench [--cases N] [--size N]
  euf-viper bench-or [--cases N] [--branches N] [--depth N]"""

PARSE_CHECK_BASIC_SAT = (
    b'{"schema":"euf-viper.typed-parser-parity.v1","status":"match",'
    b'"tree_well_sorted":true,"stream_well_sorted":true,"fallback":false,'
    b'"snapshot_fnv1a64":"79414a6a050e4402","symbols":6,"sorts":2,'
    b'"functions":5,"terms":6,"applications":2,"assertions":1,'
    b'"bool_data_terms":0,"unsupported_diagnostics":0}\n'
)


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


def require(
    label: str,
    completed: subprocess.CompletedProcess[bytes],
    code: int,
    stdout: bytes,
    stderr: bytes,
) -> None:
    actual = (completed.returncode, completed.stdout, completed.stderr)
    expected = (code, stdout, stderr)
    if actual != expected:
        raise SystemExit(
            f"{label} differs from f8d9205:\n"
            f"  expected code/stdout/stderr={expected!r}\n"
            f"  actual   code/stdout/stderr={actual!r}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--certificates", action="store_true")
    args = parser.parse_args()
    root = args.repository.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    usage = CERTIFICATE_USAGE if args.certificates else BASE_USAGE
    usage_bytes = (usage + "\n").encode("ascii")
    basic = "tests/fixtures/basic_sat.smt2"
    malformed = "tests/fixtures/parser_parity/malformed_unclosed.smt2"
    missing = "tests/fixtures/__f8d9205_missing__.smt2"
    if (root / missing).exists():
        raise SystemExit(f"locked missing-file fixture unexpectedly exists: {missing}")

    require("no arguments", execute(binary, root, []), 2, b"", usage_bytes)
    for option in ("--help", "-h", "help"):
        require(option, execute(binary, root, [option]), 0, usage_bytes, b"")
    require(
        "unknown top-level command",
        execute(binary, root, ["--build-features"]),
        2,
        b"",
        b"unknown command `--build-features`\n" + usage_bytes,
    )
    require(
        "missing solve input",
        execute(binary, root, ["solve", "--stats"]),
        2,
        b"",
        usage_bytes,
    )
    require("file solve", execute(binary, root, ["solve", basic]), 0, b"sat\n", b"")
    require(
        "legacy unknown and extra solve arguments",
        execute(
            binary,
            root,
            ["solve", "--legacy-option", basic, missing, "--another-option"],
        ),
        0,
        b"sat\n",
        b"",
    )
    require(
        "parse error",
        execute(binary, root, ["solve", malformed]),
        2,
        b"",
        b"unclosed '('\n",
    )
    require(
        "missing file",
        execute(binary, root, ["solve", missing]),
        2,
        b"",
        f"failed to read {missing}: No such file or directory (os error 2)\n".encode(),
    )
    source = (root / basic).read_bytes()
    require(
        "parse-check file",
        execute(binary, root, ["parse-check", basic]),
        0,
        PARSE_CHECK_BASIC_SAT,
        b"",
    )
    require(
        "parse-check stdin",
        execute(binary, root, ["parse-check", "-"], source),
        0,
        PARSE_CHECK_BASIC_SAT,
        b"",
    )
    print("ordinary CLI matches f8d9205 byte-for-byte")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
