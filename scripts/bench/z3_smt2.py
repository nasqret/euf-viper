#!/usr/bin/env python3
"""Small z3-solver wrapper with a z3-CLI-compatible surface for SMT2 files."""

from __future__ import annotations

import sys

import z3


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] in {"-version", "--version"}:
        print(f"Z3 Python z3-solver {z3.get_version_string()}")
        return 0
    if len(sys.argv) != 2:
        print("usage: z3_smt2.py FILE.smt2", file=sys.stderr)
        return 2
    solver = z3.Solver()
    solver.from_file(sys.argv[1])
    print(solver.check())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
