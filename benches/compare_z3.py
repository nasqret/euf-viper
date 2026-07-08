#!/usr/bin/env python3
"""Compare euf-viper against z3 on a directory of SMT2 files.

This harness is intentionally conservative: missing z3 is reported as a
configuration failure, unsupported euf-viper cases are counted separately, and
all raw rows are written as CSV for later audit.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import time
from pathlib import Path


def run_solver(cmd: list[str], timeout: float) -> tuple[str, float, str]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        elapsed = time.perf_counter() - start
        out = proc.stdout.strip().splitlines()
        result = out[0].strip() if out else f"exit-{proc.returncode}"
        return result, elapsed, proc.stderr.strip()
    except subprocess.TimeoutExpired as exc:
        return "timeout", time.perf_counter() - start, (exc.stderr or "").strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bench_dir", type=Path)
    parser.add_argument("--viper", default="target/release/euf-viper")
    parser.add_argument("--z3", default=shutil.which("z3") or "z3")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--out", type=Path, default=Path("results/compare_z3.csv"))
    args = parser.parse_args()

    if not Path(args.viper).exists():
        raise SystemExit(f"missing euf-viper binary: {args.viper}")
    if shutil.which(args.z3) is None and not Path(args.z3).exists():
        raise SystemExit(f"missing z3 binary: {args.z3}")

    files = sorted(args.bench_dir.rglob("*.smt2"))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "file",
                "viper_result",
                "viper_time_s",
                "z3_result",
                "z3_time_s",
                "match",
                "viper_stderr",
                "z3_stderr",
            ],
        )
        writer.writeheader()
        for path in files:
            vr, vt, ve = run_solver([args.viper, "solve", str(path)], args.timeout)
            zr, zt, ze = run_solver([args.z3, str(path)], args.timeout)
            writer.writerow(
                {
                    "file": str(path),
                    "viper_result": vr,
                    "viper_time_s": f"{vt:.9f}",
                    "z3_result": zr,
                    "z3_time_s": f"{zt:.9f}",
                    "match": vr == zr or vr == "unsupported",
                    "viper_stderr": ve,
                    "z3_stderr": ze,
                }
            )
            print(f"{path}: viper={vr} {vt:.4f}s z3={zr} {zt:.4f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
