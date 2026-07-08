#!/usr/bin/env python3
"""Repeated median comparison between euf-viper and z3.

This complements `compare_z3.py` by reducing process cold-start noise.  It runs
each solver several times per file, writes all samples, and reports medians.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import statistics
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
    except subprocess.TimeoutExpired as exc:
        return "timeout", time.perf_counter() - start, (exc.stderr or "").strip()
    elapsed = time.perf_counter() - start
    lines = proc.stdout.strip().splitlines()
    result = lines[0].strip() if lines else f"exit-{proc.returncode}"
    return result, elapsed, proc.stderr.strip()


def timed_samples(cmd: list[str], repeats: int, warmups: int, timeout: float):
    samples = []
    for i in range(warmups + repeats):
        result, elapsed, stderr = run_solver(cmd, timeout)
        if i >= warmups:
            samples.append((result, elapsed, stderr))
    return samples


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bench_dir", type=Path)
    parser.add_argument("--viper", default="target/release/euf-viper")
    parser.add_argument("--z3", default=shutil.which("z3") or "z3")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--out", type=Path, default=Path("results/compare_z3_repeat.csv"))
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
                "solver",
                "sample",
                "result",
                "time_s",
                "median_s",
                "stderr",
            ],
        )
        writer.writeheader()
        for path in files:
            viper = timed_samples(
                [args.viper, "solve", str(path)], args.repeats, args.warmups, args.timeout
            )
            z3 = timed_samples([args.z3, str(path)], args.repeats, args.warmups, args.timeout)
            v_med = statistics.median(sample[1] for sample in viper)
            z_med = statistics.median(sample[1] for sample in z3)
            for solver, samples, median in (("euf-viper", viper, v_med), ("z3", z3, z_med)):
                for idx, (result, elapsed, stderr) in enumerate(samples):
                    writer.writerow(
                        {
                            "file": str(path),
                            "solver": solver,
                            "sample": idx,
                            "result": result,
                            "time_s": f"{elapsed:.9f}",
                            "median_s": f"{median:.9f}",
                            "stderr": stderr,
                        }
                    )
            v_result = viper[0][0] if viper else "none"
            z_result = z3[0][0] if z3 else "none"
            speedup = z_med / v_med if v_med > 0 else float("inf")
            print(
                f"{path}: viper={v_result} median={v_med:.6f}s "
                f"z3={z_result} median={z_med:.6f}s speedup={speedup:.1f}x"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
