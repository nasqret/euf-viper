#!/usr/bin/env python3
"""Run euf-viper, Z3, and cvc5 on an SMT-LIB manifest."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import statistics
import subprocess
import time
from pathlib import Path


def solver_path(value: str | None, fallback: str) -> str | None:
    if value:
        return value
    return shutil.which(fallback)


def read_manifest(path: Path, limit: int | None) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return rows[:limit] if limit else rows


def run_cmd(cmd: list[str], timeout: float) -> tuple[str, float, int, str]:
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
        return "timeout", time.perf_counter() - start, 124, (exc.stderr or "").strip()
    lines = proc.stdout.strip().splitlines()
    result = lines[0].strip() if lines else f"exit-{proc.returncode}"
    return result, time.perf_counter() - start, proc.returncode, proc.stderr.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--viper", default="target/release/euf-viper")
    parser.add_argument("--z3")
    parser.add_argument("--cvc5")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out", type=Path, default=Path("results/corpus/raw.csv"))
    parser.add_argument("--summary", type=Path, default=Path("results/corpus/summary.json"))
    args = parser.parse_args()

    solvers: list[tuple[str, list[str]]] = []
    viper = solver_path(args.viper, "euf-viper")
    if viper and Path(viper).exists():
        solvers.append(("euf-viper", [viper, "solve"]))
    z3 = solver_path(args.z3, "z3")
    if z3:
        solvers.append(("z3", [z3]))
    cvc5 = solver_path(args.cvc5, "cvc5")
    if cvc5:
        solvers.append(("cvc5", [cvc5]))
    if not solvers:
        raise SystemExit("no solver binaries found")

    rows = read_manifest(args.manifest, args.limit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)

    summary: dict[str, dict] = {
        name: {"count": 0, "results": {}, "times": []} for name, _ in solvers
    }
    mismatches = []
    with args.out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "id",
                "relative_path",
                "expected_status",
                "solver",
                "result",
                "time_s",
                "exit_code",
                "stderr",
            ],
        )
        writer.writeheader()
        for row in rows:
            file_path = row["path"]
            observed = {}
            for name, prefix in solvers:
                result, elapsed, code, stderr = run_cmd(prefix + [file_path], args.timeout)
                observed[name] = result
                s = summary[name]
                s["count"] += 1
                s["results"][result] = s["results"].get(result, 0) + 1
                s["times"].append(elapsed)
                writer.writerow(
                    {
                        "id": row.get("id"),
                        "relative_path": row.get("relative_path"),
                        "expected_status": row.get("status"),
                        "solver": name,
                        "result": result,
                        "time_s": f"{elapsed:.9f}",
                        "exit_code": code,
                        "stderr": stderr[:500],
                    }
                )
            non_unsupported = {
                name: result
                for name, result in observed.items()
                if result not in {"unsupported", "timeout"}
            }
            if len(set(non_unsupported.values())) > 1:
                mismatches.append({"relative_path": row.get("relative_path"), "results": observed})
            print(row.get("relative_path"), observed)

    for data in summary.values():
        times = data.pop("times")
        data["total_time_s"] = sum(times)
        data["median_time_s"] = statistics.median(times) if times else None
        data["mean_time_s"] = statistics.mean(times) if times else None
    payload = {
        "manifest": str(args.manifest),
        "timeout_s": args.timeout,
        "instances": len(rows),
        "solvers": summary,
        "mismatches": mismatches,
    }
    args.summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if mismatches:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
