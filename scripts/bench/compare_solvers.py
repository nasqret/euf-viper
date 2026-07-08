#!/usr/bin/env python3
"""Run euf-viper, Z3, and cvc5 on an SMT-LIB manifest."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import shutil
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


FIELDNAMES = [
    "id",
    "relative_path",
    "expected_status",
    "solver",
    "result",
    "time_s",
    "exit_code",
    "stderr",
]
DECISIVE_RESULTS = {"sat", "unsat"}


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
        stderr = exc.stderr or ""
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return "timeout", time.perf_counter() - start, 124, stderr.strip()
    lines = proc.stdout.strip().splitlines()
    result = lines[0].strip() if lines else f"exit-{proc.returncode}"
    return result, time.perf_counter() - start, proc.returncode, proc.stderr.strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def load_existing_results(
    path: Path,
    manifest_paths: set[str],
    solver_names: set[str],
) -> dict[tuple[str, str], dict]:
    observations: dict[tuple[str, str], dict] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != FIELDNAMES:
            raise SystemExit(f"cannot resume {path}: incompatible CSV header")
        for line_number, record in enumerate(reader, start=2):
            relative_path = record.get("relative_path", "")
            solver = record.get("solver", "")
            if relative_path not in manifest_paths:
                raise SystemExit(
                    f"cannot resume {path}:{line_number}: path is not in the manifest"
                )
            if solver not in solver_names:
                raise SystemExit(
                    f"cannot resume {path}:{line_number}: unknown solver {solver!r}"
                )
            key = (relative_path, solver)
            if key in observations:
                raise SystemExit(
                    f"cannot resume {path}:{line_number}: duplicate result for {key}"
                )
            try:
                elapsed = float(record["time_s"])
                exit_code = int(record["exit_code"])
            except (KeyError, TypeError, ValueError) as exc:
                raise SystemExit(
                    f"cannot resume {path}:{line_number}: malformed numeric field"
                ) from exc
            observations[key] = {
                "result": record.get("result", ""),
                "time_s": elapsed,
                "exit_code": exit_code,
                "stderr": record.get("stderr", ""),
            }
    return observations


def summarize(
    rows: list[dict],
    solver_names: list[str],
    observations: dict[tuple[str, str], dict],
) -> tuple[dict[str, dict], list[dict], list[dict], list[dict]]:
    summary: dict[str, dict] = {
        name: {
            "count": 0,
            "results": {},
            "times": [],
            "decisive": 0,
            "correct": 0,
            "wrong": 0,
            "execution_errors": 0,
        }
        for name in solver_names
    }
    wrong_answers: list[dict] = []
    solver_disagreements: list[dict] = []
    execution_errors: list[dict] = []

    for row in rows:
        relative_path = row["relative_path"]
        expected = row.get("status")
        observed: dict[str, str] = {}
        for name in solver_names:
            observation = observations.get((relative_path, name))
            if observation is None:
                continue
            result = observation["result"]
            observed[name] = result
            data = summary[name]
            data["count"] += 1
            data["results"][result] = data["results"].get(result, 0) + 1
            data["times"].append(observation["time_s"])
            if result in DECISIVE_RESULTS:
                data["decisive"] += 1
                if result == expected:
                    data["correct"] += 1
                elif expected in DECISIVE_RESULTS:
                    data["wrong"] += 1
                    wrong_answers.append(
                        {
                            "relative_path": relative_path,
                            "expected": expected,
                            "solver": name,
                            "result": result,
                        }
                    )
            if (
                observation["exit_code"] not in {0, 124}
                and result != "unsupported"
            ):
                data["execution_errors"] += 1
                execution_errors.append(
                    {
                        "relative_path": relative_path,
                        "solver": name,
                        "result": result,
                        "exit_code": observation["exit_code"],
                        "stderr": observation["stderr"],
                    }
                )

        decisive = {
            name: result for name, result in observed.items() if result in DECISIVE_RESULTS
        }
        if len(set(decisive.values())) > 1:
            solver_disagreements.append(
                {"relative_path": relative_path, "results": observed}
            )

    for data in summary.values():
        times = data.pop("times")
        count = data["count"]
        data["coverage"] = data["correct"] / len(rows) if rows else None
        data["completion"] = count / len(rows) if rows else None
        data["total_time_s"] = sum(times)
        data["median_time_s"] = statistics.median(times) if times else None
        data["mean_time_s"] = statistics.mean(times) if times else None

    return summary, wrong_answers, solver_disagreements, execution_errors


def progress_payload(
    *,
    manifest: Path,
    rows: list[dict],
    solver_names: list[str],
    observations: dict[tuple[str, str], dict],
    out: Path,
    started_at: str,
    status: str,
) -> dict:
    summary, wrong_answers, solver_disagreements, execution_errors = summarize(
        rows, solver_names, observations
    )
    complete_instances = sum(
        all((row["relative_path"], name) in observations for name in solver_names)
        for row in rows
    )
    return {
        "status": status,
        "started_at": started_at,
        "updated_at": utc_now(),
        "manifest": str(manifest),
        "output": str(out),
        "instances_total": len(rows),
        "instances_complete": complete_instances,
        "solver_runs_total": len(rows) * len(solver_names),
        "solver_runs_complete": len(observations),
        "solvers": summary,
        "wrong_answers": wrong_answers,
        "solver_disagreements": solver_disagreements,
        "execution_errors": execution_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--viper", default="target/release/euf-viper")
    parser.add_argument("--z3")
    parser.add_argument("--cvc5")
    parser.add_argument("--no-z3", action="store_true")
    parser.add_argument("--no-cvc5", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out", type=Path, default=Path("results/corpus/raw.csv"))
    parser.add_argument("--summary", type=Path, default=Path("results/corpus/summary.json"))
    parser.add_argument("--progress", type=Path)
    parser.add_argument("--checkpoint-every", type=int, default=100)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.no_z3 and args.z3:
        parser.error("--no-z3 cannot be combined with --z3")
    if args.no_cvc5 and args.cvc5:
        parser.error("--no-cvc5 cannot be combined with --cvc5")

    solvers: list[tuple[str, list[str]]] = []
    viper = solver_path(args.viper, "euf-viper")
    if viper and Path(viper).exists():
        solvers.append(("euf-viper", [viper, "solve"]))
    if not args.no_z3:
        z3 = solver_path(args.z3, "z3")
        if z3:
            solvers.append(("z3", [z3]))
    if not args.no_cvc5:
        cvc5 = solver_path(args.cvc5, "cvc5")
        if cvc5:
            solvers.append(("cvc5", [cvc5]))
    if not solvers:
        raise SystemExit("no solver binaries found")

    rows = read_manifest(args.manifest, args.limit)
    if args.jobs < 1:
        raise SystemExit("--jobs must be at least 1")
    if args.checkpoint_every < 1:
        raise SystemExit("--checkpoint-every must be at least 1")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    if args.progress:
        args.progress.parent.mkdir(parents=True, exist_ok=True)

    solver_names = [name for name, _ in solvers]
    manifest_paths = {row["relative_path"] for row in rows}
    if len(manifest_paths) != len(rows):
        raise SystemExit("manifest contains duplicate relative_path values")

    observations: dict[tuple[str, str], dict] = {}
    append = args.resume and args.out.exists()
    if append:
        observations = load_existing_results(
            args.out, manifest_paths, set(solver_names)
        )

    started_at = utc_now()
    if args.progress:
        atomic_write_json(
            args.progress,
            progress_payload(
                manifest=args.manifest,
                rows=rows,
                solver_names=solver_names,
                observations=observations,
                out=args.out,
                started_at=started_at,
                status="running",
            ),
        )

    prefixes = dict(solvers)
    tasks = [
        (row, name, prefixes[name] + [row["path"]])
        for row in rows
        for name in solver_names
        if (row["relative_path"], name) not in observations
    ]

    def execute(task: tuple[dict, str, list[str]]) -> tuple[dict, str, dict]:
        row, name, cmd = task
        result, elapsed, code, stderr = run_cmd(cmd, args.timeout)
        return row, name, {
            "result": result,
            "time_s": elapsed,
            "exit_code": code,
            "stderr": stderr,
        }

    mode = "a" if append else "w"
    with args.out.open(mode, newline="", encoding="utf-8", buffering=1) as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        if not append:
            writer.writeheader()

        if args.jobs == 1:
            task_results = map(execute, tasks)
            executor = None
        else:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs)
            task_results = executor.map(execute, tasks)

        try:
            for completed, (row, name, observation) in enumerate(task_results, start=1):
                relative_path = row["relative_path"]
                observations[(relative_path, name)] = observation
                writer.writerow(
                    {
                        "id": row.get("id"),
                        "relative_path": relative_path,
                        "expected_status": row.get("status"),
                        "solver": name,
                        "result": observation["result"],
                        "time_s": f'{observation["time_s"]:.9f}',
                        "exit_code": observation["exit_code"],
                        "stderr": observation["stderr"][:500],
                    }
                )

                if all((relative_path, solver) in observations for solver in solver_names):
                    observed = {
                        solver: observations[(relative_path, solver)]["result"]
                        for solver in solver_names
                    }
                    print(relative_path, observed, flush=True)

                if args.progress and completed % args.checkpoint_every == 0:
                    fh.flush()
                    atomic_write_json(
                        args.progress,
                        progress_payload(
                            manifest=args.manifest,
                            rows=rows,
                            solver_names=solver_names,
                            observations=observations,
                            out=args.out,
                            started_at=started_at,
                            status="running",
                        ),
                    )
        finally:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)

    summary, wrong_answers, solver_disagreements, execution_errors = summarize(
        rows, solver_names, observations
    )
    payload = {
        "manifest": str(args.manifest),
        "timeout_s": args.timeout,
        "instances": len(rows),
        "solvers": summary,
        "wrong_answers": wrong_answers,
        "solver_disagreements": solver_disagreements,
        "execution_errors": execution_errors,
        # Kept for consumers of the original schema.
        "mismatches": solver_disagreements,
    }
    atomic_write_json(args.summary, payload)
    if args.progress:
        atomic_write_json(
            args.progress,
            progress_payload(
                manifest=args.manifest,
                rows=rows,
                solver_names=solver_names,
                observations=observations,
                out=args.out,
                started_at=started_at,
                status="complete",
            ),
        )
    if wrong_answers or solver_disagreements:
        return 2
    if execution_errors:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
