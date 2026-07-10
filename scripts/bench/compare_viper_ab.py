#!/usr/bin/env python3
"""Paired, alternating repeated A/B timing for two euf-viper binaries/configs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path


DECISIVE_RESULTS = {"sat", "unsat"}
FIELDNAMES = [
    "relative_path",
    "expected_status",
    "label",
    "repeat",
    "result",
    "time_s",
    "exit_code",
    "stderr",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_metadata(
    manifest: Path,
    baseline: Path,
    candidate: Path,
    timeout_s: float,
    warmups: int,
    environment: dict[str, str] | None = None,
    hostname: str | None = None,
) -> dict:
    environment = os.environ if environment is None else environment
    hashes = {
        path: sha256_file(path)
        for path in {manifest.resolve(), baseline.resolve(), candidate.resolve()}
    }
    return {
        "manifest_sha256": hashes[manifest.resolve()],
        "baseline_sha256": hashes[baseline.resolve()],
        "candidate_sha256": hashes[candidate.resolve()],
        "timeout_s": timeout_s,
        "warmups": warmups,
        "runtime_host": hostname if hostname is not None else platform.node(),
        "git_revision": environment.get("EUF_VIPER_GIT_REVISION"),
        "slurm_job_id": environment.get("SLURM_JOB_ID"),
        "slurm_array_job_id": environment.get("SLURM_ARRAY_JOB_ID"),
        "slurm_array_task_id": environment.get("SLURM_ARRAY_TASK_ID"),
        "slurm_node_list": environment.get("SLURM_JOB_NODELIST"),
    }


def parse_environment(values: list[str]) -> dict[str, str]:
    environment = os.environ.copy()
    for value in values:
        if "=" not in value:
            raise ValueError(f"environment entry must be KEY=VALUE: {value!r}")
        key, setting = value.split("=", 1)
        if not key:
            raise ValueError("environment key cannot be empty")
        environment[key] = setting
    return environment


def run(binary: Path, source: str, environment: dict[str, str], timeout: float) -> dict:
    start = time.perf_counter()
    try:
        process = subprocess.run(
            [str(binary), "solve", source],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stderr = error.stderr or ""
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return {
            "result": "timeout",
            "time_s": time.perf_counter() - start,
            "exit_code": 124,
            "stderr": stderr.strip(),
        }
    lines = process.stdout.strip().splitlines()
    return {
        "result": lines[0].strip() if lines else f"exit-{process.returncode}",
        "time_s": time.perf_counter() - start,
        "exit_code": process.returncode,
        "stderr": process.stderr.strip(),
    }


def summarize(rows: list[dict], samples: list[dict]) -> tuple[dict, list[dict]]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for sample in samples:
        grouped[(sample["relative_path"], sample["label"])].append(sample)

    path_summaries = {}
    wrong_answers = []
    execution_errors = []
    coverage = {"baseline": 0, "candidate": 0}
    common = []
    for row in rows:
        relative_path = row["relative_path"]
        expected = row["status"]
        labels = {}
        for label in ("baseline", "candidate"):
            observations = grouped[(relative_path, label)]
            results = Counter(observation["result"] for observation in observations)
            correct = all(observation["result"] == expected for observation in observations)
            coverage[label] += correct
            labels[label] = {
                "correct": correct,
                "results": dict(sorted(results.items())),
                "median_time_s": statistics.median(
                    observation["time_s"] for observation in observations
                ),
            }
            wrong_answers.extend(
                {
                    "relative_path": relative_path,
                    "label": label,
                    "expected": expected,
                    "result": observation["result"],
                    "repeat": observation["repeat"],
                }
                for observation in observations
                if observation["result"] in DECISIVE_RESULTS
                and observation["result"] != expected
            )
            execution_errors.extend(
                {
                    "relative_path": relative_path,
                    "label": label,
                    "result": observation["result"],
                    "repeat": observation["repeat"],
                    "exit_code": observation["exit_code"],
                    "stderr": observation["stderr"],
                }
                for observation in observations
                if observation["exit_code"] not in (0, 124)
            )
        if labels["baseline"]["correct"] and labels["candidate"]["correct"]:
            common.append(
                (
                    labels["baseline"]["median_time_s"],
                    labels["candidate"]["median_time_s"],
                )
            )
        path_summaries[relative_path] = labels

    baseline_total = sum(baseline for baseline, _ in common)
    candidate_total = sum(candidate for _, candidate in common)
    baseline_all_total = sum(
        labels["baseline"]["median_time_s"] for labels in path_summaries.values()
    )
    candidate_all_total = sum(
        labels["candidate"]["median_time_s"] for labels in path_summaries.values()
    )
    ratios = [
        baseline / candidate
        for baseline, candidate in common
        if baseline > 0 and candidate > 0
    ]
    baseline_only_paths = [
        path
        for path, labels in path_summaries.items()
        if labels["baseline"]["correct"] and not labels["candidate"]["correct"]
    ]
    candidate_only_paths = [
        path
        for path, labels in path_summaries.items()
        if labels["candidate"]["correct"] and not labels["baseline"]["correct"]
    ]
    payload = {
        "instances": len(rows),
        "repeats": len(samples) // (2 * len(rows)) if rows else 0,
        "baseline_correct": coverage["baseline"],
        "candidate_correct": coverage["candidate"],
        "coverage_delta": coverage["candidate"] - coverage["baseline"],
        "baseline_only_correct": len(baseline_only_paths),
        "candidate_only_correct": len(candidate_only_paths),
        "baseline_only_examples": sorted(baseline_only_paths)[:25],
        "candidate_only_examples": sorted(candidate_only_paths)[:25],
        "common_correct": len(common),
        "baseline_common_total_time_s": baseline_total,
        "candidate_common_total_time_s": candidate_total,
        "candidate_speedup_by_total": (
            baseline_total / candidate_total if candidate_total else None
        ),
        "baseline_all_total_time_s": baseline_all_total,
        "candidate_all_total_time_s": candidate_all_total,
        "candidate_all_speedup_by_total": (
            baseline_all_total / candidate_all_total
            if candidate_all_total
            else None
        ),
        "candidate_geometric_speedup": (
            math.exp(statistics.mean(math.log(ratio) for ratio in ratios))
            if ratios
            else None
        ),
        "candidate_wins": sum(candidate < baseline for baseline, candidate in common),
        "baseline_wins": sum(baseline < candidate for baseline, candidate in common),
        "wrong_answers": wrong_answers,
        "execution_errors": execution_errors,
        "paths": path_summaries,
    }
    return payload, wrong_answers


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline-env", action="append", default=[])
    parser.add_argument("--candidate-env", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    if args.repeats < 1 or args.warmups < 0:
        parser.error("--repeats must be positive and --warmups non-negative")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    for binary in (args.baseline, args.candidate):
        if not binary.is_file():
            parser.error(f"missing binary: {binary}")

    rows = [
        json.loads(line)
        for line in args.manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if args.limit is not None:
        rows = rows[: args.limit]
    if not rows:
        parser.error("manifest selection is empty")
    if len({row["relative_path"] for row in rows}) != len(rows):
        parser.error("manifest contains duplicate relative paths")
    environments = {
        "baseline": parse_environment(args.baseline_env),
        "candidate": parse_environment(args.candidate_env),
    }
    binaries = {"baseline": args.baseline, "candidate": args.candidate}

    samples = []
    for index, row in enumerate(rows):
        for _ in range(args.warmups):
            for label in ("baseline", "candidate"):
                run(binaries[label], row["path"], environments[label], args.timeout)
        for repeat in range(args.repeats):
            labels = (
                ("baseline", "candidate")
                if (index + repeat) % 2 == 0
                else ("candidate", "baseline")
            )
            for label in labels:
                observation = run(
                    binaries[label], row["path"], environments[label], args.timeout
                )
                samples.append(
                    {
                        "relative_path": row["relative_path"],
                        "expected_status": row["status"],
                        "label": label,
                        "repeat": repeat,
                        **observation,
                    }
                )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for sample in samples:
            writer.writerow({**sample, "stderr": sample["stderr"][:500]})
    payload, wrong_answers = summarize(rows, samples)
    payload.update(
        {
            "manifest": str(args.manifest),
            "baseline": str(args.baseline),
            "candidate": str(args.candidate),
            "baseline_env": args.baseline_env,
            "candidate_env": args.candidate_env,
            **artifact_metadata(
                args.manifest,
                args.baseline,
                args.candidate,
                args.timeout,
                args.warmups,
            ),
        }
    )
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    total_speedup = payload["candidate_speedup_by_total"]
    geometric_speedup = payload["candidate_geometric_speedup"]
    print(
        f"coverage {payload['baseline_correct']}/{len(rows)} -> "
        f"{payload['candidate_correct']}/{len(rows)}; "
        f"common-total speedup {total_speedup:.4f}x; "
        f"all-total speedup {payload['candidate_all_speedup_by_total']:.4f}x; "
        f"geomean {geometric_speedup:.4f}x"
        if total_speedup is not None and geometric_speedup is not None
        else f"coverage {payload['baseline_correct']}/{len(rows)} -> "
        f"{payload['candidate_correct']}/{len(rows)}; no common-correct timing"
    )
    if wrong_answers:
        return 2
    return 3 if payload["execution_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
