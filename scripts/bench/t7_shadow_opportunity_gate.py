#!/usr/bin/env python3
"""Run the one-pass T7 shadow opportunity gate on the exact M3 sources."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MANIFEST = _load(
    "t7_opportunity_manifest",
    ROOT / "scripts" / "bench" / "build_t7_sat_impact_manifest.py",
)
VALIDATOR = _load(
    "t7_opportunity_validator",
    ROOT / "scripts" / "cert" / "validate_t7_transcript.py",
)
T2 = MANIFEST.T2


SCHEMA = "t7-shadow-opportunity-gate-v1"


class OpportunityError(RuntimeError):
    """Raised when the bounded shadow gate cannot be trusted."""


def qualifying_conflicts(records: list[dict[str, Any]]) -> list[int]:
    qualifying: list[int] = []
    for event in records[1:-1]:
        candidates = event["candidates"]
        minimum = event["minimum_width"]
        minimum_clauses = {
            tuple(candidate["clause"])
            for candidate in candidates
            if len(candidate["clause"]) == minimum and candidate["replay_valid"] is True
        }
        if len(minimum_clauses) >= 2 and event["disagreement"] is True:
            qualifying.append(event["event"])
    return qualifying


def clean_environment(transcript: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EUF_VIPER_")
    }
    environment.update(
        {
            "EUF_VIPER_BACKEND": "cadical-rollback",
            "EUF_VIPER_PROFILE": "1",
            "EUF_VIPER_T7_EXPLANATION": "off",
            "EUF_VIPER_T7_TRANSCRIPT": str(transcript),
        }
    )
    return environment


def run_gate(
    *,
    solver: Path,
    manifest: Path,
    output: Path,
    corpus_root: Path | None,
    timeout_s: float,
) -> dict[str, Any]:
    if not solver.is_file():
        raise OpportunityError(f"solver is missing: {solver}")
    rows = T2.load_manifest(manifest)
    by_path = {row["relative_path"]: row for row in rows}
    selected: list[dict[str, Any]] = []
    for path in MANIFEST.M3_PATHS:
        row = by_path.get(path)
        if row is None or row.get("t7_population") != "M3":
            raise OpportunityError(f"exact M3 row is absent or misclassified: {path}")
        T2.verify_source(row, manifest, corpus_root)
        selected.append(row)
    output.mkdir(parents=True, exist_ok=False)
    observations: list[dict[str, Any]] = []
    for index, row in enumerate(selected):
        source = T2.source_path_for(row, manifest, corpus_root)
        transcript = output / f"m3-{index}.t7.jsonl"
        started = time.monotonic_ns()
        try:
            completed = subprocess.run(
                [str(solver), "solve", "--stats", str(source)],
                env=clean_environment(transcript),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise OpportunityError(f"M3 source timed out: {row['relative_path']}") from error
        wall_time_ns = time.monotonic_ns() - started
        stdout = completed.stdout
        stderr = completed.stderr
        token = stdout.decode("utf-8", errors="replace").strip().splitlines()
        result = token[0].strip().lower() if token else "missing"
        if completed.returncode != 0 or result != row["status"]:
            raise OpportunityError(
                f"M3 solve failed for {row['relative_path']}: "
                f"exit={completed.returncode} result={result!r} expected={row['status']!r}"
            )
        validation = VALIDATOR.validate_transcript(source, transcript)
        records = VALIDATOR.load_chain(transcript)
        conflicts = qualifying_conflicts(records)
        observations.append(
            {
                "chain_sha256": validation["chain_sha256"],
                "qualifying_conflicts": conflicts,
                "qualified": bool(conflicts),
                "relative_path": row["relative_path"],
                "result": result,
                "source_sha256": row["sha256"],
                "stderr_sha256": T2.sha256_bytes(stderr),
                "stdout_sha256": T2.sha256_bytes(stdout),
                "transcript_sha256": validation["transcript_sha256"],
                "wall_time_ns": wall_time_ns,
            }
        )
    qualifying_sources = sum(observation["qualified"] for observation in observations)
    payload: dict[str, Any] = {
        "binary": str(solver.resolve()),
        "binary_sha256": T2.sha256_file(solver),
        "manifest": str(manifest.resolve()),
        "manifest_sha256": T2.sha256_file(manifest),
        "observations": observations,
        "one_pass_per_source": True,
        "qualifying_sources": qualifying_sources,
        "required_sources": 2,
        "schema_version": SCHEMA,
        "status": "ready" if qualifying_sources >= 2 else "stop",
        "summary_sha256": "",
    }
    payload["summary_sha256"] = T2.sha256_bytes(T2.canonical_bytes(payload))
    T2.atomic_write(output / "opportunity-gate.json", T2.canonical_bytes(payload))
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solver", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--timeout-s", type=float, default=120.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout_s <= 0:
        parser.error("--timeout-s must be positive")
    if args.output.exists():
        parser.error("--output already exists")
    try:
        report = run_gate(
            solver=args.solver,
            manifest=args.manifest,
            output=args.output,
            corpus_root=args.corpus_root,
            timeout_s=args.timeout_s,
        )
    except (OSError, OpportunityError, T2.ManifestError, VALIDATOR.T7TranscriptError) as error:
        print(f"T7 opportunity gate failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
