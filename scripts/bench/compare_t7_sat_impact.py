#!/usr/bin/env python3
"""Run the local same-binary T7 off/on ABBA contract without scheduling work."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "campaigns" / "t7-sat-impact-2026-07.json"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MANIFEST = _load(
    "t7_compare_manifest",
    ROOT / "scripts" / "bench" / "build_t7_sat_impact_manifest.py",
)
VALIDATOR = _load(
    "t7_compare_validator",
    ROOT / "scripts" / "cert" / "validate_t7_transcript.py",
)
T2 = MANIFEST.T2


JOURNAL_SCHEMA = "t7-sat-impact-journal-v1"
SUMMARY_SCHEMA = "t7-sat-impact-run-summary-v1"
ARMS = ("off", "on")
REPEATS = 4


class CompareError(RuntimeError):
    """Raised when the preregistered local contract cannot be executed safely."""


def strict_json(path: Path, context: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=T2._reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, T2.ManifestError) as error:
        raise CompareError(f"cannot read {context} {path}: {error}") from error
    if type(value) is not dict:
        raise CompareError(f"{context} must be a JSON object")
    if T2.canonical_bytes(value) != raw.encode("utf-8"):
        raise CompareError(f"{context} is not canonical JSON")
    return value


def verify_self_hash(value: Mapping[str, Any], key: str, context: str) -> None:
    expected = value.get(key)
    if type(expected) is not str:
        raise CompareError(f"{context} lacks {key}")
    payload = dict(value)
    payload[key] = ""
    actual = T2.sha256_bytes(T2.canonical_bytes(payload))
    if actual != expected:
        raise CompareError(f"{context} {key} mismatch")


def load_contract() -> dict[str, Any]:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    if value.get("schema_version") != "t7-sat-impact-contract-v1":
        raise CompareError("T7 contract schema mismatch")
    if value.get("repeats_per_arm") != REPEATS or value.get("ordering") != "ABBA":
        raise CompareError("T7 contract no longer specifies four-repeat ABBA")
    return value


def load_rows(path: Path, stage: str) -> list[dict[str, Any]]:
    rows = T2.load_manifest(path)
    if len(rows) != 24:
        raise CompareError(f"T7 manifest must contain exactly 24 rows, got {len(rows)}")
    populations = Counter(row.get("t7_population") for row in rows)
    if populations != {"M3": 3, "T9": 9, "A12": 12}:
        raise CompareError(f"T7 population mismatch: {dict(populations)}")
    for index, row in enumerate(rows):
        try:
            MANIFEST.validate_output_row(row, index)
        except MANIFEST.T7ManifestError as error:
            raise CompareError(str(error)) from error
    targets = tuple(
        (row["relative_path"], row["status"]) for row in rows[: len(T2.TARGETS)]
    )
    if targets != T2.TARGETS:
        raise CompareError("T7 manifest target rows differ from the exact T2 rows")
    if tuple(row["relative_path"] for row in rows if row["t7_population"] == "M3") != MANIFEST.M3_PATHS:
        raise CompareError("T7 manifest M3 sources differ from the exact opportunity rows")
    if stage == "full":
        return rows
    m3 = [row for row in rows if row["t7_population"] == "M3"]
    a12 = min(
        (row for row in rows if row["t7_population"] == "A12"),
        key=lambda row: row["relative_path"],
    )
    selected = [*m3, a12]
    if len(selected) != 4:
        raise CompareError("T7 canary selection did not produce exactly four sources")
    return selected


def validate_opportunity_gate(path: Path, manifest: Path) -> dict[str, Any]:
    report = strict_json(path, "opportunity gate")
    verify_self_hash(report, "summary_sha256", "opportunity gate")
    if report.get("schema_version") != "t7-shadow-opportunity-gate-v1":
        raise CompareError("opportunity gate schema mismatch")
    if report.get("status") != "ready" or report.get("qualifying_sources", 0) < 2:
        raise CompareError("opportunity gate did not qualify at least two M3 sources")
    if report.get("manifest_sha256") != T2.sha256_file(manifest):
        raise CompareError("opportunity gate was not bound to this T7 manifest")
    return report


def abba_arms(repeat: int) -> tuple[str, str]:
    return ARMS if repeat % 2 == 0 else tuple(reversed(ARMS))


def clean_environment(arm: str, transcript: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EUF_VIPER_")
    }
    environment.update(
        {
            "EUF_VIPER_BACKEND": "cadical-rollback",
            "EUF_VIPER_PROFILE": "1",
            "EUF_VIPER_T7_EXPLANATION": arm,
            "EUF_VIPER_T7_TRANSCRIPT": str(transcript),
        }
    )
    return environment


class JournalWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: Any = None
        self.last_hash: str | None = None

    def __enter__(self) -> "JournalWriter":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("xb")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def append(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.handle is None:
            raise CompareError("journal is not open")
        record = dict(value)
        record["previous_record_sha256"] = self.last_hash
        record["record_sha256"] = T2.sha256_bytes(T2.canonical_bytes(record))
        self.handle.write(T2.canonical_bytes(record))
        self.handle.flush()
        os.fsync(self.handle.fileno())
        self.last_hash = record["record_sha256"]
        return record


def result_token(stdout: bytes) -> str:
    lines = stdout.decode("utf-8", errors="replace").splitlines()
    return lines[0].strip().lower() if lines else "missing"


def run_observation(
    *,
    solver: Path,
    source: Path,
    row: Mapping[str, Any],
    arm: str,
    transcript: Path,
    timeout_s: float,
    drat_trim: Path | None,
    proof_cache: Path | None,
    require_proofs: bool,
) -> dict[str, Any]:
    started = time.monotonic_ns()
    timed_out = False
    spawn_error: str | None = None
    try:
        completed = subprocess.run(
            [str(solver), "solve", "--stats", str(source)],
            env=clean_environment(arm, transcript),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        exit_code = None
        stdout = error.stdout or b""
        stderr = error.stderr or b""
    except OSError as error:
        exit_code = None
        stdout = b""
        stderr = b""
        spawn_error = str(error)
    wall_time_ns = time.monotonic_ns() - started
    token = result_token(stdout)
    if spawn_error is not None or timed_out or exit_code not in {0, 3}:
        outcome = "error"
    elif token not in {"sat", "unsat", "unsupported"}:
        outcome = "missing"
    elif token != row["status"]:
        outcome = "wrong" if token in {"sat", "unsat"} else "error"
    else:
        outcome = "correct"

    validation: dict[str, Any] | None = None
    validation_error: str | None = None
    transcript_summary: dict[str, Any] | None = None
    transcript_conflicts: list[dict[str, Any]] = []
    if transcript.is_file():
        try:
            validation = VALIDATOR.validate_transcript(
                source,
                transcript,
                drat_trim=drat_trim,
                proof_cache=proof_cache,
                proof_producer=solver if proof_cache is not None else None,
                require_unsat_proof=require_proofs,
            )
            records = VALIDATOR.load_chain(transcript)
            transcript_conflicts = records[1:-1]
            transcript_summary = records[-1]
        except (OSError, VALIDATOR.T7TranscriptError) as error:
            validation_error = str(error)
    else:
        validation_error = "transcript is missing"
    return {
        "arm": arm,
        "certificate_status": (
            validation["certificate_status"] if validation is not None else "failed"
        ),
        "exit_code": exit_code,
        "expected_status": row["status"],
        "outcome": outcome,
        "relative_path": row["relative_path"],
        "result": token,
        "source_bytes": row["bytes"],
        "source_path": str(source),
        "source_sha256": row["sha256"],
        "spawn_error": spawn_error,
        "stderr_sha256": T2.sha256_bytes(stderr),
        "stdout_sha256": T2.sha256_bytes(stdout),
        "t7_conflicts": transcript_conflicts,
        "t7_summary": transcript_summary,
        "timed_out": timed_out,
        "transcript_path": str(transcript),
        "transcript_sha256": (
            T2.sha256_file(transcript) if transcript.is_file() else None
        ),
        "transcript_validation": validation,
        "validation_error": validation_error,
        "wall_time_ns": wall_time_ns,
    }


def run_contract(
    *,
    solver: Path,
    manifest: Path,
    opportunity_gate: Path,
    stage: str,
    journal: Path,
    summary_path: Path,
    transcript_root: Path,
    corpus_root: Path | None,
    timeout_s: float,
    drat_trim: Path | None,
    proof_cache: Path | None,
    require_proofs: bool,
) -> dict[str, Any]:
    if stage not in {"canary", "full"}:
        raise CompareError("stage must be canary or full")
    if not require_proofs or drat_trim is None or proof_cache is None:
        raise CompareError("T7 ABBA runs require independent UNSAT proof verification")
    contract = load_contract()
    if not solver.is_file():
        raise CompareError(f"solver is missing: {solver}")
    rows = load_rows(manifest, stage)
    gate = validate_opportunity_gate(opportunity_gate, manifest)
    if gate.get("binary_sha256") != T2.sha256_file(solver):
        raise CompareError("opportunity gate was produced by a different solver binary")
    for row in rows:
        T2.verify_source(row, manifest, corpus_root)
    if transcript_root.exists():
        raise CompareError(f"transcript root already exists: {transcript_root}")
    transcript_root.mkdir(parents=True)
    observations: list[dict[str, Any]] = []
    expected = len(rows) * len(ARMS) * REPEATS
    with JournalWriter(journal) as writer:
        plan = writer.append(
            {
                "arms": list(ARMS),
                "binary": str(solver.resolve()),
                "binary_sha256": T2.sha256_file(solver),
                "contract_sha256": T2.sha256_file(CONTRACT),
                "expected_observations": expected,
                "kind": "plan",
                "manifest": str(manifest.resolve()),
                "manifest_sha256": T2.sha256_file(manifest),
                "opportunity_gate_sha256": T2.sha256_file(opportunity_gate),
                "ordering": "ABBA",
                "proofs_required": require_proofs,
                "repeats": REPEATS,
                "schema": JOURNAL_SCHEMA,
                "sources": len(rows),
                "stage": stage,
                "timeout_s": timeout_s,
            }
        )
        sequence = 0
        for row in rows:
            source = T2.source_path_for(row, manifest, corpus_root)
            for repeat in range(REPEATS):
                for order_slot, arm in enumerate(abba_arms(repeat)):
                    transcript = transcript_root / f"{row['manifest_index']}-{repeat}-{arm}.jsonl"
                    observation = run_observation(
                        solver=solver,
                        source=source,
                        row=row,
                        arm=arm,
                        transcript=transcript,
                        timeout_s=timeout_s,
                        drat_trim=drat_trim,
                        proof_cache=proof_cache,
                        require_proofs=require_proofs,
                    )
                    observation.update(
                        {
                            "kind": "observation",
                            "manifest_index": row["manifest_index"],
                            "order_slot": order_slot,
                            "population": row["t7_population"],
                            "repeat": repeat,
                            "schema": JOURNAL_SCHEMA,
                            "sequence": sequence,
                        }
                    )
                    observations.append(writer.append(observation))
                    sequence += 1
        chain_head = writer.last_hash
    if len(observations) != expected or chain_head is None:
        raise CompareError("ABBA runner did not produce the expected complete journal")
    payload: dict[str, Any] = {
        "binary_sha256": plan["binary_sha256"],
        "certificate_status_counts": dict(
            sorted(Counter(row["certificate_status"] for row in observations).items())
        ),
        "expected_observations": expected,
        "journal": str(journal.resolve()),
        "journal_chain_head": chain_head,
        "journal_sha256": T2.sha256_file(journal),
        "manifest_sha256": plan["manifest_sha256"],
        "observations": len(observations),
        "outcome_counts": dict(
            sorted(Counter(row["outcome"] for row in observations).items())
        ),
        "plan_record_sha256": plan["record_sha256"],
        "schema_version": SUMMARY_SCHEMA,
        "stage": stage,
        "summary_sha256": "",
    }
    payload["summary_sha256"] = T2.sha256_bytes(T2.canonical_bytes(payload))
    T2.atomic_write(summary_path, T2.canonical_bytes(payload))
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solver", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--opportunity-gate", type=Path, required=True)
    parser.add_argument("--stage", choices=("canary", "full"), required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--transcript-root", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--timeout-s", type=float, default=120.0)
    parser.add_argument("--drat-trim", type=Path)
    parser.add_argument("--proof-cache", type=Path)
    parser.add_argument("--require-proofs", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout_s <= 0 or not math.isfinite(args.timeout_s):
        parser.error("--timeout-s must be finite and positive")
    if args.journal.exists() or args.summary.exists() or args.transcript_root.exists():
        parser.error("output artifacts already exist")
    if (args.drat_trim is None) != (args.proof_cache is None):
        parser.error("--drat-trim and --proof-cache must be supplied together")
    if not args.require_proofs or args.proof_cache is None:
        parser.error(
            "the T7 ABBA contract requires --require-proofs, --drat-trim, and --proof-cache"
        )
    try:
        report = run_contract(
            solver=args.solver,
            manifest=args.manifest,
            opportunity_gate=args.opportunity_gate,
            stage=args.stage,
            journal=args.journal,
            summary_path=args.summary,
            transcript_root=args.transcript_root,
            corpus_root=args.corpus_root,
            timeout_s=args.timeout_s,
            drat_trim=args.drat_trim,
            proof_cache=args.proof_cache,
            require_proofs=args.require_proofs,
        )
    except (OSError, CompareError, T2.ManifestError) as error:
        print(f"T7 comparison failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
