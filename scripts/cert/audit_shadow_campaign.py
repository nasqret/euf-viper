#!/usr/bin/env python3
"""Audit a complete sharded certificate-shadow campaign without rerunning work."""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import math
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
ANALYZER_PATH = ROOT / "scripts" / "bench" / "analyze_campaign.py"
SHADOW_PATH = ROOT / "scripts" / "cert" / "shadow_campaign.py"


class ShadowAuditError(ValueError):
    """Raised when shadow evidence is missing, inconsistent, or incomplete."""


def _load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ShadowAuditError(f"cannot import {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


analyzer = _load_module("shadow_audit_analyzer", ANALYZER_PATH)
shadow = _load_module("shadow_audit_runner", SHADOW_PATH)


def _resolved_file(path: Path, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ShadowAuditError(f"cannot resolve {label} {path}: {error}") from error
    if not resolved.is_file() or resolved.is_symlink():
        raise ShadowAuditError(f"{label} must be a regular non-symlink file: {resolved}")
    return resolved


def _resolved_directory(path: Path, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ShadowAuditError(f"cannot resolve {label} {path}: {error}") from error
    if not resolved.is_dir() or resolved.is_symlink():
        raise ShadowAuditError(
            f"{label} must be a regular non-symlink directory: {resolved}"
        )
    return resolved


def _read_canonical_json(path: Path, label: str) -> dict[str, Any]:
    path = _resolved_file(path, label)
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ShadowAuditError(f"{label} is not ASCII: {error}") from error
    try:
        value = shadow._strict_json(text, label)
    except shadow.ShadowError as error:
        raise ShadowAuditError(str(error)) from error
    if type(value) is not dict or shadow.canonical_bytes(value) != raw:
        raise ShadowAuditError(f"{label} is not one canonical JSON object")
    return value


def _checker_environment() -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "TZ": "UTC",
    }


def audit_shadow_shard(
    lock_path: Path,
    raw_path: Path,
    *,
    output_directory: Path,
    binary: str | Path | None = None,
    checker: str | Path = shadow.DEFAULT_CHECKER,
    drat_trim: str | Path | None = None,
    corpus_root: Path | None = None,
    timeout_s: float = 60.0,
    checker_timeout_s: float | None = None,
    timeout_grace_s: float = 0.25,
    max_theory_rounds: int | None = None,
) -> dict[str, Any]:
    """Reconstruct and validate one completed source-shard shadow journal."""

    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ShadowAuditError("timeout must be finite and positive")
    if checker_timeout_s is None:
        checker_timeout_s = timeout_s
    if not math.isfinite(checker_timeout_s) or checker_timeout_s <= 0:
        raise ShadowAuditError("checker timeout must be finite and positive")
    if not math.isfinite(timeout_grace_s) or timeout_grace_s < 0:
        raise ShadowAuditError("timeout grace must be finite and non-negative")
    if max_theory_rounds is not None and (
        type(max_theory_rounds) is not int or max_theory_rounds < 1
    ):
        raise ShadowAuditError("max theory rounds must be a positive integer")

    lock_path = _resolved_file(lock_path, "source shard lock")
    raw_path = _resolved_file(raw_path, "source shard raw evidence")
    output_directory = _resolved_directory(output_directory, "shadow output")
    if corpus_root is not None:
        corpus_root = _resolved_directory(corpus_root, "corpus root")

    try:
        campaign = shadow.load_validated_campaign(lock_path, raw_path)
        works = shadow.derive_work_records(
            campaign, lock_path, corpus_root=corpus_root
        )
        solver = shadow._candidate_solver(campaign["lock"])
        solver_path = shadow.resolve_executable(
            binary or solver["binary"], "euf-viper binary"
        )
        if shadow.sha256_file(solver_path) != solver["sha256"]:
            raise ShadowAuditError("euf-viper binary SHA-256 mismatch")
        checker_path = shadow.resolve_executable(checker, "certificate checker")
        drat_path = (
            shadow.resolve_executable(drat_trim, "drat-trim")
            if drat_trim is not None
            else None
        )
        if drat_path is None and any(
            work["expected_result"] == "unsat" for work in works
        ):
            raise ShadowAuditError("drat-trim is required for selected UNSAT work")

        certify_environment = dict(campaign["lock"]["execution"]["environment"])
        certify_environment.update(solver["environment"])
        checker_environment = _checker_environment()
        plan = shadow.build_plan_record(
            campaign,
            works,
            works,
            solver_path=solver_path,
            checker_path=checker_path,
            drat_trim_path=drat_path,
            corpus_root=corpus_root,
            timeout_s=timeout_s,
            checker_timeout_s=checker_timeout_s,
            timeout_grace_s=timeout_grace_s,
            max_theory_rounds=max_theory_rounds,
            shard_index=0,
            shard_count=1,
            certify_environment=certify_environment,
            checker_environment=checker_environment,
        )
        journal_path = output_directory / "shard-0000-of-0001.journal.jsonl"
        summary_path = output_directory / "shard-0000-of-0001.summary.json"
        _resolved_file(journal_path, "shadow journal")
        declared_summary = _read_canonical_json(summary_path, "shadow summary")

        snapshots: dict[Path, str] = {
            lock_path: campaign["lock_file_sha256"],
            raw_path: campaign["raw_sha256"],
            solver_path: solver["sha256"],
            checker_path: plan["checker"]["sha256"],
        }
        if drat_path is not None:
            snapshots[drat_path] = plan["drat_trim"]["sha256"]
        for work in works:
            snapshots[Path(work["source_path"])] = work["source_sha256"]
        shadow.assert_unchanged(snapshots)

        with shadow.Journal(journal_path, plan) as journal:
            latest, _ = shadow.validate_journal_attempts(
                journal, works, plan, output_directory
            )
            missing = [
                work["relative_path"]
                for work in works
                if work["work_sha256"] not in latest
            ]
            failed = [
                work["relative_path"]
                for work in works
                if work["work_sha256"] in latest
                and latest[work["work_sha256"]]["verified"] is not True
            ]
            if missing or failed:
                raise ShadowAuditError(
                    f"shadow shard is incomplete: missing={missing!r}, failed={failed!r}"
                )
            expected_summary = shadow.build_summary(
                journal, plan, works, journal_path=journal_path
            )
        shadow.assert_unchanged(snapshots)
    except shadow.ShadowError as error:
        raise ShadowAuditError(str(error)) from error

    if declared_summary != expected_summary:
        raise ShadowAuditError("shadow summary differs from reconstructed journal state")
    if expected_summary["status"] != "complete":
        raise ShadowAuditError("shadow summary is not complete")
    return expected_summary


def _global_expected_paths(campaign: Mapping[str, Any]) -> list[str]:
    candidate = shadow._candidate_solver(campaign["lock"])
    budgets = [float(value) for value in campaign["lock"]["budgets_s"]]
    selected: list[str] = []
    for instance in campaign["lock"]["corpus"]["instances"]:
        path = instance["relative_path"]
        if any(
            (path, budget, candidate["id"]) in campaign["observations"]
            and campaign["observations"][(path, budget, candidate["id"])][
                "result"
            ]
            == instance["status"]
            for budget in budgets
        ):
            selected.append(path)
    return selected


def audit_sharded_shadow_campaign(
    parent_lock: Path,
    shard_lock_directory: Path,
    shard_results_root: Path,
    *,
    shadow_output_root: Path,
    binary: str | Path | None = None,
    checker: str | Path = shadow.DEFAULT_CHECKER,
    drat_trim: str | Path | None = None,
    corpus_root: Path | None = None,
    timeout_s: float = 60.0,
    checker_timeout_s: float | None = None,
    timeout_grace_s: float = 0.25,
    max_theory_rounds: int | None = None,
) -> dict[str, Any]:
    """Validate source shards, every shadow journal, and their exact union."""

    parent_lock = _resolved_file(parent_lock, "parent lock")
    shard_lock_directory = _resolved_directory(
        shard_lock_directory, "source shard lock directory"
    )
    shard_results_root = _resolved_directory(
        shard_results_root, "source shard results root"
    )
    shadow_output_root = _resolved_directory(
        shadow_output_root, "shadow output root"
    )
    try:
        shard_pairs = analyzer.discover_shard_pairs(
            shard_lock_directory, shard_results_root
        )
        campaign = analyzer.load_sharded_locked_campaign(parent_lock, shard_pairs)
    except analyzer.CampaignInputError as error:
        raise ShadowAuditError("; ".join(error.errors)) from error

    expected_paths = _global_expected_paths(campaign)
    actual_paths: list[str] = []
    verified_records: list[dict[str, Any]] = []
    result_counts: collections.Counter[str] = collections.Counter()
    historical_failures: collections.Counter[str] = collections.Counter()
    shard_records: list[dict[str, Any]] = []
    seen_indices: set[int] = set()
    for lock_path, raw_path in shard_pairs:
        try:
            child = shadow.load_validated_campaign(lock_path, raw_path)
        except shadow.ShadowError as error:
            raise ShadowAuditError(str(error)) from error
        shard = child["lock"].get("shard")
        if type(shard) is not dict or type(shard.get("index")) is not int:
            raise ShadowAuditError(f"source child lock has no shard index: {lock_path}")
        index = shard["index"]
        if index in seen_indices:
            raise ShadowAuditError(f"duplicate source shard index {index}")
        seen_indices.add(index)
        output_directory = shadow_output_root / f"source-shard-{index:04d}"
        summary = audit_shadow_shard(
            lock_path,
            raw_path,
            output_directory=output_directory,
            binary=binary,
            checker=checker,
            drat_trim=drat_trim,
            corpus_root=corpus_root,
            timeout_s=timeout_s,
            checker_timeout_s=checker_timeout_s,
            timeout_grace_s=timeout_grace_s,
            max_theory_rounds=max_theory_rounds,
        )
        paths = [record["relative_path"] for record in summary["verified"]]
        actual_paths.extend(paths)
        verified_records.extend(
            {
                **record,
                "source_shard_index": index,
            }
            for record in summary["verified"]
        )
        result_counts.update(summary["verified_results"])
        historical_failures.update(summary["historical_failure_counts"])
        summary_path = output_directory / "shard-0000-of-0001.summary.json"
        journal_path = output_directory / "shard-0000-of-0001.journal.jsonl"
        shard_records.append(
            {
                "source_shard_index": index,
                "source_lock": str(lock_path),
                "source_lock_sha256": child["lock_file_sha256"],
                "source_raw": str(raw_path),
                "source_raw_sha256": child["raw_sha256"],
                "shadow_output": str(output_directory),
                "summary_sha256": shadow.sha256_file(summary_path),
                "journal_sha256": shadow.sha256_file(journal_path),
                "verified_instances": len(paths),
            }
        )

    if len(actual_paths) != len(set(actual_paths)):
        raise ShadowAuditError("a candidate instance appears in multiple shadow shards")
    if set(actual_paths) != set(expected_paths):
        missing = sorted(set(expected_paths) - set(actual_paths))
        extra = sorted(set(actual_paths) - set(expected_paths))
        raise ShadowAuditError(
            f"global certificate selection mismatch: missing={missing!r}, extra={extra!r}"
        )
    shard_records.sort(key=lambda record: record["source_shard_index"])
    verified_records.sort(
        key=lambda record: (record["relative_path"], record["work_sha256"])
    )
    evidence_sha256 = hashlib.sha256(shadow.canonical_bytes(shard_records)).hexdigest()
    selection_sha256 = hashlib.sha256(
        shadow.canonical_bytes(
            [
                {
                    "relative_path": record["relative_path"],
                    "result": record["result"],
                    "work_sha256": record["work_sha256"],
                }
                for record in verified_records
            ]
        )
    ).hexdigest()
    return {
        "schema_version": 1,
        "status": "complete",
        "parent_lock": str(parent_lock),
        "parent_lock_file_sha256": campaign["lock_file_sha256"],
        "parent_lock_sha256": campaign["lock"]["lock_sha256"],
        "source_shard_bundle_sha256": campaign["shard_bundle_sha256"],
        "source_shards": len(shard_records),
        "budget_s": float(campaign["lock"]["budgets_s"][0]),
        "selected_instances": len(expected_paths),
        "verified_instances": len(actual_paths),
        "verified_results": dict(sorted(result_counts.items())),
        "selection_sha256": selection_sha256,
        "historical_failure_counts": dict(sorted(historical_failures.items())),
        "evidence_sha256": evidence_sha256,
        "verified": verified_records,
        "shards": shard_records,
    }


def _positive_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return value


def _nonnegative_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("must be finite and non-negative")
    return value


def _positive_int(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-lock", type=Path, required=True)
    parser.add_argument("--shard-lock-dir", type=Path, required=True)
    parser.add_argument("--shard-results-root", type=Path, required=True)
    parser.add_argument("--shadow-output-root", type=Path, required=True)
    parser.add_argument("--binary")
    parser.add_argument("--checker", default=str(shadow.DEFAULT_CHECKER))
    parser.add_argument("--drat-trim")
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--timeout", type=_positive_float, default=60.0)
    parser.add_argument("--checker-timeout", type=_positive_float)
    parser.add_argument("--timeout-grace", type=_nonnegative_float, default=0.25)
    parser.add_argument("--max-theory-rounds", type=_positive_int)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = audit_sharded_shadow_campaign(
            args.parent_lock,
            args.shard_lock_dir,
            args.shard_results_root,
            shadow_output_root=args.shadow_output_root,
            binary=args.binary,
            checker=args.checker,
            drat_trim=args.drat_trim,
            corpus_root=args.corpus_root,
            timeout_s=args.timeout,
            checker_timeout_s=args.checker_timeout,
            timeout_grace_s=args.timeout_grace,
            max_theory_rounds=args.max_theory_rounds,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        shadow._atomic_write(args.out, shadow.canonical_bytes(result))
    except (ShadowAuditError, shadow.ShadowError, OSError) as error:
        parser.exit(2, f"certificate shadow audit failed: {error}\n")
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
