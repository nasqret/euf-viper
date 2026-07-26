#!/usr/bin/env python3
"""Build an exact, audited solver-gap map from a sharded EUF campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_euf_dashboard as dashboard  # noqa: E402
import import_sharded_dashboard as importer  # noqa: E402


DECISIVE_RESULTS = {"sat", "unsat"}
SCHEMA_VERSION = "euf-viper.solver-gap-cohorts.v1"


class GapAnalysisError(ValueError):
    """Raised when an exact solver-gap report cannot be constructed."""


def _safe_sum(values: Iterable[float]) -> float:
    result = math.fsum(values)
    if not math.isfinite(result):
        raise GapAnalysisError("timing sum is not finite")
    return result


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _geometric_mean(values: Sequence[float]) -> float | None:
    if not values:
        return None
    if any(value <= 0.0 or not math.isfinite(value) for value in values):
        raise GapAnalysisError("geometric mean input is not finite and positive")
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def _factor(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator is None or denominator <= 0.0:
        return None
    result = numerator / denominator
    if not math.isfinite(result):
        raise GapAnalysisError("timing factor is not finite")
    return result


def _size_bucket(byte_count: int) -> str:
    boundaries = (
        (4 * 1024, "lt-4-kib"),
        (16 * 1024, "4-16-kib"),
        (64 * 1024, "16-64-kib"),
        (256 * 1024, "64-256-kib"),
        (1024 * 1024, "256-kib-1-mib"),
        (4 * 1024 * 1024, "1-4-mib"),
    )
    for upper, label in boundaries:
        if byte_count < upper:
            return label
    return "ge-4-mib"


def _generator_class(relative_path: str) -> str:
    path = PurePosixPath(relative_path)
    parent = path.parent.name or "root"
    stem = path.stem
    shaped: list[str] = []
    in_digits = False
    for character in stem:
        if character.isdigit():
            if not in_digits:
                shaped.append("#")
            in_digits = True
        else:
            shaped.append(character)
            in_digits = False
    return f"{parent}/{' '.join(''.join(shaped).split())}"


def _solved(observation: Mapping[str, Any]) -> bool:
    return observation["result"] in DECISIVE_RESULTS


def _observation_row(observation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "result": observation["result"],
        "wall_time_s": (
            float(observation["wall_time_s"]) if _solved(observation) else None
        ),
    }


def _cohort_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    candidate_solved = [row for row in rows if _solved(row["candidate"])]
    baseline_solved = [row for row in rows if _solved(row["baseline"])]
    common = [
        row
        for row in rows
        if _solved(row["candidate"]) and _solved(row["baseline"])
    ]
    candidate_only = [
        row
        for row in rows
        if _solved(row["candidate"]) and not _solved(row["baseline"])
    ]
    baseline_only = [
        row
        for row in rows
        if _solved(row["baseline"]) and not _solved(row["candidate"])
    ]
    candidate_times = [float(row["candidate"]["wall_time_s"]) for row in common]
    baseline_times = [float(row["baseline"]["wall_time_s"]) for row in common]
    candidate_total = _safe_sum(candidate_times)
    baseline_total = _safe_sum(baseline_times)
    candidate_geometric = _geometric_mean(candidate_times)
    baseline_geometric = _geometric_mean(baseline_times)
    return {
        "instances": len(rows),
        "candidate_solved": len(candidate_solved),
        "baseline_solved": len(baseline_solved),
        "common_solved": len(common),
        "candidate_only": len(candidate_only),
        "baseline_only": len(baseline_only),
        "neither_solved": len(rows) - len(common) - len(candidate_only) - len(baseline_only),
        "common_candidate_total_s": candidate_total,
        "common_baseline_total_s": baseline_total,
        "common_total_factor": _factor(baseline_total, candidate_total),
        "common_candidate_geometric_s": candidate_geometric,
        "common_baseline_geometric_s": baseline_geometric,
        "common_geometric_factor": _factor(baseline_geometric, candidate_geometric),
    }


def _group_summaries(
    rows: Sequence[Mapping[str, Any]], key: str
) -> list[dict[str, Any]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row[key])].append(row)
    return [
        {"id": identifier, **_cohort_summary(grouped[identifier])}
        for identifier in sorted(grouped)
    ]


def _gap_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "relative_path": row["relative_path"],
        "family": row["family"],
        "expected_status": row["expected_status"],
        "bytes": row["bytes"],
        "split": row["split"],
        "generator_lineage": row["generator_lineage"],
        "generator_class": row["generator_class"],
        "size_bucket": row["size_bucket"],
        "sha256": row["sha256"],
        "candidate": _observation_row(row["candidate"]),
        "baseline": _observation_row(row["baseline"]),
    }


def build_report(
    campaign: Mapping[str, Any],
    audit: Mapping[str, Any],
    analysis: Mapping[str, Any],
    *,
    candidate_id: str,
    baseline_ids: Sequence[str],
    budget_s: float,
    audit_path: str,
    audit_sha256: str,
) -> dict[str, Any]:
    lock = campaign["lock"]
    known_solvers = {solver["id"] for solver in lock["solvers"]}
    requested = {candidate_id, *baseline_ids}
    if candidate_id in baseline_ids:
        raise GapAnalysisError("candidate cannot also be a baseline")
    if missing := sorted(requested - known_solvers):
        raise GapAnalysisError(f"requested solvers are absent from the lock: {missing!r}")
    if budget_s not in {float(value) for value in lock["budgets_s"]}:
        raise GapAnalysisError(f"budget {budget_s} is absent from the lock")
    if len(set(baseline_ids)) != len(baseline_ids):
        raise GapAnalysisError("baseline IDs must be unique")

    metadata: dict[str, dict[str, Any]] = {}
    for instance in lock["corpus"]["instances"]:
        relative_path = instance["relative_path"]
        byte_count = instance.get("bytes")
        if type(byte_count) is not int or byte_count < 0:
            raise GapAnalysisError(f"invalid byte count for {relative_path!r}")
        metadata[relative_path] = {
            "relative_path": relative_path,
            "family": instance["family"],
            "expected_status": instance["status"],
            "bytes": byte_count,
            "split": instance.get("split", "unknown"),
            "generator_lineage": instance.get("lineage", "unknown"),
            "generator_class": _generator_class(relative_path),
            "size_bucket": _size_bucket(byte_count),
            "sha256": instance["sha256"],
        }

    comparisons: list[dict[str, Any]] = []
    for baseline_id in baseline_ids:
        rows: list[dict[str, Any]] = []
        for relative_path in sorted(metadata):
            rows.append(
                {
                    **metadata[relative_path],
                    "candidate": campaign["observations"][
                        (relative_path, budget_s, candidate_id)
                    ],
                    "baseline": campaign["observations"][
                        (relative_path, budget_s, baseline_id)
                    ],
                }
            )
        candidate_only = [
            _gap_row(row)
            for row in rows
            if _solved(row["candidate"]) and not _solved(row["baseline"])
        ]
        baseline_only = [
            _gap_row(row)
            for row in rows
            if _solved(row["baseline"]) and not _solved(row["candidate"])
        ]
        comparisons.append(
            {
                "baseline_id": baseline_id,
                "overall": _cohort_summary(rows),
                "cohorts": {
                    "family": _group_summaries(rows, "family"),
                    "expected_status": _group_summaries(rows, "expected_status"),
                    "generator_class": _group_summaries(rows, "generator_class"),
                    "size_bucket": _group_summaries(rows, "size_bucket"),
                    "split": _group_summaries(rows, "split"),
                },
                "gaps": {
                    "candidate_only": candidate_only,
                    "baseline_only": baseline_only,
                },
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "candidate_revision": audit["solver_revision"],
        "budget_s": budget_s,
        "corpus": {
            "id": lock["corpus"]["id"],
            "instances": len(lock["corpus"]["instances"]),
            "lock_sha256": lock["lock_sha256"],
        },
        "source": {"path": audit_path, "sha256": audit_sha256},
        "analysis_status": analysis["status"],
        "comparisons": comparisons,
    }


def _format_factor(value: object) -> str:
    return "n/a" if value is None else f"{float(value):.4f}x"


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Current EUF Gap Map",
        "",
        f"Candidate: `{report['candidate_id']}` at `{report['candidate_revision']}`.",
        f"Corpus: `{report['corpus']['id']}`; {report['corpus']['instances']} instances; "
        f"timeout {report['budget_s']:g}s.",
        "",
        "A factor above `1.0x` means the comparator took longer than Viper on "
        "the common solved set.",
        "",
        "## Overall",
        "",
        "| Comparator | Viper solved | Comparator solved | Viper only | Comparator only | Common total | Common geometric |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for comparison in report["comparisons"]:
        overall = comparison["overall"]
        lines.append(
            f"| {comparison['baseline_id']} | {overall['candidate_solved']} | "
            f"{overall['baseline_solved']} | {overall['candidate_only']} | "
            f"{overall['baseline_only']} | "
            f"{_format_factor(overall['common_total_factor'])} | "
            f"{_format_factor(overall['common_geometric_factor'])} |"
        )
    lines.extend(["", "## Family Matrix", ""])
    for comparison in report["comparisons"]:
        lines.extend(
            [
                f"### {comparison['baseline_id']}",
                "",
                "| Family | Instances | Viper | Comparator | Viper only | Comparator only | Total factor | Geometric factor |",
                "|---|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for cohort in comparison["cohorts"]["family"]:
            lines.append(
                f"| {cohort['id']} | {cohort['instances']} | "
                f"{cohort['candidate_solved']} | {cohort['baseline_solved']} | "
                f"{cohort['candidate_only']} | {cohort['baseline_only']} | "
                f"{_format_factor(cohort['common_total_factor'])} | "
                f"{_format_factor(cohort['common_geometric_factor'])} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("preparation_root", type=Path)
    parser.add_argument("campaign_root", type=Path)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--baseline-id", action="append", required=True)
    parser.add_argument("--budget-s", type=float, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--source-path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_argument_parser().parse_args(argv)
    if arguments.shard_count < 1:
        raise SystemExit("error: --shard-count must be positive")
    if not math.isfinite(arguments.budget_s) or arguments.budget_s <= 0.0:
        raise SystemExit("error: --budget-s must be finite and positive")
    preparation = arguments.preparation_root.expanduser().resolve()
    campaign_root = arguments.campaign_root.expanduser().resolve()
    audit_path = campaign_root / "audit-index.json"
    try:
        campaign, audit, analysis = importer.load_verified_campaign(
            preparation, campaign_root, shard_count=arguments.shard_count
        )
        audit_sha256 = _sha256_file(audit_path)
        report = build_report(
            campaign,
            audit,
            analysis,
            candidate_id=arguments.candidate_id,
            baseline_ids=arguments.baseline_id,
            budget_s=arguments.budget_s,
            audit_path=(
                arguments.source_path
                if arguments.source_path is not None
                else str(audit_path)
            ),
            audit_sha256=audit_sha256,
        )
        payload = dashboard.pretty_json_bytes(report)
        _atomic_write(arguments.output.expanduser().resolve(), payload)
        if arguments.markdown_out is not None:
            _atomic_write(
                arguments.markdown_out.expanduser().resolve(),
                render_markdown(report).encode("ascii"),
            )
    except (
        GapAnalysisError,
        importer.ShardedDashboardImportError,
        OSError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    receipt = {
        "comparisons": len(report["comparisons"]),
        "output": str(arguments.output.expanduser().resolve()),
        "output_sha256": hashlib.sha256(payload).hexdigest(),
    }
    print(json.dumps(receipt, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
