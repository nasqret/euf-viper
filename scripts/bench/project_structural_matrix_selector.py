#!/usr/bin/env python3
"""Project a structural router from a complete multi-arm matrix and census."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "euf-viper.structural-matrix-projection.v1"


class ProjectionError(ValueError):
    """The matrix, census, or selector is incomplete or inconsistent."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectionError(f"cannot read {context}: {error}") from error
    if type(value) is not dict:
        raise ProjectionError(f"{context} must be a JSON object")
    return value


def verify_matrix_self_hash(matrix: Mapping[str, Any]) -> None:
    expected = matrix.get("audit_sha256")
    if type(expected) is not str or len(expected) != 64:
        raise ProjectionError("matrix audit has no valid self-hash")
    payload = dict(matrix)
    payload["audit_sha256"] = ""
    actual = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    if actual != expected:
        raise ProjectionError(f"matrix audit self-hash mismatch: {actual} != {expected}")


def checked_observation(path: Mapping[str, Any], arm: str) -> dict[str, Any]:
    arms = path.get("arms")
    if type(arms) is not dict or type(arms.get(arm)) is not dict:
        raise ProjectionError(f"path {path.get('relative_path')!r} lacks arm {arm!r}")
    observation = dict(arms[arm])
    if type(observation.get("covered")) is not bool:
        raise ProjectionError(f"path {path.get('relative_path')!r} has invalid coverage")
    elapsed = observation.get("median_time_s")
    if type(elapsed) not in {int, float} or not math.isfinite(float(elapsed)) or elapsed <= 0:
        raise ProjectionError(f"path {path.get('relative_path')!r} has invalid timing")
    return observation


def summarize_projection(
    paths: Sequence[Mapping[str, Any]],
    metrics: Mapping[str, int],
    threshold: int,
    reference: str,
    candidate: str,
    include_paths: bool,
) -> dict[str, Any]:
    selected: list[str] = []
    gains: list[str] = []
    losses: list[str] = []
    common_reference: list[float] = []
    common_hybrid: list[float] = []
    coverage_by_status: Counter[str] = Counter()
    reference_covered = 0
    hybrid_covered = 0

    for path in paths:
        name = str(path["relative_path"])
        reference_observation = checked_observation(path, reference)
        use_candidate = metrics[name] <= threshold
        if use_candidate:
            selected.append(name)
        source = candidate if use_candidate else reference
        hybrid_observation = checked_observation(path, source)
        reference_ok = reference_observation["covered"] is True
        hybrid_ok = hybrid_observation["covered"] is True
        reference_covered += reference_ok
        hybrid_covered += hybrid_ok
        if hybrid_ok:
            coverage_by_status[str(path["expected_status"])] += 1
        if hybrid_ok and not reference_ok:
            gains.append(name)
        if reference_ok and not hybrid_ok:
            losses.append(name)
        if reference_ok and hybrid_ok:
            common_reference.append(float(reference_observation["median_time_s"]))
            common_hybrid.append(float(hybrid_observation["median_time_s"]))

    reference_total = math.fsum(common_reference)
    hybrid_total = math.fsum(common_hybrid)
    ratios = [
        baseline / current
        for baseline, current in zip(common_reference, common_hybrid)
    ]
    report: dict[str, Any] = {
        "threshold": threshold,
        "selected_paths": len(selected),
        "covered_paths": hybrid_covered,
        "coverage": hybrid_covered / len(paths),
        "coverage_by_status": dict(sorted(coverage_by_status.items())),
        "coverage_delta_vs_reference": hybrid_covered - reference_covered,
        "gains_vs_reference": len(gains),
        "losses_vs_reference": len(losses),
        "common_correct": len(common_reference),
        "common_reference_total_time_s": reference_total,
        "common_hybrid_total_time_s": hybrid_total,
        "common_aggregate_speedup_vs_reference": (
            reference_total / hybrid_total if hybrid_total > 0 else None
        ),
        "common_geometric_speedup_vs_reference": (
            math.exp(math.fsum(math.log(value) for value in ratios) / len(ratios))
            if ratios
            else None
        ),
        "timing_wins_vs_reference": sum(
            candidate_time < reference_time
            for reference_time, candidate_time in zip(
                common_reference, common_hybrid
            )
        ),
        "timing_losses_vs_reference": sum(
            reference_time < candidate_time
            for reference_time, candidate_time in zip(
                common_reference, common_hybrid
            )
        ),
        "timing_ties_vs_reference": sum(
            reference_time == candidate_time
            for reference_time, candidate_time in zip(
                common_reference, common_hybrid
            )
        ),
    }
    if include_paths:
        report.update(
            {
                "selected_relative_paths": selected,
                "gain_relative_paths": gains,
                "loss_relative_paths": losses,
            }
        )
    return report


def project(
    matrix: Mapping[str, Any],
    census: Mapping[str, Any],
    metric: str,
    threshold: int,
    candidate: str,
    matrix_sha256: str,
    census_sha256: str,
) -> dict[str, Any]:
    verify_matrix_self_hash(matrix)
    if matrix.get("status") != "complete":
        raise ProjectionError("matrix audit is not complete")
    accounting = matrix.get("accounting")
    if type(accounting) is not dict or accounting.get("wrong_answers") != 0:
        raise ProjectionError("matrix contains wrong answers or invalid accounting")
    if accounting.get("execution_errors") != 0:
        raise ProjectionError("matrix contains execution errors")
    reference = matrix.get("reference_arm")
    arm_order = matrix.get("arm_order")
    if type(reference) is not str or type(arm_order) is not list:
        raise ProjectionError("matrix arm contract is invalid")
    if candidate == reference or candidate not in arm_order:
        raise ProjectionError("candidate arm is absent or equals the reference")

    paths = matrix.get("paths")
    instances = census.get("instances")
    counts = census.get("counts")
    if type(paths) is not list or not paths or type(instances) is not list:
        raise ProjectionError("matrix or census instances are invalid")
    if (
        type(counts) is not dict
        or counts.get("failed_instances") != 0
        or counts.get("successful_instances") != len(paths)
    ):
        raise ProjectionError("finite-structure census is incomplete")

    path_names = [path.get("relative_path") for path in paths if type(path) is dict]
    if len(path_names) != len(paths) or len(set(path_names)) != len(paths):
        raise ProjectionError("matrix paths are invalid or duplicated")
    metrics: dict[str, int] = {}
    for instance in instances:
        if type(instance) is not dict or type(instance.get("metrics")) is not dict:
            raise ProjectionError("census instance is invalid")
        name = instance.get("relative_path")
        value = instance["metrics"].get(metric)
        if type(name) is not str or name in metrics or type(value) is not int or value < 0:
            raise ProjectionError(f"census metric {metric!r} is missing or invalid")
        metrics[name] = value
    if set(metrics) != set(path_names):
        raise ProjectionError("census and matrix path sets differ")

    chosen = summarize_projection(
        paths, metrics, threshold, reference, candidate, include_paths=True
    )
    frontier = [
        summarize_projection(
            paths, metrics, value, reference, candidate, include_paths=False
        )
        for value in sorted(set(metrics.values()))
    ]
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "audit_sha256": "",
        "inputs": {
            "matrix_audit_sha256": matrix_sha256,
            "matrix_self_hash": matrix["audit_sha256"],
            "finite_census_sha256": census_sha256,
        },
        "instances": len(paths),
        "reference_arm": reference,
        "candidate_arm": candidate,
        "selector": {"metric": metric, "operator": "<=", "threshold": threshold},
        "projection": chosen,
        "threshold_frontier": frontier,
        "evidence_boundary": (
            "post-hoc projection from measured arms; requires an exact-binary "
            "confirmation and is not independent holdout evidence"
        ),
    }
    payload["audit_sha256"] = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return payload


def atomic_write_new(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ProjectionError(f"refuse to replace output: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(dict(payload)))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix_audit", type=Path)
    parser.add_argument("finite_census", type=Path)
    parser.add_argument("--candidate-arm", required=True)
    parser.add_argument("--metric", required=True)
    parser.add_argument("--threshold", required=True, type=int)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        matrix = load_json(args.matrix_audit, "matrix audit")
        census = load_json(args.finite_census, "finite census")
        payload = project(
            matrix,
            census,
            args.metric,
            args.threshold,
            args.candidate_arm,
            sha256_file(args.matrix_audit),
            sha256_file(args.finite_census),
        )
        atomic_write_new(args.out, payload)
    except (OSError, ProjectionError, ValueError) as error:
        parser.exit(2, f"structural projection failed: {error}\n")
    projection = payload["projection"]
    print(
        f"audit={payload['audit_sha256']} selected={projection['selected_paths']} "
        f"coverage={projection['covered_paths']}/{payload['instances']} "
        f"delta={projection['coverage_delta_vs_reference']:+d}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
