#!/usr/bin/env python3
"""Build a deterministic euf-viper versus Yices2 opportunity atlas.

The input is the strict CSV schema emitted by ``compare_solvers.py``.  Timing
metrics include only instances solved correctly by both selected solvers.
Coverage gaps are reported separately and never receive timeout-charged times.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


SCHEMA_VERSION = "euf-viper.yices-opportunity-atlas.v1"
CSV_FIELDNAMES = [
    "id",
    "relative_path",
    "expected_status",
    "solver",
    "result",
    "time_s",
    "exit_code",
    "stderr",
]
DECISIVE_RESULTS = frozenset({"sat", "unsat"})
RESULT_RE = re.compile(r"(?:sat|unsat|unknown|timeout|unsupported|exit--?[0-9]+)\Z")
INTEGER_RE = re.compile(r"[+-]?[0-9]+\Z")
QG_DEGREE_RE = re.compile(r"(?:qg|loops)(?P<degree>[0-9]+)\Z")
DEFAULT_TOP_N = (10, 50, 100, 500)


class AtlasError(ValueError):
    """The input cannot support a fail-closed opportunity analysis."""


@dataclass(frozen=True)
class Observation:
    identifier: str
    relative_path: str
    expected_status: str
    solver: str
    result: str
    time_s: float
    exit_code: int
    stderr: str

    @property
    def correct(self) -> bool:
        return self.result == self.expected_status


@dataclass(frozen=True)
class InstancePair:
    relative_path: str
    expected_status: str
    family: str
    qg_degree: str | None
    viper: Observation
    yices: Observation

    @property
    def common_correct(self) -> bool:
        return self.viper.correct and self.yices.correct

    @property
    def deficit_s(self) -> float:
        if not self.common_correct:
            raise AtlasError("coverage-only rows do not have a common timing deficit")
        return self.viper.time_s - self.yices.time_s


def canonical_json_bytes(value: object) -> bytes:
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


def publish_atomic(path: Path, data: bytes) -> None:
    """Durably replace ``path`` without sharing a predictable staging name."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def reject_input_output_alias(source: Path, output: Path) -> None:
    """Reject lexical, symlink, and hard-link aliases before reading input."""
    try:
        source_identity = source.stat()
    except OSError as error:
        raise AtlasError(f"cannot stat {source}: {error}") from error
    try:
        output_identity = output.stat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise AtlasError(f"cannot stat {output}: {error}") from error
    if os.path.samestat(source_identity, output_identity):
        raise AtlasError("input CSV and output JSON must be different files")


def _clean_float(value: float) -> float:
    if not math.isfinite(value):
        raise AtlasError("internal metric is non-finite")
    return 0.0 if value == 0.0 else value


def _parse_time(value: str, *, source: Path, line_number: int) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise AtlasError(
            f"{source}:{line_number}: malformed time_s {value!r}"
        ) from error
    if not math.isfinite(parsed):
        raise AtlasError(f"{source}:{line_number}: time_s must be finite")
    if parsed < 0.0:
        raise AtlasError(f"{source}:{line_number}: time_s must be nonnegative")
    return _clean_float(parsed)


def _validate_relative_path(value: str, *, source: Path, line_number: int) -> str:
    if not value or "\\" in value:
        raise AtlasError(
            f"{source}:{line_number}: relative_path must be a nonempty POSIX path"
        )
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AtlasError(f"{source}:{line_number}: unsafe relative_path {value!r}")
    if path.suffix.lower() != ".smt2":
        raise AtlasError(f"{source}:{line_number}: expected an .smt2 relative_path")
    return path.as_posix()


def path_taxonomy(relative_path: str) -> tuple[str, str | None]:
    parts = PurePosixPath(relative_path).parts
    body = parts[1:] if parts and parts[0] == "QF_UF" else parts
    if len(body) < 2:
        raise AtlasError(
            f"relative_path has no source family and filename: {relative_path!r}"
        )
    family = body[0]
    if family != "QG-classification":
        return family, None
    if len(body) != 3:
        raise AtlasError(f"unrecognized QG path layout: {relative_path!r}")
    match = QG_DEGREE_RE.fullmatch(body[1])
    if match is None:
        raise AtlasError(f"unrecognized QG degree: {relative_path!r}")
    return family, str(int(match.group("degree")))


def load_csv(
    source: Path,
    *,
    viper_solver: str,
    yices_solver: str,
) -> tuple[list[InstancePair], list[str], str, int]:
    if viper_solver == yices_solver:
        raise AtlasError("the Viper and Yices solver identifiers must differ")

    observations: dict[tuple[str, str], Observation] = {}
    paths: dict[str, tuple[str, str]] = {}
    identifiers: dict[str, str] = {}
    solvers: set[str] = set()
    row_count = 0
    try:
        handle = source.open(newline="", encoding="utf-8")
    except OSError as error:
        raise AtlasError(f"cannot read {source}: {error}") from error

    with handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != CSV_FIELDNAMES:
            raise AtlasError(
                f"{source}: incompatible CSV header; expected {CSV_FIELDNAMES!r}, "
                f"got {reader.fieldnames!r}"
            )
        for line_number, row in enumerate(reader, start=2):
            row_count += 1
            if None in row or any(row[field] is None for field in CSV_FIELDNAMES):
                raise AtlasError(f"{source}:{line_number}: malformed CSV row")

            identifier = row["id"]
            if not identifier or identifier != identifier.strip():
                raise AtlasError(f"{source}:{line_number}: id must be nonempty and trimmed")
            relative_path = _validate_relative_path(
                row["relative_path"], source=source, line_number=line_number
            )
            expected_status = row["expected_status"]
            if expected_status not in DECISIVE_RESULTS:
                raise AtlasError(
                    f"{source}:{line_number}: expected_status must be sat or unsat"
                )
            solver = row["solver"]
            if not solver or solver != solver.strip():
                raise AtlasError(
                    f"{source}:{line_number}: solver must be nonempty and trimmed"
                )
            result = row["result"]
            if RESULT_RE.fullmatch(result) is None:
                raise AtlasError(f"{source}:{line_number}: malformed result {result!r}")
            time_s = _parse_time(row["time_s"], source=source, line_number=line_number)
            if INTEGER_RE.fullmatch(row["exit_code"]) is None:
                raise AtlasError(f"{source}:{line_number}: malformed exit_code")

            key = (relative_path, solver)
            if key in observations:
                raise AtlasError(
                    f"{source}:{line_number}: duplicate row for {relative_path!r}, "
                    f"solver {solver!r}"
                )
            previous_path = identifiers.get(identifier)
            if previous_path is not None and previous_path != relative_path:
                raise AtlasError(
                    f"{source}:{line_number}: id {identifier!r} names multiple paths"
                )
            identifiers[identifier] = relative_path
            previous = paths.get(relative_path)
            identity = (identifier, expected_status)
            if previous is not None and previous != identity:
                raise AtlasError(
                    f"{source}:{line_number}: inconsistent id or expected_status for "
                    f"{relative_path!r}"
                )
            paths[relative_path] = identity
            solvers.add(solver)
            observations[key] = Observation(
                identifier=identifier,
                relative_path=relative_path,
                expected_status=expected_status,
                solver=solver,
                result=result,
                time_s=time_s,
                exit_code=int(row["exit_code"]),
                stderr=row["stderr"],
            )

    if not observations:
        raise AtlasError(f"{source}: CSV contains no result rows")
    required = {viper_solver, yices_solver}
    missing_required = sorted(required - solvers)
    if missing_required:
        raise AtlasError(f"{source}: missing required solvers {missing_required!r}")

    expected_solvers = sorted(solvers)
    for relative_path in sorted(paths):
        present = [
            solver
            for solver in expected_solvers
            if (relative_path, solver) in observations
        ]
        if present != expected_solvers:
            missing = sorted(set(expected_solvers) - set(present))
            raise AtlasError(
                f"{source}: incomplete solver matrix for {relative_path!r}; "
                f"missing {missing!r}"
            )

    pairs = []
    for relative_path in sorted(paths):
        family, degree = path_taxonomy(relative_path)
        pairs.append(
            InstancePair(
                relative_path=relative_path,
                expected_status=paths[relative_path][1],
                family=family,
                qg_degree=degree,
                viper=observations[(relative_path, viper_solver)],
                yices=observations[(relative_path, yices_solver)],
            )
        )

    normalized_rows = [
        {
            "exit_code": observation.exit_code,
            "expected_status": observation.expected_status,
            "id": observation.identifier,
            "relative_path": observation.relative_path,
            "result": observation.result,
            "solver": observation.solver,
            "stderr": observation.stderr,
            "time_s": observation.time_s,
        }
        for observation in sorted(
            observations.values(), key=lambda item: (item.relative_path, item.solver)
        )
    ]
    dataset_sha256 = hashlib.sha256(canonical_json_bytes(normalized_rows)).hexdigest()
    return pairs, expected_solvers, dataset_sha256, row_count


def summarize(pairs: Sequence[InstancePair]) -> dict[str, object]:
    ordered = sorted(pairs, key=lambda item: item.relative_path)
    common = [pair for pair in ordered if pair.common_correct]
    deficits = [pair.deficit_s for pair in common]
    log_ratios = [
        math.log(pair.yices.time_s) - math.log(pair.viper.time_s)
        for pair in common
        if pair.viper.time_s > 0.0 and pair.yices.time_s > 0.0
    ]
    factor = None
    if log_ratios:
        try:
            factor = _clean_float(math.exp(math.fsum(log_ratios) / len(log_ratios)))
        except OverflowError as error:
            raise AtlasError("geometric timing factor overflowed") from error
    return {
        "common_correct": len(common),
        "euf_viper_faster": sum(deficit < 0.0 for deficit in deficits),
        "equal_time": sum(deficit == 0.0 for deficit in deficits),
        "geometric_pair_count": len(log_ratios),
        "geometric_yices_over_viper_factor": factor,
        "instances": len(ordered),
        "net_time_deficit_s": _clean_float(math.fsum(deficits)),
        "positive_time_deficit_s": _clean_float(
            math.fsum(max(deficit, 0.0) for deficit in deficits)
        ),
        "viper_only_correct": sum(
            pair.viper.correct and not pair.yices.correct for pair in ordered
        ),
        "yices2_faster": sum(deficit > 0.0 for deficit in deficits),
        "yices2_only_correct": sum(
            pair.yices.correct and not pair.viper.correct for pair in ordered
        ),
        "zero_time_pairs_excluded_from_geometric": len(common) - len(log_ratios),
    }


def _grouped(
    pairs: Sequence[InstancePair],
    key_values: Iterable[tuple[str, Sequence[InstancePair]]],
) -> dict[str, dict[str, object]]:
    del pairs
    return {key: summarize(group) for key, group in sorted(key_values)}


def _group_by(
    pairs: Sequence[InstancePair], attribute: str
) -> dict[str, list[InstancePair]]:
    groups: dict[str, list[InstancePair]] = defaultdict(list)
    for pair in pairs:
        value = getattr(pair, attribute)
        if value is not None:
            groups[str(value)].append(pair)
    return dict(groups)


def _coverage_gaps(pairs: Sequence[InstancePair]) -> dict[str, list[dict[str, str]]]:
    viper_only = []
    yices_only = []
    for pair in sorted(pairs, key=lambda item: item.relative_path):
        if pair.viper.correct and not pair.yices.correct:
            viper_only.append(
                {
                    "expected_status": pair.expected_status,
                    "relative_path": pair.relative_path,
                    "yices2_result": pair.yices.result,
                }
            )
        elif pair.yices.correct and not pair.viper.correct:
            yices_only.append(
                {
                    "euf_viper_result": pair.viper.result,
                    "expected_status": pair.expected_status,
                    "relative_path": pair.relative_path,
                }
            )
    return {
        "euf_viper_only_correct": viper_only,
        "yices2_only_correct": yices_only,
    }


def _top_n_mass(
    pairs: Sequence[InstancePair], top_ns: Sequence[int]
) -> list[dict[str, object]]:
    losses = sorted(
        (pair.deficit_s, pair.relative_path)
        for pair in pairs
        if pair.common_correct and pair.deficit_s > 0.0
    )
    losses.reverse()
    total = math.fsum(deficit for deficit, _ in losses)
    entries = []
    for requested in top_ns:
        selected = losses[:requested]
        mass = _clean_float(math.fsum(deficit for deficit, _ in selected))
        entries.append(
            {
                "actual_count": len(selected),
                "fraction_of_total_positive_deficit": mass / total if total else None,
                "positive_time_deficit_s": mass,
                "requested_top_n": requested,
            }
        )
    return entries


def _cohort_candidates(
    pairs: Sequence[InstancePair],
) -> list[tuple[str, str, list[InstancePair]]]:
    candidates: list[tuple[str, str, list[InstancePair]]] = []
    statuses = _group_by(pairs, "expected_status")
    families = _group_by(pairs, "family")
    degrees = _group_by(pairs, "qg_degree")
    candidates.extend(
        ("expected_status", key, value) for key, value in statuses.items()
    )
    candidates.extend(("source_family", key, value) for key, value in families.items())
    candidates.extend(("qg_degree", key, value) for key, value in degrees.items())
    for family, family_pairs in families.items():
        for status, status_pairs in _group_by(family_pairs, "expected_status").items():
            candidates.append(("source_family_and_status", f"{family}|{status}", status_pairs))
    for degree, degree_pairs in degrees.items():
        for status, status_pairs in _group_by(degree_pairs, "expected_status").items():
            candidates.append(("qg_degree_and_status", f"{degree}|{status}", status_pairs))
    return candidates


def qualifying_cohorts(
    pairs: Sequence[InstancePair], fraction: float
) -> list[dict[str, object]]:
    total_positive = summarize(pairs)["positive_time_deficit_s"]
    assert isinstance(total_positive, float)
    threshold = total_positive * fraction
    qualified = []
    if total_positive == 0.0:
        return qualified
    for dimension, key, cohort_pairs in _cohort_candidates(pairs):
        metrics = summarize(cohort_pairs)
        mass = metrics["positive_time_deficit_s"]
        assert isinstance(mass, float)
        if mass < threshold:
            continue
        qualified.append(
            {
                "cohort": key,
                "dimension": dimension,
                "fraction_of_total_positive_deficit": mass / total_positive,
                "metrics": metrics,
            }
        )
    qualified.sort(
        key=lambda item: (
            -float(item["fraction_of_total_positive_deficit"]),
            str(item["dimension"]),
            str(item["cohort"]),
        )
    )
    return qualified


def build_atlas(
    pairs: Sequence[InstancePair],
    *,
    solvers: Sequence[str],
    dataset_sha256: str,
    row_count: int,
    viper_solver: str,
    yices_solver: str,
    cohort_fraction: float,
    top_ns: Sequence[int],
) -> dict[str, object]:
    status_groups = _group_by(pairs, "expected_status")
    for status in sorted(DECISIVE_RESULTS):
        status_groups.setdefault(status, [])
    family_groups = _group_by(pairs, "family")
    degree_groups = _group_by(pairs, "qg_degree")
    overall = summarize(pairs)
    total_positive = overall["positive_time_deficit_s"]
    assert isinstance(total_positive, float)
    return {
        "by_expected_status": _grouped(pairs, status_groups.items()),
        "by_family": _grouped(pairs, family_groups.items()),
        "by_qg_degree": _grouped(pairs, degree_groups.items()),
        "cohort_gate": {
            "minimum_fraction_of_total_positive_deficit": cohort_fraction,
            "minimum_positive_time_deficit_s": _clean_float(
                total_positive * cohort_fraction
            ),
        },
        "coverage_only_gaps": _coverage_gaps(pairs),
        "cumulative_top_n_positive_deficit": _top_n_mass(pairs, top_ns),
        "dataset_sha256": dataset_sha256,
        "definitions": {
            "common_correct": "both results equal the decisive expected_status",
            "geometric_yices_over_viper_factor": "exp(mean(log(yices2_time/euf_viper_time))) over positive-time common-correct rows only",
            "net_time_deficit_s": "sum(euf_viper_time-yices2_time) over common-correct rows",
            "positive_time_deficit_s": "sum(max(euf_viper_time-yices2_time,0)) over common-correct rows",
        },
        "overall": overall,
        "qualifying_path_independent_cohorts": qualifying_cohorts(
            pairs, cohort_fraction
        ),
        "schema_version": SCHEMA_VERSION,
        "solver_roles": {
            "euf_viper": viper_solver,
            "yices2": yices_solver,
        },
        "validation": {
            "instances": len(pairs),
            "rows": row_count,
            "solvers": list(solvers),
        },
    }


def parse_top_ns(value: str) -> tuple[int, ...]:
    try:
        parsed = [int(item) for item in value.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "top-N values must be comma-separated integers"
        ) from error
    if not parsed or any(item < 1 for item in parsed):
        raise argparse.ArgumentTypeError("top-N values must all be positive")
    if len(set(parsed)) != len(parsed):
        raise argparse.ArgumentTypeError("top-N values must be unique")
    return tuple(sorted(parsed))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--viper-solver", default="euf-viper")
    parser.add_argument("--yices-solver", default="yices2")
    parser.add_argument("--cohort-fraction", type=float, default=0.10)
    parser.add_argument("--top-n", type=parse_top_ns, default=DEFAULT_TOP_N)
    args = parser.parse_args(argv)
    if not math.isfinite(args.cohort_fraction) or not 0.0 < args.cohort_fraction <= 1.0:
        parser.error("--cohort-fraction must be finite and in (0, 1]")

    try:
        reject_input_output_alias(args.csv, args.out)
        pairs, solvers, dataset_sha256, row_count = load_csv(
            args.csv,
            viper_solver=args.viper_solver,
            yices_solver=args.yices_solver,
        )
        payload = build_atlas(
            pairs,
            solvers=solvers,
            dataset_sha256=dataset_sha256,
            row_count=row_count,
            viper_solver=args.viper_solver,
            yices_solver=args.yices_solver,
            cohort_fraction=args.cohort_fraction,
            top_ns=args.top_n,
        )
        rendered = canonical_json_bytes(payload)
        publish_atomic(args.out, rendered)
    except (AtlasError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
