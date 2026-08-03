#!/usr/bin/env python3
"""Build a deterministic euf-viper versus Yices2 opportunity atlas.

The default input is the strict CSV schema emitted by ``compare_solvers.py``.
``--input-format staged-analysis`` instead consumes the hash-bound effective
observations emitted by ``analyze_staged_campaign.py`` and selects one budget.
Timing metrics include only instances solved correctly by both selected
solvers.  Coverage gaps are reported separately and never receive
timeout-charged times.
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


SCHEMA_VERSION = "euf-viper.yices-opportunity-atlas.v2"
COHORT_MANIFEST_SCHEMA_VERSION = "euf-viper.yices-opportunity-cohort.v1"
STAGED_OBSERVATION_SCHEMA = "euf-viper.staged-observations.v1"
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
RESULT_RE = re.compile(
    r"(?:sat|unsat|unknown|timeout|unsupported|error|invalid|exit--?[0-9]+)\Z"
)
INTEGER_RE = re.compile(r"[+-]?[0-9]+\Z")
QG_DEGREE_RE = re.compile(r"(?:qg|loops)(?P<degree>[0-9]+)\Z")
DEFAULT_TOP_N = (10, 50, 100, 500)
PROSPECTIVE_TARGET_COUNT = 100
GEOMETRIC_SERIALIZATION_SIGNIFICANT_DIGITS = 12
CONTROL_SELECTION_DOMAIN = "euf-viper.yices-opportunity.control.v1"
STAGED_PROVENANCE_KEYS = {
    "binary_sha256",
    "budget_s",
    "carried_forward",
    "cpu_time_s",
    "expected_status",
    "family",
    "instance_id",
    "origin_budget_s",
    "relative_path",
    "repetitions",
    "result",
    "solver_id",
    "source_lock_sha256",
    "source_raw_sha256",
    "source_record_sha256s",
    "wall_time_s",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


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


def _quantize_geometric_metric(value: float) -> float:
    """Round only the serialized geometric metric to a stable precision."""
    value = _clean_float(value)
    rendered = format(value, f".{GEOMETRIC_SERIALIZATION_SIGNIFICANT_DIGITS}g")
    return _clean_float(float(rendered))


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


def _pairs_from_matrix(
    observations: dict[tuple[str, str], Observation],
    paths: dict[str, tuple[str, str]],
    solvers: set[str],
    *,
    source: Path,
    viper_solver: str,
    yices_solver: str,
) -> tuple[list[InstancePair], list[str]]:
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
    return pairs, expected_solvers


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
    pairs, expected_solvers = _pairs_from_matrix(
        observations,
        paths,
        solvers,
        source=source,
        viper_solver=viper_solver,
        yices_solver=yices_solver,
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


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AtlasError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _finite_number(value: object, context: str, *, positive: bool = False) -> float:
    if type(value) not in {int, float}:
        raise AtlasError(f"{context} must be a JSON number")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0.0 or (positive and parsed <= 0.0):
        qualifier = "positive and finite" if positive else "nonnegative and finite"
        raise AtlasError(f"{context} must be {qualifier}")
    return _clean_float(parsed)


def _staged_solver_matrix(
    inputs: dict[str, object],
    hashes: dict[str, object],
    *,
    source: Path,
    viper_solver: str,
    yices_solver: str,
) -> tuple[list[str], dict[str, object], str]:
    """Read the required comparator matrix from hash-bound staged metadata."""
    candidate = inputs.get("candidate_id")
    baselines = inputs.get("baseline_ids")
    if (
        type(candidate) is not str
        or not candidate
        or candidate.strip() != candidate
    ):
        raise AtlasError(f"{source}: staged candidate_id is missing or invalid")
    if type(baselines) is not list or not baselines:
        raise AtlasError(f"{source}: staged baseline_ids are missing or invalid")
    if any(
        type(item) is not str or not item or item.strip() != item
        for item in baselines
    ):
        raise AtlasError(f"{source}: staged baseline_ids contain an invalid solver id")
    declared = [candidate, *baselines]
    if len(set(declared)) != len(declared):
        raise AtlasError(f"{source}: staged comparator solver ids must be unique")
    if candidate != viper_solver:
        raise AtlasError(
            f"{source}: Viper role {viper_solver!r} disagrees with staged "
            f"candidate_id {candidate!r}"
        )
    if yices_solver not in baselines:
        raise AtlasError(
            f"{source}: Yices role {yices_solver!r} is not a staged baseline"
        )

    solver_hashes = hashes.get("solver_binary_sha256")
    if type(solver_hashes) is not dict or set(solver_hashes) != set(declared):
        raise AtlasError(
            f"{source}: solver_binary_sha256 does not match the declared "
            "comparator matrix"
        )
    for solver, digest in solver_hashes.items():
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise AtlasError(
                f"{source}: solver_binary_sha256[{solver!r}] is invalid"
            )

    expected_solvers = sorted(declared)
    declaration = {
        "baseline_ids": list(baselines),
        "candidate_id": candidate,
        "solver_binary_sha256": {
            solver: solver_hashes[solver] for solver in expected_solvers
        },
    }
    declaration_sha256 = hashlib.sha256(
        canonical_json_bytes(declaration)
    ).hexdigest()
    return expected_solvers, declaration, declaration_sha256


def load_staged_analysis(
    source: Path,
    *,
    viper_solver: str,
    yices_solver: str,
    budget_s: float | None,
) -> tuple[
    list[InstancePair],
    list[str],
    str,
    int,
    float,
    dict[str, object],
]:
    """Load one hash-bound effective budget from staged campaign analysis."""
    if viper_solver == yices_solver:
        raise AtlasError("the Viper and Yices solver identifiers must differ")
    try:
        with source.open(encoding="ascii") as handle:
            payload = json.load(handle, object_pairs_hook=_unique_json_object)
    except AtlasError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AtlasError(f"cannot read staged analysis {source}: {error}") from error
    if type(payload) is not dict or payload.get("schema_version") != 1:
        raise AtlasError(f"{source}: incompatible staged analysis schema")
    inputs = payload.get("inputs")
    hashes = payload.get("input_hashes")
    if type(inputs) is not dict or type(hashes) is not dict:
        raise AtlasError(f"{source}: staged analysis lacks inputs or input_hashes")
    if inputs.get("observation_provenance_schema") != STAGED_OBSERVATION_SCHEMA:
        raise AtlasError(
            f"{source}: staged observation schema is missing or incompatible"
        )
    expected_solvers, solver_declaration, solver_matrix_sha256 = (
        _staged_solver_matrix(
            inputs,
            hashes,
            source=source,
            viper_solver=viper_solver,
            yices_solver=yices_solver,
        )
    )
    rows = inputs.get("observation_provenance")
    if type(rows) is not list or not rows:
        raise AtlasError(f"{source}: staged analysis has no observation provenance")
    declared_hash = hashes.get("observation_provenance_sha256")
    actual_hash = hashlib.sha256(canonical_json_bytes(rows)).hexdigest()
    if declared_hash != actual_hash:
        raise AtlasError(f"{source}: observation provenance SHA-256 mismatch")

    raw_budgets = inputs.get("budgets_s")
    if type(raw_budgets) is not list or not raw_budgets:
        raise AtlasError(f"{source}: staged analysis has no declared budgets")
    budgets = [
        _finite_number(value, f"{source}: budgets_s[{index}]", positive=True)
        for index, value in enumerate(raw_budgets)
    ]
    if budgets != sorted(set(budgets)):
        raise AtlasError(f"{source}: staged budgets must be unique and increasing")
    selected_budget = budgets[-1] if budget_s is None else float(budget_s)
    if not math.isfinite(selected_budget) or selected_budget <= 0.0:
        raise AtlasError("selected budget must be positive and finite")
    if selected_budget not in budgets:
        raise AtlasError(
            f"{source}: selected budget {selected_budget:g} is not in {budgets!r}"
        )

    observations: dict[tuple[str, str], Observation] = {}
    paths: dict[str, tuple[str, str]] = {}
    all_keys: set[tuple[str, float, str]] = set()
    all_solvers: set[str] = set()
    all_paths: dict[str, tuple[str, str]] = {}
    normalized_rows: list[dict[str, object]] = []
    carried_count = 0
    expected_binary_hashes = solver_declaration["solver_binary_sha256"]
    assert isinstance(expected_binary_hashes, dict)
    for index, raw in enumerate(rows):
        context = f"{source}: observation_provenance[{index}]"
        if type(raw) is not dict or set(raw) != STAGED_PROVENANCE_KEYS:
            raise AtlasError(f"{context} has an incompatible field set")
        raw_relative_path = raw["relative_path"]
        if type(raw_relative_path) is not str:
            raise AtlasError(f"{context}.relative_path must be a string")
        relative_path = _validate_relative_path(
            raw_relative_path, source=source, line_number=index + 1
        )
        instance_id = raw["instance_id"]
        expected_status = raw["expected_status"]
        family = raw["family"]
        solver = raw["solver_id"]
        result = raw["result"]
        if type(instance_id) is not str or not instance_id or instance_id.strip() != instance_id:
            raise AtlasError(f"{context}.instance_id must be nonempty and trimmed")
        if expected_status not in DECISIVE_RESULTS:
            raise AtlasError(f"{context}.expected_status must be sat or unsat")
        if type(family) is not str or not family or family.strip() != family:
            raise AtlasError(f"{context}.family must be nonempty and trimmed")
        path_family, _ = path_taxonomy(relative_path)
        if family not in {path_family, f"QF_UF/{path_family}"}:
            raise AtlasError(f"{context}.family disagrees with relative_path")
        if type(solver) is not str or not solver or solver.strip() != solver:
            raise AtlasError(f"{context}.solver_id must be nonempty and trimmed")
        if type(result) is not str or RESULT_RE.fullmatch(result) is None:
            raise AtlasError(f"{context}.result is invalid")
        if result in DECISIVE_RESULTS and result != expected_status:
            raise AtlasError(f"{context} contains a wrong decisive answer")
        row_budget = _finite_number(raw["budget_s"], f"{context}.budget_s", positive=True)
        origin_budget = _finite_number(
            raw["origin_budget_s"], f"{context}.origin_budget_s", positive=True
        )
        if row_budget not in budgets or origin_budget > row_budget:
            raise AtlasError(f"{context} has inconsistent budget provenance")
        carried_forward = raw["carried_forward"]
        if type(carried_forward) is not bool or carried_forward != (
            origin_budget < row_budget
        ):
            raise AtlasError(f"{context}.carried_forward disagrees with origin budget")
        carried_count += int(carried_forward)
        cpu_time = _finite_number(raw["cpu_time_s"], f"{context}.cpu_time_s")
        wall_time = _finite_number(raw["wall_time_s"], f"{context}.wall_time_s")
        if result in DECISIVE_RESULTS:
            if wall_time <= 0.0:
                raise AtlasError(
                    f"{context}: decisive result requires positive wall time"
                )
        repetitions = raw["repetitions"]
        if type(repetitions) is not int or repetitions < 1:
            raise AtlasError(f"{context}.repetitions must be a positive integer")
        for field in (
            "binary_sha256",
            "source_lock_sha256",
            "source_raw_sha256",
        ):
            if type(raw[field]) is not str or SHA256_RE.fullmatch(raw[field]) is None:
                raise AtlasError(f"{context}.{field} is not a canonical SHA-256")
        if (
            solver in expected_binary_hashes
            and raw["binary_sha256"] != expected_binary_hashes[solver]
        ):
            raise AtlasError(
                f"{context}.binary_sha256 disagrees with the staged solver "
                "declaration"
            )
        record_hashes = raw["source_record_sha256s"]
        if (
            type(record_hashes) is not list
            or len(record_hashes) != repetitions
            or any(type(item) is not str or SHA256_RE.fullmatch(item) is None for item in record_hashes)
        ):
            raise AtlasError(f"{context}.source_record_sha256s is invalid")

        identity = (instance_id, expected_status)
        previous_identity = all_paths.setdefault(relative_path, identity)
        if previous_identity != identity:
            raise AtlasError(f"{context}: path identity changed across observations")
        key = (relative_path, row_budget, solver)
        if key in all_keys:
            raise AtlasError(f"{context}: duplicate staged observation")
        all_keys.add(key)
        all_solvers.add(solver)
        if row_budget != selected_budget:
            continue

        selected_key = (relative_path, solver)
        observations[selected_key] = Observation(
            identifier=instance_id,
            relative_path=relative_path,
            expected_status=expected_status,
            solver=solver,
            result=result,
            time_s=wall_time,
            exit_code=0,
            stderr="",
        )
        paths[relative_path] = identity
        normalized_rows.append(
            {
                "binary_sha256": raw["binary_sha256"],
                "expected_status": expected_status,
                "instance_id": instance_id,
                "origin_budget_s": origin_budget,
                "relative_path": relative_path,
                "result": result,
                "solver_id": solver,
                "source_record_sha256s": record_hashes,
                "wall_time_s": wall_time,
            }
        )

    declared_carried = inputs.get("carried_forward_observations")
    if type(declared_carried) is not int or declared_carried != carried_count:
        raise AtlasError(f"{source}: carried-forward observation count mismatch")
    declared_instances = inputs.get("instances")
    if type(declared_instances) is not int or declared_instances != len(all_paths):
        raise AtlasError(f"{source}: instance count disagrees with provenance")
    missing_matrix_count = 0
    missing_matrix_first: list[tuple[str, float, str]] = []
    for relative_path in sorted(all_paths):
        for budget in budgets:
            for solver in expected_solvers:
                key = (relative_path, budget, solver)
                if key in all_keys:
                    continue
                missing_matrix_count += 1
                if len(missing_matrix_first) < 3:
                    missing_matrix_first.append(key)
    if missing_matrix_count:
        raise AtlasError(
            f"{source}: declared staged solver matrix is incomplete; "
            f"missing={missing_matrix_count}, first={missing_matrix_first!r}"
        )

    pairs, expected_solvers = _pairs_from_matrix(
        observations,
        paths,
        set(expected_solvers),
        source=source,
        viper_solver=viper_solver,
        yices_solver=yices_solver,
    )
    normalized_rows.sort(
        key=lambda item: (str(item["relative_path"]), str(item["solver_id"]))
    )
    dataset = {
        "budget_s": selected_budget,
        "expected_solver_matrix_sha256": solver_matrix_sha256,
        "observation_provenance_sha256": actual_hash,
        "rows": normalized_rows,
    }
    dataset_sha256 = hashlib.sha256(canonical_json_bytes(dataset)).hexdigest()
    matrix_validation = {
        "expected_solver_matrix": solver_declaration,
        "expected_solver_matrix_sha256": solver_matrix_sha256,
        "observed_solvers": sorted(all_solvers),
        "solver_matrix_source": (
            "staged candidate_id, baseline_ids, and solver_binary_sha256"
        ),
    }
    return (
        pairs,
        expected_solvers,
        dataset_sha256,
        len(normalized_rows),
        selected_budget,
        matrix_validation,
    )


def summarize(pairs: Sequence[InstancePair]) -> dict[str, object]:
    ordered = sorted(pairs, key=lambda item: item.relative_path)
    common = [pair for pair in ordered if pair.common_correct]
    deficits = [pair.deficit_s for pair in common]
    log_ratios = [
        math.log(pair.yices.time_s) - math.log(pair.viper.time_s)
        for pair in common
        if pair.viper.time_s > 0.0 and pair.yices.time_s > 0.0
    ]
    factor_unquantized = None
    factor_serialized = None
    if log_ratios:
        try:
            factor_unquantized = _clean_float(
                math.exp(math.fsum(log_ratios) / len(log_ratios))
            )
        except OverflowError as error:
            raise AtlasError("geometric timing factor overflowed") from error
        factor_serialized = _quantize_geometric_metric(factor_unquantized)
    return {
        "common_correct": len(common),
        "euf_viper_faster": sum(deficit < 0.0 for deficit in deficits),
        "equal_time": sum(deficit == 0.0 for deficit in deficits),
        "geometric_pair_count": len(log_ratios),
        "geometric_yices_over_viper_factor": factor_serialized,
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


def _ranked_positive_deficits(
    pairs: Sequence[InstancePair],
) -> list[tuple[float, InstancePair]]:
    losses = [
        (pair.deficit_s, pair)
        for pair in pairs
        if pair.common_correct and pair.deficit_s > 0.0
    ]
    return sorted(losses, key=lambda item: (-item[0], item[1].relative_path))


def _top_n_mass(
    pairs: Sequence[InstancePair], top_ns: Sequence[int]
) -> list[dict[str, object]]:
    losses = _ranked_positive_deficits(pairs)
    total = math.fsum(deficit for deficit, _ in losses)
    entries = []
    for requested in top_ns:
        selected = losses[:requested]
        mass = _clean_float(math.fsum(deficit for deficit, _pair in selected))
        entries.append(
            {
                "actual_count": len(selected),
                "fraction_of_total_positive_deficit": mass / total if total else None,
                "positive_time_deficit_s": mass,
                "requested_top_n": requested,
            }
        )
    return entries


def _control_selection_key(
    family: str, expected_status: str, relative_path: str
) -> tuple[str, str]:
    material = "\0".join(
        (
            CONTROL_SELECTION_DOMAIN,
            family,
            expected_status,
            relative_path,
        )
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest(), relative_path


def _cohort_manifest_sha256(manifest: dict[str, object]) -> str:
    prepared = dict(manifest)
    prepared["manifest_sha256"] = ""
    return hashlib.sha256(canonical_json_bytes(prepared)).hexdigest()


def build_prospective_cohort_manifest(
    pairs: Sequence[InstancePair],
    *,
    dataset_sha256: str,
    target_count: int = PROSPECTIVE_TARGET_COUNT,
) -> dict[str, object]:
    """Freeze deficit-selected targets and timing-independent matched controls."""
    if SHA256_RE.fullmatch(dataset_sha256) is None:
        raise AtlasError("prospective cohort requires a canonical dataset SHA-256")
    if (
        isinstance(target_count, bool)
        or not isinstance(target_count, int)
        or target_count < 1
    ):
        raise AtlasError("prospective cohort target_count must be positive")

    ranked = _ranked_positive_deficits(pairs)
    selected_targets = [pair for _deficit, pair in ranked[:target_count]]
    target_paths = {pair.relative_path for pair in selected_targets}
    targets = [
        {
            "expected_status": pair.expected_status,
            "rank": rank,
            "relative_path": pair.relative_path,
            "source_family": pair.family,
        }
        for rank, pair in enumerate(selected_targets, start=1)
    ]

    targets_by_stratum: dict[tuple[str, str], list[InstancePair]] = defaultdict(list)
    controls_by_stratum: dict[tuple[str, str], list[InstancePair]] = defaultdict(list)
    for pair in selected_targets:
        targets_by_stratum[(pair.family, pair.expected_status)].append(pair)
    for pair in pairs:
        if pair.common_correct and pair.relative_path not in target_paths:
            controls_by_stratum[(pair.family, pair.expected_status)].append(pair)

    strata = []
    actual_controls = 0
    for family, expected_status in sorted(targets_by_stratum):
        stratum_targets = targets_by_stratum[(family, expected_status)]
        ordered_controls = sorted(
            controls_by_stratum.get((family, expected_status), []),
            key=lambda pair: _control_selection_key(
                family,
                expected_status,
                pair.relative_path,
            ),
        )
        selected_controls = ordered_controls[: len(stratum_targets)]
        actual_controls += len(selected_controls)
        strata.append(
            {
                "control_count": len(selected_controls),
                "control_paths": [pair.relative_path for pair in selected_controls],
                "expected_status": expected_status,
                "requested_control_count": len(stratum_targets),
                "source_family": family,
                "target_count": len(stratum_targets),
                "target_paths": [pair.relative_path for pair in stratum_targets],
            }
        )

    manifest: dict[str, object] = {
        "hash_convention": (
            "SHA256 of canonical JSON with manifest_sha256 set to the empty string"
        ),
        "manifest_sha256": "",
        "matched_controls": {
            "actual_count": actual_controls,
            "eligibility": (
                "common-correct non-target instances in the same source_family "
                "and decisive expected_status stratum"
            ),
            "no_replacement": True,
            "selection_key": (
                "SHA256(domain NUL source_family NUL expected_status NUL "
                "relative_path), ascending; relative_path breaks digest ties"
            ),
            "selection_key_domain": CONTROL_SELECTION_DOMAIN,
            "selection_uses_control_timing": False,
            "strata": strata,
            "timing_claims": (
                "none; controls freeze paths only and carry no baseline timing or "
                "deficit claim"
            ),
            "underfill_policy": (
                "use every eligible path in the stratum; never reuse a control or "
                "cross strata"
            ),
        },
        "schema_version": COHORT_MANIFEST_SCHEMA_VERSION,
        "source_dataset_sha256": dataset_sha256,
        "stratification": ["source_family", "expected_status"],
        "target_selection": {
            "actual_count": len(targets),
            "eligibility": (
                "common-correct instances with unquantized "
                "euf_viper_time-yices2_time greater than zero"
            ),
            "ordering": (
                "descending unquantized positive deficit, then relative_path "
                "ascending"
            ),
            "requested_count": target_count,
            "targets": targets,
        },
    }
    manifest["manifest_sha256"] = _cohort_manifest_sha256(manifest)
    return manifest


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
            "geometric_yices_over_viper_factor": (
                "exp(mean(log(yices2_time/euf_viper_time))) over positive-time "
                "common-correct rows only; serialized at the declared significant-"
                "digit precision"
            ),
            "net_time_deficit_s": "sum(euf_viper_time-yices2_time) over common-correct rows",
            "positive_time_deficit_s": "sum(max(euf_viper_time-yices2_time,0)) over common-correct rows",
        },
        "numeric_serialization": {
            "geometric_metric_internal": (
                "timing comparisons and cohort selection use unquantized wall "
                "times and deficits; quantization is applied only to serialized "
                "geometric factors"
            ),
            "geometric_metric_serialized_significant_decimal_digits": (
                GEOMETRIC_SERIALIZATION_SIGNIFICANT_DIGITS
            ),
            "scope": "geometric metrics only",
        },
        "overall": overall,
        "prospective_cohort_manifest": build_prospective_cohort_manifest(
            pairs,
            dataset_sha256=dataset_sha256,
        ),
        "qualifying_path_independent_cohorts": qualifying_cohorts(
            pairs, cohort_fraction
        ),
        "schema_version": SCHEMA_VERSION,
        "solver_roles": {
            "euf_viper": viper_solver,
            "yices2": yices_solver,
        },
        "validation": {
            "expected_solvers": list(solvers),
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
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--input-format",
        choices=("csv", "staged-analysis"),
        default="csv",
    )
    parser.add_argument(
        "--budget",
        type=float,
        help="staged-analysis budget to select (defaults to the largest budget)",
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--viper-solver", default="euf-viper")
    parser.add_argument("--yices-solver", default="yices2")
    parser.add_argument("--cohort-fraction", type=float, default=0.10)
    parser.add_argument("--top-n", type=parse_top_ns, default=DEFAULT_TOP_N)
    args = parser.parse_args(argv)
    if not math.isfinite(args.cohort_fraction) or not 0.0 < args.cohort_fraction <= 1.0:
        parser.error("--cohort-fraction must be finite and in (0, 1]")
    if args.budget is not None and args.input_format != "staged-analysis":
        parser.error("--budget requires --input-format staged-analysis")
    if args.budget is not None and (
        not math.isfinite(args.budget) or args.budget <= 0.0
    ):
        parser.error("--budget must be positive and finite")

    try:
        reject_input_output_alias(args.input, args.out)
        effective_budget = None
        if args.input_format == "csv":
            pairs, solvers, dataset_sha256, row_count = load_csv(
                args.input,
                viper_solver=args.viper_solver,
                yices_solver=args.yices_solver,
            )
            matrix_validation = {
                "observed_solvers": list(solvers),
                "solver_matrix_source": "flat CSV observed solver ids (legacy)",
            }
        else:
            (
                pairs,
                solvers,
                dataset_sha256,
                row_count,
                effective_budget,
                matrix_validation,
            ) = load_staged_analysis(
                args.input,
                viper_solver=args.viper_solver,
                yices_solver=args.yices_solver,
                budget_s=args.budget,
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
        payload["validation"]["input_format"] = args.input_format
        payload["validation"].update(matrix_validation)
        if effective_budget is not None:
            payload["validation"]["effective_budget_s"] = effective_budget
        rendered = canonical_json_bytes(payload)
        publish_atomic(args.out, rendered)
    except (AtlasError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
