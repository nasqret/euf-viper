#!/usr/bin/env python3
"""Probe deterministic bounded-variable addition opportunities in DIMACS CNF.

The analyzer is deliberately offline: it does not alter the production solver.
It finds syntactic clause bicliques of the form ``left_literal OR tail`` and
optionally labels them as finite-table-aware when literal metadata describes a
coherent table cell/value axis.  Every accepted rewrite has a replayable
certificate, and small results are checked independently by exhaustive truth
table enumeration with existentially quantified added variables.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REPORT_SCHEMA = "euf-viper-euf-bva-report-v1"
CERTIFICATE_SCHEMA = "euf-viper-euf-bva-certificate-v1"
METADATA_SCHEMA = "euf-viper-finite-table-literals-v1"
DEFAULT_CANDIDATE_CAP = 256
DEFAULT_MAX_ADDED_VARIABLES = 64
DEFAULT_EXHAUSTIVE_MAX_VARIABLES = 16


class AnalyzerError(ValueError):
    """Raised when input, metadata, or analyzer configuration is invalid."""


class DimacsError(AnalyzerError):
    """Raised when DIMACS input is malformed."""


class MetadataError(AnalyzerError):
    """Raised when finite-table literal metadata is malformed."""


class CertificateError(AnalyzerError):
    """Raised when a BVA transformation certificate cannot be replayed."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical_clause(literals: Iterable[int]) -> tuple[int, ...]:
    return tuple(sorted(literals))


def _canonical_clauses(
    clauses: Iterable[Sequence[int]],
) -> tuple[tuple[int, ...], ...]:
    return tuple(sorted(_canonical_clause(clause) for clause in clauses))


@dataclass(frozen=True)
class Cnf:
    """A canonical clause multiset with an explicit DIMACS variable bound."""

    variables: int
    clauses: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        if not _is_int(self.variables) or self.variables < 0:
            raise DimacsError("variable count must be a non-negative integer")
        if self.clauses != _canonical_clauses(self.clauses):
            raise DimacsError("CNF clauses must be canonically sorted")
        for clause_index, clause in enumerate(self.clauses):
            for literal in clause:
                if not _is_int(literal) or literal == 0:
                    raise DimacsError(
                        f"clause {clause_index} contains a non-DIMACS literal"
                    )
                if abs(literal) > self.variables:
                    raise DimacsError(
                        f"literal {literal} exceeds declared variable count "
                        f"{self.variables}"
                    )

    @classmethod
    def from_clauses(cls, variables: int, clauses: Iterable[Iterable[int]]) -> "Cnf":
        if not _is_int(variables) or variables < 0:
            raise DimacsError("variable count must be a non-negative integer")
        canonical: list[tuple[int, ...]] = []
        for clause_index, raw_clause in enumerate(clauses):
            clause: list[int] = []
            for literal in raw_clause:
                if not _is_int(literal) or literal == 0:
                    raise DimacsError(
                        f"clause {clause_index} contains a non-DIMACS literal"
                    )
                if abs(literal) > variables:
                    raise DimacsError(
                        f"literal {literal} exceeds declared variable count {variables}"
                    )
                clause.append(literal)
            canonical.append(_canonical_clause(clause))
        return cls(variables, tuple(sorted(canonical)))


@dataclass(frozen=True)
class LiteralMetadata:
    table: str
    cell: tuple[str | int, ...]
    value: str | int

    def as_json(self, literal: int) -> dict[str, object]:
        return {
            "literal": literal,
            "table": self.table,
            "cell": list(self.cell),
            "value": self.value,
        }


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    left_literals: tuple[int, ...]
    tails: tuple[tuple[int, ...], ...]
    removed_clauses: tuple[tuple[int, ...], ...]
    removed_literal_count: int
    added_literal_count: int
    removed_clause_count: int
    added_clause_count: int
    max_removed_width: int
    max_added_width: int
    classification: str
    table_evidence_json: str | None

    @property
    def literal_reduction(self) -> int:
        return self.removed_literal_count - self.added_literal_count

    @property
    def clause_reduction(self) -> int:
        return self.removed_clause_count - self.added_clause_count

    @property
    def table_evidence(self) -> dict[str, object] | None:
        if self.table_evidence_json is None:
            return None
        value = json.loads(self.table_evidence_json)
        assert isinstance(value, dict)
        return value


def parse_dimacs(text: str) -> Cnf:
    """Parse one strict DIMACS CNF problem, including multi-line clauses."""
    variables: int | None = None
    expected_clauses: int | None = None
    tokens: list[int] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("c"):
            continue
        fields = line.split()
        if fields[0] == "p":
            if variables is not None:
                raise DimacsError(f"duplicate problem header on line {line_number}")
            if len(fields) != 4 or fields[1] != "cnf":
                raise DimacsError(
                    f"malformed problem header on line {line_number}; expected p cnf V C"
                )
            try:
                variables = int(fields[2])
                expected_clauses = int(fields[3])
            except ValueError as error:
                raise DimacsError(
                    f"non-integer problem size on line {line_number}"
                ) from error
            if variables < 0 or expected_clauses < 0:
                raise DimacsError("problem sizes must be non-negative")
            continue
        if variables is None:
            raise DimacsError(f"clause data precedes problem header on line {line_number}")
        for field in fields:
            try:
                tokens.append(int(field))
            except ValueError as error:
                raise DimacsError(
                    f"non-integer DIMACS token {field!r} on line {line_number}"
                ) from error

    if variables is None or expected_clauses is None:
        raise DimacsError("missing p cnf problem header")

    clauses: list[list[int]] = []
    current: list[int] = []
    for token in tokens:
        if token == 0:
            clauses.append(current)
            current = []
        else:
            current.append(token)
    if current:
        raise DimacsError("last clause is not terminated by 0")
    if len(clauses) != expected_clauses:
        raise DimacsError(
            f"header declares {expected_clauses} clauses but input contains {len(clauses)}"
        )
    return Cnf.from_clauses(variables, clauses)


def load_dimacs(path: Path) -> Cnf:
    try:
        return parse_dimacs(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise DimacsError(f"cannot read DIMACS file {path}: {error}") from error
    except UnicodeError as error:
        raise DimacsError(f"DIMACS file {path} is not UTF-8: {error}") from error


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MetadataError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_metadata_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
        )
    except MetadataError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MetadataError(f"cannot load metadata {path}: {error}") from error


def _metadata_scalar(value: object, context: str) -> str | int:
    if isinstance(value, str):
        if not value:
            raise MetadataError(f"{context} must not be empty")
        return value
    if _is_int(value):
        return value
    raise MetadataError(f"{context} must be a string or integer")


def parse_metadata(
    payload: object, variable_count: int
) -> dict[int, LiteralMetadata]:
    """Validate exact-literal finite-table cell/value metadata."""
    if not isinstance(payload, dict):
        raise MetadataError("metadata root must be a JSON object")
    unknown_root = sorted(set(payload) - {"schema", "literals"})
    if unknown_root:
        raise MetadataError("unknown metadata fields: " + ", ".join(unknown_root))
    if payload.get("schema", METADATA_SCHEMA) != METADATA_SCHEMA:
        raise MetadataError(f"metadata schema must be {METADATA_SCHEMA!r}")
    literal_payload = payload.get("literals")
    if not isinstance(literal_payload, dict):
        raise MetadataError("metadata field 'literals' must be a JSON object")

    for raw_literal in literal_payload:
        if not isinstance(raw_literal, str):
            raise MetadataError("literal metadata keys must be strings")

    parsed: dict[int, LiteralMetadata] = {}
    assignments: dict[tuple[str, str, str], int] = {}
    for raw_literal, raw_record in sorted(literal_payload.items()):
        try:
            literal = int(raw_literal)
        except ValueError as error:
            raise MetadataError(
                f"literal metadata key {raw_literal!r} is not an integer"
            ) from error
        if literal == 0 or str(literal) != raw_literal:
            raise MetadataError(
                f"literal metadata key {raw_literal!r} is not canonical"
            )
        if abs(literal) > variable_count:
            raise MetadataError(
                f"metadata literal {literal} exceeds variable count {variable_count}"
            )
        if not isinstance(raw_record, dict):
            raise MetadataError(f"metadata for literal {literal} must be an object")
        missing = sorted({"table", "cell", "value"} - set(raw_record))
        unknown = sorted(set(raw_record) - {"table", "cell", "value"})
        if missing:
            raise MetadataError(
                f"metadata for literal {literal} is missing: " + ", ".join(missing)
            )
        if unknown:
            raise MetadataError(
                f"metadata for literal {literal} has unknown fields: "
                + ", ".join(unknown)
            )
        table = _metadata_scalar(raw_record["table"], f"table for literal {literal}")
        if not isinstance(table, str):
            raise MetadataError(f"table for literal {literal} must be a string")
        raw_cell = raw_record["cell"]
        if not isinstance(raw_cell, list) or not raw_cell:
            raise MetadataError(f"cell for literal {literal} must be a non-empty array")
        cell = tuple(
            _metadata_scalar(item, f"cell coordinate for literal {literal}")
            for item in raw_cell
        )
        value = _metadata_scalar(raw_record["value"], f"value for literal {literal}")
        record = LiteralMetadata(table=table, cell=cell, value=value)
        assignment_key = (
            table,
            json.dumps(list(cell), sort_keys=True, separators=(",", ":")),
            json.dumps(value, sort_keys=True, separators=(",", ":")),
        )
        if assignment_key in assignments:
            other = assignments[assignment_key]
            raise MetadataError(
                f"literals {other} and {literal} map to the same table cell/value"
            )
        assignments[assignment_key] = literal
        parsed[literal] = record
    return parsed


def _metadata_digest(metadata: Mapping[int, LiteralMetadata]) -> str:
    payload = {
        str(literal): {
            "table": record.table,
            "cell": list(record.cell),
            "value": record.value,
        }
        for literal, record in sorted(metadata.items())
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def formula_digest(variables: int, clauses: Iterable[Sequence[int]]) -> str:
    payload = {
        "variables": variables,
        "clauses": [list(clause) for clause in _canonical_clauses(clauses)],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def formula_metrics(variables: int, clauses: Iterable[Sequence[int]]) -> dict[str, object]:
    canonical = _canonical_clauses(clauses)
    return {
        "variables": variables,
        "clauses": len(canonical),
        "literal_count": sum(len(clause) for clause in canonical),
        "max_width": max((len(clause) for clause in canonical), default=0),
        "sha256": formula_digest(variables, canonical),
    }


def _json_sort_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _coherent_table_axis(
    literals: tuple[int, ...],
    metadata: Mapping[int, LiteralMetadata],
    axis: str,
) -> dict[str, object] | None:
    if any(literal not in metadata for literal in literals):
        return None
    records = [metadata[literal] for literal in literals]
    tables = {record.table for record in records}
    if len(tables) != 1:
        return None

    cell_map = {_json_sort_key(list(record.cell)): record.cell for record in records}
    value_map = {_json_sort_key(record.value): record.value for record in records}
    pairs = {
        (_json_sort_key(list(record.cell)), _json_sort_key(record.value))
        for record in records
    }
    if len(pairs) != len(records) or len(pairs) != len(cell_map) * len(value_map):
        return None
    if len(cell_map) == 1 and len(value_map) > 1:
        pattern = "same_cell_distinct_values"
    elif len(value_map) == 1 and len(cell_map) > 1:
        pattern = "same_value_distinct_cells"
    elif len(cell_map) > 1 and len(value_map) > 1:
        pattern = "complete_cell_value_block"
    else:
        return None

    return {
        "axis": axis,
        "table": records[0].table,
        "pattern": pattern,
        "cells": [list(cell_map[key]) for key in sorted(cell_map)],
        "values": [value_map[key] for key in sorted(value_map)],
        "entries": [
            metadata[literal].as_json(literal) for literal in sorted(literals)
        ],
    }


def _table_evidence(
    left_literals: tuple[int, ...],
    tails: tuple[tuple[int, ...], ...],
    metadata: Mapping[int, LiteralMetadata],
) -> dict[str, object] | None:
    left_evidence = _coherent_table_axis(left_literals, metadata, "left_literals")
    if left_evidence is not None:
        return left_evidence

    common_tail = set(tails[0])
    for tail in tails[1:]:
        common_tail.intersection_update(tail)
    varying = [tuple(item for item in tail if item not in common_tail) for tail in tails]
    if any(len(items) != 1 for items in varying):
        return None
    varying_literals = tuple(sorted(items[0] for items in varying))
    tail_evidence = _coherent_table_axis(varying_literals, metadata, "tails")
    if tail_evidence is None:
        return None
    tail_evidence["common_tail"] = sorted(common_tail)
    return tail_evidence


def _candidate_id(
    left_literals: Sequence[int], tails: Sequence[Sequence[int]]
) -> str:
    payload = {
        "left_literals": list(left_literals),
        "tails": [list(tail) for tail in tails],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return "bva-" + digest[:20]


def _make_candidate(
    lefts: Iterable[int],
    tails: Iterable[Sequence[int]],
    clause_set: set[tuple[int, ...]],
    metadata: Mapping[int, LiteralMetadata],
) -> Candidate | None:
    left_literals = tuple(sorted(set(lefts)))
    canonical_tails = tuple(sorted({_canonical_clause(tail) for tail in tails}))
    if len(left_literals) < 2 or not canonical_tails:
        return None
    if len({abs(literal) for literal in left_literals}) != len(left_literals):
        return None
    left_variables = {abs(literal) for literal in left_literals}
    if any(left_variables.intersection(abs(item) for item in tail) for tail in canonical_tails):
        return None

    removed = tuple(
        sorted(
            _canonical_clause((*tail, left))
            for left in left_literals
            for tail in canonical_tails
        )
    )
    if len(set(removed)) != len(removed) or any(clause not in clause_set for clause in removed):
        return None

    evidence = _table_evidence(left_literals, canonical_tails, metadata)
    removed_literals = sum(len(clause) for clause in removed)
    added_literals = 2 * len(left_literals) + sum(
        1 + len(tail) for tail in canonical_tails
    )
    max_removed_width = max(len(clause) for clause in removed)
    max_added_width = max(
        [2, *(1 + len(tail) for tail in canonical_tails)]
    )
    evidence_json = (
        json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        if evidence is not None
        else None
    )
    return Candidate(
        candidate_id=_candidate_id(left_literals, canonical_tails),
        left_literals=left_literals,
        tails=canonical_tails,
        removed_clauses=removed,
        removed_literal_count=removed_literals,
        added_literal_count=added_literals,
        removed_clause_count=len(removed),
        added_clause_count=len(left_literals) + len(canonical_tails),
        max_removed_width=max_removed_width,
        max_added_width=max_added_width,
        classification="table-aware" if evidence is not None else "syntactic",
        table_evidence_json=evidence_json,
    )


def _policy_rejection(candidate: Candidate, width_cap: int | None) -> str | None:
    if candidate.literal_reduction <= 0:
        return "no_literal_reduction"
    if candidate.max_added_width > candidate.max_removed_width:
        return "width_increase"
    if width_cap is not None and candidate.max_added_width > width_cap:
        return "width_cap"
    return None


def _candidate_rank(candidate: Candidate, width_cap: int | None) -> tuple[object, ...]:
    return (
        0 if _policy_rejection(candidate, width_cap) is None else 1,
        -candidate.literal_reduction,
        0 if candidate.classification == "table-aware" else 1,
        -candidate.clause_reduction,
        candidate.left_literals,
        candidate.tails,
        candidate.candidate_id,
    )


def _intersection(sets: Sequence[set[Any]]) -> set[Any]:
    if not sets:
        return set()
    result = set(sets[0])
    for values in sets[1:]:
        result.intersection_update(values)
        if not result:
            break
    return result


def _enumerate_candidates(
    cnf: Cnf,
    metadata: Mapping[int, LiteralMetadata],
    candidate_cap: int,
    width_cap: int | None,
) -> tuple[list[Candidate], dict[str, object]]:
    if candidate_cap == 0:
        return [], {
            "candidate_cap": 0,
            "retained": 0,
            "truncated": True,
            "pair_seeds_scanned": 0,
        }

    clause_set = set(cnf.clauses)
    neighbors: dict[int, set[tuple[int, ...]]] = defaultdict(set)
    reverse: dict[tuple[int, ...], set[int]] = defaultdict(set)
    for clause in sorted(clause_set):
        if len(clause) < 2 or len({abs(literal) for literal in clause}) != len(clause):
            continue
        for index, left in enumerate(clause):
            tail = clause[:index] + clause[index + 1 :]
            neighbors[left].add(tail)
            reverse[tail].add(left)

    retained: dict[str, Candidate] = {}
    truncated = False
    candidates_seen = 0

    def retain(candidate: Candidate | None) -> None:
        nonlocal candidates_seen, truncated
        if candidate is None or candidate.candidate_id in retained:
            return
        candidates_seen += 1
        if len(retained) < candidate_cap:
            retained[candidate.candidate_id] = candidate
            return
        worst = max(retained.values(), key=lambda item: _candidate_rank(item, width_cap))
        if _candidate_rank(candidate, width_cap) < _candidate_rank(worst, width_cap):
            del retained[worst.candidate_id]
            retained[candidate.candidate_id] = candidate
        truncated = True

    primary_axes: list[tuple[tuple[int, ...], tuple[tuple[int, ...], ...]]] = []
    for tail, lefts in reverse.items():
        primary_axes.append((tuple(sorted(lefts)), (tail,)))

    tails_by_lefts: dict[tuple[int, ...], list[tuple[int, ...]]] = defaultdict(list)
    for tail, lefts in reverse.items():
        tails_by_lefts[tuple(sorted(lefts))].append(tail)
    for lefts, tails in tails_by_lefts.items():
        primary_axes.append((lefts, tuple(sorted(tails))))

    lefts_by_tails: dict[tuple[tuple[int, ...], ...], list[int]] = defaultdict(list)
    for left, tails in neighbors.items():
        lefts_by_tails[tuple(sorted(tails))].append(left)
    for tails, lefts in lefts_by_tails.items():
        primary_axes.append((tuple(sorted(lefts)), tails))

    def rough_rank(
        axes: tuple[tuple[int, ...], tuple[tuple[int, ...], ...]]
    ) -> tuple[object, ...]:
        lefts, tails = axes
        removed = len(lefts) * sum(1 + len(tail) for tail in tails)
        added = 2 * len(lefts) + sum(1 + len(tail) for tail in tails)
        return (-(removed - added), lefts, tails)

    for lefts, tails in sorted(set(primary_axes), key=rough_rank):
        retain(_make_candidate(lefts, tails, clause_set, metadata))

    pair_scan_cap = max(1024, candidate_cap * 64)
    pair_seeds_scanned = 0
    ordered_lefts = sorted(neighbors, key=lambda item: (-len(neighbors[item]), item))
    for first, second in itertools.combinations(ordered_lefts, 2):
        if pair_seeds_scanned >= pair_scan_cap:
            truncated = True
            break
        pair_seeds_scanned += 1
        common_tails = neighbors[first].intersection(neighbors[second])
        if not common_tails:
            continue
        closed_lefts = _intersection([reverse[tail] for tail in sorted(common_tails)])
        closed_tails = _intersection(
            [neighbors[left] for left in sorted(closed_lefts)]
        )
        retain(_make_candidate(closed_lefts, closed_tails, clause_set, metadata))

    if pair_seeds_scanned < pair_scan_cap:
        ordered_tails = sorted(reverse, key=lambda item: (-len(reverse[item]), item))
        for first, second in itertools.combinations(ordered_tails, 2):
            if pair_seeds_scanned >= pair_scan_cap:
                truncated = True
                break
            pair_seeds_scanned += 1
            common_lefts = reverse[first].intersection(reverse[second])
            if len(common_lefts) < 2:
                continue
            closed_tails = _intersection(
                [neighbors[left] for left in sorted(common_lefts)]
            )
            closed_lefts = _intersection(
                [reverse[tail] for tail in sorted(closed_tails)]
            )
            retain(_make_candidate(closed_lefts, closed_tails, clause_set, metadata))

    candidates = sorted(retained.values(), key=lambda item: _candidate_rank(item, width_cap))
    return candidates, {
        "candidate_cap": candidate_cap,
        "retained": len(candidates),
            "candidate_admission_events": candidates_seen,
        "truncated": truncated,
        "pair_seed_cap": pair_scan_cap,
        "pair_seeds_scanned": pair_seeds_scanned,
        "left_literals_indexed": len(neighbors),
        "tails_indexed": len(reverse),
    }


def _added_clauses(candidate: Candidate, new_variable: int) -> tuple[tuple[int, ...], ...]:
    return tuple(
        sorted(
            [
                *(
                    _canonical_clause((literal, new_variable))
                    for literal in candidate.left_literals
                ),
                *(
                    _canonical_clause((-new_variable, *tail))
                    for tail in candidate.tails
                ),
            ]
        )
    )


def _apply_exact_rewrite(
    clauses: Sequence[Sequence[int]],
    removed: Sequence[Sequence[int]],
    added: Sequence[Sequence[int]],
) -> tuple[tuple[int, ...], ...]:
    counts = Counter(_canonical_clauses(clauses))
    for clause in _canonical_clauses(removed):
        if counts[clause] <= 0:
            raise CertificateError(f"removed clause {list(clause)} is absent")
        counts[clause] -= 1
        if counts[clause] == 0:
            del counts[clause]
    counts.update(_canonical_clauses(added))
    expanded: list[tuple[int, ...]] = []
    for clause, multiplicity in sorted(counts.items()):
        expanded.extend([clause] * multiplicity)
    return tuple(expanded)


def _candidate_report(
    candidate: Candidate,
    decision: str,
    reason: str,
    new_variable: int | None,
) -> dict[str, object]:
    return {
        "id": candidate.candidate_id,
        "classification": candidate.classification,
        "table_evidence": candidate.table_evidence,
        "left_literals": list(candidate.left_literals),
        "tails": [list(tail) for tail in candidate.tails],
        "removed_clauses": [list(clause) for clause in candidate.removed_clauses],
        "metrics": {
            "removed_clauses": candidate.removed_clause_count,
            "added_clauses": candidate.added_clause_count,
            "clause_reduction": candidate.clause_reduction,
            "removed_literals": candidate.removed_literal_count,
            "added_literals": candidate.added_literal_count,
            "literal_reduction": candidate.literal_reduction,
            "max_removed_width": candidate.max_removed_width,
            "max_added_width": candidate.max_added_width,
        },
        "decision": decision,
        "reason": reason,
        "new_variable": new_variable,
    }


def _satisfies(clauses: Sequence[Sequence[int]], assignment: int) -> bool:
    for clause in clauses:
        clause_true = False
        for literal in clause:
            value = bool(assignment & (1 << (abs(literal) - 1)))
            if value == (literal > 0):
                clause_true = True
                break
        if not clause_true:
            return False
    return True


def exhaustive_projective_check(
    original: Cnf,
    projected: Cnf,
    max_variables: int = DEFAULT_EXHAUSTIVE_MAX_VARIABLES,
) -> dict[str, object]:
    """Check ``original == exists(added vars). projected`` by enumeration."""
    if not _is_int(max_variables) or max_variables < 0:
        raise AnalyzerError("exhaustive max_variables must be non-negative")
    if projected.variables < original.variables:
        raise AnalyzerError("projected CNF has fewer variables than original CNF")
    if projected.variables > max_variables:
        return {
            "status": "skipped",
            "reason": "variable_cap",
            "max_variables": max_variables,
            "original_variables": original.variables,
            "projected_variables": projected.variables,
        }

    added_variables = projected.variables - original.variables
    extension_count = 1 << added_variables
    extension_assignments_checked = 0
    for original_assignment in range(1 << original.variables):
        original_result = _satisfies(original.clauses, original_assignment)
        projected_result = False
        for extension in range(extension_count):
            assignment = original_assignment | (extension << original.variables)
            extension_assignments_checked += 1
            if _satisfies(projected.clauses, assignment):
                projected_result = True
                break
        if original_result != projected_result:
            return {
                "status": "mismatch",
                "equivalent": False,
                "original_assignments_checked": original_assignment + 1,
                "extension_assignments_checked": extension_assignments_checked,
                "witness": {
                    "original_true_variables": [
                        variable
                        for variable in range(1, original.variables + 1)
                        if original_assignment & (1 << (variable - 1))
                    ],
                    "original_result": original_result,
                    "projected_has_extension": projected_result,
                },
            }
    return {
        "status": "verified",
        "equivalent": True,
        "original_assignments_checked": 1 << original.variables,
        "extension_assignments_checked": extension_assignments_checked,
        "added_variables": added_variables,
    }


def _require_mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise CertificateError(f"{context} must be an object")
    return value


def _require_int(value: object, context: str, minimum: int = 0) -> int:
    if not _is_int(value) or value < minimum:
        raise CertificateError(f"{context} must be an integer >= {minimum}")
    return value


def _certificate_clauses(value: object, context: str) -> tuple[tuple[int, ...], ...]:
    if not isinstance(value, list):
        raise CertificateError(f"{context} must be an array")
    clauses: list[tuple[int, ...]] = []
    for clause_index, raw_clause in enumerate(value):
        if not isinstance(raw_clause, list):
            raise CertificateError(f"{context}[{clause_index}] must be an array")
        clause: list[int] = []
        for literal in raw_clause:
            if not _is_int(literal) or literal == 0:
                raise CertificateError(f"{context} contains a non-DIMACS literal")
            clause.append(literal)
        canonical = _canonical_clause(clause)
        if list(canonical) != raw_clause:
            raise CertificateError(f"{context} is not canonically sorted")
        clauses.append(canonical)
    canonical_clauses = tuple(sorted(clauses))
    if list(map(list, canonical_clauses)) != value:
        raise CertificateError(f"{context} is not canonically sorted")
    return canonical_clauses


def _metric_record(value: object, context: str) -> dict[str, object]:
    record = _require_mapping(value, context)
    required = {"variables", "clauses", "literal_count", "max_width", "sha256"}
    if set(record) != required:
        raise CertificateError(f"{context} has incorrect metric fields")
    for key in ("variables", "clauses", "literal_count", "max_width"):
        _require_int(record[key], f"{context}.{key}")
    digest = record["sha256"]
    if not isinstance(digest, str) or len(digest) != 64:
        raise CertificateError(f"{context}.sha256 must be a SHA-256 hex string")
    try:
        bytes.fromhex(digest)
    except ValueError as error:
        raise CertificateError(
            f"{context}.sha256 must be a SHA-256 hex string"
        ) from error
    return dict(record)


def verify_certificate(
    original: Cnf,
    certificate: object,
    exhaustive_max_variables: int = DEFAULT_EXHAUSTIVE_MAX_VARIABLES,
) -> dict[str, object]:
    """Replay a certificate exactly, then independently check small formulas."""
    root = _require_mapping(certificate, "certificate")
    required_root = {
        "schema",
        "policy",
        "original",
        "steps",
        "projected",
        "projected_clauses",
    }
    if set(root) != required_root:
        raise CertificateError("certificate has incorrect top-level fields")
    if root["schema"] != CERTIFICATE_SCHEMA:
        raise CertificateError("unsupported certificate schema")

    policy = _require_mapping(root["policy"], "certificate.policy")
    if set(policy) != {"require_strict_literal_reduction", "forbid_width_increase", "width_cap"}:
        raise CertificateError("certificate.policy has incorrect fields")
    if policy["require_strict_literal_reduction"] is not True:
        raise CertificateError("certificate must require strict literal reduction")
    if policy["forbid_width_increase"] is not True:
        raise CertificateError("certificate must forbid width increase")
    width_cap = policy["width_cap"]
    if width_cap is not None:
        width_cap = _require_int(width_cap, "certificate.policy.width_cap", 1)

    if _metric_record(root["original"], "certificate.original") != formula_metrics(
        original.variables, original.clauses
    ):
        raise CertificateError("certificate original metrics/hash do not match input")

    raw_steps = root["steps"]
    if not isinstance(raw_steps, list):
        raise CertificateError("certificate.steps must be an array")
    current_variables = original.variables
    current_clauses = original.clauses

    for step_index, raw_step in enumerate(raw_steps):
        step = _require_mapping(raw_step, f"certificate.steps[{step_index}]")
        required_step = {
            "index",
            "candidate_id",
            "new_variable",
            "left_literals",
            "tails",
            "removed_clauses",
            "added_clauses",
            "literal_reduction",
            "before",
            "after",
        }
        if set(step) != required_step:
            raise CertificateError(f"certificate step {step_index} has incorrect fields")
        if step["index"] != step_index:
            raise CertificateError(f"certificate step {step_index} has incorrect index")
        before = formula_metrics(current_variables, current_clauses)
        if _metric_record(step["before"], f"step {step_index}.before") != before:
            raise CertificateError(f"certificate step {step_index} before-state mismatch")

        new_variable = _require_int(
            step["new_variable"], f"step {step_index}.new_variable", 1
        )
        if new_variable != current_variables + 1:
            raise CertificateError(f"certificate step {step_index} new variable is not fresh")
        raw_lefts = step["left_literals"]
        if not isinstance(raw_lefts, list) or any(
            not _is_int(literal) or literal == 0 for literal in raw_lefts
        ):
            raise CertificateError(f"certificate step {step_index} has invalid left literals")
        lefts = tuple(sorted(raw_lefts))
        if list(lefts) != raw_lefts or len(lefts) < 2 or len(set(lefts)) != len(lefts):
            raise CertificateError(
                f"certificate step {step_index} left literals are not canonical"
            )
        if any(abs(literal) > current_variables for literal in lefts):
            raise CertificateError(f"certificate step {step_index} uses an unknown literal")
        tails = _certificate_clauses(step["tails"], f"step {step_index}.tails")
        if not tails:
            raise CertificateError(f"certificate step {step_index} has no tails")

        expected_id = _candidate_id(lefts, tails)
        if step["candidate_id"] != expected_id:
            raise CertificateError(f"certificate step {step_index} candidate ID mismatch")
        left_variables = {abs(literal) for literal in lefts}
        if len(left_variables) != len(lefts) or any(
            left_variables.intersection(abs(item) for item in tail) for tail in tails
        ):
            raise CertificateError(f"certificate step {step_index} has degenerate axes")

        expected_removed = tuple(
            sorted(
                _canonical_clause((*tail, left))
                for left in lefts
                for tail in tails
            )
        )
        removed = _certificate_clauses(
            step["removed_clauses"], f"step {step_index}.removed_clauses"
        )
        if removed != expected_removed:
            raise CertificateError(f"certificate step {step_index} rectangle mismatch")

        expected_added = tuple(
            sorted(
                [
                    *(_canonical_clause((literal, new_variable)) for literal in lefts),
                    *(
                        _canonical_clause((-new_variable, *tail))
                        for tail in tails
                    ),
                ]
            )
        )
        added = _certificate_clauses(
            step["added_clauses"], f"step {step_index}.added_clauses"
        )
        if added != expected_added:
            raise CertificateError(f"certificate step {step_index} added clauses mismatch")

        reduction = sum(map(len, removed)) - sum(map(len, added))
        if step["literal_reduction"] != reduction or reduction <= 0:
            raise CertificateError(
                f"certificate step {step_index} lacks strict literal reduction"
            )
        max_removed = max(map(len, removed), default=0)
        max_added = max(map(len, added), default=0)
        if max_added > max_removed:
            raise CertificateError(f"certificate step {step_index} increases clause width")
        if width_cap is not None and max_added > width_cap:
            raise CertificateError(f"certificate step {step_index} exceeds width cap")

        current_clauses = _apply_exact_rewrite(current_clauses, removed, added)
        current_variables = new_variable
        after = formula_metrics(current_variables, current_clauses)
        if _metric_record(step["after"], f"step {step_index}.after") != after:
            raise CertificateError(f"certificate step {step_index} after-state mismatch")

    projected_clauses = _certificate_clauses(
        root["projected_clauses"], "certificate.projected_clauses"
    )
    if projected_clauses != current_clauses:
        raise CertificateError("certificate projected clause multiset mismatch")
    projected_metrics = _metric_record(root["projected"], "certificate.projected")
    if projected_metrics != formula_metrics(current_variables, current_clauses):
        raise CertificateError("certificate projected metrics/hash mismatch")

    projected = Cnf(current_variables, current_clauses)
    exhaustive = exhaustive_projective_check(
        original, projected, max_variables=exhaustive_max_variables
    )
    if exhaustive["status"] == "mismatch":
        raise CertificateError("certificate failed exhaustive semantic validation")
    return {
        "structural": "verified",
        "steps_replayed": len(raw_steps),
        "exhaustive": exhaustive,
    }


def analyze_cnf(
    cnf: Cnf,
    metadata: Mapping[int, LiteralMetadata] | None = None,
    *,
    width_cap: int | None = None,
    candidate_cap: int = DEFAULT_CANDIDATE_CAP,
    max_added_variables: int = DEFAULT_MAX_ADDED_VARIABLES,
    exhaustive_max_variables: int = DEFAULT_EXHAUSTIVE_MAX_VARIABLES,
) -> dict[str, object]:
    """Analyze, project, certify, and conditionally exhaustively check one CNF."""
    if width_cap is not None and (not _is_int(width_cap) or width_cap < 1):
        raise AnalyzerError("width_cap must be a positive integer or None")
    if not _is_int(candidate_cap) or candidate_cap < 0:
        raise AnalyzerError("candidate_cap must be a non-negative integer")
    if not _is_int(max_added_variables) or max_added_variables < 0:
        raise AnalyzerError("max_added_variables must be a non-negative integer")
    if not _is_int(exhaustive_max_variables) or exhaustive_max_variables < 0:
        raise AnalyzerError("exhaustive_max_variables must be non-negative")
    metadata = dict(metadata or {})
    for literal in metadata:
        if not _is_int(literal) or literal == 0 or abs(literal) > cnf.variables:
            raise MetadataError(f"invalid metadata literal {literal!r}")
        if not isinstance(metadata[literal], LiteralMetadata):
            raise MetadataError(f"metadata literal {literal} has invalid record type")

    candidates, enumeration = _enumerate_candidates(
        cnf, metadata, candidate_cap, width_cap
    )
    used_clauses: set[tuple[int, ...]] = set()
    accepted: list[Candidate] = []
    decisions: dict[str, tuple[str, str]] = {}
    for candidate in candidates:
        rejection = _policy_rejection(candidate, width_cap)
        if rejection is not None:
            decisions[candidate.candidate_id] = ("rejected", rejection)
        elif any(clause in used_clauses for clause in candidate.removed_clauses):
            decisions[candidate.candidate_id] = ("rejected", "overlap")
        elif len(accepted) >= max_added_variables:
            decisions[candidate.candidate_id] = ("rejected", "added_variable_cap")
        else:
            accepted.append(candidate)
            used_clauses.update(candidate.removed_clauses)
            decisions[candidate.candidate_id] = ("accepted", "strict_literal_reduction")

    current_variables = cnf.variables
    current_clauses = cnf.clauses
    steps: list[dict[str, object]] = []
    new_variables: dict[str, int] = {}
    for step_index, candidate in enumerate(accepted):
        before = formula_metrics(current_variables, current_clauses)
        new_variable = current_variables + 1
        added = _added_clauses(candidate, new_variable)
        current_clauses = _apply_exact_rewrite(
            current_clauses, candidate.removed_clauses, added
        )
        current_variables = new_variable
        after = formula_metrics(current_variables, current_clauses)
        new_variables[candidate.candidate_id] = new_variable
        steps.append(
            {
                "index": step_index,
                "candidate_id": candidate.candidate_id,
                "new_variable": new_variable,
                "left_literals": list(candidate.left_literals),
                "tails": [list(tail) for tail in candidate.tails],
                "removed_clauses": [
                    list(clause) for clause in candidate.removed_clauses
                ],
                "added_clauses": [list(clause) for clause in added],
                "literal_reduction": candidate.literal_reduction,
                "before": before,
                "after": after,
            }
        )

    original_metrics = formula_metrics(cnf.variables, cnf.clauses)
    projected_metrics = formula_metrics(current_variables, current_clauses)
    certificate: dict[str, object] = {
        "schema": CERTIFICATE_SCHEMA,
        "policy": {
            "require_strict_literal_reduction": True,
            "forbid_width_increase": True,
            "width_cap": width_cap,
        },
        "original": original_metrics,
        "steps": steps,
        "projected": projected_metrics,
        "projected_clauses": [list(clause) for clause in current_clauses],
    }
    verification = verify_certificate(
        cnf, certificate, exhaustive_max_variables=exhaustive_max_variables
    )

    candidate_reports = []
    for candidate in candidates:
        decision, reason = decisions[candidate.candidate_id]
        candidate_reports.append(
            _candidate_report(
                candidate,
                decision,
                reason,
                new_variables.get(candidate.candidate_id),
            )
        )

    accepted_table = sum(
        candidate.classification == "table-aware" for candidate in accepted
    )
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "configuration": {
            "width_cap": width_cap,
            "candidate_cap": candidate_cap,
            "max_added_variables": max_added_variables,
            "exhaustive_max_variables": exhaustive_max_variables,
        },
        "metadata": {
            "provided": bool(metadata),
            "mapped_literals": len(metadata),
            "sha256": _metadata_digest(metadata) if metadata else None,
        },
        "original": original_metrics,
        "projected": {
            **projected_metrics,
            "added_variables": current_variables - cnf.variables,
        },
        "summary": {
            "candidates_retained": len(candidates),
            "accepted": len(accepted),
            "rejected": len(candidates) - len(accepted),
            "accepted_table_aware": accepted_table,
            "accepted_syntactic": len(accepted) - accepted_table,
            "literal_reduction": int(original_metrics["literal_count"])
            - int(projected_metrics["literal_count"]),
            "clause_reduction": int(original_metrics["clauses"])
            - int(projected_metrics["clauses"]),
        },
        "enumeration": enumeration,
        "candidates": candidate_reports,
        "certificate": certificate,
        "verification": verification,
    }
    return report


def _non_negative_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if value < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return value


def _positive_int(text: str) -> int:
    value = _non_negative_int(text)
    if value == 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("cnf", type=Path, help="input DIMACS CNF")
    parser.add_argument(
        "--metadata",
        type=Path,
        help="optional finite-table literal metadata JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write JSON report here instead of stdout",
    )
    parser.add_argument(
        "--width-cap",
        type=_positive_int,
        help="reject rewrites whose newly added clauses exceed this width",
    )
    parser.add_argument(
        "--candidate-cap",
        type=_non_negative_int,
        default=DEFAULT_CANDIDATE_CAP,
        help="maximum candidate rectangles retained in the report",
    )
    parser.add_argument(
        "--max-added-variables",
        type=_non_negative_int,
        default=DEFAULT_MAX_ADDED_VARIABLES,
        help="maximum accepted BVA variables",
    )
    parser.add_argument(
        "--exhaustive-max-variables",
        type=_non_negative_int,
        default=DEFAULT_EXHAUSTIVE_MAX_VARIABLES,
        help="truth-table-check only projections at or below this variable count",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cnf = load_dimacs(args.cnf)
        metadata: dict[int, LiteralMetadata] = {}
        if args.metadata is not None:
            metadata = parse_metadata(load_metadata_json(args.metadata), cnf.variables)
        report = analyze_cnf(
            cnf,
            metadata,
            width_cap=args.width_cap,
            candidate_cap=args.candidate_cap,
            max_added_variables=args.max_added_variables,
            exhaustive_max_variables=args.exhaustive_max_variables,
        )
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            args.output.write_text(rendered, encoding="utf-8")
    except (AnalyzerError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
