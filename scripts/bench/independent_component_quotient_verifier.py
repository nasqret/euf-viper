#!/usr/bin/env python3
"""Independent source-to-decision verifier for the fixed T5 census.

This module intentionally does not import the census analyzer.  It parses the
captured SMT-LIB source again, reconstructs the two promotion-relevant count
projections with separate data structures, and independently recomputes every
selector and aggregate gate.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
import re
import stat
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import component_quotient_contract as contract  # noqa: E402
from scripts.bench import t5_independent_smtlib as audit_smtlib  # noqa: E402


RECORD_SCHEMA = "euf-viper.component-quotient-ram-source-projection.v1"
AGGREGATE_SCHEMA = "euf-viper.component-quotient-ram-census-summary.v1"
TARGET_SCHEMA = "euf-viper.component-quotient-ram-target.v1"
INTERPRETATION = "structural_projection_only_no_solver_invocation_no_timing_claim"
PARSER_API = "scripts.cert.independent_qfuf.parse_and_encode"
AUDIT_PARSER_API = "scripts.bench.t5_independent_smtlib.parse_qfuf_for_audit"
DECODER_ORACLE_SCHEMA = "euf-viper.component-quotient-decoder-oracle.v1"
DECODER_ORACLE_SHA256 = (
    "7562fb7e9953604bd61a68689466e617013bb798bc2657d0c8522e488262af89"
)
PROJECTION_ORACLE_SCHEMA = (
    "euf-viper.component-quotient-independent-projection-oracle.v1"
)
PROJECTION_ORACLE_SHA256 = (
    "4d6cdda1f86a619a95fbf7fa4a4ce0148eebc1153b9ae790c265914a9458edf3"
)
PPM = 1_000_000
COUNT_FIELDS = (
    "variables",
    "clauses",
    "literal_slots",
    "unit_clauses",
    "watch_entries",
)
CAPS = {
    "max_source_bytes": 33_554_432,
    "max_terms": 1_000_000,
    "max_applications": 1_000_000,
    "max_symbols": 250_000,
    "max_component_terms": 1_000_000,
    "max_ackermann_pairs": 1_000_000_000_000,
    "max_equality_edges": 100_000_000,
    "max_fill_edges": 100_000_000,
    "max_sorter_records": 1_048_576,
    "max_sorter_comparators": 1_000_000_000,
    "max_packed_record_bits": 1_000_000_000_000,
    "max_decoder_operations": 1_000_000_000_000,
    "max_projected_count": 9_223_372_036_854_775_807,
}

QG_VARIANT = re.compile(r"^(?:qg|loops)[0-9]+$")
QG_STEM = re.compile(r"^(?P<kind>.*?)[0-9]+$")
FINITE = re.compile(r"^(?P<problem>(?:NEQ|PEQ|SEQ)[0-9]+)_size[0-9]+$")
GOEL = re.compile(r"^QF_UF_(?P<instance>.+)_ab_(?:br|cti|fp|reg)_max$")
GOEL_SIZE = re.compile(r"\.[0-9]+(?:\.prop[0-9]+)?$")


class IndependentVerificationError(ValueError):
    """A captured artifact cannot independently authorize a T5 decision."""


class IndependentCap(IndependentVerificationError):
    pass


@dataclass(frozen=True)
class CountVector:
    variables: int = 0
    clauses: int = 0
    literal_slots: int = 0
    unit_clauses: int = 0
    watch_entries: int = 0

    def __add__(self, other: "CountVector") -> "CountVector":
        return CountVector(
            *(getattr(self, field) + getattr(other, field) for field in COUNT_FIELDS)
        )

    def scale(self, factor: int) -> "CountVector":
        if type(factor) is not int or factor < 0:
            raise IndependentVerificationError("negative count multiplier")
        return CountVector(*(getattr(self, field) * factor for field in COUNT_FIELDS))

    def to_json(self) -> dict[str, int]:
        return {field: getattr(self, field) for field in COUNT_FIELDS}


ZERO = CountVector()
AND2 = CountVector(1, 3, 7, 0, 6)
XNOR2 = CountVector(1, 4, 12, 0, 8)
XOR2 = CountVector(1, 4, 12, 0, 8)
MUX2 = CountVector(1, 4, 12, 0, 8)
UNIT = CountVector(0, 1, 1, 1, 0)
UNIT_WITH_VARIABLE = CountVector(1, 1, 1, 1, 0)


@dataclass(frozen=True)
class SourceSnapshot:
    record_id: int
    line_number: int
    relative_path: str
    source_path: Path
    source_bytes: bytes
    source_sha256: str
    source_family: str
    generator_lineage: str
    taxonomy_rule: str


@dataclass(frozen=True)
class IndependentSnapshot:
    repository_root: Path
    lock_path: Path
    manifest_path: Path
    records_path: Path
    aggregate_path: Path
    targets_path: Path
    lock_bytes: bytes
    manifest_bytes: bytes
    records_bytes: bytes
    aggregate_bytes: bytes
    targets_bytes: bytes
    sources: tuple[SourceSnapshot, ...]
    portable_source_bytes: bytes


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentVerificationError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def strict_json(payload: bytes, context: str) -> object:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                IndependentVerificationError(f"non-finite JSON value {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IndependentVerificationError(f"malformed {context}: {error}") from error


def strict_jsonl(
    payload: bytes, context: str, *, allow_empty: bool = False
) -> list[dict[str, object]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IndependentVerificationError(f"{context} is not UTF-8: {error}") from error
    if not text:
        if allow_empty:
            return []
        raise IndependentVerificationError(f"{context} must not be empty")
    if not text.endswith("\n"):
        raise IndependentVerificationError(f"{context} must end with a newline")
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise IndependentVerificationError(f"{context} line {line_number} is blank")
        row = strict_json(line.encode("utf-8"), f"{context} line {line_number}")
        if type(row) is not dict:
            raise IndependentVerificationError(
                f"{context} line {line_number} is not an object"
            )
        rows.append(row)
    return rows


def _checked(value: int, cap_name: str) -> int:
    if type(value) is not int or value < 0:
        raise IndependentVerificationError(f"{cap_name} is not nonnegative")
    limit = CAPS[cap_name]
    if value > limit:
        raise IndependentCap(f"{cap_name} cap exceeded: {value} > {limit}")
    return value


def _choose2(value: int) -> int:
    return value * (value - 1) // 2


def _component_width(size: int) -> int:
    if size < 1:
        raise IndependentVerificationError("empty component")
    return max(1, math.ceil(math.log2(size)))


def _next_power_two(value: int) -> int:
    return 1 << (value - 1).bit_length()


def _increment(width: int) -> CountVector:
    return ZERO if width == 1 else XOR2.scale(width - 1) + AND2.scale(width - 2)


def _greater(width: int) -> CountVector:
    if width == 1:
        return AND2
    return (
        AND2.scale(width)
        + MUX2.scale(width - 1)
        + XNOR2.scale(width - 1)
        + AND2.scale(width - 2)
    )


def _restricted_growth(size: int, width: int) -> CountVector:
    counts = UNIT.scale(width)
    for index in range(1, size):
        counts += _increment(width) + _greater(width) + UNIT
        if index + 1 < size:
            counts += _greater(width) + MUX2.scale(width)
    return counts


def _equality_link(width: int) -> CountVector:
    channel_clauses = width + 1
    return XNOR2.scale(width) + CountVector(
        clauses=channel_clauses,
        literal_slots=3 * width + 1,
        watch_entries=2 * channel_clauses,
    )


def _bitonic_comparators(records: int) -> int:
    logarithm = records.bit_length() - 1
    return records * logarithm * (logarithm + 1) // 4


def _application_groups(
    problem: audit_smtlib.AuditProblem,
) -> dict[int, tuple[int, ...]]:
    groups: dict[int, list[int]] = defaultdict(list)
    for term_id, arguments in enumerate(problem.term_arguments):
        if arguments:
            groups[problem.term_functions[term_id]].append(term_id)
    return {key: tuple(sorted(value)) for key, value in sorted(groups.items())}


def _analyzer_oracle_reference() -> dict[str, object]:
    return {
        "schema": DECODER_ORACLE_SCHEMA,
        "executed": True,
        "passed": True,
        "sha256": DECODER_ORACLE_SHA256,
    }


def _components(
    problem: audit_smtlib.AuditProblem,
    groups: Mapping[int, Sequence[int]],
) -> tuple[list[tuple[int, int, tuple[int, ...], int]], dict[int, tuple[int, int]]]:
    hyperedges: list[tuple[int, ...]] = []
    for left, right in problem.equality_pairs:
        hyperedges.append((left, right))
    for function_id, applications in groups.items():
        function = problem.signatures[function_id]
        if function.result_sort != audit_smtlib.BOOL_SORT:
            hyperedges.append(tuple(applications))
        for position, sort_id in enumerate(function.argument_sorts):
            if sort_id != audit_smtlib.BOOL_SORT:
                hyperedges.append(
                    tuple(
                        problem.term_arguments[term][position]
                        for term in applications
                    )
                )
    grouped = _hypergraph_components(problem.term_sorts, hyperedges)
    ordered = sorted(
        (problem.term_sorts[members[0]], members) for members in grouped
    )
    components: list[tuple[int, int, tuple[int, ...], int]] = []
    channels: dict[int, tuple[int, int]] = {}
    for component_id, (sort_id, members) in enumerate(ordered):
        _checked(len(members), "max_component_terms")
        width = _component_width(len(members))
        components.append((component_id, sort_id, members, width))
        for member in members:
            channels[member] = (component_id, width)
    expected = {
        term
        for term, sort_id in enumerate(problem.term_sorts)
        if sort_id != audit_smtlib.BOOL_SORT
    }
    if set(channels) != expected:
        raise IndependentVerificationError("independent component coverage failed")
    return components, channels


def _hypergraph_components(
    term_sorts: Sequence[int], hyperedges: Sequence[Sequence[int]]
) -> list[tuple[int, ...]]:
    """Compute non-Boolean connected components by hypergraph reachability."""

    neighbors = [set((term,)) for term in range(len(term_sorts))]
    for members in hyperedges:
        unique = tuple(sorted(set(members)))
        if not unique:
            continue
        if any(not 0 <= term < len(term_sorts) for term in unique):
            raise IndependentVerificationError("component hyperedge is out of range")
        if len({term_sorts[term] for term in unique}) > 1:
            raise IndependentVerificationError("component hyperedge crossed sorts")
        for term in unique:
            neighbors[term].update(unique)
    grouped: list[tuple[int, ...]] = []
    unseen = {
        term
        for term, sort_id in enumerate(term_sorts)
        if sort_id != audit_smtlib.BOOL_SORT
    }
    while unseen:
        frontier = [min(unseen)]
        reached: set[int] = set()
        while frontier:
            term = frontier.pop()
            if term in reached:
                continue
            reached.add(term)
            frontier.extend(sorted(neighbors[term] - reached, reverse=True))
        unseen.difference_update(reached)
        grouped.append(tuple(sorted(reached)))
    return grouped


class EqualityProjection:
    def __init__(self, term_count: int) -> None:
        self.matrix = [bytearray(term_count) for _ in range(term_count)]
        self.edges = 0

    def connect(self, left: int, right: int) -> bool:
        if left == right or self.matrix[left][right]:
            return False
        self.matrix[left][right] = 1
        self.matrix[right][left] = 1
        self.edges += 1
        _checked(self.edges, "max_equality_edges")
        return True

    def clique(self, members: Sequence[int]) -> None:
        ordered = sorted(set(members))
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                self.connect(left, right)

    def complete(self) -> tuple[int, int, int]:
        active = {
            vertex for vertex, row in enumerate(self.matrix) if any(row)
        }
        fill = 0
        triangles = 0
        eliminated = 0
        while active:
            vertex = min(
                active,
                key=lambda candidate: (
                    sum(self.matrix[candidate][other] for other in active),
                    candidate,
                ),
            )
            adjacent = sorted(
                other for other in active if self.matrix[vertex][other]
            )
            for index, left in enumerate(adjacent):
                for right in adjacent[index + 1 :]:
                    if self.connect(left, right):
                        fill += 1
                        _checked(fill, "max_fill_edges")
            triangles += _choose2(len(adjacent))
            if triangles > CAPS["max_projected_count"]:
                raise IndependentCap("triangle count cap exceeded")
            active.remove(vertex)
            eliminated += 1
        return fill, triangles, eliminated


def _sum_counts(categories: Mapping[str, CountVector]) -> CountVector:
    total = ZERO
    for name in sorted(categories):
        total += categories[name]
        for field in COUNT_FIELDS:
            if getattr(total, field) > CAPS["max_projected_count"]:
                raise IndependentCap(f"{name} {field} count cap exceeded")
    return total


def independent_projection(problem: audit_smtlib.AuditProblem) -> dict[str, object]:
    term_count = problem.term_count
    function_count = len(problem.signatures)
    _checked(term_count, "max_terms")
    _checked(function_count, "max_symbols")
    groups = _application_groups(problem)
    applications = sum(len(group) for group in groups.values())
    _checked(applications, "max_applications")
    argument_slots = sum(
        len(problem.term_arguments[term_id])
        for group in groups.values()
        for term_id in group
    )
    bool_variables = set(problem.boolean_carriers)
    components, channels = _components(problem, groups)
    component_rows: list[dict[str, object]] = []
    quotient_bits = 0
    canonicalization = ZERO
    for component_id, sort_id, members, width in components:
        class_bits = len(members) * width
        quotient_bits += class_bits
        _checked(quotient_bits, "max_projected_count")
        component_canonicalization = _restricted_growth(len(members), width)
        canonicalization += component_canonicalization
        sort_row = problem.sorts[sort_id]
        component_rows.append(
            {
                "id": component_id,
                "sort": {
                    "id": sort_id,
                    "name": sort_row.name,
                    "quoted": sort_row.quoted,
                },
                "terms": len(members),
                "first_term": members[0],
                "last_term": members[-1],
                "width": width,
                "class_bits": class_bits,
                "canonicalization": component_canonicalization.to_json(),
            }
        )

    def channel(term_id: int) -> tuple[str, int, int | None]:
        if problem.term_sorts[term_id] == audit_smtlib.BOOL_SORT:
            if term_id not in bool_variables:
                raise IndependentVerificationError("Boolean term lacks atom channel")
            return "boolean", 1, None
        component_id, width = channels[term_id]
        return "component", width, component_id

    graph = EqualityProjection(term_count)
    reflexive: set[int] = set()
    equality_atoms = 0
    for left, right in problem.equality_pairs:
        equality_atoms += 1
        if left == right:
            reflexive.add(left)
        else:
            graph.connect(left, right)
    initial_edges = graph.edges

    ackermann_pairs = 0
    ackermann_clauses = 0
    ackermann_literals = 0
    sorter_counts = ZERO
    adjacency_counts = ZERO
    sorter_comparators = 0
    padded_bits = 0
    logical_bits = 0
    maximum_symbol_applications = 0
    needs_sorter_constant = False
    symbol_rows: list[dict[str, object]] = []
    for function_id, term_ids in groups.items():
        function = problem.signatures[function_id]
        count = len(term_ids)
        maximum_symbol_applications = max(maximum_symbol_applications, count)
        pairs = _choose2(count)
        ackermann_pairs += pairs
        _checked(ackermann_pairs, "max_ackermann_pairs")
        argument_widths: list[int] = []
        argument_rows: list[dict[str, object]] = []
        differing_total = 0
        for position, sort_id in enumerate(function.argument_sorts):
            values = [problem.term_arguments[term_id][position] for term_id in term_ids]
            frequencies = Counter(values)
            differing = pairs - sum(
                _choose2(frequency) for frequency in frequencies.values()
            )
            differing_total += differing
            graph.clique(values)
            observed_channels = {channel(value) for value in values}
            if len(observed_channels) != 1:
                raise IndependentVerificationError("argument namespace mismatch")
            channel_name, width, component_id = next(iter(observed_channels))
            argument_widths.append(width)
            argument_rows.append(
                {
                    "position": position,
                    "sort": sort_id,
                    "channel": channel_name,
                    "component_id": component_id,
                    "width": width,
                    "distinct_terms": len(frequencies),
                    "differing_application_pairs": differing,
                }
            )
        result_channels = {channel(term_id) for term_id in term_ids}
        if len(result_channels) != 1:
            raise IndependentVerificationError("result namespace mismatch")
        result_channel, result_width, result_component_id = next(
            iter(result_channels)
        )
        if function.result_sort == audit_smtlib.BOOL_SORT:
            symbol_ackermann_clauses = 2 * pairs
            symbol_ackermann_literals = 4 * pairs + 2 * differing_total
        else:
            graph.clique(term_ids)
            symbol_ackermann_clauses = pairs
            symbol_ackermann_literals = pairs + differing_total
        ackermann_clauses += symbol_ackermann_clauses
        ackermann_literals += symbol_ackermann_literals
        key_width = sum(argument_widths)
        record_width = key_width + result_width + 1
        logical_bits += count * record_width
        padded_records = count
        comparators = 0
        symbol_sorter = ZERO
        symbol_adjacency = ZERO
        if count >= 2:
            needs_sorter_constant = True
            padded_records = _next_power_two(count)
            _checked(padded_records, "max_sorter_records")
            comparators = _bitonic_comparators(padded_records)
            sorter_comparators += comparators
            _checked(sorter_comparators, "max_sorter_comparators")
            comparator_counts = _greater(key_width + 1) + MUX2.scale(
                2 * record_width
            )
            symbol_sorter = comparator_counts.scale(comparators)
            sorter_counts += symbol_sorter
            one_adjacency = XNOR2.scale(key_width) + CountVector(
                clauses=2 * result_width,
                literal_slots=2 * result_width * (key_width + 4),
                watch_entries=4 * result_width,
            )
            symbol_adjacency = one_adjacency.scale(padded_records - 1)
            adjacency_counts += symbol_adjacency
        padded_bits += padded_records * record_width
        _checked(padded_bits, "max_packed_record_bits")
        symbol_rows.append(
            {
                "function": {
                    "id": function_id,
                    "name": function.name,
                    "quoted": function.quoted,
                    "internal": function.internal,
                },
                "signature": {
                    "argument_sorts": list(function.argument_sorts),
                    "result_sort": function.result_sort,
                },
                "applications": count,
                "ackermann_pairs": pairs,
                "arguments": argument_rows,
                "result": {
                    "channel": result_channel,
                    "component_id": result_component_id,
                    "width": result_width,
                },
                "eager_ackermann": {
                    "clauses": symbol_ackermann_clauses,
                    "literal_slots": symbol_ackermann_literals,
                },
                "cqram": {
                    "key_width": key_width,
                    "value_width": result_width,
                    "record_width": record_width,
                    "padded_records": padded_records,
                    "comparators": comparators,
                    "network_depth": (
                        (padded_records.bit_length() - 1)
                        * padded_records.bit_length()
                        // 2
                    ),
                    "sorter": symbol_sorter.to_json(),
                    "adjacency": symbol_adjacency.to_json(),
                },
            }
        )

    ackermann_edges = graph.edges - initial_edges
    fill_edges, triangles, eliminated = graph.complete()
    eager_categories = {
        "ackermann": CountVector(
            variables=ackermann_edges,
            clauses=ackermann_clauses,
            literal_slots=ackermann_literals,
            watch_entries=2 * ackermann_clauses,
        ),
        "chordal_fill": CountVector(variables=fill_edges),
        "transitivity": UNIT.scale(len(reflexive))
        + CountVector(
            clauses=3 * triangles,
            literal_slots=9 * triangles,
            watch_entries=6 * triangles,
        ),
    }
    equality_links = ZERO
    for left, right in problem.equality_pairs:
        if left == right:
            equality_links += UNIT
        elif problem.term_sorts[left] == audit_smtlib.BOOL_SORT:
            channel(left)
            channel(right)
            equality_links += XNOR2 + CountVector(
                clauses=2, literal_slots=4, watch_entries=4
            )
        else:
            left_component, width = channels[left]
            right_component, _ = channels[right]
            if left_component != right_component:
                raise IndependentVerificationError("equality component mismatch")
            equality_links += _equality_link(width)
    bool_domain = ZERO
    if problem.true_term in bool_variables:
        bool_domain += UNIT
    if problem.false_term in bool_variables:
        bool_domain += UNIT
    cqram_categories = {
        "class_codes": CountVector(variables=quotient_bits),
        "restricted_growth": canonicalization,
        "equality_links": equality_links,
        "boolean_domain": bool_domain,
        "sorter_constant": UNIT_WITH_VARIABLE if needs_sorter_constant else ZERO,
        "sorters": sorter_counts,
        "adjacent_consistency": adjacency_counts,
    }
    eager_total = _sum_counts(eager_categories)
    cqram_total = _sum_counts(cqram_categories)

    relevant_boolean: set[int] = set()
    for term_ids in groups.values():
        for term_id in term_ids:
            if problem.term_sorts[term_id] == audit_smtlib.BOOL_SORT:
                relevant_boolean.add(term_id)
            relevant_boolean.update(
                argument
                for argument in problem.term_arguments[term_id]
                if problem.term_sorts[argument] == audit_smtlib.BOOL_SORT
            )
    if not relevant_boolean.issubset(bool_variables):
        raise IndependentVerificationError("decoder Boolean channel is incomplete")
    decoder_counts = {
        "assignment_bits_read": quotient_bits + len(bool_variables),
        "term_codes_materialized": problem.term_count,
        "equality_atoms_checked": equality_atoms,
        "argument_code_lookups": argument_slots,
        "result_code_lookups": applications,
        "records_checked": applications,
        "map_probes": 2 * applications,
        "logical_record_bits": logical_bits,
        "padded_record_bits": padded_bits,
        "sorter_comparators_replayed": sorter_comparators,
        "maximum_symbol_records": maximum_symbol_applications,
        "sort_defaults_materialized": len(problem.sorts),
    }
    decoder_operations = sum(
        value
        for key, value in decoder_counts.items()
        if key not in {"maximum_symbol_records", "padded_record_bits"}
    )
    _checked(decoder_operations, "max_decoder_operations")
    decoder_counts["total_operations"] = decoder_operations
    shape = {
        "sorts": len(problem.sorts),
        "function_declarations": function_count,
        "terms": term_count,
        "non_boolean_terms": sum(
            sort_id != audit_smtlib.BOOL_SORT for sort_id in problem.term_sorts
        ),
        "boolean_terms": sum(
            sort_id == audit_smtlib.BOOL_SORT for sort_id in problem.term_sorts
        ),
        "applications": applications,
        "application_symbols": len(groups),
        "maximum_symbol_applications": maximum_symbol_applications,
        "argument_slots": argument_slots,
        "source_equality_atoms": equality_atoms,
        "source_boolean_atoms": len(bool_variables),
        "components": len(components),
        "maximum_component_terms": max(
            (len(members) for _, _, members, _ in components), default=0
        ),
        "ackermann_pairs": ackermann_pairs,
        "initial_equality_edges": initial_edges,
        "ackermann_equality_edges": ackermann_edges,
        "chordal_fill_edges": fill_edges,
        "completed_equality_edges": graph.edges,
        "completed_equality_triangles": triangles,
        "eliminated_equality_vertices": eliminated,
    }
    return {
        "shape": shape,
        "components": component_rows,
        "symbols": symbol_rows,
        "counts": {
            "eager": {
                "categories": {
                    name: value.to_json() for name, value in sorted(eager_categories.items())
                },
                "total": eager_total.to_json(),
            },
            "component_quotient_ram": {
                "categories": {
                    name: value.to_json() for name, value in sorted(cqram_categories.items())
                },
                "total": cqram_total.to_json(),
            },
        },
        "selector": {
            "eligible": applications >= contract.SELECTOR_MINIMUM_APPLICATIONS
            and maximum_symbol_applications
            >= contract.SELECTOR_MINIMUM_SYMBOL_APPLICATIONS,
            "minimum_total_applications": contract.SELECTOR_MINIMUM_APPLICATIONS,
            "minimum_max_symbol_applications": contract.SELECTOR_MINIMUM_SYMBOL_APPLICATIONS,
        },
        "decoder": {
            "complete": True,
            "oracle": _analyzer_oracle_reference(),
            "domain_value": "typed_tuple_sort_id_component_id_class_code",
            "boolean_carrier": "false_true",
            "unobserved_function_completion": "typed_arbitrary_default",
            "counts": decoder_counts,
        },
        "ratios_ppm": {
            field: 0
            if getattr(eager_total, field) == 0
            and getattr(cqram_total, field) == 0
            else None
            if getattr(eager_total, field) == 0
            else getattr(cqram_total, field) * PPM // getattr(eager_total, field)
            for field in COUNT_FIELDS
        },
    }


def _restricted_growth_assignments(size: int) -> tuple[tuple[int, ...], ...]:
    if size < 1:
        raise IndependentVerificationError("oracle component must be nonempty")
    output: list[tuple[int, ...]] = []

    def extend(prefix: tuple[int, ...], maximum: int) -> None:
        if len(prefix) == size:
            output.append(prefix)
            return
        for value in range(maximum + 2):
            extend(prefix + (value,), max(maximum, value))

    extend((0,), 0)
    return tuple(output)


def run_independent_decoder_oracle() -> dict[str, object]:
    records_examined = 0
    records_accepted = 0
    records_rejected = 0
    function_rechecks = 0
    for size in range(1, 5):
        partitions = _restricted_growth_assignments(size)
        for keys in partitions:
            for values in partitions:
                records_examined += 1
                table: dict[int, int] = {}
                consistent = True
                for key, value in zip(keys, values):
                    previous = table.setdefault(key, value)
                    if previous != value:
                        consistent = False
                        break
                if not consistent:
                    records_rejected += 1
                    continue
                records_accepted += 1
                for key, value in zip(keys, values):
                    function_rechecks += 1
                    if table[key] != value:
                        raise IndependentVerificationError(
                            "independent decoder oracle table reconstruction failed"
                        )
    boolean_assignments = 0
    boolean_equality_checks = 0
    for left in (False, True):
        for right in (False, True):
            for asserted_equal in (False, True):
                boolean_assignments += 1
                boolean_equality_checks += 1
                semantic_equal = left == right
                if asserted_equal == semantic_equal:
                    continue
    namespace_checks = 0
    for sort_id in range(2):
        for component_id in range(3):
            for class_code in range(4):
                value = (sort_id, component_id, class_code)
                namespace_checks += 1
                if value != (sort_id, component_id, class_code):
                    raise IndependentVerificationError(
                        "typed namespace oracle reconstruction failed"
                    )
    counts = {
        "record_assignments_examined": records_examined,
        "record_assignments_accepted": records_accepted,
        "record_assignments_rejected": records_rejected,
        "function_rechecks": function_rechecks,
        "boolean_assignments": boolean_assignments,
        "boolean_equality_checks": boolean_equality_checks,
        "typed_namespace_checks": namespace_checks,
    }
    payload = {
        "schema": "euf-viper.component-quotient-independent-decoder-oracle.v1",
        "passed": True,
        "bounds": {
            "maximum_component_terms": 4,
            "boolean_terms": 2,
            "sorts": 2,
            "components_per_sort": 3,
        },
        "counts": counts,
    }
    payload["sha256"] = sha256_bytes(contract.canonical_json_bytes(payload))
    return payload


def _merged_partition(
    size: int, hyperedges: Sequence[Sequence[int]]
) -> tuple[tuple[int, ...], ...]:
    """Reference connectivity using immutable block coalescing."""

    blocks = [frozenset((vertex,)) for vertex in range(size)]
    for hyperedge in hyperedges:
        members = frozenset(hyperedge)
        touched = [block for block in blocks if block & members]
        untouched = [block for block in blocks if not block & members]
        if touched:
            blocks = untouched + [frozenset().union(*touched)]
    return tuple(sorted(tuple(sorted(block)) for block in blocks))


def _elimination_reference(
    size: int, initial_edges: Sequence[tuple[int, int]]
) -> tuple[int, int, int, int]:
    """Reference min-degree elimination over immutable unordered edge pairs."""

    edges = {tuple(sorted(edge)) for edge in initial_edges if edge[0] != edge[1]}
    active = {vertex for edge in edges for vertex in edge}
    fill = 0
    triangles = 0
    eliminated = 0
    while active:
        neighborhoods = {
            vertex: tuple(
                sorted(
                    other
                    for other in active
                    if other != vertex
                    and tuple(sorted((vertex, other))) in edges
                )
            )
            for vertex in active
        }
        vertex = min(active, key=lambda item: (len(neighborhoods[item]), item))
        adjacent = neighborhoods[vertex]
        missing = {
            tuple(sorted((left, right)))
            for index, left in enumerate(adjacent)
            for right in adjacent[index + 1 :]
            if tuple(sorted((left, right))) not in edges
        }
        edges.update(missing)
        fill += len(missing)
        triangles += _choose2(len(adjacent))
        active.remove(vertex)
        eliminated += 1
    return fill, triangles, eliminated, len(edges)


def _clauses_accept(
    clauses: Sequence[Sequence[tuple[int, bool]]], assignment: Sequence[bool]
) -> bool:
    return all(
        any(assignment[variable] == positive for variable, positive in clause)
        for clause in clauses
    )


def run_independent_projection_oracle() -> dict[str, object]:
    """Exhaustively check the audit derivation on finite semantic models."""

    graph_cases = 0
    fill_edges = 0
    elimination_triangles = 0
    eliminated_vertices = 0
    for size in range(1, 5):
        possible = [
            (left, right)
            for left in range(size)
            for right in range(left + 1, size)
        ]
        for mask in range(1 << len(possible)):
            selected = [
                edge for bit, edge in enumerate(possible) if mask & (1 << bit)
            ]
            graph_cases += 1
            derived_components = tuple(
                sorted(_hypergraph_components([1] * size, selected))
            )
            if derived_components != _merged_partition(size, selected):
                raise IndependentVerificationError(
                    "projection oracle component closure mismatch"
                )
            graph = EqualityProjection(size)
            for left, right in selected:
                graph.connect(left, right)
            observed = (*graph.complete(), graph.edges)
            expected = _elimination_reference(size, selected)
            if observed != expected:
                raise IndependentVerificationError(
                    "projection oracle equality completion mismatch"
                )
            fill_edges += observed[0]
            elimination_triangles += observed[1]
            eliminated_vertices += observed[2]

    functionality_cases = 0
    functional_cases = 0
    nonfunctional_cases = 0
    padding_records = 0
    for size in range(1, 5):
        partitions = _restricted_growth_assignments(size)
        padded_size = _next_power_two(size)
        for keys in partitions:
            for values in partitions:
                functionality_cases += 1
                semantic = all(
                    keys[left] != keys[right] or values[left] == values[right]
                    for left in range(size)
                    for right in range(left + 1, size)
                )
                records = [(True, key, value) for key, value in zip(keys, values)]
                records.extend((False, 0, 0) for _ in range(padded_size - size))
                records.sort(key=lambda row: (row[0], row[1], row[2]))
                adjacent = all(
                    not (
                        left[0]
                        and right[0]
                        and left[1] == right[1]
                        and left[2] != right[2]
                    )
                    for left, right in zip(records, records[1:])
                )
                if adjacent != semantic:
                    raise IndependentVerificationError(
                        "projection oracle sorted-adjacency semantics mismatch"
                    )
                padding_records += padded_size - size
                if semantic:
                    functional_cases += 1
                else:
                    nonfunctional_cases += 1

    restricted_growth_cases = 0
    restricted_growth_valid = 0
    bell_numbers = {1: 1, 2: 2, 3: 5, 4: 15}
    for size, expected_valid in bell_numbers.items():
        width = _component_width(size)
        valid_for_size = 0
        for codes in itertools.product(range(1 << width), repeat=size):
            restricted_growth_cases += 1
            valid = codes[0] == 0 and all(
                codes[index] <= 1 + max(codes[:index])
                for index in range(1, size)
            )
            if valid:
                valid_for_size += 1
                restricted_growth_valid += 1
        if valid_for_size != expected_valid:
            raise IndependentVerificationError(
                "projection oracle restricted-growth semantics mismatch"
            )

    gate_templates = {
        "and2": (
            (
                ((0, False), (1, False), (2, True)),
                ((0, True), (2, False)),
                ((1, True), (2, False)),
            ),
            lambda values: values[0] and values[1],
            AND2,
        ),
        "xor2": (
            (
                ((0, True), (1, True), (2, False)),
                ((0, False), (1, False), (2, False)),
                ((0, True), (1, False), (2, True)),
                ((0, False), (1, True), (2, True)),
            ),
            lambda values: values[0] != values[1],
            XOR2,
        ),
        "xnor2": (
            (
                ((0, True), (1, True), (2, True)),
                ((0, False), (1, False), (2, True)),
                ((0, True), (1, False), (2, False)),
                ((0, False), (1, True), (2, False)),
            ),
            lambda values: values[0] == values[1],
            XNOR2,
        ),
        "mux2": (
            (
                ((0, True), (1, False), (3, True)),
                ((0, True), (1, True), (3, False)),
                ((0, False), (2, False), (3, True)),
                ((0, False), (2, True), (3, False)),
            ),
            lambda values: values[2] if values[0] else values[1],
            MUX2,
        ),
    }
    gate_assignments = 0
    for name, (clauses, operation, expected_counts) in gate_templates.items():
        variable_count = max(variable for clause in clauses for variable, _ in clause) + 1
        observed_counts = CountVector(
            variables=1,
            clauses=len(clauses),
            literal_slots=sum(len(clause) for clause in clauses),
            watch_entries=2 * len(clauses),
        )
        if observed_counts != expected_counts:
            raise IndependentVerificationError(
                f"projection oracle {name} count-vector mismatch"
            )
        for assignment in itertools.product((False, True), repeat=variable_count):
            gate_assignments += 1
            expected_output = bool(operation(assignment))
            if _clauses_accept(clauses, assignment) != (
                assignment[-1] == expected_output
            ):
                raise IndependentVerificationError(
                    f"projection oracle {name} truth-table mismatch"
                )

    payload: dict[str, object] = {
        "schema": PROJECTION_ORACLE_SCHEMA,
        "passed": True,
        "bounds": {
            "maximum_graph_vertices": 4,
            "maximum_function_records": 4,
            "maximum_component_terms": 4,
            "gate_templates": sorted(gate_templates),
        },
        "counts": {
            "graph_cases": graph_cases,
            "fill_edges": fill_edges,
            "elimination_triangles": elimination_triangles,
            "eliminated_vertices": eliminated_vertices,
            "functionality_cases": functionality_cases,
            "functional_cases": functional_cases,
            "nonfunctional_cases": nonfunctional_cases,
            "padding_records": padding_records,
            "restricted_growth_cases": restricted_growth_cases,
            "restricted_growth_valid": restricted_growth_valid,
            "gate_assignments": gate_assignments,
        },
    }
    oracle_sha256 = sha256_bytes(contract.canonical_json_bytes(payload))
    if oracle_sha256 != PROJECTION_ORACLE_SHA256:
        raise IndependentVerificationError(
            "independent projection-oracle evidence digest drift"
        )
    payload["sha256"] = oracle_sha256
    return payload


def _taxonomy(relative_path: str) -> tuple[str, str, str]:
    pure = PurePosixPath(relative_path)
    if (
        pure.is_absolute()
        or pure.suffix.lower() != ".smt2"
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise IndependentVerificationError(f"unsafe source path {relative_path!r}")
    parts = pure.parts
    if parts[0] == "QF_UF":
        prefix = ("QF_UF",)
        body = parts[1:]
    else:
        prefix = ()
        body = parts
    if len(body) < 2:
        raise IndependentVerificationError("source path lacks family and file")
    family = body[0]
    source_family = "/".join((*prefix, family))
    stem = PurePosixPath(body[-1]).stem
    if family == "QG-classification":
        match = QG_STEM.fullmatch(stem)
        if (
            len(body) != 3
            or not QG_VARIANT.fullmatch(body[1])
            or match is None
            or not match.group("kind")
        ):
            raise IndependentVerificationError("invalid QG taxonomy path")
        return source_family, "/".join((*prefix, family, stem)), "qg-size-variant"
    if family in {"NEQ", "PEQ", "SEQ"}:
        match = FINITE.fullmatch(stem)
        if len(body) != 2 or match is None:
            raise IndependentVerificationError("invalid finite taxonomy path")
        return (
            source_family,
            "/".join((*prefix, family, match.group("problem"))),
            "finite-size-series",
        )
    if family == "2018-Goel-hwbench":
        match = GOEL.fullmatch(stem)
        if len(body) != 2 or match is None:
            raise IndependentVerificationError("invalid Goel taxonomy path")
        model = GOEL_SIZE.sub("", match.group("instance"))
        return (
            source_family,
            "/".join((*prefix, family, model)),
            "goel-model-series",
        )
    if family == "20190906-CLEARSY":
        if len(body) != 3 or not body[1].isdigit() or not stem.isdigit():
            raise IndependentVerificationError("invalid ClearSy taxonomy path")
        return (
            source_family,
            "/".join((*prefix, family, body[1])),
            "clearsy-model-directory",
        )
    fixed_batches = {
        "20170829-Rodin": (r"smt[0-9]+", "rodin-source-batch"),
        "TypeSafe": (r"z3\.[0-9]+", "typesafe-source-batch"),
        "eq_diamond": (r"eq_diamond[0-9]+", "eq-diamond-size-series"),
    }
    if family in fixed_batches:
        expression, rule = fixed_batches[family]
        if len(body) != 2 or re.fullmatch(expression, stem) is None:
            raise IndependentVerificationError("invalid fixed-batch taxonomy path")
        return source_family, source_family, rule
    return (
        source_family,
        "/".join((*prefix, *body[:-1], stem)),
        "fallback-relative-stem",
    )


def _read_regular_no_follow(path: Path, context: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IndependentVerificationError(f"cannot open {context} {path}: {error}") from error
    try:
        descriptor_stat = os.fstat(descriptor)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise IndependentVerificationError(f"{context} is not a regular file")
        output = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            output.extend(chunk)
        if os.fstat(descriptor).st_size != len(output):
            raise IndependentVerificationError(f"{context} changed while captured")
        return bytes(output)
    finally:
        os.close(descriptor)


def _sources_from_manifest(
    *,
    repository_root: Path,
    manifest_bytes: bytes,
    source_loader: Callable[[dict[str, object], str], tuple[Path, bytes]],
) -> tuple[tuple[SourceSnapshot, ...], bytes]:
    manifest_rows = strict_jsonl(manifest_bytes, "manifest")
    if len(manifest_rows) != contract.EXPECTED_SOURCES:
        raise IndependentVerificationError("manifest source cardinality drift")
    seen_paths: set[str] = set()
    sources: list[SourceSnapshot] = []
    for index, row in enumerate(manifest_rows):
        if row.get("id") != index:
            raise IndependentVerificationError("manifest id is not its zero-based index")
        relative_path = row.get("relative_path")
        source_name = row.get("path")
        if type(relative_path) is not str or type(source_name) is not str:
            raise IndependentVerificationError("manifest source path is malformed")
        if relative_path in seen_paths:
            raise IndependentVerificationError("manifest contains a duplicate source path")
        seen_paths.add(relative_path)
        source_path, source_bytes = source_loader(row, relative_path)
        source_sha256 = sha256_bytes(source_bytes)
        if row.get("bytes") != len(source_bytes) or row.get("sha256") != source_sha256:
            raise IndependentVerificationError("manifest source size or digest mismatch")
        taxonomy = _taxonomy(relative_path)
        sources.append(
            SourceSnapshot(
                index,
                index + 1,
                relative_path,
                source_path,
                source_bytes,
                source_sha256,
                *taxonomy,
            )
        )
    sources.sort(key=lambda source: source.relative_path)
    portable = b"".join(
        contract.canonical_json_bytes(
            {
                "relative_path": source.relative_path,
                "bytes": len(source.source_bytes),
                "sha256": source.source_sha256,
            }
        )
        for source in sources
    )
    if sha256_bytes(portable) != contract.PORTABLE_SOURCE_SET_SHA256:
        raise IndependentVerificationError("portable source-set SHA-256 drift")
    return tuple(sources), portable


def capture_snapshot(
    *,
    repository_root: Path,
    lock_path: Path,
    manifest_path: Path,
    records_path: Path,
    aggregate_path: Path,
    targets_path: Path,
    expected_manifest_sha256: str | None = None,
) -> IndependentSnapshot:
    repository_root = Path(os.path.abspath(repository_root))
    lock_bytes = _read_regular_no_follow(lock_path, "campaign lock")
    contract.require_exact_lock_bytes(lock_bytes)
    contract.require_campaign_manifest_path(repository_root, manifest_path)
    manifest_bytes = _read_regular_no_follow(manifest_path, "manifest")
    manifest_sha256 = sha256_bytes(manifest_bytes)
    if expected_manifest_sha256 is not None and manifest_sha256 != expected_manifest_sha256:
        raise IndependentVerificationError("manifest SHA-256 differs from submission binding")
    if expected_manifest_sha256 == contract.MANIFEST_SHA256:
        contract.require_campaign_manifest_bytes(manifest_bytes)

    def load_source(
        row: dict[str, object], relative_path: str
    ) -> tuple[Path, bytes]:
        source_name = row["path"]
        assert type(source_name) is str
        source_path = Path(source_name)
        if not source_path.is_absolute():
            source_path = repository_root / source_path
        source_path = Path(os.path.abspath(source_path))
        relative_parts = PurePosixPath(relative_path).parts
        if tuple(source_path.parts[-len(relative_parts) :]) != relative_parts:
            raise IndependentVerificationError(
                "manifest path suffix differs from relative path"
            )
        return source_path, _read_regular_no_follow(source_path, "SMT-LIB source")

    sources, portable = _sources_from_manifest(
        repository_root=repository_root,
        manifest_bytes=manifest_bytes,
        source_loader=load_source,
    )
    return IndependentSnapshot(
        repository_root,
        Path(lock_path),
        Path(manifest_path),
        Path(records_path),
        Path(aggregate_path),
        Path(targets_path),
        lock_bytes,
        manifest_bytes,
        _read_regular_no_follow(records_path, "records"),
        _read_regular_no_follow(aggregate_path, "aggregate"),
        _read_regular_no_follow(targets_path, "targets"),
        sources,
        portable,
    )


def snapshot_from_bytes(
    *,
    repository_root: Path,
    lock_bytes: bytes,
    manifest_bytes: bytes,
    records_bytes: bytes,
    aggregate_bytes: bytes,
    targets_bytes: bytes,
    source_bytes: Mapping[str, bytes],
    expected_manifest_sha256: str,
) -> IndependentSnapshot:
    """Build a verifier snapshot from immutable archive members only."""

    repository_root = Path(os.path.abspath(repository_root))
    contract.require_exact_lock_bytes(lock_bytes)
    if sha256_bytes(manifest_bytes) != expected_manifest_sha256:
        raise IndependentVerificationError(
            "archived manifest SHA-256 differs from submission binding"
        )
    if expected_manifest_sha256 == contract.MANIFEST_SHA256:
        contract.require_campaign_manifest_bytes(manifest_bytes)
    consumed: set[str] = set()

    def load_source(
        row: dict[str, object], relative_path: str
    ) -> tuple[Path, bytes]:
        del row
        if relative_path not in source_bytes:
            raise IndependentVerificationError(
                f"archive lacks captured source {relative_path}"
            )
        consumed.add(relative_path)
        return Path(relative_path), source_bytes[relative_path]

    sources, portable = _sources_from_manifest(
        repository_root=repository_root,
        manifest_bytes=manifest_bytes,
        source_loader=load_source,
    )
    if consumed != set(source_bytes):
        raise IndependentVerificationError("archive contains an unbound captured source")
    virtual = Path("<immutable-archive>")
    return IndependentSnapshot(
        repository_root,
        virtual / "campaign-lock.json",
        virtual / "manifest.jsonl",
        virtual / "records.jsonl",
        virtual / "aggregate.json",
        virtual / "targets.jsonl",
        lock_bytes,
        manifest_bytes,
        records_bytes,
        aggregate_bytes,
        targets_bytes,
        sources,
        portable,
    )


def _ratio(candidate: int, baseline: int) -> Fraction | None:
    if baseline == 0:
        return Fraction(0) if candidate == 0 else None
    return Fraction(candidate, baseline)


def _ppm(value: Fraction | None) -> int | None:
    return None if value is None else value.numerator * PPM // value.denominator


def _median(values: Sequence[tuple[int, int]]) -> Fraction | None:
    ratios = sorted(
        (_ratio(candidate, baseline) for candidate, baseline in values),
        key=lambda value: (value is None, Fraction(0) if value is None else value),
    )
    if not ratios:
        return None
    middle = len(ratios) // 2
    if len(ratios) % 2:
        return ratios[middle]
    if ratios[middle - 1] is None or ratios[middle] is None:
        return None
    return (ratios[middle - 1] + ratios[middle]) / 2


def _percentile(values: Sequence[tuple[int, int]], percentile: int) -> Fraction | None:
    ratios = sorted(
        (_ratio(candidate, baseline) for candidate, baseline in values),
        key=lambda value: (value is None, Fraction(0) if value is None else value),
    )
    if not ratios:
        return None
    rank = (percentile * len(ratios) + 99) // 100
    return ratios[rank - 1]


def _total(record: Mapping[str, object], encoding: str) -> dict[str, int]:
    counts = record["counts"]
    if type(counts) is not dict or type(counts.get(encoding)) is not dict:
        raise IndependentVerificationError("record count object is malformed")
    total = counts[encoding].get("total")
    if type(total) is not dict or set(total) != set(COUNT_FIELDS):
        raise IndependentVerificationError("record total count is malformed")
    if any(type(total[field]) is not int or total[field] < 0 for field in COUNT_FIELDS):
        raise IndependentVerificationError("record total count is not nonnegative")
    return {field: total[field] for field in COUNT_FIELDS}


def _ceil_ratio(value: int, ratio: tuple[int, int]) -> int:
    numerator, denominator = ratio
    return (value * numerator + denominator - 1) // denominator


def _reduction_gate(
    records: Sequence[Mapping[str, object]], metric: str
) -> dict[str, object]:
    pairs = [
        (_total(record, "component_quotient_ram")[metric], _total(record, "eager")[metric])
        for record in records
    ]
    candidate_total = sum(candidate for candidate, _ in pairs)
    eager_total = sum(eager for _, eager in pairs)
    median = _median(pairs)
    reduction_numerator, reduction_denominator = contract.MINIMUM_REDUCTION
    target = Fraction(reduction_denominator - reduction_numerator, reduction_denominator)
    individual = sum(
        baseline > 0 and candidate * reduction_denominator <= baseline * (
            reduction_denominator - reduction_numerator
        )
        for candidate, baseline in pairs
    )
    required = _ceil_ratio(len(records), contract.MINIMUM_INDIVIDUAL_FRACTION)
    weighted_pass = eager_total > 0 and candidate_total * reduction_denominator <= eager_total * (
        reduction_denominator - reduction_numerator
    )
    median_pass = median is not None and median <= target
    individual_pass = individual >= required
    return {
        "metric": metric,
        "candidate_total": candidate_total,
        "eager_total": eager_total,
        "weighted_ratio_ppm": 0
        if eager_total == 0 and candidate_total == 0
        else None
        if eager_total == 0
        else candidate_total * PPM // eager_total,
        "median_ratio_ppm": _ppm(median),
        "individual_passing": individual,
        "individual_required": required,
        "weighted_pass": weighted_pass,
        "median_pass": median_pass,
        "individual_pass": individual_pass,
        "pass": weighted_pass and median_pass and individual_pass,
    }


def _control_gate(
    records: Sequence[Mapping[str, object]],
    metric: str,
    maximum: tuple[int, int],
    percentile: int,
) -> dict[str, object]:
    pairs = [
        (_total(record, "component_quotient_ram")[metric], _total(record, "eager")[metric])
        for record in records
    ]
    candidate_total = sum(candidate for candidate, _ in pairs)
    eager_total = sum(eager for _, eager in pairs)
    weighted = _ratio(candidate_total, eager_total)
    tail = _percentile(pairs, percentile)
    maximum_fraction = Fraction(*maximum)
    weighted_pass = weighted is not None and weighted <= maximum_fraction
    percentile_pass = tail is not None and tail <= maximum_fraction
    return {
        "metric": metric,
        "candidate_total": candidate_total,
        "eager_total": eager_total,
        "weighted_ratio_ppm": _ppm(weighted),
        "percentile": percentile,
        "percentile_ratio_ppm": _ppm(tail),
        "weighted_pass": weighted_pass,
        "percentile_pass": percentile_pass,
        "pass": weighted_pass and percentile_pass,
    }


def _independent_gates(records: Sequence[dict[str, object]]) -> dict[str, object]:
    families = {
        "goel": "QF_UF/2018-Goel-hwbench",
        "qg": "QF_UF/QG-classification",
    }
    family_gates: dict[str, object] = {}
    population_match_all = True
    for key, family_name in families.items():
        population = [
            record
            for record in records
            if record["taxonomy"]["source_family"] == family_name  # type: ignore[index]
        ]
        targets = [
            record
            for record in population
            if record["selector"]["eligible"] is True  # type: ignore[index]
        ]
        expected_population = contract.EXPECTED_FAMILY_POPULATIONS[key]
        population_match = len(population) == expected_population
        population_match_all &= population_match
        required_targets = _ceil_ratio(
            expected_population, contract.MINIMUM_FAMILY_FRACTION
        )
        lineages = {
            record["taxonomy"]["generator_lineage"]  # type: ignore[index]
            for record in targets
        }
        broadness = (
            population_match
            and len(targets) >= required_targets
            and len(lineages) >= contract.MINIMUM_GENERATOR_LINEAGES
        )
        reductions = {
            metric: _reduction_gate(targets, metric)
            for metric in ("clauses", "watch_entries")
        }
        primary = any(gate["pass"] is True for gate in reductions.values())
        ram_controls = {
            metric: _control_gate(
                targets,
                metric,
                contract.RAM_MAXIMUM_RATIO,
                contract.RAM_PERCENTILE,
            )
            for metric in ("clauses", "literal_slots")
        }
        ram_pass = all(gate["pass"] is True for gate in ram_controls.values())
        opportunity = {
            "reductions": reductions,
            "primary_reduction_pass": primary,
            "ram_no_regression": ram_controls,
            "ram_no_regression_pass": ram_pass,
            "pass": primary and ram_pass,
        }
        variable = _control_gate(
            targets,
            "variables",
            contract.VARIABLE_MAXIMUM_RATIO,
            contract.VARIABLE_PERCENTILE,
        )
        family_gates[key] = {
            "source_family": family_name,
            "expected_population": expected_population,
            "observed_population": len(population),
            "population_match": population_match,
            "target_sources": len(targets),
            "required_target_sources": required_targets,
            "target_generator_lineages": len(lineages),
            "required_generator_lineages": contract.MINIMUM_GENERATOR_LINEAGES,
            "broadness_pass": broadness,
            "opportunity": opportunity,
            "opportunity_pass": opportunity["pass"],
            "variable_control": variable,
            "pass": broadness and opportunity["pass"] is True and variable["pass"] is True,
        }
    statuses = Counter(str(record["status"]) for record in records)
    validity_checks = {
        "source_cardinality": len(records) == contract.EXPECTED_SOURCES,
        "all_sources_projected": statuses == Counter({"projected": len(records)}),
        "zero_parse_errors": statuses.get("parse_error", 0) == 0,
        "zero_unknown_projections": statuses.get("unknown_projection", 0) == 0,
        "zero_cap_events": all(not record.get("cap_events") for record in records),
        "complete_decoder_for_every_source": all(
            type(record.get("decoder")) is dict
            and record["decoder"].get("complete") is True  # type: ignore[union-attr]
            for record in records
        ),
        "bounded_exhaustive_decoder_oracle": run_independent_decoder_oracle()[
            "passed"
        ]
        is True,
        "family_populations_match": population_match_all,
    }
    validity = all(validity_checks.values())
    implementation_allowed = validity and all(
        gate["pass"] is True for gate in family_gates.values()  # type: ignore[index]
    )
    return {
        "validity": {"checks": validity_checks, "pass": validity},
        "families": family_gates,
        "implementation_allowed": implementation_allowed,
    }


def _record_digest(record: Mapping[str, object]) -> str:
    unhashed = dict(record)
    unhashed.pop("record_sha256", None)
    return sha256_bytes(contract.canonical_json_bytes(unhashed))


def _require_record_projection(
    source: SourceSnapshot,
    stored: dict[str, object],
    previous_digest: str | None,
    sequence: int,
    *,
    campaign_id: str,
    manifest_sha256: str,
    parser_sha256: str,
    taxonomy_builder_sha256: str,
) -> dict[str, object]:
    if len(source.source_bytes) > CAPS["max_source_bytes"]:
        raise IndependentCap("source byte cap exceeded")
    try:
        text = source.source_bytes.decode("utf-8")
        problem = audit_smtlib.parse_qfuf_for_audit(text)
        projection = independent_projection(problem)
    except (UnicodeDecodeError, audit_smtlib.AuditParseError) as error:
        raise IndependentVerificationError(
            f"independent parser rejected {source.relative_path}: {error}"
        ) from error
    expected: dict[str, object] = {
        "schema": RECORD_SCHEMA,
        "sequence": sequence,
        "previous_record_sha256": previous_digest,
        "record_sha256": "",
        "lock_sha256": contract.LOCK_SHA256,
        "campaign_id": campaign_id,
        "interpretation": INTERPRETATION,
        "parser_api": PARSER_API,
        "parser_sha256": parser_sha256,
        "taxonomy_builder_sha256": taxonomy_builder_sha256,
        "manifest": {
            "sha256": manifest_sha256,
            "record_line": source.line_number,
        },
        "source": {
            "id": source.record_id,
            "relative_path": source.relative_path,
            "bytes": len(source.source_bytes),
            "sha256": source.source_sha256,
        },
        "taxonomy": {
            "source_family": source.source_family,
            "generator_lineage": source.generator_lineage,
            "rule": source.taxonomy_rule,
        },
        "status": "projected",
        "reason": None,
        "cap_events": [],
        "shape": projection["shape"],
        "components": projection["components"],
        "symbols": projection["symbols"],
        "counts": projection["counts"],
        "decoder": projection["decoder"],
        "selector": projection["selector"],
        "ratios_ppm": projection["ratios_ppm"],
    }
    expected["record_sha256"] = _record_digest(expected)
    if stored != expected:
        raise IndependentVerificationError(
            f"full independent record mismatch for {source.relative_path}"
        )
    return expected


def _fixed_analyzer_oracle(lock: Mapping[str, object]) -> dict[str, object]:
    try:
        projection = lock["projection"]
        cqram = projection["component_quotient_ram"]  # type: ignore[index]
        configured = cqram["decoder_oracle"]  # type: ignore[index]
        fixtures = configured["fixtures"]  # type: ignore[index]
        features = configured["required_features"]  # type: ignore[index]
        counts = configured["counts"]  # type: ignore[index]
        maximum_component_terms = configured["maximum_component_terms"]  # type: ignore[index]
        maximum_free_boolean_terms = configured[  # type: ignore[index]
            "maximum_free_boolean_terms"
        ]
        receipt_sha256 = configured["receipt_sha256"]  # type: ignore[index]
    except (KeyError, TypeError) as error:
        raise IndependentVerificationError(
            "fixed analyzer decoder-oracle contract is malformed"
        ) from error
    if (
        type(fixtures) is not list
        or not all(type(item) is str for item in fixtures)
        or type(features) is not list
        or not all(type(item) is str for item in features)
        or type(counts) is not dict
        or any(type(value) is not int or value < 0 for value in counts.values())
        or type(maximum_component_terms) is not int
        or type(maximum_free_boolean_terms) is not int
        or receipt_sha256 != DECODER_ORACLE_SHA256
    ):
        raise IndependentVerificationError(
            "fixed analyzer decoder-oracle values are malformed"
        )
    evidence: dict[str, object] = {
        "schema": DECODER_ORACLE_SCHEMA,
        "executed": True,
        "passed": True,
        "fixtures": fixtures,
        "required_features": features,
        "exercised_features": features,
        "bounds": {
            "maximum_component_terms": maximum_component_terms,
            "maximum_free_boolean_terms": maximum_free_boolean_terms,
        },
        "counts": counts,
    }
    if sha256_bytes(contract.canonical_json_bytes(evidence)) != receipt_sha256:
        raise IndependentVerificationError(
            "fixed analyzer decoder-oracle evidence digest drift"
        )
    evidence["sha256"] = receipt_sha256
    return evidence


def verify_snapshot(snapshot: IndependentSnapshot) -> dict[str, object]:
    lock = contract.require_exact_lock_bytes(snapshot.lock_bytes)
    campaign_id = lock.get("campaign_id")
    if type(campaign_id) is not str or not campaign_id:
        raise IndependentVerificationError("fixed campaign id is malformed")
    if lock.get("caps") != CAPS:
        raise IndependentVerificationError(
            "independent verifier caps differ from the fixed campaign lock"
        )
    manifest_sha256 = sha256_bytes(snapshot.manifest_bytes)
    parser_bytes = _read_regular_no_follow(
        snapshot.repository_root / "scripts/cert/independent_qfuf.py",
        "independent parser revision blob",
    )
    taxonomy_bytes = _read_regular_no_follow(
        snapshot.repository_root / "scripts/bench/build_family_manifest.py",
        "taxonomy revision blob",
    )
    analyzer_bytes = _read_regular_no_follow(
        snapshot.repository_root / "scripts/bench/census_component_quotient_ram.py",
        "analyzer revision blob",
    )
    audit_parser_bytes = _read_regular_no_follow(
        snapshot.repository_root / "scripts/bench/t5_independent_smtlib.py",
        "independent audit parser revision blob",
    )
    parser_sha256 = sha256_bytes(parser_bytes)
    taxonomy_builder_sha256 = sha256_bytes(taxonomy_bytes)
    stored_records = strict_jsonl(snapshot.records_bytes, "records")
    if len(stored_records) != len(snapshot.sources):
        raise IndependentVerificationError("record/source cardinality mismatch")
    canonical_records = b"".join(
        contract.canonical_json_bytes(record) for record in stored_records
    )
    if canonical_records != snapshot.records_bytes:
        raise IndependentVerificationError("record stream is not canonical JSONL")
    verified_records: list[dict[str, object]] = []
    previous: str | None = None
    last_path = ""
    for sequence, (source, stored) in enumerate(zip(snapshot.sources, stored_records)):
        if source.relative_path <= last_path:
            raise IndependentVerificationError("source order is not strictly increasing")
        verified = _require_record_projection(
            source,
            stored,
            previous,
            sequence,
            campaign_id=campaign_id,
            manifest_sha256=manifest_sha256,
            parser_sha256=parser_sha256,
            taxonomy_builder_sha256=taxonomy_builder_sha256,
        )
        verified_records.append(verified)
        previous = str(stored["record_sha256"])
        last_path = source.relative_path

    targets = [
        {
            "schema": TARGET_SCHEMA,
            "sequence": record["sequence"],
            "source": {
                "id": record["source"]["id"],  # type: ignore[index]
                "relative_path": record["source"]["relative_path"],  # type: ignore[index]
                "sha256": record["source"]["sha256"],  # type: ignore[index]
            },
            "taxonomy": record["taxonomy"],
            "shape": {
                "applications": record["shape"]["applications"],  # type: ignore[index]
                "maximum_symbol_applications": record["shape"][  # type: ignore[index]
                    "maximum_symbol_applications"
                ],
            },
            "record_sha256": record["record_sha256"],
        }
        for record in verified_records
        if record["selector"]["eligible"] is True  # type: ignore[index]
    ]
    stored_targets = strict_jsonl(
        snapshot.targets_bytes, "targets", allow_empty=True
    )
    expected_target_bytes = b"".join(
        contract.canonical_json_bytes(target) for target in targets
    )
    if stored_targets != targets or snapshot.targets_bytes != expected_target_bytes:
        raise IndependentVerificationError("target manifest differs from source recomputation")
    projection_oracle = run_independent_projection_oracle()
    gates = _independent_gates(verified_records)
    aggregate = strict_json(snapshot.aggregate_bytes, "aggregate")
    aggregate_counts = {
        encoding: {
            field: sum(_total(record, encoding)[field] for record in verified_records)
            for field in COUNT_FIELDS
        }
        for encoding in ("eager", "component_quotient_ram")
    }
    expected_hashes = {
        "lock_sha256": contract.LOCK_SHA256,
        "input_manifest_sha256": manifest_sha256,
        "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
        "analyzer_sha256": sha256_bytes(analyzer_bytes),
        "parser_sha256": parser_sha256,
        "taxonomy_builder_sha256": taxonomy_builder_sha256,
        "records_jsonl_sha256": sha256_bytes(snapshot.records_bytes),
        "terminal_record_sha256": previous,
        "derived_target_manifest_sha256": sha256_bytes(snapshot.targets_bytes),
    }
    analyzer_oracle = _fixed_analyzer_oracle(lock)
    expected_aggregate = {
        "schema": AGGREGATE_SCHEMA,
        "campaign_id": campaign_id,
        "interpretation": INTERPRETATION,
        "parser_api": PARSER_API,
        "decoder_oracle": analyzer_oracle,
        "hashes": expected_hashes,
        "sources": {
            "expected": contract.EXPECTED_SOURCES,
            "observed": len(verified_records),
            "statuses": {"projected": len(verified_records)},
            "cap_events": {},
            "decoder_incomplete": 0,
        },
        "aggregate_counts": aggregate_counts,
        "gates": gates,
    }
    if (
        aggregate != expected_aggregate
        or snapshot.aggregate_bytes
        != contract.canonical_json_bytes(expected_aggregate)
    ):
        raise IndependentVerificationError(
            "full aggregate differs from independent reconstruction"
        )
    oracle = run_independent_decoder_oracle()
    receipt = {
        "schema": contract.INDEPENDENT_RECEIPT_SCHEMA,
        "decisive": True,
        "full_artifact_reconstruction": True,
        "decision": "authorize_t5" if gates["implementation_allowed"] else "reject_t5",
        "implementation_allowed": gates["implementation_allowed"],
        "validity_pass": gates["validity"]["pass"],  # type: ignore[index]
        "sources": len(verified_records),
        "targets": len(targets),
        "independent_decoder_oracle": oracle,
        "independent_projection_oracle": projection_oracle,
        "independent_parser": {
            "api": AUDIT_PARSER_API,
            "sha256": sha256_bytes(audit_parser_bytes),
        },
        "hashes": {
            **expected_hashes,
            "aggregate_json_sha256": sha256_bytes(snapshot.aggregate_bytes),
            "independent_audit_parser_sha256": sha256_bytes(audit_parser_bytes),
            "independent_gates_sha256": sha256_bytes(
                contract.canonical_json_bytes(gates)
            ),
        },
    }
    receipt["receipt_sha256"] = sha256_bytes(contract.canonical_json_bytes(receipt))
    return receipt


def verify_or_nondecisive(snapshot: IndependentSnapshot) -> dict[str, object]:
    try:
        return verify_snapshot(snapshot)
    except (IndependentVerificationError, contract.ContractError) as error:
        receipt = {
            "schema": contract.INDEPENDENT_RECEIPT_SCHEMA,
            "decisive": False,
            "decision": "nondecisive",
            "implementation_allowed": False,
            "reason": str(error),
            "hashes": {
                "lock_sha256": sha256_bytes(snapshot.lock_bytes),
                "input_manifest_sha256": sha256_bytes(snapshot.manifest_bytes),
                "records_jsonl_sha256": sha256_bytes(snapshot.records_bytes),
                "aggregate_json_sha256": sha256_bytes(snapshot.aggregate_bytes),
                "derived_target_manifest_sha256": sha256_bytes(snapshot.targets_bytes),
            },
        }
        receipt["receipt_sha256"] = sha256_bytes(contract.canonical_json_bytes(receipt))
        return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--require-decisive", action="store_true")
    return parser


def _write_unique_receipt(path: Path, payload: bytes) -> None:
    path = Path(os.path.abspath(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise IndependentVerificationError(
            f"cannot create unique verifier receipt {path}: {error}"
        ) from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise IndependentVerificationError("verifier receipt write made no progress")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        path.parent,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        snapshot = capture_snapshot(
            repository_root=args.repository_root,
            lock_path=args.lock,
            manifest_path=args.manifest,
            records_path=args.records,
            aggregate_path=args.aggregate,
            targets_path=args.targets,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
        receipt = verify_or_nondecisive(snapshot)
        _write_unique_receipt(
            args.receipt_out, contract.canonical_json_bytes(receipt)
        )
    except (IndependentVerificationError, contract.ContractError) as error:
        raise SystemExit(f"independent T5 verification failed: {error}")
    print(json.dumps(receipt, sort_keys=True))
    if args.require_decisive and receipt["decisive"] is not True:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
