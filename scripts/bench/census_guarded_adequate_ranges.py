#!/usr/bin/env python3
"""Census source-certified guarded adequate ranges and conditional Hall pressure.

This is a source-only opportunity analyzer.  It uses the independent QF_UF
certificate parser, never invokes a solver, and never reports SAT or UNSAT.
Only explicit non-Boolean equality disjunctions and explicit disequalities are
used.  Facts are combined under an identical structured guard, with
unconditional facts also available in every guarded context.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import build_family_manifest as family_manifest  # noqa: E402
from scripts.cert import independent_qfuf as qfuf  # noqa: E402


RECORD_SCHEMA = "euf-viper.guard-range-hall-source-census.v1"
AGGREGATE_SCHEMA = "euf-viper.guard-range-hall-source-census-summary.v1"
PARSER_API = "scripts.cert.independent_qfuf.parse_and_encode"
INTERPRETATION = "conditional_source_opportunity_only_no_satisfiability_result"
TRUE_GUARD: tuple[object, ...] = ("const", True)
FALSE_GUARD: tuple[object, ...] = ("const", False)


class CensusError(ValueError):
    """Raised when census inputs or outputs fail closed."""


class FactCapExceeded(CensusError):
    def __init__(self, observed: int) -> None:
        super().__init__("source exceeds the proved-fact cap")
        self.observed = observed


@dataclass(frozen=True)
class Caps:
    max_source_bytes: int = 32 * 1024 * 1024
    max_terms: int = 250_000
    max_proved_facts: int = 250_000
    max_candidate_terms_per_domain: int = 32
    max_hall_subset_size: int = 8
    max_hall_subset_enumerations: int = 100_000
    max_hall_witnesses: int = 1_000

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise CensusError(f"{name} must be a positive integer")
        if self.max_hall_subset_size < 2:
            raise CensusError("max_hall_subset_size must be at least two")


@dataclass(frozen=True)
class ManifestSource:
    record_id: int | str
    line_number: int
    relative_path: str
    source_path: Path
    source_bytes: bytes
    source_sha256: str


@dataclass(frozen=True, order=True)
class RangeFact:
    guard: tuple[object, ...]
    target: int
    values: tuple[int, ...]


@dataclass(frozen=True, order=True)
class DisequalityFact:
    guard: tuple[object, ...]
    left: int
    right: int


@dataclass(frozen=True)
class EffectiveRange:
    guard: tuple[object, ...]
    target: int
    sort: int
    values: tuple[int, ...]
    contributing_facts: int


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def load_manifest(
    manifest_path: Path, repository_root: Path
) -> tuple[list[ManifestSource], bytes]:
    """Load provenance without attempting semantic SMT-LIB normalization."""

    try:
        manifest_bytes = Path(manifest_path).read_bytes()
    except OSError as error:
        raise CensusError(f"cannot read manifest {manifest_path}: {error}") from error
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CensusError(f"manifest is not UTF-8: {error}") from error
    lines = text.splitlines()
    if not lines:
        raise CensusError("manifest has no records")

    sources: list[ManifestSource] = []
    seen_ids: set[int | str] = set()
    seen_relative_paths: set[str] = set()
    seen_paths: set[Path] = set()
    root = Path(repository_root).resolve()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise CensusError(f"line {line_number}: blank JSONL record")
        try:
            row = family_manifest.strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as error:
            raise CensusError(f"line {line_number}: malformed JSON: {error}") from error
        if not isinstance(row, dict):
            raise CensusError(f"line {line_number}: record must be a JSON object")
        for field in ("id", "path", "relative_path"):
            if field not in row:
                raise CensusError(f"line {line_number}: missing field {field!r}")

        record_id = row["id"]
        if isinstance(record_id, bool) or not isinstance(record_id, (int, str)):
            raise CensusError(f"line {line_number}: id must be an integer or string")
        if record_id in seen_ids:
            raise CensusError(f"line {line_number}: duplicate id {record_id!r}")
        seen_ids.add(record_id)

        try:
            relative_path = family_manifest._validated_relative_path(
                row["relative_path"], line_number=line_number
            )
            source_path = family_manifest._resolve_source_path(
                row["path"], root, line_number=line_number
            )
        except family_manifest.ManifestError as error:
            raise CensusError(str(error)) from error
        if relative_path in seen_relative_paths:
            raise CensusError(
                f"line {line_number}: duplicate relative_path {relative_path!r}"
            )
        seen_relative_paths.add(relative_path)
        if source_path in seen_paths:
            raise CensusError(f"line {line_number}: duplicate source file {source_path}")
        seen_paths.add(source_path)
        relative_parts = PurePosixPath(relative_path).parts
        if tuple(source_path.parts[-len(relative_parts) :]) != relative_parts:
            raise CensusError(
                f"line {line_number}: path does not end in relative_path: "
                f"{source_path} vs {relative_path!r}"
            )
        try:
            source_bytes = source_path.read_bytes()
        except OSError as error:
            raise CensusError(
                f"line {line_number}: cannot read source file {source_path}: {error}"
            ) from error
        source_sha256 = sha256_bytes(source_bytes)
        expected_sha256 = row.get("sha256")
        if expected_sha256 is not None:
            if not _is_lower_sha256(expected_sha256):
                raise CensusError(
                    f"line {line_number}: sha256 is not a lowercase SHA-256"
                )
            if expected_sha256 != source_sha256:
                raise CensusError(
                    f"line {line_number}: sha256 mismatch for {relative_path!r}"
                )
        expected_bytes = row.get("bytes")
        if expected_bytes is not None:
            if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int):
                raise CensusError(f"line {line_number}: bytes must be an integer")
            if expected_bytes != len(source_bytes):
                raise CensusError(
                    f"line {line_number}: byte-count mismatch for {relative_path!r}"
                )
        sources.append(
            ManifestSource(
                record_id,
                line_number,
                relative_path,
                source_path,
                source_bytes,
                source_sha256,
            )
        )
    return sorted(sources, key=lambda source: source.relative_path), manifest_bytes


def _canonical_sort_key(value: tuple[object, ...]) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _canonical_nary(op: str, children: Iterable[tuple[object, ...]]) -> tuple[object, ...]:
    flattened: list[tuple[object, ...]] = []
    for child in children:
        if child and child[0] == op:
            flattened.extend(child[1:])  # type: ignore[arg-type]
        else:
            flattened.append(child)
    unique = sorted(set(flattened), key=_canonical_sort_key)
    if op == "and":
        if FALSE_GUARD in unique:
            return FALSE_GUARD
        unique = [child for child in unique if child != TRUE_GUARD]
        if not unique:
            return TRUE_GUARD
    elif op == "or":
        if TRUE_GUARD in unique:
            return TRUE_GUARD
        unique = [child for child in unique if child != FALSE_GUARD]
        if not unique:
            return FALSE_GUARD
    if len(unique) == 1:
        return unique[0]
    return (op, *unique)


def canonical_expression(expression: Any) -> tuple[object, ...]:
    """Canonicalize the independent parser's typed Boolean expression."""

    op = expression.op
    arguments = expression.arguments
    if op == "const":
        if len(arguments) != 1 or not isinstance(arguments[0], bool):
            raise CensusError("invalid structured Boolean constant")
        return ("const", arguments[0])
    if op == "atom":
        if len(arguments) != 1:
            raise CensusError("invalid structured atom")
        key = arguments[0]
        if key.kind == "equality" and key.left is not None and key.right is not None:
            left, right = sorted((key.left, key.right))
            return ("eq", left, right)
        if key.kind == "bool_term" and key.term is not None:
            return ("bool_term", key.term)
        raise CensusError("unsupported structured atom")
    if op == "not":
        if len(arguments) != 1:
            raise CensusError("invalid structured negation")
        child = canonical_expression(arguments[0])
        if child[0] == "const":
            return ("const", not child[1])
        if child[0] == "not":
            return child[1]  # type: ignore[return-value]
        return ("not", child)
    if op in {"and", "or"}:
        return _canonical_nary(op, (canonical_expression(item) for item in arguments))
    if op == "iff":
        children = sorted(
            (canonical_expression(item) for item in arguments),
            key=_canonical_sort_key,
        )
        return ("iff", *children)
    if op == "ite":
        if len(arguments) != 3:
            raise CensusError("invalid structured Boolean ite")
        return ("ite", *(canonical_expression(item) for item in arguments))
    raise CensusError(f"unsupported structured Boolean operator {op!r}")


def _combine_guards(
    left: tuple[object, ...], right: tuple[object, ...]
) -> tuple[object, ...]:
    return _canonical_nary("and", (left, right))


def _eq_pair(expression: Any) -> tuple[int, int] | None:
    if expression.op != "atom" or len(expression.arguments) != 1:
        return None
    key = expression.arguments[0]
    if key.kind != "equality" or key.left is None or key.right is None:
        return None
    return tuple(sorted((key.left, key.right)))


def _disequality_pair(expression: Any) -> tuple[int, int] | None:
    if expression.op != "not" or len(expression.arguments) != 1:
        return None
    return _eq_pair(expression.arguments[0])


def _range_shape(expression: Any, problem: Any) -> tuple[int, tuple[int, ...]] | None:
    if expression.op != "or" or len(expression.arguments) < 2:
        return None
    pairs: list[tuple[int, int]] = []
    for child in expression.arguments:
        pair = _eq_pair(child)
        if pair is None:
            return None
        pairs.append(pair)
    shared = set(pairs[0])
    for pair in pairs[1:]:
        shared.intersection_update(pair)
    if len(shared) != 1:
        return None
    target = next(iter(shared))
    values = tuple(sorted({right if left == target else left for left, right in pairs}))
    if len(values) < 2 or target in values:
        return None
    target_sort = problem.terms[target].sort
    if target_sort == qfuf.BOOL_SORT:
        return None
    if any(problem.terms[value].sort != target_sort for value in values):
        raise CensusError("structured parser returned a mixed-sort equality range")
    return target, values


def _term_is_source(problem: Any, term_id: int, memo: dict[int, bool]) -> bool:
    previous = memo.get(term_id)
    if previous is not None:
        return previous
    # The independent parser interns arguments before applications.  Walking
    # term IDs in order avoids recursion on adversarially deep source terms.
    for current_id in range(term_id + 1):
        if current_id in memo:
            continue
        term = problem.terms[current_id]
        function = problem.functions[term.function]
        memo[current_id] = not function.internal and all(
            memo[argument] for argument in term.args
        )
    return memo[term_id]


def _guard_term_ids(guard: tuple[object, ...]) -> tuple[int, ...]:
    op = guard[0]
    if op == "eq":
        return int(guard[1]), int(guard[2])
    if op == "bool_term":
        return (int(guard[1]),)
    result: list[int] = []
    for child in guard[1:]:
        if isinstance(child, tuple):
            result.extend(_guard_term_ids(child))
    return tuple(sorted(set(result)))


def extract_facts(
    problem: Any, caps: Caps
) -> tuple[tuple[RangeFact, ...], tuple[DisequalityFact, ...], tuple[str, ...]]:
    ranges: set[RangeFact] = set()
    disequalities: set[DisequalityFact] = set()
    abstentions: set[str] = set()
    source_term_memo: dict[int, bool] = {}

    def add_fact(fact: RangeFact | DisequalityFact) -> None:
        target = ranges if isinstance(fact, RangeFact) else disequalities
        if fact in target:
            return
        if len(ranges) + len(disequalities) >= caps.max_proved_facts:
            raise FactCapExceeded(len(ranges) + len(disequalities) + 1)
        target.add(fact)

    def visit(expression: Any, guard: tuple[object, ...]) -> None:
        if guard == FALSE_GUARD:
            abstentions.add("vacuous_false_guard")
            return
        if expression.op == "and":
            for child in expression.arguments:
                visit(child, guard)
            return

        range_shape = _range_shape(expression, problem)
        if range_shape is not None:
            target, values = range_shape
            involved = (target, *values, *_guard_term_ids(guard))
            if all(_term_is_source(problem, term, source_term_memo) for term in involved):
                add_fact(RangeFact(guard, target, values))
            else:
                abstentions.add("range_or_guard_uses_parser_internal_term")
            return

        disequality = _disequality_pair(expression)
        if disequality is not None:
            left, right = disequality
            involved = (left, right, *_guard_term_ids(guard))
            if (
                problem.terms[left].sort != qfuf.BOOL_SORT
                and all(
                    _term_is_source(problem, term, source_term_memo)
                    for term in involved
                )
            ):
                add_fact(DisequalityFact(guard, left, right))
            return

        # The parser lowers implication to (or (not premise) conclusion).
        # Either ordering is semantically sufficient; only a conclusion that
        # recursively yields a supported fact can affect the census.
        if expression.op == "or" and len(expression.arguments) == 2:
            for premise_index in (0, 1):
                premise = expression.arguments[premise_index]
                if premise.op != "not" or len(premise.arguments) != 1:
                    continue
                conclusion = expression.arguments[1 - premise_index]
                before = len(ranges) + len(disequalities)
                premise_guard = canonical_expression(premise.arguments[0])
                visit(conclusion, _combine_guards(guard, premise_guard))
                if len(ranges) + len(disequalities) > before:
                    return

    for assertion in problem.assertions:
        visit(assertion, TRUE_GUARD)
    return tuple(sorted(ranges)), tuple(sorted(disequalities)), tuple(sorted(abstentions))


def effective_ranges(
    range_facts: Sequence[RangeFact],
    disequality_facts: Sequence[DisequalityFact],
    problem: Any,
) -> list[EffectiveRange]:
    by_target_guard: dict[tuple[int, tuple[object, ...]], list[RangeFact]] = {}
    unconditional_targets = {
        fact.target for fact in range_facts if fact.guard == TRUE_GUARD
    }
    observed_contexts = {(fact.target, fact.guard) for fact in range_facts}
    for fact in disequality_facts:
        if fact.guard == TRUE_GUARD:
            continue
        for target in (fact.left, fact.right):
            if target in unconditional_targets:
                observed_contexts.add((target, fact.guard))
    ordered_contexts = sorted(
        observed_contexts,
        key=lambda item: (item[0], _canonical_sort_key(item[1])),
    )
    for target, guard in ordered_contexts:
        applicable = [
            fact
            for fact in range_facts
            if fact.target == target and fact.guard in {TRUE_GUARD, guard}
        ]
        by_target_guard[(target, guard)] = applicable

    result: list[EffectiveRange] = []
    for (target, guard), facts in by_target_guard.items():
        candidates = set(facts[0].values)
        for fact in facts[1:]:
            candidates.intersection_update(fact.values)
        result.append(
            EffectiveRange(
                guard,
                target,
                problem.terms[target].sort,
                tuple(sorted(candidates)),
                len(facts),
            )
        )
    return sorted(
        result,
        key=lambda item: (_canonical_sort_key(item.guard), item.sort, item.target),
    )


def _applicable_edges(
    facts: Sequence[DisequalityFact], guard: tuple[object, ...]
) -> set[tuple[int, int]]:
    return {
        (fact.left, fact.right)
        for fact in facts
        if fact.guard == TRUE_GUARD or fact.guard == guard
    }


def _all_pairs_present(values: Sequence[int], edges: set[tuple[int, int]]) -> bool:
    return all(tuple(sorted(pair)) in edges for pair in itertools.combinations(values, 2))


def _quoted_symbol(name: str) -> str:
    return "|" + name.replace("\\", "\\\\").replace("|", "\\|") + "|"


def _symbol(name: str, quoted: bool) -> str:
    return _quoted_symbol(name) if quoted else name


def term_text(problem: Any, term_id: int, memo: dict[int, str]) -> str:
    previous = memo.get(term_id)
    if previous is not None:
        return previous
    for current_id in range(term_id + 1):
        if current_id in memo:
            continue
        term = problem.terms[current_id]
        function = problem.functions[term.function]
        name = _symbol(function.name, function.quoted)
        if term.args:
            arguments = " ".join(memo[item] for item in term.args)
            memo[current_id] = f"({name} {arguments})"
        else:
            memo[current_id] = name
    return memo[term_id]


def term_record(problem: Any, term_id: int, memo: dict[int, str]) -> dict[str, object]:
    sort = problem.sorts[problem.terms[term_id].sort]
    return {
        "id": term_id,
        "sort": {"id": sort.id, "name": sort.name, "quoted": sort.quoted},
        "text": term_text(problem, term_id, memo),
    }


def guard_id(guard: tuple[object, ...]) -> str:
    if guard == TRUE_GUARD:
        return "unconditional"
    return "guard-sha256:" + sha256_bytes(canonical_json_bytes(guard))


def guard_payload(
    problem: Any, guard: tuple[object, ...], memo: dict[int, str]
) -> dict[str, object]:
    op = guard[0]
    if op == "const":
        return {"op": "const", "value": guard[1]}
    if op == "eq":
        return {
            "op": "equality",
            "left": term_record(problem, int(guard[1]), memo),
            "right": term_record(problem, int(guard[2]), memo),
        }
    if op == "bool_term":
        return {
            "op": "bool_term",
            "term": term_record(problem, int(guard[1]), memo),
        }
    return {
        "op": op,
        "arguments": [
            guard_payload(problem, child, memo)
            for child in guard[1:]
            if isinstance(child, tuple)
        ],
    }


def hall_census(
    candidates: Sequence[EffectiveRange],
    edges: set[tuple[int, int]],
    problem: Any,
    caps: Caps,
    memo: dict[int, str],
) -> tuple[dict[str, object], list[dict[str, object]], list[str]]:
    targets = sorted(candidate.target for candidate in candidates)
    ranges = {candidate.target: set(candidate.values) for candidate in candidates}
    summary: dict[str, object] = {
        "candidate_terms": len(targets),
        "subset_enumerations": 0,
        "subsets_checked": 0,
        "tight_subsets": 0,
        "checked_conflicts": 0,
        "minimum_slack": None,
        "complete": True,
    }
    witnesses: list[dict[str, object]] = []
    abstentions: list[str] = []
    if len(targets) < 2:
        return summary, witnesses, abstentions
    if len(targets) > caps.max_candidate_terms_per_domain:
        summary["complete"] = False
        abstentions.append("hall_candidate_term_cap")
        return summary, witnesses, abstentions

    stop = False
    maximum_size = min(len(targets), caps.max_hall_subset_size)
    for subset_size in range(2, maximum_size + 1):
        for subset in itertools.combinations(targets, subset_size):
            if int(summary["subset_enumerations"]) >= caps.max_hall_subset_enumerations:
                summary["complete"] = False
                abstentions.append("hall_subset_enumeration_cap")
                stop = True
                break
            summary["subset_enumerations"] = int(summary["subset_enumerations"]) + 1
            if not _all_pairs_present(subset, edges):
                continue
            summary["subsets_checked"] = int(summary["subsets_checked"]) + 1
            union = set().union(*(ranges[target] for target in subset))
            slack = len(union) - len(subset)
            minimum = summary["minimum_slack"]
            if minimum is None or slack < int(minimum):
                summary["minimum_slack"] = slack
            if slack <= 0:
                if slack == 0:
                    summary["tight_subsets"] = int(summary["tight_subsets"]) + 1
                else:
                    summary["checked_conflicts"] = int(summary["checked_conflicts"]) + 1
                if len(witnesses) < caps.max_hall_witnesses:
                    witnesses.append(
                        {
                            "kind": "checked_conflict" if slack < 0 else "tight_pressure",
                            "guard_conditioned": candidates[0].guard != TRUE_GUARD,
                            "subset": [term_record(problem, term, memo) for term in subset],
                            "candidate_union": [
                                term_record(problem, term, memo) for term in sorted(union)
                            ],
                            "subset_size": len(subset),
                            "candidate_union_size": len(union),
                            "slack": slack,
                        }
                    )
                elif "hall_witness_cap" not in abstentions:
                    abstentions.append("hall_witness_cap")
        if stop:
            break
    if len(targets) > caps.max_hall_subset_size:
        summary["complete"] = False
        abstentions.append("hall_subset_size_cap")
    return summary, witnesses, sorted(set(abstentions))


def _base_record(
    source: ManifestSource, manifest_sha256: str, caps: Caps
) -> dict[str, object]:
    return {
        "schema": RECORD_SCHEMA,
        "interpretation": INTERPRETATION,
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
        "parser_api": PARSER_API,
        "caps": asdict(caps),
        "eligible": False,
        "ineligibility_reason": None,
        "cap_events": [],
        "abstentions": [],
        "proven_range_facts": [],
        "proven_disequality_facts": 0,
        "guards": [],
        "domains": [],
        "totals": {
            "proven_range_facts": 0,
            "effective_candidate_ranges": 0,
            "certified_uniform_domains": 0,
            "uniform_value_cells": 0,
            "non_uniform_value_cells": 0,
            "value_cell_savings": 0,
            "hall_subsets_checked": 0,
            "hall_checked_conflicts": 0,
        },
    }


def _ineligible(record: dict[str, object], reason: str) -> dict[str, object]:
    record["eligible"] = False
    record["ineligibility_reason"] = reason
    abstentions = record["abstentions"]
    assert isinstance(abstentions, list)
    if reason not in abstentions:
        abstentions.append(reason)
    abstentions.sort()
    return record


def analyze_source(
    source: ManifestSource, manifest_sha256: str, caps: Caps
) -> dict[str, object]:
    record = _base_record(source, manifest_sha256, caps)
    if len(source.source_bytes) > caps.max_source_bytes:
        record["cap_events"] = [
            {
                "code": "source_byte_cap",
                "limit": caps.max_source_bytes,
                "observed": len(source.source_bytes),
            }
        ]
        return _ineligible(record, "source_byte_cap")
    try:
        source_text = source.source_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        record["parse_error"] = f"source is not UTF-8: {error}"
        return _ineligible(record, "source_not_utf8")
    try:
        problem = qfuf.parse_and_encode(source_text)
    except qfuf.IndependentQfufError as error:
        record["parse_error"] = str(error)
        return _ineligible(record, "structured_parse_error")
    if len(problem.terms) > caps.max_terms:
        record["cap_events"] = [
            {
                "code": "parsed_term_cap",
                "limit": caps.max_terms,
                "observed": len(problem.terms),
            }
        ]
        return _ineligible(record, "parsed_term_cap")
    if problem.bool_data_terms:
        return _ineligible(record, "bool_as_data_present")

    try:
        ranges, disequalities, extraction_abstentions = extract_facts(problem, caps)
    except FactCapExceeded as error:
        record["cap_events"] = [
            {
                "code": "proved_fact_cap",
                "limit": caps.max_proved_facts,
                "observed": error.observed,
            }
        ]
        return _ineligible(record, "proved_fact_cap")

    memo: dict[int, str] = {}
    record["abstentions"] = list(extraction_abstentions)
    record["proven_disequality_facts"] = len(disequalities)
    record["proven_range_facts"] = [
        {
            "guard_id": guard_id(fact.guard),
            "guard": guard_payload(problem, fact.guard, memo),
            "target": term_record(problem, fact.target, memo),
            "values": [term_record(problem, value, memo) for value in fact.values],
            "range_size": len(fact.values),
        }
        for fact in ranges
    ]
    totals = record["totals"]
    assert isinstance(totals, dict)
    totals["proven_range_facts"] = len(ranges)
    if not ranges:
        return _ineligible(record, "no_proven_non_bool_range")

    effective = effective_ranges(ranges, disequalities, problem)
    nonempty: list[EffectiveRange] = []
    abstentions = set(record["abstentions"])
    for candidate in effective:
        if candidate.values:
            nonempty.append(candidate)
        else:
            abstentions.add("empty_effective_candidate_range")
    totals["effective_candidate_ranges"] = len(nonempty)

    guards = sorted({item.guard for item in nonempty}, key=_canonical_sort_key)
    record["guards"] = [
        {
            "id": guard_id(guard),
            "kind": "unconditional" if guard == TRUE_GUARD else "structured_condition",
            "expression": guard_payload(problem, guard, memo),
        }
        for guard in guards
    ]

    domains: list[dict[str, object]] = []
    for guard in guards:
        edges = _applicable_edges(disequalities, guard)
        sorts = sorted({item.sort for item in nonempty if item.guard == guard})
        for sort_id in sorts:
            candidates = [
                item for item in nonempty if item.guard == guard and item.sort == sort_id
            ]
            values = sorted(set().union(*(set(item.values) for item in candidates)))
            if len(values) < 2 or not _all_pairs_present(values, edges):
                abstentions.add("uniform_value_union_not_proved_pairwise_distinct")
                continue
            sort = problem.sorts[sort_id]
            domain_id_material = [guard, sort_id, values]
            domain_id = "domain-sha256:" + sha256_bytes(
                canonical_json_bytes(domain_id_material)
            )
            candidate_records: list[dict[str, object]] = []
            uniform_cells = len(candidates) * len(values)
            non_uniform_cells = sum(len(item.values) for item in candidates)
            for item in candidates:
                candidate_records.append(
                    {
                        "term": term_record(problem, item.target, memo),
                        "values": [
                            term_record(problem, value, memo) for value in item.values
                        ],
                        "range_size": len(item.values),
                        "uniform_range_size": len(values),
                        "value_cell_savings": len(values) - len(item.values),
                        "contributing_proven_range_facts": item.contributing_facts,
                    }
                )
            hall_summary, hall_witnesses, hall_abstentions = hall_census(
                candidates, edges, problem, caps, memo
            )
            abstentions.update(hall_abstentions)
            domains.append(
                {
                    "id": domain_id,
                    "guard_id": guard_id(guard),
                    "sort": {"id": sort.id, "name": sort.name, "quoted": sort.quoted},
                    "uniform_values": [
                        term_record(problem, value, memo) for value in values
                    ],
                    "uniform_range_size": len(values),
                    "candidate_ranges": candidate_records,
                    "value_cells": {
                        "uniform_one_hot": uniform_cells,
                        "non_uniform": non_uniform_cells,
                        "savings": uniform_cells - non_uniform_cells,
                    },
                    "hall": {
                        "summary": hall_summary,
                        "witnesses": hall_witnesses,
                    },
                }
            )

    domains.sort(key=lambda item: str(item["id"]))
    record["domains"] = domains
    totals["certified_uniform_domains"] = len(domains)
    totals["uniform_value_cells"] = sum(
        int(domain["value_cells"]["uniform_one_hot"]) for domain in domains  # type: ignore[index]
    )
    totals["non_uniform_value_cells"] = sum(
        int(domain["value_cells"]["non_uniform"]) for domain in domains  # type: ignore[index]
    )
    totals["value_cell_savings"] = sum(
        int(domain["value_cells"]["savings"]) for domain in domains  # type: ignore[index]
    )
    totals["hall_subsets_checked"] = sum(
        int(domain["hall"]["summary"]["subsets_checked"])  # type: ignore[index]
        for domain in domains
    )
    totals["hall_checked_conflicts"] = sum(
        int(domain["hall"]["summary"]["checked_conflicts"])  # type: ignore[index]
        for domain in domains
    )
    record["abstentions"] = sorted(abstentions)
    if not domains:
        return _ineligible(record, "no_source_certified_uniform_domain")
    if int(totals["value_cell_savings"]) <= 0:
        return _ineligible(record, "no_non_uniform_value_cell_savings")
    record["eligible"] = True
    record["ineligibility_reason"] = None
    return record


def aggregate_records(
    records: Sequence[dict[str, object]],
    manifest_sha256: str,
    records_sha256: str,
    caps: Caps,
) -> dict[str, object]:
    reasons = Counter(
        str(record["ineligibility_reason"])
        for record in records
        if record["ineligibility_reason"] is not None
    )
    abstentions = Counter(
        str(reason)
        for record in records
        for reason in record["abstentions"]  # type: ignore[union-attr]
    )
    cap_events = Counter(
        str(event["code"])
        for record in records
        for event in record["cap_events"]  # type: ignore[union-attr]
    )
    total_fields = (
        "proven_range_facts",
        "effective_candidate_ranges",
        "certified_uniform_domains",
        "uniform_value_cells",
        "non_uniform_value_cells",
        "value_cell_savings",
        "hall_subsets_checked",
        "hall_checked_conflicts",
    )
    totals = {
        field: sum(int(record["totals"][field]) for record in records)  # type: ignore[index]
        for field in total_fields
    }
    return {
        "schema": AGGREGATE_SCHEMA,
        "interpretation": INTERPRETATION,
        "parser_api": PARSER_API,
        "caps": asdict(caps),
        "hashes": {
            "input_manifest_sha256": manifest_sha256,
            "records_jsonl_sha256": records_sha256,
            "analyzer_sha256": sha256_bytes(Path(__file__).read_bytes()),
        },
        "sources": {
            "total": len(records),
            "eligible": sum(bool(record["eligible"]) for record in records),
            "ineligible": sum(not bool(record["eligible"]) for record in records),
            "ineligibility_reasons": dict(sorted(reasons.items())),
        },
        "totals": totals,
        "abstentions": dict(sorted(abstentions.items())),
        "cap_events": dict(sorted(cap_events.items())),
    }


def _atomic_write_pair(artifacts: Sequence[tuple[Path, bytes]]) -> None:
    resolved = [path.resolve(strict=False) for path, _ in artifacts]
    if len(set(resolved)) != len(resolved):
        raise CensusError("output paths must be distinct")
    staged: list[tuple[Path, Path]] = []
    try:
        for path, payload in artifacts:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            temporary = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            staged.append((temporary, path))
        for temporary, path in staged:
            os.replace(temporary, path)
    finally:
        for temporary, _ in staged:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def run_census(
    manifest_path: Path,
    records_out: Path,
    aggregate_out: Path,
    *,
    repository_root: Path,
    caps: Caps,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    caps.validate()
    manifest_resolved = Path(manifest_path).resolve(strict=False)
    if manifest_resolved in {
        Path(records_out).resolve(strict=False),
        Path(aggregate_out).resolve(strict=False),
    }:
        raise CensusError("outputs must not overwrite the input manifest")
    sources, manifest_bytes = load_manifest(manifest_path, repository_root)
    manifest_sha256 = sha256_bytes(manifest_bytes)
    records = [analyze_source(source, manifest_sha256, caps) for source in sources]
    records_bytes = b"".join(canonical_json_bytes(record) for record in records)
    aggregate = aggregate_records(
        records, manifest_sha256, sha256_bytes(records_bytes), caps
    )
    _atomic_write_pair(
        (
            (Path(records_out), records_bytes),
            (Path(aggregate_out), canonical_json_bytes(aggregate)),
        )
    )
    return records, aggregate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--records-out", type=Path, required=True)
    parser.add_argument("--aggregate-out", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--max-source-bytes", type=int, default=Caps.max_source_bytes)
    parser.add_argument("--max-terms", type=int, default=Caps.max_terms)
    parser.add_argument("--max-proved-facts", type=int, default=Caps.max_proved_facts)
    parser.add_argument(
        "--max-candidate-terms-per-domain",
        type=int,
        default=Caps.max_candidate_terms_per_domain,
    )
    parser.add_argument(
        "--max-hall-subset-size", type=int, default=Caps.max_hall_subset_size
    )
    parser.add_argument(
        "--max-hall-subset-enumerations",
        type=int,
        default=Caps.max_hall_subset_enumerations,
    )
    parser.add_argument(
        "--max-hall-witnesses", type=int, default=Caps.max_hall_witnesses
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    caps = Caps(
        max_source_bytes=args.max_source_bytes,
        max_terms=args.max_terms,
        max_proved_facts=args.max_proved_facts,
        max_candidate_terms_per_domain=args.max_candidate_terms_per_domain,
        max_hall_subset_size=args.max_hall_subset_size,
        max_hall_subset_enumerations=args.max_hall_subset_enumerations,
        max_hall_witnesses=args.max_hall_witnesses,
    )
    try:
        records, aggregate = run_census(
            args.manifest,
            args.records_out,
            args.aggregate_out,
            repository_root=args.repository_root,
            caps=caps,
        )
    except CensusError as error:
        parser.exit(2, f"guarded adequate-range census failed: {error}\n")
    print(
        f"sources={len(records)} eligible={aggregate['sources']['eligible']} "
        f"records_sha256={aggregate['hashes']['records_jsonl_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
