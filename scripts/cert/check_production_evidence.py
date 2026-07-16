#!/usr/bin/env python3
"""Independently validate evidence emitted by the literal production solve.

SAT validation reconstructs QF_UF from source and evaluates it in the exact
ground model carried by the timed run. UNSAT is never accepted by this schema;
an unsupported record only documents why the production result was withheld.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from independent_qfuf import (  # noqa: E402
    BOOL_SORT,
    BoolExpr,
    EncodedProblem,
    IndependentQfufError,
    congruence_axiom_clauses,
    equality_transitivity_clauses,
    parse_and_encode_production,
    validate_euf_lemma,
    validate_total_assignment,
)
from strict_artifacts import (  # noqa: E402
    StrictArtifactError,
    canonical_json_bytes,
    read_regular_nofollow,
    strict_json_loads,
)


SCHEMA: Final = "euf-viper.production-evidence.v4"
CONTRACT: Final = "deterministic-cnf-transcript-v1"
SEALED_BUILD_RECEIPT_SCHEMA: Final = "euf-viper.sealed-build-receipt.v3"
SEALED_BUILD_ATTESTATION_SCHEMA: Final = "euf-viper.sealed-build-attestation.v1"
SEALED_BUILD_RECEIPT_SHA256_ENV: Final = "EUF_VIPER_SEALED_BUILD_RECEIPT_SHA256"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
INDEPENDENT_INTERNAL = re.compile(r"@independent_(.+)_[0-9]+\Z")


class ProductionEvidenceError(Exception):
    """Raised when a production sidecar is missing, malformed, or unsound."""


def canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json_bytes(value)
    except StrictArtifactError as error:
        raise ProductionEvidenceError(f"value is not canonical JSON: {error}") from error


def _read_regular_nofollow(path: Path, context: str) -> tuple[Path, bytes]:
    try:
        return read_regular_nofollow(path, context)
    except StrictArtifactError as error:
        raise ProductionEvidenceError(str(error)) from error


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProductionEvidenceError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _read_json_bytes(content: bytes, context: str) -> dict[str, Any]:
    try:
        text = content.decode("utf-8")
        value = strict_json_loads(text, context)
    except (UnicodeError, StrictArtifactError) as error:
        raise ProductionEvidenceError(f"cannot parse {context}: {error}") from error
    if type(value) is not dict:
        raise ProductionEvidenceError(f"{context} root must be an object")
    if canonical_bytes(value) != content:
        raise ProductionEvidenceError(f"{context} is not canonical UTF-8 JSON")
    return value


def _exact(value: object, keys: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ProductionEvidenceError(f"{context} must be an object")
    found = set(value)
    if found != keys:
        raise ProductionEvidenceError(
            f"{context} keys differ: missing={sorted(keys - found)!r}, "
            f"extra={sorted(found - keys)!r}"
        )
    return value


def _string(value: object, context: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        raise ProductionEvidenceError(f"{context} must be a string")
    return value


def _integer(value: object, context: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ProductionEvidenceError(f"{context} must be an integer >= {minimum}")
    return value


def _hash(value: object, context: str) -> str:
    text = _string(value, context)
    if not HEX64.fullmatch(text):
        raise ProductionEvidenceError(f"{context} must be a lowercase SHA-256")
    return text


def _value(term: Mapping[str, Any]) -> tuple[str, int]:
    return str(term["sort"]), int(term["class"])


def _validate_assignment(model: Mapping[str, Any]) -> tuple[bool, ...]:
    assignment = model["assignment"]
    assignment_hash = model["assignment_sha256"]
    if isinstance(assignment, (str, bytes)) or not isinstance(assignment, Sequence):
        raise ProductionEvidenceError("model.assignment must be a literal list")
    values = [False]
    for variable, literal in enumerate(assignment, start=1):
        if type(literal) is not int or literal == 0 or abs(literal) != variable:
            raise ProductionEvidenceError(
                f"assignment entry {variable} must assign variable {variable}"
            )
        values.append(literal > 0)
    expected = hashlib.sha256(canonical_bytes(list(assignment))).hexdigest()
    if _hash(assignment_hash, "model.assignment_sha256") != expected:
        raise ProductionEvidenceError("assignment SHA-256 mismatch")
    return tuple(values)


def _validate_terms(model: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_terms = model["terms"]
    if isinstance(raw_terms, (str, bytes)) or not isinstance(raw_terms, Sequence):
        raise ProductionEvidenceError("model.terms must be a list")
    terms: list[dict[str, Any]] = []
    class_sorts: dict[int, str] = {}
    for expected_id, raw in enumerate(raw_terms):
        term = _exact(
            raw,
            {"id", "function", "args", "sort", "class", "internal", "internal_kind"},
            f"model.terms[{expected_id}]",
        )
        if _integer(term["id"], f"model.terms[{expected_id}].id") != expected_id:
            raise ProductionEvidenceError("term IDs must be contiguous and ordered")
        _string(term["function"], f"model.terms[{expected_id}].function")
        sort = _string(term["sort"], f"model.terms[{expected_id}].sort")
        class_id = _integer(term["class"], f"model.terms[{expected_id}].class")
        if type(term["internal"]) is not bool:
            raise ProductionEvidenceError(f"model.terms[{expected_id}].internal must be boolean")
        kind = term["internal_kind"]
        if term["internal"]:
            _string(kind, f"model.terms[{expected_id}].internal_kind")
        elif kind is not None:
            raise ProductionEvidenceError("non-internal term cannot carry internal_kind")
        args = term["args"]
        if isinstance(args, (str, bytes)) or not isinstance(args, Sequence):
            raise ProductionEvidenceError(f"model.terms[{expected_id}].args must be a list")
        for argument in args:
            if type(argument) is not int or not 0 <= argument < expected_id:
                raise ProductionEvidenceError(
                    f"model.terms[{expected_id}] has an invalid argument"
                )
        previous_sort = class_sorts.setdefault(class_id, sort)
        if previous_sort != sort:
            raise ProductionEvidenceError(
                f"model class {class_id} crosses sorts {previous_sort!r} and {sort!r}"
            )
        terms.append(term)

    signatures: dict[tuple[str, str, tuple[tuple[str, int], ...]], tuple[str, int]] = {}
    for term in terms:
        if term["internal"]:
            continue
        key = (
            str(term["sort"]),
            str(term["function"]),
            tuple(_value(terms[argument]) for argument in term["args"]),
        )
        result = _value(term)
        previous = signatures.setdefault(key, result)
        if previous != result:
            raise ProductionEvidenceError(
                f"function {term['function']!r} has inconsistent ground interpretation"
            )
    return terms


def _validate_atoms(
    model: Mapping[str, Any],
    terms: Sequence[Mapping[str, Any]],
    assignment: tuple[bool, ...] | None,
) -> dict[int, tuple[Any, ...]]:
    atoms = model["atoms"]
    if isinstance(atoms, (str, bytes)) or not isinstance(atoms, Sequence):
        raise ProductionEvidenceError("model.atoms must be a list")
    variables: set[int] = set()
    atom_map: dict[int, tuple[Any, ...]] = {}
    true_term = model["true_term"]
    false_term = model["false_term"]
    if (true_term is None) != (false_term is None):
        raise ProductionEvidenceError("true_term and false_term must both be present or absent")
    true_value: tuple[str, int] | None = None
    false_value: tuple[str, int] | None = None
    if true_term is not None:
        true_id = _integer(true_term, "model.true_term")
        false_id = _integer(false_term, "model.false_term")
        if not true_id < len(terms) or not false_id < len(terms):
            raise ProductionEvidenceError("Boolean value term is out of range")
        true_value = _value(terms[true_id])
        false_value = _value(terms[false_id])
        if true_value[0] != "Bool" or false_value[0] != "Bool":
            raise ProductionEvidenceError("true and false must have sort Bool")
        if true_value == false_value:
            raise ProductionEvidenceError("true and false share one model class")
    bool_values = {_value(term) for term in terms if term["sort"] == "Bool"}
    if bool_values and (true_value is None or false_value is None):
        raise ProductionEvidenceError("Boolean model terms lack true/false metadata")
    if true_value is not None and not bool_values <= {true_value, false_value}:
        raise ProductionEvidenceError("production model gives Bool a third value")
    for index, raw in enumerate(atoms):
        if type(raw) is not dict:
            raise ProductionEvidenceError(f"model.atoms[{index}] must be an object")
        kind = raw.get("kind")
        if kind == "equality":
            atom = _exact(raw, {"kind", "variable", "left", "right", "value"}, f"atom {index}")
            left = _integer(atom["left"], f"atom {index}.left")
            right = _integer(atom["right"], f"atom {index}.right")
            if not left < len(terms) or not right < len(terms):
                raise ProductionEvidenceError(f"atom {index} references an invalid term")
            expected_value = _value(terms[left]) == _value(terms[right])
            atom_key: tuple[Any, ...] = ("equality", left, right)
        elif kind == "bool_term":
            atom = _exact(raw, {"kind", "variable", "term", "value"}, f"atom {index}")
            term = _integer(atom["term"], f"atom {index}.term")
            if not term < len(terms) or true_value is None or false_value is None:
                raise ProductionEvidenceError(f"atom {index} has invalid Boolean term metadata")
            term_value = _value(terms[term])
            if term_value not in {true_value, false_value}:
                raise ProductionEvidenceError(f"atom {index} Boolean term has a third value")
            expected_value = term_value == true_value
            atom_key = ("bool_term", term)
        else:
            raise ProductionEvidenceError(f"atom {index} has unknown kind {kind!r}")
        variable = _integer(atom["variable"], f"atom {index}.variable", 1)
        if variable in variables:
            raise ProductionEvidenceError(f"duplicate atom variable {variable}")
        variables.add(variable)
        atom_map[variable] = atom_key
        if type(atom["value"]) is not bool or atom["value"] != expected_value:
            raise ProductionEvidenceError(f"atom {index} disagrees with the production model")
        if assignment is not None:
            if variable >= len(assignment) or assignment[variable] != atom["value"]:
                raise ProductionEvidenceError(f"atom {index} disagrees with the SAT assignment")
    return atom_map


def _clauses(value: object, context: str, var_count: int) -> list[list[int]]:
    if type(value) is not list:
        raise ProductionEvidenceError(f"{context} must be a list")
    result: list[list[int]] = []
    for index, raw_clause in enumerate(value):
        if type(raw_clause) is not list or not raw_clause:
            raise ProductionEvidenceError(f"{context}[{index}] must be a nonempty list")
        clause: list[int] = []
        for literal in raw_clause:
            if type(literal) is not int or literal == 0 or abs(literal) > var_count:
                raise ProductionEvidenceError(
                    f"{context}[{index}] has an invalid DIMACS literal"
                )
            clause.append(literal)
        result.append(clause)
    return result


def _assignment_literals(value: object, var_count: int, context: str) -> list[int]:
    if type(value) is not list or len(value) != var_count:
        raise ProductionEvidenceError(
            f"{context} must assign all {var_count} variables exactly once"
        )
    for variable, literal in enumerate(value, start=1):
        if type(literal) is not int or abs(literal) != variable:
            raise ProductionEvidenceError(
                f"{context}[{variable - 1}] must assign variable {variable}"
            )
    return list(value)


def _satisfies(assignment: Sequence[int], clauses: Sequence[Sequence[int]]) -> bool:
    values = (False, *(literal > 0 for literal in assignment))
    return all(
        any(values[abs(literal)] == (literal > 0) for literal in clause)
        for clause in clauses
    )


def _expected_variables(
    problem: EncodedProblem, source_term_ids: Sequence[int | None]
) -> tuple[list[dict[str, Any]], dict[int, tuple[Any, ...]]]:
    variables: list[dict[str, Any]] = []
    atoms: dict[int, tuple[Any, ...]] = {}
    for atom in problem.atoms:
        if atom.kind == "auxiliary":
            variables.append({"kind": "auxiliary", "variable": atom.variable})
            continue
        if atom.kind == "equality":
            assert atom.left is not None and atom.right is not None
            left = source_term_ids[atom.left]
            right = source_term_ids[atom.right]
            if left is None or right is None:
                raise ProductionEvidenceError(
                    f"equality variable {atom.variable} lacks exact production terms"
                )
            left, right = sorted((left, right))
            variables.append(
                {
                    "kind": "equality",
                    "variable": atom.variable,
                    "left": left,
                    "right": right,
                }
            )
            atoms[atom.variable] = ("equality", left, right)
            continue
        if atom.kind == "bool_term":
            assert atom.term is not None
            term = source_term_ids[atom.term]
            if term is None:
                raise ProductionEvidenceError(
                    f"Boolean variable {atom.variable} lacks an exact production term"
                )
            variables.append(
                {"kind": "bool_term", "variable": atom.variable, "term": term}
            )
            atoms[atom.variable] = ("bool_term", term)
            continue
        raise ProductionEvidenceError(
            f"independent variable {atom.variable} has unknown kind {atom.kind!r}"
        )
    return variables, atoms


def _static_clause_events(
    problem: EncodedProblem, backend: str, config: Mapping[str, str]
) -> tuple[list[dict[str, Any]], list[list[int]]]:
    events: list[dict[str, Any]] = []
    clauses: list[list[int]] = []

    def extend(phase: str, additions: Sequence[Sequence[int]]) -> None:
        for addition in additions:
            clause = list(addition)
            events.append({"kind": "clause", "phase": phase, "clause": clause})
            clauses.append(clause)

    if backend in {"kissat", "cadical", "cadical-refine", "varisat"}:
        extend("transitivity", equality_transitivity_clauses(problem))
    if backend in {"kissat", "cadical", "varisat"}:
        eager = config.get("EUF_VIPER_EAGER_CONGRUENCE") != "0"
        if eager:
            extend("congruence", congruence_axiom_clauses(problem))
    if backend not in {"kissat", "cadical", "cadical-refine", "varisat", "dpll-t"}:
        raise ProductionEvidenceError(
            f"backend {backend!r} has no decisive production-evidence contract"
        )
    return events, clauses


def _validate_backend_cnf(
    raw_cnf: object,
    problem: EncodedProblem,
    source_term_ids: Sequence[int | None],
    model_assignment: Sequence[int],
    model_atoms: Mapping[int, tuple[Any, ...]],
    backend: str,
    config: Mapping[str, str],
) -> tuple[int, int, int]:
    cnf = _exact(
        raw_cnf,
        {
            "format",
            "claim",
            "var_count",
            "variables",
            "initial_clause_count",
            "initial_clauses_sha256",
            "initial_clauses",
            "final_clause_count",
            "final_clauses_sha256",
            "final_clauses",
            "transcript_event_count",
            "transcript_sha256",
            "transcript",
        },
        "backend_cnf",
    )
    if cnf["format"] != "dimacs-literal-arrays":
        raise ProductionEvidenceError("backend_cnf.format is unsupported")
    if cnf["claim"] != "clauses-supplied-through-backend-api":
        raise ProductionEvidenceError("backend_cnf.claim exceeds or changes the API-clause claim")
    var_count = _integer(cnf["var_count"], "backend_cnf.var_count", 0)
    if var_count != problem.variable_count or var_count != len(model_assignment):
        raise ProductionEvidenceError(
            "backend variable count differs from independent reconstruction"
        )

    expected_variables, expected_atoms = _expected_variables(problem, source_term_ids)
    if cnf["variables"] != expected_variables:
        raise ProductionEvidenceError(
            "backend variable namespace/map differs from independent reconstruction"
        )
    if dict(model_atoms) != expected_atoms:
        raise ProductionEvidenceError(
            "model atom identities differ from the exact reconstructed namespace"
        )

    initial_clauses = _clauses(
        cnf["initial_clauses"], "backend_cnf.initial_clauses", var_count
    )
    expected_initial = [list(clause) for clause in problem.clauses]
    if initial_clauses != expected_initial:
        raise ProductionEvidenceError(
            "initial production CNF differs from independent source reconstruction"
        )
    if _integer(cnf["initial_clause_count"], "backend_cnf.initial_clause_count") != len(
        initial_clauses
    ):
        raise ProductionEvidenceError("initial clause count mismatch")
    initial_hash = hashlib.sha256(canonical_bytes(initial_clauses)).hexdigest()
    if _hash(cnf["initial_clauses_sha256"], "initial_clauses_sha256") != initial_hash:
        raise ProductionEvidenceError("initial clause SHA-256 mismatch")

    final_clauses = _clauses(
        cnf["final_clauses"], "backend_cnf.final_clauses", var_count
    )
    if _integer(cnf["final_clause_count"], "backend_cnf.final_clause_count") != len(
        final_clauses
    ):
        raise ProductionEvidenceError("final clause count mismatch")
    final_hash = hashlib.sha256(canonical_bytes(final_clauses)).hexdigest()
    if _hash(cnf["final_clauses_sha256"], "final_clauses_sha256") != final_hash:
        raise ProductionEvidenceError("final clause SHA-256 mismatch")

    transcript = cnf["transcript"]
    if type(transcript) is not list:
        raise ProductionEvidenceError("backend_cnf.transcript must be a list")
    if _integer(cnf["transcript_event_count"], "transcript_event_count") != len(transcript):
        raise ProductionEvidenceError("transcript event count mismatch")
    transcript_hash = hashlib.sha256(canonical_bytes(transcript)).hexdigest()
    if _hash(cnf["transcript_sha256"], "transcript_sha256") != transcript_hash:
        raise ProductionEvidenceError("transcript SHA-256 mismatch")

    static_events, static_clauses = _static_clause_events(problem, backend, config)
    if transcript[: len(static_events)] != static_events:
        raise ProductionEvidenceError(
            "static backend clause transcript differs from independent reconstruction"
        )
    current_clauses = [*initial_clauses, *static_clauses]
    position = len(static_events)
    call = 1
    final_assignment: list[int] | None = None
    learned: set[tuple[int, ...]] = set()
    while position < len(transcript):
        solve = _exact(transcript[position], {"kind", "call"}, f"transcript[{position}]")
        if solve["kind"] != "solve" or _integer(solve["call"], "solve.call", 1) != call:
            raise ProductionEvidenceError("transcript solve events are not contiguous")
        position += 1
        if position >= len(transcript):
            raise ProductionEvidenceError("transcript ends after solve event")
        assignment_event = _exact(
            transcript[position],
            {"kind", "call", "assignment"},
            f"transcript[{position}]",
        )
        if (
            assignment_event["kind"] != "assignment"
            or _integer(assignment_event["call"], "assignment.call", 1) != call
        ):
            raise ProductionEvidenceError("solve lacks its exact assignment event")
        assignment = _assignment_literals(
            assignment_event["assignment"], var_count, "transcript assignment"
        )
        if not _satisfies(assignment, current_clauses):
            raise ProductionEvidenceError(
                f"transcript assignment {call} falsifies the replayed clause stream"
            )
        position += 1
        if position >= len(transcript):
            raise ProductionEvidenceError("transcript ends before validation event")
        validation = _exact(
            transcript[position],
            {"kind", "call", "conflicts"},
            f"transcript[{position}]",
        )
        if (
            validation["kind"] != "validation"
            or _integer(validation["call"], "validation.call", 1) != call
        ):
            raise ProductionEvidenceError("assignment lacks its exact validation event")
        conflicts = _clauses(validation["conflicts"], "validation.conflicts", var_count)
        position += 1
        try:
            validate_total_assignment(problem, assignment)
            theory_valid = True
        except IndependentQfufError:
            theory_valid = False
        if theory_valid:
            if conflicts:
                raise ProductionEvidenceError("valid assignment records invented theory conflicts")
            if position != len(transcript):
                raise ProductionEvidenceError("transcript continues after a valid final assignment")
            final_assignment = assignment
            break

        conflict = sorted(
            -assignment[atom.variable - 1]
            for atom in problem.atoms
            if atom.kind != "auxiliary"
        )
        expected_conflicts = [conflict]
        if conflicts != expected_conflicts:
            raise ProductionEvidenceError(
                "theory validation conflict differs from the deterministic atom cut"
            )
        try:
            validate_euf_lemma(problem, conflict)
        except IndependentQfufError as error:
            raise ProductionEvidenceError(
                f"recorded theory cut is not independently valid: {error}"
            ) from error
        if tuple(conflict) in learned:
            raise ProductionEvidenceError("transcript repeats a theory clause")
        learned.add(tuple(conflict))
        if position >= len(transcript):
            raise ProductionEvidenceError("validation conflict is omitted from the backend stream")
        clause_event = _exact(
            transcript[position],
            {"kind", "phase", "clause"},
            f"transcript[{position}]",
        )
        if (
            clause_event["kind"] != "clause"
            or clause_event["phase"] != "theory"
            or clause_event["clause"] != conflict
        ):
            raise ProductionEvidenceError("backend theory-clause event differs from validation")
        current_clauses.append(conflict)
        position += 1
        call += 1

    if final_assignment is None:
        raise ProductionEvidenceError("transcript has no independently valid final assignment")
    if final_assignment != list(model_assignment):
        raise ProductionEvidenceError("final transcript assignment differs from model.assignment")
    if current_clauses != final_clauses:
        raise ProductionEvidenceError(
            "final backend clause stream has an omission, addition, or reordering"
        )
    if not _satisfies(model_assignment, final_clauses):
        raise ProductionEvidenceError("model assignment does not satisfy every final clause")
    return var_count, len(initial_clauses), len(final_clauses)


def _evaluate_source_model(
    problem: EncodedProblem, terms: Sequence[Mapping[str, Any]], model: Mapping[str, Any]
) -> tuple[int | None, ...]:
    interpretations: dict[
        tuple[str, str, tuple[tuple[str, int], ...]], tuple[str, int]
    ] = {}
    production_terms: dict[tuple[str, str, tuple[int, ...]], int] = {}
    internal_by_kind: dict[str, list[tuple[int, tuple[str, int]]]] = defaultdict(list)
    for term in terms:
        value = _value(term)
        if term["internal"]:
            internal_by_kind[str(term["internal_kind"])].append((int(term["id"]), value))
            continue
        syntax = (
            str(term["sort"]),
            str(term["function"]),
            tuple(int(argument) for argument in term["args"]),
        )
        if syntax in production_terms:
            raise ProductionEvidenceError(
                f"production model repeats ground term {term['function']!r}"
            )
        production_terms[syntax] = int(term["id"])
        key = (
            str(term["sort"]),
            str(term["function"]),
            tuple(_value(terms[argument]) for argument in term["args"]),
        )
        previous = interpretations.setdefault(key, value)
        if previous != value:
            raise ProductionEvidenceError(f"inconsistent interpretation for {term['function']!r}")

    true_id = model["true_term"]
    false_id = model["false_term"]
    if true_id is None:
        true_value = ("Bool", -1)
        false_value = ("Bool", -2)
    else:
        true_value = _value(terms[int(true_id)])
        false_value = _value(terms[int(false_id)])

    source_values: list[tuple[str, int]] = []
    source_term_ids: list[int | None] = []
    internal_positions: dict[str, int] = defaultdict(int)
    for source_term in problem.terms:
        function = problem.functions[source_term.function]
        sort_name = problem.sorts[source_term.sort].name
        if source_term.id == problem.true_term:
            value = true_value
            production_id = None if true_id is None else int(true_id)
        elif source_term.id == problem.false_term:
            value = false_value
            production_id = None if false_id is None else int(false_id)
        elif function.internal:
            match = INDEPENDENT_INTERNAL.fullmatch(function.name)
            if match is None:
                raise ProductionEvidenceError(
                    f"independent internal function {function.name!r} has no stable kind"
                )
            kind = match.group(1)
            position = internal_positions[kind]
            internal_positions[kind] += 1
            candidates = internal_by_kind.get(kind, [])
            if position >= len(candidates):
                raise ProductionEvidenceError(
                    f"production model lacks internal {kind!r} term {position}"
                )
            production_id, value = candidates[position]
        else:
            value_args = tuple(source_values[argument] for argument in source_term.args)
            key = (sort_name, function.name, value_args)
            try:
                value = interpretations[key]
            except KeyError as error:
                raise ProductionEvidenceError(
                    f"production model lacks source term {function.name!r}{value_args!r}"
                ) from error
            syntax_args = tuple(source_term_ids[argument] for argument in source_term.args)
            if any(argument is None for argument in syntax_args):
                raise ProductionEvidenceError(
                    f"source term {function.name!r} depends on an unmapped internal value"
                )
            syntax = (
                sort_name,
                function.name,
                tuple(int(argument) for argument in syntax_args),
            )
            try:
                production_id = production_terms[syntax]
            except KeyError as error:
                raise ProductionEvidenceError(
                    f"production model lacks exact source term {function.name!r}"
                ) from error
        if value[0] != sort_name:
            raise ProductionEvidenceError(
                f"source term {source_term.id} has value of sort {value[0]!r}, "
                f"expected {sort_name!r}"
            )
        source_values.append(value)
        source_term_ids.append(production_id)

    def evaluate(expression: BoolExpr) -> bool:
        if expression.op == "const":
            value = expression.arguments[0]
            if type(value) is not bool:
                raise ProductionEvidenceError("invalid independent Boolean constant")
            return value
        if expression.op == "atom":
            atom = expression.arguments[0]
            if getattr(atom, "kind", None) == "equality":
                return source_values[atom.left] == source_values[atom.right]
            if getattr(atom, "kind", None) == "bool_term":
                value = source_values[atom.term]
                if value not in {true_value, false_value}:
                    raise ProductionEvidenceError("source Boolean term has a third value")
                return value == true_value
            raise ProductionEvidenceError("unknown independent atom kind")
        if expression.op == "not":
            return not evaluate(expression.arguments[0])
        if expression.op == "and":
            return all(evaluate(child) for child in expression.arguments)
        if expression.op == "or":
            return any(evaluate(child) for child in expression.arguments)
        if expression.op == "iff":
            values = [evaluate(child) for child in expression.arguments]
            return not values or all(value == values[0] for value in values[1:])
        if expression.op == "ite":
            condition, then_expr, else_expr = expression.arguments
            return evaluate(then_expr if evaluate(condition) else else_expr)
        raise ProductionEvidenceError(f"unknown independent Boolean operator {expression.op!r}")

    for index, assertion in enumerate(problem.assertions, start=1):
        if not evaluate(assertion):
            raise ProductionEvidenceError(
                f"production model falsifies independently reconstructed assertion {index}"
            )
    return tuple(source_term_ids)


def _validate_source_atom_coverage(
    problem: EncodedProblem,
    source_term_ids: Sequence[int | None],
    model_atoms: Mapping[int, tuple[Any, ...]],
) -> None:
    expected: set[tuple[Any, ...]] = set()
    for atom in problem.atoms:
        if atom.kind == "auxiliary":
            continue
        if atom.kind == "equality":
            assert atom.left is not None and atom.right is not None
            left = source_term_ids[atom.left]
            right = source_term_ids[atom.right]
            if left is None or right is None:
                raise ProductionEvidenceError(
                    "independent source equality lacks production term identity"
                )
            expected.add(("equality", *sorted((left, right))))
        elif atom.kind == "bool_term":
            assert atom.term is not None
            term = source_term_ids[atom.term]
            if term is None:
                raise ProductionEvidenceError(
                    "independent source Boolean atom lacks production term identity"
                )
            expected.add(("bool_term", term))
        else:
            raise ProductionEvidenceError(
                f"independent source atom has unknown kind {atom.kind!r}"
            )
    actual = set(model_atoms.values())
    missing = sorted(expected - actual)
    if missing:
        raise ProductionEvidenceError(
            f"independently reconstructed atom coverage is incomplete: missing={missing!r}"
        )


def _validate_build(value: object, expected_hash: object) -> str:
    build = _exact(
        value,
        {
            "features",
            "target",
            "profile",
            "rustc",
            "cargo",
            "source_manifest_sha256",
            "sealed_source_manifest_sha256",
            "execution_closure_sha256",
        },
        "solver.build",
    )
    features = build["features"]
    if (
        type(features) is not list
        or any(type(feature) is not str or not feature for feature in features)
        or features != sorted(set(features))
    ):
        raise ProductionEvidenceError("solver.build.features must be sorted unique strings")
    for field in ("target", "profile", "rustc", "cargo"):
        _string(build[field], f"solver.build.{field}")
    _hash(build["source_manifest_sha256"], "solver.build.source_manifest_sha256")
    _hash(
        build["sealed_source_manifest_sha256"],
        "solver.build.sealed_source_manifest_sha256",
    )
    _hash(
        build["execution_closure_sha256"],
        "solver.build.execution_closure_sha256",
    )
    actual = hashlib.sha256(canonical_bytes(build)).hexdigest()
    if _hash(expected_hash, "solver.build_sha256") != actual:
        raise ProductionEvidenceError("solver build manifest SHA-256 mismatch")
    return actual


def _validate_sealed_build_receipt(
    value: object,
    *,
    expected_receipt_sha256: str | None,
    executable_sha256: str,
    revision: str,
    dirty: bool,
    diagnostic_build: Mapping[str, Any],
) -> str:
    binding = _exact(value, {"receipt", "receipt_sha256"}, "solver.sealed_build")
    receipt = _exact(
        binding["receipt"],
        {
            "artifacts",
            "build",
            "independent_attestation",
            "schema",
            "sealed_build_manifest_sha256",
            "source",
            "status",
        },
        "solver.sealed_build.receipt",
    )
    actual_receipt_sha256 = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    receipt_sha256 = _hash(
        binding["receipt_sha256"], "solver.sealed_build.receipt_sha256"
    )
    if receipt_sha256 != actual_receipt_sha256:
        raise ProductionEvidenceError("sealed build receipt SHA-256 mismatch")
    if expected_receipt_sha256 is None:
        raise ProductionEvidenceError(
            "externally bound sealed build receipt SHA-256 is required"
        )
    if _hash(expected_receipt_sha256, "expected sealed build receipt SHA-256") != receipt_sha256:
        raise ProductionEvidenceError("external sealed build receipt binding differs")
    if (
        receipt["schema"] != SEALED_BUILD_RECEIPT_SCHEMA
        or receipt["status"] != "accepted"
    ):
        raise ProductionEvidenceError("sealed build receipt schema/status differs")

    source = _exact(
        receipt["source"],
        {"dirty", "revision", "snapshot_manifest_sha256", "tree"},
        "solver.sealed_build.receipt.source",
    )
    if type(source["dirty"]) is not bool or source["dirty"]:
        raise ProductionEvidenceError("sealed build receipt source must be clean")
    if source["revision"] != revision or source["dirty"] != dirty:
        raise ProductionEvidenceError("sealed build receipt source identity differs")
    if not isinstance(source["revision"], str) or not re.fullmatch(
        r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["revision"]
    ):
        raise ProductionEvidenceError("sealed build receipt revision is malformed")
    if not isinstance(source["tree"], str) or not re.fullmatch(
        r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["tree"]
    ):
        raise ProductionEvidenceError("sealed build receipt tree is malformed")
    _hash(
        source["snapshot_manifest_sha256"],
        "solver.sealed_build.receipt.source.snapshot_manifest_sha256",
    )
    _hash(
        receipt["sealed_build_manifest_sha256"],
        "solver.sealed_build.receipt.sealed_build_manifest_sha256",
    )

    build = _exact(
        receipt["build"],
        {"execution_closure_sha256", "features", "profile", "target", "toolchain"},
        "solver.sealed_build.receipt.build",
    )
    features = build["features"]
    if (
        type(features) is not list
        or features != sorted(set(features))
        or any(type(feature) is not str or not feature for feature in features)
        or "production-evidence" not in features
    ):
        raise ProductionEvidenceError("sealed build receipt features are invalid")
    if build["profile"] != "release" or "linux" not in _string(
        build["target"], "solver.sealed_build.receipt.build.target"
    ):
        raise ProductionEvidenceError("sealed build receipt is not a Linux release")
    toolchain = build["toolchain"]
    if (
        type(toolchain) is not dict
        or set(toolchain) != {"cargo", "rustc"}
        or any(type(key) is not str or type(item) is not str or not item for key, item in toolchain.items())
    ):
        raise ProductionEvidenceError("sealed build receipt toolchain is incomplete")
    _hash(
        build["execution_closure_sha256"],
        "solver.sealed_build.receipt.build.execution_closure_sha256",
    )
    if (
        build["features"] != diagnostic_build["features"]
        or build["target"] != diagnostic_build["target"]
        or build["profile"] != diagnostic_build["profile"]
        or build["execution_closure_sha256"]
        != diagnostic_build["execution_closure_sha256"]
        or source["snapshot_manifest_sha256"]
        != diagnostic_build["sealed_source_manifest_sha256"]
    ):
        raise ProductionEvidenceError(
            "external sealed build receipt disagrees with diagnostic build fields"
        )

    artifacts = receipt["artifacts"]
    if type(artifacts) is not dict or set(artifacts) != {
        "euf-viper",
        "euf-viper-build-features",
    }:
        raise ProductionEvidenceError("sealed build receipt artifact set differs")
    for name, raw_record in artifacts.items():
        record = _exact(
            raw_record,
            {"bytes", "mode", "sha256"},
            f"solver.sealed_build.receipt.artifacts.{name}",
        )
        if _integer(record["bytes"], f"sealed artifact {name}.bytes") <= 0:
            raise ProductionEvidenceError("sealed build receipt artifact is empty")
        if record["mode"] != "0500":
            raise ProductionEvidenceError("sealed build receipt artifact mode differs")
        _hash(record["sha256"], f"sealed artifact {name}.sha256")
    if artifacts["euf-viper"]["sha256"] != executable_sha256:
        raise ProductionEvidenceError("sealed build receipt executable hash differs")
    attestation = _exact(
        receipt["independent_attestation"],
        {
            "artifacts",
            "attestor_sha256",
            "build_inputs",
            "build_manifest_sha256",
            "closure_sha256",
            "features",
            "schema",
            "source",
            "status",
            "toolchain",
            "traces",
        },
        "solver.sealed_build.receipt.independent_attestation",
    )
    if (
        attestation["schema"] != SEALED_BUILD_ATTESTATION_SCHEMA
        or attestation["status"] != "accepted"
        or attestation["artifacts"] != artifacts
        or attestation["features"] != features
        or attestation["toolchain"] != toolchain
        or attestation["closure_sha256"] != build["execution_closure_sha256"]
        or attestation["build_manifest_sha256"]
        != receipt["sealed_build_manifest_sha256"]
    ):
        raise ProductionEvidenceError("independent sealed build attestation differs")
    _hash(attestation["attestor_sha256"], "sealed build attestor SHA-256")
    attested_source = _exact(
        attestation["source"],
        {"bundle_sha256", "file_count", "manifest_sha256", "revision", "tree"},
        "sealed build attestation source",
    )
    if (
        attested_source["revision"] != source["revision"]
        or attested_source["tree"] != source["tree"]
        or attested_source["manifest_sha256"]
        != source["snapshot_manifest_sha256"]
        or _integer(attested_source["file_count"], "attested source file count") < 1
    ):
        raise ProductionEvidenceError("attested source reconstruction differs")
    _hash(attested_source["bundle_sha256"], "attested source bundle SHA-256")
    build_inputs = _exact(
        attestation["build_inputs"],
        {
            "archive_sha256",
            "cargo_sha256",
            "file_count",
            "index_sha256",
            "object_count",
            "rustc_sha256",
        },
        "sealed build attestation inputs",
    )
    for field in ("archive_sha256", "cargo_sha256", "index_sha256", "rustc_sha256"):
        _hash(build_inputs[field], f"attested build input {field}")
    if (
        _integer(build_inputs["file_count"], "attested build input file count") < 1
        or _integer(build_inputs["object_count"], "attested build input object count") < 1
    ):
        raise ProductionEvidenceError("attested build input closure is empty")
    traces = _exact(
        attestation["traces"],
        {
            "canonical_sha256",
            "discovery_raw_sha256",
            "network",
            "production_raw_sha256",
            "randomness_events",
            "time_events",
        },
        "sealed build attestation traces",
    )
    for field in ("canonical_sha256", "discovery_raw_sha256", "production_raw_sha256"):
        _hash(traces[field], f"attested build trace {field}")
    if (
        traces["network"] != "denied-and-namespaced"
        or _integer(traces["randomness_events"], "attested randomness event count") < 0
        or _integer(traces["time_events"], "attested time event count") < 0
    ):
        raise ProductionEvidenceError("attested build input channels differ")
    return receipt_sha256


def validate_production_evidence(
    evidence_path: Path,
    source_path: Path,
    *,
    expected_source_sha256: str | None = None,
    expected_revision: str | None = None,
    expected_status: str | None = None,
    expected_executable_sha256: str | None = None,
    expected_runtime_config: Mapping[str, str] | None = None,
    expected_evidence_sha256: str | None = None,
    expected_run_nonce: str | None = None,
    expected_sealed_build_receipt_sha256: str | None = None,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    evidence_path, evidence_bytes = _read_regular_nofollow(evidence_path, "evidence")
    source_path, source_bytes = _read_regular_nofollow(source_path, "source")
    evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()
    if expected_evidence_sha256 is not None and evidence_hash != expected_evidence_sha256:
        raise ProductionEvidenceError("bound evidence SHA-256 mismatch")
    payload = _exact(
        _read_json_bytes(evidence_bytes, f"evidence {evidence_path}"),
        {
            "schema",
            "run_nonce",
            "status",
            "backend_status",
            "source",
            "solver",
            "backend_cnf",
            "model",
            "limitations",
        },
        "evidence",
    )
    if payload["schema"] != SCHEMA:
        raise ProductionEvidenceError(f"unsupported evidence schema {payload['schema']!r}")
    run_nonce = _hash(payload["run_nonce"], "run_nonce")
    if expected_run_nonce is not None and run_nonce != expected_run_nonce:
        raise ProductionEvidenceError("production evidence run nonce mismatch")
    status = payload["status"]
    if status not in {"sat", "unsupported"}:
        raise ProductionEvidenceError(f"invalid evidence status {status!r}")
    if expected_status is not None and status != expected_status:
        raise ProductionEvidenceError(
            f"evidence status mismatch: expected {expected_status!r}, got {status!r}"
        )
    backend_status = payload["backend_status"]
    if (status, backend_status) not in {
        ("sat", "sat"),
        ("unsupported", "sat"),
        ("unsupported", "unsat"),
        ("unsupported", "unsupported"),
    }:
        raise ProductionEvidenceError(
            f"incoherent evidence status/backend_status pair {(status, backend_status)!r}"
        )

    source = _exact(payload["source"], {"path", "sha256", "bytes"}, "source")
    _string(source["path"], "source.path")
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    if _hash(source["sha256"], "source.sha256") != source_hash:
        raise ProductionEvidenceError("evidence source SHA-256 mismatch")
    if expected_source_sha256 is not None and source_hash != expected_source_sha256:
        raise ProductionEvidenceError("locked source SHA-256 mismatch")
    if _integer(source["bytes"], "source.bytes") != len(source_bytes):
        raise ProductionEvidenceError("evidence source byte count mismatch")

    solver = _exact(
        payload["solver"],
        {
            "package_version",
            "revision",
            "dirty",
            "executable_sha256",
            "backend",
            "config",
            "config_sha256",
            "build",
            "build_sha256",
            "sealed_build",
        },
        "solver",
    )
    _string(solver["package_version"], "solver.package_version")
    revision = _string(solver["revision"], "solver.revision")
    if expected_revision is not None and revision != expected_revision:
        raise ProductionEvidenceError(
            f"solver revision mismatch: expected {expected_revision}, got {revision}"
        )
    if type(solver["dirty"]) is not bool:
        raise ProductionEvidenceError("solver.dirty must be boolean")
    executable_sha256 = _hash(
        solver["executable_sha256"], "solver.executable_sha256"
    )
    if status == "sat":
        if solver["dirty"] and not allow_dirty:
            raise ProductionEvidenceError(
                "decisive evidence was emitted by a dirty build"
            )
        if expected_executable_sha256 is None:
            raise ProductionEvidenceError(
                "trusted executable SHA-256 is required for decisive evidence"
            )
        if executable_sha256 != expected_executable_sha256:
            raise ProductionEvidenceError("trusted executable SHA-256 mismatch")
    _string(solver["backend"], "solver.backend")
    config = solver["config"]
    if type(config) is not dict or any(
        type(key) is not str or type(value) is not str
        for key, value in config.items()
    ):
        raise ProductionEvidenceError("solver.config must map strings to strings")
    expected_config_hash = hashlib.sha256(canonical_bytes(config)).hexdigest()
    if _hash(solver["config_sha256"], "solver.config_sha256") != expected_config_hash:
        raise ProductionEvidenceError("solver config SHA-256 mismatch")
    if expected_runtime_config is not None and dict(config) != dict(expected_runtime_config):
        raise ProductionEvidenceError("solver runtime config differs from lock-derived config")
    required_resolved = {
        "resolved.production_evidence_contract": CONTRACT,
        "resolved.production_evidence_mode": "cnf-assignment-transcript",
        "resolved.eq_abstraction": "off",
        "resolved.finite_domain": "off",
        "resolved.full_ackermann": "off",
        "resolved.chordal_transitivity": "off",
        "resolved.refinement_mode": "model-cuts",
    }
    for key, expected in required_resolved.items():
        if config.get(key) != expected:
            raise ProductionEvidenceError(
                f"solver config does not bind {key}={expected!r}"
            )
    for key in ("resolved.direct_root_cnf", "resolved.direct_negated_root"):
        if config.get(key) not in {"0", "1"}:
            raise ProductionEvidenceError(f"solver config has invalid {key}")
    build_hash = _validate_build(solver["build"], solver["build_sha256"])
    runtime_receipt_sha256 = config.get(SEALED_BUILD_RECEIPT_SHA256_ENV)
    if expected_runtime_config is not None:
        expected_from_runtime = expected_runtime_config.get(
            SEALED_BUILD_RECEIPT_SHA256_ENV
        )
        if expected_from_runtime is None:
            raise ProductionEvidenceError(
                "locked runtime config lacks the sealed build receipt digest"
            )
        if (
            expected_sealed_build_receipt_sha256 is not None
            and expected_sealed_build_receipt_sha256 != expected_from_runtime
        ):
            raise ProductionEvidenceError(
                "sealed build receipt bindings disagree across trust boundaries"
            )
        expected_sealed_build_receipt_sha256 = expected_from_runtime
    if runtime_receipt_sha256 != expected_sealed_build_receipt_sha256:
        raise ProductionEvidenceError(
            "solver runtime config does not bind the expected sealed build receipt"
        )
    sealed_build_receipt_sha256 = _validate_sealed_build_receipt(
        solver["sealed_build"],
        expected_receipt_sha256=expected_sealed_build_receipt_sha256,
        executable_sha256=executable_sha256,
        revision=revision,
        dirty=solver["dirty"],
        diagnostic_build=solver["build"],
    )

    limitations = payload["limitations"]
    if isinstance(limitations, (str, bytes)) or not isinstance(limitations, Sequence) or any(
        type(item) is not str or not item for item in limitations
    ):
        raise ProductionEvidenceError("limitations must be a list of nonempty strings")

    if status == "unsupported":
        if payload["backend_cnf"] is not None or payload["model"] is not None or not limitations:
            raise ProductionEvidenceError(
                "unsupported evidence must omit model and state a limitation"
            )
        return {
            "schema": SCHEMA,
            "status": status,
            "backend_status": backend_status,
            "run_nonce": run_nonce,
            "evidence_sha256": evidence_hash,
            "evidence_bytes": len(evidence_bytes),
            "source_sha256": source_hash,
            "solver_revision": revision,
            "solver_executable_sha256": executable_sha256,
            "solver_config_sha256": solver["config_sha256"],
            "solver_build_sha256": build_hash,
            "sealed_build_receipt_sha256": sealed_build_receipt_sha256,
        }
    if backend_status != "sat" or limitations:
        raise ProductionEvidenceError("SAT evidence has inconsistent status or limitations")
    backend = _string(solver["backend"], "solver.backend")
    if backend == "congruence-closure":
        raise ProductionEvidenceError(
            "congruence-closure SAT is unsupported by the independent contract"
        )
    model = _exact(
        payload["model"],
        {"assignment", "assignment_sha256", "terms", "atoms", "true_term", "false_term"},
        "model",
    )
    assignment = _validate_assignment(model)
    terms = _validate_terms(model)
    model_atoms = _validate_atoms(model, terms, assignment)
    try:
        source_text = source_bytes.decode("utf-8")
        problem = parse_and_encode_production(
            source_text,
            direct_root_cnf=config["resolved.direct_root_cnf"] == "1",
            direct_negated_root=config["resolved.direct_negated_root"] == "1",
        )
    except (UnicodeError, IndependentQfufError) as error:
        raise ProductionEvidenceError(
            f"independent source reconstruction failed: {error}"
        ) from error
    source_term_ids = _evaluate_source_model(problem, terms, model)
    mapped_term_ids = {term for term in source_term_ids if term is not None}
    if mapped_term_ids != set(range(len(terms))):
        raise ProductionEvidenceError(
            "production term namespace differs from exact source reconstruction"
        )
    model_assignment = _assignment_literals(
        model["assignment"], problem.variable_count, "model.assignment"
    )
    var_count, initial_clause_count, final_clause_count = _validate_backend_cnf(
        payload["backend_cnf"],
        problem,
        source_term_ids,
        model_assignment,
        model_atoms,
        backend,
        config,
    )
    return {
        "schema": SCHEMA,
        "status": "sat",
        "backend_status": "sat",
        "run_nonce": run_nonce,
        "evidence_sha256": evidence_hash,
        "evidence_bytes": len(evidence_bytes),
        "source_sha256": source_hash,
        "solver_revision": revision,
        "solver_executable_sha256": executable_sha256,
        "solver_config_sha256": solver["config_sha256"],
        "solver_build_sha256": build_hash,
        "sealed_build_receipt_sha256": sealed_build_receipt_sha256,
        "terms": len(terms),
        "atoms": len(model["atoms"]),
        "assignment_variables": var_count,
        "initial_backend_clauses": initial_clause_count,
        "backend_clauses": final_clause_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--source-sha256")
    parser.add_argument("--revision")
    parser.add_argument("--status", choices=("sat", "unsupported"))
    parser.add_argument("--executable-sha256")
    parser.add_argument("--evidence-sha256")
    parser.add_argument("--run-nonce")
    parser.add_argument("--sealed-build-receipt-sha256")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    try:
        result = validate_production_evidence(
            args.evidence,
            args.source,
            expected_source_sha256=args.source_sha256,
            expected_revision=args.revision,
            expected_status=args.status,
            expected_executable_sha256=args.executable_sha256,
            expected_evidence_sha256=args.evidence_sha256,
            expected_run_nonce=args.run_nonce,
            expected_sealed_build_receipt_sha256=args.sealed_build_receipt_sha256,
            allow_dirty=args.allow_dirty,
        )
    except (OSError, ProductionEvidenceError) as error:
        raise SystemExit(f"production evidence rejected: {error}") from error
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
