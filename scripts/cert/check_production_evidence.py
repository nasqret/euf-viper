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
import stat
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
    parse_and_encode,
)


SCHEMA: Final = "euf-viper.production-evidence.v2"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
INDEPENDENT_INTERNAL = re.compile(r"@independent_(.+)_[0-9]+\Z")


class ProductionEvidenceError(Exception):
    """Raised when a production sidecar is missing, malformed, or unsound."""


def canonical_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ProductionEvidenceError(f"value is not canonical JSON: {error}") from error
    return (rendered + "\n").encode("utf-8")


def _read_regular_nofollow(path: Path, context: str) -> tuple[Path, bytes]:
    absolute = Path(os.path.abspath(path.expanduser()))
    if not hasattr(os, "O_NOFOLLOW"):
        raise ProductionEvidenceError("O_NOFOLLOW is required for production evidence")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ProductionEvidenceError(
            f"cannot open {context} {absolute} without following links: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProductionEvidenceError(f"{context} is not a regular file: {absolute}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
    except OSError as error:
        raise ProductionEvidenceError(f"cannot read {context} {absolute}: {error}") from error
    finally:
        os.close(descriptor)
    try:
        path_after = os.stat(absolute, follow_symlinks=False)
    except OSError as error:
        raise ProductionEvidenceError(f"{context} path changed while it was read: {error}") from error
    fingerprint_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    fingerprint_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    content = b"".join(chunks)
    if fingerprint_before != fingerprint_after or len(content) != after.st_size:
        raise ProductionEvidenceError(f"{context} changed while it was read")
    if (
        not stat.S_ISREG(path_after.st_mode)
        or path_after.st_dev != after.st_dev
        or path_after.st_ino != after.st_ino
    ):
        raise ProductionEvidenceError(f"{context} path was replaced while it was read")
    return absolute, content


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
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProductionEvidenceError(f"non-finite JSON number {value!r}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
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


def _validate_assignment(model: Mapping[str, Any]) -> tuple[bool, ...] | None:
    assignment = model["assignment"]
    assignment_hash = model["assignment_sha256"]
    if assignment is None:
        if assignment_hash is not None:
            raise ProductionEvidenceError("null assignment must have null assignment hash")
        return None
    if isinstance(assignment, (str, bytes)) or not isinstance(assignment, Sequence):
        raise ProductionEvidenceError("model.assignment must be a literal list or null")
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


def _validate_backend_cnf(
    raw_cnf: object,
    terms: Sequence[Mapping[str, Any]],
    assignment: tuple[bool, ...],
    model_atoms: Mapping[int, tuple[Any, ...]],
) -> tuple[int, int]:
    cnf = _exact(
        raw_cnf,
        {"format", "var_count", "clause_count", "clauses_sha256", "variables", "clauses"},
        "backend_cnf",
    )
    if cnf["format"] != "dimacs-literal-arrays":
        raise ProductionEvidenceError("backend_cnf.format is unsupported")
    var_count = _integer(cnf["var_count"], "backend_cnf.var_count", 1)
    if var_count != len(assignment) - 1:
        raise ProductionEvidenceError("backend CNF var_count differs from the assignment")

    raw_variables = cnf["variables"]
    if type(raw_variables) is not list or len(raw_variables) != var_count:
        raise ProductionEvidenceError(
            "backend_cnf.variables must map every variable exactly once"
        )
    mapped_atoms: dict[int, tuple[Any, ...]] = {}
    for offset, raw in enumerate(raw_variables, start=1):
        if type(raw) is not dict:
            raise ProductionEvidenceError(f"backend variable {offset} must be an object")
        kind = raw.get("kind")
        if kind == "auxiliary":
            variable = _exact(raw, {"kind", "variable"}, f"backend variable {offset}")
            atom_key = None
        elif kind == "equality":
            variable = _exact(
                raw,
                {"kind", "variable", "left", "right"},
                f"backend variable {offset}",
            )
            left = _integer(variable["left"], f"backend variable {offset}.left")
            right = _integer(variable["right"], f"backend variable {offset}.right")
            if not left < len(terms) or not right < len(terms):
                raise ProductionEvidenceError(
                    f"backend variable {offset} references an invalid term"
                )
            atom_key = ("equality", left, right)
        elif kind == "bool_term":
            variable = _exact(
                raw,
                {"kind", "variable", "term"},
                f"backend variable {offset}",
            )
            term = _integer(variable["term"], f"backend variable {offset}.term")
            if not term < len(terms) or terms[term]["sort"] != "Bool":
                raise ProductionEvidenceError(
                    f"backend variable {offset} references an invalid Boolean term"
                )
            atom_key = ("bool_term", term)
        else:
            raise ProductionEvidenceError(
                f"backend variable {offset} has unknown kind {kind!r}"
            )
        if _integer(variable["variable"], f"backend variable {offset}.variable", 1) != offset:
            raise ProductionEvidenceError("backend variable IDs must be contiguous and ordered")
        if atom_key is not None:
            mapped_atoms[offset] = atom_key
    if mapped_atoms != dict(model_atoms):
        missing = sorted(set(mapped_atoms) - set(model_atoms))
        extra = sorted(set(model_atoms) - set(mapped_atoms))
        mismatched = sorted(
            variable
            for variable in set(mapped_atoms) & set(model_atoms)
            if mapped_atoms[variable] != model_atoms[variable]
        )
        raise ProductionEvidenceError(
            "backend/model atom coverage differs: "
            f"missing={missing!r}, extra={extra!r}, mismatched={mismatched!r}"
        )

    clauses = cnf["clauses"]
    if type(clauses) is not list:
        raise ProductionEvidenceError("backend_cnf.clauses must be a list")
    clause_count = _integer(cnf["clause_count"], "backend_cnf.clause_count")
    if clause_count != len(clauses):
        raise ProductionEvidenceError("backend CNF clause count mismatch")
    expected_hash = hashlib.sha256(canonical_bytes(clauses)).hexdigest()
    if _hash(cnf["clauses_sha256"], "backend_cnf.clauses_sha256") != expected_hash:
        raise ProductionEvidenceError("backend CNF clause SHA-256 mismatch")
    for index, clause in enumerate(clauses):
        if type(clause) is not list:
            raise ProductionEvidenceError(f"backend clause {index} must be a list")
        satisfied = False
        for literal in clause:
            if type(literal) is not int or literal == 0 or abs(literal) > var_count:
                raise ProductionEvidenceError(
                    f"backend clause {index} has an invalid DIMACS literal"
                )
            value = assignment[abs(literal)]
            if value == (literal > 0):
                satisfied = True
        if not satisfied:
            raise ProductionEvidenceError(
                f"SAT assignment falsifies backend clause {index}"
            )
    return var_count, clause_count


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
        {"features", "target", "profile", "rustc", "cargo", "source_manifest_sha256"},
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
    actual = hashlib.sha256(canonical_bytes(build)).hexdigest()
    if _hash(expected_hash, "solver.build_sha256") != actual:
        raise ProductionEvidenceError("solver build manifest SHA-256 mismatch")
    return actual


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
    build_hash = _validate_build(solver["build"], solver["build_sha256"])

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
        }
    if solver["dirty"] and not allow_dirty:
        raise ProductionEvidenceError("decisive evidence was emitted by a dirty build")
    if expected_executable_sha256 is None:
        raise ProductionEvidenceError("trusted executable SHA-256 is required for decisive evidence")
    if executable_sha256 != expected_executable_sha256:
        raise ProductionEvidenceError("trusted executable SHA-256 mismatch")
    if backend_status != "sat" or limitations:
        raise ProductionEvidenceError("SAT evidence has inconsistent status or limitations")
    model = _exact(
        payload["model"],
        {"origin", "assignment", "assignment_sha256", "terms", "atoms", "true_term", "false_term"},
        "model",
    )
    if model["origin"] not in {"cnf_assignment", "congruence_closure"}:
        raise ProductionEvidenceError(f"unknown model origin {model['origin']!r}")
    assignment = _validate_assignment(model)
    if model["origin"] == "cnf_assignment" and assignment is None:
        raise ProductionEvidenceError("CNF assignment evidence lacks an assignment")
    if model["origin"] == "congruence_closure" and assignment is not None:
        raise ProductionEvidenceError("closure evidence unexpectedly carries a CNF assignment")
    terms = _validate_terms(model)
    model_atoms = _validate_atoms(model, terms, assignment)
    if model["origin"] == "cnf_assignment":
        assert assignment is not None
        var_count, clause_count = _validate_backend_cnf(
            payload["backend_cnf"], terms, assignment, model_atoms
        )
    else:
        if payload["backend_cnf"] is not None or model_atoms:
            raise ProductionEvidenceError(
                "congruence-closure evidence cannot carry backend CNF variables"
            )
        var_count = 0
        clause_count = 0
    try:
        source_text = source_bytes.decode("utf-8")
        problem = parse_and_encode(source_text)
    except (UnicodeError, IndependentQfufError) as error:
        raise ProductionEvidenceError(
            f"independent source reconstruction failed: {error}"
        ) from error
    source_term_ids = _evaluate_source_model(problem, terms, model)
    if model["origin"] == "cnf_assignment":
        _validate_source_atom_coverage(problem, source_term_ids, model_atoms)
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
        "terms": len(terms),
        "atoms": len(model["atoms"]),
        "assignment_variables": var_count,
        "backend_clauses": clause_count,
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
            allow_dirty=args.allow_dirty,
        )
    except (OSError, ProductionEvidenceError) as error:
        raise SystemExit(f"production evidence rejected: {error}") from error
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
