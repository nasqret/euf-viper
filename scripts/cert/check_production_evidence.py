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
    parse_and_encode,
)


SCHEMA: Final = "euf-viper.production-evidence.v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
INDEPENDENT_INTERNAL = re.compile(r"@independent_(.+)_[0-9]+\Z")


class ProductionEvidenceError(Exception):
    """Raised when a production sidecar is missing, malformed, or unsound."""


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProductionEvidenceError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProductionEvidenceError(f"cannot read evidence {path}: {error}") from error
    if type(value) is not dict:
        raise ProductionEvidenceError("evidence root must be an object")
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
) -> None:
    atoms = model["atoms"]
    if isinstance(atoms, (str, bytes)) or not isinstance(atoms, Sequence):
        raise ProductionEvidenceError("model.atoms must be a list")
    variables: set[int] = set()
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
        elif kind == "bool_term":
            atom = _exact(raw, {"kind", "variable", "term", "value"}, f"atom {index}")
            term = _integer(atom["term"], f"atom {index}.term")
            if not term < len(terms) or true_value is None or false_value is None:
                raise ProductionEvidenceError(f"atom {index} has invalid Boolean term metadata")
            term_value = _value(terms[term])
            if term_value not in {true_value, false_value}:
                raise ProductionEvidenceError(f"atom {index} Boolean term has a third value")
            expected_value = term_value == true_value
        else:
            raise ProductionEvidenceError(f"atom {index} has unknown kind {kind!r}")
        variable = _integer(atom["variable"], f"atom {index}.variable", 1)
        if variable in variables:
            raise ProductionEvidenceError(f"duplicate atom variable {variable}")
        variables.add(variable)
        if type(atom["value"]) is not bool or atom["value"] != expected_value:
            raise ProductionEvidenceError(f"atom {index} disagrees with the production model")
        if assignment is not None:
            if variable >= len(assignment) or assignment[variable] != atom["value"]:
                raise ProductionEvidenceError(f"atom {index} disagrees with the SAT assignment")


def _evaluate_source_model(
    problem: EncodedProblem, terms: Sequence[Mapping[str, Any]], model: Mapping[str, Any]
) -> None:
    interpretations: dict[
        tuple[str, str, tuple[tuple[str, int], ...]], tuple[str, int]
    ] = {}
    internal_by_kind: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for term in terms:
        value = _value(term)
        if term["internal"]:
            internal_by_kind[str(term["internal_kind"])].append(value)
            continue
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
    internal_positions: dict[str, int] = defaultdict(int)
    for source_term in problem.terms:
        function = problem.functions[source_term.function]
        sort_name = problem.sorts[source_term.sort].name
        if source_term.id == problem.true_term:
            value = true_value
        elif source_term.id == problem.false_term:
            value = false_value
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
            value = candidates[position]
        else:
            args = tuple(source_values[argument] for argument in source_term.args)
            key = (sort_name, function.name, args)
            try:
                value = interpretations[key]
            except KeyError as error:
                raise ProductionEvidenceError(
                    f"production model lacks source term {function.name!r}{args!r}"
                ) from error
        if value[0] != sort_name:
            raise ProductionEvidenceError(
                f"source term {source_term.id} has value of sort {value[0]!r}, "
                f"expected {sort_name!r}"
            )
        source_values.append(value)

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


def validate_production_evidence(
    evidence_path: Path,
    source_path: Path,
    *,
    expected_source_sha256: str | None = None,
    expected_revision: str | None = None,
    expected_status: str | None = None,
) -> dict[str, Any]:
    evidence_path = evidence_path.expanduser().resolve(strict=True)
    source_path = source_path.expanduser().resolve(strict=True)
    payload = _exact(
        _read_json(evidence_path),
        {"schema", "status", "backend_status", "source", "solver", "model", "limitations"},
        "evidence",
    )
    if payload["schema"] != SCHEMA:
        raise ProductionEvidenceError(f"unsupported evidence schema {payload['schema']!r}")
    status = payload["status"]
    if status not in {"sat", "unsupported"}:
        raise ProductionEvidenceError(f"invalid evidence status {status!r}")
    if expected_status is not None and status != expected_status:
        raise ProductionEvidenceError(
            f"evidence status mismatch: expected {expected_status!r}, got {status!r}"
        )
    backend_status = payload["backend_status"]
    if backend_status not in {"sat", "unsat", "unsupported"}:
        raise ProductionEvidenceError(f"invalid backend_status {backend_status!r}")

    source = _exact(payload["source"], {"path", "sha256", "bytes"}, "source")
    _string(source["path"], "source.path")
    source_hash = sha256_file(source_path)
    if _hash(source["sha256"], "source.sha256") != source_hash:
        raise ProductionEvidenceError("evidence source SHA-256 mismatch")
    if expected_source_sha256 is not None and source_hash != expected_source_sha256:
        raise ProductionEvidenceError("locked source SHA-256 mismatch")
    if _integer(source["bytes"], "source.bytes") != source_path.stat().st_size:
        raise ProductionEvidenceError("evidence source byte count mismatch")

    solver = _exact(
        payload["solver"],
        {"package_version", "revision", "dirty", "backend", "config", "config_sha256"},
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

    limitations = payload["limitations"]
    if isinstance(limitations, (str, bytes)) or not isinstance(limitations, Sequence) or any(
        type(item) is not str or not item for item in limitations
    ):
        raise ProductionEvidenceError("limitations must be a list of nonempty strings")

    if status == "unsupported":
        if payload["model"] is not None or not limitations:
            raise ProductionEvidenceError(
                "unsupported evidence must omit model and state a limitation"
            )
        return {
            "schema": SCHEMA,
            "status": status,
            "backend_status": backend_status,
            "source_sha256": source_hash,
            "solver_revision": revision,
            "solver_config_sha256": solver["config_sha256"],
        }
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
    _validate_atoms(model, terms, assignment)
    try:
        problem = parse_and_encode(source_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, IndependentQfufError) as error:
        raise ProductionEvidenceError(
            f"independent source reconstruction failed: {error}"
        ) from error
    _evaluate_source_model(problem, terms, model)
    return {
        "schema": SCHEMA,
        "status": "sat",
        "backend_status": "sat",
        "source_sha256": source_hash,
        "solver_revision": revision,
        "solver_config_sha256": solver["config_sha256"],
        "terms": len(terms),
        "atoms": len(model["atoms"]),
        "assignment_variables": 0 if assignment is None else len(assignment) - 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--source-sha256")
    parser.add_argument("--revision")
    parser.add_argument("--status", choices=("sat", "unsupported"))
    args = parser.parse_args()
    try:
        result = validate_production_evidence(
            args.evidence,
            args.source,
            expected_source_sha256=args.source_sha256,
            expected_revision=args.revision,
            expected_status=args.status,
        )
    except (OSError, ProductionEvidenceError) as error:
        raise SystemExit(f"production evidence rejected: {error}") from error
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
