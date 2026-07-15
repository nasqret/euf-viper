#!/usr/bin/env python3
"""Check a DRAT proof and replay every EUF clause in a certificate manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from independent_qfuf import (
    IndependentQfufError,
    V2_FORMAT,
    parse_and_encode,
    parse_dimacs as parse_dimacs_independent,
    validate_v2_sat_manifest,
    validate_v2_unsat_manifest,
)


class UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> bool:
        left = self.find(left)
        right = self.find(right)
        if left == right:
            return False
        if self.rank[left] < self.rank[right]:
            left, right = right, left
        self.parent[right] = left
        if self.rank[left] == self.rank[right]:
            self.rank[left] += 1
        return True


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json_loads(text: str) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r}")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    return json.loads(
        text,
        parse_constant=reject_constant,
        object_pairs_hook=unique_object,
    )


def required_manifest_string(manifest: dict, field: str) -> str:
    value = manifest.get(field)
    if type(value) is not str or not value:
        raise SystemExit(
            f"certificate manifest field {field!r} must be a nonempty string"
        )
    return value


def artifact_path(value: str, manifest_path: Path, override: Path | None) -> Path:
    if override is not None:
        return override
    path = Path(value)
    if path.exists() or path.is_absolute():
        return path
    adjacent = manifest_path.parent / path.name
    return adjacent if adjacent.exists() else path


def parse_dimacs(path: Path) -> tuple[int, list[list[int]]]:
    variables = None
    expected_clauses = None
    clauses: list[list[int]] = []
    current: list[int] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="ascii").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("c"):
            continue
        if line.startswith("p"):
            if variables is not None:
                raise ValueError(f"{path}:{line_number}: duplicate DIMACS header")
            fields = line.split()
            if len(fields) != 4 or fields[:2] != ["p", "cnf"]:
                raise ValueError(f"{path}:{line_number}: malformed DIMACS header")
            variables = int(fields[2])
            expected_clauses = int(fields[3])
            if variables < 0 or expected_clauses < 0:
                raise ValueError(f"{path}:{line_number}: negative DIMACS count")
            continue
        if variables is None:
            raise ValueError(f"{path}:{line_number}: clause precedes DIMACS header")
        for field in line.split():
            literal = int(field)
            if literal == 0:
                clauses.append(current)
                current = []
            else:
                if abs(literal) > variables:
                    raise ValueError(
                        f"{path}:{line_number}: literal {literal} exceeds variable count"
                    )
                current.append(literal)
    if variables is None or expected_clauses is None:
        raise ValueError(f"{path}: missing DIMACS header")
    if current:
        raise ValueError(f"{path}: unterminated final clause")
    if len(clauses) != expected_clauses:
        raise ValueError(
            f"{path}: parsed {len(clauses)} clauses, expected {expected_clauses}"
        )
    return variables, clauses


def close_congruence(terms: list[dict], union_find: UnionFind) -> None:
    while True:
        changed = False
        signatures: dict[tuple[int, tuple[int, ...]], int] = {}
        for term in terms:
            signature = (
                term["function"],
                tuple(union_find.find(argument) for argument in term["args"]),
            )
            previous = signatures.get(signature)
            if previous is None:
                signatures[signature] = term["id"]
            else:
                changed |= union_find.union(previous, term["id"])
        if not changed:
            return


def theory_clause_is_valid(
    clause: list[int],
    atoms: dict[int, dict],
    terms: list[dict],
    true_term: int,
    false_term: int,
) -> bool:
    union_find = UnionFind(len(terms))
    disequalities = [(true_term, false_term)]
    for literal in clause:
        atom = atoms[abs(literal)]
        kind = atom["kind"]
        if kind == "auxiliary":
            return False
        if kind == "equality":
            pair = (atom["left"], atom["right"])
            if literal < 0:
                union_find.union(*pair)
            else:
                disequalities.append(pair)
        elif kind == "bool_term":
            target = true_term if literal < 0 else false_term
            union_find.union(atom["term"], target)
        else:
            return False
    close_congruence(terms, union_find)
    return any(union_find.find(left) == union_find.find(right) for left, right in disequalities)


def validate_manifest(manifest: dict, variables: int, clauses: list[list[int]]) -> int:
    if manifest.get("format") != "euf-viper-euf-cnf-v1":
        raise ValueError("unsupported certificate manifest format")
    if manifest.get("result") != "unsat":
        raise ValueError("certificate manifest does not claim UNSAT")
    if manifest.get("finite_domain_axioms") != 0:
        raise ValueError("finite-domain axioms are not replayable in format v1")
    if manifest.get("variables") != variables:
        raise ValueError("manifest and DIMACS variable counts differ")

    terms = manifest["terms"]
    if [term.get("id") for term in terms] != list(range(len(terms))):
        raise ValueError("term IDs must be contiguous and ordered")
    for term in terms:
        if not isinstance(term.get("function"), int) or term["function"] < 0:
            raise ValueError(f"term {term['id']} has an invalid function ID")
        if any(
            not isinstance(arg, int) or not 0 <= arg < term["id"]
            for arg in term["args"]
        ):
            raise ValueError(f"term {term['id']} has an invalid argument")

    atom_entries = manifest["atoms"]
    atoms = {atom["variable"]: atom for atom in atom_entries}
    if len(atom_entries) != variables:
        raise ValueError("atom map contains a duplicate or extra entry")
    if sorted(atoms) != list(range(1, variables + 1)):
        raise ValueError("atom map must cover every DIMACS variable exactly once")
    for atom in atoms.values():
        kind = atom.get("kind")
        if kind == "equality":
            term_ids = [atom.get("left"), atom.get("right")]
        elif kind == "bool_term":
            term_ids = [atom.get("term")]
        elif kind == "auxiliary":
            term_ids = []
        else:
            raise ValueError(f"variable {atom['variable']} has an unknown atom kind")
        if any(not isinstance(term, int) or not 0 <= term < len(terms) for term in term_ids):
            raise ValueError(f"variable {atom['variable']} references an invalid term")

    true_term = manifest["true_term"]
    false_term = manifest["false_term"]
    if not 0 <= true_term < len(terms) or not 0 <= false_term < len(terms):
        raise ValueError("Boolean value term is out of range")
    if true_term == false_term:
        raise ValueError("true and false must use distinct terms")
    true_value = terms[true_term]
    false_value = terms[false_term]
    if true_value["args"] or false_value["args"]:
        raise ValueError("true and false must be zero-arity terms")
    if true_value["function"] == false_value["function"]:
        raise ValueError("true and false must use distinct function symbols")

    counts = manifest["clauses"]
    categories = ["base", "transitivity", "congruence", "theory_conflicts"]
    if any(not isinstance(counts.get(name), int) or counts[name] < 0 for name in categories):
        raise ValueError("manifest has an invalid clause category count")
    if counts.get("total") != len(clauses) or sum(counts[name] for name in categories) != len(
        clauses
    ):
        raise ValueError("manifest and DIMACS clause counts differ")

    base_count = counts["base"]
    for index, clause in enumerate(clauses[base_count:], start=base_count + 1):
        if not theory_clause_is_valid(clause, atoms, terms, true_term, false_term):
            raise ValueError(f"DIMACS clause {index} is not a valid EUF theory clause")
    return len(clauses) - base_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--dimacs", type=Path)
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--drat-trim", default=shutil.which("drat-trim"))
    args = parser.parse_args()

    try:
        manifest = strict_json_loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"cannot read certificate manifest: {error}") from error
    if type(manifest) is not dict or manifest.get("format") != V2_FORMAT:
        raise SystemExit(
            "independent checking requires euf-viper-euf-cnf-v2; "
            "legacy v1 trusts the solver-emitted base CNF"
        )
    if manifest.get("encoding") != "canonical-tseitin-v1":
        raise SystemExit("unsupported or missing independent encoding identifier")

    result = manifest.get("result")
    if result != "sat" and result != "unsat":
        raise SystemExit(f"certificate manifest has unsupported result {result!r}")

    source_value = required_manifest_string(manifest, "source")
    expected_source_hash = required_manifest_string(manifest, "source_sha256")
    sat_variables = None
    if result == "sat":
        sat_variables = manifest.get("variables")
        if type(sat_variables) is not int:
            raise SystemExit("SAT manifest variables must be an exact integer")
    else:
        dimacs_value = required_manifest_string(manifest, "dimacs")
        expected_dimacs_hash = required_manifest_string(manifest, "dimacs_sha256")
        proof_value = required_manifest_string(manifest, "proof")
        expected_proof_hash = required_manifest_string(manifest, "proof_sha256")

    try:
        source = artifact_path(source_value, args.manifest, args.source)
        actual_source_hash = sha256(source)
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(f"cannot read source artifact: {error}") from error
    if actual_source_hash != expected_source_hash:
        raise SystemExit(
            "source SHA-256 mismatch: "
            f"expected {expected_source_hash}, got {actual_source_hash}"
        )
    try:
        source_text = source.read_text(encoding="utf-8")
        problem = parse_and_encode(source_text)
    except (OSError, UnicodeError, IndependentQfufError) as error:
        raise SystemExit(f"independent SMT-LIB reconstruction failed: {error}") from error

    if result == "sat":
        if sat_variables != problem.variable_count:
            raise SystemExit(
                "SAT manifest variable count differs from independent reconstruction"
            )
        try:
            validate_v2_sat_manifest(manifest, problem)
        except IndependentQfufError as error:
            raise SystemExit(f"independent SAT model check failed: {error}") from error
        print(
            json.dumps(
                {
                    "status": "verified",
                    "result": "sat",
                    "variables": problem.variable_count,
                    "base_clauses": problem.base_count,
                    "source_sha256": actual_source_hash,
                },
                sort_keys=True,
            )
        )
        return 0

    try:
        dimacs = artifact_path(dimacs_value, args.manifest, args.dimacs)
        proof = artifact_path(proof_value, args.manifest, args.proof)
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(f"cannot resolve certificate artifact: {error}") from error
    for path, expected, label in [
        (dimacs, expected_dimacs_hash, "DIMACS"),
        (proof, expected_proof_hash, "proof"),
    ]:
        try:
            actual = sha256(path)
        except (OSError, ValueError) as error:
            raise SystemExit(f"cannot read {label} artifact: {error}") from error
        if actual != expected:
            raise SystemExit(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")
    try:
        variables, clauses = parse_dimacs_independent(
            dimacs.read_text(encoding="ascii")
        )
        replayed = validate_v2_unsat_manifest(
            manifest, problem, variables, clauses
        )
    except (OSError, UnicodeError, IndependentQfufError) as error:
        raise SystemExit(f"independent UNSAT reconstruction failed: {error}") from error
    if not args.drat_trim:
        raise SystemExit("drat-trim is required; pass --drat-trim PATH")
    try:
        checked = subprocess.run(
            [args.drat_trim, str(dimacs), str(proof), "-I"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as error:
        raise SystemExit(f"cannot run drat-trim: {error}") from error
    if checked.returncode != 0 or "VERIFIED" not in checked.stdout:
        raise SystemExit(f"drat-trim rejected the proof:\n{checked.stdout}")

    print(
        json.dumps(
            {
                "status": "verified",
                "result": "unsat",
                "variables": variables,
                "clauses": len(clauses),
                "base_clauses": problem.base_count,
                "replayed_theory_clauses": replayed,
                "source_sha256": expected_source_hash,
                "dimacs_sha256": expected_dimacs_hash,
                "proof_sha256": expected_proof_hash,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
