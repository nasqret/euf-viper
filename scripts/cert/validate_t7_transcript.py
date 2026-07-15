#!/usr/bin/env python3
"""Independently validate one chain-hashed T7 explanation transcript."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from independent_qfuf import (  # noqa: E402
    IndependentQfufError,
    parse_and_encode,
    validate_euf_lemma,
    validate_total_assignment,
)


SCHEMA = "euf-viper.t7-transcript.v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FORESTS = {
    "trail",
    "reverse-trail",
    "increasing-decision-level",
    "decreasing-decision-level",
}
DISPOSITIONS = {
    "emitted",
    "handoff-duplicate",
    "pending-occupied",
    "persistent-duplicate",
    "preempted",
    "queued",
    "selected",
}


class T7TranscriptError(RuntimeError):
    """Raised when a transcript or requested proof fails closed."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise T7TranscriptError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def canonical_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise T7TranscriptError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _nonnegative_int(value: Any, context: str) -> int:
    if type(value) is not int or value < 0:
        raise T7TranscriptError(f"{context} must be a non-negative integer")
    return value


def _index(value: Any, size: int, context: str) -> int:
    index = _nonnegative_int(value, context)
    if index >= size:
        raise T7TranscriptError(f"{context} {index} is out of range for {size} candidates")
    return index


def _literal_list(value: Any, context: str) -> list[int]:
    if type(value) is not list or any(type(item) is not int for item in value):
        raise T7TranscriptError(f"{context} must be an integer list")
    if any(item == 0 or item == -(2**31) for item in value):
        raise T7TranscriptError(f"{context} contains an invalid literal")
    if any(left >= right for left, right in zip(value, value[1:])):
        raise T7TranscriptError(f"{context} must be strictly increasing")
    return list(value)


def load_chain(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_bytes()
        text = raw.decode("ascii")
    except (OSError, UnicodeError) as error:
        raise T7TranscriptError(f"cannot read transcript {path}: {error}") from error
    if not raw or not raw.endswith(b"\n"):
        raise T7TranscriptError("transcript must be non-empty ASCII JSONL with a final newline")
    records: list[dict[str, Any]] = []
    previous = bytes(32)
    previous_hex = "0" * 64
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise T7TranscriptError(f"transcript line {line_number} is blank")
        try:
            record = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, T7TranscriptError) as error:
            raise T7TranscriptError(
                f"transcript line {line_number} is invalid JSON: {error}"
            ) from error
        if type(record) is not dict:
            raise T7TranscriptError(f"transcript line {line_number} must be an object")
        if record.get("schema") != SCHEMA:
            raise T7TranscriptError(f"transcript line {line_number} has the wrong schema")
        if record.get("sequence") != len(records):
            raise T7TranscriptError(f"transcript line {line_number} has a non-contiguous sequence")
        if record.get("previous_sha256") != previous_hex:
            raise T7TranscriptError(f"transcript line {line_number} breaks the previous hash link")
        actual_hash = record.get("record_sha256")
        if type(actual_hash) is not str or HEX64.fullmatch(actual_hash) is None:
            raise T7TranscriptError(f"transcript line {line_number} has an invalid record hash")
        payload = dict(record)
        del payload["record_sha256"]
        digest = hashlib.sha256(previous + canonical_bytes(payload)).digest()
        if digest.hex() != actual_hash:
            raise T7TranscriptError(f"transcript line {line_number} record hash mismatch")
        previous = digest
        previous_hex = actual_hash
        records.append(record)
    if len(records) < 2 or records[0].get("kind") != "header":
        raise T7TranscriptError("transcript must start with one header")
    if records[-1].get("kind") != "summary":
        raise T7TranscriptError("transcript must end with one summary")
    if any(record.get("kind") != "conflict" for record in records[1:-1]):
        raise T7TranscriptError("only conflict records may occur between header and summary")
    return records


def base_cnf_hash(problem: Any) -> str:
    return sha256_bytes(
        canonical_bytes(
            {
                "clauses": [list(clause) for clause in problem.clauses],
                "variables": problem.variable_count,
            }
        )
    )


def _active_levels(problem: Any, event: dict[str, Any]) -> dict[int, int]:
    facts = event.get("active_facts")
    if type(facts) is not list:
        raise T7TranscriptError("conflict active_facts must be a list")
    levels: dict[int, int] = {}
    variables: set[int] = set()
    previous_ordinal: int | None = None
    root_facts = 0
    event_level = _nonnegative_int(event.get("decision_level"), "decision_level")
    for index, fact in enumerate(facts):
        if type(fact) is not dict:
            raise T7TranscriptError(f"active fact {index} must be an object")
        if fact.get("kind") not in {"equality", "disequality"}:
            raise T7TranscriptError(f"active fact {index} has an invalid kind")
        _nonnegative_int(fact.get("left"), f"active fact {index} left")
        _nonnegative_int(fact.get("right"), f"active fact {index} right")
        level = _nonnegative_int(
            fact.get("decision_level"), f"active fact {index} decision_level"
        )
        ordinal = _nonnegative_int(fact.get("ordinal"), f"active fact {index} ordinal")
        if level > event_level:
            raise T7TranscriptError(f"active fact {index} is above the event decision level")
        if previous_ordinal is not None and ordinal <= previous_ordinal:
            raise T7TranscriptError("active fact ordinals are not stable and increasing")
        previous_ordinal = ordinal
        literal = fact.get("literal")
        if literal is None:
            if (
                fact.get("kind") != "disequality"
                or fact.get("left") != problem.true_term
                or fact.get("right") != problem.false_term
                or level != 0
            ):
                raise T7TranscriptError("only a root disequality may omit its literal")
            if index != 0 or ordinal != 0:
                raise T7TranscriptError("root disequality must retain ordinal zero at trail head")
            root_facts += 1
            continue
        if type(literal) is not int or literal == 0 or literal == -(2**31):
            raise T7TranscriptError(f"active fact {index} has an invalid literal")
        variable = abs(literal)
        if variable in variables:
            raise T7TranscriptError("active facts reuse one SAT variable")
        variables.add(variable)
        try:
            atom = problem.atom_for_variable(variable)
        except IndependentQfufError as error:
            raise T7TranscriptError(f"active fact {index} has no source atom") from error
        if atom.kind == "equality":
            expected = (
                "equality" if literal > 0 else "disequality",
                atom.left,
                atom.right,
            )
        elif atom.kind == "bool_term":
            expected = (
                "equality",
                atom.term,
                problem.true_term if literal > 0 else problem.false_term,
            )
        else:
            raise T7TranscriptError(
                f"active fact {index} references non-theory variable {variable}"
            )
        actual = (fact.get("kind"), fact.get("left"), fact.get("right"))
        if actual != expected:
            raise T7TranscriptError(f"active fact {index} differs from its source atom")
        levels[literal] = level
    if root_facts != 1:
        raise T7TranscriptError("active trail must contain exactly one root disequality")
    expected_trail_hash = sha256_bytes(canonical_bytes(facts))
    if event.get("trail_sha256") != expected_trail_hash:
        raise T7TranscriptError("conflict trail SHA-256 mismatch")
    return levels


def _candidate_metrics(
    antecedents: list[int],
    clause: list[int],
    levels: dict[int, int],
    current_level: int,
    reuse: dict[int, int],
) -> dict[str, int]:
    try:
        candidate_levels = {levels[literal] for literal in antecedents}
    except KeyError as error:
        raise T7TranscriptError(
            f"candidate references inactive literal {error.args[0]}"
        ) from error
    descending = sorted(candidate_levels, reverse=True)
    return {
        "lbd": len(candidate_levels),
        "current_level_literals": sum(
            levels[literal] == current_level for literal in antecedents
        ),
        "second_highest_level": descending[1] if len(descending) > 1 else 0,
        "historical_reuse": sum(reuse.get(literal, 0) for literal in clause),
    }


def _validate_conflicts(problem: Any, records: list[dict[str, Any]]) -> None:
    mode = records[0].get("mode")
    if mode not in {"off", "on"}:
        raise T7TranscriptError("header mode must be off or on")
    reuse: dict[int, int] = {}
    ordinal_owners: dict[int, tuple[Any, ...]] = {}
    previous_ordinals: set[int] | None = None
    highest_ordinal = -1
    for event_index, event in enumerate(records[1:-1]):
        if event.get("event") != event_index:
            raise T7TranscriptError("conflict event indices are not contiguous")
        levels = _active_levels(problem, event)
        current_ordinals: set[int] = set()
        for fact in event["active_facts"]:
            ordinal = fact["ordinal"]
            identity = (
                fact["kind"],
                fact["left"],
                fact["right"],
                fact["literal"],
                fact["decision_level"],
            )
            owner = ordinal_owners.get(ordinal)
            if owner is not None:
                if owner != identity:
                    raise T7TranscriptError("active fact ordinal changed identity")
                if previous_ordinals is not None and ordinal not in previous_ordinals:
                    raise T7TranscriptError("rolled-back active fact ordinal reappeared")
            else:
                if ordinal <= highest_ordinal:
                    raise T7TranscriptError("active fact ordinal was reused or moved backward")
                ordinal_owners[ordinal] = identity
                highest_ordinal = ordinal
            current_ordinals.add(ordinal)
        previous_ordinals = current_ordinals
        current_level = event["decision_level"]
        candidates = event.get("candidates")
        if type(candidates) is not list or not 1 <= len(candidates) <= 4:
            raise T7TranscriptError("each conflict needs between one and four candidates")
        all_forests: list[str] = []
        clauses: list[list[int]] = []
        metric_rows: list[dict[str, int]] = []
        for candidate_index, candidate in enumerate(candidates):
            if type(candidate) is not dict:
                raise T7TranscriptError(f"candidate {candidate_index} must be an object")
            clause = _literal_list(candidate.get("clause"), "candidate clause")
            antecedents = _literal_list(
                candidate.get("antecedents"), "candidate antecedents"
            )
            if clause != sorted(-literal for literal in antecedents):
                raise T7TranscriptError("candidate clause is not the negated antecedent set")
            forests = candidate.get("forests")
            if (
                type(forests) is not list
                or not forests
                or any(type(forest) is not str or forest not in FORESTS for forest in forests)
                or len(set(forests)) != len(forests)
            ):
                raise T7TranscriptError("candidate forest provenance is invalid")
            all_forests.extend(forests)
            if candidate.get("replay_valid") is not True:
                raise T7TranscriptError("candidate was not replay-valid in the producing run")
            try:
                validate_euf_lemma(problem, clause)
            except IndependentQfufError as error:
                raise T7TranscriptError(
                    f"candidate {candidate_index} is not an independent EUF lemma: {error}"
                ) from error
            expected_metrics = _candidate_metrics(
                antecedents, clause, levels, current_level, reuse
            )
            if candidate.get("metrics") != expected_metrics:
                raise T7TranscriptError(f"candidate {candidate_index} metrics mismatch")
            clauses.append(clause)
            metric_rows.append(expected_metrics)
        if len(all_forests) != 4 or set(all_forests) != FORESTS:
            raise T7TranscriptError("candidate forest provenance does not cover all four orders")
        if len({tuple(clause) for clause in clauses}) != len(clauses):
            raise T7TranscriptError("candidate clauses were not deduplicated")
        duplicates = _nonnegative_int(
            event.get("candidate_duplicates"), "candidate_duplicates"
        )
        if duplicates != 4 - len(candidates):
            raise T7TranscriptError("candidate duplicate count mismatch")
        minimum_width = min(map(len, clauses))
        if event.get("minimum_width") != minimum_width:
            raise T7TranscriptError("minimum candidate width mismatch")
        eligible = [index for index, clause in enumerate(clauses) if len(clause) == minimum_width]
        off_index = min(eligible, key=lambda index: clauses[index])
        on_index = min(
            eligible,
            key=lambda index: (
                metric_rows[index]["lbd"],
                metric_rows[index]["current_level_literals"],
                metric_rows[index]["second_highest_level"],
                -metric_rows[index]["historical_reuse"],
                clauses[index],
            ),
        )
        if _index(event.get("off_index"), len(candidates), "off_index") != off_index:
            raise T7TranscriptError("off selector index mismatch")
        if _index(event.get("on_index"), len(candidates), "on_index") != on_index:
            raise T7TranscriptError("on selector index mismatch")
        selected_index = _index(
            event.get("selected_index"), len(candidates), "selected_index"
        )
        expected_selected = off_index if mode == "off" else on_index
        if selected_index != expected_selected:
            raise T7TranscriptError("policy selected the wrong candidate")
        if len(clauses[selected_index]) != minimum_width:
            raise T7TranscriptError("selected candidate is wider than the minimum")
        if event.get("disagreement") is not (off_index != on_index):
            raise T7TranscriptError("selector disagreement flag mismatch")
        if event.get("disposition") not in DISPOSITIONS:
            raise T7TranscriptError("conflict disposition is invalid")
        for field in ("build_ns", "score_ns", "replay_ns"):
            _nonnegative_int(event.get(field), field)
        for literal in clauses[on_index]:
            reuse[literal] = reuse.get(literal, 0) + 1


def _clauses_hold(clauses: Iterable[Iterable[int]], assignment: list[int]) -> bool:
    values = [False, *(literal > 0 for literal in assignment)]
    return all(
        any((literal > 0) == values[abs(literal)] for literal in clause)
        for clause in clauses
    )


def _selected_suffix(records: list[dict[str, Any]]) -> list[list[int]]:
    suffix: list[list[int]] = []
    seen: set[tuple[int, ...]] = set()
    for event in records[1:-1]:
        if event["disposition"] != "emitted":
            continue
        clause = list(event["candidates"][event["selected_index"]]["clause"])
        key = tuple(clause)
        if key not in seen:
            seen.add(key)
            suffix.append(clause)
    return suffix


def write_dimacs(path: Path, variables: int, clauses: Iterable[Iterable[int]]) -> None:
    rows = [list(clause) for clause in clauses]
    payload = [f"p cnf {variables} {len(rows)}\n"]
    payload.extend(" ".join(map(str, clause)) + " 0\n" for clause in rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(payload), encoding="ascii")


def _verify_drat(
    *,
    problem: Any,
    suffix: list[list[int]],
    drat_trim: Path | None,
    proof: Path | None,
    proof_cache: Path | None,
    proof_producer: Path | None,
    require_proof: bool,
) -> tuple[str, str | None, str | None]:
    proof_key = sha256_bytes(
        canonical_bytes(
            {
                "base_cnf_sha256": base_cnf_hash(problem),
                "selected_suffix": suffix,
            }
        )
    )
    if (
        proof is None
        and proof_cache is None
        and proof_producer is None
        and drat_trim is None
        and not require_proof
    ):
        return "not-requested", proof_key, None
    temporary = None
    if proof_cache is not None:
        proof_cache.mkdir(parents=True, exist_ok=True)
        dimacs = proof_cache / f"{proof_key}.cnf"
        cached_proof = proof_cache / f"{proof_key}.drat"
    else:
        temporary = tempfile.TemporaryDirectory(prefix="euf-viper-t7-cert-")
        temporary_path = Path(temporary.name)
        dimacs = temporary_path / f"{proof_key}.cnf"
        cached_proof = temporary_path / f"{proof_key}.drat"
    try:
        write_dimacs(
            dimacs,
            problem.variable_count,
            [*problem.clauses, *suffix],
        )
        selected_proof = proof or cached_proof
        if proof is None and not selected_proof.is_file() and proof_producer is not None:
            completed = subprocess.run(
                [
                    str(proof_producer),
                    "prove-dimacs",
                    str(dimacs),
                    "--proof",
                    str(selected_proof),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            if completed.returncode != 0:
                raise T7TranscriptError(
                    f"T7 proof producer failed for {proof_key}:\n{completed.stdout}"
                )
        if not selected_proof.is_file():
            if require_proof:
                raise T7TranscriptError(
                    f"requested UNSAT proof evidence is absent for transcript key {proof_key}"
                )
            return "not-requested", proof_key, None
        if drat_trim is None or not drat_trim.is_file():
            raise T7TranscriptError(
                "drat-trim is required when UNSAT proof evidence is present"
            )
        completed = subprocess.run(
            [str(drat_trim), str(dimacs), str(selected_proof), "-I"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if completed.returncode != 0 or "VERIFIED" not in completed.stdout:
            raise T7TranscriptError(
                f"drat-trim rejected T7 suffix proof:\n{completed.stdout}"
            )
        return "verified", proof_key, sha256_file(selected_proof)
    finally:
        if temporary is not None:
            temporary.cleanup()


def validate_transcript(
    source: Path,
    transcript: Path,
    *,
    drat_trim: Path | None = None,
    proof: Path | None = None,
    proof_cache: Path | None = None,
    proof_producer: Path | None = None,
    require_unsat_proof: bool = False,
) -> dict[str, Any]:
    records = load_chain(transcript)
    header = records[0]
    summary = records[-1]
    if header.get("backend") != "cadical-rollback":
        raise T7TranscriptError("T7 transcript did not use cadical-rollback")
    direct_root = header.get("direct_root_cnf")
    direct_negated = header.get("direct_negated_root")
    if type(direct_root) is not bool or type(direct_negated) is not bool:
        raise T7TranscriptError("header root-CNF settings must be Boolean")
    try:
        source_text = source.read_text(encoding="utf-8")
        problem = parse_and_encode(
            source_text,
            direct_root_cnf=direct_root,
            direct_negated_root=direct_negated,
        )
    except (OSError, UnicodeError, IndependentQfufError) as error:
        raise T7TranscriptError(f"independent source reconstruction failed: {error}") from error
    if header.get("base_variables") != problem.variable_count:
        raise T7TranscriptError("independent base variable count mismatch")
    if header.get("base_clauses") != len(problem.clauses):
        raise T7TranscriptError("independent base clause count mismatch")
    if header.get("base_cnf_sha256") != base_cnf_hash(problem):
        raise T7TranscriptError("independent base CNF SHA-256 mismatch")
    if summary.get("mode") != header.get("mode"):
        raise T7TranscriptError("summary mode differs from header mode")
    _validate_conflicts(problem, records)

    events = records[1:-1]
    suffix = _selected_suffix(records)
    if summary.get("selected_suffix") != suffix:
        raise T7TranscriptError("summary selected suffix mismatch")
    if summary.get("selected_suffix_sha256") != sha256_bytes(canonical_bytes(suffix)):
        raise T7TranscriptError("summary selected suffix SHA-256 mismatch")
    expected_totals = {
        "build_ns": sum(event["build_ns"] for event in events),
        "score_ns": sum(event["score_ns"] for event in events),
        "replay_ns": sum(event["replay_ns"] for event in events),
        "candidate_duplicates": sum(event["candidate_duplicates"] for event in events),
        "disagreements": sum(bool(event["disagreement"]) for event in events),
        "theory_conflicts": len(events),
        "replay_failures": 0,
    }
    for key, expected in expected_totals.items():
        if summary.get(key) != expected:
            raise T7TranscriptError(f"summary {key} mismatch")
    for key in (
        "decisions",
        "propagations",
        "sat_conflicts",
        "backtracks",
        "model_checks",
        "validations",
        "persistent_duplicates",
        "fallbacks",
    ):
        _nonnegative_int(summary.get(key), f"summary {key}")
    if summary["validations"] < summary["model_checks"]:
        raise T7TranscriptError("summary validations are below model checks")

    result = summary.get("result")
    certificate_status = "sat-model"
    proof_key: str | None = None
    proof_sha256: str | None = None
    if result == "sat":
        assignment = summary.get("final_model")
        if type(assignment) is not list or len(assignment) != problem.variable_count:
            raise T7TranscriptError("SAT transcript lacks a complete final model")
        if any(
            type(literal) is not int or abs(literal) != variable
            for variable, literal in enumerate(assignment, start=1)
        ):
            raise T7TranscriptError("SAT final model is not ordered by DIMACS variable")
        if not _clauses_hold([*problem.clauses, *suffix], assignment):
            raise T7TranscriptError(
                "SAT final model fails the independent base CNF or selected suffix"
            )
        try:
            validate_total_assignment(problem, assignment)
        except IndependentQfufError as error:
            raise T7TranscriptError(f"SAT final model fails independent EUF: {error}") from error
    elif result == "unsat":
        if summary.get("final_model") is not None:
            raise T7TranscriptError("UNSAT transcript must not contain a final model")
        certificate_status, proof_key, proof_sha256 = _verify_drat(
            problem=problem,
            suffix=suffix,
            drat_trim=drat_trim,
            proof=proof,
            proof_cache=proof_cache,
            proof_producer=proof_producer,
            require_proof=require_unsat_proof,
        )
    else:
        raise T7TranscriptError("summary result must be sat or unsat")
    return {
        "base_cnf_sha256": header["base_cnf_sha256"],
        "candidate_clauses": sum(len(event["candidates"]) for event in events),
        "certificate_status": certificate_status,
        "chain_sha256": records[-1]["record_sha256"],
        "conflicts": len(events),
        "disagreements": summary["disagreements"],
        "mode": header["mode"],
        "proof_key": proof_key,
        "proof_sha256": proof_sha256,
        "result": result,
        "schema": "euf-viper.t7-transcript-validation.v1",
        "selected_suffix_clauses": len(suffix),
        "source": str(source.resolve()),
        "transcript": str(transcript.resolve()),
        "transcript_sha256": sha256_file(transcript),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("transcript", type=Path)
    parser.add_argument("--drat-trim", type=Path)
    parser.add_argument("--drat-proof", type=Path)
    parser.add_argument("--proof-cache", type=Path)
    parser.add_argument("--proof-producer", type=Path)
    parser.add_argument("--require-unsat-proof", action="store_true")
    parser.add_argument("--out", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = validate_transcript(
            args.source,
            args.transcript,
            drat_trim=args.drat_trim,
            proof=args.drat_proof,
            proof_cache=args.proof_cache,
            proof_producer=args.proof_producer,
            require_unsat_proof=args.require_unsat_proof,
        )
        payload = canonical_bytes(report)
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
        sys.stdout.buffer.write(payload)
    except (OSError, T7TranscriptError) as error:
        print(f"T7 transcript validation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
