#!/usr/bin/env python3
"""Lexically scan the fixed T5 corpus for define-fun caller-scope hazards.

This command parses S-expressions and lexical binders only.  It never encodes,
solves, or asks another solver for SAT/UNSAT.  The strict corpus mode accepts
only the external 7,503-source T5 manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TypeAlias

from scripts.bench import component_quotient_contract as contract


REPORT_SCHEMA = "euf-viper.define-fun-shadowing-corpus-scan.v1"
SOURCE_SCHEMA = "euf-viper.define-fun-shadowing-source-scan.v1"


class ShadowScanError(ValueError):
    """The source or report is outside the strict lexical scan contract."""


@dataclass(frozen=True)
class Atom:
    text: str
    kind: str


Sexp: TypeAlias = Atom | tuple["Sexp", ...]


@dataclass(frozen=True)
class Definition:
    name: str
    command_index: int
    parameters: tuple[str, ...]
    global_references: tuple[str, ...]


def _tokens(source: str) -> tuple[Atom, ...]:
    output: list[Atom] = []
    index = 0
    while index < len(source):
        character = source[index]
        if character.isspace():
            index += 1
            continue
        if character == ";":
            index += 1
            while index < len(source) and source[index] not in "\r\n":
                index += 1
            continue
        if character in "()":
            output.append(Atom(character, character))
            index += 1
            continue
        if character == "|":
            index += 1
            value: list[str] = []
            while index < len(source) and source[index] != "|":
                if source[index] == "\\":
                    index += 1
                    if index == len(source):
                        raise ShadowScanError("unterminated quoted-symbol escape")
                value.append(source[index])
                index += 1
            if index == len(source):
                raise ShadowScanError("unterminated quoted symbol")
            output.append(Atom("".join(value), "quoted"))
            index += 1
            continue
        if character == '"':
            index += 1
            value = []
            while index < len(source):
                if source[index] == '"':
                    index += 1
                    if index < len(source) and source[index] == '"':
                        value.append('"')
                        index += 1
                        continue
                    break
                if source[index] == "\x00":
                    raise ShadowScanError("NUL in SMT-LIB string")
                value.append(source[index])
                index += 1
            else:
                raise ShadowScanError("unterminated string")
            output.append(Atom("".join(value), "string"))
            continue
        start = index
        while (
            index < len(source)
            and not source[index].isspace()
            and source[index] not in "();|\""
        ):
            index += 1
        if start == index:
            raise ShadowScanError("unsupported SMT-LIB token")
        text = source[start:index]
        output.append(
            Atom(
                text,
                "keyword"
                if text.startswith(":")
                else "numeral"
                if text.isdecimal()
                else "symbol",
            )
        )
    return tuple(output)


def _forms(source: str) -> tuple[Sexp, ...]:
    stack: list[list[Sexp]] = []
    forms: list[Sexp] = []
    for token in _tokens(source):
        if token.kind == "(":
            stack.append([])
        elif token.kind == ")":
            if not stack:
                raise ShadowScanError("unexpected closing parenthesis")
            value: Sexp = tuple(stack.pop())
            (stack[-1] if stack else forms).append(value)
        else:
            (stack[-1] if stack else forms).append(token)
    if stack:
        raise ShadowScanError("unclosed parenthesis")
    return tuple(forms)


def _list(value: Sexp, context: str) -> tuple[Sexp, ...]:
    if not isinstance(value, tuple):
        raise ShadowScanError(f"{context} must be a list")
    return value


def _name(value: Sexp, context: str) -> str:
    if not isinstance(value, Atom) or value.kind not in {"symbol", "quoted"}:
        raise ShadowScanError(f"{context} must be a symbol")
    return value.text


def _syntax(value: Sexp) -> str | None:
    if isinstance(value, Atom) and value.kind == "symbol":
        return value.text
    return None


def _free_global_atoms(
    expression: Sexp, bound: frozenset[str], global_nullaries: frozenset[str]
) -> set[str]:
    if isinstance(expression, Atom):
        if (
            expression.kind in {"symbol", "quoted"}
            and expression.text not in bound
            and expression.text in global_nullaries
            and not (
                expression.kind == "symbol"
                and expression.text in {"true", "false"}
            )
        ):
            return {expression.text}
        return set()
    if not expression:
        return set()
    syntax = _syntax(expression[0])
    if syntax == "let":
        if len(expression) != 3:
            raise ShadowScanError("let must contain bindings and one body")
        bindings = _list(expression[1], "let binding block")
        references: set[str] = set()
        names: set[str] = set()
        for row_value in bindings:
            row = _list(row_value, "let binding")
            if len(row) != 2:
                raise ShadowScanError("let binding must be a pair")
            name = _name(row[0], "let binding name")
            if name in names:
                raise ShadowScanError(f"duplicate let binding {name!r}")
            names.add(name)
            references.update(_free_global_atoms(row[1], bound, global_nullaries))
        references.update(
            _free_global_atoms(expression[2], bound | frozenset(names), global_nullaries)
        )
        return references
    if syntax == "!":
        return (
            _free_global_atoms(expression[1], bound, global_nullaries)
            if len(expression) >= 2
            else set()
        )
    references = set()
    for child in expression[1:]:
        references.update(_free_global_atoms(child, bound, global_nullaries))
    return references


def scan_source(source: str) -> dict[str, object]:
    """Return a deterministic lexical-scope report for one SMT-LIB source."""

    if type(source) is not str:
        raise ShadowScanError("SMT-LIB source must be text")
    forms = _forms(source)
    global_nullaries: set[str] = set()
    definitions: list[Definition] = []
    available_macros: dict[str, Definition] = {}
    calls: dict[tuple[str, int], list[dict[str, object]]] = {}

    def record_call(
        callee: Definition,
        bound: frozenset[str],
        command_index: int,
        context: str,
        path: tuple[int, ...],
    ) -> None:
        collision = sorted(bound.intersection(callee.global_references))
        if not collision:
            return
        calls.setdefault((callee.name, callee.command_index), []).append(
            {
                "caller_bindings": collision,
                "command_index": command_index,
                "context": context,
                "expression_path": list(path),
            }
        )

    def walk_calls(
        expression: Sexp,
        bound: frozenset[str],
        command_index: int,
        context: str,
        path: tuple[int, ...],
    ) -> None:
        if isinstance(expression, Atom):
            if expression.kind in {"symbol", "quoted"} and expression.text not in bound:
                callee = available_macros.get(expression.text)
                if callee is not None:
                    record_call(callee, bound, command_index, context, path)
            return
        if not expression:
            return
        syntax = _syntax(expression[0])
        if syntax == "let":
            if len(expression) != 3:
                raise ShadowScanError("let must contain bindings and one body")
            bindings = _list(expression[1], "let binding block")
            names: set[str] = set()
            for row_index, row_value in enumerate(bindings):
                row = _list(row_value, "let binding")
                if len(row) != 2:
                    raise ShadowScanError("let binding must be a pair")
                name = _name(row[0], "let binding name")
                if name in names:
                    raise ShadowScanError(f"duplicate let binding {name!r}")
                names.add(name)
                walk_calls(
                    row[1],
                    bound,
                    command_index,
                    context,
                    (*path, 1, row_index, 1),
                )
            walk_calls(
                expression[2],
                bound | frozenset(names),
                command_index,
                context,
                (*path, 2),
            )
            return
        if syntax == "!":
            if len(expression) >= 2:
                walk_calls(
                    expression[1], bound, command_index, context, (*path, 1)
                )
            return
        head = expression[0]
        if isinstance(head, Atom) and head.kind in {"symbol", "quoted"}:
            callee = available_macros.get(head.text)
            if callee is not None:
                record_call(callee, bound, command_index, context, path)
        for child_index, child in enumerate(expression[1:], start=1):
            walk_calls(
                child, bound, command_index, context, (*path, child_index)
            )

    for command_index, form in enumerate(forms):
        command = _list(form, "top-level command")
        if not command:
            raise ShadowScanError("empty top-level command")
        head = _syntax(command[0])
        if head == "declare-const":
            if len(command) == 3:
                global_nullaries.add(_name(command[1], "constant name"))
        elif head == "declare-fun":
            if len(command) == 4 and not _list(command[2], "function arguments"):
                global_nullaries.add(_name(command[1], "function name"))
        elif head == "define-fun":
            if len(command) != 5:
                raise ShadowScanError("define-fun has invalid arity")
            name = _name(command[1], "define-fun name")
            parameter_rows = _list(command[2], "define-fun parameters")
            parameters: list[str] = []
            for row_value in parameter_rows:
                row = _list(row_value, "define-fun parameter")
                if len(row) != 2:
                    raise ShadowScanError("define-fun parameter must be a pair")
                parameter = _name(row[0], "define-fun parameter name")
                if parameter in parameters:
                    raise ShadowScanError(f"duplicate define-fun parameter {parameter!r}")
                parameters.append(parameter)
            references = tuple(
                sorted(
                    _free_global_atoms(
                        command[4],
                        frozenset(parameters),
                        frozenset(global_nullaries),
                    )
                )
            )
            definition = Definition(
                name, command_index, tuple(parameters), references
            )
            walk_calls(
                command[4],
                frozenset(parameters),
                command_index,
                f"define-fun:{name}",
                (4,),
            )
            definitions.append(definition)
            available_macros[name] = definition
            if not parameters:
                global_nullaries.add(name)
        elif head == "assert" and len(command) == 2:
            walk_calls(
                command[1], frozenset(), command_index, "assert", (1,)
            )

    candidates: list[dict[str, object]] = []
    affected: list[dict[str, object]] = []
    for definition in definitions:
        if not definition.global_references:
            continue
        row: dict[str, object] = {
            "command_index": definition.command_index,
            "global_references": list(definition.global_references),
            "name": definition.name,
            "parameters": list(definition.parameters),
        }
        candidates.append(row)
        collisions = calls.get((definition.name, definition.command_index), [])
        if collisions:
            affected.append({**row, "colliding_calls": collisions})
    return {
        "schema": SOURCE_SCHEMA,
        "counts": {
            "affected_definitions": len(affected),
            "colliding_call_sites": sum(
                len(row["colliding_calls"]) for row in affected
            ),
            "definitions": len(definitions),
            "definitions_with_global_references": len(candidates),
        },
        "candidate_definitions": candidates,
        "affected_definitions": affected,
    }


def _source_path(root: Path, row: dict[str, object], line_number: int) -> Path:
    path_text = row.get("path")
    relative_text = row.get("relative_path")
    if type(path_text) is not str or type(relative_text) is not str:
        raise ShadowScanError(f"manifest line {line_number} lacks source paths")
    path = PurePosixPath(path_text)
    relative = PurePosixPath(relative_text)
    if (
        path.is_absolute()
        or relative.is_absolute()
        or not path.parts
        or not relative.parts
        or any(part in {"", ".", ".."} for part in (*path.parts, *relative.parts))
        or tuple(path.parts[-len(relative.parts) :]) != relative.parts
    ):
        raise ShadowScanError(f"manifest line {line_number} has an unsafe source path")
    return root.joinpath(*path.parts)


def scan_corpus(repository_root: Path, manifest_path: Path) -> dict[str, object]:
    root = Path(os.path.abspath(repository_root))
    selected = contract.require_campaign_manifest_path(root, manifest_path)
    manifest_bytes = selected.read_bytes()
    rows = contract.require_campaign_manifest_bytes(manifest_bytes)
    candidates: list[dict[str, object]] = []
    affected: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    totals = {
        "affected_definitions": 0,
        "colliding_call_sites": 0,
        "definitions": 0,
        "definitions_with_global_references": 0,
        "scan_failures": 0,
        "sources": len(rows),
    }
    seen_paths: set[str] = set()
    for index, raw_row in enumerate(rows):
        row = dict(raw_row)
        path = _source_path(root, row, index + 1)
        relative_path = row.get("relative_path")
        source_sha256 = row.get("sha256")
        expected_bytes = row.get("bytes")
        if (
            type(relative_path) is not str
            or relative_path in seen_paths
            or type(source_sha256) is not str
            or type(expected_bytes) is not int
            or expected_bytes < 0
        ):
            raise ShadowScanError(f"manifest line {index + 1} has malformed identity")
        seen_paths.add(relative_path)
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        if digest != source_sha256 or len(payload) != expected_bytes:
            raise ShadowScanError(
                f"manifest source identity drift at {relative_path!r}"
            )
        source_identity = {
            "manifest_id": index,
            "relative_path": relative_path,
            "sha256": digest,
        }
        try:
            source_report = scan_source(payload.decode("utf-8"))
        except (UnicodeDecodeError, ShadowScanError) as error:
            failures.append({**source_identity, "error": str(error)})
            totals["scan_failures"] += 1
            continue
        counts = source_report["counts"]
        assert type(counts) is dict
        for field in (
            "affected_definitions",
            "colliding_call_sites",
            "definitions",
            "definitions_with_global_references",
        ):
            totals[field] += int(counts[field])
        for candidate in source_report["candidate_definitions"]:
            candidates.append({"source": source_identity, **candidate})
        for affected_row in source_report["affected_definitions"]:
            affected.append({"source": source_identity, **affected_row})
    report = {
        "schema": REPORT_SCHEMA,
        "status": "complete" if not failures else "incomplete",
        "decisive": False,
        "authoritative": False,
        "analysis": {
            "kind": "standalone-s-expression-lexical-scope-scan",
            "solving_performed": False,
        },
        "corpus": {
            "expected_sources": contract.EXPECTED_SOURCES,
            "manifest_relative_path": contract.MANIFEST_RELATIVE_PATH,
            "manifest_sha256": contract.MANIFEST_SHA256,
            "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
        },
        "counts": totals,
        "candidate_definitions": candidates,
        "affected_definitions": affected,
        "failures": failures,
    }
    validate_report(report)
    return report


def validate_report(value: object) -> dict[str, object]:
    required = {
        "schema",
        "status",
        "decisive",
        "authoritative",
        "analysis",
        "corpus",
        "counts",
        "candidate_definitions",
        "affected_definitions",
        "failures",
    }
    if type(value) is not dict or set(value) != required:
        raise ShadowScanError("shadow-scan report field set drift")
    failures = value["failures"]
    if (
        value["schema"] != REPORT_SCHEMA
        or value["decisive"] is not False
        or value["authoritative"] is not False
        or value["status"] not in {"complete", "incomplete"}
        or type(failures) is not list
        or (value["status"] == "complete") is not (len(failures) == 0)
    ):
        raise ShadowScanError("shadow-scan report status drift")
    if value["analysis"] != {
        "kind": "standalone-s-expression-lexical-scope-scan",
        "solving_performed": False,
    }:
        raise ShadowScanError("shadow-scan analysis identity drift")
    if value["corpus"] != {
        "expected_sources": contract.EXPECTED_SOURCES,
        "manifest_relative_path": contract.MANIFEST_RELATIVE_PATH,
        "manifest_sha256": contract.MANIFEST_SHA256,
        "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
    }:
        raise ShadowScanError("shadow-scan corpus binding drift")
    counts = value["counts"]
    count_fields = {
        "affected_definitions",
        "colliding_call_sites",
        "definitions",
        "definitions_with_global_references",
        "scan_failures",
        "sources",
    }
    if (
        type(counts) is not dict
        or set(counts) != count_fields
        or any(type(item) is not int or item < 0 for item in counts.values())
        or counts["sources"] != contract.EXPECTED_SOURCES
        or counts["scan_failures"] != len(failures)
        or type(value["candidate_definitions"]) is not list
        or type(value["affected_definitions"]) is not list
        or counts["definitions_with_global_references"]
        != len(value["candidate_definitions"])
        or counts["affected_definitions"] != len(value["affected_definitions"])
    ):
        raise ShadowScanError("shadow-scan counters drift")

    def source_identity(item: object, context: str) -> tuple[int, str, str]:
        if type(item) is not dict or set(item) != {
            "manifest_id",
            "relative_path",
            "sha256",
        }:
            raise ShadowScanError(f"{context} source identity field set drift")
        manifest_id = item["manifest_id"]
        relative_path = item["relative_path"]
        digest = item["sha256"]
        if (
            type(manifest_id) is not int
            or not 0 <= manifest_id < contract.EXPECTED_SOURCES
            or type(relative_path) is not str
            or not relative_path
            or PurePosixPath(relative_path).is_absolute()
            or any(
                part in {"", ".", ".."}
                for part in PurePosixPath(relative_path).parts
            )
            or type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ShadowScanError(f"{context} source identity is malformed")
        return manifest_id, relative_path, digest

    def definition_row(
        item: object, context: str, *, affected: bool
    ) -> tuple[
        tuple[int, str, str], int, str, tuple[str, ...], tuple[str, ...]
    ]:
        fields = {
            "source",
            "command_index",
            "global_references",
            "name",
            "parameters",
        }
        if affected:
            fields.add("colliding_calls")
        if type(item) is not dict or set(item) != fields:
            raise ShadowScanError(f"{context} definition field set drift")
        source = source_identity(item["source"], context)
        command_index = item["command_index"]
        name = item["name"]
        parameters = item["parameters"]
        globals_ = item["global_references"]
        if (
            type(command_index) is not int
            or command_index < 0
            or type(name) is not str
            or not name
            or type(parameters) is not list
            or any(type(parameter) is not str or not parameter for parameter in parameters)
            or len(parameters) != len(set(parameters))
            or type(globals_) is not list
            or not globals_
            or any(type(reference) is not str or not reference for reference in globals_)
            or globals_ != sorted(set(globals_))
        ):
            raise ShadowScanError(f"{context} definition identity is malformed")
        if affected:
            calls = item["colliding_calls"]
            if type(calls) is not list or not calls:
                raise ShadowScanError(f"{context} has no colliding call sites")
            for call in calls:
                if type(call) is not dict or set(call) != {
                    "caller_bindings",
                    "command_index",
                    "context",
                    "expression_path",
                }:
                    raise ShadowScanError(f"{context} call field set drift")
                bindings = call["caller_bindings"]
                expression_path = call["expression_path"]
                if (
                    type(bindings) is not list
                    or not bindings
                    or bindings != sorted(set(bindings))
                    or any(binding not in globals_ for binding in bindings)
                    or type(call["command_index"]) is not int
                    or call["command_index"] < 0
                    or type(call["context"]) is not str
                    or not call["context"]
                    or type(expression_path) is not list
                    or any(type(index) is not int or index < 0 for index in expression_path)
                ):
                    raise ShadowScanError(f"{context} call identity is malformed")
        return source, command_index, name, tuple(parameters), tuple(globals_)

    candidates = value["candidate_definitions"]
    affected_rows = value["affected_definitions"]
    candidate_keys = [
        definition_row(row, "candidate", affected=False) for row in candidates
    ]
    affected_keys = [
        definition_row(row, "affected", affected=True) for row in affected_rows
    ]
    if (
        len(candidate_keys) != len(set(candidate_keys))
        or len(affected_keys) != len(set(affected_keys))
        or any(key not in set(candidate_keys) for key in affected_keys)
        or counts["colliding_call_sites"]
        != sum(len(row["colliding_calls"]) for row in affected_rows)
        or counts["affected_definitions"]
        > counts["definitions_with_global_references"]
        or counts["definitions_with_global_references"] > counts["definitions"]
    ):
        raise ShadowScanError("shadow-scan definition accounting drift")

    failure_sources: list[tuple[int, str, str]] = []
    for failure in failures:
        if type(failure) is not dict or set(failure) != {
            "manifest_id",
            "relative_path",
            "sha256",
            "error",
        }:
            raise ShadowScanError("shadow-scan failure field set drift")
        identity = source_identity(
            {key: failure[key] for key in ("manifest_id", "relative_path", "sha256")},
            "failure",
        )
        if (
            type(failure["error"]) is not str
            or not failure["error"]
            or any(character in failure["error"] for character in "\x00\r\n")
        ):
            raise ShadowScanError("shadow-scan failure message is malformed")
        failure_sources.append(identity)
    if len(failure_sources) != len(set(failure_sources)):
        raise ShadowScanError("shadow-scan failure source duplication")
    return value


def _write_no_replace(path: Path, payload: bytes) -> None:
    path = Path(os.path.abspath(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise ShadowScanError("shadow-scan report write made no progress")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        descriptor_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_stat.st_mode)
            or stat.S_IMODE(descriptor_stat.st_mode) != 0o444
            or descriptor_stat.st_size != len(payload)
        ):
            raise ShadowScanError("shadow-scan report persistence drift")
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


def _read_report(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ShadowScanError(f"shadow-scan report is not ASCII JSON: {error}") from error
    if contract.canonical_json_bytes(value) != payload:
        raise ShadowScanError("shadow-scan report is not canonical JSON")
    return validate_report(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan the exact external corpus")
    scan.add_argument("--repository-root", type=Path, default=contract.ROOT)
    scan.add_argument("--manifest", type=Path)
    scan.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate", help="validate a canonical report")
    validate.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "validate":
            report = _read_report(arguments.report)
        else:
            manifest = arguments.manifest or (
                arguments.repository_root / contract.MANIFEST_RELATIVE_PATH
            )
            report = scan_corpus(arguments.repository_root, manifest)
            _write_no_replace(arguments.output, contract.canonical_json_bytes(report))
        print(
            json.dumps(
                {
                    "affected_definitions": report["counts"]["affected_definitions"],
                    "manifest_sha256": report["corpus"]["manifest_sha256"],
                    "scan_failures": report["counts"]["scan_failures"],
                    "schema": report["schema"],
                    "solving_performed": False,
                    "status": report["status"],
                },
                sort_keys=True,
            )
        )
        return 0 if report["status"] == "complete" else 2
    except (OSError, contract.ContractError, ShadowScanError) as error:
        print(f"define-fun shadow scan failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
