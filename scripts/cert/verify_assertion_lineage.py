#!/usr/bin/env python3
"""Independently reconstruct and verify source assertion lineage ledgers."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "euf-viper.assertion-lineage.v1"
BYTE_BINDING = "no-follow-single-open-buffer.v1"
SPAN_CONVENTION = "zero-based-half-open-source-bytes.v1"
RAW_AST_ENCODING = "lossless-token-tree.v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ID_PATTERNS = {
    "assertion": re.compile(r"assertion-[0-9]{6}"),
    "command": re.compile(r"command-[0-9]{6}"),
    "diagnostic": re.compile(r"diagnostic-[0-9]{6}"),
    "object": re.compile(r"object-[0-9]{6}"),
}
ALLOWED_TRANSFORMS = {
    "boolean_assertion": {
        "bool_materialization_axiom",
        "source_assertion_root",
        "term_ite_else_axiom",
        "term_ite_then_axiom",
    },
    "contradiction": {
        "all_positive_or_branches_pruned",
        "asserted_false",
        "empty_positive_or",
        "negated_true",
    },
    "disequality": {
        "asserted_distinct_pair",
        "negated_binary_equality",
    },
    "equality": {
        "asserted_equality_pair",
        "negated_binary_distinct",
        "positive_or_branch_intersection",
    },
    "internal_term": {
        "bool_materialization_term",
        "internal_bool_false_term",
        "internal_bool_true_term",
        "term_ite_result_term",
    },
}
LEDGER_KEYS = {
    "active_check_sat",
    "assertions",
    "build",
    "commands",
    "counts",
    "diagnostics",
    "lineage_sha256",
    "objects",
    "parser",
    "schema",
    "scope",
    "source",
    "status",
    "unsupported_accounting_complete",
}
COMMAND_KEYS = {
    "assertion_id",
    "head",
    "id",
    "ordinal",
    "raw_ast_sha256",
    "source_slice_sha256",
    "span",
}
ASSERTION_KEYS = {
    "command_id",
    "id",
    "ordinal",
    "raw_ast_sha256",
    "source_slice_sha256",
    "span",
}
ORIGIN_KEYS = {
    "assertion_id",
    "raw_ast_sha256",
    "source_slice_sha256",
    "span",
}
OBJECT_KEYS = {
    "id",
    "local_index",
    "object_kind",
    "origins",
    "transformation_kind",
    "typed_object_sha256",
}
DIAGNOSTIC_KEYS = {
    "assertion_origins",
    "category",
    "command_id",
    "id",
    "message",
}


class LineageError(ValueError):
    """Raised when source bytes or a ledger violate the lineage contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LineageError(message)


def require_exact_keys(value: Any, expected: set[str], *, where: str) -> dict[str, Any]:
    require(type(value) is dict, f"{where}: expected object")
    actual = set(value)
    require(
        actual == expected,
        f"{where}: key mismatch; missing={sorted(expected - actual)}, "
        f"extra={sorted(actual - expected)}",
    )
    return value


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


def strict_json_bytes(content: bytes, *, where: str) -> Any:
    try:
        text = content.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise LineageError(f"{where}: malformed strict JSON: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return (text + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise LineageError(f"cannot canonicalize JSON: {error}") from error


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


@dataclass(frozen=True)
class FileFingerprint:
    changed_ns: int
    device: int
    inode: int
    mode: int
    modified_ns: int
    size: int


def fingerprint(metadata: os.stat_result) -> FileFingerprint:
    return FileFingerprint(
        changed_ns=metadata.st_ctime_ns,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        modified_ns=metadata.st_mtime_ns,
        size=metadata.st_size,
    )


def read_no_follow(path: Path) -> tuple[bytes, FileFingerprint, Path]:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "pread"):
        raise LineageError("platform lacks no-follow descriptor reads")
    canonical_parent = path.parent.resolve(strict=True)
    canonical = canonical_parent / path.name
    descriptor = -1
    try:
        descriptor = os.open(canonical, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "opened input is not a regular file")
        original = fingerprint(before)
        chunks: list[bytes] = []
        offset = 0
        while offset < original.size:
            chunk = os.pread(descriptor, min(1024 * 1024, original.size - offset), offset)
            require(bool(chunk), "opened input became truncated while read")
            chunks.append(chunk)
            offset += len(chunk)
        require(not os.pread(descriptor, 1, original.size), "opened input grew while read")
        content = b"".join(chunks)
        require(fingerprint(os.fstat(descriptor)) == original, "opened input changed while read")
        path_state = os.lstat(canonical)
        require(
            path_state.st_dev == original.device
            and path_state.st_ino == original.inode
            and stat.S_ISREG(path_state.st_mode),
            "input path identity changed after open",
        )
        replay = b"".join(
            os.pread(descriptor, min(1024 * 1024, original.size - position), position)
            for position in range(0, original.size, 1024 * 1024)
        )
        require(replay == content, "opened input bytes changed after snapshot")
        require(
            fingerprint(os.fstat(descriptor)) == original,
            "opened input changed during replay",
        )
        return content, original, canonical
    except OSError as error:
        raise LineageError(f"cannot no-follow read {path}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@dataclass(frozen=True)
class Node:
    kind: str
    raw: bytes
    children: tuple["Node", ...]
    start: int
    end: int

    def syntax_head(self) -> bytes | None:
        if self.kind != "list" or not self.children:
            return None
        first = self.children[0]
        if first.kind != "atom" or first.raw.startswith(b'"'):
            return None
        return first.raw

    def symbol(self) -> str | None:
        if self.kind == "atom" and not self.raw.startswith(b'"'):
            return self.raw.decode("utf-8")
        if self.kind != "quoted":
            return None
        decoded = bytearray()
        index = 1
        while index + 1 < len(self.raw):
            if self.raw[index] == ord("\\") and index + 2 < len(self.raw):
                index += 1
            decoded.append(self.raw[index])
            index += 1
        return decoded.decode("utf-8")

    def ast_bytes(self) -> bytes:
        if self.kind == "atom":
            return b"A" + str(len(self.raw)).encode("ascii") + b":" + self.raw
        if self.kind == "quoted":
            return b"Q" + str(len(self.raw)).encode("ascii") + b":" + self.raw
        return (
            b"L"
            + str(len(self.children)).encode("ascii")
            + b":"
            + b"".join(child.ast_bytes() for child in self.children)
        )


class SourceParser:
    """A lossless parser independent from the Rust tokenizer and serializer."""

    def __init__(self, source: bytes):
        self.source = source
        self.position = 0

    def skip_layout(self) -> None:
        while True:
            while self.position < len(self.source) and self.source[self.position] in b" \n\r\t":
                self.position += 1
            if self.position >= len(self.source) or self.source[self.position] != ord(";"):
                return
            while self.position < len(self.source) and self.source[self.position] != ord("\n"):
                self.position += 1

    def parse_all(self) -> list[Node]:
        nodes: list[Node] = []
        self.skip_layout()
        while self.position < len(self.source):
            nodes.append(self.parse_one())
            self.skip_layout()
        return nodes

    def parse_one(self) -> Node:
        self.skip_layout()
        require(self.position < len(self.source), "unexpected end of source")
        start = self.position
        byte = self.source[self.position]
        if byte == ord("("):
            return self.parse_list(start)
        if byte == ord(")"):
            raise LineageError(f"unexpected ')' at byte {start}")
        if byte == ord("|"):
            return self.parse_quoted(start)
        if byte == ord('"'):
            return self.parse_string(start)
        return self.parse_atom(start)

    def parse_list(self, start: int) -> Node:
        self.position += 1
        children: list[Node] = []
        while True:
            self.skip_layout()
            require(self.position < len(self.source), f"unclosed '(' at byte {start}")
            if self.source[self.position] == ord(")"):
                self.position += 1
                return Node("list", b"", tuple(children), start, self.position)
            children.append(self.parse_one())

    def parse_quoted(self, start: int) -> Node:
        self.position += 1
        while self.position < len(self.source):
            if self.source[self.position] == ord("\\") and self.position + 1 < len(self.source):
                self.position += 2
            elif self.source[self.position] == ord("|"):
                self.position += 1
                return Node(
                    "quoted",
                    self.source[start : self.position],
                    (),
                    start,
                    self.position,
                )
            else:
                self.position += 1
        raise LineageError(f"unterminated quoted symbol at byte {start}")

    def parse_string(self, start: int) -> Node:
        self.position += 1
        while self.position < len(self.source):
            if self.source[self.position] == ord("\\") and self.position + 1 < len(self.source):
                self.position += 2
            elif self.source[self.position] == ord('"'):
                self.position += 1
                return Node(
                    "atom",
                    self.source[start : self.position],
                    (),
                    start,
                    self.position,
                )
            else:
                self.position += 1
        raise LineageError(f"unterminated string at byte {start}")

    def parse_atom(self, start: int) -> Node:
        delimiters = b" \n\r\t();"
        while self.position < len(self.source) and self.source[self.position] not in delimiters:
            self.position += 1
        require(self.position > start, f"empty atom at byte {start}")
        return Node(
            "atom",
            self.source[start : self.position],
            (),
            start,
            self.position,
        )


def span(node: Node) -> dict[str, int]:
    return {"end": node.end, "start": node.start}


def command_record(node: Node, ordinal: int, assertion_ordinal: int | None) -> dict[str, Any]:
    head_bytes = node.syntax_head()
    head = head_bytes.decode("utf-8") if head_bytes is not None else None
    return {
        "assertion_id": (
            f"assertion-{assertion_ordinal:06}" if assertion_ordinal is not None else None
        ),
        "head": head,
        "id": f"command-{ordinal:06}",
        "ordinal": ordinal,
        "raw_ast_sha256": sha256_bytes(node.ast_bytes()),
        "source_slice_sha256": "",
        "span": span(node),
    }


def reconstruct_commands(source: bytes, nodes: list[Node]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    commands: list[dict[str, Any]] = []
    assertions: list[dict[str, Any]] = []
    assertion_ordinal = 0
    previous_end = 0
    for ordinal, node in enumerate(nodes):
        require(node.start >= previous_end, f"overlapping command span at command {ordinal}")
        require(0 <= node.start < node.end <= len(source), f"invalid command span at command {ordinal}")
        previous_end = node.end
        is_assertion = node.syntax_head() == b"assert"
        current = assertion_ordinal if is_assertion else None
        record = command_record(node, ordinal, current)
        record["source_slice_sha256"] = sha256_bytes(source[node.start : node.end])
        commands.append(record)
        if is_assertion:
            assertions.append(
                {
                    "command_id": record["id"],
                    "id": f"assertion-{assertion_ordinal:06}",
                    "ordinal": assertion_ordinal,
                    "raw_ast_sha256": record["raw_ast_sha256"],
                    "source_slice_sha256": record["source_slice_sha256"],
                    "span": record["span"],
                }
            )
            assertion_ordinal += 1
    return commands, assertions


def validate_sha256(value: Any, *, where: str) -> str:
    require(type(value) is str and SHA256_RE.fullmatch(value) is not None, f"{where}: invalid SHA-256")
    return value


def validate_uint(value: Any, *, where: str) -> int:
    require(type(value) is int and value >= 0, f"{where}: expected non-negative integer")
    return value


def validate_span(value: Any, source_bytes: int, *, where: str) -> None:
    record = require_exact_keys(value, {"end", "start"}, where=where)
    start = validate_uint(record["start"], where=f"{where}.start")
    end = validate_uint(record["end"], where=f"{where}.end")
    require(start < end <= source_bytes, f"{where}: invalid byte span")


def validate_id(value: Any, kind: str, ordinal: int, *, where: str) -> None:
    require(type(value) is str and ID_PATTERNS[kind].fullmatch(value) is not None, f"{where}: malformed ID")
    require(value == f"{kind}-{ordinal:06}", f"{where}: non-canonical ID order")


def validate_origin(
    value: Any,
    assertions_by_id: dict[str, dict[str, Any]],
    source_bytes: int,
    *,
    where: str,
) -> str:
    origin = require_exact_keys(value, ORIGIN_KEYS, where=where)
    assertion_id = origin["assertion_id"]
    require(type(assertion_id) is str and assertion_id in assertions_by_id, f"{where}: unknown assertion")
    validate_sha256(origin["raw_ast_sha256"], where=f"{where}.raw_ast_sha256")
    validate_sha256(origin["source_slice_sha256"], where=f"{where}.source_slice_sha256")
    validate_span(origin["span"], source_bytes, where=f"{where}.span")
    expected = assertions_by_id[assertion_id]
    require(
        origin
        == {
            "assertion_id": assertion_id,
            "raw_ast_sha256": expected["raw_ast_sha256"],
            "source_slice_sha256": expected["source_slice_sha256"],
            "span": expected["span"],
        },
        f"{where}: assertion identity or span mismatch",
    )
    return assertion_id


def validate_ledger(source_path: Path, ledger_path: Path, *, reconstruct: bool = False) -> dict[str, Any]:
    source, source_fingerprint, canonical_source = read_no_follow(source_path)
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LineageError(f"malformed UTF-8 source at byte {error.start}") from error
    raw_ledger, _, _ = read_no_follow(ledger_path)
    ledger = require_exact_keys(
        strict_json_bytes(raw_ledger, where="ledger"), LEDGER_KEYS, where="ledger"
    )
    require(raw_ledger == canonical_bytes(ledger), "ledger is not strict canonical JSON")
    require(ledger["schema"] == SCHEMA, "ledger schema mismatch")
    require(ledger["status"] == "complete", "ledger status is not complete")
    require(ledger["unsupported_accounting_complete"] is True, "unsupported accounting is incomplete")

    source_binding = require_exact_keys(
        ledger["source"],
        {"byte_binding", "bytes", "device", "inode", "path", "sha256"},
        where="source",
    )
    require(source_binding["byte_binding"] == BYTE_BINDING, "source byte binding mismatch")
    require(validate_uint(source_binding["bytes"], where="source.bytes") == len(source), "source size mismatch")
    require(
        validate_uint(source_binding["device"], where="source.device")
        == source_fingerprint.device,
        "source device mismatch",
    )
    require(
        validate_uint(source_binding["inode"], where="source.inode")
        == source_fingerprint.inode,
        "source inode mismatch",
    )
    require(type(source_binding["path"]) is str, "source.path is not a string")
    require(Path(source_binding["path"]) == canonical_source, "source canonical path mismatch")
    validate_sha256(source_binding["sha256"], where="source.sha256")
    require(source_binding["sha256"] == sha256_bytes(source), "stale-source hash mismatch")

    scope = require_exact_keys(
        ledger["scope"],
        {"boolean_euf_typed_ir_only", "sat_solving_performed"},
        where="scope",
    )
    require(scope == {"boolean_euf_typed_ir_only": True, "sat_solving_performed": False}, "scope permits solving")
    parser = require_exact_keys(
        ledger["parser"],
        {
            "architecture",
            "bounded_let_count",
            "legacy_preprocess_term_limit",
            "raw_ast_encoding",
            "requested_scoped_let_mode",
            "selected_scoped_let",
            "single_assertion_preprocessing",
            "source_revision_sha256",
            "span_convention",
        },
        where="parser",
    )
    require(parser["architecture"] == "authoritative-typed-tree.v1", "parser architecture mismatch")
    require(parser["raw_ast_encoding"] == RAW_AST_ENCODING, "raw AST encoding mismatch")
    require(parser["span_convention"] == SPAN_CONVENTION, "span convention mismatch")
    require(parser["requested_scoped_let_mode"] in {"auto", "off", "on"}, "unsupported parser mode")
    require(type(parser["selected_scoped_let"]) is bool, "selected scoped-let flag is not Boolean")
    bounded_let_count = validate_uint(
        parser["bounded_let_count"], where="parser.bounded_let_count"
    )
    expected_bounded_let_count = min(source.count(b"(let"), 512)
    require(
        bounded_let_count == expected_bounded_let_count,
        "bounded lexical-let count mismatch",
    )
    expected_scoped_let = {
        "auto": bounded_let_count >= 512,
        "off": False,
        "on": True,
    }[parser["requested_scoped_let_mode"]]
    require(
        parser["selected_scoped_let"] is expected_scoped_let,
        "selected scoped-let binding mismatch",
    )
    require(
        type(parser["legacy_preprocess_term_limit"]) is int
        and parser["legacy_preprocess_term_limit"] >= 0,
        "legacy preprocess term limit is invalid",
    )
    require(
        type(parser["single_assertion_preprocessing"]) is bool,
        "single-assert preprocessing flag is not Boolean",
    )
    validate_sha256(parser["source_revision_sha256"], where="parser.source_revision_sha256")
    build = require_exact_keys(
        ledger["build"],
        {"git_dirty", "git_revision", "package_version", "rustc", "source_revision_sha256"},
        where="build",
    )
    require(type(build["git_dirty"]) is bool, "build.git_dirty is not Boolean")
    require(
        type(build["package_version"]) is str and bool(build["package_version"]),
        "build.package_version is invalid",
    )
    require(type(build["rustc"]) is str and bool(build["rustc"]), "build.rustc is invalid")
    require(
        build["git_revision"] == "unknown"
        or (type(build["git_revision"]) is str and re.fullmatch(r"[0-9a-f]{40}", build["git_revision"])),
        "build git revision is malformed",
    )
    validate_sha256(build["source_revision_sha256"], where="build.source_revision_sha256")

    nodes = SourceParser(source).parse_all()
    expected_commands, expected_assertions = reconstruct_commands(source, nodes)
    require(
        parser["single_assertion_preprocessing"] == (len(expected_assertions) == 1),
        "single-assert preprocessing binding mismatch",
    )
    commands = ledger["commands"]
    assertions = ledger["assertions"]
    require(type(commands) is list and commands == expected_commands, "command reconstruction mismatch")
    require(type(assertions) is list and assertions == expected_assertions, "assertion reconstruction mismatch")
    for ordinal, command in enumerate(commands):
        require_exact_keys(command, COMMAND_KEYS, where=f"commands[{ordinal}]")
        validate_id(command["id"], "command", ordinal, where=f"commands[{ordinal}].id")
        require(
            validate_uint(command["ordinal"], where=f"commands[{ordinal}].ordinal")
            == ordinal,
            f"commands[{ordinal}]: non-canonical ordinal",
        )
        validate_sha256(command["raw_ast_sha256"], where=f"commands[{ordinal}].raw_ast_sha256")
        validate_sha256(
            command["source_slice_sha256"],
            where=f"commands[{ordinal}].source_slice_sha256",
        )
        validate_span(command["span"], len(source), where=f"commands[{ordinal}].span")
    for ordinal, assertion in enumerate(assertions):
        require_exact_keys(assertion, ASSERTION_KEYS, where=f"assertions[{ordinal}]")
        validate_id(assertion["id"], "assertion", ordinal, where=f"assertions[{ordinal}].id")
        require(
            validate_uint(assertion["ordinal"], where=f"assertions[{ordinal}].ordinal")
            == ordinal,
            f"assertions[{ordinal}]: non-canonical ordinal",
        )
        validate_sha256(
            assertion["raw_ast_sha256"], where=f"assertions[{ordinal}].raw_ast_sha256"
        )
        validate_sha256(
            assertion["source_slice_sha256"],
            where=f"assertions[{ordinal}].source_slice_sha256",
        )
        validate_span(assertion["span"], len(source), where=f"assertions[{ordinal}].span")

    check_sat = [command for command in commands if command["head"] == "check-sat"]
    require(len(check_sat) == 1, "source must have exactly one active check-sat")
    require_exact_keys(ledger["active_check_sat"], COMMAND_KEYS, where="active_check_sat")
    require(ledger["active_check_sat"] == check_sat[0], "active check-sat binding mismatch")
    assertions_by_id = {assertion["id"]: assertion for assertion in assertions}

    objects = ledger["objects"]
    require(type(objects) is list, "objects must be an array")
    local_indices: collections.Counter[str] = collections.Counter()
    normalized_objects: collections.Counter[tuple[str, str, tuple[str, ...]]] = collections.Counter()
    covered_assertions: set[str] = set()
    for ordinal, value in enumerate(objects):
        obj = require_exact_keys(value, OBJECT_KEYS, where=f"objects[{ordinal}]")
        validate_id(obj["id"], "object", ordinal, where=f"objects[{ordinal}].id")
        kind = obj["object_kind"]
        transform = obj["transformation_kind"]
        require(type(kind) is str and kind in ALLOWED_TRANSFORMS, f"objects[{ordinal}]: unsupported object kind")
        require(
            type(transform) is str and transform in ALLOWED_TRANSFORMS[kind],
            f"objects[{ordinal}]: unsupported transformation",
        )
        validate_uint(obj["local_index"], where=f"objects[{ordinal}].local_index")
        require(
            obj["local_index"] == local_indices[transform],
            f"objects[{ordinal}]: duplicate or non-canonical local index",
        )
        local_indices[transform] += 1
        validate_sha256(obj["typed_object_sha256"], where=f"objects[{ordinal}].typed_object_sha256")
        origins = obj["origins"]
        require(type(origins) is list and origins, f"objects[{ordinal}]: missing lineage")
        origin_ids = [
            validate_origin(
                origin,
                assertions_by_id,
                len(source),
                where=f"objects[{ordinal}].origins[{index}]",
            )
            for index, origin in enumerate(origins)
        ]
        require(origin_ids == sorted(set(origin_ids)), f"objects[{ordinal}]: duplicate or non-canonical origins")
        covered_assertions.update(origin_ids)
        normalized_objects[(kind, transform, tuple(origin_ids))] += 1

    diagnostics = ledger["diagnostics"]
    require(type(diagnostics) is list, "diagnostics must be an array")
    for ordinal, value in enumerate(diagnostics):
        diagnostic = require_exact_keys(value, DIAGNOSTIC_KEYS, where=f"diagnostics[{ordinal}]")
        validate_id(diagnostic["id"], "diagnostic", ordinal, where=f"diagnostics[{ordinal}].id")
        require(diagnostic["category"] in {"boolean", "problem"}, f"diagnostics[{ordinal}]: unsupported category")
        require(diagnostic["command_id"] in {command["id"] for command in commands}, f"diagnostics[{ordinal}]: unknown command")
        require(type(diagnostic["message"]) is str and diagnostic["message"], f"diagnostics[{ordinal}]: empty message")
        origins = diagnostic["assertion_origins"]
        require(type(origins) is list, f"diagnostics[{ordinal}]: origins must be an array")
        origin_ids = [
            validate_origin(
                origin,
                assertions_by_id,
                len(source),
                where=f"diagnostics[{ordinal}].origins[{index}]",
            )
            for index, origin in enumerate(origins)
        ]
        require(origin_ids == sorted(set(origin_ids)), f"diagnostics[{ordinal}]: duplicate origins")
        covered_assertions.update(origin_ids)

    require(covered_assertions == set(assertions_by_id), "one or more source assertions have no object or diagnostic lineage")
    counts = require_exact_keys(
        ledger["counts"],
        {
            "boolean_assertions",
            "commands",
            "contradiction_events",
            "diagnostics",
            "euf_disequalities",
            "euf_equalities",
            "internal_terms",
            "objects",
            "source_assertions",
        },
        where="counts",
    )
    expected_counts = {
        "boolean_assertions": sum(obj["object_kind"] == "boolean_assertion" for obj in objects),
        "commands": len(commands),
        "contradiction_events": sum(obj["object_kind"] == "contradiction" for obj in objects),
        "diagnostics": len(diagnostics),
        "euf_disequalities": sum(obj["object_kind"] == "disequality" for obj in objects),
        "euf_equalities": sum(obj["object_kind"] == "equality" for obj in objects),
        "internal_terms": sum(obj["object_kind"] == "internal_term" for obj in objects),
        "objects": len(objects),
        "source_assertions": len(assertions),
    }
    for name, value in counts.items():
        validate_uint(value, where=f"counts.{name}")
    require(counts == expected_counts, "ledger count reconstruction mismatch")

    commitment = dict(ledger)
    commitment.pop("lineage_sha256")
    validate_sha256(ledger["lineage_sha256"], where="lineage_sha256")
    require(
        ledger["lineage_sha256"] == sha256_bytes(canonical_bytes(commitment)),
        "lineage commitment mismatch",
    )

    if reconstruct:
        expected_objects = reconstruct_supported_objects(nodes, assertions)
        require(
            normalized_objects == expected_objects,
            "independent Boolean/EUF auxiliary reconstruction mismatch: "
            f"expected={expected_objects}, observed={normalized_objects}",
        )

    return {
        "schema": "euf-viper.assertion-lineage-verification.v1",
        "status": "verified",
        "source_sha256": sha256_bytes(source),
        "source_assertions": len(assertions),
        "objects": len(objects),
        "diagnostics": len(diagnostics),
        "independent_reconstruction": reconstruct,
    }


@dataclass
class Declaration:
    argument_sorts: tuple[str, ...]
    result_sort: str


class SubsetReconstructor:
    """Separate typed subset lowering used only by adversarial fixtures."""

    def __init__(self, nodes: list[Node], assertions: list[dict[str, Any]]):
        self.nodes = nodes
        self.assertions = assertions
        self.declarations: dict[str, Declaration] = {}
        self.macros: dict[str, Node] = {}
        self.macro_dependencies: dict[str, set[str]] = collections.defaultdict(set)
        self.macro_objects: list[tuple[str, str, str]] = []
        self.direct_macro_uses: dict[str, set[str]] = collections.defaultdict(set)
        self.objects: list[tuple[str, str, tuple[str, ...]]] = []

    @staticmethod
    def list_items(node: Node, head: str) -> tuple[Node, ...] | None:
        if node.kind != "list" or not node.children:
            return None
        if node.children[0].kind != "atom" or node.children[0].symbol() != head:
            return None
        return node.children[1:]

    def expression_sort(self, node: Node, env: dict[str, str]) -> str:
        symbol = node.symbol()
        if symbol is not None:
            if node.kind == "atom" and symbol in {"true", "false"}:
                return "Bool"
            if symbol in env:
                return env[symbol]
            if symbol in self.macros:
                return "Bool"
            declaration = self.declarations.get(symbol)
            require(declaration is not None and not declaration.argument_sorts, f"reconstructor: unknown atom {symbol!r}")
            return declaration.result_sort
        require(node.kind == "list" and node.children, "reconstructor: malformed expression")
        head = node.children[0].symbol()
        require(head is not None, "reconstructor: quoted or malformed syntax head")
        args = node.children[1:]
        if head in {"!", "and", "or", "not", "=>", "xor", "=", "distinct"}:
            return "Bool"
        if head == "ite":
            require(len(args) == 3, "reconstructor: malformed ite")
            return self.expression_sort(args[1], env)
        if head == "let":
            require(len(args) == 2 and args[0].kind == "list", "reconstructor: malformed let")
            local = dict(env)
            additions: list[tuple[str, str]] = []
            for binding in args[0].children:
                require(binding.kind == "list" and len(binding.children) == 2, "reconstructor: malformed binding")
                name = binding.children[0].symbol()
                require(name is not None, "reconstructor: malformed binding name")
                additions.append((name, self.expression_sort(binding.children[1], env)))
            local.update(additions)
            return self.expression_sort(args[1], local)
        if head in self.macros and not args:
            return "Bool"
        declaration = self.declarations.get(head)
        require(declaration is not None, f"reconstructor: unknown function {head!r}")
        require(len(args) == len(declaration.argument_sorts), f"reconstructor: arity mismatch for {head!r}")
        return declaration.result_sort

    def macro_references(self, node: Node, bound: frozenset[str] = frozenset()) -> set[str]:
        symbol = node.symbol()
        if symbol is not None:
            return {symbol} if symbol in self.macros and symbol not in bound else set()
        if node.kind != "list" or not node.children:
            return set()
        head = node.children[0].symbol()
        if head == "let" and len(node.children) == 3 and node.children[1].kind == "list":
            references: set[str] = set()
            names: set[str] = set()
            for binding in node.children[1].children:
                require(binding.kind == "list" and len(binding.children) == 2, "reconstructor: malformed let")
                name = binding.children[0].symbol()
                require(name is not None, "reconstructor: malformed let name")
                names.add(name)
                references.update(self.macro_references(binding.children[1], bound))
            references.update(self.macro_references(node.children[2], bound | frozenset(names)))
            return references
        references = set()
        for child in node.children:
            references.update(self.macro_references(child, bound))
        return references

    def lower(self, node: Node, env: dict[str, str], owner: str) -> None:
        if node.kind != "list" or not node.children:
            return
        head = node.children[0].symbol()
        require(head is not None, "reconstructor: malformed head")
        args = node.children[1:]
        if head == "let":
            require(len(args) == 2 and args[0].kind == "list", "reconstructor: malformed let")
            local = dict(env)
            additions: list[tuple[str, str]] = []
            for binding in args[0].children:
                require(binding.kind == "list" and len(binding.children) == 2, "reconstructor: malformed binding")
                name = binding.children[0].symbol()
                require(name is not None, "reconstructor: malformed binding name")
                self.lower(binding.children[1], env, owner)
                additions.append((name, self.expression_sort(binding.children[1], env)))
            local.update(additions)
            self.lower(args[1], local, owner)
            return
        if head == "ite":
            require(len(args) == 3, "reconstructor: malformed ite")
            self.lower(args[0], env, owner)
            self.lower(args[1], env, owner)
            self.lower(args[2], env, owner)
            if self.expression_sort(args[1], env) != "Bool" and args[1].ast_bytes() != args[2].ast_bytes():
                self.macro_objects.append((owner, "internal_term", "term_ite_result_term"))
                self.macro_objects.append((owner, "boolean_assertion", "term_ite_then_axiom"))
                self.macro_objects.append((owner, "boolean_assertion", "term_ite_else_axiom"))
            return
        declaration = self.declarations.get(head)
        if declaration is not None:
            for child, expected_sort in zip(args, declaration.argument_sorts, strict=True):
                self.lower(child, env, owner)
                if expected_sort == "Bool" and child.kind == "list":
                    child_head = child.children[0].symbol() if child.children else None
                    if child_head not in {None, "!"}:
                        self.macro_objects.append((owner, "internal_term", "bool_materialization_term"))
                        self.macro_objects.append((owner, "boolean_assertion", "bool_materialization_axiom"))
            return
        for child in args:
            self.lower(child, env, owner)

    def run(self) -> collections.Counter[tuple[str, str, tuple[str, ...]]]:
        assertion_nodes: list[Node] = []
        for node in self.nodes:
            head = node.syntax_head()
            if head == b"declare-fun":
                require(node.kind == "list" and len(node.children) == 4, "reconstructor: malformed declaration")
                name = node.children[1].symbol()
                require(name is not None and node.children[2].kind == "list", "reconstructor: malformed declaration")
                argument_sorts = tuple(
                    child.symbol() or "" for child in node.children[2].children
                )
                result_sort = node.children[3].symbol()
                require(result_sort is not None and all(argument_sorts), "reconstructor: malformed sort")
                self.declarations[name] = Declaration(argument_sorts, result_sort)
            elif head == b"define-fun":
                require(node.kind == "list" and len(node.children) == 5, "reconstructor: malformed macro")
                name = node.children[1].symbol()
                require(name is not None, "reconstructor: malformed macro name")
                self.macros[name] = node.children[4]
            elif head == b"assert":
                require(node.kind == "list" and len(node.children) == 2, "reconstructor: malformed assertion")
                assertion_nodes.append(node.children[1])

        for name, body in self.macros.items():
            self.macro_dependencies[name] = self.macro_references(body)
            self.lower(body, {}, name)
        for ordinal, body in enumerate(assertion_nodes):
            assertion_id = f"assertion-{ordinal:06}"
            self.direct_macro_uses[assertion_id] = self.macro_references(body)
            self.lower(body, {}, assertion_id)
            self.objects.append(("boolean_assertion", "source_assertion_root", (assertion_id,)))

        macro_origins: dict[str, set[str]] = collections.defaultdict(set)
        for assertion_id, roots in self.direct_macro_uses.items():
            pending = list(roots)
            seen: set[str] = set()
            while pending:
                macro = pending.pop()
                if macro in seen:
                    continue
                seen.add(macro)
                macro_origins[macro].add(assertion_id)
                pending.extend(self.macro_dependencies.get(macro, set()))

        normalized: collections.Counter[tuple[str, str, tuple[str, ...]]] = collections.Counter()
        for owner, kind, transform in self.macro_objects:
            origins = (
                tuple(sorted(macro_origins[owner]))
                if owner in self.macros
                else (owner,)
            )
            normalized[(kind, transform, origins)] += 1
        for item in self.objects:
            normalized[item] += 1
        all_assertion_ids = tuple(assertion["id"] for assertion in self.assertions)
        if all_assertion_ids:
            normalized[("internal_term", "internal_bool_true_term", all_assertion_ids)] += 1
            normalized[("internal_term", "internal_bool_false_term", all_assertion_ids)] += 1
        return normalized


def reconstruct_supported_objects(
    nodes: list[Node], assertions: list[dict[str, Any]]
) -> collections.Counter[tuple[str, str, tuple[str, ...]]]:
    return SubsetReconstructor(nodes, assertions).run()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument(
        "--reconstruct",
        action="store_true",
        help="independently lower the supported adversarial fixture subset",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = validate_ledger(args.source, args.ledger, reconstruct=args.reconstruct)
    except LineageError as error:
        print(f"assertion-lineage verification failed: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
