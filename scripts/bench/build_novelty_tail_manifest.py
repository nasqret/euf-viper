#!/usr/bin/env python3
"""Build a verified, deterministic novelty-tail manifest from QF_UF JSONL.

The input is a full hashed QF_UF manifest.  Every input row is validated, and
every selected source is checked against its declared byte count, SHA-256, and
top-level SMT-LIB ``set-info :status`` command before any output is replaced.
Selection order is explicit: rows are emitted in request order, never input or
lexicographic order.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple, Sequence


SCHEMA_VERSION = "euf-viper.novelty-tail-selection-report.v1"
CANONICAL_DEFICIT_SELECTION = "shared-z3-yices-deficit-22"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
VALID_STATUSES = frozenset({"sat", "unsat"})
REQUIRED_FIELDS = frozenset(
    {"id", "logic", "path", "relative_path", "status", "bytes", "sha256"}
)


class SelectionError(ValueError):
    """Raised when an input cannot be selected and verified exactly."""


class ExpectedSource(NamedTuple):
    relative_path: str
    status: str
    bytes: int
    sha256: str


class ManifestRecord(NamedTuple):
    line_number: int
    row: dict[str, Any]


class VerifiedRecord(NamedTuple):
    record: ManifestRecord
    source_path: Path
    source_status: str


# This is the frozen 60-second deficit solved by both Z3 and Yices2 but missed
# by euf-viper: six SAT and sixteen UNSAT sources.  Binding bytes and hashes as
# well as paths/statuses prevents a same-name corpus replacement from silently
# redefining the named selection.
SHARED_Z3_YICES_DEFICIT_22: tuple[ExpectedSource, ...] = (
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/"
        "QF_UF_firewire_tree.5.prop1_ab_reg_max.smt2",
        "unsat",
        4_642_043,
        "a62e4209ebd2db1aef56631878280ced1b73438fd6b8eab8c26b4ce575d5842f",
    ),
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/"
        "QF_UF_firewire_tree.5.prop2_ab_reg_max.smt2",
        "sat",
        4_643_062,
        "7f9f8c05bf5fa9ea98eaa95d1c931cbb220ce2a357e680c37047099e8e1b45d5",
    ),
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/QF_UF_frogs.2.prop1_ab_br_max.smt2",
        "sat",
        1_146_846,
        "6db2ccdeecb6e2ef248596dc6b85a3bba3da39aa5dcdde859d5c1e05916417cc",
    ),
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/QF_UF_frogs.3.prop1_ab_br_max.smt2",
        "sat",
        959_808,
        "19018c9d99e99c63d9b85d18f120ba24c543662e587846b0370e3fef23dc0517",
    ),
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/QF_UF_frogs.5.prop1_ab_br_max.smt2",
        "sat",
        718_405,
        "71bf533dbe0469deeefae511840df695c82a4562b90e0f8289088bca34533331",
    ),
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/QF_UF_h_TicTacToe_ab_cti_max.smt2",
        "sat",
        1_204_641,
        "ba5726941ca08fdde0cd93fbe57afd1b062e07e9c81b06350496b715c5dda035",
    ),
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/QF_UF_hanoi.3.prop1_ab_br_max.smt2",
        "sat",
        922_231,
        "48c2285c877d8d4050524944de2edce502de2312f7d9249395523310051fd7b7",
    ),
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/QF_UF_sokoban.2.prop1_ab_br_max.smt2",
        "unsat",
        2_264_612,
        "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112",
    ),
    ExpectedSource(
        "QF_UF/2018-Goel-hwbench/QF_UF_sokoban.3.prop1_ab_br_max.smt2",
        "unsat",
        1_391_629,
        "0cdaf516495f28d82f2282338487c472ba2db91a23865e7cfd7fffa4aed2f70b",
    ),
    ExpectedSource(
        "QF_UF/PEQ/PEQ012_size6.smt2",
        "unsat",
        42_150,
        "b3ef5c792f5df9f55bddc92062262b75b3f53aeae51609cde0b301c8f973b139",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen001.smt2",
        "unsat",
        6_013_419,
        "6e9ea0786a672c467f853bf8964283bbdc53c2b51c41e0b0e6fc1fbd8ba34be0",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen002.smt2",
        "unsat",
        6_013_089,
        "05295ac0b0b9d7757b3c2b68184ab0504fc90d56582fb97cc891b8a990bf23ac",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen003.smt2",
        "unsat",
        6_013_964,
        "5143c7d94d43c5dc077fb8c92dcc7bce4c672c79c03dcbeef901dd8a8532f5a8",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen004.smt2",
        "unsat",
        6_013_634,
        "5d487c7da1e60eb8b28ba24d8dc7bc79f40915318ec62d38b44771420d30fc8b",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen005.smt2",
        "unsat",
        6_012_142,
        "42ec7341e7b5294e44042572702f6346a990b151fe47d48deb6595d679645ed5",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen007.smt2",
        "unsat",
        6_014_935,
        "a6c8c7c8a2a8d1b67574674ea78570977245a728743eca52768b52f9ef165675",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk001.smt2",
        "unsat",
        6_010_211,
        "175547f0f09d2238085f5621dfede32190411257315b215abcc2857d96d7e78f",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk002.smt2",
        "unsat",
        6_011_031,
        "dbcbdc19201c2a39ce2839becb61f4f4191ff1e9738396d894da962b33611c2b",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk003.smt2",
        "unsat",
        6_013_082,
        "a9f9ba690dc07f211035fc43da019da8baff81c6366d51467fd64fff016d9514",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk004.smt2",
        "unsat",
        6_013_902,
        "72b5e5242f0de636f031840d9e04e4d1cf55203ac1d0653c10e3576d7561e1b8",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk005.smt2",
        "unsat",
        6_012_398,
        "d0c7fd4c118d0f4eafec0851bdf82e52508c08ea6c12a962f1e48045aacdd5c8",
    ),
    ExpectedSource(
        "QF_UF/QG-classification/qg7/iso_icl_nogen_sk007.smt2",
        "unsat",
        6_012_899,
        "fe3693b6f59618083ca4734c299a200c4cfd5b3edcd15457add15e04663781f7",
    ),
)

NAMED_SELECTIONS: dict[str, tuple[ExpectedSource, ...]] = {
    CANONICAL_DEFICIT_SELECTION: SHARED_Z3_YICES_DEFICIT_22,
}
NAMED_SELECTION_ALIASES = {
    "current-shared-z3-yices-deficit": CANONICAL_DEFICIT_SELECTION,
    "z3-yices-shared-deficit-22": CANONICAL_DEFICIT_SELECTION,
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number {value}")

    return json.loads(
        text,
        object_pairs_hook=_strict_object,
        parse_constant=reject_constant,
    )


def validate_relative_path(value: object, *, context: str = "path") -> str:
    if type(value) is not str or not value:
        raise SelectionError(f"{context} must be a nonempty string")
    if "\x00" in value:
        raise SelectionError(f"{context} contains NUL")
    if "\\" in value:
        raise SelectionError(f"{context} must use POSIX separators: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or pure.as_posix() != value:
        raise SelectionError(
            f"{context} is not a canonical relative POSIX path: {value!r}"
        )
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise SelectionError(f"{context} is not traversal-safe: {value!r}")
    if len(pure.parts) < 3 or pure.parts[0] != "QF_UF":
        raise SelectionError(f"{context} is not below QF_UF/: {value!r}")
    if pure.suffix != ".smt2":
        raise SelectionError(f"{context} is not an .smt2 path: {value!r}")
    return value


def _validate_declared_path(
    value: object, relative_path: str, *, context: str
) -> str:
    if type(value) is not str or not value:
        raise SelectionError(f"{context} must be a nonempty string")
    if "\x00" in value or "\\" in value:
        raise SelectionError(f"{context} must be a POSIX path without NUL")
    pure = PurePosixPath(value)
    if pure.as_posix() != value:
        raise SelectionError(f"{context} is not a canonical POSIX path: {value!r}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise SelectionError(f"{context} is not traversal-safe: {value!r}")
    relative_parts = PurePosixPath(relative_path).parts
    if tuple(pure.parts[-len(relative_parts) :]) != relative_parts:
        raise SelectionError(
            f"{context} does not end in relative_path {relative_path!r}"
        )
    return value


def _validated_manifest_row(value: Any, line_number: int) -> dict[str, Any]:
    context = f"manifest line {line_number}"
    if not isinstance(value, dict):
        raise SelectionError(f"{context} must be a JSON object")
    missing = sorted(REQUIRED_FIELDS - value.keys())
    if missing:
        raise SelectionError(f"{context} is missing fields: {', '.join(missing)}")

    identifier = value["id"]
    if type(identifier) not in {int, str} or identifier == "":
        raise SelectionError(f"{context} has invalid id {identifier!r}")
    if value["logic"] != "QF_UF":
        raise SelectionError(f"{context} has non-QF_UF logic {value['logic']!r}")
    status_value = value["status"]
    if type(status_value) is not str or status_value not in VALID_STATUSES:
        raise SelectionError(f"{context} has invalid status {status_value!r}")
    byte_count = value["bytes"]
    if type(byte_count) is not int or byte_count < 0:
        raise SelectionError(f"{context} has invalid byte count {byte_count!r}")
    digest = value["sha256"]
    if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
        raise SelectionError(f"{context} has invalid lowercase SHA-256")

    relative_path = validate_relative_path(
        value["relative_path"], context=f"{context} relative_path"
    )
    declared_path = _validate_declared_path(
        value["path"], relative_path, context=f"{context} path"
    )
    row = dict(value)
    row["relative_path"] = relative_path
    row["path"] = declared_path
    return row


def load_hashed_manifest(path: Path) -> tuple[list[ManifestRecord], bytes]:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SelectionError(f"cannot read manifest {path}: {error}") from error
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SelectionError(f"manifest is not UTF-8: {error}") from error
    lines = text.splitlines()
    if not lines:
        raise SelectionError("manifest has no records")

    records: list[ManifestRecord] = []
    seen_ids: dict[str, int] = {}
    seen_relative_paths: dict[str, int] = {}
    seen_declared_paths: dict[str, int] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise SelectionError(f"manifest line {line_number} is blank")
        try:
            value = strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as error:
            raise SelectionError(
                f"manifest line {line_number} is malformed JSON: {error}"
            ) from error
        row = _validated_manifest_row(value, line_number)
        identifier_key = json.dumps(
            row["id"], ensure_ascii=True, separators=(",", ":")
        )
        for field, key, seen in (
            ("id", identifier_key, seen_ids),
            ("relative_path", row["relative_path"], seen_relative_paths),
            ("path", row["path"], seen_declared_paths),
        ):
            previous = seen.get(key)
            if previous is not None:
                raise SelectionError(
                    f"manifest line {line_number} duplicates {field} from "
                    f"line {previous}: {row[field]!r}"
                )
            seen[key] = line_number
        records.append(ManifestRecord(line_number, row))
    return records, raw


def validate_requested_paths(paths: Sequence[str]) -> list[str]:
    if not paths:
        raise SelectionError("at least one relative path must be requested")
    validated: list[str] = []
    first_ordinal: dict[str, int] = {}
    for ordinal, value in enumerate(paths, start=1):
        path = validate_relative_path(value, context=f"requested path {ordinal}")
        previous = first_ordinal.get(path)
        if previous is not None:
            raise SelectionError(
                f"requested path {ordinal} duplicates requested path {previous}: "
                f"{path!r}"
            )
        first_ordinal[path] = ordinal
        validated.append(path)
    return validated


def read_requested_paths(path: Path) -> list[str]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise SelectionError(f"cannot read requested paths file {path}: {error}") from error
    lines = text.splitlines()
    if not lines:
        raise SelectionError(f"requested paths file {path} is empty")
    if any(not line for line in lines):
        raise SelectionError(f"requested paths file {path} contains a blank line")
    return validate_requested_paths(lines)


def canonical_selection_name(name: str) -> str:
    canonical = NAMED_SELECTION_ALIASES.get(name, name)
    if canonical not in NAMED_SELECTIONS:
        available = ", ".join(sorted(NAMED_SELECTIONS))
        raise SelectionError(f"unknown named selection {name!r}; available: {available}")
    return canonical


def select_records(
    records: Sequence[ManifestRecord],
    requested_paths: Sequence[str],
    *,
    expected: Sequence[ExpectedSource] | None = None,
) -> list[ManifestRecord]:
    requested = validate_requested_paths(requested_paths)
    index = {record.row["relative_path"]: record for record in records}
    unknown = [path for path in requested if path not in index]
    if unknown:
        raise SelectionError("requested paths are absent from manifest: " + ", ".join(unknown))
    selected = [index[path] for path in requested]

    if expected is not None:
        if [item.relative_path for item in expected] != requested:
            raise SelectionError("named selection definition does not match requested order")
        for item, record in zip(expected, selected):
            row = record.row
            for field, wanted in (
                ("status", item.status),
                ("bytes", item.bytes),
                ("sha256", item.sha256),
            ):
                if row[field] != wanted:
                    raise SelectionError(
                        f"named selection binding mismatch for {item.relative_path!r}: "
                        f"{field} expected {wanted!r}, got {row[field]!r}"
                    )
    return selected


def _finish_top_level_command(
    tokens: list[tuple[str, str]],
    token_count: int,
    nested: bool,
    *,
    statuses: list[str],
    logics: list[str],
) -> None:
    if not tokens or tokens[0] != ("atom", "set-info"):
        if tokens and tokens[0] == ("atom", "set-logic"):
            if nested or token_count != 2 or len(tokens) < 2 or tokens[1][0] != "atom":
                raise SelectionError("malformed top-level set-logic command")
            logics.append(tokens[1][1])
        return
    if len(tokens) < 2 or tokens[1] != ("atom", ":status"):
        return
    if nested or token_count != 3 or len(tokens) < 3 or tokens[2][0] != "atom":
        raise SelectionError("malformed top-level set-info :status command")
    statuses.append(tokens[2][1])


def extract_qf_uf_status(source: bytes) -> str:
    """Return the unique top-level status after a complete lexical scan."""

    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SelectionError(f"SMT-LIB source is not UTF-8: {error}") from error

    statuses: list[str] = []
    logics: list[str] = []
    depth = 0
    tokens: list[tuple[str, str]] = []
    token_count = 0
    nested = False
    index = 0
    length = len(text)

    def add_token(kind: str, value: str) -> None:
        nonlocal token_count
        if depth == 0:
            raise SelectionError("SMT-LIB token outside a top-level command")
        if depth == 1:
            token_count += 1
            if len(tokens) < 3:
                tokens.append((kind, value))

    while index < length:
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == ";":
            newline = text.find("\n", index + 1)
            index = length if newline < 0 else newline + 1
            continue
        if char == "(":
            if depth == 0:
                tokens = []
                token_count = 0
                nested = False
            elif depth == 1:
                nested = True
            depth += 1
            index += 1
            continue
        if char == ")":
            if depth == 0:
                raise SelectionError("SMT-LIB has an unmatched closing parenthesis")
            if depth == 1:
                _finish_top_level_command(
                    tokens,
                    token_count,
                    nested,
                    statuses=statuses,
                    logics=logics,
                )
            depth -= 1
            index += 1
            continue
        if char == '"':
            index += 1
            value: list[str] = []
            while index < length:
                if text[index] != '"':
                    value.append(text[index])
                    index += 1
                    continue
                if index + 1 < length and text[index + 1] == '"':
                    value.append('"')
                    index += 2
                    continue
                index += 1
                add_token("string", "".join(value))
                break
            else:
                raise SelectionError("SMT-LIB has an unterminated string")
            continue
        if char == "|":
            closing = text.find("|", index + 1)
            if closing < 0:
                raise SelectionError("SMT-LIB has an unterminated quoted symbol")
            add_token("quoted", text[index + 1 : closing])
            index = closing + 1
            continue

        start = index
        while index < length and not text[index].isspace() and text[index] not in "();":
            if text[index] in {'"', "|"}:
                raise SelectionError("SMT-LIB has a quote inside an unquoted token")
            index += 1
        if index == start:
            raise SelectionError(f"cannot tokenize SMT-LIB at character {index}")
        add_token("atom", text[start:index])

    if depth != 0:
        raise SelectionError("SMT-LIB has unbalanced parentheses")
    if len(logics) != 1 or logics[0] != "QF_UF":
        raise SelectionError(
            f"SMT-LIB must declare exactly one QF_UF logic, got {logics!r}"
        )
    if len(statuses) != 1 or statuses[0] not in VALID_STATUSES:
        raise SelectionError(
            f"SMT-LIB must declare exactly one sat/unsat status, got {statuses!r}"
        )
    return statuses[0]


def _resolve_source_path(
    record: ManifestRecord,
    *,
    source_root: Path | None,
    repository_root: Path,
) -> Path:
    relative = PurePosixPath(record.row["relative_path"])
    if source_root is not None:
        try:
            root = Path(source_root).expanduser().resolve(strict=True)
        except OSError as error:
            raise SelectionError(f"cannot resolve source root {source_root}: {error}") from error
        if not root.is_dir():
            raise SelectionError(f"source root is not a directory: {root}")
        candidate = root.joinpath(*relative.parts)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise SelectionError(
                f"missing source for {relative.as_posix()!r}: {candidate}: {error}"
            ) from error
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise SelectionError(
                f"source escapes source root for {relative.as_posix()!r}: {resolved}"
            ) from error
    else:
        declared = Path(record.row["path"])
        candidate = declared if declared.is_absolute() else repository_root / declared
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise SelectionError(
                f"missing source for {relative.as_posix()!r}: {candidate}: {error}"
            ) from error
        if not declared.is_absolute():
            try:
                resolved.relative_to(repository_root.resolve(strict=True))
            except (OSError, ValueError) as error:
                raise SelectionError(
                    f"relative declared source escapes repository root: {resolved}"
                ) from error
    if not resolved.is_file():
        raise SelectionError(f"source is not a regular file: {resolved}")
    return resolved


def _read_stable_source(path: Path, relative_path: str) -> bytes:
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise SelectionError(f"source is not a regular file: {path}")
            source = handle.read()
            after = os.fstat(handle.fileno())
    except OSError as error:
        raise SelectionError(f"cannot read source {relative_path!r}: {error}") from error
    fingerprint_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    fingerprint_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if fingerprint_before != fingerprint_after or len(source) != after.st_size:
        raise SelectionError(f"source changed while being read: {relative_path!r}")
    return source


def verify_selected_sources(
    selected: Sequence[ManifestRecord],
    *,
    source_root: Path | None = None,
    repository_root: Path = REPOSITORY_ROOT,
) -> list[VerifiedRecord]:
    verified: list[VerifiedRecord] = []
    seen_paths: dict[Path, str] = {}
    seen_inodes: dict[tuple[int, int], str] = {}
    for record in selected:
        row = record.row
        relative_path = row["relative_path"]
        source_path = _resolve_source_path(
            record,
            source_root=source_root,
            repository_root=Path(repository_root).expanduser().resolve(),
        )
        source = _read_stable_source(source_path, relative_path)
        actual_bytes = len(source)
        if actual_bytes != row["bytes"]:
            raise SelectionError(
                f"source byte-count mismatch for {relative_path!r}: "
                f"expected {row['bytes']}, got {actual_bytes}"
            )
        actual_sha256 = sha256_bytes(source)
        if actual_sha256 != row["sha256"]:
            raise SelectionError(
                f"source SHA-256 mismatch for {relative_path!r}: "
                f"expected {row['sha256']}, got {actual_sha256}"
            )
        try:
            source_status = extract_qf_uf_status(source)
        except SelectionError as error:
            raise SelectionError(f"invalid source {relative_path!r}: {error}") from error
        if source_status != row["status"]:
            raise SelectionError(
                f"source status mismatch for {relative_path!r}: "
                f"manifest {row['status']!r}, source {source_status!r}"
            )

        source_stat = source_path.stat()
        previous = seen_paths.get(source_path)
        if previous is not None:
            raise SelectionError(
                f"selected sources {previous!r} and {relative_path!r} resolve "
                f"to the same path"
            )
        inode = (source_stat.st_dev, source_stat.st_ino)
        previous = seen_inodes.get(inode)
        if previous is not None:
            raise SelectionError(
                f"selected sources {previous!r} and {relative_path!r} are the same file"
            )
        seen_paths[source_path] = relative_path
        seen_inodes[inode] = relative_path
        verified.append(VerifiedRecord(record, source_path, source_status))
    return verified


def _normalized_rebase_root(value: Path | None) -> PurePosixPath | None:
    if value is None:
        return None
    raw = Path(value).expanduser().as_posix()
    if "\x00" in raw or "\\" in raw:
        raise SelectionError("rebase root must be a POSIX path without NUL")
    root = PurePosixPath(raw)
    if not root.is_absolute():
        raise SelectionError("rebase root must be absolute")
    if any(part in {".", ".."} for part in root.parts):
        raise SelectionError("rebase root must not contain traversal components")
    return root


def serialize_selected_manifest(
    verified: Sequence[VerifiedRecord],
    *,
    path_mode: str,
    rebase_root: Path | None = None,
) -> bytes:
    if path_mode not in {"portable", "rebased"}:
        raise SelectionError(f"unknown output path mode {path_mode!r}")
    root = _normalized_rebase_root(rebase_root)
    if path_mode == "portable" and root is not None:
        raise SelectionError("portable output cannot have a rebase root")
    if path_mode == "rebased" and root is None:
        raise SelectionError("rebased output requires an absolute rebase root")

    chunks: list[bytes] = []
    for item in verified:
        row = dict(item.record.row)
        relative_path = row["relative_path"]
        row["path"] = (
            relative_path
            if root is None
            else (root / PurePosixPath(relative_path)).as_posix()
        )
        chunks.append(canonical_json_bytes(row))
    return b"".join(chunks)


def _selection_definition_payload(
    requested_paths: Sequence[str], expected: Sequence[ExpectedSource] | None
) -> object:
    if expected is None:
        return list(requested_paths)
    return [
        {
            "bytes": item.bytes,
            "relative_path": item.relative_path,
            "sha256": item.sha256,
            "status": item.status,
        }
        for item in expected
    ]


def build_selection_artifacts(
    manifest_path: Path,
    *,
    requested_paths: Sequence[str] | None = None,
    selection_name: str | None = None,
    source_root: Path | None = None,
    repository_root: Path = REPOSITORY_ROOT,
    path_mode: str = "portable",
    rebase_root: Path | None = None,
) -> tuple[bytes, bytes, dict[str, Any]]:
    if (requested_paths is None) == (selection_name is None):
        raise SelectionError("choose exactly one named or explicit selection")

    expected: tuple[ExpectedSource, ...] | None = None
    canonical_name: str | None = None
    if selection_name is not None:
        canonical_name = canonical_selection_name(selection_name)
        expected = NAMED_SELECTIONS[canonical_name]
        requested = [item.relative_path for item in expected]
    else:
        assert requested_paths is not None
        requested = validate_requested_paths(requested_paths)

    records, input_bytes = load_hashed_manifest(manifest_path)
    selected = select_records(records, requested, expected=expected)
    verified = verify_selected_sources(
        selected,
        source_root=source_root,
        repository_root=repository_root,
    )
    output_bytes = serialize_selected_manifest(
        verified,
        path_mode=path_mode,
        rebase_root=rebase_root,
    )
    normalized_root = _normalized_rebase_root(rebase_root)
    statuses = Counter(item.source_status for item in verified)
    definition = _selection_definition_payload(requested, expected)
    selection_hash = sha256_bytes(canonical_json_bytes(definition))
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "selection": {
            "mode": "named" if canonical_name is not None else "explicit",
            "name": canonical_name,
            "definition_sha256": selection_hash,
            "relative_paths": list(requested),
        },
        "path_rewrite": {
            "mode": path_mode,
            "rebase_root": (
                normalized_root.as_posix() if normalized_root is not None else None
            ),
        },
        "counts": {
            "input_records": len(records),
            "selected_records": len(verified),
            "sat": statuses.get("sat", 0),
            "unsat": statuses.get("unsat", 0),
            "source_bytes": sum(item.record.row["bytes"] for item in verified),
        },
        "hashes": {
            "input_manifest_sha256": sha256_bytes(input_bytes),
            "output_manifest_sha256": sha256_bytes(output_bytes),
            "selection_definition_sha256": selection_hash,
        },
        "verification": {
            "logic": "QF_UF",
            "size": "verified_against_source",
            "sha256": "verified_against_source",
            "status": "verified_against_top_level_set_info",
            "source_resolution": (
                "source_root_relative_path"
                if source_root is not None
                else "manifest_declared_path"
            ),
        },
        "records": [
            {
                "bytes": item.record.row["bytes"],
                "id": item.record.row["id"],
                "manifest_line": item.record.line_number,
                "ordinal": ordinal,
                "path": (
                    item.record.row["relative_path"]
                    if normalized_root is None
                    else (
                        normalized_root
                        / PurePosixPath(item.record.row["relative_path"])
                    ).as_posix()
                ),
                "relative_path": item.record.row["relative_path"],
                "sha256": item.record.row["sha256"],
                "status": item.source_status,
            }
            for ordinal, item in enumerate(verified)
        ],
    }
    report_bytes = canonical_json_bytes(report)
    return output_bytes, report_bytes, report


def _stage_atomic(path: Path, data: bytes) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_dir():
        raise SelectionError(f"output path is a directory: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _path_identity(path: Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def write_artifacts_atomic(
    manifest_out: Path,
    report_out: Path,
    manifest_bytes: bytes,
    report_bytes: bytes,
) -> None:
    manifest_out = Path(manifest_out)
    report_out = Path(report_out)
    if _path_identity(manifest_out) == _path_identity(report_out):
        raise SelectionError("manifest and report outputs must be different files")

    staged: list[tuple[Path, Path]] = []
    try:
        staged.append((_stage_atomic(manifest_out, manifest_bytes), manifest_out))
        staged.append((_stage_atomic(report_out, report_bytes), report_out))
        for temporary, destination in staged:
            os.replace(temporary, destination)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)


def _validate_named_selections() -> None:
    for name, sources in NAMED_SELECTIONS.items():
        paths = validate_requested_paths([item.relative_path for item in sources])
        if any(item.status not in VALID_STATUSES for item in sources):
            raise RuntimeError(f"named selection {name!r} has an invalid status")
        if any(item.bytes < 0 or SHA256_RE.fullmatch(item.sha256) is None for item in sources):
            raise RuntimeError(f"named selection {name!r} has invalid source identity")
        if paths != [item.relative_path for item in sources]:
            raise RuntimeError(f"named selection {name!r} is not canonical")
    deficit = NAMED_SELECTIONS[CANONICAL_DEFICIT_SELECTION]
    counts = Counter(item.status for item in deficit)
    if len(deficit) != 22 or counts != Counter({"unsat": 16, "sat": 6}):
        raise RuntimeError("the shared Z3/Yices deficit must remain 22 = 6 SAT + 16 UNSAT")


_validate_named_selections()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="full hashed QF_UF JSONL manifest")
    parser.add_argument("--out", "--manifest-out", dest="manifest_out", type=Path, required=True)
    parser.add_argument(
        "--report-out", "--selection-report", dest="report_out", type=Path, required=True
    )
    parser.add_argument(
        "--selection",
        help="named checked selection (canonical: shared-z3-yices-deficit-22)",
    )
    parser.add_argument(
        "--relative-path", "--path", dest="relative_paths", action="append", default=[]
    )
    parser.add_argument("--paths-file", "--relative-paths-file", type=Path)
    parser.add_argument(
        "--source-root",
        "--corpus-root",
        dest="source_root",
        type=Path,
        help="resolve sources as ROOT/relative_path and ignore host-local row paths",
    )
    parser.add_argument(
        "--repository-root",
        "--repo-root",
        dest="repository_root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="base for relative input row paths when --source-root is absent",
    )
    parser.add_argument("--path-mode", choices=("portable", "rebased"))
    parser.add_argument(
        "--rebase-root",
        "--output-corpus-root",
        dest="rebase_root",
        type=Path,
        help="absolute root written before every output relative_path",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    selection_sources = sum(
        bool(value)
        for value in (args.selection, args.relative_paths, args.paths_file)
    )
    if selection_sources != 1:
        parser.error(
            "choose exactly one of --selection, repeated --relative-path, or --paths-file"
        )
    identities = {
        _path_identity(args.manifest),
        _path_identity(args.manifest_out),
        _path_identity(args.report_out),
    }
    if len(identities) != 3:
        parser.error("input manifest and both outputs must be different files")

    path_mode = args.path_mode
    if path_mode is None:
        path_mode = "rebased" if args.rebase_root is not None else "portable"
    if path_mode == "portable" and args.rebase_root is not None:
        parser.error("--path-mode portable cannot be combined with --rebase-root")
    if path_mode == "rebased" and args.rebase_root is None:
        parser.error("--path-mode rebased requires --rebase-root")

    try:
        explicit_paths = (
            read_requested_paths(args.paths_file)
            if args.paths_file is not None
            else (args.relative_paths or None)
        )
        manifest_bytes, report_bytes, report = build_selection_artifacts(
            args.manifest,
            requested_paths=explicit_paths,
            selection_name=args.selection,
            source_root=args.source_root,
            repository_root=args.repository_root,
            path_mode=path_mode,
            rebase_root=args.rebase_root,
        )
        write_artifacts_atomic(
            args.manifest_out,
            args.report_out,
            manifest_bytes,
            report_bytes,
        )
    except (SelectionError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    counts = report["counts"]
    hashes = report["hashes"]
    print(
        f"manifest={args.manifest_out} report={args.report_out} "
        f"selected={counts['selected_records']} sat={counts['sat']} "
        f"unsat={counts['unsat']} "
        f"manifest_sha256={hashes['output_manifest_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
