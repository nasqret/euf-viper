#!/usr/bin/env python3
"""Derive the current T6 qg7 confirmation manifest from frozen P0 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, NamedTuple


SCHEMA = "euf-viper.t6-theory-dag-manifest.v2"
P0_REVISION = "30828a4f0c1e7e478a9c6f406ccb245eeefc4961"
P0_AUDIT_SHA256 = (
    "2458b01872a290c89f715a277dfd41e2c28091fc649925c9acbfefeb6e72686a"
)
P0_AUDIT_MANIFEST_SHA256 = (
    "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
)
LOCAL_MANIFEST_SHA256 = (
    "597f8ee5dad0d4e55d407a18cbd48d727a70b6b86590020863cd2145e73eac0a"
)
PROJECTION_TEMPLATE_SHA256 = (
    "198b0824c8847f249cc0c4405dcdea4e9b3101979c0b437cdeebd26165892476"
)
P0_BINARY_SHA256 = (
    "edcf8d1af94e9eb937fb5e073ffd08de1738bb369409484b5e067980597ba576"
)
P0_OBSERVATION_PROVENANCE_SHA256 = (
    "eecdc97e95cbbde241e4a968ed8a330e4eece4574e056ea7008e1b0aaa5159c6"
)
EXPECTED_CORPUS_SOURCES = 7_503
EXPECTED_SELECTED_SOURCES = 12
MINIMUM_SOURCE_BYTES = 6_000_000
MINIMUM_PARENTHESES = 80_000
PARENT_GATE_POPULATION = 10
PARENT_GATE_MINIMUM = 8
CORPUS_DESCRIPTOR_PREFIX = "QF_UF/"
CORPUS_ARCHIVE_MD5 = "e185bc80a80116bcfea116df190f87d2"
CORPUS_SOURCE_DOI = "10.5281/zenodo.16740866"
CORPUS_SOURCE_URL = (
    "https://zenodo.org/api/records/16740866/files/QF_UF.tar.zst/content"
)
SOLVED_RESULTS = frozenset({"sat", "unsat"})
RESULTS = SOLVED_RESULTS | {"timeout", "unknown", "error", "invalid"}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
QG7_PREFIX = "QF_UF/QG-classification/qg7/"
SOLVERS = (
    "euf-viper",
    "cvc5",
    "opensmt",
    "yices2",
    "z3-default",
    "z3-sat-euf",
)
BASELINE_SOLVERS = SOLVERS[1:]
BUDGETS = (2.0, 60.0)
SOLVER_BINARY_SHA256S = {
    "cvc5": "7562a8b0b835e3eaad5f1a7b4616cd762350cf567b6be03d7e8ee24fa5ced5ee",
    "euf-viper": P0_BINARY_SHA256,
    "opensmt": "b7899e9aff299026d3251df7a28f51f56d8bd1e5b0fd7be11bcc72c4f2803a98",
    "yices2": "eab7efbff2a6f0cce2fcd2c25cb4a94e0e048c902d8ef9e6fd7d7989aa54c501",
    "z3-default": "796e7c7b05446f14065303082cc026e0383b1321cf8a1d88ec67b693a26c27ca",
    "z3-sat-euf": "796e7c7b05446f14065303082cc026e0383b1321cf8a1d88ec67b693a26c27ca",
}
OBSERVATION_FIELDS = frozenset(
    {
        "budget_s",
        "carried_forward",
        "origin_budget_s",
        "relative_path",
        "result",
        "solver_id",
        "source_lock_sha256",
        "source_raw_sha256",
        "source_record_sha256s",
    }
)
CORPUS_FIELDS = frozenset(
    {
        "archive_md5",
        "bytes",
        "id",
        "logic",
        "path",
        "relative_path",
        "sha256",
        "source_doi",
        "source_url",
        "status",
    }
)

ARM_A = "tree expansion with globally identified source atoms and no compound-gate sharing"
ARM_B = "generic source-DAG hash-consing with signed edges and no theory rewriting"
ARM_C = "B after typed union of positive equality atoms in unconditional assertion roots"
ARM_D = "B after typed congruence closure seeded only by the C root unions"
ENCODING = (
    "signed-edge n-ary Tseitin v1: not is polarity; and/or use n binary "
    "implications plus one length-(n+1) clause; all-equal iff uses 2(n-1) "
    "ternary plus two length-(n+1) clauses; ite uses four ternary clauses; "
    "each assertion adds one unit; constants share one fixed-true variable"
)
QUALIFYING_SOURCE_RULE = (
    "D reduction from A is at least 250000 ppm and exceeds both B and C "
    "reductions from A by at least 50000 ppm"
)
TWO_WATCH_RULE = (
    "two entries for every clause of length at least two; units use no ordinary "
    "watch entries"
)


class DerivationError(ValueError):
    """Raised when evidence does not satisfy the frozen derivation contract."""


class ImmutableFile(NamedTuple):
    """One stable file snapshot used for both hashing and parsing."""

    data: bytes
    sha256: str
    identity: tuple[int, int]


class PhysicalSource(NamedTuple):
    """Verified bytes and structural evidence for one selected source."""

    source_bytes: int
    source_sha256: str
    metrics: dict[str, int]


class P0Selection(NamedTuple):
    """Fully checked audit/corpus selection before physical source verification."""

    index: dict[tuple[float, str, str], dict[str, Any]]
    corpus_by_path: dict[str, dict[str, Any]]
    selected_paths: list[str]


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DerivationError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonfinite_json(value: str) -> None:
    raise DerivationError(f"non-finite JSON number {value!r}")


def parse_json_bytes(data: bytes, context: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_json,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DerivationError(f"cannot parse {context}: {error}") from error


def _snapshot_descriptor(descriptor: int, context: str) -> ImmutableFile:
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise DerivationError(f"{context} is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise DerivationError(f"cannot read {context}: {error}") from error
    before_state = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_state = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    data = b"".join(chunks)
    if before_state != after_state or len(data) != after.st_size:
        raise DerivationError(f"{context} changed while it was being read")
    return ImmutableFile(
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        identity=(after.st_dev, after.st_ino),
    )


def read_immutable_file(path: Path, context: str) -> ImmutableFile:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DerivationError(f"cannot open {context} {path}: {error}") from error
    try:
        return _snapshot_descriptor(descriptor, context)
    finally:
        os.close(descriptor)


def require_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DerivationError(f"{context} is not a lowercase SHA-256")
    return value


def require_hash(blob: ImmutableFile, expected: str, context: str) -> str:
    require_sha256(expected, f"expected {context}")
    observed = blob.sha256
    if observed != expected:
        raise DerivationError(
            f"{context} hash mismatch: expected {expected}, observed {observed}"
        )
    return observed


def require_frozen_audit_hash(blob: ImmutableFile) -> str:
    return require_hash(blob, P0_AUDIT_SHA256, "P0 audit")


def require_frozen_corpus_manifest_hash(blob: ImmutableFile) -> str:
    return require_hash(blob, LOCAL_MANIFEST_SHA256, "corpus manifest")


def require_frozen_projection_template_hash(blob: ImmutableFile) -> str:
    return require_hash(blob, PROJECTION_TEMPLATE_SHA256, "projection template")


def canonical_json_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise DerivationError(f"value is not canonical JSON: {error}") from error
    return (rendered + "\n").encode("ascii")


def canonical_relative_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise DerivationError(f"{context} is not a nonempty relative path")
    if (
        value.startswith("/")
        or "\\" in value
        or "//" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    ):
        raise DerivationError(f"{context} is not a canonical relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise DerivationError(f"{context} contains a path alias or traversal")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise DerivationError(f"{context} is not a canonical relative path")
    return value


def canonical_path_digest(paths: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def canonical_source_digest(sources: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for source in sources:
        digest.update(
            json.dumps(
                source,
                allow_nan=False,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def load_corpus_manifest(data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_descriptor_paths: set[str] = set()
    seen_ids: set[int] = set()
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise DerivationError(f"cannot decode corpus manifest: {error}") from error
    if data and not data.endswith(b"\n"):
        raise DerivationError("corpus manifest lacks a final LF")
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        if not line:
            raise DerivationError(f"blank corpus manifest row at line {line_number}")
        try:
            row = json.loads(
                line,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonfinite_json,
            )
        except (json.JSONDecodeError, DerivationError) as error:
            raise DerivationError(
                f"invalid corpus manifest row at line {line_number}: {error}"
            ) from error
        if not isinstance(row, dict):
            raise DerivationError(f"corpus manifest line {line_number} is not an object")
        if frozenset(row) != CORPUS_FIELDS:
            raise DerivationError(f"corpus manifest field drift at line {line_number}")
        relative_path = canonical_relative_path(
            row.get("relative_path"), f"corpus relative path at line {line_number}"
        )
        descriptor_path = canonical_relative_path(
            row.get("path"), f"corpus descriptor path at line {line_number}"
        )
        expected_descriptor_path = CORPUS_DESCRIPTOR_PREFIX + relative_path
        if descriptor_path != expected_descriptor_path:
            raise DerivationError(
                f"corpus descriptor/source identity drift at line {line_number}: "
                f"expected {expected_descriptor_path!r}, got {descriptor_path!r}"
            )
        source_id = row.get("id")
        source_bytes = row.get("bytes")
        if type(source_id) is not int or source_id < 0:
            raise DerivationError(f"invalid source id at line {line_number}")
        if source_id != line_number - 1:
            raise DerivationError(
                f"corpus source id/order drift at line {line_number}: got {source_id}"
            )
        if type(source_bytes) is not int or source_bytes <= 0:
            raise DerivationError(f"invalid source byte count at line {line_number}")
        require_sha256(row.get("sha256"), f"source SHA-256 at line {line_number}")
        if (
            row.get("logic") != "QF_UF"
            or row.get("status") not in SOLVED_RESULTS
            or row.get("archive_md5") != CORPUS_ARCHIVE_MD5
            or row.get("source_doi") != CORPUS_SOURCE_DOI
            or row.get("source_url") != CORPUS_SOURCE_URL
        ):
            raise DerivationError(f"invalid source logic/status at line {line_number}")
        if (
            relative_path in seen_paths
            or descriptor_path in seen_descriptor_paths
            or source_id in seen_ids
        ):
            raise DerivationError(f"duplicate source identity at line {line_number}")
        seen_paths.add(relative_path)
        seen_descriptor_paths.add(descriptor_path)
        seen_ids.add(source_id)
        rows.append(row)
    if len(rows) != EXPECTED_CORPUS_SOURCES:
        raise DerivationError(
            "corpus source count mismatch: "
            f"expected {EXPECTED_CORPUS_SOURCES}, got {len(rows)}"
        )
    if seen_ids != set(range(EXPECTED_CORPUS_SOURCES)):
        raise DerivationError("corpus source ids are not exactly 0..N-1")
    return rows


def observation_index(
    audit: dict[str, Any],
    corpus_paths: set[str],
) -> dict[tuple[float, str, str], dict[str, Any]]:
    inputs = audit.get("inputs")
    hashes = audit.get("input_hashes")
    if not isinstance(inputs, dict) or not isinstance(hashes, dict):
        raise DerivationError("P0 audit lacks inputs or input_hashes")
    expected_sources = len(corpus_paths)
    if expected_sources != EXPECTED_CORPUS_SOURCES:
        raise DerivationError(
            "P0 corpus population is incompatible with the frozen contract: "
            f"expected {EXPECTED_CORPUS_SOURCES}, got {expected_sources}"
        )
    if (
        audit.get("schema_version") != 1
        or audit.get("status") != "rejected"
        or inputs.get("campaign_id") != "best-overall-qf-uf-2026-07"
        or inputs.get("candidate_id") != "euf-viper"
        or inputs.get("instances") != expected_sources
    ):
        raise DerivationError("P0 audit identity drift")
    budgets = inputs.get("budgets_s")
    if (
        not isinstance(budgets, list)
        or [type(value) for value in budgets] != [float, float]
        or tuple(budgets) != BUDGETS
    ):
        raise DerivationError("P0 budget identity drift")
    if inputs.get("baseline_ids") != list(BASELINE_SOLVERS):
        raise DerivationError("P0 comparator identity drift")
    if hashes.get("manifest_sha256") != P0_AUDIT_MANIFEST_SHA256:
        raise DerivationError("P0 audit manifest identity drift")
    binaries = hashes.get("solver_binary_sha256")
    if binaries != SOLVER_BINARY_SHA256S:
        raise DerivationError("P0 solver binary identity drift")

    observations = inputs.get("observation_provenance")
    expected_observations = expected_sources * len(SOLVERS) * len(BUDGETS)
    if not isinstance(observations, list) or len(observations) != expected_observations:
        raise DerivationError(
            "P0 observation count mismatch: "
            f"expected {expected_observations}, got "
            f"{len(observations) if isinstance(observations, list) else 'non-list'}"
        )
    declared_provenance_sha256 = require_sha256(
        hashes.get("observation_provenance_sha256"),
        "declared observation provenance SHA-256",
    )
    if declared_provenance_sha256 != P0_OBSERVATION_PROVENANCE_SHA256:
        raise DerivationError(
            "P0 frozen observation provenance SHA-256 drift: "
            f"expected {P0_OBSERVATION_PROVENANCE_SHA256}, "
            f"got {declared_provenance_sha256}"
        )
    observed_provenance_sha256 = hashlib.sha256(
        canonical_json_bytes(observations)
    ).hexdigest()
    if observed_provenance_sha256 != declared_provenance_sha256:
        raise DerivationError(
            "P0 observation provenance SHA-256 mismatch: "
            f"declared {declared_provenance_sha256}, observed "
            f"{observed_provenance_sha256}"
        )

    index: dict[tuple[float, str, str], dict[str, Any]] = {}
    for row_number, row in enumerate(observations, start=1):
        if not isinstance(row, dict):
            raise DerivationError(f"P0 observation {row_number} is not an object")
        if frozenset(row) != OBSERVATION_FIELDS:
            raise DerivationError(f"P0 observation field drift at row {row_number}")
        budget = row.get("budget_s")
        solver = row.get("solver_id")
        relative_path = canonical_relative_path(
            row.get("relative_path"), f"P0 observation path at row {row_number}"
        )
        result = row.get("result")
        if type(budget) is not float or budget not in BUDGETS or solver not in SOLVERS:
            raise DerivationError(f"P0 observation identity drift at row {row_number}")
        if relative_path not in corpus_paths:
            raise DerivationError(
                f"P0 observation path is outside the frozen corpus at row {row_number}"
            )
        if result not in RESULTS:
            raise DerivationError(f"P0 observation result drift at row {row_number}")
        carried_forward = row.get("carried_forward")
        origin_budget = row.get("origin_budget_s")
        if type(carried_forward) is not bool or type(origin_budget) is not float:
            raise DerivationError(f"P0 observation carry semantics drift at row {row_number}")
        require_sha256(row.get("source_lock_sha256"), "observation lock SHA-256")
        require_sha256(row.get("source_raw_sha256"), "observation raw SHA-256")
        record_hashes = row.get("source_record_sha256s")
        if not isinstance(record_hashes, list) or len(record_hashes) != 1:
            raise DerivationError(f"P0 observation record hashes missing at row {row_number}")
        for value in record_hashes:
            require_sha256(value, "observation record SHA-256")
        key = (budget, solver, relative_path)
        if key in index:
            raise DerivationError(f"duplicate P0 observation {key!r}")
        index[key] = row

    for relative_path in corpus_paths:
        for solver in SOLVERS:
            first = index.get((2.0, solver, relative_path))
            final = index.get((60.0, solver, relative_path))
            if first is None or final is None:
                raise DerivationError(
                    "P0 observation keyset is not the exact corpus x budgets x solvers "
                    f"product at {relative_path!r}/{solver!r}"
                )
            if first["carried_forward"] is not False or first["origin_budget_s"] != 2.0:
                raise DerivationError(
                    f"P0 2-second observation carry semantics drift for "
                    f"{relative_path!r}/{solver!r}"
                )
            if first["result"] in SOLVED_RESULTS:
                same_physical_record = all(
                    final[field] == first[field]
                    for field in (
                        "result",
                        "source_lock_sha256",
                        "source_raw_sha256",
                        "source_record_sha256s",
                    )
                )
                if (
                    final["carried_forward"] is not True
                    or final["origin_budget_s"] != 2.0
                    or not same_physical_record
                ):
                    raise DerivationError(
                        f"P0 solved observation was not carried forward exactly for "
                        f"{relative_path!r}/{solver!r}"
                    )
            elif (
                final["carried_forward"] is not False
                or final["origin_budget_s"] != 60.0
            ):
                raise DerivationError(
                    f"P0 unresolved observation lacks physical 60-second evidence for "
                    f"{relative_path!r}/{solver!r}"
                )
    return index


class SmtTokenizer:
    """Minimal SMT-LIB 2 tokenizer with comments and quoted atoms handled exactly."""

    def __init__(self, text: str, context: str):
        self.text = text
        self.context = context
        self.offset = 0

    def __iter__(self) -> Iterator[str]:
        return self

    def __next__(self) -> str:
        text = self.text
        length = len(text)
        while self.offset < length:
            character = text[self.offset]
            if character.isspace():
                self.offset += 1
                continue
            if character == ";":
                newline = text.find("\n", self.offset + 1)
                self.offset = length if newline < 0 else newline + 1
                continue
            break
        if self.offset >= length:
            raise StopIteration

        start = self.offset
        character = text[start]
        if character in "()":
            self.offset += 1
            return character
        if character == '"':
            self.offset += 1
            while self.offset < length:
                if text[self.offset] == '"':
                    if self.offset + 1 < length and text[self.offset + 1] == '"':
                        self.offset += 2
                        continue
                    self.offset += 1
                    return text[start : self.offset]
                if text[self.offset] == "\\" and self.offset + 1 < length:
                    self.offset += 2
                else:
                    self.offset += 1
            raise DerivationError(f"unterminated string in {self.context}")
        if character == "|":
            self.offset += 1
            while self.offset < length:
                if text[self.offset] == "|":
                    self.offset += 1
                    return text[start : self.offset]
                if text[self.offset] == "\\" and self.offset + 1 < length:
                    self.offset += 2
                else:
                    self.offset += 1
            raise DerivationError(f"unterminated quoted symbol in {self.context}")

        while self.offset < length:
            character = text[self.offset]
            if character.isspace() or character in "();":
                break
            self.offset += 1
        if self.offset == start:
            raise DerivationError(
                f"invalid SMT-LIB token at byte-like offset {start} in {self.context}"
            )
        return text[start : self.offset]


def iter_smt2_forms(data: bytes, context: str) -> Iterator[list[Any]]:
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise DerivationError(f"cannot decode {context} as UTF-8: {error}") from error
    stack: list[list[Any]] = []
    for token in SmtTokenizer(text, context):
        if token == "(":
            if len(stack) >= 512:
                raise DerivationError(f"SMT-LIB nesting is too deep in {context}")
            stack.append([])
        elif token == ")":
            if not stack:
                raise DerivationError(f"unmatched closing parenthesis in {context}")
            value = stack.pop()
            if stack:
                stack[-1].append(value)
            else:
                yield value
        elif not stack:
            raise DerivationError(f"top-level SMT-LIB atom {token!r} in {context}")
        else:
            stack[-1].append(token)
    if stack:
        raise DerivationError(f"unterminated SMT-LIB form in {context}")


def _normalized_pair(left: int, right: int) -> tuple[int, int]:
    return (left, right) if left < right else (right, left)


class SmtStructureAnalyzer:
    """Parse QF_UF assertions into the structural facts used by the frozen atlas."""

    def __init__(self, context: str):
        self.context = context
        self.declarations: dict[str, tuple[int, bool]] = {}
        self.term_ids: dict[tuple[str, tuple[int, ...]], int] = {}
        self.terms: list[tuple[str, tuple[int, ...]]] = []
        self.non_boolean_constants: set[int] = set()
        self.mandatory_disequalities: set[tuple[int, int]] = set()
        self.coverage_candidates: list[tuple[tuple[int, int], ...]] = []
        self.guarded_candidates: list[tuple[int, int, int, int]] = []
        self.logic_seen = False
        self.assertions = 0

    def _intern_term(self, function: str, arguments: tuple[int, ...]) -> int:
        key = (function, arguments)
        existing = self.term_ids.get(key)
        if existing is not None:
            return existing
        term_id = len(self.terms)
        self.term_ids[key] = term_id
        self.terms.append(key)
        return term_id

    def _declare(self, name: object, argument_sorts: object, result_sort: object) -> None:
        if (
            not isinstance(name, str)
            or not isinstance(argument_sorts, list)
            or not all(isinstance(sort_name, str) for sort_name in argument_sorts)
            or not isinstance(result_sort, str)
        ):
            raise DerivationError(f"malformed declaration in {self.context}")
        if name in self.declarations:
            raise DerivationError(f"duplicate declaration {name!r} in {self.context}")
        returns_boolean = result_sort == "Bool"
        self.declarations[name] = (len(argument_sorts), returns_boolean)
        if not argument_sorts:
            term_id = self._intern_term(name, ())
            if not returns_boolean:
                self.non_boolean_constants.add(term_id)

    @staticmethod
    def _require_boolean(value: object, context: str) -> tuple[Any, ...]:
        if not isinstance(value, tuple):
            raise DerivationError(f"expected Boolean expression in {context}")
        return value

    @staticmethod
    def _require_term(value: object, context: str) -> int:
        if type(value) is not int:
            raise DerivationError(f"expected first-order term in {context}")
        return value

    def _boolean_nary(
        self, operator: str, expressions: list[Any], environment: dict[str, object], depth: int
    ) -> tuple[Any, ...]:
        children: list[tuple[Any, ...]] = []
        for expression in expressions:
            child = self._require_boolean(
                self._value(expression, environment, depth + 1), self.context
            )
            if child[0] == operator:
                children.extend(child[1])
            else:
                children.append(child)
        if not children:
            return ("const", operator == "and")
        if len(children) == 1:
            return children[0]
        return (operator, tuple(children))

    def _value(
        self, expression: Any, environment: dict[str, object], depth: int = 0
    ) -> object:
        if depth >= 500:
            raise DerivationError(f"SMT-LIB expression is too deep in {self.context}")
        if isinstance(expression, str):
            if expression in environment:
                return environment[expression]
            if expression == "true":
                return ("const", True)
            if expression == "false":
                return ("const", False)
            declaration = self.declarations.get(expression)
            if declaration is None or declaration[0] != 0:
                raise DerivationError(
                    f"undeclared or unapplied symbol {expression!r} in {self.context}"
                )
            term_id = self._intern_term(expression, ())
            return ("atom", term_id) if declaration[1] else term_id
        if not isinstance(expression, list) or not expression or not isinstance(
            expression[0], str
        ):
            raise DerivationError(f"malformed SMT-LIB expression in {self.context}")

        operator = expression[0]
        arguments = expression[1:]
        if operator == "let":
            if len(arguments) != 2 or not isinstance(arguments[0], list):
                raise DerivationError(f"malformed let expression in {self.context}")
            additions: dict[str, object] = {}
            for binding in arguments[0]:
                if (
                    not isinstance(binding, list)
                    or len(binding) != 2
                    or not isinstance(binding[0], str)
                    or binding[0] in additions
                ):
                    raise DerivationError(f"malformed let binding in {self.context}")
                additions[binding[0]] = self._value(binding[1], environment, depth + 1)
            nested = dict(environment)
            nested.update(additions)
            return self._value(arguments[1], nested, depth + 1)
        if operator == "!":
            if not arguments:
                raise DerivationError(f"malformed annotation in {self.context}")
            return self._value(arguments[0], environment, depth + 1)
        if operator in {"and", "or"}:
            return self._boolean_nary(operator, arguments, environment, depth)
        if operator == "not":
            if len(arguments) != 1:
                raise DerivationError(f"malformed not expression in {self.context}")
            child = self._require_boolean(
                self._value(arguments[0], environment, depth + 1), self.context
            )
            return ("not", child)
        if operator == "=":
            if len(arguments) != 2:
                raise DerivationError(
                    f"only binary equality is accepted by the structural parser in "
                    f"{self.context}"
                )
            left = self._value(arguments[0], environment, depth + 1)
            right = self._value(arguments[1], environment, depth + 1)
            if type(left) is int and type(right) is int:
                return ("eq", left, right)
            left_boolean = self._require_boolean(left, self.context)
            right_boolean = self._require_boolean(right, self.context)
            return ("iff", (left_boolean, right_boolean))
        if operator == "distinct":
            terms = [
                self._require_term(
                    self._value(argument, environment, depth + 1), self.context
                )
                for argument in arguments
            ]
            children = [
                ("not", ("eq", terms[left], terms[right]))
                for left in range(len(terms))
                for right in range(left + 1, len(terms))
            ]
            return self._boolean_nary_from_values("and", children)
        if operator in {"=>", "xor"}:
            children = tuple(
                self._require_boolean(
                    self._value(argument, environment, depth + 1), self.context
                )
                for argument in arguments
            )
            return ("other", operator, children)
        if operator == "ite":
            if len(arguments) != 3:
                raise DerivationError(f"malformed ite expression in {self.context}")
            condition = self._require_boolean(
                self._value(arguments[0], environment, depth + 1), self.context
            )
            then_value = self._value(arguments[1], environment, depth + 1)
            else_value = self._value(arguments[2], environment, depth + 1)
            if type(then_value) is int or type(else_value) is int:
                raise DerivationError(
                    f"term-valued ite is outside the structural parser contract in "
                    f"{self.context}"
                )
            return (
                "ite",
                condition,
                self._require_boolean(then_value, self.context),
                self._require_boolean(else_value, self.context),
            )

        declaration = self.declarations.get(operator)
        if declaration is None:
            raise DerivationError(f"undeclared function {operator!r} in {self.context}")
        if len(arguments) != declaration[0]:
            raise DerivationError(f"arity mismatch for {operator!r} in {self.context}")
        term_arguments = tuple(
            self._require_term(
                self._value(argument, environment, depth + 1), self.context
            )
            for argument in arguments
        )
        term_id = self._intern_term(operator, term_arguments)
        return ("atom", term_id) if declaration[1] else term_id

    @staticmethod
    def _boolean_nary_from_values(
        operator: str, children: list[tuple[Any, ...]]
    ) -> tuple[Any, ...]:
        if not children:
            return ("const", operator == "and")
        if len(children) == 1:
            return children[0]
        return (operator, tuple(children))

    def _collect_assertion(self, assertion: tuple[Any, ...]) -> None:
        stack = [assertion]
        while stack:
            expression = stack.pop()
            kind = expression[0]
            if kind == "and":
                stack.extend(expression[1])
                continue
            if kind == "not" and expression[1][0] == "eq":
                _, left, right = expression[1]
                if left != right:
                    self.mandatory_disequalities.add(_normalized_pair(left, right))
                continue
            if kind != "or":
                continue
            children = expression[1]
            if all(child[0] == "eq" for child in children):
                self.coverage_candidates.append(
                    tuple((child[1], child[2]) for child in children)
                )
            if len(children) != 2:
                continue
            first, second = children
            for guard, consequence in ((first, second), (second, first)):
                if (
                    guard[0] == "eq"
                    and consequence[0] == "not"
                    and consequence[1][0] == "eq"
                ):
                    self.guarded_candidates.append(
                        (
                            guard[1],
                            guard[2],
                            consequence[1][1],
                            consequence[1][2],
                        )
                    )
                    break

    def consume(self, form: list[Any]) -> None:
        if not form or not isinstance(form[0], str):
            raise DerivationError(f"malformed top-level form in {self.context}")
        command = form[0]
        if command == "set-logic":
            if form != ["set-logic", "QF_UF"] or self.logic_seen:
                raise DerivationError(f"logic identity drift in {self.context}")
            self.logic_seen = True
            return
        if command == "declare-sort":
            if len(form) != 3 or not isinstance(form[1], str) or form[2] != "0":
                raise DerivationError(f"malformed sort declaration in {self.context}")
            return
        if command == "declare-fun":
            if len(form) != 4:
                raise DerivationError(f"malformed function declaration in {self.context}")
            self._declare(form[1], form[2], form[3])
            return
        if command == "declare-const":
            if len(form) != 3:
                raise DerivationError(f"malformed constant declaration in {self.context}")
            self._declare(form[1], [], form[2])
            return
        if command == "assert":
            if len(form) != 2:
                raise DerivationError(f"malformed assertion in {self.context}")
            assertion = self._require_boolean(self._value(form[1], {}), self.context)
            self._collect_assertion(assertion)
            self.assertions += 1
            return
        if command in {"set-info", "set-option", "check-sat", "exit"}:
            return
        raise DerivationError(f"unsupported top-level command {command!r} in {self.context}")

    def _maximum_constant_clique(self) -> tuple[int, ...]:
        if not self.mandatory_disequalities:
            return ()
        vertices = set(self.non_boolean_constants)
        if len(vertices) > 128:
            raise DerivationError(
                f"too many constants for independent clique proof in {self.context}"
            )
        adjacency = {vertex: set() for vertex in vertices}
        for left, right in self.mandatory_disequalities:
            if left in vertices and right in vertices:
                adjacency[left].add(right)
                adjacency[right].add(left)

        best: tuple[int, ...] = ()

        def visit(current: tuple[int, ...], possible: set[int], excluded: set[int]) -> None:
            nonlocal best
            if len(current) + len(possible) <= len(best):
                return
            if not possible and not excluded:
                candidate = tuple(sorted(current))
                if len(candidate) > len(best) or (
                    len(candidate) == len(best) and candidate < best
                ):
                    best = candidate
                return
            union = possible | excluded
            pivot = max(
                union,
                key=lambda vertex: (len(possible & adjacency[vertex]), -vertex),
                default=None,
            )
            candidates = possible - (adjacency[pivot] if pivot is not None else set())
            for vertex in sorted(candidates):
                visit(
                    current + (vertex,),
                    possible & adjacency[vertex],
                    excluded & adjacency[vertex],
                )
                possible.remove(vertex)
                excluded.add(vertex)

        visit((), set(vertices), set())
        return best

    def metrics(self, *, source_bytes: int, parentheses: int) -> dict[str, int]:
        if not self.logic_seen or self.assertions == 0:
            raise DerivationError(f"incomplete QF_UF source {self.context}")
        domain = set(self._maximum_constant_clique())
        covered_terms: set[int] = set()
        for pairs in self.coverage_candidates:
            candidate: int | None = None
            values: set[int] = set()
            valid = True
            for left, right in pairs:
                if left in domain and right not in domain:
                    term, value = right, left
                elif right in domain and left not in domain:
                    term, value = left, right
                else:
                    valid = False
                    break
                if candidate is not None and candidate != term:
                    valid = False
                    break
                candidate = term
                values.add(value)
            if valid and candidate is not None and values == domain:
                covered_terms.add(candidate)

        by_function: dict[tuple[str, int], set[int]] = {}
        for term_id in covered_terms:
            function, arguments = self.terms[term_id]
            if arguments and all(argument in domain for argument in arguments):
                by_function.setdefault((function, len(arguments)), set()).add(term_id)
        closed_functions = {
            function
            for (function, arity), terms in by_function.items()
            if len(terms) == len(domain) ** arity
        }

        finite_terms = set(domain) | covered_terms
        changed = True
        while changed:
            changed = False
            for term_id, (function, arguments) in enumerate(self.terms):
                if (
                    arguments
                    and function in closed_functions
                    and all(argument in finite_terms for argument in arguments)
                    and term_id not in finite_terms
                ):
                    finite_terms.add(term_id)
                    changed = True
        binary_table_apps = sum(
            1
            for term_id, (function, arguments) in enumerate(self.terms)
            if term_id in finite_terms and function in closed_functions and len(arguments) == 2
        )
        guarded_clauses = sum(
            1
            for guard_left, guard_right, left, right in self.guarded_candidates
            if guard_left in domain
            and guard_right in domain
            and _normalized_pair(guard_left, guard_right)
            in self.mandatory_disequalities
            and left != right
        )
        return {
            "binary_table_apps": binary_table_apps,
            "closed_table_functions": len(closed_functions),
            "domain_size": len(domain),
            "guarded_disequality_clauses": guarded_clauses,
            "parentheses": parentheses,
            "source_bytes": source_bytes,
        }


def analyze_smt2_source(data: bytes, context: str) -> dict[str, int]:
    analyzer = SmtStructureAnalyzer(context)
    for form in iter_smt2_forms(data, context):
        analyzer.consume(form)
    return analyzer.metrics(source_bytes=len(data), parentheses=data.count(b"("))


def require_domain7_huge(metrics: dict[str, int], context: str) -> None:
    requirements = (
        (metrics.get("domain_size") == 7, "domain_size = 7"),
        (metrics.get("closed_table_functions", 0) >= 1, "closed_table_functions >= 1"),
        (metrics.get("binary_table_apps", 0) >= 49, "binary_table_apps >= 49"),
        (
            metrics.get("guarded_disequality_clauses") == 0,
            "guarded_disequality_clauses = 0",
        ),
        (metrics.get("parentheses", 0) >= MINIMUM_PARENTHESES, "parens >= 80000"),
        (metrics.get("source_bytes", 0) >= MINIMUM_SOURCE_BYTES, "bytes >= 6000000"),
    )
    failed = [description for satisfied, description in requirements if not satisfied]
    if failed:
        raise DerivationError(
            f"selected source is outside DOMAIN7_HUGE ({', '.join(failed)}): {context}"
        )


def _read_relative_source(
    root_descriptor: int, relative_path: str, context: str
) -> ImmutableFile:
    parts = canonical_relative_path(relative_path, context).split("/")
    directory_descriptor = os.dup(root_descriptor)
    try:
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0)
        )
        for part in parts[:-1]:
            try:
                next_descriptor = os.open(
                    part, directory_flags, dir_fd=directory_descriptor
                )
            except OSError as error:
                raise DerivationError(
                    f"cannot open source directory component {part!r} for {context}: {error}"
                ) from error
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            file_descriptor = os.open(
                parts[-1], file_flags, dir_fd=directory_descriptor
            )
        except OSError as error:
            raise DerivationError(f"cannot open physical source {context}: {error}") from error
        try:
            return _snapshot_descriptor(file_descriptor, f"physical source {context}")
        finally:
            os.close(file_descriptor)
    finally:
        os.close(directory_descriptor)


def verify_selected_sources(
    descriptor_root: Path,
    selected_paths: list[str],
    corpus_by_path: dict[str, dict[str, Any]],
) -> dict[str, PhysicalSource]:
    root_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        root_descriptor = os.open(descriptor_root, root_flags)
    except OSError as error:
        raise DerivationError(
            f"cannot open corpus descriptor root {descriptor_root}: {error}"
        ) from error
    verified: dict[str, PhysicalSource] = {}
    identities: dict[tuple[int, int], str] = {}
    try:
        for relative_path in selected_paths:
            row = corpus_by_path[relative_path]
            blob = _read_relative_source(
                root_descriptor, row["path"], relative_path
            )
            previous = identities.get(blob.identity)
            if previous is not None:
                raise DerivationError(
                    f"duplicate physical source identity for {previous!r} and "
                    f"{relative_path!r}"
                )
            identities[blob.identity] = relative_path
            if len(blob.data) != row["bytes"]:
                raise DerivationError(
                    f"physical source byte count mismatch for {relative_path}: "
                    f"manifest {row['bytes']}, observed {len(blob.data)}"
                )
            if blob.sha256 != row["sha256"]:
                raise DerivationError(
                    f"physical source SHA-256 mismatch for {relative_path}: "
                    f"manifest {row['sha256']}, observed {blob.sha256}"
                )
            metrics = analyze_smt2_source(blob.data, relative_path)
            require_domain7_huge(metrics, relative_path)
            verified[relative_path] = PhysicalSource(
                source_bytes=len(blob.data),
                source_sha256=blob.sha256,
                metrics=metrics,
            )
    finally:
        os.close(root_descriptor)
    return verified


def qg7_taxonomy(relative_path: str) -> dict[str, str]:
    canonical_relative_path(relative_path, "selected qg7 source path")
    path = PurePosixPath(relative_path)
    parts = path.parts
    if (
        len(parts) != 4
        or parts[:3] != ("QF_UF", "QG-classification", "qg7")
        or path.suffix != ".smt2"
    ):
        raise DerivationError(f"selected source is not a qg7 SMT-LIB file: {relative_path}")
    stem = path.stem
    lineage_stem = stem.rstrip("0123456789")
    if not lineage_stem or lineage_stem == stem:
        raise DerivationError(f"selected qg7 source lacks numeric variant: {relative_path}")
    return {
        "generator_lineage": f"QF_UF/QG-classification/{lineage_stem}",
        "rule": "qg-size-variant",
        "source_family": "QF_UF/QG-classification",
        "variant": "qg7",
    }


def frozen_projection_contract() -> dict[str, Any]:
    return {
        "arms": {"A": ARM_A, "B": ARM_B, "C": ARM_C, "D": ARM_D},
        "encoding": ENCODING,
        "primary_measure": "literal_slots",
        "secondary_measures": [
            "variables",
            "clauses",
            "unit_clauses",
            "two_watch_entries",
        ],
        "two_watch_rule": TWO_WATCH_RULE,
    }


def frozen_qualifying_rule() -> dict[str, Any]:
    return {
        "qualifying_source_rule": QUALIFYING_SOURCE_RULE,
        "required_d_reduction_from_a_ppm": 250_000,
        "required_increment_over_b_ppm": 50_000,
        "required_increment_over_c_ppm": 50_000,
    }


def validate_projection_template(
    template: dict[str, Any],
) -> None:
    projection_contract = template.get("projection_contract")
    selection = template.get("selection")
    gate = template.get("gate")
    if (
        template.get("schema") != "euf-viper.t6-theory-dag-manifest.v1"
        or not isinstance(projection_contract, dict)
        or not isinstance(selection, dict)
        or not isinstance(gate, dict)
    ):
        raise DerivationError("projection template identity drift")
    expected_projection_contract = frozen_projection_contract()
    if projection_contract != expected_projection_contract:
        raise DerivationError("projection template contract drift")
    if (
        type(selection.get("candidate_count")) is not int
        or selection["candidate_count"] != PARENT_GATE_POPULATION
        or type(gate.get("minimum_qualifying_sources")) is not int
        or gate["minimum_qualifying_sources"] != PARENT_GATE_MINIMUM
        or gate.get("decision_rule")
        != "pass iff at least 8 of 10 sources qualify; otherwise reject"
    ):
        raise DerivationError("projection template parent 8/10 gate drift")
    required_gate = frozen_qualifying_rule()
    if any(gate.get(key) != value for key, value in required_gate.items()):
        raise DerivationError("projection template qualifying rule drift")


def qualifying_threshold(population: int) -> int:
    if type(population) is not int or population <= 0:
        raise DerivationError("qualifying population must be a positive integer")
    return (
        PARENT_GATE_MINIMUM * population + PARENT_GATE_POPULATION - 1
    ) // PARENT_GATE_POPULATION


def select_p0_sources(
    audit: dict[str, Any],
    corpus_rows: list[dict[str, Any]],
) -> P0Selection:
    if len(corpus_rows) != EXPECTED_CORPUS_SOURCES:
        raise DerivationError(
            "corpus population is incompatible with the frozen contract: "
            f"expected {EXPECTED_CORPUS_SOURCES}, got {len(corpus_rows)}"
        )
    corpus_by_path = {row["relative_path"]: row for row in corpus_rows}
    if len(corpus_by_path) != len(corpus_rows):
        raise DerivationError("corpus relative paths are not unique")
    index = observation_index(audit, set(corpus_by_path))
    selected_paths: list[str] = []
    for relative_path in sorted(corpus_by_path, key=lambda value: value.encode("utf-8")):
        if not relative_path.startswith(QG7_PREFIX):
            continue
        candidate = index[(60.0, "euf-viper", relative_path)]["result"]
        z3 = index[(60.0, "z3-default", relative_path)]["result"]
        yices = index[(60.0, "yices2", relative_path)]["result"]
        if candidate == "timeout" and z3 in SOLVED_RESULTS and yices in SOLVED_RESULTS:
            selected_paths.append(relative_path)
    if len(selected_paths) != EXPECTED_SELECTED_SOURCES:
        raise DerivationError(
            "P0 qg7 shared-deficit count mismatch: "
            f"expected {EXPECTED_SELECTED_SOURCES}, got {len(selected_paths)}"
        )
    return P0Selection(index, corpus_by_path, selected_paths)


def build_manifest(
    selection: P0Selection,
    physical_sources: dict[str, PhysicalSource],
) -> dict[str, Any]:
    index = selection.index
    corpus_by_path = selection.corpus_by_path
    selected_paths = selection.selected_paths
    if (
        len(corpus_by_path) != EXPECTED_CORPUS_SOURCES
        or len(selected_paths) != EXPECTED_SELECTED_SOURCES
    ):
        raise DerivationError("selection population drift before manifest construction")
    if set(physical_sources) != set(selected_paths):
        raise DerivationError("physical source evidence does not exactly cover selection")

    sources: list[dict[str, Any]] = []
    for sequence, relative_path in enumerate(selected_paths):
        row = corpus_by_path[relative_path]
        physical = physical_sources[relative_path]
        require_domain7_huge(physical.metrics, relative_path)
        if (
            physical.source_bytes != row["bytes"]
            or physical.source_sha256 != row["sha256"]
            or physical.metrics.get("source_bytes") != physical.source_bytes
        ):
            raise DerivationError(f"physical/corpus source binding drift for {relative_path}")
        z3 = index[(60.0, "z3-default", relative_path)]["result"]
        yices = index[(60.0, "yices2", relative_path)]["result"]
        if row["status"] != z3 or row["status"] != yices:
            raise DerivationError(f"comparator/source status mismatch for {relative_path}")
        sources.append(
            {
                "p0_results": {
                    "euf-viper": "timeout",
                    "yices2": yices,
                    "z3-default": z3,
                },
                "relative_path": relative_path,
                "selection_tags": [
                    "DOMAIN7_HUGE",
                    "P0_30828A4_FULL60_EUF_TIMEOUT",
                    "P0_30828A4_FULL60_Z3_YICES_SOLVED",
                ],
                "sequence": sequence,
                "source_bytes": physical.source_bytes,
                "source_structure": physical.metrics,
                "source_id": row["id"],
                "source_sha256": physical.source_sha256,
                "source_status": row["status"],
                "taxonomy": qg7_taxonomy(relative_path),
            }
        )

    path_digest = canonical_path_digest(selected_paths)
    population = len(sources)
    minimum_qualifying = qualifying_threshold(population)
    return {
        "schema": SCHEMA,
        "selection": {
            "audit": {
                "file_sha256": P0_AUDIT_SHA256,
                "manifest_sha256": P0_AUDIT_MANIFEST_SHA256,
                "observation_provenance_sha256": P0_OBSERVATION_PROVENANCE_SHA256,
                "path": "p0-144990/continuations/chain-145036/audit/full-60.json",
                "revision": P0_REVISION,
                "solver_binary_sha256": P0_BINARY_SHA256,
            },
            "candidate_count": population,
            "canonical_order": "relative_path_utf8_bytewise_ascending",
            "canonical_path_list_sha256": path_digest,
            "corpus_manifest": {
                "file_sha256": LOCAL_MANIFEST_SHA256,
                "records": len(corpus_by_path),
            },
            "derivation": (
                "exact intersection of P0 60-second euf-viper timeouts, qg7 sources "
                "mechanically satisfying frozen DOMAIN7_HUGE structure and physical "
                "bytes, and instances solved with the manifest status by both "
                "z3-default and yices2"
            ),
            "evidence_scope": "current_p0_full60_qg7_shared_z3_yices_deficit",
            "projection_template_sha256": PROJECTION_TEMPLATE_SHA256,
            "selection_version": "p0-30828a4-full60-qg7-shared-deficit-v1",
            "source_records_sha256": canonical_source_digest(sources),
        },
        "population_status": "accepted",
        "projection_contract": frozen_projection_contract(),
        "projection_status": "not_executed",
        "gate": {
            "decision_rule": (
                f"pass iff at least {minimum_qualifying} of {population} sources "
                "qualify; otherwise reject"
            ),
            "minimum_qualifying_sources": minimum_qualifying,
            "parent_gate_ratio": {
                "minimum_qualifying_sources": PARENT_GATE_MINIMUM,
                "population_sources": PARENT_GATE_POPULATION,
            },
            "population_sources": population,
            "threshold_derivation": (
                f"ceil({PARENT_GATE_MINIMUM} * {population} / "
                f"{PARENT_GATE_POPULATION})"
            ),
            **frozen_qualifying_rule(),
        },
        "implementation_or_promotion_eligible": False,
        "sources": sources,
    }


def atomic_write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (
        json.dumps(payload, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("ascii")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return hashlib.sha256(data).hexdigest()
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--corpus-manifest", required=True, type=Path)
    parser.add_argument("--projection-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    audit_blob = read_immutable_file(args.audit, "P0 audit")
    manifest_blob = read_immutable_file(args.corpus_manifest, "corpus manifest")
    template_blob = read_immutable_file(args.projection_template, "projection template")
    require_frozen_audit_hash(audit_blob)
    require_frozen_corpus_manifest_hash(manifest_blob)
    require_frozen_projection_template_hash(template_blob)
    audit = parse_json_bytes(audit_blob.data, "P0 audit")
    template = parse_json_bytes(template_blob.data, "projection template")
    if not isinstance(audit, dict) or not isinstance(template, dict):
        raise DerivationError("audit and projection template must be objects")
    validate_projection_template(template)
    corpus_rows = load_corpus_manifest(manifest_blob.data)
    selection = select_p0_sources(audit, corpus_rows)
    physical_sources = verify_selected_sources(
        args.corpus_manifest.parent,
        selection.selected_paths,
        selection.corpus_by_path,
    )
    payload = build_manifest(selection, physical_sources)
    output_sha256 = atomic_write_json(args.output, payload)
    print(json.dumps({"output": str(args.output), "sha256": output_sha256}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DerivationError as error:
        raise SystemExit(f"T6 manifest derivation failed: {error}") from error
