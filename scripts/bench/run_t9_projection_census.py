#!/usr/bin/env python3
"""Run the frozen, source-bound, no-SAT T9 Stage-0 projection census."""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import json
import math
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Mapping


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "scripts/bench/run_t9_projection_census.py"
AUDITOR_PATH = ROOT / "scripts/bench/audit_t9_projection_census.py"
DESIGN_PATH = ROOT / "research-vault/02-design/2026-07-15-t9-clique-gated-ackermann-escape.md"
CONTROL_MANIFEST_PATH = ROOT / "campaigns/t9-rollback-control-manifest-20260713.jsonl"

RECORD_SCHEMA = "euf-viper.t9-projection-record.v2"
SUMMARY_SCHEMA = "euf-viper.t9-projection-census.v2"
PROJECTION_VERSION = "1"
ZERO_SHA256 = "0" * 64
KEY_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID_RE = re.compile(r"[0-9a-f]{40,64}\Z")

PRODUCTION_SOURCE_COUNT = 7_503
PRODUCTION_SOURCE_SET_SHA256 = (
    "6b3c316cd90d8093bba184522dd3238892e06b6215fc2a8e8b510e1b5b19ba60"
)
PRODUCTION_QG_SOURCE_COUNT = 6_396
CONTROL_MANIFEST_SHA256 = (
    "85c18f76bc4908477e906eb0706cb06724ef23ef0536112651fe75e86ff18390"
)
CONTROL_MANIFEST_ROWS = 24
CONTROL_MANIFEST_BYTES = 12_998
QG_PREFIX = "QF_UF/QG-classification/"
TARGET_PATH = (
    "QF_UF/2018-Goel-hwbench/"
    "QF_UF_sokoban.2.prop1_ab_br_max.smt2"
)
TARGET_SHA256 = "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112"
FROG_SOURCES = {
    "QF_UF/2018-Goel-hwbench/QF_UF_frogs.1.prop1_ab_br_max.smt2": (
        "bfb3748e4f7f3a55771036d2307e05e70bad8ce5f6bfb0c0c031123c098c1101"
    ),
    "QF_UF/2018-Goel-hwbench/QF_UF_frogs.4.prop1_ab_br_max.smt2": (
        "acef229717e93633b7b3297d9f3d7fb65a1787a9ea0b12b5680540bbe83d7a92"
    ),
}

MAX_U64 = (1 << 64) - 1
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_PROJECTOR_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_PROJECTOR_ADDRESS_SPACE_BYTES = 6 * 1024**3
MAX_PROJECTOR_OPEN_FILES = 32
MAX_PROJECTION_TIMEOUT_SECONDS = 60.0

MAX_TERMS = 16_384
MAX_BASE_CLAUSES = 131_072
MAX_BASE_LITERAL_SLOTS = 1_048_576
MAX_APPLICATIONS = 256
MAX_ARITY = 64
MAX_APPLICATION_ARGUMENT_SLOTS = 16_384
MAX_ACKERMANN_CLAUSES = 5_000
MAX_FILL_EDGES = 20_000
MAX_FILL_PAIR_EXAMINATIONS = 8_388_608
MAX_TRANSITIVITY_CLAUSES = 2_000_000
MAX_TRIANGLE_VISITS = 2_000_000
MAX_FINAL_VARIABLES = 50_000
MAX_ADDED_LITERAL_SLOTS = 6_000_000

DIRECT_COUNT_FIELDS = {
    "finite_added",
    "covered_finite_terms",
    "closed_table_functions",
    "all_different_clique_lb",
    "disequality_graph_edges",
    "disequality_clique_excess_edges",
    "equality_graph_vertices",
    "equality_graph_edges",
    "applications",
    "terms",
    "baseline_vars",
    "baseline_clauses",
    "baseline_literal_slots",
    "sat_calls",
}
PLANNED_COUNT_FIELDS = {
    "planned_max_arity",
    "planned_application_argument_slots",
    "planned_ackermann_function_pairs",
    "planned_ackermann_predicate_pairs",
    "planned_ackermann_candidate_pairs",
    "planned_ackermann_function_differing_argument_pairs",
    "planned_ackermann_predicate_differing_argument_pairs",
    "planned_ackermann_clauses",
    "planned_ackermann_literal_slots",
    "planned_fill_edges",
    "planned_fill_pair_examinations",
    "planned_added_vars",
    "planned_transitivity_clauses",
    "planned_triangle_visits",
    "planned_transitivity_literal_slots",
    "planned_candidate_vars",
    "planned_candidate_clauses",
    "planned_candidate_literal_slots",
    "planned_added_literal_slots",
}
MATERIALIZED_COUNT_FIELDS = {
    "materialized_ackermann_clauses",
    "materialized_ackermann_literal_slots",
    "materialized_fill_edges",
    "materialized_added_vars",
    "materialized_transitivity_clauses",
    "materialized_triangle_visits",
    "materialized_transitivity_literal_slots",
    "materialized_candidate_vars",
    "materialized_candidate_clauses",
    "materialized_candidate_literal_slots",
    "materialized_added_literal_slots",
}
STATEFUL_COUNT_FIELDS = PLANNED_COUNT_FIELDS | MATERIALIZED_COUNT_FIELDS
COUNT_FIELDS = DIRECT_COUNT_FIELDS | STATEFUL_COUNT_FIELDS
COUNT_STATE_FIELDS = {f"{field}_state" for field in STATEFUL_COUNT_FIELDS}
BOOLEAN_FIELDS = {"selector_selected", "selected"}
HASH_FIELDS = {
    "baseline_before_sha256",
    "baseline_after_sha256",
    "materialized_candidate_sha256",
}
TEXT_FIELDS = {
    "mode",
    "reason",
    "backend",
    "triangle_visits_definition",
} | HASH_FIELDS
REQUIRED_FIELDS = COUNT_FIELDS | COUNT_STATE_FIELDS | BOOLEAN_FIELDS | TEXT_FIELDS

COUNT_STATES = {"not_computed", "exact", "lower_bound", "unavailable"}
BACKENDS = {"kissat", "cadical", "cadical-refine", "varisat", "dpll"}
REASON_VOCABULARY = {
    "selected",
    "mode_off",
    "finite_added_nonzero",
    "covered_finite_terms_nonzero",
    "closed_table_functions_nonzero",
    "all_different_clique_below_minimum",
    "disequality_clique_arithmetic_overflow",
    "disequality_clique_excess_edges",
    "equality_graph_vertices_below_minimum",
    "equality_graph_edges_below_minimum",
    "application_count_cap",
    "backend_not_kissat",
    "runtime_fact_mismatch",
    "finite_state_mismatch",
    "term_count_cap",
    "base_clause_cap",
    "base_literal_slot_cap",
    "arity_cap",
    "application_argument_slot_cap",
    "invalid_clause_store",
    "invalid_clause_literal",
    "invalid_application_term",
    "invalid_application_argument",
    "invalid_atom_table",
    "invalid_atom_term",
    "invalid_equality_endpoint",
    "unsupported_sort",
    "footprint_arithmetic_overflow",
    "ackermann_invalid_term",
    "ackermann_arithmetic_overflow",
    "ackermann_allocation_failure",
    "ackermann_clause_cap",
    "planning_allocation_failure",
    "planning_mismatch",
    "fill_invalid_term",
    "fill_arithmetic_overflow",
    "fill_edge_cap",
    "fill_pair_examination_cap",
    "final_variable_cap",
    "transitivity_arithmetic_overflow",
    "transitivity_clause_cap",
    "triangle_visit_cap",
    "candidate_clause_overflow",
    "candidate_literal_overflow",
    "added_literal_slot_cap",
    "materialization_variable_capacity",
    "materialization_allocation_failure",
    "materialization_arithmetic_overflow",
    "materialization_mismatch",
    "baseline_state_changed",
    "sat_dispatch_observed",
}
COMPLETED_REASONS = {
    "selected",
    "finite_added_nonzero",
    "covered_finite_terms_nonzero",
    "closed_table_functions_nonzero",
    "all_different_clique_below_minimum",
    "disequality_clique_excess_edges",
    "equality_graph_vertices_below_minimum",
    "equality_graph_edges_below_minimum",
    "application_count_cap",
    "backend_not_kissat",
    "term_count_cap",
    "base_clause_cap",
    "base_literal_slot_cap",
    "arity_cap",
    "application_argument_slot_cap",
    "ackermann_clause_cap",
    "fill_edge_cap",
    "fill_pair_examination_cap",
    "final_variable_cap",
    "transitivity_clause_cap",
    "triangle_visit_cap",
    "added_literal_slot_cap",
}

PROJECTOR_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
EVIDENCE_BOUNDARY = (
    "exact_reviewed_rust_revision_tree_and_binary_call_graph_with_verified_stdin_"
    "source_snapshot_and_no_descendant_sandbox_and_sat_calls_zero_is_defense_in_depth"
)


class CensusError(RuntimeError):
    """Raised when input, execution, or evidence violates the frozen contract."""


@dataclass(frozen=True)
class ManifestSource:
    record_id: int | str
    relative_path: str
    source_bytes: int
    source_sha256: str


@dataclass(frozen=True)
class ControlBinding:
    sha256: str
    byte_count: int
    row_count: int
    identities: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class EvidenceContract:
    kind: str
    expected_sources: int
    source_set_sha256: str
    expected_qg_sources: int
    required_sources: tuple[tuple[str, str], ...]
    control: ControlBinding
    target_path: str
    target_projection: Mapping[str, Any] | None
    require_clean_git: bool

    def descriptor(self) -> dict[str, Any]:
        target_projection_sha256 = (
            None
            if self.target_projection is None
            else canonical_hash(dict(self.target_projection))
        )
        return {
            "kind": self.kind,
            "expected_sources": self.expected_sources,
            "source_set_sha256": self.source_set_sha256,
            "expected_qg_sources": self.expected_qg_sources,
            "required_sources": [
                {"relative_path": path, "sha256": digest}
                for path, digest in self.required_sources
            ],
            "control_manifest_sha256": self.control.sha256,
            "control_manifest_bytes": self.control.byte_count,
            "control_manifest_rows": self.control.row_count,
            "target_path": self.target_path,
            "target_projection_sha256": target_projection_sha256,
            "require_clean_git": self.require_clean_git,
        }

    @property
    def sha256(self) -> str:
        return canonical_hash(self.descriptor())


PRODUCTION_CONTRACT = EvidenceContract(
    kind="production",
    expected_sources=PRODUCTION_SOURCE_COUNT,
    source_set_sha256=PRODUCTION_SOURCE_SET_SHA256,
    expected_qg_sources=PRODUCTION_QG_SOURCE_COUNT,
    required_sources=tuple(
        sorted({TARGET_PATH: TARGET_SHA256, **FROG_SOURCES}.items())
    ),
    control=ControlBinding(
        sha256=CONTROL_MANIFEST_SHA256,
        byte_count=CONTROL_MANIFEST_BYTES,
        row_count=CONTROL_MANIFEST_ROWS,
        identities=(),
    ),
    target_path=TARGET_PATH,
    # This must be replaced by the exact full projection emitted by the reviewed
    # Rust worker. A production census fails closed until then.
    target_projection=None,
    require_clean_git=True,
)


@dataclass
class NamedSnapshot:
    path: Path
    descriptor: int
    initial_stat: os.stat_result
    payload: bytes
    sha256: str

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def revalidate(self, context: str | None = None) -> None:
        if self.descriptor < 0:
            raise CensusError("cannot revalidate a closed snapshot")
        label = context or str(self.path)
        current = os.fstat(self.descriptor)
        if _stat_fingerprint(current) != _stat_fingerprint(self.initial_stat):
            raise CensusError(f"{label}: descriptor changed after stable read")
        try:
            named = os.stat(self.path, follow_symlinks=False)
        except OSError as error:
            raise CensusError(f"{label}: named path changed after stable read: {error}") from error
        if (named.st_dev, named.st_ino) != (
            self.initial_stat.st_dev,
            self.initial_stat.st_ino,
        ):
            raise CensusError(f"{label}: named path was replaced after stable read")

    def __enter__(self) -> NamedSnapshot:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True)
class PublishedArtifact:
    sha256: str
    byte_count: int
    mode: int


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CensusError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def strict_json_loads(text: str, context: str) -> Any:
    def reject_constant(value: str) -> None:
        raise CensusError(f"{context}: non-finite JSON constant {value!r}")

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, CensusError) as error:
        raise CensusError(f"{context}: invalid JSON: {error}") from error


def canonical_json_bytes(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise CensusError(f"value is not canonical JSON: {error}") from error
    return (text + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_hash(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _stat_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_descriptor_stable(
    descriptor: int,
    context: str,
    *,
    max_bytes: int,
    expected_bytes: int | None = None,
    expected_sha256: str | None = None,
    required_mode: int | None = None,
    require_executable: bool = False,
) -> tuple[bytes, os.stat_result, str]:
    try:
        before = os.fstat(descriptor)
    except OSError as error:
        raise CensusError(f"{context}: cannot stat descriptor: {error}") from error
    if not stat.S_ISREG(before.st_mode):
        raise CensusError(f"{context}: descriptor is not a regular file")
    mode = stat.S_IMODE(before.st_mode)
    if required_mode is not None and mode != required_mode:
        raise CensusError(
            f"{context}: mode must be {required_mode:04o}, got {mode:04o}"
        )
    if require_executable and before.st_mode & 0o111 == 0:
        raise CensusError(f"{context}: file is not executable")
    if before.st_size < 0 or before.st_size > max_bytes:
        raise CensusError(f"{context}: byte size exceeds frozen limit {max_bytes}")
    if expected_bytes is not None and before.st_size != expected_bytes:
        raise CensusError(
            f"{context}: byte count mismatch: expected {expected_bytes}, got {before.st_size}"
        )
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise CensusError(f"{context}: short read from regular file")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CensusError(f"{context}: file grew during stable read")
        after = os.fstat(descriptor)
    except OSError as error:
        raise CensusError(f"{context}: stable read failed: {error}") from error
    if _stat_fingerprint(before) != _stat_fingerprint(after):
        raise CensusError(f"{context}: file changed during stable read")
    payload = b"".join(chunks)
    digest = sha256_bytes(payload)
    if expected_sha256 is not None and digest != expected_sha256:
        raise CensusError(f"{context}: SHA-256 mismatch")
    return payload, before, digest


def open_named_snapshot(
    path: Path,
    context: str,
    *,
    max_bytes: int,
    expected_bytes: int | None = None,
    expected_sha256: str | None = None,
    required_mode: int | None = None,
    require_executable: bool = False,
) -> NamedSnapshot:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CensusError(f"{context}: cannot open {path}: {error}") from error
    try:
        payload, initial_stat, digest = _read_descriptor_stable(
            descriptor,
            context,
            max_bytes=max_bytes,
            expected_bytes=expected_bytes,
            expected_sha256=expected_sha256,
            required_mode=required_mode,
            require_executable=require_executable,
        )
        snapshot = NamedSnapshot(path, descriptor, initial_stat, payload, digest)
        snapshot.revalidate(context)
        return snapshot
    except BaseException:
        os.close(descriptor)
        raise


def sha256_file(path: Path) -> str:
    with open_named_snapshot(
        path,
        str(path),
        max_bytes=MAX_BINARY_BYTES,
    ) as snapshot:
        return snapshot.sha256


def _canonical_relative_path(value: object, context: str) -> str:
    if type(value) is not str or not value.startswith("QF_UF/"):
        raise CensusError(f"{context}: relative_path must start with QF_UF/")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CensusError(f"{context}: relative_path is not canonical")
    if path.as_posix() != value:
        raise CensusError(f"{context}: relative_path is not canonical")
    return value


def parse_manifest(payload: bytes) -> list[ManifestSource]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise CensusError(f"manifest is not UTF-8: {error}") from error
    if not payload or not payload.endswith(b"\n"):
        raise CensusError("manifest must be nonempty and end with a newline")
    sources: list[ManifestSource] = []
    seen_ids: set[int | str] = set()
    seen_paths: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        context = f"manifest line {line_number}"
        if not line:
            raise CensusError(f"{context}: blank record")
        row = strict_json_loads(line, context)
        if type(row) is not dict:
            raise CensusError(f"{context}: record must be an object")
        record_id = row.get("id")
        if type(record_id) not in {int, str}:
            raise CensusError(f"{context}: id must be an integer or string")
        if record_id in seen_ids:
            raise CensusError(f"{context}: duplicate id {record_id!r}")
        seen_ids.add(record_id)
        relative_path = _canonical_relative_path(row.get("relative_path"), context)
        if relative_path in seen_paths:
            raise CensusError(f"{context}: duplicate relative_path {relative_path!r}")
        seen_paths.add(relative_path)
        source_bytes = row.get("bytes")
        if type(source_bytes) is not int or not 0 <= source_bytes <= MAX_SOURCE_BYTES:
            raise CensusError(
                f"{context}: bytes must be a nonnegative integer at most {MAX_SOURCE_BYTES}"
            )
        source_sha256 = row.get("sha256")
        if type(source_sha256) is not str or SHA256_RE.fullmatch(source_sha256) is None:
            raise CensusError(f"{context}: sha256 must be lowercase hexadecimal")
        sources.append(
            ManifestSource(record_id, relative_path, source_bytes, source_sha256)
        )
    return sorted(sources, key=lambda source: source.relative_path)


def load_manifest(manifest_path: Path, corpus_root: Path) -> tuple[list[ManifestSource], bytes]:
    if corpus_root is None:
        raise CensusError("corpus root is mandatory")
    with open_named_snapshot(
        manifest_path,
        "manifest",
        max_bytes=MAX_MANIFEST_BYTES,
    ) as snapshot:
        return parse_manifest(snapshot.payload), snapshot.payload


class CorpusRoot:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.descriptor = -1
        self.initial_stat: os.stat_result | None = None

    def __enter__(self) -> CorpusRoot:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            self.descriptor = os.open(self.path, flags)
            self.initial_stat = os.fstat(self.descriptor)
        except OSError as error:
            if self.descriptor >= 0:
                os.close(self.descriptor)
            raise CensusError(f"cannot open corpus root {self.path}: {error}") from error
        if not stat.S_ISDIR(self.initial_stat.st_mode):
            self.close()
            raise CensusError(f"corpus root is not a directory: {self.path}")
        return self

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __exit__(self, *_: object) -> None:
        self.close()

    def revalidate(self) -> None:
        if self.descriptor < 0 or self.initial_stat is None:
            raise CensusError("corpus root is not open")
        current = os.fstat(self.descriptor)
        if (current.st_dev, current.st_ino, current.st_mode) != (
            self.initial_stat.st_dev,
            self.initial_stat.st_ino,
            self.initial_stat.st_mode,
        ):
            raise CensusError("corpus-root descriptor changed during census")

    def snapshot(self, source: ManifestSource) -> bytes:
        if self.descriptor < 0:
            raise CensusError("corpus root is not open")
        parts = PurePosixPath(source.relative_path).parts
        directory = os.dup(self.descriptor)
        try:
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            for component in parts[:-1]:
                next_directory = os.open(component, directory_flags, dir_fd=directory)
                os.close(directory)
                directory = next_directory
            file_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(parts[-1], file_flags, dir_fd=directory)
        except OSError as error:
            raise CensusError(
                f"{source.relative_path}: descriptor-bound source open failed: {error}"
            ) from error
        finally:
            os.close(directory)
        try:
            payload, _, _ = _read_descriptor_stable(
                descriptor,
                source.relative_path,
                max_bytes=MAX_SOURCE_BYTES,
                expected_bytes=source.source_bytes,
                expected_sha256=source.source_sha256,
            )
            return payload
        finally:
            os.close(descriptor)


def _parse_control_payload(payload: bytes, context: str) -> tuple[tuple[str, str], ...]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise CensusError(f"{context}: control manifest is not UTF-8: {error}") from error
    if not payload or not payload.endswith(b"\n"):
        raise CensusError(f"{context}: control manifest must be newline terminated")
    identities: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        row = strict_json_loads(line, f"{context} line {line_number}")
        if type(row) is not dict:
            raise CensusError(f"{context} line {line_number}: record must be an object")
        path = _canonical_relative_path(
            row.get("relative_path"), f"{context} line {line_number}"
        )
        digest = row.get("sha256")
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise CensusError(f"{context} line {line_number}: invalid sha256")
        if path in seen:
            raise CensusError(f"{context}: duplicate control path {path}")
        seen.add(path)
        identities.append((path, digest))
    return tuple(sorted(identities))


def _test_control_payload(identities: tuple[tuple[str, str], ...]) -> bytes:
    return b"".join(
        canonical_json_bytes({"relative_path": path, "sha256": digest})
        for path, digest in identities
    )


def production_control_snapshot() -> tuple[ControlBinding, NamedSnapshot]:
    snapshot = open_named_snapshot(
        CONTROL_MANIFEST_PATH,
        "frozen rollback control manifest",
        max_bytes=CONTROL_MANIFEST_BYTES,
        expected_bytes=CONTROL_MANIFEST_BYTES,
        expected_sha256=CONTROL_MANIFEST_SHA256,
    )
    try:
        identities = _parse_control_payload(snapshot.payload, "control manifest")
        if len(identities) != CONTROL_MANIFEST_ROWS:
            raise CensusError(
                f"control manifest row count mismatch: expected {CONTROL_MANIFEST_ROWS}, "
                f"got {len(identities)}"
            )
        return (
            ControlBinding(
                CONTROL_MANIFEST_SHA256,
                CONTROL_MANIFEST_BYTES,
                CONTROL_MANIFEST_ROWS,
                identities,
            ),
            snapshot,
        )
    except BaseException:
        snapshot.close()
        raise


def resolve_control_binding(
    contract: EvidenceContract,
) -> tuple[ControlBinding, NamedSnapshot | None]:
    if contract.kind == "production":
        binding, snapshot = production_control_snapshot()
        if binding.sha256 != contract.control.sha256:
            snapshot.close()
            raise CensusError("production control-manifest contract mismatch")
        return binding, snapshot
    if contract.kind != "test":
        raise CensusError(f"unsupported evidence contract kind {contract.kind!r}")
    identities = tuple(sorted(contract.control.identities))
    payload = _test_control_payload(identities)
    actual = ControlBinding(
        sha256_bytes(payload), len(payload), len(identities), identities
    )
    if actual != contract.control:
        raise CensusError("test control binding does not match its embedded digest")
    return actual, None


def source_set_value(sources: Iterable[ManifestSource]) -> list[dict[str, str]]:
    return [
        {"relative_path": source.relative_path, "sha256": source.source_sha256}
        for source in sources
    ]


def validate_source_population(
    sources: list[ManifestSource],
    contract: EvidenceContract,
    control: ControlBinding,
) -> None:
    if len(sources) != contract.expected_sources:
        raise CensusError(
            f"source count mismatch: expected {contract.expected_sources}, got {len(sources)}"
        )
    actual_source_set = canonical_hash(source_set_value(sources))
    if actual_source_set != contract.source_set_sha256:
        raise CensusError(
            "source-set digest mismatch: "
            f"expected {contract.source_set_sha256}, got {actual_source_set}"
        )
    by_path = {source.relative_path: source for source in sources}
    for path, digest in contract.required_sources:
        source = by_path.get(path)
        if source is None:
            raise CensusError(f"required frozen source is absent: {path}")
        if source.source_sha256 != digest:
            raise CensusError(f"required frozen source hash drift: {path}")
    qg_count = sum(source.relative_path.startswith(QG_PREFIX) for source in sources)
    if qg_count != contract.expected_qg_sources:
        raise CensusError(
            f"QG population mismatch: expected {contract.expected_qg_sources}, got {qg_count}"
        )
    for path, digest in control.identities:
        source = by_path.get(path)
        if source is None:
            raise CensusError(f"frozen control source is absent: {path}")
        if source.source_sha256 != digest:
            raise CensusError(f"frozen control source hash drift: {path}")


def _canonical_nonnegative_integer(value: str, field: str) -> int:
    if not value or not value.isascii() or not value.isdigit():
        raise CensusError(f"projection field {field!r} is not a canonical integer")
    if value != "0" and value.startswith("0"):
        raise CensusError(f"projection field {field!r} is not a canonical integer")
    parsed = int(value)
    if parsed > MAX_U64:
        raise CensusError(f"projection field {field!r} exceeds unsigned 64-bit range")
    return parsed


def parse_projection_report(payload: bytes, return_code: int) -> dict[str, Any]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise CensusError(f"projection output is not ASCII: {error}") from error
    if not text.endswith("\n"):
        raise CensusError("projection output lacks a final newline")
    lines = text.splitlines()
    if not lines or lines[0] != f"t9_projection_version {PROJECTION_VERSION}":
        raise CensusError("projection version line is missing or invalid")
    raw: dict[str, str] = {}
    for line_number, line in enumerate(lines[1:], start=2):
        if " " not in line:
            raise CensusError(f"projection line {line_number} is not `key value`")
        key, value = line.split(" ", 1)
        if KEY_RE.fullmatch(key) is None or not value or value != value.strip():
            raise CensusError(f"projection line {line_number} is not canonical")
        if key in raw:
            raise CensusError(f"projection line {line_number}: duplicate key {key!r}")
        raw[key] = value
    if raw.keys() != REQUIRED_FIELDS:
        missing = sorted(REQUIRED_FIELDS - raw.keys())
        unknown = sorted(raw.keys() - REQUIRED_FIELDS)
        details: list[str] = []
        if missing:
            details.append(f"missing fields: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown fields: {', '.join(unknown)}")
        raise CensusError("projection schema mismatch: " + "; ".join(details))

    parsed: dict[str, Any] = {}
    for field in COUNT_FIELDS:
        parsed[field] = _canonical_nonnegative_integer(raw[field], field)
    for field in BOOLEAN_FIELDS:
        if raw[field] not in {"0", "1"}:
            raise CensusError(f"projection Boolean {field!r} must be 0 or 1")
        parsed[field] = raw[field] == "1"
    for field in COUNT_STATE_FIELDS:
        if raw[field] not in COUNT_STATES:
            raise CensusError(f"projection count state {field!r} is invalid")
        parsed[field] = raw[field]
    for field in TEXT_FIELDS:
        value = raw[field]
        if not value.isascii() or any(character.isspace() for character in value):
            raise CensusError(f"projection text field {field!r} is not canonical")
        parsed[field] = value

    for field in STATEFUL_COUNT_FIELDS:
        state = parsed[f"{field}_state"]
        value = parsed[field]
        if state in {"not_computed", "unavailable"} and value != 0:
            raise CensusError(f"{field}: {state} count must have value zero")
        if state == "lower_bound" and value == 0:
            raise CensusError(f"{field}: lower_bound count must be positive")
    if parsed["mode"] != "clique-auto":
        raise CensusError("projection mode must be clique-auto")
    if parsed["backend"] not in BACKENDS:
        raise CensusError("projection backend is outside the frozen vocabulary")
    if parsed["reason"] not in REASON_VOCABULARY:
        raise CensusError("projection reason is outside the frozen vocabulary")
    if parsed["triangle_visits_definition"] != "eligible_third_vertex_probes":
        raise CensusError("triangle-visits definition is not frozen")
    for field in HASH_FIELDS:
        if SHA256_RE.fullmatch(parsed[field]) is None:
            raise CensusError(f"projection hash {field!r} is not canonical")
    expected_return_code = 0 if parsed["selected"] else 3
    if return_code != expected_return_code:
        raise CensusError(
            f"projection return code {return_code} disagrees with selected="
            f"{int(parsed['selected'])}"
        )
    if parsed["sat_calls"] != 0:
        raise CensusError("projection reported a SAT call")
    return parsed


def checked_add(*values: int, context: str) -> int:
    total = 0
    for value in values:
        if type(value) is not int or value < 0 or value > MAX_U64:
            raise CensusError(f"{context}: invalid unsigned integer")
        if total > MAX_U64 - value:
            raise CensusError(f"{context}: unsigned integer overflow")
        total += value
    return total


def checked_mul(left: int, right: int, context: str) -> int:
    if type(left) is not int or type(right) is not int or left < 0 or right < 0:
        raise CensusError(f"{context}: invalid unsigned integer")
    if left and right > MAX_U64 // left:
        raise CensusError(f"{context}: unsigned integer overflow")
    return left * right


def checked_pair_count(value: int, context: str) -> int:
    if value < 2:
        return 0
    if value % 2 == 0:
        return checked_mul(value // 2, value - 1, context=context)
    return checked_mul(value, (value - 1) // 2, context=context)


def projection_environment() -> dict[str, str]:
    return dict(PROJECTOR_ENVIRONMENT)


def _write_all(descriptor: int, payload: bytes, context: str) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as error:
            raise CensusError(f"{context}: write failed: {error}") from error
        if written <= 0:
            raise CensusError(f"{context}: short write")
        offset += written


def _resource_limiter(timeout_seconds: float):
    cpu_seconds = max(1, math.ceil(timeout_seconds) + 1)

    def limit() -> None:
        os.umask(0o077)
        limits = [
            (resource.RLIMIT_CORE, 0),
            (resource.RLIMIT_FSIZE, MAX_PROJECTOR_OUTPUT_BYTES),
            (resource.RLIMIT_NOFILE, MAX_PROJECTOR_OPEN_FILES),
            (resource.RLIMIT_CPU, cpu_seconds),
        ]
        # Darwin exposes RLIMIT_AS but rejects lowering it in a pre-exec child.
        # The remaining limits and the output files still bound the portable
        # execution surface; Linux production additionally gets the VM cap.
        if hasattr(resource, "RLIMIT_AS") and sys.platform != "darwin":
            limits.append((resource.RLIMIT_AS, MAX_PROJECTOR_ADDRESS_SPACE_BYTES))
        if hasattr(resource, "RLIMIT_NPROC"):
            limits.append((resource.RLIMIT_NPROC, 0))
        for limit_name, value in limits:
            _soft, hard = resource.getrlimit(limit_name)
            bounded = value if hard == resource.RLIM_INFINITY else min(value, hard)
            resource.setrlimit(limit_name, (bounded, hard))

    return limit


def _kill_process_group(process_id: int) -> bool:
    try:
        os.killpg(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise CensusError(f"cannot inspect projector process group: {error}") from error
    try:
        os.killpg(process_id, signal.SIGKILL)
    except ProcessLookupError:
        return False
    return True


class ProjectorSnapshot:
    def __init__(self, binary: Path) -> None:
        self.binary = binary
        self.original: NamedSnapshot | None = None
        self.temporary: tempfile.TemporaryDirectory[str] | None = None
        self.snapshot_path: Path | None = None

    @property
    def sha256(self) -> str:
        if self.original is None:
            raise CensusError("projector snapshot is not open")
        return self.original.sha256

    def __enter__(self) -> ProjectorSnapshot:
        self.original = open_named_snapshot(
            self.binary,
            "projection binary",
            max_bytes=MAX_BINARY_BYTES,
            require_executable=True,
        )
        self.temporary = tempfile.TemporaryDirectory(prefix="euf-viper-t9-projector-")
        self.snapshot_path = Path(self.temporary.name) / "projector"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self.snapshot_path, flags, 0o500)
        try:
            _write_all(descriptor, self.original.payload, "projector snapshot")
            os.fchmod(descriptor, 0o500)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        with open_named_snapshot(
            self.snapshot_path,
            "copied projection binary",
            max_bytes=MAX_BINARY_BYTES,
            expected_bytes=len(self.original.payload),
            expected_sha256=self.original.sha256,
            required_mode=0o500,
            require_executable=True,
        ):
            pass
        return self

    def revalidate(self) -> None:
        if self.original is None:
            raise CensusError("projector snapshot is not open")
        self.original.revalidate("projection binary")

    def __exit__(self, *_: object) -> None:
        if self.temporary is not None:
            self.temporary.cleanup()
        if self.original is not None:
            self.original.close()


def run_projection(
    projector: ProjectorSnapshot,
    source_bytes: bytes,
    source_label: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    if not 0 < timeout_seconds <= MAX_PROJECTION_TIMEOUT_SECONDS:
        raise CensusError(
            f"timeout_seconds must be in (0, {MAX_PROJECTION_TIMEOUT_SECONDS}]"
        )
    if projector.snapshot_path is None or projector.temporary is None:
        raise CensusError("projector snapshot is not open")
    with tempfile.TemporaryDirectory(
        prefix="run-", dir=projector.temporary.name
    ) as neutral_cwd:
        with tempfile.TemporaryFile(dir=neutral_cwd) as stdout_file:
            with tempfile.TemporaryFile(dir=neutral_cwd) as stderr_file:
                try:
                    process = subprocess.Popen(
                        [str(projector.snapshot_path), "project-t9", "-"],
                        stdin=subprocess.PIPE,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        cwd=neutral_cwd,
                        env=projection_environment(),
                        close_fds=True,
                        start_new_session=True,
                        preexec_fn=_resource_limiter(timeout_seconds),
                    )
                except OSError as error:
                    raise CensusError(
                        f"cannot execute projection binary for {source_label}: {error}"
                    ) from error
                timed_out = False
                try:
                    process.communicate(input=source_bytes, timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill_process_group(process.pid)
                    process.wait()
                descendants = _kill_process_group(process.pid)
                if descendants:
                    process.wait()
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout = stdout_file.read(MAX_PROJECTOR_OUTPUT_BYTES + 1)
                stderr = stderr_file.read(MAX_PROJECTOR_OUTPUT_BYTES + 1)
    if timed_out:
        raise CensusError(f"projection timed out for {source_label}")
    if descendants:
        raise CensusError(f"projection attempted to leave a descendant for {source_label}")
    if len(stdout) > MAX_PROJECTOR_OUTPUT_BYTES or len(stderr) > MAX_PROJECTOR_OUTPUT_BYTES:
        raise CensusError(f"projection output exceeded the frozen bound for {source_label}")
    if process.returncode not in {0, 3}:
        rendered = stderr.decode("utf-8", errors="replace").strip()
        raise CensusError(
            f"projection failed for {source_label} with exit {process.returncode}: {rendered}"
        )
    if stderr:
        raise CensusError(f"projection wrote unexpected stderr for {source_label}")
    return parse_projection_report(stdout, process.returncode)


def _publication_checkpoint(
    stage: str, path: Path, parent_descriptor: int, final_name: str
) -> None:
    """Test hook for deterministic publication-race injection."""


def _same_named_inode(
    parent_descriptor: int,
    final_name: str,
    expected: os.stat_result,
    context: str,
) -> os.stat_result:
    try:
        named = os.stat(
            final_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise CensusError(f"{context}: published pathname changed: {error}") from error
    if (named.st_dev, named.st_ino) != (expected.st_dev, expected.st_ino):
        raise CensusError(f"{context}: published pathname was replaced")
    return named


def immutable_write_new(path: Path, payload: bytes) -> PublishedArtifact:
    parent_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_fd = os.open(path.parent, parent_flags)
    except OSError as error:
        raise CensusError(f"cannot open artifact parent {path.parent}: {error}") from error
    final_fd = -1
    named_fd = -1
    try:
        parent_initial = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_initial.st_mode):
            raise CensusError(f"artifact parent is not a directory: {path.parent}")
        try:
            named_parent = os.stat(path.parent, follow_symlinks=False)
        except OSError as error:
            raise CensusError(f"cannot revalidate artifact parent {path.parent}: {error}") from error
        if (named_parent.st_dev, named_parent.st_ino) != (
            parent_initial.st_dev,
            parent_initial.st_ino,
        ):
            raise CensusError(f"artifact parent path was replaced: {path.parent}")
        final_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            final_fd = os.open(
                path.name,
                final_flags,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError as error:
            raise CensusError(f"refusing to overwrite existing artifact {path}") from error
        os.fchmod(final_fd, 0o600)
        created_stat = os.fstat(final_fd)
        _publication_checkpoint("after_create", path, parent_fd, path.name)
        _write_all(final_fd, payload, f"artifact {path}")
        os.fsync(final_fd)
        payload_read, _, digest = _read_descriptor_stable(
            final_fd,
            f"unfrozen artifact {path}",
            max_bytes=max(1, len(payload)),
            expected_bytes=len(payload),
            expected_sha256=sha256_bytes(payload),
            required_mode=0o600,
        )
        if payload_read != payload:
            raise CensusError(f"artifact bytes differ before publication: {path}")
        _publication_checkpoint("after_write_verify", path, parent_fd, path.name)
        os.fchmod(final_fd, 0o400)
        os.fsync(final_fd)
        frozen_stat = os.fstat(final_fd)
        if (frozen_stat.st_dev, frozen_stat.st_ino) != (
            created_stat.st_dev,
            created_stat.st_ino,
        ):
            raise CensusError(f"artifact descriptor identity changed: {path}")
        _publication_checkpoint("after_mode_freeze", path, parent_fd, path.name)
        payload_read, stable_stat, digest = _read_descriptor_stable(
            final_fd,
            f"published artifact {path}",
            max_bytes=max(1, len(payload)),
            expected_bytes=len(payload),
            expected_sha256=sha256_bytes(payload),
            required_mode=0o400,
        )
        if payload_read != payload:
            raise CensusError(f"published artifact bytes differ: {path}")
        _same_named_inode(parent_fd, path.name, stable_stat, f"artifact {path}")
        _publication_checkpoint("after_named_verify", path, parent_fd, path.name)
        named_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            named_fd = os.open(path.name, named_flags, dir_fd=parent_fd)
        except OSError as error:
            raise CensusError(
                f"artifact {path}: cannot reopen published pathname: {error}"
            ) from error
        reopened_stat = os.fstat(named_fd)
        if (reopened_stat.st_dev, reopened_stat.st_ino) != (
            stable_stat.st_dev,
            stable_stat.st_ino,
        ):
            raise CensusError(f"artifact {path}: reopened pathname was replaced")
        reopened_payload, reopened_stable, reopened_digest = _read_descriptor_stable(
            named_fd,
            f"reopened published artifact {path}",
            max_bytes=max(1, len(payload)),
            expected_bytes=len(payload),
            expected_sha256=digest,
            required_mode=0o400,
        )
        if reopened_payload != payload or reopened_digest != digest:
            raise CensusError(f"reopened published artifact bytes differ: {path}")
        _publication_checkpoint(
            "after_named_reopen_verify", path, parent_fd, path.name
        )
        _same_named_inode(
            parent_fd,
            path.name,
            reopened_stable,
            f"reopened artifact {path}",
        )
        parent_current = os.fstat(parent_fd)
        if (parent_current.st_dev, parent_current.st_ino, parent_current.st_mode) != (
            parent_initial.st_dev,
            parent_initial.st_ino,
            parent_initial.st_mode,
        ):
            raise CensusError(f"artifact parent descriptor changed: {path.parent}")
        named_parent = os.stat(path.parent, follow_symlinks=False)
        if (named_parent.st_dev, named_parent.st_ino) != (
            parent_initial.st_dev,
            parent_initial.st_ino,
        ):
            raise CensusError(f"artifact parent path was replaced: {path.parent}")
        _publication_checkpoint("after_parent_verify", path, parent_fd, path.name)
        final_named = _same_named_inode(
            parent_fd, path.name, stable_stat, f"artifact {path} final recheck"
        )
        if stat.S_IMODE(final_named.st_mode) != 0o400:
            raise CensusError(f"published artifact mode changed: {path}")
        if final_named.st_size != len(payload):
            raise CensusError(f"published artifact size changed: {path}")
        if (
            stable_stat.st_nlink != 1
            or reopened_stable.st_nlink != 1
            or final_named.st_nlink != 1
        ):
            raise CensusError(f"published artifact link count is not one: {path}")
        os.fsync(parent_fd)
        return PublishedArtifact(digest, len(payload), stat.S_IMODE(stable_stat.st_mode))
    finally:
        if named_fd >= 0:
            os.close(named_fd)
        if final_fd >= 0:
            os.close(final_fd)
        os.close(parent_fd)


def read_published_artifact(path: Path, context: str) -> NamedSnapshot:
    return open_named_snapshot(
        path,
        context,
        max_bytes=MAX_MANIFEST_BYTES,
        required_mode=0o400,
    )


def encode_records(records: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(record) for record in records)


def _run_git(arguments: list[str]) -> str:
    system_git = Path("/usr/bin/git")
    git = str(system_git) if system_git.is_file() else shutil.which("git")
    if git is None:
        raise CensusError("git is required to bind T9 provenance")
    try:
        completed = subprocess.run(
            [git, "-C", str(ROOT), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=PROJECTOR_ENVIRONMENT,
            close_fds=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CensusError(f"cannot query Git provenance: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise CensusError(f"Git provenance query failed: {detail}")
    return completed.stdout.decode("ascii").strip()


def capture_provenance(
    contract: EvidenceContract,
    stack: contextlib.ExitStack,
) -> dict[str, str]:
    revision = _run_git(["rev-parse", "HEAD^{commit}"])
    tree = _run_git(["rev-parse", "HEAD^{tree}"])
    if GIT_OID_RE.fullmatch(revision) is None or GIT_OID_RE.fullmatch(tree) is None:
        raise CensusError("Git revision or tree is not canonical")
    if contract.require_clean_git:
        dirty = _run_git(["status", "--porcelain=v1", "--untracked-files=all"])
        if dirty:
            raise CensusError("production T9 census requires a completely clean Git worktree")
    bindings: dict[str, str] = {"git_revision": revision, "git_tree": tree}
    for name, path in (
        ("runner_sha256", RUNNER_PATH),
        ("auditor_sha256", AUDITOR_PATH),
        ("design_sha256", DESIGN_PATH),
    ):
        snapshot = stack.enter_context(
            open_named_snapshot(path, name, max_bytes=MAX_MANIFEST_BYTES)
        )
        bindings[name] = snapshot.sha256
    return bindings


def sandbox_contract(timeout_seconds: float) -> dict[str, Any]:
    return {
        "argv": ["project-t9", "-"],
        "cwd": "private_temporary_directory",
        "stdin": "descriptor_verified_source_snapshot",
        "environment": PROJECTOR_ENVIRONMENT,
        "close_fds": True,
        "new_process_session": True,
        "descendants": "rlimit_nproc_when_available_and_process_group_reaped",
        "stdout_max_bytes": MAX_PROJECTOR_OUTPUT_BYTES,
        "stderr_max_bytes": MAX_PROJECTOR_OUTPUT_BYTES,
        "address_space_max_bytes": MAX_PROJECTOR_ADDRESS_SPACE_BYTES,
        "open_files_max": MAX_PROJECTOR_OPEN_FILES,
        "timeout_seconds": timeout_seconds,
    }


def _assert_contract_ready(contract: EvidenceContract) -> None:
    if contract.target_projection is None:
        raise CensusError(
            "production target anchors are not frozen from the final Rust schema; "
            "Stage 0 remains blocked"
        )
    if set(contract.target_projection) != REQUIRED_FIELDS:
        raise CensusError("target anchor projection does not use the exact final schema")


def run_census(
    manifest_path: Path,
    corpus_root: Path,
    binary: Path,
    records_out: Path,
    summary_out: Path,
    *,
    timeout_seconds: float,
    contract: EvidenceContract = PRODUCTION_CONTRACT,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if corpus_root is None:
        raise CensusError("corpus root is mandatory")
    if not 0 < timeout_seconds <= MAX_PROJECTION_TIMEOUT_SECONDS:
        raise CensusError(
            f"timeout_seconds must be in (0, {MAX_PROJECTION_TIMEOUT_SECONDS}]"
        )
    if records_out.exists() or summary_out.exists():
        raise CensusError("refusing to overwrite census outputs")

    with contextlib.ExitStack() as stack:
        manifest_snapshot = stack.enter_context(
            open_named_snapshot(
                manifest_path,
                "manifest",
                max_bytes=MAX_MANIFEST_BYTES,
            )
        )
        sources = parse_manifest(manifest_snapshot.payload)
        control, control_snapshot = resolve_control_binding(contract)
        if control_snapshot is not None:
            stack.enter_context(control_snapshot)
        validate_source_population(sources, contract, control)
        _assert_contract_ready(contract)
        provenance = capture_provenance(contract, stack)
        projector = stack.enter_context(ProjectorSnapshot(binary))
        corpus = stack.enter_context(CorpusRoot(corpus_root))

        records: list[dict[str, Any]] = []
        previous_hash = ZERO_SHA256
        reason_counts: Counter[str] = Counter()
        selected_paths: list[str] = []
        for source in sources:
            source_bytes = corpus.snapshot(source)
            projection = run_projection(
                projector,
                source_bytes,
                source.relative_path,
                timeout_seconds,
            )
            if projection["reason"] not in COMPLETED_REASONS:
                raise CensusError(
                    f"{source.relative_path}: semantic projection error "
                    f"{projection['reason']!r} cannot complete a census"
                )
            if projection["baseline_before_sha256"] != projection["baseline_after_sha256"]:
                raise CensusError(f"{source.relative_path}: baseline CNF/atom hash changed")
            if projection["selected"]:
                selected_paths.append(source.relative_path)
            reason_counts[projection["reason"]] += 1
            record: dict[str, Any] = {
                "schema": RECORD_SCHEMA,
                "contract_sha256": contract.sha256,
                "source": {
                    "id": source.record_id,
                    "relative_path": source.relative_path,
                    "bytes": source.source_bytes,
                    "sha256": source.source_sha256,
                },
                "binary_sha256": projector.sha256,
                "projection": projection,
                "previous_record_sha256": previous_hash,
            }
            record_hash = canonical_hash(record)
            record["record_sha256"] = record_hash
            records.append(record)
            previous_hash = record_hash

        target_record = next(
            record for record in records if record["source"]["relative_path"] == contract.target_path
        )
        if target_record["projection"] != dict(contract.target_projection or {}):
            raise CensusError("frozen target projection anchors do not match Rust output")

        records_bytes = encode_records(records)
        qg_count = sum(source.relative_path.startswith(QG_PREFIX) for source in sources)
        summary = {
            "schema": SUMMARY_SCHEMA,
            "status": (
                "completed_no_sat" if contract.kind == "production" else "completed_no_sat_test_only"
            ),
            "contract_kind": contract.kind,
            "contract_sha256": contract.sha256,
            "source_count": len(sources),
            "qg_source_count": qg_count,
            "control_source_count": control.row_count,
            "selected_count": len(selected_paths),
            "selected_paths": selected_paths,
            "selected_set_sha256": canonical_hash(selected_paths),
            "reason_counts": dict(sorted(reason_counts.items())),
            "manifest_sha256": manifest_snapshot.sha256,
            "source_set_sha256": canonical_hash(source_set_value(sources)),
            "control_manifest_sha256": control.sha256,
            "binary_sha256": projector.sha256,
            "records_sha256": sha256_bytes(records_bytes),
            "record_chain_head": previous_hash,
            "sat_calls": 0,
            "environment_contract": "only_LANG_LC_ALL_TZ",
            "sandbox_contract": sandbox_contract(timeout_seconds),
            "provenance": provenance,
            "evidence_boundary": EVIDENCE_BOUNDARY,
        }
        summary_bytes = canonical_json_bytes(summary)
        manifest_snapshot.revalidate("manifest")
        projector.revalidate()
        corpus.revalidate()
        if control_snapshot is not None:
            control_snapshot.revalidate("frozen rollback control manifest")

        immutable_write_new(records_out, records_bytes)
        records_snapshot = stack.enter_context(
            read_published_artifact(records_out, "published records")
        )
        if records_snapshot.sha256 != summary["records_sha256"]:
            raise CensusError("published records hash changed before summary publication")
        immutable_write_new(summary_out, summary_bytes)
        summary_snapshot = stack.enter_context(
            read_published_artifact(summary_out, "published summary")
        )
        if summary_snapshot.payload != summary_bytes:
            raise CensusError("published summary bytes changed after publication")
        records_snapshot.revalidate("published records")
        summary_snapshot.revalidate("published summary")
        return records, summary


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("value must be a number") from error
    if not math.isfinite(parsed) or not 0 < parsed <= MAX_PROJECTION_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"value must be in (0, {MAX_PROJECTION_TIMEOUT_SECONDS}]"
        )
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--records-out", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=positive_float, default=30.0)
    return parser


def main() -> int:
    parser = build_argument_parser()
    arguments = parser.parse_args()
    try:
        _, summary = run_census(
            arguments.manifest,
            arguments.corpus_root,
            arguments.binary,
            arguments.records_out,
            arguments.summary_out,
            timeout_seconds=arguments.timeout_seconds,
        )
    except CensusError as error:
        parser.error(str(error))
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
