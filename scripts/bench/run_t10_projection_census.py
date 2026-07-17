#!/usr/bin/env python3
"""Run the frozen, source-bound, no-SAT T10 Stage-0 projection census."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import run_t9_projection_census as hardened_stage0  # noqa: E402


RUNNER_PATH = ROOT / "scripts/bench/run_t10_projection_census.py"
AUDITOR_PATH = ROOT / "scripts/bench/audit_t10_projection_census.py"
HARDENED_STAGE0_PATH = ROOT / "scripts/bench/run_t9_projection_census.py"
CONTROL_MANIFEST_PATH = ROOT / "campaigns/t9-rollback-control-manifest-20260713.jsonl"
CARGO_LOCK_PATH = ROOT / "Cargo.lock"

DESIGN_COMMIT = "05de7841ac005e2a251d71e1a2394f8980cbdd17"
DESIGN_TREE = "18dcfeca26b5cb72bc443476dc92203f04b412c2"
DESIGN_PATH = "research-vault/02-design/2026-07-17-t10-closed-atom-ackermann-kernel.md"
DESIGN_BLOB = "4bde59e6aca9f89a8dae305e129e77febbefc1ca"
DESIGN_SHA256 = "8d42a123a5a08b880701e6be0fe9e037da98d49d569fadcba567c3c37f033d8c"

RECORD_SCHEMA = "euf-viper.t10-projection-record.v1"
SUMMARY_SCHEMA = "euf-viper.t10-projection-census.v1"
PROJECTION_VERSION = "1"
ZERO_SHA256 = "0" * 64
KEY_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID_RE = re.compile(r"[0-9a-f]{40,64}\Z")

PRODUCTION_SOURCE_COUNT = 7_503
PRODUCTION_MANIFEST_SHA256 = (
    "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
)
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
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_PROJECTOR_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_PROJECTOR_ADDRESS_SPACE_BYTES = 6 * 1024**3
MAX_PROJECTOR_OPEN_FILES = 32
MAX_PROJECTION_TIMEOUT_SECONDS = 60.0

MIN_CLOSED_CLAUSES = 1
MAX_CLOSED_CLAUSES = 4_096
MAX_CLOSED_LITERAL_SLOTS = 16_384
MAX_CLOSED_CLAUSE_WIDTH = 4
MAX_APPLICATIONS = 256

# This table is the one integration surface expected to change if the Rust
# report spelling changes. Every parser, record validator, and audit drift
# check derives its accepted keys from these categories.
DIRECT_COUNT_FIELDS = frozenset(
    {
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
        "ackermann_replay_clauses",
        "ackermann_replay_failures",
        "parse_errors",
        "hash_errors",
        "arithmetic_errors",
        "allocation_errors",
        "planning_errors",
        "sat_calls",
    }
)
PROJECTED_COUNT_FIELDS = frozenset(
    {
        "projected_closed_clauses",
        "projected_literal_slots",
        "projected_max_clause_width",
        "projected_added_vars",
        "projected_new_atoms",
        "projected_fill_edges",
        "projected_transitivity_clauses",
    }
)
MATERIALIZED_COUNT_FIELDS = frozenset(
    {
        "materialized_closed_clauses",
        "materialized_literal_slots",
        "materialized_max_clause_width",
        "materialized_added_vars",
        "materialized_new_atoms",
        "materialized_fill_edges",
        "materialized_transitivity_clauses",
    }
)
COUNT_FIELDS = DIRECT_COUNT_FIELDS | PROJECTED_COUNT_FIELDS | MATERIALIZED_COUNT_FIELDS
BOOLEAN_FIELDS = frozenset({"selector_selected", "selected"})
HASH_FIELDS = frozenset(
    {
        "baseline_before_sha256",
        "baseline_after_sha256",
        "atom_map_before_sha256",
        "atom_map_after_sha256",
        "projected_clauses_sha256",
        "materialized_clauses_sha256",
    }
)
TOKEN_FIELDS = frozenset({"mode", "reason", "backend"})
ACCEPTED_PROJECTION_KEYS = (
    COUNT_FIELDS | BOOLEAN_FIELDS | HASH_FIELDS | TOKEN_FIELDS
)
ERROR_COUNT_FIELDS = frozenset(
    {
        "parse_errors",
        "hash_errors",
        "arithmetic_errors",
        "allocation_errors",
        "planning_errors",
        "ackermann_replay_failures",
    }
)
ZERO_WHEN_REJECTED_FIELDS = (
    PROJECTED_COUNT_FIELDS
    | MATERIALIZED_COUNT_FIELDS
    | frozenset({"ackermann_replay_clauses", "ackermann_replay_failures"})
)
PROJECTED_MATERIALIZED_PAIRS = {
    "projected_closed_clauses": "materialized_closed_clauses",
    "projected_literal_slots": "materialized_literal_slots",
    "projected_max_clause_width": "materialized_max_clause_width",
    "projected_added_vars": "materialized_added_vars",
    "projected_new_atoms": "materialized_new_atoms",
    "projected_fill_edges": "materialized_fill_edges",
    "projected_transitivity_clauses": "materialized_transitivity_clauses",
}
ZERO_SIDE_EFFECT_FIELDS = frozenset(
    {
        "projected_added_vars",
        "projected_new_atoms",
        "projected_fill_edges",
        "projected_transitivity_clauses",
        "materialized_added_vars",
        "materialized_new_atoms",
        "materialized_fill_edges",
        "materialized_transitivity_clauses",
    }
)

BACKENDS = frozenset({"kissat", "cadical", "fallback"})
COMPLETED_REASONS = frozenset(
    {
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
    }
)
ERROR_REASONS = frozenset(
    {
        "mode_off",
        "runtime_fact_mismatch",
        "finite_state_mismatch",
        "parse_error",
        "hash_error",
        "arithmetic_error",
        "allocation_error",
        "planning_error",
        "closed_clause_cap",
        "literal_slot_cap",
        "clause_width_cap",
        "baseline_state_changed",
        "atom_map_changed",
        "materialization_mismatch",
        "ackermann_replay_failure",
        "sat_dispatch_observed",
    }
)
REASON_VOCABULARY = COMPLETED_REASONS | ERROR_REASONS

PROJECTOR_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
EVIDENCE_BOUNDARY = (
    "exact_revision_tree_binary_and_design_object_with_descriptor_verified_file_"
    "source_no_solver_environment_no_descendants_and_sat_calls_zero"
)


CensusError = hardened_stage0.CensusError
NamedSnapshot = hardened_stage0.NamedSnapshot
PublishedArtifact = hardened_stage0.PublishedArtifact
CorpusRoot = hardened_stage0.CorpusRoot
open_named_snapshot = hardened_stage0.open_named_snapshot
immutable_write_new = hardened_stage0.immutable_write_new


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
    manifest_sha256: str
    source_set_sha256: str
    expected_qg_sources: int
    required_sources: tuple[tuple[str, str], ...]
    control: ControlBinding
    expected_selected_sources: tuple[tuple[str, str], ...]
    require_clean_git: bool

    def descriptor(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "expected_sources": self.expected_sources,
            "manifest_sha256": self.manifest_sha256,
            "source_set_sha256": self.source_set_sha256,
            "expected_qg_sources": self.expected_qg_sources,
            "required_sources": [
                {"relative_path": path, "sha256": digest}
                for path, digest in self.required_sources
            ],
            "control_manifest_sha256": self.control.sha256,
            "control_manifest_bytes": self.control.byte_count,
            "control_manifest_rows": self.control.row_count,
            "expected_selected_sources": [
                {"relative_path": path, "sha256": digest}
                for path, digest in self.expected_selected_sources
            ],
            "projection_schema_sha256": projection_schema_sha256(),
            "projector_argv": ["project-t10", "FILE"],
            "closed_clause_bounds": {
                "minimum": MIN_CLOSED_CLAUSES,
                "maximum": MAX_CLOSED_CLAUSES,
                "literal_slots_maximum": MAX_CLOSED_LITERAL_SLOTS,
                "clause_width_maximum": MAX_CLOSED_CLAUSE_WIDTH,
            },
            "design": {
                "commit": DESIGN_COMMIT,
                "tree": DESIGN_TREE,
                "path": DESIGN_PATH,
                "blob": DESIGN_BLOB,
                "sha256": DESIGN_SHA256,
            },
            "require_clean_git": self.require_clean_git,
        }

    @property
    def sha256(self) -> str:
        return canonical_hash(self.descriptor())


PRODUCTION_CONTRACT = EvidenceContract(
    kind="production",
    expected_sources=PRODUCTION_SOURCE_COUNT,
    manifest_sha256=PRODUCTION_MANIFEST_SHA256,
    source_set_sha256=PRODUCTION_SOURCE_SET_SHA256,
    expected_qg_sources=PRODUCTION_QG_SOURCE_COUNT,
    required_sources=tuple(
        sorted({TARGET_PATH: TARGET_SHA256, **FROG_SOURCES}.items())
    ),
    control=ControlBinding(
        CONTROL_MANIFEST_SHA256,
        CONTROL_MANIFEST_BYTES,
        CONTROL_MANIFEST_ROWS,
        (),
    ),
    expected_selected_sources=((TARGET_PATH, TARGET_SHA256),),
    require_clean_git=True,
)


@dataclass(frozen=True)
class ProjectionObservation:
    projection: dict[str, Any]
    opened_bytes: int
    opened_sha256: str


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


def projection_schema_descriptor() -> dict[str, list[str]]:
    return {
        "counts": sorted(COUNT_FIELDS),
        "booleans": sorted(BOOLEAN_FIELDS),
        "hashes": sorted(HASH_FIELDS),
        "tokens": sorted(TOKEN_FIELDS),
    }


def projection_schema_sha256() -> str:
    return canonical_hash(projection_schema_descriptor())


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
            raise CensusError(f"{context}: invalid source byte count")
        source_sha256 = row.get("sha256")
        if type(source_sha256) is not str or SHA256_RE.fullmatch(source_sha256) is None:
            raise CensusError(f"{context}: invalid source SHA-256")
        sources.append(
            ManifestSource(record_id, relative_path, source_bytes, source_sha256)
        )
    return sorted(sources, key=lambda source: source.relative_path)


def _parse_control_payload(payload: bytes, context: str) -> tuple[tuple[str, str], ...]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise CensusError(f"{context}: control manifest is not UTF-8") from error
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
            raise CensusError(f"{context} line {line_number}: invalid SHA-256")
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


def resolve_control_binding(
    contract: EvidenceContract,
) -> tuple[ControlBinding, NamedSnapshot | None]:
    if contract.kind == "production":
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
                raise CensusError("control manifest row count mismatch")
            binding = ControlBinding(
                CONTROL_MANIFEST_SHA256,
                CONTROL_MANIFEST_BYTES,
                CONTROL_MANIFEST_ROWS,
                identities,
            )
            if binding.sha256 != contract.control.sha256:
                raise CensusError("production control-manifest contract mismatch")
            return binding, snapshot
        except BaseException:
            snapshot.close()
            raise
    if contract.kind != "test":
        raise CensusError(f"unsupported evidence contract kind {contract.kind!r}")
    identities = tuple(sorted(contract.control.identities))
    payload = _test_control_payload(identities)
    binding = ControlBinding(
        sha256_bytes(payload), len(payload), len(identities), identities
    )
    if binding != contract.control:
        raise CensusError("test control binding does not match its embedded digest")
    return binding, None


def source_set_value(sources: Iterable[ManifestSource]) -> list[dict[str, str]]:
    return [
        {"relative_path": source.relative_path, "sha256": source.source_sha256}
        for source in sources
    ]


def validate_source_population(
    sources: list[ManifestSource],
    manifest_sha256: str,
    contract: EvidenceContract,
    control: ControlBinding,
) -> None:
    if manifest_sha256 != contract.manifest_sha256:
        raise CensusError("accepted manifest SHA-256 mismatch")
    if len(sources) != contract.expected_sources:
        raise CensusError(
            f"source count mismatch: expected {contract.expected_sources}, got {len(sources)}"
        )
    actual_source_set = canonical_hash(source_set_value(sources))
    if actual_source_set != contract.source_set_sha256:
        raise CensusError("source-set digest mismatch")
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
    if not lines or lines[0] != f"t10_projection_version {PROJECTION_VERSION}":
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
    if raw.keys() != ACCEPTED_PROJECTION_KEYS:
        missing = sorted(ACCEPTED_PROJECTION_KEYS - raw.keys())
        unknown = sorted(raw.keys() - ACCEPTED_PROJECTION_KEYS)
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
    for field in HASH_FIELDS | TOKEN_FIELDS:
        value = raw[field]
        if not value.isascii() or any(character.isspace() for character in value):
            raise CensusError(f"projection token {field!r} is not canonical")
        parsed[field] = value

    if parsed["mode"] != "closed-atom-auto":
        raise CensusError("projection mode must be closed-atom-auto")
    if parsed["backend"] not in BACKENDS:
        raise CensusError("projection backend is outside the frozen vocabulary")
    if parsed["reason"] not in REASON_VOCABULARY:
        raise CensusError("projection reason is outside the frozen vocabulary")
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
        if type(value) is not int or not 0 <= value <= MAX_U64:
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


def selector_reason(projection: Mapping[str, Any], context: str) -> str | None:
    clique = projection["all_different_clique_lb"]
    minimum_edges = checked_pair_count(clique, f"{context}:clique edge count")
    excess = projection["disequality_clique_excess_edges"]
    expected_edges = checked_add(
        minimum_edges, excess, context=f"{context}:disequality edge equation"
    )
    if projection["disequality_graph_edges"] != expected_edges:
        raise CensusError(
            f"{context}: disequality_graph_edges must equal C(clique_lb,2) plus excess"
        )
    ordered = (
        (projection["finite_added"] != 0, "finite_added_nonzero"),
        (projection["applications"] > MAX_APPLICATIONS, "application_count_cap"),
        (projection["backend"] != "kissat", "backend_not_kissat"),
        (projection["covered_finite_terms"] != 0, "covered_finite_terms_nonzero"),
        (projection["closed_table_functions"] != 0, "closed_table_functions_nonzero"),
        (clique < 48, "all_different_clique_below_minimum"),
        (excess > 8, "disequality_clique_excess_edges"),
        (
            projection["equality_graph_vertices"] < 2_500,
            "equality_graph_vertices_below_minimum",
        ),
        (
            projection["equality_graph_edges"] < 10_000,
            "equality_graph_edges_below_minimum",
        ),
    )
    return next((reason for failed, reason in ordered if failed), None)


def validate_projection_semantics(
    projection: Mapping[str, Any], context: str
) -> None:
    if projection["reason"] not in COMPLETED_REASONS:
        raise CensusError(
            f"{context}: semantic projection error {projection['reason']!r}"
        )
    for field in ERROR_COUNT_FIELDS:
        if projection[field] != 0:
            raise CensusError(f"{context}: {field} is not zero")
    if projection["sat_calls"] != 0:
        raise CensusError(f"{context}: sat_calls is not zero")
    for before, after, label in (
        ("baseline_before_sha256", "baseline_after_sha256", "baseline CNF"),
        ("atom_map_before_sha256", "atom_map_after_sha256", "atom map"),
    ):
        if projection[before] == ZERO_SHA256:
            raise CensusError(f"{context}: {label} hash cannot be zero")
        if projection[before] != projection[after]:
            raise CensusError(f"{context}: {label} hash changed")

    rejection = selector_reason(projection, context)
    if rejection is not None:
        if projection["selector_selected"] or projection["selected"]:
            raise CensusError(f"{context}: selector accepted despite {rejection}")
        if projection["reason"] != rejection:
            raise CensusError(
                f"{context}: expected first selector reason {rejection}, "
                f"got {projection['reason']}"
            )
        for field in ZERO_WHEN_REJECTED_FIELDS:
            if projection[field] != 0:
                raise CensusError(f"{context}: rejected row has nonzero {field}")
        for field in ("projected_clauses_sha256", "materialized_clauses_sha256"):
            if projection[field] != ZERO_SHA256:
                raise CensusError(f"{context}: rejected row has a clause hash")
        return

    if not projection["selector_selected"] or not projection["selected"]:
        raise CensusError(f"{context}: every selector condition passes but row is rejected")
    if projection["reason"] != "selected":
        raise CensusError(f"{context}: selected row does not report reason selected")

    clauses = projection["projected_closed_clauses"]
    literals = projection["projected_literal_slots"]
    width = projection["projected_max_clause_width"]
    if not MIN_CLOSED_CLAUSES <= clauses <= MAX_CLOSED_CLAUSES:
        raise CensusError(f"{context}: selected closed-clause count is out of bounds")
    if not clauses <= literals <= MAX_CLOSED_LITERAL_SLOTS:
        raise CensusError(f"{context}: selected literal-slot count is out of bounds")
    if not 1 <= width <= MAX_CLOSED_CLAUSE_WIDTH:
        raise CensusError(f"{context}: selected maximum clause width is out of bounds")
    if literals > checked_mul(clauses, width, context=f"{context}:literal width bound"):
        raise CensusError(f"{context}: literal slots exceed clause-width capacity")
    for projected, materialized in PROJECTED_MATERIALIZED_PAIRS.items():
        if projection[projected] != projection[materialized]:
            raise CensusError(
                f"{context}: {materialized} differs from exact {projected}"
            )
    for field in ZERO_SIDE_EFFECT_FIELDS:
        if projection[field] != 0:
            raise CensusError(f"{context}: T10 side effect {field} is not zero")
    if projection["ackermann_replay_clauses"] != clauses:
        raise CensusError(f"{context}: Ackermann replay count differs from clauses")
    if projection["projected_clauses_sha256"] == ZERO_SHA256:
        raise CensusError(f"{context}: selected row has a zero clause hash")
    if (
        projection["projected_clauses_sha256"]
        != projection["materialized_clauses_sha256"]
    ):
        raise CensusError(f"{context}: projected/materialized clause hashes differ")


def projection_environment() -> dict[str, str]:
    return dict(PROJECTOR_ENVIRONMENT)


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

    @property
    def byte_count(self) -> int:
        if self.original is None:
            raise CensusError("projector snapshot is not open")
        return len(self.original.payload)

    def __enter__(self) -> ProjectorSnapshot:
        self.original = open_named_snapshot(
            self.binary,
            "projection binary",
            max_bytes=MAX_BINARY_BYTES,
            require_executable=True,
        )
        self.temporary = tempfile.TemporaryDirectory(prefix="euf-viper-t10-projector-")
        self.snapshot_path = Path(self.temporary.name) / "projector"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self.snapshot_path, flags, 0o500)
        try:
            hardened_stage0._write_all(descriptor, self.original.payload, "projector snapshot")
            os.fchmod(descriptor, 0o500)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        with open_named_snapshot(
            self.snapshot_path,
            "copied T10 projection binary",
            max_bytes=MAX_BINARY_BYTES,
            expected_bytes=self.byte_count,
            expected_sha256=self.sha256,
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


def _create_source_file(directory: Path, source_bytes: bytes) -> Path:
    path = directory / "source.smt2"
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        hardened_stage0._write_all(descriptor, source_bytes, "projector source snapshot")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def run_projection(
    projector: ProjectorSnapshot,
    source_bytes: bytes,
    source_label: str,
    timeout_seconds: float,
) -> ProjectionObservation:
    if not 0 < timeout_seconds <= MAX_PROJECTION_TIMEOUT_SECONDS:
        raise CensusError(
            f"timeout_seconds must be in (0, {MAX_PROJECTION_TIMEOUT_SECONDS}]"
        )
    if projector.snapshot_path is None or projector.temporary is None:
        raise CensusError("projector snapshot is not open")
    with tempfile.TemporaryDirectory(
        prefix="run-", dir=projector.temporary.name
    ) as neutral_cwd_text:
        neutral_cwd = Path(neutral_cwd_text)
        source_path = _create_source_file(neutral_cwd, source_bytes)
        with open_named_snapshot(
            source_path,
            f"opened source {source_label}",
            max_bytes=MAX_SOURCE_BYTES,
            expected_bytes=len(source_bytes),
            expected_sha256=sha256_bytes(source_bytes),
            required_mode=0o400,
        ) as source_snapshot:
            with tempfile.TemporaryFile(dir=neutral_cwd) as stdout_file:
                with tempfile.TemporaryFile(dir=neutral_cwd) as stderr_file:
                    try:
                        process = subprocess.Popen(
                            [str(projector.snapshot_path), "project-t10", "source.smt2"],
                            stdin=subprocess.DEVNULL,
                            stdout=stdout_file,
                            stderr=stderr_file,
                            cwd=neutral_cwd,
                            env=projection_environment(),
                            close_fds=True,
                            start_new_session=True,
                            preexec_fn=hardened_stage0._resource_limiter(timeout_seconds),
                        )
                    except OSError as error:
                        raise CensusError(
                            f"cannot execute T10 projector for {source_label}: {error}"
                        ) from error
                    timed_out = False
                    try:
                        process.wait(timeout=timeout_seconds)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        hardened_stage0._kill_process_group(process.pid)
                        process.wait()
                    descendants = hardened_stage0._kill_process_group(process.pid)
                    if descendants:
                        process.wait()
                    stdout_file.seek(0)
                    stderr_file.seek(0)
                    stdout = stdout_file.read(MAX_PROJECTOR_OUTPUT_BYTES + 1)
                    stderr = stderr_file.read(MAX_PROJECTOR_OUTPUT_BYTES + 1)
            source_snapshot.revalidate(f"opened source {source_label}")
            opened_bytes = len(source_snapshot.payload)
            opened_sha256 = source_snapshot.sha256
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
    return ProjectionObservation(
        parse_projection_report(stdout, process.returncode),
        opened_bytes,
        opened_sha256,
    )


def _system_git() -> str:
    path = Path("/usr/bin/git")
    git = str(path) if path.is_file() else shutil.which("git")
    if git is None:
        raise CensusError("git is required to bind T10 provenance")
    return git


def _run_git(arguments: list[str]) -> str:
    try:
        completed = subprocess.run(
            [_system_git(), "-C", str(ROOT), *arguments],
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
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise CensusError("Git provenance is not ASCII") from error


def _run_git_bytes(arguments: list[str], context: str) -> bytes:
    try:
        completed = subprocess.run(
            [_system_git(), "-C", str(ROOT), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=PROJECTOR_ENVIRONMENT,
            close_fds=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CensusError(f"cannot read {context} from Git: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise CensusError(f"cannot read {context} from Git: {detail}")
    if len(completed.stdout) > MAX_MANIFEST_BYTES:
        raise CensusError(f"{context} exceeds the frozen byte bound")
    return completed.stdout


def _capture_python_identity(
    stack: contextlib.ExitStack,
) -> tuple[dict[str, str], NamedSnapshot]:
    executable = Path(sys.executable).resolve(strict=True)
    snapshot = stack.enter_context(
        open_named_snapshot(
            executable,
            "Python executable",
            max_bytes=MAX_BINARY_BYTES,
            require_executable=True,
        )
    )
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=PROJECTOR_ENVIRONMENT,
            close_fds=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CensusError(f"cannot capture Python version: {error}") from error
    if completed.returncode != 0:
        raise CensusError("cannot capture Python version")
    try:
        version = completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise CensusError("Python version is not ASCII") from error
    if not version or "\n" in version:
        raise CensusError("Python version is not a single line")
    identity = {
        "path": str(executable),
        "sha256": snapshot.sha256,
        "version": version,
        "implementation": platform.python_implementation(),
        "cache_tag": sys.implementation.cache_tag or "none",
    }
    return identity, snapshot


def capture_provenance(
    contract: EvidenceContract,
    stack: contextlib.ExitStack,
) -> tuple[dict[str, Any], tuple[NamedSnapshot, ...]]:
    revision = _run_git(["rev-parse", "HEAD^{commit}"])
    tree = _run_git(["rev-parse", "HEAD^{tree}"])
    if GIT_OID_RE.fullmatch(revision) is None or GIT_OID_RE.fullmatch(tree) is None:
        raise CensusError("Git revision or tree is not canonical")
    if contract.require_clean_git:
        dirty = _run_git(["status", "--porcelain=v1", "--untracked-files=all"])
        if dirty:
            raise CensusError("production T10 census requires a clean Git worktree")
    if _run_git(["rev-parse", f"{DESIGN_COMMIT}^{{commit}}"] ) != DESIGN_COMMIT:
        raise CensusError("immutable T10 design commit is unavailable")
    if _run_git(["rev-parse", f"{DESIGN_COMMIT}^{{tree}}"] ) != DESIGN_TREE:
        raise CensusError("immutable T10 design tree mismatch")
    if _run_git(["rev-parse", f"{DESIGN_COMMIT}:{DESIGN_PATH}"]) != DESIGN_BLOB:
        raise CensusError("immutable T10 design blob mismatch")
    design_bytes = _run_git_bytes(["cat-file", "blob", DESIGN_BLOB], "T10 design blob")
    if sha256_bytes(design_bytes) != DESIGN_SHA256:
        raise CensusError("immutable T10 design bytes mismatch")

    snapshots: list[NamedSnapshot] = []
    code_hashes: dict[str, str] = {}
    for name, path in (
        ("runner_sha256", RUNNER_PATH),
        ("auditor_sha256", AUDITOR_PATH),
        ("hardened_stage0_sha256", HARDENED_STAGE0_PATH),
        ("cargo_lock_sha256", CARGO_LOCK_PATH),
    ):
        snapshot = stack.enter_context(
            open_named_snapshot(path, name, max_bytes=MAX_MANIFEST_BYTES)
        )
        snapshots.append(snapshot)
        code_hashes[name] = snapshot.sha256
    python_identity, python_snapshot = _capture_python_identity(stack)
    snapshots.append(python_snapshot)
    return (
        {
            "git_revision": revision,
            "git_tree": tree,
            **code_hashes,
            "design_commit": DESIGN_COMMIT,
            "design_tree": DESIGN_TREE,
            "design_path": DESIGN_PATH,
            "design_blob": DESIGN_BLOB,
            "design_sha256": DESIGN_SHA256,
            "python": python_identity,
        },
        tuple(snapshots),
    )


def sandbox_contract(timeout_seconds: float) -> dict[str, Any]:
    return {
        "argv": ["project-t10", "FILE"],
        "file_argument": "private_descriptor_verified_source.smt2",
        "cwd": "private_temporary_directory",
        "stdin": "null",
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
    if contract.kind not in {"production", "test"}:
        raise CensusError(f"unsupported evidence contract kind {contract.kind!r}")
    if contract.kind == "production":
        if contract.descriptor() != PRODUCTION_CONTRACT.descriptor():
            raise CensusError("caller attempted to alter the production census contract")
    elif contract.require_clean_git:
        raise CensusError("test census requires an explicit nonproduction contract")
    if contract.expected_sources <= 0:
        raise CensusError("evidence contract has no sources")
    if not contract.expected_selected_sources:
        raise CensusError("evidence contract has no frozen selected population")
    for digest in (
        contract.manifest_sha256,
        contract.source_set_sha256,
        *(digest for _path, digest in contract.required_sources),
        *(digest for _path, digest in contract.expected_selected_sources),
    ):
        if SHA256_RE.fullmatch(digest) is None:
            raise CensusError("evidence contract contains a noncanonical SHA-256")
    if tuple(sorted(contract.required_sources)) != contract.required_sources:
        raise CensusError("required source identities are not sorted")
    if tuple(sorted(contract.expected_selected_sources)) != contract.expected_selected_sources:
        raise CensusError("selected source identities are not sorted")
    required = dict(contract.required_sources)
    if len(required) != len(contract.required_sources):
        raise CensusError("required source identities are not unique")
    if len(dict(contract.expected_selected_sources)) != len(
        contract.expected_selected_sources
    ):
        raise CensusError("selected source identities are not unique")
    for path, digest in contract.expected_selected_sources:
        if required.get(path) != digest:
            raise CensusError("selected source identity is not frozen as required")


def read_published_artifact(path: Path, context: str) -> NamedSnapshot:
    return open_named_snapshot(
        path,
        context,
        max_bytes=MAX_ARTIFACT_BYTES,
        required_mode=0o400,
    )


def encode_records(records: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(record) for record in records)


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
    _assert_contract_ready(contract)

    with contextlib.ExitStack() as stack:
        manifest_snapshot = stack.enter_context(
            open_named_snapshot(manifest_path, "manifest", max_bytes=MAX_MANIFEST_BYTES)
        )
        sources = parse_manifest(manifest_snapshot.payload)
        control, control_snapshot = resolve_control_binding(contract)
        if control_snapshot is not None:
            stack.enter_context(control_snapshot)
        validate_source_population(
            sources, manifest_snapshot.sha256, contract, control
        )
        provenance, provenance_snapshots = capture_provenance(contract, stack)
        projector = stack.enter_context(ProjectorSnapshot(binary))
        corpus = stack.enter_context(CorpusRoot(corpus_root))

        records: list[dict[str, Any]] = []
        previous_hash = ZERO_SHA256
        reason_counts: Counter[str] = Counter()
        error_counts: Counter[str] = Counter()
        selected_identities: list[tuple[str, str]] = []
        opened_source_set: list[dict[str, Any]] = []
        opened_total_bytes = 0
        for source in sources:
            source_bytes = corpus.snapshot(source)
            observation = run_projection(
                projector, source_bytes, source.relative_path, timeout_seconds
            )
            if observation.opened_bytes != source.source_bytes:
                raise CensusError(f"{source.relative_path}: opened byte count mismatch")
            if observation.opened_sha256 != source.source_sha256:
                raise CensusError(f"{source.relative_path}: opened source hash mismatch")
            projection = observation.projection
            validate_projection_semantics(projection, source.relative_path)
            if projection["selected"]:
                selected_identities.append(
                    (source.relative_path, source.source_sha256)
                )
            reason_counts[projection["reason"]] += 1
            for field in ERROR_COUNT_FIELDS:
                error_counts[field] += projection[field]
            opened_total_bytes = checked_add(
                opened_total_bytes,
                observation.opened_bytes,
                context="opened source byte total",
            )
            opened_source_set.append(
                {
                    "relative_path": source.relative_path,
                    "bytes": observation.opened_bytes,
                    "sha256": observation.opened_sha256,
                }
            )
            record: dict[str, Any] = {
                "schema": RECORD_SCHEMA,
                "contract_sha256": contract.sha256,
                "source": {
                    "id": source.record_id,
                    "relative_path": source.relative_path,
                    "manifest_bytes": source.source_bytes,
                    "manifest_sha256": source.source_sha256,
                    "opened_bytes": observation.opened_bytes,
                    "opened_sha256": observation.opened_sha256,
                },
                "binary_sha256": projector.sha256,
                "projection": projection,
                "previous_record_sha256": previous_hash,
            }
            record_hash = canonical_hash(record)
            record["record_sha256"] = record_hash
            records.append(record)
            previous_hash = record_hash

        actual_selected = tuple(selected_identities)
        if actual_selected != contract.expected_selected_sources:
            raise CensusError(
                "selected population mismatch: "
                f"expected {contract.expected_selected_sources!r}, got {actual_selected!r}"
            )
        if any(error_counts.values()):
            raise CensusError("projection error aggregate is nonzero")

        records_bytes = encode_records(records)
        selected_paths = [path for path, _digest in selected_identities]
        qg_count = sum(source.relative_path.startswith(QG_PREFIX) for source in sources)
        summary = {
            "schema": SUMMARY_SCHEMA,
            "status": (
                "completed_no_sat"
                if contract.kind == "production"
                else "completed_no_sat_test_only"
            ),
            "contract_kind": contract.kind,
            "contract_sha256": contract.sha256,
            "source_count": len(sources),
            "qg_source_count": qg_count,
            "control_source_count": control.row_count,
            "selected_count": len(selected_paths),
            "selected_paths": selected_paths,
            "selected_set_sha256": canonical_hash(
                [
                    {"relative_path": path, "sha256": digest}
                    for path, digest in selected_identities
                ]
            ),
            "reason_counts": dict(sorted(reason_counts.items())),
            "error_counts": {
                field: error_counts[field] for field in sorted(ERROR_COUNT_FIELDS)
            },
            "manifest_bytes": len(manifest_snapshot.payload),
            "manifest_sha256": manifest_snapshot.sha256,
            "source_set_sha256": canonical_hash(source_set_value(sources)),
            "opened_source_count": len(opened_source_set),
            "opened_source_bytes": opened_total_bytes,
            "opened_source_set_sha256": canonical_hash(opened_source_set),
            "control_manifest_sha256": control.sha256,
            "binary_bytes": projector.byte_count,
            "binary_sha256": projector.sha256,
            "records_bytes": len(records_bytes),
            "records_sha256": sha256_bytes(records_bytes),
            "record_chain_head": previous_hash,
            "sat_calls": 0,
            "projector_environment": PROJECTOR_ENVIRONMENT,
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
        for snapshot in provenance_snapshots:
            snapshot.revalidate(str(snapshot.path))

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
