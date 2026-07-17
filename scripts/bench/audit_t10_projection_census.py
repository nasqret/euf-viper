#!/usr/bin/env python3
"""Independently audit the frozen T10 no-SAT Stage-0 projection census."""

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
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import run_t10_projection_census as census  # noqa: E402


AUDIT_SCHEMA = "euf-viper.t10-projection-audit.v1"
RECORD_SCHEMA = "euf-viper.t10-projection-record.v1"
SUMMARY_SCHEMA = "euf-viper.t10-projection-census.v1"
PROJECTION_VERSION = "1"
ZERO_SHA256 = "0" * 64
MAX_U64 = (1 << 64) - 1
KEY_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID_RE = re.compile(r"[0-9a-f]{40,64}\Z")

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

# Deliberately duplicated from the runner. _assert_runner_contract_match makes
# either side fail if an integration edit updates only one accepted-key table.
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
ACCEPTED_PROJECTION_KEYS = COUNT_FIELDS | BOOLEAN_FIELDS | HASH_FIELDS | TOKEN_FIELDS
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

RECORD_FIELDS = {
    "schema",
    "contract_sha256",
    "source",
    "binary_sha256",
    "projection",
    "previous_record_sha256",
    "record_sha256",
}
SOURCE_FIELDS = {
    "id",
    "relative_path",
    "manifest_bytes",
    "manifest_sha256",
    "opened_bytes",
    "opened_sha256",
}
SUMMARY_FIELDS = {
    "schema",
    "status",
    "contract_kind",
    "contract_sha256",
    "source_count",
    "qg_source_count",
    "control_source_count",
    "selected_count",
    "selected_paths",
    "selected_set_sha256",
    "reason_counts",
    "error_counts",
    "manifest_bytes",
    "manifest_sha256",
    "source_set_sha256",
    "opened_source_count",
    "opened_source_bytes",
    "opened_source_set_sha256",
    "control_manifest_sha256",
    "binary_bytes",
    "binary_sha256",
    "records_bytes",
    "records_sha256",
    "record_chain_head",
    "sat_calls",
    "projector_environment",
    "sandbox_contract",
    "provenance",
    "evidence_boundary",
}
PROVENANCE_FIELDS = {
    "git_revision",
    "git_tree",
    "runner_sha256",
    "auditor_sha256",
    "hardened_stage0_sha256",
    "cargo_lock_sha256",
    "design_commit",
    "design_tree",
    "design_path",
    "design_blob",
    "design_sha256",
    "python",
}
PYTHON_FIELDS = {"path", "sha256", "version", "implementation", "cache_tag"}
RECEIPT_FIELDS = {
    "schema",
    "status",
    "contract_kind",
    "contract_sha256",
    "source_count",
    "qg_source_count",
    "control_source_count",
    "selected_count",
    "selected_paths",
    "selected_set_sha256",
    "replayed_selected_count",
    "selected_projection_sha256",
    "replayed_selected_projection_sha256",
    "selected_projection_bindings",
    "record_chain_head",
    "evidence_boundary",
    "provenance",
    "artifacts",
}
RECEIPT_ARTIFACT_FIELDS = {
    "manifest_bytes",
    "manifest_sha256",
    "source_set_sha256",
    "opened_source_set_sha256",
    "control_manifest_sha256",
    "binary_bytes",
    "binary_sha256",
    "runner_sha256",
    "auditor_sha256",
    "hardened_stage0_sha256",
    "cargo_lock_sha256",
    "design_commit",
    "design_tree",
    "design_blob",
    "design_sha256",
    "records_bytes",
    "records_sha256",
    "summary_bytes",
    "summary_sha256",
    "records_mode",
    "summary_mode",
}
SELECTED_BINDING_FIELDS = {
    "relative_path",
    "source_sha256",
    "projection_sha256",
    "closed_clauses",
    "literal_slots",
    "max_clause_width",
    "clause_sha256",
}


class AuditError(RuntimeError):
    """Raised when a census does not satisfy the frozen T10 Stage-0 gate."""


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


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def strict_json_loads(text: str, context: str) -> Any:
    def reject_constant(value: str) -> None:
        raise AuditError(f"{context}: non-finite JSON constant {value!r}")

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, AuditError) as error:
        raise AuditError(f"{context}: invalid JSON: {error}") from error


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
        raise AuditError(f"value is not canonical JSON: {error}") from error
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


def _exact_keys(
    value: Mapping[str, Any],
    expected: set[str] | frozenset[str],
    context: str,
) -> None:
    actual = set(value)
    if actual == set(expected):
        return
    missing = sorted(set(expected) - actual)
    unknown = sorted(actual - set(expected))
    details: list[str] = []
    if missing:
        details.append(f"missing {', '.join(missing)}")
    if unknown:
        details.append(f"unknown {', '.join(unknown)}")
    raise AuditError(f"{context}: schema mismatch ({'; '.join(details)})")


def _require_uint(value: object, context: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise AuditError(f"{context} must be an unsigned 64-bit integer")
    return value


def _require_bool(value: object, context: str) -> bool:
    if type(value) is not bool:
        raise AuditError(f"{context} must be a JSON Boolean")
    return value


def _require_ascii(value: object, context: str, *, token: bool = False) -> str:
    if type(value) is not str or not value or not value.isascii():
        raise AuditError(f"{context} must be nonempty ASCII text")
    if token and any(character.isspace() for character in value):
        raise AuditError(f"{context} must not contain whitespace")
    return value


def _canonical_relative_path(value: object, context: str) -> str:
    if type(value) is not str or not value.startswith("QF_UF/"):
        raise AuditError(f"{context}: relative_path must start with QF_UF/")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AuditError(f"{context}: relative_path is not canonical")
    if path.as_posix() != value:
        raise AuditError(f"{context}: relative_path is not canonical")
    return value


def _parse_manifest(payload: bytes) -> list[ManifestSource]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise AuditError("manifest is not UTF-8") from error
    if not payload or not payload.endswith(b"\n"):
        raise AuditError("manifest must be nonempty and newline terminated")
    sources: list[ManifestSource] = []
    seen_ids: set[int | str] = set()
    seen_paths: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        context = f"manifest line {line_number}"
        if not line:
            raise AuditError(f"{context}: blank record")
        row = strict_json_loads(line, context)
        if type(row) is not dict:
            raise AuditError(f"{context}: record must be an object")
        record_id = row.get("id")
        if type(record_id) not in {int, str} or record_id in seen_ids:
            raise AuditError(f"{context}: invalid or duplicate id")
        seen_ids.add(record_id)
        relative_path = _canonical_relative_path(row.get("relative_path"), context)
        if relative_path in seen_paths:
            raise AuditError(f"{context}: duplicate relative_path")
        seen_paths.add(relative_path)
        source_bytes = row.get("bytes")
        if type(source_bytes) is not int or not 0 <= source_bytes <= MAX_SOURCE_BYTES:
            raise AuditError(f"{context}: invalid source byte count")
        source_sha256 = row.get("sha256")
        if type(source_sha256) is not str or SHA256_RE.fullmatch(source_sha256) is None:
            raise AuditError(f"{context}: invalid source SHA-256")
        sources.append(
            ManifestSource(record_id, relative_path, source_bytes, source_sha256)
        )
    return sorted(sources, key=lambda source: source.relative_path)


def _source_set_value(sources: list[ManifestSource]) -> list[dict[str, str]]:
    return [
        {"relative_path": source.relative_path, "sha256": source.source_sha256}
        for source in sources
    ]


def _parse_control_payload(payload: bytes, context: str) -> tuple[tuple[str, str], ...]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise AuditError(f"{context}: control manifest is not UTF-8") from error
    if not payload or not payload.endswith(b"\n"):
        raise AuditError(f"{context}: control manifest is not newline terminated")
    identities: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        row = strict_json_loads(line, f"{context} line {line_number}")
        if type(row) is not dict:
            raise AuditError(f"{context} line {line_number}: record must be an object")
        path = _canonical_relative_path(
            row.get("relative_path"), f"{context} line {line_number}"
        )
        digest = row.get("sha256")
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise AuditError(f"{context} line {line_number}: invalid SHA-256")
        if path in seen:
            raise AuditError(f"{context}: duplicate control path {path}")
        seen.add(path)
        identities.append((path, digest))
    return tuple(sorted(identities))


def _test_control_payload(identities: tuple[tuple[str, str], ...]) -> bytes:
    return b"".join(
        canonical_json_bytes({"relative_path": path, "sha256": digest})
        for path, digest in identities
    )


def _resolve_control_binding(
    contract: EvidenceContract,
) -> tuple[ControlBinding, census.NamedSnapshot | None]:
    if contract.kind == "production":
        snapshot = census.open_named_snapshot(
            CONTROL_MANIFEST_PATH,
            "frozen rollback control manifest",
            max_bytes=CONTROL_MANIFEST_BYTES,
            expected_bytes=CONTROL_MANIFEST_BYTES,
            expected_sha256=CONTROL_MANIFEST_SHA256,
        )
        try:
            identities = _parse_control_payload(snapshot.payload, "control manifest")
            if len(identities) != CONTROL_MANIFEST_ROWS:
                raise AuditError("control manifest row count mismatch")
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
    if contract.kind != "test":
        raise AuditError(f"unsupported evidence contract kind {contract.kind!r}")
    identities = tuple(sorted(contract.control.identities))
    payload = _test_control_payload(identities)
    binding = ControlBinding(
        sha256_bytes(payload), len(payload), len(identities), identities
    )
    if binding != contract.control:
        raise AuditError("test control binding does not match its embedded digest")
    return binding, None


def _normalize_contract(contract: object) -> EvidenceContract:
    try:
        normalized = EvidenceContract(
            kind=contract.kind,
            expected_sources=contract.expected_sources,
            manifest_sha256=contract.manifest_sha256,
            source_set_sha256=contract.source_set_sha256,
            expected_qg_sources=contract.expected_qg_sources,
            required_sources=tuple(contract.required_sources),
            control=ControlBinding(
                contract.control.sha256,
                contract.control.byte_count,
                contract.control.row_count,
                tuple(contract.control.identities),
            ),
            expected_selected_sources=tuple(contract.expected_selected_sources),
            require_clean_git=contract.require_clean_git,
        )
    except (AttributeError, TypeError) as error:
        raise AuditError("audit contract is missing a frozen field") from error
    if normalized.kind not in {"production", "test"}:
        raise AuditError("audit contract kind is invalid")
    if type(normalized.expected_sources) is not int or normalized.expected_sources <= 0:
        raise AuditError("audit contract source count is invalid")
    if (
        type(normalized.expected_qg_sources) is not int
        or not 0 <= normalized.expected_qg_sources <= normalized.expected_sources
    ):
        raise AuditError("audit contract QG count is invalid")
    for label, identities in (
        ("required", normalized.required_sources),
        ("selected", normalized.expected_selected_sources),
    ):
        for index, identity in enumerate(identities):
            if type(identity) is not tuple or len(identity) != 2:
                raise AuditError(f"audit contract {label} identity {index} is invalid")
            _canonical_relative_path(
                identity[0], f"audit contract {label} identity {index}"
            )
            if (
                type(identity[1]) is not str
                or SHA256_RE.fullmatch(identity[1]) is None
            ):
                raise AuditError(
                    f"audit contract {label} identity {index} has an invalid SHA-256"
                )
    for digest in (
        normalized.manifest_sha256,
        normalized.source_set_sha256,
        normalized.control.sha256,
        *(digest for _path, digest in normalized.required_sources),
        *(digest for _path, digest in normalized.expected_selected_sources),
    ):
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise AuditError("audit contract contains an invalid SHA-256")
    if tuple(sorted(normalized.required_sources)) != normalized.required_sources:
        raise AuditError("audit contract required sources are not sorted")
    if tuple(sorted(normalized.expected_selected_sources)) != normalized.expected_selected_sources:
        raise AuditError("audit contract selected sources are not sorted")
    required = dict(normalized.required_sources)
    if len(required) != len(normalized.required_sources):
        raise AuditError("audit contract required sources are not unique")
    if len(dict(normalized.expected_selected_sources)) != len(
        normalized.expected_selected_sources
    ):
        raise AuditError("audit contract selected sources are not unique")
    for path, digest in normalized.expected_selected_sources:
        if required.get(path) != digest:
            raise AuditError("audit contract selected source is not frozen as required")
    if type(normalized.require_clean_git) is not bool:
        raise AuditError("audit contract clean-worktree flag is invalid")
    if normalized.kind == "production":
        if normalized.descriptor() != PRODUCTION_CONTRACT.descriptor():
            raise AuditError("caller attempted to alter the production audit contract")
        return PRODUCTION_CONTRACT
    if normalized.require_clean_git:
        raise AuditError("test audit requires an explicit nonproduction contract")
    return normalized


def _validate_source_population(
    sources: list[ManifestSource],
    manifest_sha256: str,
    contract: EvidenceContract,
    control: ControlBinding,
) -> None:
    if manifest_sha256 != contract.manifest_sha256:
        raise AuditError("accepted manifest SHA-256 mismatch")
    if len(sources) != contract.expected_sources:
        raise AuditError(
            f"source count mismatch: expected {contract.expected_sources}, got {len(sources)}"
        )
    if canonical_hash(_source_set_value(sources)) != contract.source_set_sha256:
        raise AuditError("source-set digest mismatch")
    by_path = {source.relative_path: source for source in sources}
    for path, digest in contract.required_sources:
        source = by_path.get(path)
        if source is None:
            raise AuditError(f"required frozen source is absent: {path}")
        if source.source_sha256 != digest:
            raise AuditError(f"required frozen source hash drift: {path}")
    qg_count = sum(source.relative_path.startswith(QG_PREFIX) for source in sources)
    if qg_count != contract.expected_qg_sources:
        raise AuditError("QG population mismatch")
    for path, digest in control.identities:
        source = by_path.get(path)
        if source is None or source.source_sha256 != digest:
            raise AuditError(f"frozen control source mismatch: {path}")


def _checked_add(*values: int, context: str) -> int:
    total = 0
    for value in values:
        if type(value) is not int or not 0 <= value <= MAX_U64:
            raise AuditError(f"{context}: invalid unsigned integer")
        if total > MAX_U64 - value:
            raise AuditError(f"{context}: unsigned integer overflow")
        total += value
    return total


def _checked_mul(left: int, right: int, context: str) -> int:
    if type(left) is not int or type(right) is not int or left < 0 or right < 0:
        raise AuditError(f"{context}: invalid unsigned integer")
    if left and right > MAX_U64 // left:
        raise AuditError(f"{context}: unsigned integer overflow")
    return left * right


def _checked_pair_count(value: int, context: str) -> int:
    if value < 2:
        return 0
    if value % 2 == 0:
        return _checked_mul(value // 2, value - 1, context=context)
    return _checked_mul(value, (value - 1) // 2, context=context)


def _selector_reason(projection: Mapping[str, Any], context: str) -> str | None:
    clique = projection["all_different_clique_lb"]
    expected_edges = _checked_add(
        _checked_pair_count(clique, f"{context}:clique edge count"),
        projection["disequality_clique_excess_edges"],
        context=f"{context}:disequality edge equation",
    )
    if projection["disequality_graph_edges"] != expected_edges:
        raise AuditError(
            f"{context}: disequality_graph_edges must equal C(clique_lb,2) plus excess"
        )
    ordered = (
        (projection["finite_added"] != 0, "finite_added_nonzero"),
        (projection["applications"] > MAX_APPLICATIONS, "application_count_cap"),
        (projection["backend"] != "kissat", "backend_not_kissat"),
        (projection["covered_finite_terms"] != 0, "covered_finite_terms_nonzero"),
        (projection["closed_table_functions"] != 0, "closed_table_functions_nonzero"),
        (clique < 48, "all_different_clique_below_minimum"),
        (
            projection["disequality_clique_excess_edges"] > 8,
            "disequality_clique_excess_edges",
        ),
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


def _validate_projection_shape(projection: object, context: str) -> dict[str, Any]:
    if type(projection) is not dict:
        raise AuditError(f"{context}: projection must be an object")
    _exact_keys(projection, ACCEPTED_PROJECTION_KEYS, f"{context}:projection")
    for field in COUNT_FIELDS:
        _require_uint(projection[field], f"{context}:{field}")
    for field in BOOLEAN_FIELDS:
        _require_bool(projection[field], f"{context}:{field}")
    for field in HASH_FIELDS | TOKEN_FIELDS:
        _require_ascii(projection[field], f"{context}:{field}", token=True)
    if projection["mode"] != "closed-atom-auto":
        raise AuditError(f"{context}: mode is not closed-atom-auto")
    if projection["backend"] not in BACKENDS:
        raise AuditError(f"{context}: backend is outside the frozen vocabulary")
    if projection["reason"] not in REASON_VOCABULARY:
        raise AuditError(f"{context}: reason is outside the frozen vocabulary")
    for field in HASH_FIELDS:
        if SHA256_RE.fullmatch(projection[field]) is None:
            raise AuditError(f"{context}:{field} is not a canonical SHA-256")
    if projection["sat_calls"] != 0:
        raise AuditError(f"{context}: sat_calls is not zero")
    return projection


def _validate_projection_semantics(
    projection: Mapping[str, Any], context: str
) -> None:
    if projection["reason"] not in COMPLETED_REASONS:
        raise AuditError(f"{context}: semantic projection error {projection['reason']!r}")
    for field in ERROR_COUNT_FIELDS:
        if projection[field] != 0:
            raise AuditError(f"{context}: {field} is not zero")
    for before, after, label in (
        ("baseline_before_sha256", "baseline_after_sha256", "baseline CNF"),
        ("atom_map_before_sha256", "atom_map_after_sha256", "atom map"),
    ):
        if projection[before] == ZERO_SHA256:
            raise AuditError(f"{context}: {label} hash cannot be zero")
        if projection[before] != projection[after]:
            raise AuditError(f"{context}: {label} hash changed")

    rejection = _selector_reason(projection, context)
    if rejection is not None:
        if projection["selector_selected"] or projection["selected"]:
            raise AuditError(f"{context}: selector accepted despite {rejection}")
        if projection["reason"] != rejection:
            raise AuditError(
                f"{context}: expected first selector reason {rejection}, "
                f"got {projection['reason']}"
            )
        for field in ZERO_WHEN_REJECTED_FIELDS:
            if projection[field] != 0:
                raise AuditError(f"{context}: rejected row has nonzero {field}")
        for field in ("projected_clauses_sha256", "materialized_clauses_sha256"):
            if projection[field] != ZERO_SHA256:
                raise AuditError(f"{context}: rejected row has a clause hash")
        return

    if not projection["selector_selected"] or not projection["selected"]:
        raise AuditError(f"{context}: every selector condition passes but row is rejected")
    if projection["reason"] != "selected":
        raise AuditError(f"{context}: selected row reason is not selected")
    clauses = projection["projected_closed_clauses"]
    literals = projection["projected_literal_slots"]
    width = projection["projected_max_clause_width"]
    if not MIN_CLOSED_CLAUSES <= clauses <= MAX_CLOSED_CLAUSES:
        raise AuditError(f"{context}: selected closed-clause count is out of bounds")
    if not clauses <= literals <= MAX_CLOSED_LITERAL_SLOTS:
        raise AuditError(f"{context}: selected literal-slot count is out of bounds")
    if not 1 <= width <= MAX_CLOSED_CLAUSE_WIDTH:
        raise AuditError(f"{context}: selected maximum clause width is out of bounds")
    if literals > _checked_mul(clauses, width, context=f"{context}:literal width bound"):
        raise AuditError(f"{context}: literal slots exceed clause-width capacity")
    for projected, materialized in PROJECTED_MATERIALIZED_PAIRS.items():
        if projection[projected] != projection[materialized]:
            raise AuditError(
                f"{context}: {materialized} differs from exact {projected}"
            )
    for field in ZERO_SIDE_EFFECT_FIELDS:
        if projection[field] != 0:
            raise AuditError(f"{context}: T10 side effect {field} is not zero")
    if projection["ackermann_replay_clauses"] != clauses:
        raise AuditError(f"{context}: Ackermann replay count differs from clauses")
    if projection["projected_clauses_sha256"] == ZERO_SHA256:
        raise AuditError(f"{context}: selected row has a zero clause hash")
    if (
        projection["projected_clauses_sha256"]
        != projection["materialized_clauses_sha256"]
    ):
        raise AuditError(f"{context}: projected/materialized clause hashes differ")


def _canonical_integer(value: str, field: str) -> int:
    if not value or not value.isascii() or not value.isdigit():
        raise AuditError(f"projection field {field!r} is not a canonical integer")
    if value != "0" and value.startswith("0"):
        raise AuditError(f"projection field {field!r} is not a canonical integer")
    parsed = int(value)
    if parsed > MAX_U64:
        raise AuditError(f"projection field {field!r} exceeds unsigned 64-bit range")
    return parsed


def _parse_projection_report(payload: bytes, return_code: int) -> dict[str, Any]:
    try:
        text = payload.decode("ascii")
    except UnicodeError as error:
        raise AuditError("replayed projection output is not ASCII") from error
    if not text.endswith("\n"):
        raise AuditError("replayed projection output is not newline terminated")
    lines = text.splitlines()
    if not lines or lines[0] != f"t10_projection_version {PROJECTION_VERSION}":
        raise AuditError("replayed projection version mismatch")
    raw: dict[str, str] = {}
    for line_number, line in enumerate(lines[1:], start=2):
        if " " not in line:
            raise AuditError(f"replayed projection line {line_number} is malformed")
        key, value = line.split(" ", 1)
        if KEY_RE.fullmatch(key) is None or not value or value != value.strip():
            raise AuditError(f"replayed projection line {line_number} is noncanonical")
        if key in raw:
            raise AuditError(f"replayed projection has duplicate key {key!r}")
        raw[key] = value
    _exact_keys(raw, ACCEPTED_PROJECTION_KEYS, "replayed projection")
    projection: dict[str, Any] = {}
    for field in COUNT_FIELDS:
        projection[field] = _canonical_integer(raw[field], field)
    for field in BOOLEAN_FIELDS:
        if raw[field] not in {"0", "1"}:
            raise AuditError(f"replayed projection Boolean {field} is invalid")
        projection[field] = raw[field] == "1"
    for field in HASH_FIELDS | TOKEN_FIELDS:
        projection[field] = raw[field]
    projection = _validate_projection_shape(projection, "replayed")
    expected_return_code = 0 if projection["selected"] else 3
    if return_code != expected_return_code:
        raise AuditError("replayed projection exit status disagrees with selected")
    _validate_projection_semantics(projection, "replayed")
    return projection


def _write_all(descriptor: int, payload: bytes, context: str) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as error:
            raise AuditError(f"{context}: write failed: {error}") from error
        if written <= 0:
            raise AuditError(f"{context}: short write")
        offset += written


def _run_selected_projection(
    projector: census.ProjectorSnapshot,
    source_bytes: bytes,
    source_label: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    if projector.snapshot_path is None or projector.temporary is None:
        raise AuditError("replay projector snapshot is not open")
    with tempfile.TemporaryDirectory(
        prefix="audit-run-", dir=projector.temporary.name
    ) as neutral_cwd_text:
        neutral_cwd = Path(neutral_cwd_text)
        source_path = neutral_cwd / "source.smt2"
        descriptor = os.open(
            source_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            _write_all(descriptor, source_bytes, "audit source snapshot")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        with census.open_named_snapshot(
            source_path,
            f"audit-opened source {source_label}",
            max_bytes=MAX_SOURCE_BYTES,
            expected_bytes=len(source_bytes),
            expected_sha256=sha256_bytes(source_bytes),
            required_mode=0o400,
        ) as source_snapshot:
            with tempfile.TemporaryFile(dir=neutral_cwd) as stdout_file:
                with tempfile.TemporaryFile(dir=neutral_cwd) as stderr_file:
                    try:
                        process = subprocess.Popen(
                            [
                                str(projector.snapshot_path),
                                "project-t10",
                                "source.smt2",
                            ],
                            stdin=subprocess.DEVNULL,
                            stdout=stdout_file,
                            stderr=stderr_file,
                            cwd=neutral_cwd,
                            env=PROJECTOR_ENVIRONMENT,
                            close_fds=True,
                            start_new_session=True,
                            preexec_fn=(
                                census.hardened_stage0._resource_limiter(
                                    timeout_seconds
                                )
                            ),
                        )
                    except OSError as error:
                        raise AuditError(
                            f"cannot replay T10 projector for {source_label}: {error}"
                        ) from error
                    timed_out = False
                    try:
                        process.wait(timeout=timeout_seconds)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        census.hardened_stage0._kill_process_group(process.pid)
                        process.wait()
                    descendants = census.hardened_stage0._kill_process_group(process.pid)
                    if descendants:
                        process.wait()
                    stdout_file.seek(0)
                    stderr_file.seek(0)
                    stdout = stdout_file.read(MAX_PROJECTOR_OUTPUT_BYTES + 1)
                    stderr = stderr_file.read(MAX_PROJECTOR_OUTPUT_BYTES + 1)
            source_snapshot.revalidate(f"audit-opened source {source_label}")
    if timed_out:
        raise AuditError(f"selected replay timed out for {source_label}")
    if descendants:
        raise AuditError(f"selected replay left a descendant for {source_label}")
    if len(stdout) > MAX_PROJECTOR_OUTPUT_BYTES or len(stderr) > MAX_PROJECTOR_OUTPUT_BYTES:
        raise AuditError(f"selected replay output exceeded its bound for {source_label}")
    if process.returncode not in {0, 3}:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise AuditError(
            f"selected replay failed for {source_label} with {process.returncode}: {detail}"
        )
    if stderr:
        raise AuditError(f"selected replay wrote stderr for {source_label}")
    return _parse_projection_report(stdout, process.returncode)


def _system_git() -> str:
    path = Path("/usr/bin/git")
    git = str(path) if path.is_file() else shutil.which("git")
    if git is None:
        raise AuditError("git is required to bind T10 audit provenance")
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
        raise AuditError(f"cannot query Git audit provenance: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AuditError(f"Git audit provenance query failed: {detail}")
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise AuditError("Git audit provenance is not ASCII") from error


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
        raise AuditError(f"cannot read {context} from Git: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AuditError(f"cannot read {context} from Git: {detail}")
    if len(completed.stdout) > MAX_MANIFEST_BYTES:
        raise AuditError(f"{context} exceeds the frozen byte bound")
    return completed.stdout


def _capture_python_identity(
    stack: contextlib.ExitStack,
) -> tuple[dict[str, str], census.NamedSnapshot]:
    executable = Path(sys.executable).resolve(strict=True)
    snapshot = stack.enter_context(
        census.open_named_snapshot(
            executable,
            "audit Python executable",
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
        raise AuditError(f"cannot capture audit Python version: {error}") from error
    if completed.returncode != 0:
        raise AuditError("cannot capture audit Python version")
    try:
        version = completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise AuditError("audit Python version is not ASCII") from error
    return (
        {
            "path": str(executable),
            "sha256": snapshot.sha256,
            "version": version,
            "implementation": platform.python_implementation(),
            "cache_tag": sys.implementation.cache_tag or "none",
        },
        snapshot,
    )


def _capture_provenance(
    contract: EvidenceContract,
    stack: contextlib.ExitStack,
) -> tuple[dict[str, Any], tuple[census.NamedSnapshot, ...]]:
    revision = _run_git(["rev-parse", "HEAD^{commit}"])
    tree = _run_git(["rev-parse", "HEAD^{tree}"])
    if GIT_OID_RE.fullmatch(revision) is None or GIT_OID_RE.fullmatch(tree) is None:
        raise AuditError("Git audit revision or tree is not canonical")
    if contract.require_clean_git:
        dirty = _run_git(["status", "--porcelain=v1", "--untracked-files=all"])
        if dirty:
            raise AuditError("production T10 audit requires a clean Git worktree")
    if _run_git(["rev-parse", f"{DESIGN_COMMIT}^{{commit}}"] ) != DESIGN_COMMIT:
        raise AuditError("immutable T10 design commit is unavailable")
    if _run_git(["rev-parse", f"{DESIGN_COMMIT}^{{tree}}"] ) != DESIGN_TREE:
        raise AuditError("immutable T10 design tree mismatch")
    if _run_git(["rev-parse", f"{DESIGN_COMMIT}:{DESIGN_PATH}"]) != DESIGN_BLOB:
        raise AuditError("immutable T10 design blob mismatch")
    design_bytes = _run_git_bytes(
        ["cat-file", "blob", DESIGN_BLOB], "T10 design blob"
    )
    if sha256_bytes(design_bytes) != DESIGN_SHA256:
        raise AuditError("immutable T10 design bytes mismatch")

    snapshots: list[census.NamedSnapshot] = []
    code_hashes: dict[str, str] = {}
    for name, path in (
        ("runner_sha256", RUNNER_PATH),
        ("auditor_sha256", AUDITOR_PATH),
        ("hardened_stage0_sha256", HARDENED_STAGE0_PATH),
        ("cargo_lock_sha256", CARGO_LOCK_PATH),
    ):
        snapshot = stack.enter_context(
            census.open_named_snapshot(path, name, max_bytes=MAX_MANIFEST_BYTES)
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


def _assert_runner_contract_match() -> None:
    comparisons = {
        "record schema": (census.RECORD_SCHEMA, RECORD_SCHEMA),
        "summary schema": (census.SUMMARY_SCHEMA, SUMMARY_SCHEMA),
        "projection version": (census.PROJECTION_VERSION, PROJECTION_VERSION),
        "source count": (census.PRODUCTION_SOURCE_COUNT, PRODUCTION_SOURCE_COUNT),
        "manifest digest": (census.PRODUCTION_MANIFEST_SHA256, PRODUCTION_MANIFEST_SHA256),
        "source-set digest": (census.PRODUCTION_SOURCE_SET_SHA256, PRODUCTION_SOURCE_SET_SHA256),
        "QG count": (census.PRODUCTION_QG_SOURCE_COUNT, PRODUCTION_QG_SOURCE_COUNT),
        "control digest": (census.CONTROL_MANIFEST_SHA256, CONTROL_MANIFEST_SHA256),
        "control rows": (census.CONTROL_MANIFEST_ROWS, CONTROL_MANIFEST_ROWS),
        "control bytes": (census.CONTROL_MANIFEST_BYTES, CONTROL_MANIFEST_BYTES),
        "target path": (census.TARGET_PATH, TARGET_PATH),
        "target hash": (census.TARGET_SHA256, TARGET_SHA256),
        "frog identities": (census.FROG_SOURCES, FROG_SOURCES),
        "design commit": (census.DESIGN_COMMIT, DESIGN_COMMIT),
        "design tree": (census.DESIGN_TREE, DESIGN_TREE),
        "design path": (census.DESIGN_PATH, DESIGN_PATH),
        "design blob": (census.DESIGN_BLOB, DESIGN_BLOB),
        "design hash": (census.DESIGN_SHA256, DESIGN_SHA256),
        "minimum clauses": (census.MIN_CLOSED_CLAUSES, MIN_CLOSED_CLAUSES),
        "maximum clauses": (census.MAX_CLOSED_CLAUSES, MAX_CLOSED_CLAUSES),
        "literal cap": (census.MAX_CLOSED_LITERAL_SLOTS, MAX_CLOSED_LITERAL_SLOTS),
        "width cap": (census.MAX_CLOSED_CLAUSE_WIDTH, MAX_CLOSED_CLAUSE_WIDTH),
        "application cap": (census.MAX_APPLICATIONS, MAX_APPLICATIONS),
        "direct count fields": (census.DIRECT_COUNT_FIELDS, DIRECT_COUNT_FIELDS),
        "projected count fields": (census.PROJECTED_COUNT_FIELDS, PROJECTED_COUNT_FIELDS),
        "materialized count fields": (census.MATERIALIZED_COUNT_FIELDS, MATERIALIZED_COUNT_FIELDS),
        "count fields": (census.COUNT_FIELDS, COUNT_FIELDS),
        "Boolean fields": (census.BOOLEAN_FIELDS, BOOLEAN_FIELDS),
        "hash fields": (census.HASH_FIELDS, HASH_FIELDS),
        "token fields": (census.TOKEN_FIELDS, TOKEN_FIELDS),
        "accepted projection keys": (census.ACCEPTED_PROJECTION_KEYS, ACCEPTED_PROJECTION_KEYS),
        "error count fields": (census.ERROR_COUNT_FIELDS, ERROR_COUNT_FIELDS),
        "materialization pairs": (
            census.PROJECTED_MATERIALIZED_PAIRS,
            PROJECTED_MATERIALIZED_PAIRS,
        ),
        "zero side effects": (census.ZERO_SIDE_EFFECT_FIELDS, ZERO_SIDE_EFFECT_FIELDS),
        "backends": (census.BACKENDS, BACKENDS),
        "completed reasons": (census.COMPLETED_REASONS, COMPLETED_REASONS),
        "error reasons": (census.ERROR_REASONS, ERROR_REASONS),
        "projector environment": (census.PROJECTOR_ENVIRONMENT, PROJECTOR_ENVIRONMENT),
        "evidence boundary": (census.EVIDENCE_BOUNDARY, EVIDENCE_BOUNDARY),
        "production contract": (
            census.PRODUCTION_CONTRACT.descriptor(),
            PRODUCTION_CONTRACT.descriptor(),
        ),
    }
    drift = sorted(name for name, (runner, auditor) in comparisons.items() if runner != auditor)
    if drift:
        raise AuditError(f"runner/auditor contract drift: {', '.join(drift)}")


def _read_canonical_json(snapshot: census.NamedSnapshot, context: str) -> dict[str, Any]:
    try:
        text = snapshot.payload.decode("ascii")
    except UnicodeError as error:
        raise AuditError(f"{context}: artifact is not ASCII") from error
    if not snapshot.payload.endswith(b"\n") or len(text.splitlines()) != 1:
        raise AuditError(f"{context}: expected one newline-terminated JSON record")
    value = strict_json_loads(text, context)
    if type(value) is not dict:
        raise AuditError(f"{context}: JSON value must be an object")
    if canonical_json_bytes(value) != snapshot.payload:
        raise AuditError(f"{context}: JSON is not canonical")
    return value


def _read_canonical_records(snapshot: census.NamedSnapshot) -> list[dict[str, Any]]:
    try:
        text = snapshot.payload.decode("ascii")
    except UnicodeError as error:
        raise AuditError("records are not ASCII") from error
    if not snapshot.payload or not snapshot.payload.endswith(b"\n"):
        raise AuditError("records must be nonempty and newline terminated")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise AuditError(f"records line {line_number} is blank")
        record = strict_json_loads(line, f"records line {line_number}")
        if type(record) is not dict:
            raise AuditError(f"records line {line_number} is not an object")
        if canonical_json_bytes(record) != (line + "\n").encode("ascii"):
            raise AuditError(f"records line {line_number} is not canonical JSON")
        records.append(record)
    return records


def _sandbox_contract(timeout_seconds: float) -> dict[str, Any]:
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


def _validate_provenance(value: object, expected: Mapping[str, Any], context: str) -> None:
    if type(value) is not dict:
        raise AuditError(f"{context}: provenance must be an object")
    _exact_keys(value, PROVENANCE_FIELDS, f"{context}:provenance")
    python = value["python"]
    if type(python) is not dict:
        raise AuditError(f"{context}: Python identity must be an object")
    _exact_keys(python, PYTHON_FIELDS, f"{context}:python")
    for field in PYTHON_FIELDS:
        _require_ascii(python[field], f"{context}:python:{field}")
    if value != expected:
        differing = sorted(
            field
            for field in PROVENANCE_FIELDS
            if value.get(field) != expected.get(field)
        )
        raise AuditError(f"{context}: provenance mismatch: {', '.join(differing)}")


def _validate_summary_shape(summary: object) -> dict[str, Any]:
    if type(summary) is not dict:
        raise AuditError("summary must be an object")
    _exact_keys(summary, SUMMARY_FIELDS, "summary")
    for field in (
        "source_count",
        "qg_source_count",
        "control_source_count",
        "selected_count",
        "manifest_bytes",
        "opened_source_count",
        "opened_source_bytes",
        "binary_bytes",
        "records_bytes",
        "sat_calls",
    ):
        _require_uint(summary[field], f"summary:{field}")
    for field in (
        "schema",
        "status",
        "contract_kind",
        "contract_sha256",
        "selected_set_sha256",
        "manifest_sha256",
        "source_set_sha256",
        "opened_source_set_sha256",
        "control_manifest_sha256",
        "binary_sha256",
        "records_sha256",
        "record_chain_head",
        "evidence_boundary",
    ):
        _require_ascii(summary[field], f"summary:{field}", token=True)
    if type(summary["selected_paths"]) is not list or not all(
        type(path) is str for path in summary["selected_paths"]
    ):
        raise AuditError("summary:selected_paths must be a string array")
    if type(summary["reason_counts"]) is not dict:
        raise AuditError("summary:reason_counts must be an object")
    for reason, count in summary["reason_counts"].items():
        if reason not in COMPLETED_REASONS or _require_uint(count, f"summary:{reason}") == 0:
            raise AuditError("summary contains an invalid reason aggregate")
    if type(summary["error_counts"]) is not dict:
        raise AuditError("summary:error_counts must be an object")
    _exact_keys(summary["error_counts"], ERROR_COUNT_FIELDS, "summary:error_counts")
    for field in ERROR_COUNT_FIELDS:
        if _require_uint(summary["error_counts"][field], f"summary:error_counts:{field}") != 0:
            raise AuditError("summary error aggregate is nonzero")
    if summary["projector_environment"] != PROJECTOR_ENVIRONMENT:
        raise AuditError("summary projector environment drift")
    if type(summary["sandbox_contract"]) is not dict:
        raise AuditError("summary sandbox contract must be an object")
    timeout = summary["sandbox_contract"].get("timeout_seconds")
    if (
        type(timeout) is not float
        or not math.isfinite(timeout)
        or not 0 < timeout <= MAX_PROJECTION_TIMEOUT_SECONDS
    ):
        raise AuditError("summary sandbox timeout is invalid")
    if summary["sandbox_contract"] != _sandbox_contract(timeout):
        raise AuditError("summary sandbox contract drift")
    return summary


def _selected_binding(
    path: str, source_sha256: str, projection: Mapping[str, Any]
) -> dict[str, Any]:
    binding = {
        "relative_path": path,
        "source_sha256": source_sha256,
        "projection_sha256": canonical_hash(dict(projection)),
        "closed_clauses": projection["projected_closed_clauses"],
        "literal_slots": projection["projected_literal_slots"],
        "max_clause_width": projection["projected_max_clause_width"],
        "clause_sha256": projection["projected_clauses_sha256"],
    }
    _exact_keys(binding, SELECTED_BINDING_FIELDS, f"{path}:selected binding")
    return binding


def _audit_census(
    manifest_path: Path,
    corpus_root: Path,
    binary: Path,
    records_path: Path,
    summary_path: Path,
    receipt_out: Path,
    *,
    contract: object,
) -> dict[str, Any]:
    _assert_runner_contract_match()
    normalized = _normalize_contract(contract)
    if corpus_root is None:
        raise AuditError("corpus root is mandatory")
    if receipt_out.exists():
        raise AuditError(f"refusing to overwrite existing receipt {receipt_out}")

    with contextlib.ExitStack() as stack:
        manifest_snapshot = stack.enter_context(
            census.open_named_snapshot(manifest_path, "manifest", max_bytes=MAX_MANIFEST_BYTES)
        )
        sources = _parse_manifest(manifest_snapshot.payload)
        control, control_snapshot = _resolve_control_binding(normalized)
        if control_snapshot is not None:
            stack.enter_context(control_snapshot)
        _validate_source_population(
            sources, manifest_snapshot.sha256, normalized, control
        )
        provenance, provenance_snapshots = _capture_provenance(normalized, stack)
        binary_snapshot = stack.enter_context(
            census.open_named_snapshot(
                binary,
                "projection binary",
                max_bytes=MAX_BINARY_BYTES,
                require_executable=True,
            )
        )
        records_snapshot = stack.enter_context(
            census.read_published_artifact(records_path, "records")
        )
        summary_snapshot = stack.enter_context(
            census.read_published_artifact(summary_path, "summary")
        )
        records = _read_canonical_records(records_snapshot)
        summary = _validate_summary_shape(
            _read_canonical_json(summary_snapshot, "summary")
        )
        _validate_provenance(summary["provenance"], provenance, "summary")
        if len(records) != normalized.expected_sources:
            raise AuditError(
                f"record count mismatch: expected {normalized.expected_sources}, got {len(records)}"
            )

        timeout_seconds = summary["sandbox_contract"]["timeout_seconds"]
        previous_hash = ZERO_SHA256
        selected_identities: list[tuple[str, str]] = []
        selected_bindings: list[dict[str, Any]] = []
        replayed_bindings: list[dict[str, Any]] = []
        reason_counts: Counter[str] = Counter()
        error_counts: Counter[str] = Counter()
        opened_source_set: list[dict[str, Any]] = []
        opened_total_bytes = 0
        replay_projector = stack.enter_context(census.ProjectorSnapshot(binary))
        if replay_projector.sha256 != binary_snapshot.sha256:
            raise AuditError("replay projector binary hash mismatch")

        with census.CorpusRoot(corpus_root) as corpus:
            for source, record in zip(sources, records, strict=True):
                _exact_keys(record, RECORD_FIELDS, f"{source.relative_path}:record")
                if record["schema"] != RECORD_SCHEMA:
                    raise AuditError(f"{source.relative_path}: record schema mismatch")
                if record["contract_sha256"] != normalized.sha256:
                    raise AuditError(f"{source.relative_path}: contract digest mismatch")
                source_record = record["source"]
                if type(source_record) is not dict:
                    raise AuditError(f"{source.relative_path}: source record is not an object")
                _exact_keys(source_record, SOURCE_FIELDS, f"{source.relative_path}:source")
                source_bytes = corpus.snapshot(source)
                opened_sha256 = sha256_bytes(source_bytes)
                expected_source_record = {
                    "id": source.record_id,
                    "relative_path": source.relative_path,
                    "manifest_bytes": source.source_bytes,
                    "manifest_sha256": source.source_sha256,
                    "opened_bytes": len(source_bytes),
                    "opened_sha256": opened_sha256,
                }
                if source_record != expected_source_record:
                    raise AuditError(f"{source.relative_path}: source/opened identity mismatch")
                if record["binary_sha256"] != binary_snapshot.sha256:
                    raise AuditError(f"{source.relative_path}: binary hash mismatch")
                if record["previous_record_sha256"] != previous_hash:
                    raise AuditError(f"{source.relative_path}: record-chain predecessor mismatch")
                without_hash = dict(record)
                recorded_hash = without_hash.pop("record_sha256")
                actual_hash = canonical_hash(without_hash)
                if recorded_hash != actual_hash:
                    raise AuditError(f"{source.relative_path}: record hash mismatch")
                previous_hash = actual_hash
                projection = _validate_projection_shape(
                    record["projection"], source.relative_path
                )
                _validate_projection_semantics(projection, source.relative_path)
                if projection["selected"]:
                    selected_identities.append(
                        (source.relative_path, source.source_sha256)
                    )
                    selected_bindings.append(
                        _selected_binding(
                            source.relative_path, source.source_sha256, projection
                        )
                    )
                    replayed = _run_selected_projection(
                        replay_projector,
                        source_bytes,
                        source.relative_path,
                        timeout_seconds,
                    )
                    if replayed != projection:
                        differing = sorted(
                            field
                            for field in ACCEPTED_PROJECTION_KEYS
                            if replayed.get(field) != projection.get(field)
                        )
                        raise AuditError(
                            f"{source.relative_path}: selected replay mismatch: "
                            f"{', '.join(differing)}"
                        )
                    replayed_bindings.append(
                        _selected_binding(
                            source.relative_path, source.source_sha256, replayed
                        )
                    )
                reason_counts[projection["reason"]] += 1
                for field in ERROR_COUNT_FIELDS:
                    error_counts[field] += projection[field]
                opened_total_bytes = _checked_add(
                    opened_total_bytes,
                    len(source_bytes),
                    context="opened source byte total",
                )
                opened_source_set.append(
                    {
                        "relative_path": source.relative_path,
                        "bytes": len(source_bytes),
                        "sha256": opened_sha256,
                    }
                )
            corpus.revalidate()

        actual_selected = tuple(selected_identities)
        if actual_selected != normalized.expected_selected_sources:
            raise AuditError(
                "selected population mismatch: "
                f"expected {normalized.expected_selected_sources!r}, got {actual_selected!r}"
            )
        if any(error_counts.values()):
            raise AuditError("audited projection error aggregate is nonzero")

        selected_paths = [path for path, _digest in selected_identities]
        qg_count = sum(source.relative_path.startswith(QG_PREFIX) for source in sources)
        expected_status = (
            "completed_no_sat"
            if normalized.kind == "production"
            else "completed_no_sat_test_only"
        )
        expected_summary = {
            "schema": SUMMARY_SCHEMA,
            "status": expected_status,
            "contract_kind": normalized.kind,
            "contract_sha256": normalized.sha256,
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
            "source_set_sha256": canonical_hash(_source_set_value(sources)),
            "opened_source_count": len(opened_source_set),
            "opened_source_bytes": opened_total_bytes,
            "opened_source_set_sha256": canonical_hash(opened_source_set),
            "control_manifest_sha256": control.sha256,
            "binary_bytes": len(binary_snapshot.payload),
            "binary_sha256": binary_snapshot.sha256,
            "records_bytes": len(records_snapshot.payload),
            "records_sha256": records_snapshot.sha256,
            "record_chain_head": previous_hash,
            "sat_calls": 0,
            "projector_environment": PROJECTOR_ENVIRONMENT,
            "sandbox_contract": _sandbox_contract(timeout_seconds),
            "provenance": provenance,
            "evidence_boundary": EVIDENCE_BOUNDARY,
        }
        if summary != expected_summary:
            differing = sorted(
                field
                for field in SUMMARY_FIELDS
                if summary.get(field) != expected_summary.get(field)
            )
            raise AuditError(f"summary recomputation mismatch: {', '.join(differing)}")

        selected_projection_sha256 = canonical_hash(selected_bindings)
        replayed_selected_projection_sha256 = canonical_hash(replayed_bindings)
        if selected_projection_sha256 != replayed_selected_projection_sha256:
            raise AuditError("selected projection aggregate differs from replay")
        receipt = {
            "schema": AUDIT_SCHEMA,
            "status": "pass" if normalized.kind == "production" else "pass_test_only",
            "contract_kind": normalized.kind,
            "contract_sha256": normalized.sha256,
            "source_count": len(sources),
            "qg_source_count": qg_count,
            "control_source_count": control.row_count,
            "selected_count": len(selected_paths),
            "selected_paths": selected_paths,
            "selected_set_sha256": expected_summary["selected_set_sha256"],
            "replayed_selected_count": len(replayed_bindings),
            "selected_projection_sha256": selected_projection_sha256,
            "replayed_selected_projection_sha256": replayed_selected_projection_sha256,
            "selected_projection_bindings": selected_bindings,
            "record_chain_head": previous_hash,
            "evidence_boundary": EVIDENCE_BOUNDARY,
            "provenance": provenance,
            "artifacts": {
                "manifest_bytes": len(manifest_snapshot.payload),
                "manifest_sha256": manifest_snapshot.sha256,
                "source_set_sha256": normalized.source_set_sha256,
                "opened_source_set_sha256": expected_summary["opened_source_set_sha256"],
                "control_manifest_sha256": control.sha256,
                "binary_bytes": len(binary_snapshot.payload),
                "binary_sha256": binary_snapshot.sha256,
                "runner_sha256": provenance["runner_sha256"],
                "auditor_sha256": provenance["auditor_sha256"],
                "hardened_stage0_sha256": provenance["hardened_stage0_sha256"],
                "cargo_lock_sha256": provenance["cargo_lock_sha256"],
                "design_commit": DESIGN_COMMIT,
                "design_tree": DESIGN_TREE,
                "design_blob": DESIGN_BLOB,
                "design_sha256": DESIGN_SHA256,
                "records_bytes": len(records_snapshot.payload),
                "records_sha256": records_snapshot.sha256,
                "summary_bytes": len(summary_snapshot.payload),
                "summary_sha256": summary_snapshot.sha256,
                "records_mode": 0o400,
                "summary_mode": 0o400,
            },
        }
        _exact_keys(receipt, RECEIPT_FIELDS, "receipt")
        _exact_keys(receipt["artifacts"], RECEIPT_ARTIFACT_FIELDS, "receipt:artifacts")

        manifest_snapshot.revalidate("manifest")
        binary_snapshot.revalidate("projection binary")
        replay_projector.revalidate()
        records_snapshot.revalidate("records")
        summary_snapshot.revalidate("summary")
        if control_snapshot is not None:
            control_snapshot.revalidate("frozen rollback control manifest")
        for snapshot in provenance_snapshots:
            snapshot.revalidate(str(snapshot.path))
        census.immutable_write_new(receipt_out, canonical_json_bytes(receipt))
        receipt_snapshot = stack.enter_context(
            census.read_published_artifact(receipt_out, "audit receipt")
        )
        if receipt_snapshot.payload != canonical_json_bytes(receipt):
            raise AuditError("published receipt bytes changed")
        records_snapshot.revalidate("records")
        summary_snapshot.revalidate("summary")
        receipt_snapshot.revalidate("audit receipt")
        return receipt


def audit_census(
    manifest_path: Path,
    corpus_root: Path,
    binary: Path,
    records_path: Path,
    summary_path: Path,
    receipt_out: Path,
    *,
    contract: object = PRODUCTION_CONTRACT,
) -> dict[str, Any]:
    try:
        return _audit_census(
            manifest_path,
            corpus_root,
            binary,
            records_path,
            summary_path,
            receipt_out,
            contract=contract,
        )
    except census.CensusError as error:
        raise AuditError(str(error)) from error


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_argument_parser()
    arguments = parser.parse_args()
    try:
        receipt = audit_census(
            arguments.manifest,
            arguments.corpus_root,
            arguments.binary,
            arguments.records,
            arguments.summary,
            arguments.receipt_out,
        )
    except AuditError as error:
        parser.error(str(error))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
