#!/usr/bin/env python3
"""Independently audit the frozen T9 no-SAT Stage-0 projection census."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import run_t9_projection_census as census  # noqa: E402


AUDIT_SCHEMA = "euf-viper.t9-projection-audit.v2"
RECORD_SCHEMA = "euf-viper.t9-projection-record.v2"
SUMMARY_SCHEMA = "euf-viper.t9-projection-census.v2"
ZERO_SHA256 = "0" * 64
MAX_U64 = (1 << 64) - 1
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_PROJECTOR_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_PROJECTOR_ADDRESS_SPACE_BYTES = 6 * 1024**3
MAX_PROJECTOR_OPEN_FILES = 32
MAX_PROJECTION_TIMEOUT_SECONDS = 60.0
GIT_OID_RE = re.compile(r"[0-9a-f]{40,64}\Z")

RUNNER_PATH = ROOT / "scripts/bench/run_t9_projection_census.py"
AUDITOR_PATH = ROOT / "scripts/bench/audit_t9_projection_census.py"
DESIGN_PATH = ROOT / "research-vault/02-design/2026-07-15-t9-clique-gated-ackermann-escape.md"

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
CONTROL_MANIFEST_PATH = ROOT / "campaigns/t9-rollback-control-manifest-20260713.jsonl"
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
REQUIRED_PROJECTION_FIELDS = (
    COUNT_FIELDS | COUNT_STATE_FIELDS | BOOLEAN_FIELDS | TEXT_FIELDS
)
COUNT_STATES = {"not_computed", "exact", "lower_bound", "unavailable"}
BACKENDS = {"kissat", "cadical", "fallback"}
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
            else census.canonical_hash(dict(self.target_projection))
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
        return census.canonical_hash(self.descriptor())


PRODUCTION_CONTRACT = EvidenceContract(
    kind="production",
    expected_sources=PRODUCTION_SOURCE_COUNT,
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
    target_path=TARGET_PATH,
    target_projection={
        "all_different_clique_lb": 60,
        "applications": 138,
        "backend": "kissat",
        "baseline_after_sha256": "738eb37efc536a48ca70772be0525f4a872508c67daf5fb35ae0cd5814925aca",
        "baseline_before_sha256": "738eb37efc536a48ca70772be0525f4a872508c67daf5fb35ae0cd5814925aca",
        "baseline_clauses": 89470,
        "baseline_literal_slots": 147132,
        "baseline_vars": 21744,
        "closed_table_functions": 0,
        "covered_finite_terms": 0,
        "disequality_clique_excess_edges": 3,
        "disequality_graph_edges": 1773,
        "equality_graph_edges": 14241,
        "equality_graph_vertices": 4838,
        "finite_added": 0,
        "materialized_ackermann_clauses": 3686,
        "materialized_ackermann_clauses_state": "exact",
        "materialized_ackermann_literal_slots": 7958,
        "materialized_ackermann_literal_slots_state": "exact",
        "materialized_added_literal_slots": 4561103,
        "materialized_added_literal_slots_state": "exact",
        "materialized_added_vars": 16951,
        "materialized_added_vars_state": "exact",
        "materialized_candidate_clauses": 93156,
        "materialized_candidate_clauses_state": "exact",
        "materialized_candidate_literal_slots": 155090,
        "materialized_candidate_literal_slots_state": "exact",
        "materialized_candidate_sha256": "bca990827a3adc0b60d27fe4acb8c00172559146eee162bcdd7acdb2d9ce7dbb",
        "materialized_candidate_vars": 38695,
        "materialized_candidate_vars_state": "exact",
        "materialized_fill_edges": 9900,
        "materialized_fill_edges_state": "exact",
        "materialized_transitivity_clauses": 1517715,
        "materialized_transitivity_clauses_state": "exact",
        "materialized_transitivity_literal_slots": 4553145,
        "materialized_transitivity_literal_slots_state": "exact",
        "materialized_triangle_visits": 616496,
        "materialized_triangle_visits_state": "exact",
        "mode": "clique-auto",
        "planned_ackermann_candidate_pairs": 3686,
        "planned_ackermann_candidate_pairs_state": "exact",
        "planned_ackermann_clauses": 3686,
        "planned_ackermann_clauses_state": "exact",
        "planned_ackermann_function_differing_argument_pairs": 4272,
        "planned_ackermann_function_differing_argument_pairs_state": "exact",
        "planned_ackermann_function_pairs": 3686,
        "planned_ackermann_function_pairs_state": "exact",
        "planned_ackermann_literal_slots": 7958,
        "planned_ackermann_literal_slots_state": "exact",
        "planned_ackermann_predicate_differing_argument_pairs": 0,
        "planned_ackermann_predicate_differing_argument_pairs_state": "exact",
        "planned_ackermann_predicate_pairs": 0,
        "planned_ackermann_predicate_pairs_state": "exact",
        "planned_added_literal_slots": 4561103,
        "planned_added_literal_slots_state": "exact",
        "planned_added_vars": 16951,
        "planned_added_vars_state": "exact",
        "planned_application_argument_slots": 268,
        "planned_application_argument_slots_state": "exact",
        "planned_candidate_clauses": 93156,
        "planned_candidate_clauses_state": "exact",
        "planned_candidate_literal_slots": 155090,
        "planned_candidate_literal_slots_state": "exact",
        "planned_candidate_vars": 38695,
        "planned_candidate_vars_state": "exact",
        "planned_fill_edges": 9900,
        "planned_fill_edges_state": "exact",
        "planned_fill_pair_examinations": 505905,
        "planned_fill_pair_examinations_state": "exact",
        "planned_max_arity": 2,
        "planned_max_arity_state": "exact",
        "planned_transitivity_clauses": 1517715,
        "planned_transitivity_clauses_state": "exact",
        "planned_transitivity_literal_slots": 4553145,
        "planned_transitivity_literal_slots_state": "exact",
        "planned_triangle_visits": 616496,
        "planned_triangle_visits_state": "exact",
        "reason": "selected",
        "sat_calls": 0,
        "selected": True,
        "selector_selected": True,
        "terms": 8682,
        "triangle_visits_definition": "eligible_third_vertex_probes",
    },
    require_clean_git=True,
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
SOURCE_FIELDS = {"id", "relative_path", "bytes", "sha256"}
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
    "manifest_sha256",
    "source_set_sha256",
    "control_manifest_sha256",
    "binary_sha256",
    "records_sha256",
    "record_chain_head",
    "sat_calls",
    "environment_contract",
    "sandbox_contract",
    "provenance",
    "evidence_boundary",
}
PROVENANCE_FIELDS = {
    "git_revision",
    "git_tree",
    "runner_sha256",
    "auditor_sha256",
    "design_sha256",
}
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
    "record_chain_head",
    "evidence_boundary",
    "provenance",
    "artifacts",
}
RECEIPT_ARTIFACT_FIELDS = {
    "manifest_sha256",
    "source_set_sha256",
    "control_manifest_sha256",
    "binary_sha256",
    "runner_sha256",
    "auditor_sha256",
    "design_sha256",
    "records_sha256",
    "summary_sha256",
    "records_mode",
    "summary_mode",
}

SELECTOR_REASONS = {
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
PLAN_REASONS = {
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

MATERIALIZATION_PAIRS = {
    "planned_ackermann_clauses": "materialized_ackermann_clauses",
    "planned_ackermann_literal_slots": "materialized_ackermann_literal_slots",
    "planned_fill_edges": "materialized_fill_edges",
    "planned_added_vars": "materialized_added_vars",
    "planned_transitivity_clauses": "materialized_transitivity_clauses",
    "planned_triangle_visits": "materialized_triangle_visits",
    "planned_transitivity_literal_slots": "materialized_transitivity_literal_slots",
    "planned_candidate_vars": "materialized_candidate_vars",
    "planned_candidate_clauses": "materialized_candidate_clauses",
    "planned_candidate_literal_slots": "materialized_candidate_literal_slots",
    "planned_added_literal_slots": "materialized_added_literal_slots",
}

FOOTPRINT_PLAN_FIELDS = {
    "planned_max_arity",
    "planned_application_argument_slots",
}
ACKERMANN_PLAN_FIELDS = {
    "planned_ackermann_function_pairs",
    "planned_ackermann_predicate_pairs",
    "planned_ackermann_candidate_pairs",
    "planned_ackermann_function_differing_argument_pairs",
    "planned_ackermann_predicate_differing_argument_pairs",
    "planned_ackermann_clauses",
    "planned_ackermann_literal_slots",
}
FILL_PLAN_FIELDS = {
    "planned_fill_edges",
    "planned_fill_pair_examinations",
}
VARIABLE_PLAN_FIELDS = {
    "planned_added_vars",
    "planned_candidate_vars",
}
TRANSITIVITY_PLAN_FIELDS = {
    "planned_transitivity_clauses",
    "planned_triangle_visits",
    "planned_transitivity_literal_slots",
}
FINAL_PLAN_FIELDS = {
    "planned_candidate_clauses",
    "planned_candidate_literal_slots",
    "planned_added_literal_slots",
}


class AuditError(RuntimeError):
    """Raised when a census does not satisfy the frozen Stage-0 gate."""


def _assert_runner_contract_match() -> None:
    comparisons = {
        "record schema": (census.RECORD_SCHEMA, RECORD_SCHEMA),
        "summary schema": (census.SUMMARY_SCHEMA, SUMMARY_SCHEMA),
        "source count": (census.PRODUCTION_SOURCE_COUNT, PRODUCTION_SOURCE_COUNT),
        "source-set digest": (
            census.PRODUCTION_SOURCE_SET_SHA256,
            PRODUCTION_SOURCE_SET_SHA256,
        ),
        "QG count": (census.PRODUCTION_QG_SOURCE_COUNT, PRODUCTION_QG_SOURCE_COUNT),
        "control digest": (census.CONTROL_MANIFEST_SHA256, CONTROL_MANIFEST_SHA256),
        "control rows": (census.CONTROL_MANIFEST_ROWS, CONTROL_MANIFEST_ROWS),
        "control bytes": (census.CONTROL_MANIFEST_BYTES, CONTROL_MANIFEST_BYTES),
        "target path": (census.TARGET_PATH, TARGET_PATH),
        "target hash": (census.TARGET_SHA256, TARGET_SHA256),
        "frog identities": (census.FROG_SOURCES, FROG_SOURCES),
        "QG prefix": (census.QG_PREFIX, QG_PREFIX),
        "term cap": (census.MAX_TERMS, MAX_TERMS),
        "base clause cap": (census.MAX_BASE_CLAUSES, MAX_BASE_CLAUSES),
        "base literal cap": (census.MAX_BASE_LITERAL_SLOTS, MAX_BASE_LITERAL_SLOTS),
        "application cap": (census.MAX_APPLICATIONS, MAX_APPLICATIONS),
        "arity cap": (census.MAX_ARITY, MAX_ARITY),
        "argument-slot cap": (
            census.MAX_APPLICATION_ARGUMENT_SLOTS,
            MAX_APPLICATION_ARGUMENT_SLOTS,
        ),
        "Ackermann cap": (census.MAX_ACKERMANN_CLAUSES, MAX_ACKERMANN_CLAUSES),
        "fill cap": (census.MAX_FILL_EDGES, MAX_FILL_EDGES),
        "fill-examination cap": (
            census.MAX_FILL_PAIR_EXAMINATIONS,
            MAX_FILL_PAIR_EXAMINATIONS,
        ),
        "transitivity cap": (
            census.MAX_TRANSITIVITY_CLAUSES,
            MAX_TRANSITIVITY_CLAUSES,
        ),
        "triangle cap": (census.MAX_TRIANGLE_VISITS, MAX_TRIANGLE_VISITS),
        "variable cap": (census.MAX_FINAL_VARIABLES, MAX_FINAL_VARIABLES),
        "added-literal cap": (
            census.MAX_ADDED_LITERAL_SLOTS,
            MAX_ADDED_LITERAL_SLOTS,
        ),
        "direct count fields": (census.DIRECT_COUNT_FIELDS, DIRECT_COUNT_FIELDS),
        "planned count fields": (census.PLANNED_COUNT_FIELDS, PLANNED_COUNT_FIELDS),
        "materialized count fields": (
            census.MATERIALIZED_COUNT_FIELDS,
            MATERIALIZED_COUNT_FIELDS,
        ),
        "stateful count fields": (
            census.STATEFUL_COUNT_FIELDS,
            STATEFUL_COUNT_FIELDS,
        ),
        "count fields": (census.COUNT_FIELDS, COUNT_FIELDS),
        "state fields": (census.COUNT_STATE_FIELDS, COUNT_STATE_FIELDS),
        "Boolean fields": (census.BOOLEAN_FIELDS, BOOLEAN_FIELDS),
        "hash fields": (census.HASH_FIELDS, HASH_FIELDS),
        "text fields": (census.TEXT_FIELDS, TEXT_FIELDS),
        "projection schema": (census.REQUIRED_FIELDS, REQUIRED_PROJECTION_FIELDS),
        "count states": (census.COUNT_STATES, COUNT_STATES),
        "backends": (census.BACKENDS, BACKENDS),
        "reason vocabulary": (census.REASON_VOCABULARY, REASON_VOCABULARY),
        "completed reasons": (census.COMPLETED_REASONS, COMPLETED_REASONS),
        "projector environment": (census.PROJECTOR_ENVIRONMENT, PROJECTOR_ENVIRONMENT),
        "evidence boundary": (census.EVIDENCE_BOUNDARY, EVIDENCE_BOUNDARY),
        "manifest byte cap": (census.MAX_MANIFEST_BYTES, MAX_MANIFEST_BYTES),
        "source byte cap": (census.MAX_SOURCE_BYTES, MAX_SOURCE_BYTES),
        "binary byte cap": (census.MAX_BINARY_BYTES, MAX_BINARY_BYTES),
        "projector output cap": (
            census.MAX_PROJECTOR_OUTPUT_BYTES,
            MAX_PROJECTOR_OUTPUT_BYTES,
        ),
        "projector address-space cap": (
            census.MAX_PROJECTOR_ADDRESS_SPACE_BYTES,
            MAX_PROJECTOR_ADDRESS_SPACE_BYTES,
        ),
        "projector open-file cap": (
            census.MAX_PROJECTOR_OPEN_FILES,
            MAX_PROJECTOR_OPEN_FILES,
        ),
        "projector timeout cap": (
            census.MAX_PROJECTION_TIMEOUT_SECONDS,
            MAX_PROJECTION_TIMEOUT_SECONDS,
        ),
        "production contract": (
            census.PRODUCTION_CONTRACT.descriptor(),
            PRODUCTION_CONTRACT.descriptor(),
        ),
    }
    drift = sorted(name for name, (runner, auditor) in comparisons.items() if runner != auditor)
    if drift:
        raise AuditError(f"runner/auditor contract drift: {', '.join(drift)}")


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
        raise AuditError(f"manifest is not UTF-8: {error}") from error
    if not payload or not payload.endswith(b"\n"):
        raise AuditError("manifest must be nonempty and newline terminated")
    sources: list[ManifestSource] = []
    seen_ids: set[int | str] = set()
    seen_paths: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        context = f"manifest line {line_number}"
        if not line:
            raise AuditError(f"{context}: blank record")
        row = census.strict_json_loads(line, context)
        if type(row) is not dict:
            raise AuditError(f"{context}: record must be an object")
        record_id = row.get("id")
        if type(record_id) not in {int, str}:
            raise AuditError(f"{context}: id must be an integer or string")
        if record_id in seen_ids:
            raise AuditError(f"{context}: duplicate id")
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


def _source_set_value(
    sources: list[ManifestSource],
) -> list[dict[str, str]]:
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
        row = census.strict_json_loads(line, f"{context} line {line_number}")
        if type(row) is not dict:
            raise AuditError(f"{context} line {line_number}: record must be an object")
        path = _canonical_relative_path(
            row.get("relative_path"), f"{context} line {line_number}"
        )
        digest = row.get("sha256")
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise AuditError(f"{context} line {line_number}: invalid SHA-256")
        if path in seen:
            raise AuditError(f"{context}: duplicate path {path}")
        seen.add(path)
        identities.append((path, digest))
    return tuple(sorted(identities))


def _test_control_payload(identities: tuple[tuple[str, str], ...]) -> bytes:
    return b"".join(
        census.canonical_json_bytes({"relative_path": path, "sha256": digest})
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
        census.sha256_bytes(payload), len(payload), len(identities), identities
    )
    if binding != contract.control:
        raise AuditError("test control binding does not match its embedded digest")
    return binding, None


def _contract_uint(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise AuditError(f"contract {field} must be an unsigned integer")
    return value


def _normalize_contract(contract: object) -> EvidenceContract:
    try:
        kind = contract.kind
        expected_sources = contract.expected_sources
        source_set_sha256 = contract.source_set_sha256
        expected_qg_sources = contract.expected_qg_sources
        raw_required_sources = contract.required_sources
        raw_control = contract.control
        target_path = contract.target_path
        target_projection = contract.target_projection
        require_clean_git = contract.require_clean_git
    except AttributeError as error:
        raise AuditError("audit contract is missing a frozen field") from error

    if type(kind) is not str or kind not in {"production", "test"}:
        raise AuditError(f"unsupported evidence contract kind {kind!r}")
    expected_sources = _contract_uint(expected_sources, "expected_sources")
    expected_qg_sources = _contract_uint(expected_qg_sources, "expected_qg_sources")
    if expected_sources == 0 or expected_qg_sources > expected_sources:
        raise AuditError("contract source populations are invalid")
    if type(source_set_sha256) is not str or SHA256_RE.fullmatch(source_set_sha256) is None:
        raise AuditError("contract source-set digest is invalid")
    if type(raw_required_sources) is not tuple:
        raise AuditError("contract required_sources must be a frozen tuple")
    required_sources: list[tuple[str, str]] = []
    for index, identity in enumerate(raw_required_sources):
        if type(identity) is not tuple or len(identity) != 2:
            raise AuditError(f"contract required source {index} is invalid")
        path = _canonical_relative_path(identity[0], f"contract required source {index}")
        digest = identity[1]
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise AuditError(f"contract required source {index} has an invalid digest")
        required_sources.append((path, digest))
    if (
        tuple(required_sources) != tuple(sorted(required_sources))
        or len({path for path, _digest in required_sources}) != len(required_sources)
    ):
        raise AuditError("contract required sources are not unique and sorted")

    try:
        control_sha256 = raw_control.sha256
        control_bytes = raw_control.byte_count
        control_rows = raw_control.row_count
        raw_control_identities = raw_control.identities
    except AttributeError as error:
        raise AuditError("audit control contract is missing a frozen field") from error
    if type(control_sha256) is not str or SHA256_RE.fullmatch(control_sha256) is None:
        raise AuditError("contract control digest is invalid")
    control_bytes = _contract_uint(control_bytes, "control byte count")
    control_rows = _contract_uint(control_rows, "control row count")
    if type(raw_control_identities) is not tuple:
        raise AuditError("contract control identities must be a frozen tuple")
    control_identities: list[tuple[str, str]] = []
    for index, identity in enumerate(raw_control_identities):
        if type(identity) is not tuple or len(identity) != 2:
            raise AuditError(f"contract control identity {index} is invalid")
        path = _canonical_relative_path(identity[0], f"contract control identity {index}")
        digest = identity[1]
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise AuditError(f"contract control identity {index} has an invalid digest")
        control_identities.append((path, digest))
    if (
        tuple(control_identities) != tuple(sorted(control_identities))
        or len({path for path, _digest in control_identities})
        != len(control_identities)
    ):
        raise AuditError("contract control identities are not unique and sorted")
    control = ControlBinding(
        control_sha256,
        control_bytes,
        control_rows,
        tuple(control_identities),
    )

    target_path = _canonical_relative_path(target_path, "contract target")
    if target_projection is not None and type(target_projection) is not dict:
        raise AuditError("contract target projection must be an exact JSON object")
    if type(require_clean_git) is not bool:
        raise AuditError("contract require_clean_git must be a Boolean")
    normalized = EvidenceContract(
        kind=kind,
        expected_sources=expected_sources,
        source_set_sha256=source_set_sha256,
        expected_qg_sources=expected_qg_sources,
        required_sources=tuple(required_sources),
        control=control,
        target_path=target_path,
        target_projection=(
            None if target_projection is None else dict(target_projection)
        ),
        require_clean_git=require_clean_git,
    )
    if normalized.kind == "production":
        if normalized.descriptor() != PRODUCTION_CONTRACT.descriptor():
            raise AuditError("caller attempted to alter the production audit contract")
        return PRODUCTION_CONTRACT
    if normalized.require_clean_git:
        raise AuditError("test audit requires an explicit nonproduction contract")
    return normalized


def _run_git(arguments: list[str]) -> str:
    system_git = Path("/usr/bin/git")
    git = str(system_git) if system_git.is_file() else shutil.which("git")
    if git is None:
        raise AuditError("git is required to bind T9 audit provenance")
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
        raise AuditError(f"cannot query Git audit provenance: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AuditError(f"Git audit provenance query failed: {detail}")
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise AuditError("Git audit provenance is not ASCII") from error


def _capture_provenance(
    contract: EvidenceContract,
    stack: contextlib.ExitStack,
) -> tuple[dict[str, str], tuple[census.NamedSnapshot, ...]]:
    revision = _run_git(["rev-parse", "HEAD^{commit}"])
    tree = _run_git(["rev-parse", "HEAD^{tree}"])
    if GIT_OID_RE.fullmatch(revision) is None or GIT_OID_RE.fullmatch(tree) is None:
        raise AuditError("Git revision or tree is not canonical")
    if contract.require_clean_git:
        dirty = _run_git(["status", "--porcelain=v1", "--untracked-files=all"])
        if dirty:
            raise AuditError("production T9 audit requires a completely clean Git worktree")
    bindings: dict[str, str] = {"git_revision": revision, "git_tree": tree}
    snapshots: list[census.NamedSnapshot] = []
    for name, path in (
        ("runner_sha256", RUNNER_PATH),
        ("auditor_sha256", AUDITOR_PATH),
        ("design_sha256", DESIGN_PATH),
    ):
        snapshot = stack.enter_context(
            census.open_named_snapshot(path, name, max_bytes=MAX_MANIFEST_BYTES)
        )
        snapshots.append(snapshot)
        bindings[name] = snapshot.sha256
    return bindings, tuple(snapshots)


def _validate_source_population(
    sources: list[ManifestSource],
    contract: EvidenceContract,
    control: ControlBinding,
) -> None:
    if len(sources) != contract.expected_sources:
        raise AuditError(
            f"source count mismatch: expected {contract.expected_sources}, got {len(sources)}"
        )
    source_set_sha256 = census.canonical_hash(_source_set_value(sources))
    if source_set_sha256 != contract.source_set_sha256:
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
        raise AuditError(
            f"QG population mismatch: expected {contract.expected_qg_sources}, got {qg_count}"
        )
    for path, digest in control.identities:
        source = by_path.get(path)
        if source is None:
            raise AuditError(f"frozen control source is absent: {path}")
        if source.source_sha256 != digest:
            raise AuditError(f"frozen control source hash drift: {path}")


def _assert_contract_ready(contract: EvidenceContract) -> None:
    if contract.target_projection is None:
        raise AuditError(
            "production target anchors are not frozen from the final Rust schema; "
            "Stage 0 remains blocked"
        )
    if set(contract.target_projection) != REQUIRED_PROJECTION_FIELDS:
        raise AuditError("target anchors do not use the exact auditor projection schema")


def _sandbox_contract(timeout_seconds: float) -> dict[str, Any]:
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


def _exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing {', '.join(missing)}")
    if unknown:
        details.append(f"unknown {', '.join(unknown)}")
    raise AuditError(f"{context}: schema mismatch ({'; '.join(details)})")


def _require_int(value: object, context: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise AuditError(f"{context} must be an unsigned 64-bit integer")
    return value


def _require_bool(value: object, context: str) -> bool:
    if type(value) is not bool:
        raise AuditError(f"{context} must be a JSON Boolean")
    return value


def _require_text(value: object, context: str) -> str:
    if type(value) is not str or not value or not value.isascii():
        raise AuditError(f"{context} must be nonempty ASCII text")
    if any(character.isspace() for character in value):
        raise AuditError(f"{context} must not contain whitespace")
    return value


def _read_canonical_json(snapshot: census.NamedSnapshot, context: str) -> dict[str, Any]:
    try:
        text = snapshot.payload.decode("ascii")
    except UnicodeError as error:
        raise AuditError(f"{context}: artifact is not ASCII: {error}") from error
    if not snapshot.payload.endswith(b"\n") or len(text.splitlines()) != 1:
        raise AuditError(f"{context}: expected one newline-terminated JSON record")
    value = census.strict_json_loads(text, context)
    if type(value) is not dict:
        raise AuditError(f"{context}: JSON value must be an object")
    if census.canonical_json_bytes(value) != snapshot.payload:
        raise AuditError(f"{context}: JSON is not canonical")
    return value


def _read_canonical_records(
    snapshot: census.NamedSnapshot,
) -> list[dict[str, Any]]:
    try:
        text = snapshot.payload.decode("ascii")
    except UnicodeError as error:
        raise AuditError(f"records are not ASCII: {error}") from error
    if not snapshot.payload or not snapshot.payload.endswith(b"\n"):
        raise AuditError("records must be nonempty and newline terminated")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise AuditError(f"records line {line_number} is blank")
        record = census.strict_json_loads(line, f"records line {line_number}")
        if type(record) is not dict:
            raise AuditError(f"records line {line_number} is not an object")
        if census.canonical_json_bytes(record) != (line + "\n").encode("ascii"):
            raise AuditError(f"records line {line_number} is not canonical JSON")
        records.append(record)
    return records


def _validate_count_state(projection: Mapping[str, Any], field: str, path: str) -> None:
    value = _require_int(projection[field], f"{path}:{field}")
    state = _require_text(projection[f"{field}_state"], f"{path}:{field}_state")
    if state not in COUNT_STATES:
        raise AuditError(f"{path}:{field}_state is outside the frozen vocabulary")
    if state in {"not_computed", "unavailable"} and value != 0:
        raise AuditError(f"{path}:{field} must be zero in state {state}")
    if state == "lower_bound" and value == 0:
        raise AuditError(f"{path}:{field} lower bound must be positive")


def _validate_projection_shape(projection: object, path: str) -> dict[str, Any]:
    if type(projection) is not dict:
        raise AuditError(f"{path}: projection must be an object")
    _exact_keys(projection, REQUIRED_PROJECTION_FIELDS, f"{path}:projection")
    for field in COUNT_FIELDS:
        _require_int(projection[field], f"{path}:{field}")
    for field in BOOLEAN_FIELDS:
        _require_bool(projection[field], f"{path}:{field}")
    for field in COUNT_STATE_FIELDS | TEXT_FIELDS:
        _require_text(projection[field], f"{path}:{field}")
    for field in STATEFUL_COUNT_FIELDS:
        _validate_count_state(projection, field, path)
    if projection["mode"] != "clique-auto":
        raise AuditError(f"{path}: mode is not clique-auto")
    if projection["backend"] not in BACKENDS:
        raise AuditError(f"{path}: backend is outside the frozen vocabulary")
    if projection["reason"] not in REASON_VOCABULARY:
        raise AuditError(f"{path}: reason is outside the frozen vocabulary")
    if projection["triangle_visits_definition"] != "eligible_third_vertex_probes":
        raise AuditError(f"{path}: triangle-visits definition drift")
    for field in HASH_FIELDS:
        if SHA256_RE.fullmatch(projection[field]) is None:
            raise AuditError(f"{path}:{field} is not a canonical SHA-256")
    if projection["sat_calls"] != 0:
        raise AuditError(f"{path}: sat_calls is not zero")
    if projection["reason"] not in COMPLETED_REASONS:
        raise AuditError(
            f"{path}: semantic projection error {projection['reason']!r} "
            "cannot occur in a completed census"
        )
    return projection


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


def _selector_reason(projection: Mapping[str, Any], path: str) -> str | None:
    clique = projection["all_different_clique_lb"]
    minimum_edges = _checked_pair_count(clique, f"{path}:disequality clique C(d,2)")
    edges = projection["disequality_graph_edges"]
    excess = projection["disequality_clique_excess_edges"]
    expected_edges = _checked_add(
        minimum_edges,
        excess,
        context=f"{path}:disequality edge/excess equation",
    )
    if edges != expected_edges:
        raise AuditError(
            f"{path}: disequality_graph_edges must equal C(clique_lb,2) plus "
            "disequality_clique_excess_edges"
        )
    ordered_conditions = (
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
    return next((reason for failed, reason in ordered_conditions if failed), None)


def _state(projection: Mapping[str, Any], field: str) -> str:
    return projection[f"{field}_state"]


def _exact_count(projection: Mapping[str, Any], field: str, path: str) -> int:
    if _state(projection, field) != "exact":
        raise AuditError(f"{path}:{field} must be exact")
    return projection[field]


def _require_not_computed_vector(
    projection: Mapping[str, Any], fields: set[str], path: str
) -> None:
    for field in fields:
        if projection[field] != 0 or _state(projection, field) != "not_computed":
            raise AuditError(f"{path}:{field} must be zero/not_computed")


def _plan_reason(projection: Mapping[str, Any], path: str) -> str | None:
    direct_checks = (
        (projection["terms"] > MAX_TERMS, "term_count_cap"),
        (projection["baseline_clauses"] > MAX_BASE_CLAUSES, "base_clause_cap"),
        (
            projection["baseline_literal_slots"] > MAX_BASE_LITERAL_SLOTS,
            "base_literal_slot_cap",
        ),
        (projection["baseline_vars"] > MAX_FINAL_VARIABLES, "final_variable_cap"),
    )
    direct_reason = next((reason for failed, reason in direct_checks if failed), None)
    if direct_reason is not None:
        return direct_reason

    max_arity_state = _state(projection, "planned_max_arity")
    argument_slots_state = _state(projection, "planned_application_argument_slots")
    if max_arity_state == "lower_bound":
        if projection["planned_max_arity"] <= MAX_ARITY:
            raise AuditError(f"{path}: max-arity lower bound does not prove its cap")
        return "arity_cap"
    if argument_slots_state == "lower_bound":
        if projection["planned_application_argument_slots"] <= MAX_APPLICATION_ARGUMENT_SLOTS:
            raise AuditError(f"{path}: argument-slot lower bound does not prove its cap")
        return "application_argument_slot_cap"
    if max_arity_state != "exact" or argument_slots_state != "exact":
        raise AuditError(f"{path}: footprint plan counts are not exact")
    if projection["planned_max_arity"] > MAX_ARITY:
        return "arity_cap"
    if projection["planned_application_argument_slots"] > MAX_APPLICATION_ARGUMENT_SLOTS:
        return "application_argument_slot_cap"

    for field in ACKERMANN_PLAN_FIELDS:
        _exact_count(projection, field, path)
    if projection["planned_ackermann_clauses"] > MAX_ACKERMANN_CLAUSES:
        return "ackermann_clause_cap"

    fill_edge_state = _state(projection, "planned_fill_edges")
    fill_exam_state = _state(projection, "planned_fill_pair_examinations")
    if "lower_bound" in {fill_edge_state, fill_exam_state}:
        if {fill_edge_state, fill_exam_state} != {"lower_bound"}:
            raise AuditError(f"{path}: fill rejection must bind both lower bounds")
        if projection["planned_fill_edges"] > MAX_FILL_EDGES:
            return "fill_edge_cap"
        if projection["planned_fill_pair_examinations"] > MAX_FILL_PAIR_EXAMINATIONS:
            return "fill_pair_examination_cap"
        raise AuditError(f"{path}: fill lower bounds do not prove a cap failure")
    if fill_edge_state != "exact" or fill_exam_state != "exact":
        raise AuditError(f"{path}: fill plan counts are not exact")
    if projection["planned_fill_edges"] > MAX_FILL_EDGES:
        return "fill_edge_cap"
    if projection["planned_fill_pair_examinations"] > MAX_FILL_PAIR_EXAMINATIONS:
        return "fill_pair_examination_cap"

    for field in VARIABLE_PLAN_FIELDS:
        _exact_count(projection, field, path)
    if projection["planned_candidate_vars"] > MAX_FINAL_VARIABLES:
        return "final_variable_cap"

    transitivity_state = _state(projection, "planned_transitivity_clauses")
    triangle_state = _state(projection, "planned_triangle_visits")
    if "lower_bound" in {transitivity_state, triangle_state}:
        if {transitivity_state, triangle_state} != {"lower_bound"}:
            raise AuditError(
                f"{path}: transitivity rejection must bind both lower bounds"
            )
        if projection["planned_transitivity_clauses"] > MAX_TRANSITIVITY_CLAUSES:
            return "transitivity_clause_cap"
        if projection["planned_triangle_visits"] > MAX_TRIANGLE_VISITS:
            return "triangle_visit_cap"
        raise AuditError(
            f"{path}: transitivity lower bounds do not prove a cap failure"
        )
    for field in TRANSITIVITY_PLAN_FIELDS:
        _exact_count(projection, field, path)
    if projection["planned_transitivity_clauses"] > MAX_TRANSITIVITY_CLAUSES:
        return "transitivity_clause_cap"
    if projection["planned_triangle_visits"] > MAX_TRIANGLE_VISITS:
        return "triangle_visit_cap"

    for field in FINAL_PLAN_FIELDS:
        _exact_count(projection, field, path)
    if projection["planned_added_literal_slots"] > MAX_ADDED_LITERAL_SLOTS:
        return "added_literal_slot_cap"
    return None


def _require_rejected_plan_vector(
    projection: Mapping[str, Any], reason: str, path: str
) -> None:
    expected = {field: "not_computed" for field in PLANNED_COUNT_FIELDS}

    def mark_exact(*groups: set[str]) -> None:
        for group in groups:
            for field in group:
                expected[field] = "exact"

    if reason == "final_variable_cap" and projection["baseline_vars"] > MAX_FINAL_VARIABLES:
        expected["planned_candidate_vars"] = "lower_bound"
    elif reason == "arity_cap":
        expected["planned_max_arity"] = "lower_bound"
    elif reason == "application_argument_slot_cap":
        expected["planned_application_argument_slots"] = "lower_bound"
    elif reason == "ackermann_clause_cap":
        mark_exact(FOOTPRINT_PLAN_FIELDS, ACKERMANN_PLAN_FIELDS)
    elif reason in {"fill_edge_cap", "fill_pair_examination_cap"}:
        mark_exact(FOOTPRINT_PLAN_FIELDS, ACKERMANN_PLAN_FIELDS)
        expected["planned_fill_edges"] = "lower_bound"
        expected["planned_fill_pair_examinations"] = "lower_bound"
    elif reason == "final_variable_cap":
        mark_exact(
            FOOTPRINT_PLAN_FIELDS,
            ACKERMANN_PLAN_FIELDS,
            FILL_PLAN_FIELDS,
            VARIABLE_PLAN_FIELDS,
        )
    elif reason in {"transitivity_clause_cap", "triangle_visit_cap"}:
        mark_exact(
            FOOTPRINT_PLAN_FIELDS,
            ACKERMANN_PLAN_FIELDS,
            FILL_PLAN_FIELDS,
            VARIABLE_PLAN_FIELDS,
        )
        expected["planned_transitivity_clauses"] = "lower_bound"
        expected["planned_triangle_visits"] = "lower_bound"
    elif reason == "added_literal_slot_cap":
        mark_exact(PLANNED_COUNT_FIELDS)
    elif reason not in {"term_count_cap", "base_clause_cap", "base_literal_slot_cap"}:
        raise AuditError(f"{path}: no frozen plan vector for reason {reason}")

    for field in PLANNED_COUNT_FIELDS:
        actual_state = _state(projection, field)
        if actual_state != expected[field]:
            raise AuditError(
                f"{path}:{field} state {actual_state} disagrees with frozen "
                f"{reason} vector {expected[field]}"
            )
    if reason == "final_variable_cap" and projection["baseline_vars"] > MAX_FINAL_VARIABLES:
        if projection["planned_candidate_vars"] != projection["baseline_vars"]:
            raise AuditError(f"{path}: baseline variable-cap lower bound is inconsistent")


def _all_exact(projection: Mapping[str, Any], fields: set[str]) -> bool:
    return all(_state(projection, field) == "exact" for field in fields)


def _validate_available_plan_equations(
    projection: Mapping[str, Any], path: str
) -> None:
    if _all_exact(projection, FOOTPRINT_PLAN_FIELDS):
        applications = projection["applications"]
        max_arity = projection["planned_max_arity"]
        argument_slots = projection["planned_application_argument_slots"]
        if applications == 0:
            if max_arity != 0 or argument_slots != 0:
                raise AuditError(f"{path}: zero applications have a nonzero footprint")
        else:
            if max_arity == 0 or argument_slots < applications:
                raise AuditError(f"{path}: application footprint is impossible")
            maximum_slots = _checked_mul(
                applications,
                max_arity,
                context=f"{path}:application argument-slot upper bound",
            )
            if argument_slots > maximum_slots:
                raise AuditError(f"{path}: application argument slots exceed arity bound")
        if max_arity > argument_slots:
            raise AuditError(f"{path}: max arity exceeds total application argument slots")

    if _all_exact(projection, ACKERMANN_PLAN_FIELDS):
        function_pairs = projection["planned_ackermann_function_pairs"]
        predicate_pairs = projection["planned_ackermann_predicate_pairs"]
        candidate_pairs = _checked_add(
            function_pairs,
            predicate_pairs,
            context=f"{path}:Ackermann candidate-pair equation",
        )
        if projection["planned_ackermann_candidate_pairs"] != candidate_pairs:
            raise AuditError(f"{path}: Ackermann candidate-pair equation failed")
        all_application_pairs = _checked_pair_count(
            projection["applications"], f"{path}:application pair bound"
        )
        if candidate_pairs > all_application_pairs:
            raise AuditError(f"{path}: Ackermann candidate pairs exceed C(applications,2)")
        expected_ackermann_clauses = _checked_add(
            function_pairs,
            _checked_mul(
                2, predicate_pairs, context=f"{path}:predicate Ackermann clauses"
            ),
            context=f"{path}:Ackermann clause equation",
        )
        if projection["planned_ackermann_clauses"] != expected_ackermann_clauses:
            raise AuditError(f"{path}: Ackermann clause equation failed")
        function_differences = projection[
            "planned_ackermann_function_differing_argument_pairs"
        ]
        predicate_differences = projection[
            "planned_ackermann_predicate_differing_argument_pairs"
        ]
        if _all_exact(projection, FOOTPRINT_PLAN_FIELDS):
            max_arity = projection["planned_max_arity"]
            function_difference_max = _checked_mul(
                function_pairs,
                max_arity,
                context=f"{path}:function differing-argument upper bound",
            )
            predicate_difference_max = _checked_mul(
                predicate_pairs,
                max_arity,
                context=f"{path}:predicate differing-argument upper bound",
            )
            if not function_pairs <= function_differences <= function_difference_max:
                raise AuditError(f"{path}: function differing-argument count is impossible")
            if not predicate_pairs <= predicate_differences <= predicate_difference_max:
                raise AuditError(f"{path}: predicate differing-argument count is impossible")
        expected_ackermann_literals = _checked_add(
            function_pairs,
            function_differences,
            _checked_mul(
                4, predicate_pairs, context=f"{path}:predicate Ackermann literals"
            ),
            _checked_mul(
                2,
                predicate_differences,
                context=f"{path}:predicate differing-argument literals",
            ),
            context=f"{path}:Ackermann literal equation",
        )
        if projection["planned_ackermann_literal_slots"] != expected_ackermann_literals:
            raise AuditError(f"{path}: Ackermann literal equation failed")

    fill_states = {_state(projection, field) for field in FILL_PLAN_FIELDS}
    if fill_states <= {"exact", "lower_bound"}:
        fill_edges = projection["planned_fill_edges"]
        fill_examinations = projection["planned_fill_pair_examinations"]
        if fill_examinations < fill_edges:
            raise AuditError(f"{path}: fill pair examinations are below emitted fill edges")
        possible_edges = _checked_pair_count(projection["terms"], f"{path}:fill edge bound")
        if fill_edges > possible_edges:
            raise AuditError(f"{path}: fill edges exceed C(terms,2)")

    if _all_exact(projection, VARIABLE_PLAN_FIELDS):
        expected_candidate_vars = _checked_add(
            projection["baseline_vars"],
            projection["planned_added_vars"],
            context=f"{path}:candidate variable equation",
        )
        if projection["planned_candidate_vars"] != expected_candidate_vars:
            raise AuditError(f"{path}: candidate variable equation failed")

    if _all_exact(projection, TRANSITIVITY_PLAN_FIELDS):
        transitivity_clauses = projection["planned_transitivity_clauses"]
        transitivity_literals = projection["planned_transitivity_literal_slots"]
        maximum_transitivity_literals = _checked_mul(
            3,
            transitivity_clauses,
            context=f"{path}:transitivity literal upper bound",
        )
        if not transitivity_clauses <= transitivity_literals <= maximum_transitivity_literals:
            raise AuditError(
                f"{path}: transitivity literal slots must account for unit/ternary clauses"
            )
        ternary_deficit = maximum_transitivity_literals - transitivity_literals
        if ternary_deficit % 2 != 0:
            raise AuditError(
                f"{path}: transitivity unit/ternary literal equation has odd deficit"
            )

    if _all_exact(projection, FINAL_PLAN_FIELDS):
        expected_added_literals = _checked_add(
            projection["planned_ackermann_literal_slots"],
            projection["planned_transitivity_literal_slots"],
            context=f"{path}:added literal equation",
        )
        if projection["planned_added_literal_slots"] != expected_added_literals:
            raise AuditError(f"{path}: added literal equation failed")
        expected_candidate_clauses = _checked_add(
            projection["baseline_clauses"],
            projection["planned_ackermann_clauses"],
            context=f"{path}:candidate clause equation",
        )
        if projection["planned_candidate_clauses"] != expected_candidate_clauses:
            raise AuditError(f"{path}: candidate clause equation failed")
        expected_candidate_literals = _checked_add(
            projection["baseline_literal_slots"],
            projection["planned_ackermann_literal_slots"],
            context=f"{path}:candidate literal equation",
        )
        if projection["planned_candidate_literal_slots"] != expected_candidate_literals:
            raise AuditError(f"{path}: candidate literal equation failed")


def _validate_plan_equations(projection: Mapping[str, Any], path: str) -> None:
    for field in PLANNED_COUNT_FIELDS:
        _exact_count(projection, field, path)
    _validate_available_plan_equations(projection, path)


def _validate_projection_semantics(projection: Mapping[str, Any], path: str) -> None:
    if projection["baseline_before_sha256"] == ZERO_SHA256:
        raise AuditError(f"{path}: baseline-before hash cannot be zero")
    if projection["baseline_before_sha256"] != projection["baseline_after_sha256"]:
        raise AuditError(f"{path}: baseline CNF/atom hash changed")
    selector_reason = _selector_reason(projection, path)
    if selector_reason is not None:
        if projection["selector_selected"]:
            raise AuditError(f"{path}: selector true despite first failure {selector_reason}")
        if projection["selected"]:
            raise AuditError(f"{path}: selector-rejected row is selected")
        if projection["reason"] != selector_reason:
            raise AuditError(
                f"{path}: expected first selector reason {selector_reason}, "
                f"got {projection['reason']}"
            )
        _require_not_computed_vector(
            projection, PLANNED_COUNT_FIELDS, path
        )
        _require_not_computed_vector(
            projection, MATERIALIZED_COUNT_FIELDS, path
        )
        if projection["materialized_candidate_sha256"] != ZERO_SHA256:
            raise AuditError(f"{path}: selector-rejected row has a candidate hash")
        return

    if not projection["selector_selected"]:
        raise AuditError(f"{path}: selector false although every selector condition passes")
    plan_reason = _plan_reason(projection, path)
    if plan_reason is not None:
        if projection["selected"]:
            raise AuditError(f"{path}: cap-rejected row is selected")
        if projection["reason"] != plan_reason:
            raise AuditError(
                f"{path}: expected first plan reason {plan_reason}, got {projection['reason']}"
            )
        _require_not_computed_vector(
            projection, MATERIALIZED_COUNT_FIELDS, path
        )
        if projection["materialized_candidate_sha256"] != ZERO_SHA256:
            raise AuditError(f"{path}: rejected plan has a materialized candidate hash")
        _require_rejected_plan_vector(projection, plan_reason, path)
        _validate_available_plan_equations(projection, path)
        return

    if projection["reason"] != "selected" or not projection["selected"]:
        raise AuditError(f"{path}: all selector/plan conditions pass but row is not selected")
    _validate_plan_equations(projection, path)
    for planned, materialized in MATERIALIZATION_PAIRS.items():
        planned_value = _exact_count(projection, planned, path)
        materialized_value = _exact_count(projection, materialized, path)
        if materialized_value != planned_value:
            raise AuditError(
                f"{path}: {materialized} differs from accepted {planned}"
            )
    if projection["materialized_candidate_sha256"] == ZERO_SHA256:
        raise AuditError(f"{path}: selected row lacks a materialized candidate hash")


def _validate_provenance(value: object, expected: Mapping[str, str], context: str) -> None:
    if type(value) is not dict:
        raise AuditError(f"{context}: provenance must be an object")
    _exact_keys(value, PROVENANCE_FIELDS, f"{context}:provenance")
    for field in PROVENANCE_FIELDS:
        actual = _require_text(value[field], f"{context}:provenance:{field}")
        if actual != expected[field]:
            raise AuditError(f"{context}: provenance field {field} mismatch")


def _validate_summary_shape(summary: object) -> dict[str, Any]:
    if type(summary) is not dict:
        raise AuditError("summary must be an object")
    _exact_keys(summary, SUMMARY_FIELDS, "summary")
    for field in (
        "source_count",
        "qg_source_count",
        "control_source_count",
        "selected_count",
        "sat_calls",
    ):
        _require_int(summary[field], f"summary:{field}")
    for field in (
        "schema",
        "status",
        "contract_kind",
        "contract_sha256",
        "selected_set_sha256",
        "manifest_sha256",
        "source_set_sha256",
        "control_manifest_sha256",
        "binary_sha256",
        "records_sha256",
        "record_chain_head",
        "environment_contract",
        "evidence_boundary",
    ):
        _require_text(summary[field], f"summary:{field}")
    if type(summary["selected_paths"]) is not list or not all(
        type(path) is str for path in summary["selected_paths"]
    ):
        raise AuditError("summary:selected_paths must be a string array")
    if type(summary["reason_counts"]) is not dict:
        raise AuditError("summary:reason_counts must be an object")
    for reason, count in summary["reason_counts"].items():
        if reason not in COMPLETED_REASONS:
            raise AuditError(f"summary contains invalid reason {reason!r}")
        if _require_int(count, f"summary:reason_counts:{reason}") == 0:
            raise AuditError("summary reason counts must be positive")
    if type(summary["sandbox_contract"]) is not dict:
        raise AuditError("summary:sandbox_contract must be an object")
    timeout = summary["sandbox_contract"].get("timeout_seconds")
    if (
        type(timeout) is not float
        or not math.isfinite(timeout)
        or not 0 < timeout <= MAX_PROJECTION_TIMEOUT_SECONDS
    ):
        raise AuditError(
            "summary sandbox timeout must be a bounded positive JSON float"
        )
    if summary["sandbox_contract"] != _sandbox_contract(timeout):
        raise AuditError("summary sandbox contract drift")
    return summary


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
    contract = _normalize_contract(contract)
    if corpus_root is None:
        raise AuditError("corpus root is mandatory")
    if receipt_out.exists():
        raise AuditError(f"refusing to overwrite existing receipt {receipt_out}")

    with contextlib.ExitStack() as stack:
        manifest_snapshot = stack.enter_context(
            census.open_named_snapshot(
                manifest_path,
                "manifest",
                max_bytes=MAX_MANIFEST_BYTES,
            )
        )
        sources = _parse_manifest(manifest_snapshot.payload)
        control, control_snapshot = _resolve_control_binding(contract)
        if control_snapshot is not None:
            stack.enter_context(control_snapshot)
        _validate_source_population(sources, contract, control)
        _assert_contract_ready(contract)
        provenance, provenance_snapshots = _capture_provenance(contract, stack)
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
        if len(records) != contract.expected_sources:
            raise AuditError(
                f"record count mismatch: expected {contract.expected_sources}, got {len(records)}"
            )

        with census.CorpusRoot(corpus_root) as corpus:
            for source in sources:
                corpus.snapshot(source)
            corpus.revalidate()

        previous_hash = ZERO_SHA256
        selected_paths: list[str] = []
        reason_counts: Counter[str] = Counter()
        by_path: dict[str, dict[str, Any]] = {}
        for source, record in zip(sources, records, strict=True):
            _exact_keys(record, RECORD_FIELDS, f"{source.relative_path}:record")
            if record["schema"] != RECORD_SCHEMA:
                raise AuditError(f"{source.relative_path}: record schema mismatch")
            if record["contract_sha256"] != contract.sha256:
                raise AuditError(f"{source.relative_path}: contract digest mismatch")
            source_record = record["source"]
            if type(source_record) is not dict:
                raise AuditError(f"{source.relative_path}: source record must be an object")
            _exact_keys(source_record, SOURCE_FIELDS, f"{source.relative_path}:source")
            record_id = source_record["id"]
            if type(record_id) not in {int, str}:
                raise AuditError(f"{source.relative_path}: source id type is invalid")
            expected_source = {
                "id": source.record_id,
                "relative_path": source.relative_path,
                "bytes": source.source_bytes,
                "sha256": source.source_sha256,
            }
            if source_record != expected_source:
                raise AuditError(f"{source.relative_path}: source identity mismatch")
            if record["binary_sha256"] != binary_snapshot.sha256:
                raise AuditError(f"{source.relative_path}: binary hash mismatch")
            if record["previous_record_sha256"] != previous_hash:
                raise AuditError(f"{source.relative_path}: record-chain predecessor mismatch")
            record_without_hash = dict(record)
            recorded_hash = record_without_hash.pop("record_sha256")
            actual_hash = census.canonical_hash(record_without_hash)
            if recorded_hash != actual_hash:
                raise AuditError(f"{source.relative_path}: record hash mismatch")
            previous_hash = actual_hash
            projection = _validate_projection_shape(
                record["projection"], source.relative_path
            )
            _validate_projection_semantics(projection, source.relative_path)
            if projection["selected"]:
                selected_paths.append(source.relative_path)
            reason_counts[projection["reason"]] += 1
            by_path[source.relative_path] = projection

        target_projection = by_path.get(contract.target_path)
        if target_projection is None:
            raise AuditError("frozen target is absent")
        if target_projection != dict(contract.target_projection or {}):
            raise AuditError("frozen target projection anchors mismatch")
        if not target_projection["selected"]:
            raise AuditError("frozen terminal timeout was not selected")
        for frog_path in FROG_SOURCES:
            if frog_path in by_path and by_path[frog_path]["selected"]:
                raise AuditError(f"known frogs regressor was selected: {frog_path}")
        selected_qg = [path for path in selected_paths if path.startswith(QG_PREFIX)]
        if selected_qg:
            raise AuditError(f"QG sources were selected: {selected_qg[:5]}")

        expected_status = (
            "completed_no_sat"
            if contract.kind == "production"
            else "completed_no_sat_test_only"
        )
        qg_count = sum(source.relative_path.startswith(QG_PREFIX) for source in sources)
        expected_summary = {
            "schema": SUMMARY_SCHEMA,
            "status": expected_status,
            "contract_kind": contract.kind,
            "contract_sha256": contract.sha256,
            "source_count": len(sources),
            "qg_source_count": qg_count,
            "control_source_count": control.row_count,
            "selected_count": len(selected_paths),
            "selected_paths": selected_paths,
            "selected_set_sha256": census.canonical_hash(selected_paths),
            "reason_counts": dict(sorted(reason_counts.items())),
            "manifest_sha256": manifest_snapshot.sha256,
            "source_set_sha256": census.canonical_hash(_source_set_value(sources)),
            "control_manifest_sha256": control.sha256,
            "binary_sha256": binary_snapshot.sha256,
            "records_sha256": records_snapshot.sha256,
            "record_chain_head": previous_hash,
            "sat_calls": 0,
            "environment_contract": "only_LANG_LC_ALL_TZ",
            "sandbox_contract": summary["sandbox_contract"],
            "provenance": provenance,
            "evidence_boundary": EVIDENCE_BOUNDARY,
        }
        if summary != expected_summary:
            differing = sorted(
                key
                for key in SUMMARY_FIELDS
                if summary.get(key) != expected_summary.get(key)
            )
            raise AuditError(f"summary recomputation mismatch: {', '.join(differing)}")

        receipt = {
            "schema": AUDIT_SCHEMA,
            "status": "pass" if contract.kind == "production" else "pass_test_only",
            "contract_kind": contract.kind,
            "contract_sha256": contract.sha256,
            "source_count": len(sources),
            "qg_source_count": qg_count,
            "control_source_count": control.row_count,
            "selected_count": len(selected_paths),
            "selected_paths": selected_paths,
            "selected_set_sha256": census.canonical_hash(selected_paths),
            "record_chain_head": previous_hash,
            "evidence_boundary": EVIDENCE_BOUNDARY,
            "provenance": provenance,
            "artifacts": {
                "manifest_sha256": manifest_snapshot.sha256,
                "source_set_sha256": contract.source_set_sha256,
                "control_manifest_sha256": control.sha256,
                "binary_sha256": binary_snapshot.sha256,
                "runner_sha256": provenance["runner_sha256"],
                "auditor_sha256": provenance["auditor_sha256"],
                "design_sha256": provenance["design_sha256"],
                "records_sha256": records_snapshot.sha256,
                "summary_sha256": summary_snapshot.sha256,
                "records_mode": 0o400,
                "summary_mode": 0o400,
            },
        }
        _exact_keys(receipt, RECEIPT_FIELDS, "receipt")
        _exact_keys(receipt["artifacts"], RECEIPT_ARTIFACT_FIELDS, "receipt:artifacts")

        manifest_snapshot.revalidate("manifest")
        binary_snapshot.revalidate("projection binary")
        records_snapshot.revalidate("records")
        summary_snapshot.revalidate("summary")
        if control_snapshot is not None:
            control_snapshot.revalidate("frozen rollback control manifest")
        for snapshot in provenance_snapshots:
            snapshot.revalidate(str(snapshot.path))
        census.immutable_write_new(receipt_out, census.canonical_json_bytes(receipt))
        receipt_snapshot = stack.enter_context(
            census.read_published_artifact(receipt_out, "audit receipt")
        )
        if receipt_snapshot.payload != census.canonical_json_bytes(receipt):
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
