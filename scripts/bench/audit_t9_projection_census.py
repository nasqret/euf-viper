#!/usr/bin/env python3
"""Independently audit the frozen T9 no-SAT projection census."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import run_t9_projection_census as census  # noqa: E402


AUDIT_SCHEMA = "euf-viper.t9-projection-audit.v1"
TARGET_PATH = (
    "QF_UF/2018-Goel-hwbench/"
    "QF_UF_sokoban.2.prop1_ab_br_max.smt2"
)
TARGET_SHA256 = "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112"
FORBIDDEN_GOEL_PATHS = {
    "QF_UF/2018-Goel-hwbench/QF_UF_frogs.1.prop1_ab_br_max.smt2",
    "QF_UF/2018-Goel-hwbench/QF_UF_frogs.4.prop1_ab_br_max.smt2",
}
QG_PREFIX = "QF_UF/QG-classification/"


class AuditError(RuntimeError):
    """Raised when a census does not satisfy the preregistered Stage-0 gate."""


def _read_json_file(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        payload = path.read_bytes()
        text = payload.decode("ascii")
    except (OSError, UnicodeError) as error:
        raise AuditError(f"cannot read canonical JSON {path}: {error}") from error
    if not payload.endswith(b"\n") or len(text.splitlines()) != 1:
        raise AuditError(f"{path} must contain one newline-terminated JSON record")
    value = census.strict_json_loads(text, str(path))
    if type(value) is not dict:
        raise AuditError(f"{path} must contain a JSON object")
    if census.canonical_json_bytes(value) != payload:
        raise AuditError(f"{path} is not canonical JSON")
    return value, payload


def _read_records(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    try:
        payload = path.read_bytes()
        text = payload.decode("ascii")
    except (OSError, UnicodeError) as error:
        raise AuditError(f"cannot read canonical JSONL {path}: {error}") from error
    if not payload or not payload.endswith(b"\n"):
        raise AuditError("records must be nonempty and newline terminated")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise AuditError(f"records line {line_number} is blank")
        record = census.strict_json_loads(line, f"records line {line_number}")
        if type(record) is not dict:
            raise AuditError(f"records line {line_number} is not an object")
        if census.canonical_json_bytes(record).decode("ascii").rstrip("\n") != line:
            raise AuditError(f"records line {line_number} is not canonical JSON")
        records.append(record)
    return records, payload


def _require_exact_int(value: object, context: str) -> int:
    if type(value) is not int or value < 0:
        raise AuditError(f"{context} must be a nonnegative integer")
    return value


def _validate_projection(projection: object, path: str) -> dict[str, int | str]:
    if type(projection) is not dict:
        raise AuditError(f"{path}: projection must be an object")
    missing = sorted(census.REQUIRED_FIELDS - projection.keys())
    if missing:
        raise AuditError(f"{path}: projection is missing {', '.join(missing)}")
    for field in census.COUNT_FIELDS | census.BOOLEAN_FIELDS:
        _require_exact_int(projection[field], f"{path}:{field}")
    for field in census.BOOLEAN_FIELDS:
        if projection[field] not in {0, 1}:
            raise AuditError(f"{path}:{field} must be 0 or 1")
    for field in census.TEXT_FIELDS:
        value = projection[field]
        if not isinstance(value, str) or not value or not value.isascii():
            raise AuditError(f"{path}:{field} must be nonempty ASCII text")
    if projection["sat_calls"] != 0:
        raise AuditError(f"{path}: projection called SAT")
    if projection["off_path_unchanged"] != 1:
        raise AuditError(f"{path}: off-path CNF changed")
    return projection


def _validate_selected(projection: dict[str, int | str], path: str) -> None:
    integer = {key: int(projection[key]) for key in census.COUNT_FIELDS}
    if projection["backend"] != "kissat":
        raise AuditError(f"{path}: selected route is not actual Kissat")
    if projection["reason"] != "selected":
        raise AuditError(f"{path}: selected route has nonselected reason")
    if projection["materialization_match"] != 1:
        raise AuditError(f"{path}: plan and materialization differ")
    if integer["finite_added"] != 0:
        raise AuditError(f"{path}: finite clauses were emitted")
    if integer["covered_finite_terms"] != 0:
        raise AuditError(f"{path}: finite coverage is nonzero")
    if integer["closed_table_functions"] != 0:
        raise AuditError(f"{path}: closed-table encoding is present")
    if integer["all_different_clique_lb"] < 48:
        raise AuditError(f"{path}: clique lower bound is below 48")
    if integer["disequality_clique_excess_edges"] > 8:
        raise AuditError(f"{path}: excess disequality edges exceed eight")
    if integer["equality_graph_vertices"] < 2500:
        raise AuditError(f"{path}: equality graph has fewer than 2500 vertices")
    if integer["equality_graph_edges"] < 10000:
        raise AuditError(f"{path}: equality graph has fewer than 10000 edges")
    if integer["applications"] > 256:
        raise AuditError(f"{path}: application cap exceeded")
    bounds = {
        "ackermann_clauses": 5000,
        "fill_edges": 20000,
        "transitivity_clauses": 2000000,
        "triangle_visits": 2000000,
        "candidate_vars": 50000,
        "added_literal_slots": 6000000,
    }
    for field, maximum in bounds.items():
        if integer[field] > maximum:
            raise AuditError(f"{path}: {field} exceeds frozen cap {maximum}")
    if integer["candidate_vars"] < integer["baseline_vars"]:
        raise AuditError(f"{path}: candidate variable count is impossible")
    if integer["candidate_clauses"] < integer["baseline_clauses"]:
        raise AuditError(f"{path}: candidate clause count is impossible")
    if integer["candidate_literal_slots"] < integer["baseline_literal_slots"]:
        raise AuditError(f"{path}: candidate literal count is impossible")
    if (
        integer["candidate_literal_slots"] - integer["baseline_literal_slots"]
        != integer["added_literal_slots"]
    ):
        raise AuditError(f"{path}: added literal count does not reconcile")


def audit_census(
    manifest_path: Path,
    corpus_root: Path | None,
    binary: Path,
    records_path: Path,
    summary_path: Path,
    receipt_out: Path,
    *,
    expected_sources: int,
) -> dict[str, Any]:
    sources, manifest_bytes = census.load_manifest(manifest_path, corpus_root)
    if len(sources) != expected_sources:
        raise AuditError(
            f"source count mismatch: expected {expected_sources}, got {len(sources)}"
        )
    summary, summary_bytes = _read_json_file(summary_path)
    records, records_bytes = _read_records(records_path)
    if len(records) != expected_sources:
        raise AuditError(
            f"record count mismatch: expected {expected_sources}, got {len(records)}"
        )

    binary_sha256 = census.sha256_file(binary.resolve())
    expected_summary = {
        "schema": census.SUMMARY_SCHEMA,
        "status": "completed_no_sat",
        "source_count": expected_sources,
        "manifest_sha256": census.sha256_bytes(manifest_bytes),
        "binary_sha256": binary_sha256,
        "records_sha256": census.sha256_bytes(records_bytes),
        "sat_calls": 0,
        "environment_contract": "all_EUF_VIPER_variables_removed",
    }
    for field, expected in expected_summary.items():
        if summary.get(field) != expected:
            raise AuditError(
                f"summary field {field!r} mismatch: expected {expected!r}, "
                f"got {summary.get(field)!r}"
            )

    source_set = [
        {"relative_path": source.relative_path, "sha256": source.source_sha256}
        for source in sources
    ]
    if summary.get("source_set_sha256") != census.canonical_hash(source_set):
        raise AuditError("summary source-set hash mismatch")

    previous_hash = census.ZERO_SHA256
    selected_paths: list[str] = []
    reason_counts: Counter[str] = Counter()
    by_path: dict[str, tuple[dict[str, Any], dict[str, int | str]]] = {}
    for source, record in zip(sources, records, strict=True):
        if record.get("schema") != census.RECORD_SCHEMA:
            raise AuditError(f"{source.relative_path}: record schema mismatch")
        source_record = record.get("source")
        expected_source = {
            "id": source.record_id,
            "relative_path": source.relative_path,
            "bytes": source.source_bytes,
            "sha256": source.source_sha256,
        }
        if source_record != expected_source:
            raise AuditError(f"{source.relative_path}: source identity mismatch")
        if record.get("binary_sha256") != binary_sha256:
            raise AuditError(f"{source.relative_path}: binary hash mismatch")
        if record.get("previous_record_sha256") != previous_hash:
            raise AuditError(f"{source.relative_path}: record-chain predecessor mismatch")
        record_without_hash = dict(record)
        recorded_hash = record_without_hash.pop("record_sha256", None)
        actual_hash = census.canonical_hash(record_without_hash)
        if recorded_hash != actual_hash:
            raise AuditError(f"{source.relative_path}: record hash mismatch")
        previous_hash = actual_hash

        projection = _validate_projection(record.get("projection"), source.relative_path)
        selected = projection["selected"] == 1
        if selected:
            _validate_selected(projection, source.relative_path)
            selected_paths.append(source.relative_path)
        reason = projection["reason"]
        assert isinstance(reason, str)
        reason_counts[reason] += 1
        by_path[source.relative_path] = (record, projection)

    if summary.get("record_chain_head") != previous_hash:
        raise AuditError("summary record-chain head mismatch")
    if summary.get("selected_paths") != selected_paths:
        raise AuditError("summary selected paths mismatch")
    if summary.get("selected_count") != len(selected_paths):
        raise AuditError("summary selected count mismatch")
    if summary.get("selected_set_sha256") != census.canonical_hash(selected_paths):
        raise AuditError("summary selected-set hash mismatch")
    if summary.get("reason_counts") != dict(sorted(reason_counts.items())):
        raise AuditError("summary rejection-reason accounting mismatch")

    target = by_path.get(TARGET_PATH)
    if target is None:
        raise AuditError("frozen terminal timeout is absent")
    if target[0]["source"]["sha256"] != TARGET_SHA256:
        raise AuditError("frozen terminal-timeout source hash drift")
    if target[1]["selected"] != 1:
        raise AuditError("frozen terminal timeout was not selected")
    selected_forbidden = sorted(path for path in FORBIDDEN_GOEL_PATHS if path in selected_paths)
    if selected_forbidden:
        raise AuditError(f"known frogs regressors were selected: {selected_forbidden}")
    selected_qg = [path for path in selected_paths if path.startswith(QG_PREFIX)]
    if selected_qg:
        raise AuditError(f"QG sources were selected: {selected_qg[:5]}")

    receipt = {
        "schema": AUDIT_SCHEMA,
        "status": "pass",
        "source_count": expected_sources,
        "selected_count": len(selected_paths),
        "selected_paths": selected_paths,
        "selected_set_sha256": census.canonical_hash(selected_paths),
        "checks": {
            "all_sources_present": True,
            "all_source_hashes_verified": True,
            "record_chain_verified": True,
            "zero_sat_calls": True,
            "off_path_unchanged": True,
            "all_selected_plans_materialized_exactly": True,
            "terminal_timeout_selected": True,
            "frogs_regressors_rejected": True,
            "all_qg_rejected": True,
            "all_frozen_caps_passed": True,
        },
        "artifacts": {
            "manifest_sha256": census.sha256_bytes(manifest_bytes),
            "binary_sha256": binary_sha256,
            "records_sha256": census.sha256_bytes(records_bytes),
            "summary_sha256": census.sha256_bytes(summary_bytes),
        },
    }
    census.atomic_write_new(receipt_out, census.canonical_json_bytes(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--expected-sources", type=census.positive_integer, default=7503)
    arguments = parser.parse_args()
    try:
        receipt = audit_census(
            arguments.manifest,
            arguments.corpus_root,
            arguments.binary,
            arguments.records,
            arguments.summary,
            arguments.receipt_out,
            expected_sources=arguments.expected_sources,
        )
    except (AuditError, census.CensusError) as error:
        parser.error(str(error))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
