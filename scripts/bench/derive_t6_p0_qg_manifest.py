#!/usr/bin/env python3
"""Derive the current T6 qg7 confirmation manifest from frozen P0 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "euf-viper.t6-theory-dag-manifest.v2"
P0_REVISION = "30828a4f0c1e7e478a9c6f406ccb245eeefc4961"
P0_AUDIT_SHA256 = (
    "2458b01872a290c89f715a277dfd41e2c28091fc649925c9acbfefeb6e72686a"
)
P0_AUDIT_MANIFEST_SHA256 = (
    "32aba287e33c5665847f0a0a71311da6214feb5e69f458877ba02ef96976a2d4"
)
LOCAL_MANIFEST_SHA256 = (
    "9c509b0ffd35a371738dbb31865f975b43350fca5f54393f7bb5014d450a08db"
)
PROJECTION_TEMPLATE_SHA256 = (
    "198b0824c8847f249cc0c4405dcdea4e9b3101979c0b437cdeebd26165892476"
)
P0_BINARY_SHA256 = (
    "edcf8d1af94e9eb937fb5e073ffd08de1738bb369409484b5e067980597ba576"
)
EXPECTED_CORPUS_SOURCES = 7_503
EXPECTED_SELECTED_SOURCES = 12
MINIMUM_SOURCE_BYTES = 6_000_000
SOLVED_RESULTS = frozenset({"sat", "unsat"})
RESULTS = SOLVED_RESULTS | {"timeout", "unknown", "error", "invalid"}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
QG7_PREFIX = "QF_UF/QG-classification/qg7/"


class DerivationError(ValueError):
    """Raised when evidence does not satisfy the frozen derivation contract."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DerivationError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DerivationError(f"cannot read JSON {path}: {error}") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise DerivationError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def require_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DerivationError(f"{context} is not a lowercase SHA-256")
    return value


def require_hash(path: Path, expected: str, context: str) -> str:
    require_sha256(expected, f"expected {context}")
    observed = sha256_file(path)
    if observed != expected:
        raise DerivationError(
            f"{context} hash mismatch: expected {expected}, observed {observed}"
        )
    return observed


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
            json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def load_corpus_manifest(path: Path, expected_sources: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_ids: set[int] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise DerivationError(f"cannot read corpus manifest {path}: {error}") from error
    for line_number, line in enumerate(lines, start=1):
        if not line:
            raise DerivationError(f"blank corpus manifest row at line {line_number}")
        try:
            row = json.loads(line, object_pairs_hook=reject_duplicate_keys)
        except (json.JSONDecodeError, DerivationError) as error:
            raise DerivationError(
                f"invalid corpus manifest row at line {line_number}: {error}"
            ) from error
        if not isinstance(row, dict):
            raise DerivationError(f"corpus manifest line {line_number} is not an object")
        relative_path = row.get("relative_path")
        source_id = row.get("id")
        source_bytes = row.get("bytes")
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or relative_path.startswith("/")
            or "\\" in relative_path
            or ".." in Path(relative_path).parts
        ):
            raise DerivationError(f"unsafe relative path at line {line_number}")
        if type(source_id) is not int or source_id < 0:
            raise DerivationError(f"invalid source id at line {line_number}")
        if type(source_bytes) is not int or source_bytes <= 0:
            raise DerivationError(f"invalid source byte count at line {line_number}")
        require_sha256(row.get("sha256"), f"source SHA-256 at line {line_number}")
        if row.get("logic") != "QF_UF" or row.get("status") not in SOLVED_RESULTS:
            raise DerivationError(f"invalid source logic/status at line {line_number}")
        if relative_path in seen_paths or source_id in seen_ids:
            raise DerivationError(f"duplicate source identity at line {line_number}")
        seen_paths.add(relative_path)
        seen_ids.add(source_id)
        rows.append(row)
    if len(rows) != expected_sources:
        raise DerivationError(
            f"corpus source count mismatch: expected {expected_sources}, got {len(rows)}"
        )
    if seen_ids != set(range(expected_sources)):
        raise DerivationError("corpus source ids are not exactly 0..N-1")
    return rows


def observation_index(
    audit: dict[str, Any], expected_sources: int
) -> tuple[dict[tuple[float, str, str], dict[str, Any]], list[str]]:
    inputs = audit.get("inputs")
    hashes = audit.get("input_hashes")
    if not isinstance(inputs, dict) or not isinstance(hashes, dict):
        raise DerivationError("P0 audit lacks inputs or input_hashes")
    if (
        audit.get("schema_version") != 1
        or audit.get("status") != "rejected"
        or inputs.get("campaign_id") != "best-overall-qf-uf-2026-07"
        or inputs.get("candidate_id") != "euf-viper"
        or inputs.get("instances") != expected_sources
        or inputs.get("budgets_s") != [2.0, 60.0]
    ):
        raise DerivationError("P0 audit identity drift")
    baseline_ids = inputs.get("baseline_ids")
    expected_baselines = ["cvc5", "opensmt", "yices2", "z3-default", "z3-sat-euf"]
    if baseline_ids != expected_baselines:
        raise DerivationError("P0 comparator identity drift")
    if hashes.get("manifest_sha256") != P0_AUDIT_MANIFEST_SHA256:
        raise DerivationError("P0 audit manifest identity drift")
    binaries = hashes.get("solver_binary_sha256")
    if not isinstance(binaries, dict) or binaries.get("euf-viper") != P0_BINARY_SHA256:
        raise DerivationError("P0 candidate binary identity drift")

    observations = inputs.get("observation_provenance")
    solvers = ["euf-viper", *expected_baselines]
    expected_observations = expected_sources * len(solvers) * 2
    if not isinstance(observations, list) or len(observations) != expected_observations:
        raise DerivationError(
            "P0 observation count mismatch: "
            f"expected {expected_observations}, got "
            f"{len(observations) if isinstance(observations, list) else 'non-list'}"
        )
    index: dict[tuple[float, str, str], dict[str, Any]] = {}
    for row_number, row in enumerate(observations, start=1):
        if not isinstance(row, dict):
            raise DerivationError(f"P0 observation {row_number} is not an object")
        budget = row.get("budget_s")
        solver = row.get("solver_id")
        relative_path = row.get("relative_path")
        result = row.get("result")
        if budget not in {2.0, 60.0} or solver not in solvers:
            raise DerivationError(f"P0 observation identity drift at row {row_number}")
        if not isinstance(relative_path, str) or not relative_path:
            raise DerivationError(f"P0 observation path drift at row {row_number}")
        if result not in RESULTS:
            raise DerivationError(f"P0 observation result drift at row {row_number}")
        require_sha256(row.get("source_lock_sha256"), "observation lock SHA-256")
        require_sha256(row.get("source_raw_sha256"), "observation raw SHA-256")
        record_hashes = row.get("source_record_sha256s")
        if not isinstance(record_hashes, list) or not record_hashes:
            raise DerivationError(f"P0 observation record hashes missing at row {row_number}")
        for value in record_hashes:
            require_sha256(value, "observation record SHA-256")
        key = (float(budget), solver, relative_path)
        if key in index:
            raise DerivationError(f"duplicate P0 observation {key!r}")
        index[key] = row
    return index, solvers


def qg7_taxonomy(relative_path: str) -> dict[str, str]:
    path = Path(relative_path)
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


def derive_manifest(
    audit: dict[str, Any],
    corpus_rows: list[dict[str, Any]],
    projection_contract: dict[str, Any],
    *,
    audit_sha256: str,
    local_manifest_sha256: str,
    projection_template_sha256: str,
    expected_sources: int,
    expected_selected: int,
) -> dict[str, Any]:
    index, _ = observation_index(audit, expected_sources)
    corpus_by_path = {row["relative_path"]: row for row in corpus_rows}
    selected_paths: list[str] = []
    for relative_path in sorted(corpus_by_path, key=lambda value: value.encode("utf-8")):
        if not relative_path.startswith(QG7_PREFIX):
            continue
        candidate = index[(60.0, "euf-viper", relative_path)]["result"]
        z3 = index[(60.0, "z3-default", relative_path)]["result"]
        yices = index[(60.0, "yices2", relative_path)]["result"]
        if candidate == "timeout" and z3 in SOLVED_RESULTS and yices in SOLVED_RESULTS:
            selected_paths.append(relative_path)
    if len(selected_paths) != expected_selected:
        raise DerivationError(
            f"P0 qg7 shared-deficit count mismatch: expected {expected_selected}, "
            f"got {len(selected_paths)}"
        )

    sources: list[dict[str, Any]] = []
    for sequence, relative_path in enumerate(selected_paths):
        row = corpus_by_path[relative_path]
        if row["bytes"] < MINIMUM_SOURCE_BYTES:
            raise DerivationError(f"selected source is outside DOMAIN7_HUGE: {relative_path}")
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
                "source_bytes": row["bytes"],
                "source_id": row["id"],
                "source_sha256": row["sha256"],
                "source_status": row["status"],
                "taxonomy": qg7_taxonomy(relative_path),
            }
        )

    path_digest = canonical_path_digest(selected_paths)
    return {
        "schema": SCHEMA,
        "selection": {
            "audit": {
                "file_sha256": audit_sha256,
                "manifest_sha256": P0_AUDIT_MANIFEST_SHA256,
                "path": "p0-144990/continuations/chain-145036/audit/full-60.json",
                "revision": P0_REVISION,
                "solver_binary_sha256": P0_BINARY_SHA256,
            },
            "candidate_count": len(sources),
            "canonical_order": "relative_path_utf8_bytewise_ascending",
            "canonical_path_list_sha256": path_digest,
            "corpus_manifest": {
                "file_sha256": local_manifest_sha256,
                "records": expected_sources,
            },
            "derivation": (
                "exact intersection of P0 60-second euf-viper timeouts, qg7 "
                "sources of at least 6000000 bytes, and instances solved with the "
                "manifest status by both z3-default and yices2"
            ),
            "evidence_scope": "current_p0_full60_qg7_shared_z3_yices_deficit",
            "projection_template_sha256": projection_template_sha256,
            "selection_version": "p0-30828a4-full60-qg7-shared-deficit-v1",
            "source_records_sha256": canonical_source_digest(sources),
        },
        "projection_contract": projection_contract,
        "gate": {
            "decision_rule": "pass iff at least 10 of 12 sources qualify; otherwise reject",
            "minimum_qualifying_sources": 10,
            "qualifying_source_rule": (
                "D reduction from A is at least 250000 ppm and exceeds both B and C "
                "reductions from A by at least 50000 ppm"
            ),
            "required_d_reduction_from_a_ppm": 250_000,
            "required_increment_over_b_ppm": 50_000,
            "required_increment_over_c_ppm": 50_000,
        },
        "implementation_or_promotion_eligible": False,
        "sources": sources,
    }


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("ascii")
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
    parser.add_argument("--expected-audit-sha256", default=P0_AUDIT_SHA256)
    parser.add_argument("--expected-corpus-manifest-sha256", default=LOCAL_MANIFEST_SHA256)
    parser.add_argument(
        "--expected-projection-template-sha256", default=PROJECTION_TEMPLATE_SHA256
    )
    parser.add_argument("--expected-sources", type=int, default=EXPECTED_CORPUS_SOURCES)
    parser.add_argument("--expected-selected", type=int, default=EXPECTED_SELECTED_SOURCES)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.expected_sources <= 0 or args.expected_selected <= 0:
        raise DerivationError("expected counts must be positive")
    audit_sha = require_hash(args.audit, args.expected_audit_sha256, "P0 audit")
    manifest_sha = require_hash(
        args.corpus_manifest,
        args.expected_corpus_manifest_sha256,
        "corpus manifest",
    )
    template_sha = require_hash(
        args.projection_template,
        args.expected_projection_template_sha256,
        "projection template",
    )
    audit = load_json(args.audit)
    template = load_json(args.projection_template)
    if not isinstance(audit, dict) or not isinstance(template, dict):
        raise DerivationError("audit and projection template must be objects")
    projection_contract = template.get("projection_contract")
    if template.get("schema") != "euf-viper.t6-theory-dag-manifest.v1" or not isinstance(
        projection_contract, dict
    ):
        raise DerivationError("projection template identity drift")
    corpus_rows = load_corpus_manifest(args.corpus_manifest, args.expected_sources)
    payload = derive_manifest(
        audit,
        corpus_rows,
        projection_contract,
        audit_sha256=audit_sha,
        local_manifest_sha256=manifest_sha,
        projection_template_sha256=template_sha,
        expected_sources=args.expected_sources,
        expected_selected=args.expected_selected,
    )
    atomic_write_json(args.output, payload)
    print(json.dumps({"output": str(args.output), "sha256": sha256_file(args.output)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DerivationError as error:
        raise SystemExit(f"T6 manifest derivation failed: {error}") from error
