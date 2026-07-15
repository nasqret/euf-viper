#!/usr/bin/env python3
"""Build a fresh hash-bound 24-source T7 SAT-impact manifest."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
T2_SCRIPT = ROOT / "scripts" / "bench" / "build_rollback_control_manifest.py"
SPEC = importlib.util.spec_from_file_location("t7_t2_manifest_source", T2_SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import exact T2 selector from {T2_SCRIPT}")
T2 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T2)


SCHEMA = "t7-sat-impact-manifest-v1"
SUMMARY_SCHEMA = "t7-sat-impact-manifest-summary-v1"
M3_PATHS = (
    "QF_UF/2018-Goel-hwbench/QF_UF_peg_solitaire.2.prop1_ab_br_max.smt2",
    "QF_UF/2018-Goel-hwbench/QF_UF_peg_solitaire.4.prop1_ab_br_max.smt2",
    "QF_UF/2018-Goel-hwbench/QF_UF_sokoban.3.prop1_ab_reg_max.smt2",
)
PROVENANCE = (
    ROOT / "PLAN.md",
    ROOT / "research-vault" / "06-results" / "2026-07-11-tail-opportunity-atlas.md",
    T2_SCRIPT,
)


class T7ManifestError(RuntimeError):
    """Raised when the exact 24-source construction cannot be reproduced."""


def _population(row: dict[str, Any]) -> str:
    path = row["relative_path"]
    control_class = row["control_class"]
    if control_class == "anti-target":
        return "A12"
    if control_class != "target":
        raise T7ManifestError(f"unexpected T2 control class {control_class!r}")
    return "M3" if path in M3_PATHS else "T9"


def validate_output_row(row: dict[str, Any], index: int) -> None:
    if row.get("schema_version") != SCHEMA or row.get("manifest_index") != index:
        raise T7ManifestError(f"T7 manifest row {index} has invalid binding metadata")
    population = row.get("t7_population")
    if population not in {"M3", "T9", "A12"}:
        raise T7ManifestError(f"T7 manifest row {index} has invalid population")
    metadata = {
        "manifest_index",
        "schema_version",
        "source_row_sha256",
        "t7_population",
        "t7_selection_rank",
    }
    source_row = {key: value for key, value in row.items() if key not in metadata}
    expected_source_hash = T2.sha256_bytes(T2.canonical_bytes(source_row))
    if row.get("source_row_sha256") != expected_source_hash:
        raise T7ManifestError(f"T7 manifest row {index} source-row hash mismatch")
    if population == "A12":
        expected_rank = T2.anti_target_rank(source_row, T2.DEFAULT_SEED)
        if row.get("t7_selection_rank") != expected_rank:
            raise T7ManifestError(f"T7 manifest row {index} anti-target rank mismatch")
    elif row.get("t7_selection_rank") is not None:
        raise T7ManifestError(f"T7 target row {index} unexpectedly has a selection rank")


def build_rows(source_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = T2.select_rows(
        source_rows,
        anti_targets_per_status=T2.DEFAULT_ANTI_TARGETS_PER_STATUS,
        max_anti_target_bytes=T2.DEFAULT_MAX_ANTI_TARGET_BYTES,
        seed=T2.DEFAULT_SEED,
    )
    result: list[dict[str, Any]] = []
    for manifest_index, selected_row in enumerate(selected):
        source_row = {
            key: value for key, value in selected_row.items() if key != "control_class"
        }
        population = _population(selected_row)
        rank = (
            T2.anti_target_rank(source_row, T2.DEFAULT_SEED)
            if population == "A12"
            else None
        )
        result.append(
            {
                **source_row,
                "manifest_index": manifest_index,
                "schema_version": SCHEMA,
                "source_row_sha256": T2.sha256_bytes(T2.canonical_bytes(source_row)),
                "t7_population": population,
                "t7_selection_rank": rank,
            }
        )
    counts = Counter(row["t7_population"] for row in result)
    if len(result) != 24 or counts != {"M3": 3, "T9": 9, "A12": 12}:
        raise T7ManifestError(
            f"exact T7 population split failed: rows={len(result)} counts={dict(counts)}"
        )
    if tuple(row["relative_path"] for row in result if row["t7_population"] == "M3") != M3_PATHS:
        raise T7ManifestError("M3 source order drifted from the preregistered exact order")
    for index, row in enumerate(result):
        validate_output_row(row, index)
    return result


def build_summary(
    *,
    source_manifest: Path,
    output_manifest: Path,
    rows: list[dict[str, Any]],
    output_bytes: bytes,
    source_verification: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "construction": "fresh-selection-from-exact-plan-atlas-t2-sources",
        "input_manifest": str(source_manifest.resolve()),
        "input_manifest_sha256": T2.sha256_file(source_manifest),
        "m3_paths": list(M3_PATHS),
        "missing_old_manifest_reused": False,
        "output_manifest": str(output_manifest.resolve()),
        "output_manifest_sha256": T2.sha256_bytes(output_bytes),
        "population_counts": dict(
            sorted(Counter(row["t7_population"] for row in rows).items())
        ),
        "provenance_sha256": {
            str(path.relative_to(ROOT)): T2.sha256_file(path) for path in PROVENANCE
        },
        "rows": len(rows),
        "schema_version": SUMMARY_SCHEMA,
        "source_verification": "verified" if source_verification else "skipped",
        "t2_anti_target_seed": T2.DEFAULT_SEED,
        "summary_sha256": "",
    }
    payload["summary_sha256"] = T2.sha256_bytes(T2.canonical_bytes(payload))
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="full QF_UF source manifest")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument(
        "--skip-source-verification",
        action="store_true",
        help="build a non-campaign-eligible manifest from source-row hashes only",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.out.resolve() == args.summary.resolve():
        parser.error("--out and --summary must be different files")
    if args.out.exists() or args.summary.exists():
        parser.error("output artifacts already exist")
    try:
        source_rows = T2.load_manifest(args.manifest)
        rows = build_rows(source_rows)
        if not args.skip_source_verification:
            for row in rows:
                T2.verify_source(row, args.manifest, args.corpus_root)
        output_bytes = T2.encode_jsonl(rows)
        summary = build_summary(
            source_manifest=args.manifest,
            output_manifest=args.out,
            rows=rows,
            output_bytes=output_bytes,
            source_verification=not args.skip_source_verification,
        )
        T2.atomic_write(args.out, output_bytes)
        T2.atomic_write(args.summary, T2.canonical_bytes(summary))
    except (OSError, T2.ManifestError, T7ManifestError) as error:
        print(f"T7 manifest error: {error}", file=sys.stderr)
        return 2
    print(
        f"wrote fresh T7 manifest {args.out}: 24 rows (M3=3, T9=9, A12=12)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
