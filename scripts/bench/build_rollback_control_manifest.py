#!/usr/bin/env python3
"""Build the frozen Goel/anti-target manifest for the rollback control."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "rollback-control-manifest-v1"
RANK_SCHEMA_VERSION = "rollback-control-rank-v1"
DEFAULT_SEED = "euf-viper-rollback-control-2026-07-13"
DEFAULT_ANTI_TARGETS_PER_STATUS = 6
DEFAULT_MAX_ANTI_TARGET_BYTES = 262_144
GOEL_PREFIX = "QF_UF/2018-Goel-hwbench/"
DECISIVE_STATUSES = {"sat", "unsat"}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

# Frozen from research-vault/06-results/2026-07-11-tail-opportunity-atlas.md.
TARGETS: tuple[tuple[str, str], ...] = (
    (
        "QF_UF/2018-Goel-hwbench/"
        "QF_UF_firewire_tree.5.prop1_ab_reg_max.smt2",
        "unsat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/"
        "QF_UF_firewire_tree.5.prop2_ab_reg_max.smt2",
        "sat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/QF_UF_frogs.2.prop1_ab_br_max.smt2",
        "sat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/QF_UF_frogs.3.prop1_ab_br_max.smt2",
        "sat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/QF_UF_frogs.5.prop1_ab_br_max.smt2",
        "sat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/QF_UF_h_TicTacToe_ab_cti_max.smt2",
        "sat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/QF_UF_hanoi.3.prop1_ab_br_max.smt2",
        "sat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/"
        "QF_UF_peg_solitaire.2.prop1_ab_br_max.smt2",
        "unsat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/"
        "QF_UF_peg_solitaire.4.prop1_ab_br_max.smt2",
        "sat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/QF_UF_sokoban.2.prop1_ab_br_max.smt2",
        "unsat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/QF_UF_sokoban.3.prop1_ab_br_max.smt2",
        "unsat",
    ),
    (
        "QF_UF/2018-Goel-hwbench/QF_UF_sokoban.3.prop1_ab_reg_max.smt2",
        "sat",
    ),
)
TARGET_STATUS = dict(TARGETS)


class ManifestError(RuntimeError):
    """Raised when a source manifest or selected source is not trustworthy."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ManifestError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ManifestError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def parse_json(line: str, context: str) -> dict[str, Any]:
    try:
        value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ManifestError) as error:
        raise ManifestError(f"{context}: invalid JSON: {error}") from error
    if type(value) is not dict:
        raise ManifestError(f"{context}: record must be a JSON object")
    return value


def load_manifest(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ManifestError(f"cannot read manifest {path}: {error}") from error
    if text and not text.endswith("\n"):
        raise ManifestError(f"manifest {path} lacks a final newline")

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise ManifestError(f"{path}:{line_number}: blank records are forbidden")
        row = parse_json(line, f"{path}:{line_number}")
        relative_path = row.get("relative_path")
        source_path = row.get("path")
        source_hash = row.get("sha256")
        source_bytes = row.get("bytes")
        status = row.get("status")
        if type(relative_path) is not str or not relative_path.startswith("QF_UF/"):
            raise ManifestError(
                f"{path}:{line_number}: relative_path must start with QF_UF/"
            )
        if relative_path in seen:
            raise ManifestError(
                f"{path}:{line_number}: duplicate relative_path {relative_path!r}"
            )
        if type(source_path) is not str or not source_path:
            raise ManifestError(f"{path}:{line_number}: path must be non-empty")
        if type(source_hash) is not str or SHA256_RE.fullmatch(source_hash) is None:
            raise ManifestError(f"{path}:{line_number}: sha256 is invalid")
        if type(source_bytes) is not int or source_bytes < 0:
            raise ManifestError(f"{path}:{line_number}: bytes must be non-negative")
        if status not in DECISIVE_STATUSES:
            raise ManifestError(
                f"{path}:{line_number}: status must be sat or unsat"
            )
        seen.add(relative_path)
        rows.append(row)
    if not rows:
        raise ManifestError(f"manifest {path} is empty")
    return rows


def source_path_for(
    row: dict[str, Any], manifest: Path, corpus_root: Path | None
) -> Path:
    source = Path(row["path"])
    candidates: list[Path] = []
    if source.is_absolute():
        candidates.append(source)
    else:
        candidates.extend((Path.cwd() / source, manifest.parent / source))
    if corpus_root is not None:
        candidates.append(corpus_root / row["relative_path"])
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    rendered = ", ".join(str(candidate) for candidate in candidates)
    raise ManifestError(
        f"cannot resolve source {row['relative_path']!r}; tried {rendered}"
    )


def verify_source(
    row: dict[str, Any], manifest: Path, corpus_root: Path | None
) -> None:
    source = source_path_for(row, manifest, corpus_root)
    actual_bytes = source.stat().st_size
    if actual_bytes != row["bytes"]:
        raise ManifestError(
            f"source byte count drift for {row['relative_path']!r}: "
            f"expected {row['bytes']}, got {actual_bytes}"
        )
    actual_hash = sha256_file(source)
    if actual_hash != row["sha256"]:
        raise ManifestError(
            f"source SHA-256 drift for {row['relative_path']!r}: "
            f"expected {row['sha256']}, got {actual_hash}"
        )


def anti_target_rank(row: dict[str, Any], seed: str) -> str:
    identity = {
        "relative_path": row["relative_path"],
        "schema_version": RANK_SCHEMA_VERSION,
        "seed": seed,
        "source_sha256": row["sha256"],
        "status": row["status"],
    }
    return sha256_bytes(canonical_bytes(identity))


def select_rows(
    rows: Iterable[dict[str, Any]],
    *,
    anti_targets_per_status: int,
    max_anti_target_bytes: int,
    seed: str,
) -> list[dict[str, Any]]:
    by_path = {row["relative_path"]: row for row in rows}
    selected: list[dict[str, Any]] = []
    for relative_path, expected_status in TARGETS:
        row = by_path.get(relative_path)
        if row is None:
            raise ManifestError(f"required rollback target is missing: {relative_path}")
        if row["status"] != expected_status:
            raise ManifestError(
                f"rollback target status drift for {relative_path}: "
                f"expected {expected_status}, got {row['status']}"
            )
        selected.append({**row, "control_class": "target"})

    eligible: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
        "sat": [],
        "unsat": [],
    }
    for row in by_path.values():
        relative_path = row["relative_path"]
        if relative_path.startswith(GOEL_PREFIX):
            continue
        if row["bytes"] > max_anti_target_bytes:
            continue
        rank = anti_target_rank(row, seed)
        eligible[row["status"]].append((rank, relative_path, row))

    anti_targets: list[tuple[str, str, dict[str, Any]]] = []
    for status in ("sat", "unsat"):
        candidates = sorted(eligible[status])
        if len(candidates) < anti_targets_per_status:
            raise ManifestError(
                f"only {len(candidates)} eligible {status} anti-targets; "
                f"need {anti_targets_per_status} under {max_anti_target_bytes} bytes"
            )
        anti_targets.extend(candidates[:anti_targets_per_status])
    for _, _, row in sorted(anti_targets):
        selected.append({**row, "control_class": "anti-target"})
    return selected


def encode_jsonl(rows: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(canonical_bytes(row) for row in rows)


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ManifestError(f"refusing to overwrite existing artifact {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build_summary(
    *,
    source_manifest: Path,
    output_manifest: Path,
    selected: list[dict[str, Any]],
    output_bytes: bytes,
    seed: str,
    anti_targets_per_status: int,
    max_anti_target_bytes: int,
    source_verification: bool,
) -> dict[str, Any]:
    class_counts = Counter(row["control_class"] for row in selected)
    anti_status_counts = Counter(
        row["status"]
        for row in selected
        if row["control_class"] == "anti-target"
    )
    payload: dict[str, Any] = {
        "anti_target_status_counts": dict(sorted(anti_status_counts.items())),
        "anti_targets_per_status": anti_targets_per_status,
        "class_counts": dict(sorted(class_counts.items())),
        "input_manifest": str(source_manifest.resolve()),
        "input_manifest_sha256": sha256_file(source_manifest),
        "max_anti_target_bytes": max_anti_target_bytes,
        "output_manifest": str(output_manifest.resolve()),
        "output_manifest_sha256": sha256_bytes(output_bytes),
        "rows": len(selected),
        "schema_version": SCHEMA_VERSION,
        "seed": seed,
        "selected_source_bytes": sum(row["bytes"] for row in selected),
        "source_verification": "verified" if source_verification else "skipped",
        "target_paths": [path for path, _ in TARGETS],
        "summary_sha256": "",
    }
    payload["summary_sha256"] = sha256_bytes(canonical_bytes(payload))
    return payload


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="full QF_UF JSONL manifest")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument(
        "--anti-targets-per-status",
        type=int,
        default=DEFAULT_ANTI_TARGETS_PER_STATUS,
    )
    parser.add_argument(
        "--max-anti-target-bytes",
        type=int,
        default=DEFAULT_MAX_ANTI_TARGET_BYTES,
    )
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument(
        "--skip-source-verification",
        action="store_true",
        help="trust source hashes in the input manifest (not campaign eligible)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if args.anti_targets_per_status < 1:
        parser.error("--anti-targets-per-status must be positive")
    if args.max_anti_target_bytes < 1:
        parser.error("--max-anti-target-bytes must be positive")
    if not args.seed:
        parser.error("--seed cannot be empty")
    if args.summary is not None and args.out.resolve() == args.summary.resolve():
        parser.error("--out and --summary must be different files")
    if args.out.exists() or (args.summary is not None and args.summary.exists()):
        parser.error("output artifacts already exist")
    try:
        rows = load_manifest(args.manifest)
        selected = select_rows(
            rows,
            anti_targets_per_status=args.anti_targets_per_status,
            max_anti_target_bytes=args.max_anti_target_bytes,
            seed=args.seed,
        )
        if not args.skip_source_verification:
            for row in selected:
                verify_source(row, args.manifest, args.corpus_root)
        output_bytes = encode_jsonl(selected)
        summary = build_summary(
            source_manifest=args.manifest,
            output_manifest=args.out,
            selected=selected,
            output_bytes=output_bytes,
            seed=args.seed,
            anti_targets_per_status=args.anti_targets_per_status,
            max_anti_target_bytes=args.max_anti_target_bytes,
            source_verification=not args.skip_source_verification,
        )
        atomic_write(args.out, output_bytes)
        if args.summary is not None:
            atomic_write(args.summary, canonical_bytes(summary))
    except (ManifestError, OSError) as error:
        print(f"rollback-control manifest error: {error}", file=sys.stderr)
        return 2
    print(
        f"wrote {len(selected)} rows to {args.out}: "
        f"12 targets and {2 * args.anti_targets_per_status} anti-targets"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
