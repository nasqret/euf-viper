#!/usr/bin/env python3
"""Build a deterministic source-family-disjoint PGO train/holdout split."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


SCHEMA_VERSION = "euf-viper.pgo-split.v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
VALID_STATUSES = frozenset({"sat", "unsat"})
REQUIRED_FIELDS = frozenset(
    {"id", "logic", "relative_path", "status", "bytes", "sha256"}
)


class SplitError(ValueError):
    """Raised when a split cannot be constructed without ambiguity."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def strict_json_loads(text: str) -> Any:
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number {value}")

    return json.loads(
        text,
        object_pairs_hook=strict_object,
        parse_constant=reject_constant,
    )


def family_of(relative_path: str) -> str:
    pure = PurePosixPath(relative_path)
    if (
        pure.is_absolute()
        or pure.as_posix() != relative_path
        or "\\" in relative_path
        or "\0" in relative_path
        or len(pure.parts) < 3
        or pure.parts[0] != "QF_UF"
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.suffix != ".smt2"
    ):
        raise SplitError(
            f"relative_path is not a canonical QF_UF source path: {relative_path!r}"
        )
    return pure.parts[1]


def load_manifest(path: Path) -> tuple[list[dict[str, Any]], str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SplitError(f"cannot read manifest {path}: {error}") from error
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SplitError(f"manifest {path} is not UTF-8") from error

    rows: list[dict[str, Any]] = []
    seen_ids: set[object] = set()
    seen_paths: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise SplitError(f"manifest line {line_number} is blank")
        try:
            row = strict_json_loads(line)
        except (ValueError, json.JSONDecodeError) as error:
            raise SplitError(f"manifest line {line_number} is invalid JSON: {error}") from error
        if type(row) is not dict:
            raise SplitError(f"manifest line {line_number} is not an object")
        missing = REQUIRED_FIELDS.difference(row)
        if missing:
            raise SplitError(
                f"manifest line {line_number} is missing {sorted(missing)!r}"
            )
        if row["logic"] != "QF_UF":
            raise SplitError(f"manifest line {line_number} is not QF_UF")
        relative_path = row["relative_path"]
        if type(relative_path) is not str:
            raise SplitError(f"manifest line {line_number} has a non-string path")
        family_of(relative_path)
        if type(row["status"]) is not str or row["status"] not in VALID_STATUSES:
            raise SplitError(f"manifest line {line_number} has an invalid status")
        if type(row["bytes"]) is not int or row["bytes"] < 0:
            raise SplitError(f"manifest line {line_number} has an invalid byte count")
        if type(row["sha256"]) is not str or not SHA256_RE.fullmatch(row["sha256"]):
            raise SplitError(f"manifest line {line_number} has an invalid SHA-256")
        identifier = row["id"]
        if (
            type(identifier) not in {int, str}
            or (type(identifier) is str and not identifier)
        ):
            raise SplitError(f"manifest line {line_number} has an invalid id")
        duplicate_id = identifier in seen_ids
        if duplicate_id:
            raise SplitError(f"manifest line {line_number} repeats id {identifier!r}")
        if relative_path in seen_paths:
            raise SplitError(f"manifest line {line_number} repeats {relative_path!r}")
        seen_ids.add(identifier)
        seen_paths.add(relative_path)
        rows.append(row)
    if not rows:
        raise SplitError("manifest is empty")
    return rows, hashlib.sha256(raw).hexdigest()


def family_score(seed: str, family: str) -> int:
    digest = hashlib.sha256(f"{seed}\0family\0{family}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def row_score(seed: str, relative_path: str) -> bytes:
    return hashlib.sha256(f"{seed}\0train\0{relative_path}".encode("utf-8")).digest()


def normalize_rebase_root(value: str | None) -> str | None:
    if value is None:
        return None
    pure = PurePosixPath(value)
    if (
        not pure.is_absolute()
        or pure.as_posix() != value
        or value == "/"
        or value.startswith("//")
        or "\\" in value
        or "\0" in value
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise SplitError(f"rebase root is not a canonical absolute path: {value!r}")
    return value


def rewrite_paths(
    rows: Sequence[dict[str, Any]], rebase_root: str | None
) -> list[dict[str, Any]]:
    if rebase_root is None:
        return [dict(row) for row in rows]
    root = PurePosixPath(rebase_root)
    rewritten: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["path"] = (root / PurePosixPath(row["relative_path"])).as_posix()
        rewritten.append(item)
    return rewritten


def choose_holdout_families(
    families: Sequence[str],
    *,
    seed: str,
    modulus: int,
    residue: int,
    explicit: Sequence[str],
) -> set[str]:
    known = set(families)
    if explicit:
        if any(type(family) is not str or not family for family in explicit):
            raise SplitError("explicit holdout families must be nonempty strings")
        if len(set(explicit)) != len(explicit):
            raise SplitError("explicit holdout families contain duplicates")
        selected = set(explicit)
        unknown = selected.difference(known)
        if unknown:
            raise SplitError(f"unknown explicit holdout families: {sorted(unknown)!r}")
    else:
        selected = {
            family
            for family in known
            if family_score(seed, family) % modulus == residue
        }
    if not selected:
        raise SplitError("the split selected no holdout family")
    if selected == known:
        raise SplitError("the split selected every family for holdout")
    return selected


def construct_split(
    rows: Sequence[dict[str, Any]],
    *,
    seed: str,
    holdout_modulus: int,
    holdout_residue: int,
    explicit_holdout_families: Sequence[str],
    max_train_per_family: int,
    max_train_source_bytes: int | None = None,
    rebase_root: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if not seed:
        raise SplitError("seed must be nonempty")
    if holdout_modulus < 2:
        raise SplitError("holdout modulus must be at least two")
    if not 0 <= holdout_residue < holdout_modulus:
        raise SplitError("holdout residue must be below the modulus")
    if max_train_per_family < 1:
        raise SplitError("max train rows per family must be positive")
    if (
        max_train_source_bytes is not None
        and (type(max_train_source_bytes) is not int or max_train_source_bytes < 1)
    ):
        raise SplitError("max training source bytes must be a positive integer")
    rebase_root = normalize_rebase_root(rebase_root)

    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_family[family_of(row["relative_path"])].append(row)
    families = sorted(by_family)
    holdout_families = choose_holdout_families(
        families,
        seed=seed,
        modulus=holdout_modulus,
        residue=holdout_residue,
        explicit=explicit_holdout_families,
    )

    selected_training_paths: set[str] = set()
    training_family_counts: dict[str, int] = {}
    for family in families:
        if family in holdout_families:
            continue
        candidates = sorted(
            (
                row
                for row in by_family[family]
                if max_train_source_bytes is None
                or row["bytes"] <= max_train_source_bytes
            ),
            key=lambda row: (row_score(seed, row["relative_path"]), row["relative_path"]),
        )
        selected = candidates[:max_train_per_family]
        if selected:
            training_family_counts[family] = len(selected)
        selected_training_paths.update(row["relative_path"] for row in selected)

    selected_training = [
        row for row in rows if row["relative_path"] in selected_training_paths
    ]
    selected_holdout = [
        row for row in rows if family_of(row["relative_path"]) in holdout_families
    ]
    training = rewrite_paths(selected_training, rebase_root)
    holdout = rewrite_paths(selected_holdout, rebase_root)
    if not training or not holdout:
        raise SplitError("both training and holdout outputs must be nonempty")

    training_families = {family_of(row["relative_path"]) for row in training}
    output_holdout_families = {family_of(row["relative_path"]) for row in holdout}
    overlap = training_families.intersection(output_holdout_families)
    if overlap:
        raise SplitError(f"source-family leakage detected: {sorted(overlap)!r}")

    definition = {
        "explicit_holdout_families": sorted(set(explicit_holdout_families)),
        "holdout_modulus": holdout_modulus,
        "holdout_residue": holdout_residue,
        "max_train_per_family": max_train_per_family,
        "max_train_source_bytes": max_train_source_bytes,
        "path_rewrite": {
            "mode": "preserved" if rebase_root is None else "rebased",
            "rebase_root": rebase_root,
        },
        "seed": seed,
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "definition": definition,
        "definition_sha256": hashlib.sha256(canonical_json_bytes(definition)).hexdigest(),
        "families": {
            "all": families,
            "holdout": sorted(output_holdout_families),
            "training": sorted(training_families),
            "training_selected_counts": dict(sorted(training_family_counts.items())),
        },
        "counts": {
            "holdout": len(holdout),
            "holdout_status": dict(sorted(Counter(row["status"] for row in holdout).items())),
            "input": len(rows),
            "training": len(training),
            "training_status": dict(
                sorted(Counter(row["status"] for row in training).items())
            ),
            "unselected_training_family_rows": len(rows) - len(training) - len(holdout),
        },
        "family_disjoint": True,
    }
    return training, holdout, report


def stage_file(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        return temporary
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_artifacts_atomic(artifacts: Sequence[tuple[Path, bytes]]) -> None:
    staged: list[tuple[str, Path]] = []
    try:
        for path, data in artifacts:
            staged.append((stage_file(path, data), path))
        # The report is passed last and acts as the commit marker for the split.
        for temporary, path in staged:
            os.replace(temporary, path)
    finally:
        for temporary, _ in staged:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def manifest_bytes(rows: Sequence[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(row) for row in rows)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--train-out", type=Path, required=True)
    parser.add_argument("--holdout-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--seed", default="euf-viper-pgo-v1")
    parser.add_argument("--holdout-modulus", type=int, default=5)
    parser.add_argument("--holdout-residue", type=int, default=0)
    parser.add_argument("--holdout-family", action="append", default=[])
    parser.add_argument("--max-train-per-family", type=int, default=32)
    parser.add_argument("--max-train-source-bytes", type=int)
    parser.add_argument(
        "--rebase-root",
        help="replace every output path with this absolute root plus relative_path",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    outputs = [args.train_out.resolve(), args.holdout_out.resolve(), args.report_out.resolve()]
    if len(set(outputs)) != len(outputs):
        raise SplitError("training, holdout, and report outputs must be distinct")
    if args.manifest.resolve() in outputs:
        raise SplitError("an output must not overwrite the input manifest")
    rows, manifest_sha256 = load_manifest(args.manifest)
    training, holdout, report = construct_split(
        rows,
        seed=args.seed,
        holdout_modulus=args.holdout_modulus,
        holdout_residue=args.holdout_residue,
        explicit_holdout_families=args.holdout_family,
        max_train_per_family=args.max_train_per_family,
        max_train_source_bytes=args.max_train_source_bytes,
        rebase_root=args.rebase_root,
    )
    training_data = manifest_bytes(training)
    holdout_data = manifest_bytes(holdout)
    report["input_manifest"] = {
        "path": str(args.manifest.resolve()),
        "sha256": manifest_sha256,
    }
    report["outputs"] = {
        "holdout_manifest_sha256": hashlib.sha256(holdout_data).hexdigest(),
        "training_manifest_sha256": hashlib.sha256(training_data).hexdigest(),
    }
    write_artifacts_atomic(
        (
            (args.train_out, training_data),
            (args.holdout_out, holdout_data),
            (args.report_out, canonical_json_bytes(report)),
        )
    )
    print(
        f"training={len(training)} holdout={len(holdout)} "
        f"families={len(report['families']['training'])}/{len(report['families']['holdout'])}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SplitError as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(2)
