#!/usr/bin/env python3
"""Run the source-bound, no-SAT T9 projection census."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


RECORD_SCHEMA = "euf-viper.t9-projection-record.v1"
SUMMARY_SCHEMA = "euf-viper.t9-projection-census.v1"
PROJECTION_VERSION = "1"
ZERO_SHA256 = "0" * 64
KEY_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

COUNT_FIELDS = {
    "finite_added",
    "covered_finite_terms",
    "closed_table_functions",
    "all_different_clique_lb",
    "disequality_graph_edges",
    "disequality_clique_excess_edges",
    "equality_graph_vertices",
    "equality_graph_edges",
    "applications",
    "baseline_vars",
    "baseline_clauses",
    "baseline_literal_slots",
    "ackermann_clauses",
    "ackermann_literal_slots",
    "fill_edges",
    "fill_pair_examinations",
    "transitivity_clauses",
    "triangle_visits",
    "candidate_vars",
    "candidate_clauses",
    "candidate_literal_slots",
    "added_literal_slots",
    "sat_calls",
}
BOOLEAN_FIELDS = {"selected", "materialization_match", "off_path_unchanged"}
TEXT_FIELDS = {"reason", "backend"}
REQUIRED_FIELDS = COUNT_FIELDS | BOOLEAN_FIELDS | TEXT_FIELDS


class CensusError(RuntimeError):
    """Raised when an input or projection fails the frozen census contract."""


@dataclass(frozen=True)
class ManifestSource:
    record_id: int | str
    relative_path: str
    source_path: Path
    source_bytes: int
    source_sha256: str


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise CensusError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _canonical_relative_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.startswith("QF_UF/"):
        raise CensusError(f"{context}: relative_path must start with QF_UF/")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CensusError(f"{context}: relative_path is not canonical")
    if path.as_posix() != value:
        raise CensusError(f"{context}: relative_path is not canonical")
    return value


def _source_path(row: dict[str, Any], corpus_root: Path | None, context: str) -> Path:
    relative_path = row["relative_path"]
    if corpus_root is not None:
        root = corpus_root.resolve()
        candidate = (root / relative_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise CensusError(f"{context}: source escapes corpus root") from error
        return candidate
    raw_path = row.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise CensusError(f"{context}: path must be a nonempty string")
    return Path(raw_path).resolve()


def load_manifest(
    manifest_path: Path, corpus_root: Path | None = None
) -> tuple[list[ManifestSource], bytes]:
    try:
        payload = manifest_path.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise CensusError(f"cannot read UTF-8 manifest {manifest_path}: {error}") from error
    if not payload or not payload.endswith(b"\n"):
        raise CensusError("manifest must be nonempty and end with a newline")

    sources: list[ManifestSource] = []
    seen_ids: set[int | str] = set()
    seen_paths: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise CensusError(f"manifest line {line_number}: blank record")
        context = f"manifest line {line_number}"
        row = strict_json_loads(line, context)
        if type(row) is not dict:
            raise CensusError(f"{context}: record must be an object")
        record_id = row.get("id")
        if isinstance(record_id, bool) or not isinstance(record_id, (int, str)):
            raise CensusError(f"{context}: id must be an integer or string")
        if record_id in seen_ids:
            raise CensusError(f"{context}: duplicate id {record_id!r}")
        seen_ids.add(record_id)

        relative_path = _canonical_relative_path(row.get("relative_path"), context)
        if relative_path in seen_paths:
            raise CensusError(f"{context}: duplicate relative_path {relative_path!r}")
        seen_paths.add(relative_path)
        source_path = _source_path(row, corpus_root, context)
        if not source_path.is_file():
            raise CensusError(f"{context}: missing regular source {source_path}")
        source_bytes = source_path.stat().st_size
        expected_bytes = row.get("bytes")
        if type(expected_bytes) is not int or expected_bytes < 0:
            raise CensusError(f"{context}: bytes must be a nonnegative integer")
        if source_bytes != expected_bytes:
            raise CensusError(
                f"{context}: byte count mismatch for {relative_path}: "
                f"expected {expected_bytes}, got {source_bytes}"
            )
        expected_sha256 = row.get("sha256")
        if not isinstance(expected_sha256, str) or SHA256_RE.fullmatch(expected_sha256) is None:
            raise CensusError(f"{context}: sha256 must be lowercase hexadecimal")
        actual_sha256 = sha256_file(source_path)
        if actual_sha256 != expected_sha256:
            raise CensusError(f"{context}: SHA-256 mismatch for {relative_path}")
        sources.append(
            ManifestSource(
                record_id=record_id,
                relative_path=relative_path,
                source_path=source_path,
                source_bytes=source_bytes,
                source_sha256=actual_sha256,
            )
        )
    return sorted(sources, key=lambda source: source.relative_path), payload


def _canonical_nonnegative_integer(value: str, field: str) -> int:
    if not value or (value != "0" and value.startswith("0")) or not value.isascii():
        raise CensusError(f"projection field {field!r} is not a canonical integer")
    if not value.isdigit():
        raise CensusError(f"projection field {field!r} is not a canonical integer")
    return int(value)


def parse_projection_report(payload: bytes, return_code: int) -> dict[str, int | str]:
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
    missing = sorted(REQUIRED_FIELDS - raw.keys())
    if missing:
        raise CensusError(f"projection output is missing fields: {', '.join(missing)}")

    parsed: dict[str, int | str] = {}
    for key, value in raw.items():
        if key in COUNT_FIELDS:
            parsed[key] = _canonical_nonnegative_integer(value, key)
        elif key in BOOLEAN_FIELDS:
            if value not in {"0", "1"}:
                raise CensusError(f"projection Boolean {key!r} must be 0 or 1")
            parsed[key] = int(value)
        else:
            if not value.isascii() or any(character.isspace() for character in value):
                raise CensusError(f"projection text field {key!r} is not canonical")
            parsed[key] = value

    selected = parsed["selected"]
    expected_return_code = 0 if selected == 1 else 3
    if return_code != expected_return_code:
        raise CensusError(
            f"projection return code {return_code} disagrees with selected={selected}"
        )
    if parsed["sat_calls"] != 0:
        raise CensusError("projection attempted a SAT call")
    if parsed["off_path_unchanged"] != 1:
        raise CensusError("projection did not preserve the off-path CNF")
    if selected == 1 and parsed["materialization_match"] != 1:
        raise CensusError("selected projection did not match materialization")
    return parsed


def projection_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("EUF_VIPER_")
    }
    environment.update({"LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
    return environment


def run_projection(binary: Path, source: Path, timeout_seconds: float) -> dict[str, int | str]:
    try:
        completed = subprocess.run(
            [str(binary), "project-t9", str(source)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=projection_environment(),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise CensusError(f"projection timed out for {source}") from error
    except OSError as error:
        raise CensusError(f"cannot execute projection binary {binary}: {error}") from error
    if completed.returncode not in {0, 3}:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise CensusError(
            f"projection failed for {source} with exit {completed.returncode}: {stderr}"
        )
    if completed.stderr:
        raise CensusError(f"projection wrote unexpected stderr for {source}")
    return parse_projection_report(completed.stdout, completed.returncode)


def atomic_write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise CensusError(f"refusing to overwrite existing artifact {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise CensusError(f"refusing to overwrite existing artifact {path}") from error
        parent_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def canonical_hash(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def encode_records(records: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(record) for record in records)


def run_census(
    manifest_path: Path,
    corpus_root: Path | None,
    binary: Path,
    records_out: Path,
    summary_out: Path,
    *,
    expected_sources: int,
    timeout_seconds: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if expected_sources < 1:
        raise CensusError("expected_sources must be positive")
    if timeout_seconds <= 0:
        raise CensusError("timeout_seconds must be positive")
    binary = binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise CensusError(f"projection binary is not executable: {binary}")
    sources, manifest_bytes = load_manifest(manifest_path, corpus_root)
    if len(sources) != expected_sources:
        raise CensusError(
            f"source count mismatch: expected {expected_sources}, got {len(sources)}"
        )

    binary_sha256 = sha256_file(binary)
    records: list[dict[str, Any]] = []
    previous_hash = ZERO_SHA256
    reason_counts: Counter[str] = Counter()
    selected_paths: list[str] = []
    for source in sources:
        projection = run_projection(binary, source.source_path, timeout_seconds)
        reason = projection["reason"]
        if not isinstance(reason, str):
            raise CensusError("projection reason is not text")
        reason_counts[reason] += 1
        if projection["selected"] == 1:
            selected_paths.append(source.relative_path)
        record: dict[str, Any] = {
            "schema": RECORD_SCHEMA,
            "source": {
                "id": source.record_id,
                "relative_path": source.relative_path,
                "bytes": source.source_bytes,
                "sha256": source.source_sha256,
            },
            "binary_sha256": binary_sha256,
            "projection": projection,
            "previous_record_sha256": previous_hash,
        }
        record_hash = canonical_hash(record)
        record["record_sha256"] = record_hash
        records.append(record)
        previous_hash = record_hash

    records_bytes = encode_records(records)
    source_set = [
        {"relative_path": source.relative_path, "sha256": source.source_sha256}
        for source in sources
    ]
    summary = {
        "schema": SUMMARY_SCHEMA,
        "status": "completed_no_sat",
        "source_count": len(sources),
        "selected_count": len(selected_paths),
        "selected_paths": selected_paths,
        "selected_set_sha256": canonical_hash(selected_paths),
        "reason_counts": dict(sorted(reason_counts.items())),
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "source_set_sha256": canonical_hash(source_set),
        "binary_sha256": binary_sha256,
        "records_sha256": sha256_bytes(records_bytes),
        "record_chain_head": previous_hash,
        "sat_calls": 0,
        "environment_contract": "all_EUF_VIPER_variables_removed",
    }
    summary_bytes = canonical_json_bytes(summary)
    if records_out.exists() or summary_out.exists():
        raise CensusError("refusing to overwrite census outputs")
    atomic_write_new(records_out, records_bytes)
    # A records-only failure is visibly incomplete and safe to inspect. Never
    # delete a pathname after publication because it may have been replaced.
    atomic_write_new(summary_out, summary_bytes)
    return records, summary


def positive_integer(value: str) -> int:
    try:
        parsed = _canonical_nonnegative_integer(value, "argument")
    except CensusError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if parsed == 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("value must be a number") from error
    if not math.isfinite(parsed) or not parsed > 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--records-out", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path, required=True)
    parser.add_argument("--expected-sources", type=positive_integer, default=7503)
    parser.add_argument("--timeout-seconds", type=positive_float, default=30.0)
    arguments = parser.parse_args()
    try:
        _, summary = run_census(
            arguments.manifest,
            arguments.corpus_root,
            arguments.binary,
            arguments.records_out,
            arguments.summary_out,
            expected_sources=arguments.expected_sources,
            timeout_seconds=arguments.timeout_seconds,
        )
    except CensusError as error:
        parser.error(str(error))
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
