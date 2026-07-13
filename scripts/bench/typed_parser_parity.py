#!/usr/bin/env python3
"""Prepare, execute, and audit fail-closed typed parser parity campaigns."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PREPARE_SCHEMA = "euf-viper.typed-parser-parity-prepare.v1"
WORK_SCHEMA = "euf-viper.typed-parser-parity-work.v1"
RECORD_SCHEMA = "euf-viper.typed-parser-parity-record.v1"
PARSER_SCHEMA = "euf-viper.typed-parser-parity.v1"
AUDIT_SCHEMA = "euf-viper.typed-parser-parity-audit.v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")
DIAGNOSTIC_LIMIT = 4096


class CampaignError(ValueError):
    """Raised when an input or artifact violates the parity contract."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def strict_json(text: str, *, where: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as error:
        raise CampaignError(f"{where}: malformed JSON: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path: Path, value: Any) -> None:
    atomic_write(path, canonical_bytes(value))


def atomic_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    atomic_write(path, b"".join(canonical_bytes(row) for row in rows))


def positive_integer(value: str) -> int:
    if not value.isascii() or not value.isdigit() or value.startswith("0"):
        raise argparse.ArgumentTypeError("must be a canonical positive integer")
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def nonnegative_integer(value: str) -> int:
    if value == "0":
        return 0
    return positive_integer(value)


def require_revision(value: str) -> str:
    if REVISION_RE.fullmatch(value) is None:
        raise CampaignError("revision must be a lowercase 40-hex commit hash")
    return value


def safe_relative_path(value: Any, *, line: int) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CampaignError(f"manifest line {line}: invalid relative_path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise CampaignError(f"manifest line {line}: unsafe relative_path {value!r}")
    if pure.suffix.lower() != ".smt2":
        raise CampaignError(f"manifest line {line}: source is not an .smt2 file")
    return pure.as_posix()


def resolve_source(value: Any, repository_root: Path, *, line: int) -> Path:
    if not isinstance(value, str) or not value:
        raise CampaignError(f"manifest line {line}: path must be a nonempty string")
    path = Path(value)
    if not path.is_absolute():
        path = repository_root / path
    try:
        path = path.resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"manifest line {line}: cannot resolve {path}: {error}") from error
    if not path.is_file():
        raise CampaignError(f"manifest line {line}: source is not a file: {path}")
    return path


def load_manifest(manifest: Path, repository_root: Path) -> tuple[list[dict[str, Any]], bytes]:
    try:
        manifest_bytes = manifest.read_bytes()
        text = manifest_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CampaignError(f"cannot read UTF-8 manifest {manifest}: {error}") from error
    lines = text.splitlines()
    if not lines:
        raise CampaignError("manifest has no rows")

    rows: list[dict[str, Any]] = []
    seen_ids: set[int | str] = set()
    seen_paths: set[str] = set()
    seen_sources: set[Path] = set()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise CampaignError(f"manifest line {line_number}: blank JSONL row")
        value = strict_json(line, where=f"manifest line {line_number}")
        if not isinstance(value, dict):
            raise CampaignError(f"manifest line {line_number}: row is not an object")
        for field in ("id", "path", "relative_path"):
            if field not in value:
                raise CampaignError(f"manifest line {line_number}: missing {field!r}")
        record_id = value["id"]
        if isinstance(record_id, bool) or not isinstance(record_id, (int, str)):
            raise CampaignError(f"manifest line {line_number}: invalid id")
        if record_id in seen_ids:
            raise CampaignError(f"manifest line {line_number}: duplicate id")
        seen_ids.add(record_id)

        relative = safe_relative_path(value["relative_path"], line=line_number)
        if relative in seen_paths:
            raise CampaignError(f"manifest line {line_number}: duplicate relative_path")
        seen_paths.add(relative)
        source = resolve_source(value["path"], repository_root, line=line_number)
        if source in seen_sources:
            raise CampaignError(f"manifest line {line_number}: duplicate source path")
        seen_sources.add(source)
        relative_parts = PurePosixPath(relative).parts
        if tuple(source.parts[-len(relative_parts) :]) != relative_parts:
            raise CampaignError(
                f"manifest line {line_number}: source path does not end in {relative!r}"
            )

        source_bytes = source.read_bytes()
        try:
            source_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CampaignError(
                f"manifest line {line_number}: source is not UTF-8: {error}"
            ) from error
        source_hash = sha256_bytes(source_bytes)
        expected_hash = value.get("sha256")
        if expected_hash is not None:
            if not isinstance(expected_hash, str) or SHA256_RE.fullmatch(expected_hash) is None:
                raise CampaignError(
                    f"manifest line {line_number}: sha256 is not lowercase hex"
                )
            if expected_hash != source_hash:
                raise CampaignError(f"manifest line {line_number}: source hash mismatch")
        expected_bytes = value.get("bytes")
        if expected_bytes is not None:
            if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int):
                raise CampaignError(f"manifest line {line_number}: bytes is not an integer")
            if expected_bytes != len(source_bytes):
                raise CampaignError(f"manifest line {line_number}: byte count mismatch")
        rows.append(
            {
                "manifest_line": line_number,
                "relative_path": relative,
                "source_path": str(source),
                "source_sha256": source_hash,
                "source_bytes": len(source_bytes),
            }
        )
    rows.sort(key=lambda row: row["relative_path"])
    return rows, manifest_bytes


def prepare_campaign(args: argparse.Namespace) -> None:
    revision = require_revision(args.revision)
    repository_root = args.repository_root.resolve(strict=True)
    manifest = args.manifest.resolve(strict=True)
    binary = args.binary.resolve(strict=True)
    tool = Path(__file__).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise CampaignError(f"parser binary is not executable: {binary}")
    rows, manifest_bytes = load_manifest(manifest, repository_root)
    if len(rows) != args.expected_sources:
        raise CampaignError(
            f"source cardinality mismatch: expected {args.expected_sources}, got {len(rows)}"
        )
    work_rows = [
        {
            "schema": WORK_SCHEMA,
            "sequence": sequence,
            **row,
        }
        for sequence, row in enumerate(rows)
    ]
    workset = args.output_root / "workset.jsonl"
    atomic_jsonl(workset, work_rows)
    prepare = {
        "schema": PREPARE_SCHEMA,
        "revision": revision,
        "repository_root": str(repository_root),
        "expected_sources": args.expected_sources,
        "source_count": len(rows),
        "shard_count": args.shards,
        "timeout_seconds": args.timeout_seconds,
        "manifest": {"path": str(manifest), "sha256": sha256_bytes(manifest_bytes)},
        "binary": {"path": str(binary), "sha256": sha256_file(binary)},
        "tool": {"path": str(tool), "sha256": sha256_file(tool)},
        "workset": {"path": str(workset.resolve()), "sha256": sha256_file(workset)},
    }
    atomic_json(args.output_root / "prepare.json", prepare)


def load_object(path: Path, *, schema: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="ascii")
    except OSError as error:
        raise CampaignError(f"cannot read {path}: {error}") from error
    value = strict_json(text, where=str(path))
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise CampaignError(f"{path}: unexpected schema")
    return value


def load_jsonl(path: Path, *, schema: str) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise CampaignError(f"cannot read {path}: {error}") from error
    rows = []
    for line_number, line in enumerate(lines, 1):
        if not line:
            raise CampaignError(f"{path}:{line_number}: blank row")
        value = strict_json(line, where=f"{path}:{line_number}")
        if not isinstance(value, dict) or value.get("schema") != schema:
            raise CampaignError(f"{path}:{line_number}: unexpected schema")
        rows.append(value)
    return rows


def load_prepared(root: Path, revision: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    revision = require_revision(revision)
    prepare = load_object(root / "prepare.json", schema=PREPARE_SCHEMA)
    if prepare.get("revision") != revision:
        raise CampaignError("prepare revision does not match executing revision")
    for artifact in ("manifest", "binary", "tool", "workset"):
        value = prepare.get(artifact)
        if not isinstance(value, dict):
            raise CampaignError(f"prepare is missing {artifact}")
        path = Path(value.get("path", ""))
        if not path.is_file() or sha256_file(path) != value.get("sha256"):
            raise CampaignError(f"prepared {artifact} hash mismatch")
    workset_path = Path(prepare["workset"]["path"])
    rows = load_jsonl(workset_path, schema=WORK_SCHEMA)
    if len(rows) != prepare.get("source_count"):
        raise CampaignError("workset cardinality does not match prepare")
    if [row.get("sequence") for row in rows] != list(range(len(rows))):
        raise CampaignError("workset sequence is not contiguous")
    return prepare, rows


def parser_payload(stdout: bytes) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = stdout.decode("ascii")
    except UnicodeDecodeError as error:
        return None, f"parser stdout is not ASCII: {error}"
    lines = [line for line in text.splitlines() if line]
    if len(lines) != 1:
        return None, f"parser emitted {len(lines)} nonempty stdout lines"
    try:
        value = strict_json(lines[0], where="parser stdout")
    except CampaignError as error:
        return None, str(error)
    if not isinstance(value, dict) or value.get("schema") != PARSER_SCHEMA:
        return None, "parser stdout has an unexpected schema"
    required = {
        "status": "match",
        "tree_well_sorted": True,
        "stream_well_sorted": True,
        "fallback": False,
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            return None, f"parser field {key!r} is {value.get(key)!r}, expected {expected!r}"
    return value, None


def classify_failure(exit_code: int | None, stderr: bytes, reason: str) -> str:
    diagnostic = stderr.decode("utf-8", errors="replace")
    if "semantic mismatch" in diagnostic:
        return "mismatch"
    if "fallback" in diagnostic or "fallback" in reason:
        return "fallback"
    return "error"


def diagnostic_excerpt(value: bytes) -> str | None:
    if not value:
        return None
    return value.decode("utf-8", errors="replace")[:DIAGNOSTIC_LIMIT]


def run_shard(args: argparse.Namespace) -> None:
    root = args.root.resolve(strict=True)
    prepare, workset = load_prepared(root, args.revision)
    shard_count = prepare.get("shard_count")
    if args.shard >= shard_count:
        raise CampaignError(f"shard {args.shard} is outside [0, {shard_count})")
    binary = Path(prepare["binary"]["path"])
    timeout = prepare["timeout_seconds"]
    records: list[dict[str, Any]] = []
    for work in workset:
        sequence = work["sequence"]
        if sequence % shard_count != args.shard:
            continue
        source = Path(work["source_path"])
        source_hash = sha256_file(source) if source.is_file() else None
        stdout = b""
        stderr = b""
        exit_code: int | None = None
        parser: dict[str, Any] | None = None
        reason: str | None = None
        status = "match"
        if source_hash != work["source_sha256"]:
            status = "error"
            reason = "source hash changed after prepare"
        else:
            try:
                completed = subprocess.run(
                    [str(binary), "parse-check", str(source)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False,
                    env={**os.environ, "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                )
                stdout = completed.stdout
                stderr = completed.stderr
                exit_code = completed.returncode
                if exit_code == 0:
                    parser, reason = parser_payload(stdout)
                    if reason is not None:
                        status = classify_failure(exit_code, stderr, reason)
                else:
                    reason = f"parse-check exited with status {exit_code}"
                    status = classify_failure(exit_code, stderr, reason)
            except subprocess.TimeoutExpired as error:
                stdout = error.stdout or b""
                stderr = error.stderr or b""
                reason = f"parse-check exceeded {timeout} seconds"
                status = "error"
        records.append(
            {
                "schema": RECORD_SCHEMA,
                "sequence": sequence,
                "shard": args.shard,
                "revision": prepare["revision"],
                "relative_path": work["relative_path"],
                "source_sha256": work["source_sha256"],
                "status": status,
                "exit_code": exit_code,
                "reason": reason,
                "stdout_sha256": sha256_bytes(stdout),
                "stderr_sha256": sha256_bytes(stderr),
                "stdout_excerpt": diagnostic_excerpt(stdout) if status != "match" else None,
                "stderr_excerpt": diagnostic_excerpt(stderr),
                "parser": parser,
            }
        )
    expected = sum(
        1 for row in workset if row["sequence"] % shard_count == args.shard
    )
    if len(records) != expected:
        raise CampaignError("internal shard cardinality mismatch")
    atomic_jsonl(root / "shards" / f"shard-{args.shard:05d}.jsonl", records)


def audit_campaign(args: argparse.Namespace) -> bool:
    root = args.root.resolve(strict=True)
    prepare, workset = load_prepared(root, args.revision)
    expected_sources = prepare["expected_sources"]
    if expected_sources != args.expected_sources or len(workset) != expected_sources:
        raise CampaignError("audit source cardinality does not match preregistration")
    shard_count = prepare["shard_count"]
    records: list[dict[str, Any]] = []
    shard_hashes: dict[str, str] = {}
    for shard in range(shard_count):
        path = root / "shards" / f"shard-{shard:05d}.jsonl"
        rows = load_jsonl(path, schema=RECORD_SCHEMA)
        shard_hashes[f"{shard:05d}"] = sha256_file(path)
        for row in rows:
            if row.get("shard") != shard or row.get("revision") != prepare["revision"]:
                raise CampaignError(f"shard {shard}: row provenance mismatch")
            records.append(row)
    records.sort(key=lambda row: row.get("sequence", -1))
    if [row.get("sequence") for row in records] != list(range(expected_sources)):
        raise CampaignError("merged rows are missing, duplicated, or non-contiguous")

    counts = {"match": 0, "fallback": 0, "mismatch": 0, "error": 0}
    for work, record in zip(workset, records, strict=True):
        if (
            record.get("relative_path") != work["relative_path"]
            or record.get("source_sha256") != work["source_sha256"]
        ):
            raise CampaignError("merged row does not match its workset source")
        status = record.get("status")
        if status not in counts:
            raise CampaignError(f"unknown parity status {status!r}")
        counts[status] += 1
        if status == "match":
            parser = record.get("parser")
            if not isinstance(parser, dict):
                raise CampaignError("matching row has no parser payload")
            _, error = parser_payload(canonical_bytes(parser))
            if error is not None:
                raise CampaignError(f"matching row violates parser contract: {error}")

    records_path = root / "records.jsonl"
    atomic_jsonl(records_path, records)
    passed = counts == {
        "match": expected_sources,
        "fallback": 0,
        "mismatch": 0,
        "error": 0,
    }
    aggregate = {
        "schema": AUDIT_SCHEMA,
        "status": "completed" if passed else "rejected",
        "revision": prepare["revision"],
        "source_count": len(records),
        "expected_sources": expected_sources,
        "counts": counts,
        "gate": {
            "all_tree_parses_succeeded": counts["error"] == 0,
            "all_typed_snapshots_matched": counts["mismatch"] == 0,
            "zero_fallbacks": counts["fallback"] == 0,
            "all_sources_covered": len(records) == expected_sources,
            "passed": passed,
        },
        "artifacts": {
            "prepare_sha256": sha256_file(root / "prepare.json"),
            "workset_sha256": sha256_file(Path(prepare["workset"]["path"])),
            "records_sha256": sha256_file(records_path),
            "shard_sha256": shard_hashes,
        },
    }
    atomic_json(root / "audit.json", aggregate)
    return passed


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--manifest", type=Path, required=True)
    prepare.add_argument("--repository-root", type=Path, required=True)
    prepare.add_argument("--binary", type=Path, required=True)
    prepare.add_argument("--revision", required=True)
    prepare.add_argument("--expected-sources", type=positive_integer, default=7503)
    prepare.add_argument("--shards", type=positive_integer, default=128)
    prepare.add_argument("--timeout-seconds", type=positive_integer, default=60)
    prepare.add_argument("--output-root", type=Path, required=True)

    shard = subparsers.add_parser("run-shard")
    shard.add_argument("--root", type=Path, required=True)
    shard.add_argument("--revision", required=True)
    shard.add_argument("--shard", type=nonnegative_integer, required=True)

    audit = subparsers.add_parser("audit")
    audit.add_argument("--root", type=Path, required=True)
    audit.add_argument("--revision", required=True)
    audit.add_argument("--expected-sources", type=positive_integer, default=7503)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "prepare":
            prepare_campaign(args)
            return 0
        if args.command == "run-shard":
            run_shard(args)
            return 0
        if args.command == "audit":
            return 0 if audit_campaign(args) else 1
        raise AssertionError(args.command)
    except CampaignError as error:
        print(f"typed parser parity campaign error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
