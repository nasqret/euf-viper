#!/usr/bin/env python3
"""Audit a complete Helios shard set and publish one immutable index."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "euf-viper.helios-shard-audit.v2"
HEX64 = set("0123456789abcdef")
RECEIPT_FIELDS = {
    "schema_version",
    "status",
    "job_id",
    "array_job_id",
    "array_task_id",
    "shard_index",
    "shard_count",
    "started_at",
    "finished_at",
    "exit_code",
    "orchestration_revision",
    "solver_revision",
    "preparation_receipt_sha256",
    "toolchain_sha256",
    "candidate_binary_sha256",
    "shard_lock_sha256",
    "bound_lock_sha256",
    "raw_sha256",
    "summary_sha256",
    "resource_capture_sha256",
}
PREPARATION_RECEIPT_REQUIRED_FIELDS = {
    "candidate_binary_sha256",
    "execution_mode",
    "orchestration_revision",
    "shard_count",
    "solver_revision",
    "status",
    "toolchain_sha256",
}


class AuditError(ValueError):
    """A shard set is incomplete, inconsistent, or not hash-bound."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def load_json(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read {context}: {error}") from error
    if not isinstance(value, dict):
        raise AuditError(f"{context} must be an object")
    return value


def read_single_row_tsv(path: Path) -> tuple[list[str], dict[str, str]]:
    try:
        with path.open(newline="", encoding="ascii") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise AuditError(f"cannot read receipt {path}: {error}") from error
    if reader.fieldnames is None:
        raise AuditError(f"receipt has no header: {path}")
    if len(reader.fieldnames) != len(set(reader.fieldnames)) or len(rows) != 1:
        raise AuditError(f"receipt must contain one unique-header row: {path}")
    return reader.fieldnames, rows[0]


def read_receipt(path: Path) -> dict[str, str]:
    fieldnames, row = read_single_row_tsv(path)
    if set(fieldnames) != RECEIPT_FIELDS:
        raise AuditError(f"receipt schema drifted: {path}")
    return row


def read_key_values(path: Path) -> dict[str, str]:
    try:
        with path.open(newline="", encoding="ascii") as handle:
            rows = list(csv.reader(handle, delimiter="\t"))
    except (OSError, UnicodeError, csv.Error) as error:
        raise AuditError(f"cannot read metadata {path}: {error}") from error
    if not rows or any(len(row) != 2 for row in rows):
        raise AuditError(f"metadata must contain two-column rows: {path}")
    result = {key: value for key, value in rows}
    if len(result) != len(rows):
        raise AuditError(f"metadata contains duplicate keys: {path}")
    return result


def require_digest(value: str, context: str) -> str:
    if len(value) != 64 or any(character not in HEX64 for character in value):
        raise AuditError(f"invalid SHA-256 for {context}")
    return value


def require_revision(value: str, context: str) -> str:
    if len(value) != 40 or any(character not in HEX64 for character in value):
        raise AuditError(f"invalid Git revision for {context}")
    return value


def verify_hash(path: Path, expected: str, context: str) -> None:
    require_digest(expected, context)
    if not path.is_file() or path.is_symlink():
        raise AuditError(f"missing regular file for {context}: {path}")
    actual = sha256_file(path)
    if actual != expected:
        raise AuditError(f"hash mismatch for {context}: {actual} != {expected}")


def lock_self_hash(lock: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes({**lock, "lock_sha256": ""})).hexdigest()


def portable_path(path: Path, root: Path, context: str) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise AuditError(f"{context} escaped its evidence root") from error
    if not relative.parts:
        raise AuditError(f"{context} cannot equal its evidence root")
    return relative.as_posix()


def atomic_write_new(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise AuditError(f"refuse to replace audit index: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(canonical_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def audit(
    preparation_root: Path,
    campaign_root: Path,
    shard_count: int,
    analysis_path: Path,
) -> dict[str, Any]:
    preparation_receipt = preparation_root / "receipt.tsv"
    preparation_fields, preparation_row = read_single_row_tsv(preparation_receipt)
    if not PREPARATION_RECEIPT_REQUIRED_FIELDS.issubset(preparation_fields):
        raise AuditError("preparation receipt lacks required provenance fields")
    if preparation_row["status"] != "complete":
        raise AuditError("preparation job is not complete")
    if preparation_row["execution_mode"] != "prepare-sharded":
        raise AuditError("preparation receipt is not sharded")
    if preparation_row["shard_count"] != str(shard_count):
        raise AuditError("preparation shard count drifted")
    orchestration_revision = require_revision(
        preparation_row["orchestration_revision"], "preparation orchestration"
    )
    solver_revision = require_revision(
        preparation_row["solver_revision"], "preparation solver"
    )
    toolchain_hash = require_digest(
        preparation_row["toolchain_sha256"], "preparation toolchain"
    )
    candidate_hash = require_digest(
        preparation_row["candidate_binary_sha256"], "preparation candidate"
    )
    preparation_hash = sha256_file(preparation_receipt)
    preparation = read_key_values(preparation_root / "preparation.tsv")
    for key, expected in (
        ("execution_mode", "prepare-sharded"),
        ("shard_count", str(shard_count)),
        ("orchestration_revision", orchestration_revision),
        ("solver_revision", solver_revision),
        ("candidate_binary_sha256", candidate_hash),
    ):
        if preparation.get(key) != expected:
            raise AuditError(f"preparation metadata {key} drifted")
    verify_hash(
        preparation_root / "target" / "release" / "euf-viper",
        candidate_hash,
        "prepared candidate binary",
    )
    parent_lock = load_json(preparation_root / "campaign-lock.json", "parent lock")
    parent_hash = parent_lock.get("lock_sha256")
    if not isinstance(parent_hash, str) or parent_hash != lock_self_hash(parent_lock):
        raise AuditError("parent lock self-hash mismatch")
    instances = parent_lock.get("corpus", {}).get("instances")
    if not isinstance(instances, list) or len(instances) < shard_count:
        raise AuditError("parent lock instance count cannot support shards")

    tasks: list[dict[str, Any]] = []
    completed_runs = 0
    for index in range(shard_count):
        padded = f"{index:04d}"
        task_root = campaign_root / "tasks" / f"shard-{padded}"
        result_root = campaign_root / "results" / f"shard-{padded}"
        bound_lock = campaign_root / "bound-locks" / f"bound-{padded}.json"
        receipt_path = task_root / "receipt.tsv"
        receipt = read_receipt(receipt_path)
        for key, expected in (
            ("schema_version", "1"),
            ("status", "complete"),
            ("exit_code", "0"),
            ("array_task_id", str(index)),
            ("shard_index", str(index)),
            ("shard_count", str(shard_count)),
            ("preparation_receipt_sha256", preparation_hash),
            ("orchestration_revision", orchestration_revision),
            ("solver_revision", solver_revision),
            ("toolchain_sha256", toolchain_hash),
            ("candidate_binary_sha256", candidate_hash),
        ):
            if receipt[key] != expected:
                raise AuditError(f"shard {index} receipt {key} drifted")

        paths = {
            "shard_lock_sha256": preparation_root
            / "shard-locks"
            / f"lock-{padded}.json",
            "bound_lock_sha256": bound_lock,
            "raw_sha256": result_root / "raw.jsonl",
            "summary_sha256": result_root / "summary.json",
            "resource_capture_sha256": task_root / "resource-usage.json",
        }
        for key, path in paths.items():
            verify_hash(path, receipt[key], f"shard {index} {key}")
        summary = load_json(result_root / "summary.json", f"shard {index} summary")
        if summary.get("status") != "complete":
            raise AuditError(f"shard {index} summary is not complete")
        expected_runs = summary.get("expected_runs")
        if (
            not isinstance(expected_runs, int)
            or expected_runs < 1
            or summary.get("completed_runs") != expected_runs
        ):
            raise AuditError(f"shard {index} run count is incomplete")
        with (result_root / "raw.jsonl").open(encoding="utf-8") as handle:
            raw_records = sum(1 for line in handle if line.rstrip("\n"))
        if raw_records != expected_runs:
            raise AuditError(f"shard {index} raw row count drifted")
        completed_runs += expected_runs
        tasks.append(
            {
                "index": index,
                "job_id": receipt["job_id"],
                "receipt_path": portable_path(
                    receipt_path, campaign_root, f"shard {index} receipt"
                ),
                "receipt_sha256": sha256_file(receipt_path),
                "raw_records": raw_records,
                "raw_sha256": receipt["raw_sha256"],
                "bound_lock_sha256": receipt["bound_lock_sha256"],
                "resource_capture_sha256": receipt["resource_capture_sha256"],
            }
        )

    analysis = load_json(analysis_path, "all-comparator analysis")
    if analysis.get("status") not in {"promoted", "rejected"}:
        raise AuditError("analysis is neither promoted nor rejected")
    analysis_inputs = analysis.get("inputs")
    analysis_hashes = analysis.get("input_hashes")
    if not isinstance(analysis_inputs, dict) or not isinstance(analysis_hashes, dict):
        raise AuditError("analysis lacks input provenance")
    if analysis_inputs.get("raw_records") != completed_runs:
        raise AuditError("analysis raw record count differs from shard receipts")
    if analysis_inputs.get("instances") != len(instances):
        raise AuditError("analysis instance count differs from parent lock")
    if analysis_hashes.get("lock_sha256") != parent_hash:
        raise AuditError("analysis parent lock hash drifted")
    if analysis_hashes.get("lock_file_sha256") != sha256_file(
        preparation_root / "campaign-lock.json"
    ):
        raise AuditError("analysis parent lock file hash drifted")
    solver_hashes = analysis_hashes.get("solver_binary_sha256")
    candidate_id = analysis_inputs.get("candidate_id")
    if (
        not isinstance(solver_hashes, dict)
        or not isinstance(candidate_id, str)
        or solver_hashes.get(candidate_id) != candidate_hash
    ):
        raise AuditError("analysis candidate binary hash drifted")
    analysis_shards = analysis_inputs.get("shards")
    if not isinstance(analysis_shards, list) or len(analysis_shards) != shard_count:
        raise AuditError("analysis shard provenance is incomplete")
    analysis_by_index = {
        item.get("index"): item for item in analysis_shards if isinstance(item, dict)
    }
    if set(analysis_by_index) != set(range(shard_count)):
        raise AuditError("analysis shard indices are incomplete or duplicated")
    hashed_locks = analysis_hashes.get("shard_lock_file_sha256")
    hashed_raw = analysis_hashes.get("shard_raw_sha256")
    if not isinstance(hashed_locks, dict) or not isinstance(hashed_raw, dict):
        raise AuditError("analysis lacks per-shard input hashes")
    for task in tasks:
        index = task["index"]
        source = analysis_by_index[index]
        if source.get("lock_file_sha256") != task["bound_lock_sha256"]:
            raise AuditError(f"analysis shard {index} bound lock hash drifted")
        if source.get("raw_sha256") != task["raw_sha256"]:
            raise AuditError(f"analysis shard {index} raw hash drifted")
        if source.get("raw_records") != task["raw_records"]:
            raise AuditError(f"analysis shard {index} row count drifted")
        if hashed_locks.get(str(index)) != task["bound_lock_sha256"]:
            raise AuditError(f"analysis hash map for shard {index} lock drifted")
        if hashed_raw.get(str(index)) != task["raw_sha256"]:
            raise AuditError(f"analysis hash map for shard {index} raw drifted")

    return {
        "analysis": {
            "path": portable_path(analysis_path, campaign_root, "analysis"),
            "sha256": sha256_file(analysis_path),
            "status": analysis["status"],
        },
        "candidate_binary_sha256": candidate_hash,
        "completed_runs": completed_runs,
        "instances": len(instances),
        "parent_lock_sha256": parent_hash,
        "preparation_receipt_sha256": preparation_hash,
        "orchestration_revision": orchestration_revision,
        "schema_version": SCHEMA_VERSION,
        "shard_count": shard_count,
        "solver_revision": solver_revision,
        "toolchain_sha256": toolchain_hash,
        "tasks": tasks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preparation-root", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.shard_count < 2:
            raise AuditError("shard count must be at least two")
        payload = audit(
            args.preparation_root.resolve(strict=True),
            args.campaign_root.resolve(strict=True),
            args.shard_count,
            args.analysis.resolve(strict=True),
        )
        atomic_write_new(args.out, payload)
    except (AuditError, OSError) as error:
        parser.exit(2, f"shard audit failed: {error}\n")
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
